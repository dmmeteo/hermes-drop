"""The durable record. Everything else in Drop is best-effort.

``deliver_wake`` cannot be the durability mechanism (plan §3.3): a queued wake is
newline-merged into an unrelated pending turn (``gateway/platforms/base.py:2487-2494``,
a pattern core itself calls a bug at ``gateway/run.py:8593-8600``), the pending
queue is an in-memory instance dict lost on restart, the busy handler silently
drops a wake whose user is no longer authorised (``:8356-8365``), the drain branch
posts unattributed chat noise (``:8368-8393``), and ``deliver_wake`` raises on
failure. So the contract is **at-least-once and idempotent, never exactly-once**,
and this file is what makes that sound: the journal is read to decide what still
needs doing, and a claim succeeds off the journal with no wake having landed.

Three properties are load-bearing.

**Atomic.** Write a temp file in the *same directory*, ``fsync`` it, then
``os.replace``. A kill anywhere before the rename leaves the previous entry
readable; a kill after it leaves the new one. No *entry* has a third state — but
the directory does, and the module used to claim otherwise. A real ``SIGKILL``
runs no cleanup, so it leaves a ``.tmp-XXXXXX.json`` file behind holding a
complete, valid body with the same ``drop_id`` as its target. ``Path.glob``
matches dotfiles (unlike ``glob.glob``), so ``entries()`` read that orphan as a
*second* entry for the same drop: duplicated in ``terminal_unannounced``, named
twice in one wake, and burning ``MAX_ANNOUNCE_ATTEMPTS`` at twice the rate
(review M3). So reading skips the temp prefix, and writing sweeps up orphans past
``ORPHAN_GRACE_SECONDS`` — age-gated, because a concurrent writer's in-flight temp
file is indistinguishable from litter on disk.

**Non-secret by construction.** ``ALLOWED_FIELDS`` is closed, and every string
value is refused if it looks like it could carry a URL — the capability rides in
a ``#fragment`` (§8.8), so a URL-shaped value is the one shape that could smuggle
it in. A refusal here is a loud ``JournalRejected``, not a sweep afterwards.

**Profile-scoped.** ``get_hermes_home()``, never ``Path.home()/".hermes"``
(``AGENTS.md`` profile rule 1). Reading never creates anything: the startup
reconciler reads before it knows whether there is work, and in a CLI process
there never is.

Claim authorisation lives here because it is a property of the durable record,
not of a live session. It binds ``(platform, profile, chat_id, thread_id,
user_id)`` and journals ``session_key`` for audit only — ``session_key`` is
re-derived per turn by ``build_session_key`` (``gateway/platforms/base.py:5554-5558``)
*after* ``_apply_topic_recovery`` may have replaced the source (``:3306-3325``,
called ``:5552``), so binding it would convert a legitimate claim into a refusal,
and a false refusal destroys a one-shot payload (§8.5).
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

STATE_WAITING = "waiting"
STATE_RECEIVED = "received"
STATE_EXPIRED = "expired"
#: The broker's answer never arrived, so the payload's fate is genuinely unknown
#: — mirroring ``await``'s exit 1 (``bin/handoff-admin.mjs:31-36``). Distinct from
#: ``expired`` because a guess must never become a claim.
STATE_TRANSPORT_FAILED = "transport_failed"

TERMINAL_STATES = frozenset({STATE_RECEIVED, STATE_EXPIRED, STATE_TRANSPORT_FAILED})
STATES = frozenset({STATE_WAITING}) | TERMINAL_STATES

#: A wake that keeps failing must not be retried forever. Past this, the entry
#: stays terminal and unannounced: the user still has the edited status message,
#: and the model can still claim.
MAX_ANNOUNCE_ATTEMPTS = 5

#: The closed non-secret allowlist (§8.10). Nothing outside this set is ever
#: written, and ``tests/test_journal.py`` asserts the created entry equals it.
ALLOWED_FIELDS = frozenset(
    {
        "drop_id",
        "state",
        "platform",
        "profile",
        "chat_id",
        "thread_id",
        "user_id",
        "session_key",
        "message_id",
        "purpose",
        "created_at",
        "updated_at",
        "expires_at_ms",
        "ttl_seconds",
        "announced_at",
        "announce_attempts",
        "claimed_at",
        "edit_failed",
        "notice_received",
        "notice_expired",
    }
)

#: The broker mints 22 base64url characters (``contract/control-protocol.json``).
#: The bound is deliberately wider than 22 and the character class deliberately
#: narrower than a filename: ``drop_id`` reaches ``claim_private_input`` straight
#: from the model, and it is used as a path component.
_DROP_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

#: A capability only ever travels inside a URL fragment, so a scheme separator is
#: the one shape that could smuggle one into the durable record.
_URLISH = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://")

_SUFFIX = ".json"
_TMP_PREFIX = ".tmp-"

#: How old a ``.tmp-*`` file must be before a write is willing to unlink it.
#:
#: Two waiters resolving in the same turn write concurrently — that is the reason
#: for one file per drop — so a temp file that exists right now may belong to
#: another writer mid-``fsync``. Five minutes is far longer than any write here can
#: take (one ``json.dumps``, one ``fsync``, one ``rename`` over a few hundred
#: bytes) and short enough that orphans do not pile up across a crash loop.
ORPHAN_GRACE_SECONDS = 300.0


class JournalRejected(ValueError):
    """A write that must not happen: unknown field, bad id, or URL-shaped value.

    Deliberately loud. The alternative — dropping the offending field — would let
    a near-miss on §8.8 pass silently, and the whole argument for the allowlist is
    that it is checkable.
    """


def journal_root() -> Path:
    """``$HERMES_HOME/state/hermes-drop``. Resolved per call, never created here.

    Per call because ``HERMES_HOME`` is what makes this profile-scoped, and a
    latched value would follow a profile switch into the wrong directory.
    """
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home()) / "state" / "hermes-drop"


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _validate_drop_id(drop_id: Any) -> str:
    if not isinstance(drop_id, str) or not _DROP_ID_RE.match(drop_id):
        raise JournalRejected(f"unusable drop_id: {drop_id!r}")
    return drop_id


def _validate_value(field: str, value: Any) -> Any:
    if isinstance(value, str) and _URLISH.search(value):
        raise JournalRejected(
            f"refusing to journal a URL-shaped value in {field!r}; "
            "the capability rides in a URL fragment and is never durable (§8.8)"
        )
    return value


def _validate_entry(entry: Mapping[str, Any]) -> Dict[str, Any]:
    unknown = sorted(set(entry) - ALLOWED_FIELDS)
    if unknown:
        raise JournalRejected(f"fields outside the non-secret allowlist: {unknown}")
    validated = {field: _validate_value(field, value) for field, value in entry.items()}
    _validate_drop_id(validated.get("drop_id"))
    state = validated.get("state")
    if state not in STATES:
        raise JournalRejected(f"unknown state: {state!r}")
    return validated


class DropJournal:
    """One JSON file per drop under a 0700 directory.

    One file per drop rather than one shared file: two waiters resolving in the
    same turn write concurrently, and separate files make that safe without a
    lock. Concurrent drops in one conversation are independent *by journal id* —
    drop identity never comes from the source registry, whose key is the routing
    lane and is shared by construction.
    """

    #: Exposed on the instance so a caller (and a test) reads the same grace the
    #: cleanup applies, rather than a copy of the number.
    ORPHAN_GRACE_SECONDS = ORPHAN_GRACE_SECONDS

    def __init__(self, root: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._root = Path(root) if root is not None else None
        self._clock = clock

    @property
    def root(self) -> Path:
        return self._root if self._root is not None else journal_root()

    def path_for(self, drop_id: str) -> Path:
        return self.root / (_validate_drop_id(drop_id) + _SUFFIX)

    # -- reading ------------------------------------------------------------

    def get(self, drop_id: Any) -> Optional[Dict[str, Any]]:
        """The entry, or ``None``. Never raises: ``drop_id`` comes from a model."""
        try:
            path = self.path_for(drop_id)
        except JournalRejected:
            return None
        return self._read(path)

    def entries(self) -> List[Dict[str, Any]]:
        """Every readable entry, oldest first. A missing root is simply empty.

        ``[!.]*`` rather than ``*``: ``Path.glob`` matches dotfiles, and an
        orphaned ``.tmp-XXXXXX.json`` left by a real kill holds a complete, valid
        body with a ``drop_id`` already present under its own name — so it read as
        a duplicate entry rather than as junk (review M3). Excluding every dotfile
        is safe and not merely sufficient: ``_DROP_ID_RE`` admits no ``.``, so no
        legitimate entry file can begin with one. The explicit prefix check behind
        it states the intent, and keeps this correct if the glob is ever loosened.
        """
        root = self.root
        if not root.is_dir():
            return []
        found = []
        for path in sorted(root.glob("[!.]*" + _SUFFIX)):
            if path.name.startswith(_TMP_PREFIX):  # pragma: no cover - glob covers it
                continue
            entry = self._read(path)
            if entry is not None:
                found.append(entry)
        found.sort(key=lambda e: (e.get("created_at") or 0, e.get("drop_id") or ""))
        return found

    def waiting(self) -> List[Dict[str, Any]]:
        return [e for e in self.entries() if e.get("state") == STATE_WAITING]

    def terminal_unannounced(
        self, routing_tuple: Optional[Sequence[str]] = None
    ) -> List[Dict[str, Any]]:
        """Terminal, never announced, and still within the attempt budget.

        Announce reads *this*, not one drop: §3.3's "announce the set, not the
        drop". One self-contained wake then survives boundary merging, a dropped
        wake and a restart, because whatever the next announce emits is complete
        on its own.
        """
        lane = tuple(routing_tuple) if routing_tuple is not None else None
        pending = []
        for entry in self.entries():
            if entry.get("state") not in TERMINAL_STATES:
                continue
            if entry.get("announced_at") is not None:
                continue
            if int(entry.get("announce_attempts") or 0) >= MAX_ANNOUNCE_ATTEMPTS:
                continue
            if lane is not None and routing_tuple_of(entry) != lane:
                continue
            pending.append(entry)
        return pending

    def _read(self, path: Path) -> Optional[Dict[str, Any]]:
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            # A truncated file cannot exist by construction (see the module
            # docstring), but a hand-edited or foreign one can. Skipping is the
            # only safe reading: a reconciler that died on one bad file would
            # abandon every good one behind it.
            logger.warning("hermes-drop: skipping unreadable journal entry %s", path.name)
            return None
        if not isinstance(parsed, dict):
            return None
        return {k: v for k, v in parsed.items() if k in ALLOWED_FIELDS}

    # -- writing ------------------------------------------------------------

    def create_entry(
        self,
        *,
        drop_id: str,
        origin: Any,
        message_id: str,
        expires_at_ms: int,
        ttl_seconds: int,
        purpose: Any = "",
        session_key: str = "",
        notice_received: str = "",
        notice_expired: str = "",
    ) -> Dict[str, Any]:
        """Mint a ``waiting`` entry from a resolved origin and a minted handoff.

        The two quiet notices are stored so a waiter that outlives a gateway
        restart can edit the status message without a broker round trip. They are
        constants with no URL in them (``src/notice.js:33-40``), and the URL guard
        keeps that true if a renderer ever changes.
        """
        now = self._clock()
        platform, profile, chat_id, thread_id = _routing_from_origin(origin)
        entry = {
            "drop_id": drop_id,
            "state": STATE_WAITING,
            "platform": platform,
            "profile": profile,
            "chat_id": chat_id,
            "thread_id": thread_id,
            "user_id": _text(getattr(getattr(origin, "source", None), "user_id", "")),
            "session_key": _text(session_key),
            "message_id": _text(message_id),
            "purpose": _text(purpose),
            "created_at": now,
            "updated_at": now,
            "expires_at_ms": int(expires_at_ms),
            "ttl_seconds": int(ttl_seconds),
            "announced_at": None,
            "announce_attempts": 0,
            "claimed_at": None,
            "edit_failed": False,
            "notice_received": _text(notice_received),
            "notice_expired": _text(notice_expired),
        }
        return self.put(entry)

    def put(self, entry: Mapping[str, Any]) -> Dict[str, Any]:
        validated = _validate_entry(entry)
        self._write(self.path_for(validated["drop_id"]), validated)
        return validated

    def update(self, drop_id: Any, **changes: Any) -> Optional[Dict[str, Any]]:
        """Merge *changes* into an existing entry, atomically. ``None`` if absent.

        A missing entry is not an error: the reconciler and a waiter can both
        reach a transition, and whichever arrives second must be a no-op rather
        than a resurrection.
        """
        unknown = sorted(set(changes) - ALLOWED_FIELDS)
        if unknown:
            raise JournalRejected(f"fields outside the non-secret allowlist: {unknown}")
        current = self.get(drop_id)
        if current is None:
            return None
        merged = dict(current)
        merged.update(changes)
        merged["updated_at"] = self._clock()
        return self.put(merged)

    def delete(self, drop_id: Any) -> None:
        try:
            self.path_for(drop_id).unlink()
        except (OSError, JournalRejected):
            pass

    def _sweep_orphans(self, root: Path) -> None:
        """Unlink ``.tmp-*`` files older than the grace. Never raises.

        Housekeeping is not allowed to be why a durable write fails: the journal
        is the only durable thing Drop has, and a temp file that cannot be
        unlinked — read-only directory, foreign owner — is untidy where a lost
        ``create`` is a lost drop. So every failure here is a debug line.
        """
        cutoff = time.time() - self.ORPHAN_GRACE_SECONDS
        try:
            candidates = list(root.glob(_TMP_PREFIX + "*" + _SUFFIX))
        except OSError:  # pragma: no cover - unreadable directory
            return
        for candidate in candidates:
            try:
                if candidate.stat().st_mtime < cutoff:
                    candidate.unlink(missing_ok=True)
                    logger.debug("hermes-drop: removed orphaned journal temp %s", candidate.name)
            except OSError:
                logger.debug("hermes-drop: could not remove %s", candidate.name, exc_info=True)

    def _write(self, path: Path, entry: Mapping[str, Any]) -> None:
        root = path.parent
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(root, 0o700)
        except OSError:  # pragma: no cover - a foreign-owned state dir
            logger.debug("hermes-drop: could not tighten %s to 0700", root)

        # Before writing, not after: a write that is itself killed should leave at
        # most the one orphan it just created, not that one plus every earlier one.
        self._sweep_orphans(root)

        blob = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fd, tmp_name = tempfile.mkstemp(prefix=_TMP_PREFIX, suffix=_SUFFIX, dir=str(root))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
        except BaseException:
            # BaseException on purpose: a KeyboardInterrupt between write and
            # rename is exactly the "simulated kill" case, and it must not leave
            # a temp file that a later reader has to reason about.
            tmp_path.unlink(missing_ok=True)
            raise


# ── routing and claim authorisation ────────────────────────────────────────


def _routing_from_origin(origin: Any) -> Tuple[str, str, str, str]:
    tup = tuple(_text(part) for part in getattr(origin, "routing_tuple", ("", "", "", "")))
    if len(tup) != 4:  # pragma: no cover - Origin guarantees four
        raise JournalRejected(f"unusable routing tuple: {tup!r}")
    return tup  # type: ignore[return-value]


def routing_tuple_of(entry: Mapping[str, Any]) -> Tuple[str, str, str, str]:
    return (
        _text(entry.get("platform")),
        _text(entry.get("profile")),
        _text(entry.get("chat_id")),
        _text(entry.get("thread_id")),
    )


def claim_tuple_of(entry: Mapping[str, Any]) -> Tuple[str, str, str, str, str]:
    """§8.5's five fields. ``session_key`` is deliberately not among them."""
    return routing_tuple_of(entry) + (_text(entry.get("user_id")),)


def claim_tuple_for_origin(origin: Any) -> Tuple[str, str, str, str, str]:
    return _routing_from_origin(origin) + (
        _text(getattr(getattr(origin, "source", None), "user_id", "")),
    )


def authorize_claim(entry: Optional[Mapping[str, Any]], origin: Any) -> Optional[Dict[str, Any]]:
    """``None`` when the claim may proceed, otherwise the refusal to return.

    Deliberately independent of ``announced_at``: a claim must succeed with no
    wake having landed at all, which is the third of §3.3's three mechanisms.
    """
    if entry is None:
        return {"error": "unavailable", "detail": "no such drop"}

    if claim_tuple_of(entry) != claim_tuple_for_origin(origin):
        # No detail: the refusal reaches a model, and naming the owning lane
        # would describe a conversation the caller is not in.
        return {"error": "not_authorized"}

    if entry.get("claimed_at") is not None:
        return {"error": "unavailable", "detail": "already claimed; the payload is destroyed"}

    state = _text(entry.get("state"))
    if state == STATE_RECEIVED:
        return None
    if state == STATE_WAITING:
        return {"error": "not_ready", "state": state}
    return {"error": "unavailable", "state": state}


__all__ = [
    "ALLOWED_FIELDS",
    "MAX_ANNOUNCE_ATTEMPTS",
    "STATES",
    "STATE_EXPIRED",
    "STATE_RECEIVED",
    "STATE_TRANSPORT_FAILED",
    "STATE_WAITING",
    "TERMINAL_STATES",
    "DropJournal",
    "JournalRejected",
    "authorize_claim",
    "claim_tuple_for_origin",
    "claim_tuple_of",
    "journal_root",
    "routing_tuple_of",
]
