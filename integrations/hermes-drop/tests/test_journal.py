"""S6 — the durable record, written before anything that depends on it.

The journal is the *only* durable thing in Drop. ``deliver_wake`` is best-effort
for five independently verified reasons (plan §3.3), so correctness cannot rest
on a wake landing. Everything here is therefore about two properties:

1. **A write either happened or it did not.** ``os.replace`` on a same-directory
   temp file, so a kill mid-write leaves the previous entry readable rather than
   a truncated one.
2. **Nothing secret is in it.** The field set is a closed allowlist and every
   string value is refused if it could carry a capability. §8.8: the capability
   appears exactly twice — the broker's ``create`` response and the chat message.

Claim authorisation lives here too, because it is a property of the durable
record and not of a live session: it binds the routing tuple
``(platform, profile, chat_id, thread_id, user_id)``, never ``session_key``, and
it must succeed with no wake having landed at all (§8.5, §3.3).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from gateway.config import Platform

from _stubs import StubAdapter, StubRunner
from conftest import load_plugin_package


@pytest.fixture
def journal_mod():
    return load_plugin_package().drop.journal


@pytest.fixture
def journal(journal_mod, tmp_path: Path):
    return journal_mod.DropJournal(root=tmp_path / "hermes-drop")


@pytest.fixture
def origin_for():
    """Build a real, verified-shaped :class:`Origin` without a gateway."""
    from conftest import load_plugin_package as _load

    origin_mod = _load().drop.origin
    sources = _load().drop.sources

    def _make(platform: Platform = Platform.TELEGRAM, chat_id: str = "chat-1", **kw):
        adapter = StubAdapter(platform)
        runner = StubRunner({platform: adapter})
        source = adapter.build_source(
            chat_id=chat_id, chat_type=kw.pop("chat_type", "dm"), user_id=kw.pop("user_id", "u-1"), **kw
        )
        return origin_mod.Origin(
            source=source,
            adapter=adapter,
            runner=runner,
            routing_tuple=sources.routing_tuple_for_source(source),
            reply_anchor=None,
            tier="turn_contextvar",
        )

    return _make


def _entry(journal, origin, drop_id="AAAAAAAAAAAAAAAAAAAAAA", **kw):
    return journal.create_entry(
        drop_id=drop_id,
        origin=origin,
        message_id=kw.pop("message_id", "msg-1"),
        expires_at_ms=kw.pop("expires_at_ms", 1_800_000),
        ttl_seconds=kw.pop("ttl_seconds", 1800),
        purpose=kw.pop("purpose", "deploy token"),
        session_key=kw.pop("session_key", "sess-1"),
        notice_received=kw.pop("notice_received", "✓ **Private input received**"),
        notice_expired=kw.pop("notice_expired", "✕ **Private input link expired**"),
        **kw,
    )


# ── durability ─────────────────────────────────────────────────────────────


def test_a_write_lands_through_os_replace(journal, journal_mod, origin_for, monkeypatch) -> None:
    """Atomicity is the mechanism, not an outcome that happens to hold, so the
    mechanism is what gets asserted."""
    calls: list = []
    real_replace = os.replace

    def spy(src, dst):
        calls.append((str(src), str(dst)))
        return real_replace(src, dst)

    monkeypatch.setattr(journal_mod.os, "replace", spy)
    entry = _entry(journal, origin_for())

    assert len(calls) == 1
    src, dst = calls[0]
    assert dst == str(journal.path_for(entry["drop_id"]))
    assert Path(src).parent == Path(dst).parent, "temp file must share the target's directory"


def test_a_kill_mid_write_leaves_the_previous_entry_readable(
    journal, journal_mod, origin_for, monkeypatch
) -> None:
    origin = origin_for()
    _entry(journal, origin, purpose="first")

    def die(src, dst):
        raise KeyboardInterrupt("simulated kill between write and rename")

    monkeypatch.setattr(journal_mod.os, "replace", die)
    with pytest.raises(KeyboardInterrupt):
        journal.update("AAAAAAAAAAAAAAAAAAAAAA", purpose="second")

    monkeypatch.undo()
    survivor = journal.get("AAAAAAAAAAAAAAAAAAAAAA")
    assert survivor["purpose"] == "first", "a half-written entry replaced a good one"
    assert survivor["state"] == journal_mod.STATE_WAITING
    assert list(journal.root.glob("*.tmp*")) == [], "a failed write left a temp file behind"


def test_a_stray_temp_file_is_not_an_entry(journal, origin_for) -> None:
    _entry(journal, origin_for())
    (journal.root / "leftover.json.tmp").write_text("{not json", encoding="utf-8")
    (journal.root / "corrupt.json").write_text("{not json", encoding="utf-8")

    ids = [e["drop_id"] for e in journal.entries()]
    assert ids == ["AAAAAAAAAAAAAAAAAAAAAA"], "unreadable files must be skipped, not fatal"


def test_entries_on_a_missing_root_creates_nothing(journal_mod, tmp_path: Path) -> None:
    """Reading must never be a write. The startup reconciler reads before it
    knows whether there is anything to do, and in a CLI process there never is."""
    root = tmp_path / "never-created"
    empty = journal_mod.DropJournal(root=root)
    assert empty.entries() == []
    assert empty.get("AAAAAAAAAAAAAAAAAAAAAA") is None
    assert not root.exists()


def test_the_journal_directory_is_private(journal, origin_for) -> None:
    _entry(journal, origin_for())
    assert (journal.root.stat().st_mode & 0o777) == 0o700


def test_the_root_is_profile_scoped_under_hermes_home(journal_mod, monkeypatch, tmp_path) -> None:
    """Profile rule 1: ``get_hermes_home()``, never ``Path.home()/".hermes"``."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile-b"))
    root = journal_mod.journal_root()
    assert root == tmp_path / "profile-b" / "state" / "hermes-drop"
    assert not root.exists(), "resolving the root must not create it"


# ── the non-secret allowlist ───────────────────────────────────────────────


def test_the_field_set_is_a_closed_allowlist(journal, journal_mod, origin_for) -> None:
    entry = _entry(journal, origin_for())
    assert set(entry) == set(journal_mod.ALLOWED_FIELDS)

    with pytest.raises(journal_mod.JournalRejected):
        journal.update(entry["drop_id"], url="https://example.invalid/#cap")
    with pytest.raises(journal_mod.JournalRejected):
        journal.update(entry["drop_id"], plaintext="hunter2")


def test_no_url_shaped_value_can_be_journalled(journal, journal_mod, origin_for) -> None:
    """The capability rides in a URL fragment. A value that could carry one is
    refused loudly rather than written and swept for afterwards."""
    origin = origin_for()
    for bad in (
        "https://handoff.example/#Zm9vYmFyZm9vYmFyZm9vYmFy",
        "http://127.0.0.1:8080/#cap",
        "see ftp://host/x",
    ):
        with pytest.raises(journal_mod.JournalRejected):
            _entry(journal, origin, purpose=bad)
    assert journal.entries() == []


def test_a_written_entry_contains_no_capability_and_no_payload(
    journal, origin_for
) -> None:
    capability = "Q2FwYWJpbGl0eVN0cmluZ0FB"
    payload = "e2e-marker-8ad31f"
    entry = _entry(journal, origin_for(), purpose="deploy token")
    journal.update(entry["drop_id"], state="received")

    blob = journal.path_for(entry["drop_id"]).read_text(encoding="utf-8")
    assert capability not in blob and payload not in blob
    assert "://" not in blob and "#" not in blob
    parsed = json.loads(blob)
    assert set(parsed) <= set(entry)


def test_a_drop_id_can_never_escape_the_journal_directory(journal, journal_mod, origin_for) -> None:
    """``drop_id`` reaches ``claim_private_input`` straight from the model."""
    for hostile in ("../../etc/passwd", "a/b", "", ".", "..", "x" * 200, "id with space"):
        with pytest.raises(journal_mod.JournalRejected):
            journal.path_for(hostile)
        assert journal.get(hostile) is None


# ── state and lifecycle ────────────────────────────────────────────────────


def test_a_new_entry_starts_waiting_and_unannounced(journal, journal_mod, origin_for) -> None:
    entry = _entry(journal, origin_for())
    assert entry["state"] == journal_mod.STATE_WAITING
    assert entry["announced_at"] is None
    assert entry["announce_attempts"] == 0
    assert entry["claimed_at"] is None
    assert entry["edit_failed"] is False


def test_concurrent_drops_in_one_lane_are_independent_by_journal_id(
    journal, origin_for
) -> None:
    """Drop identity is the journal id, not the source registry: two ``/drop``s
    in one Discord channel share a routing tuple and an empty ``message_id``."""
    origin = origin_for(Platform.DISCORD, chat_id="chan-1", chat_type="channel")
    a = _entry(journal, origin, drop_id="A" * 22, message_id="m-a")
    b = _entry(journal, origin, drop_id="B" * 22, message_id="m-b")

    journal.update(a["drop_id"], state="received")
    assert journal.get(b["drop_id"])["state"] == "waiting"
    assert {e["drop_id"] for e in journal.waiting()} == {"B" * 22}
    assert a["chat_id"] == b["chat_id"], "the lane really is shared"


def test_terminal_unannounced_filters_by_lane_state_and_attempts(
    journal, journal_mod, origin_for
) -> None:
    tg = origin_for(Platform.TELEGRAM, chat_id="tg-1")
    other = origin_for(Platform.TELEGRAM, chat_id="tg-2")
    lane = tg.routing_tuple

    waiting = _entry(journal, tg, drop_id="W" * 22)
    received = _entry(journal, tg, drop_id="R" * 22)
    journal.update(received["drop_id"], state=journal_mod.STATE_RECEIVED)
    elsewhere = _entry(journal, other, drop_id="O" * 22)
    journal.update(elsewhere["drop_id"], state=journal_mod.STATE_EXPIRED)
    spent = _entry(journal, tg, drop_id="S" * 22)
    journal.update(
        spent["drop_id"],
        state=journal_mod.STATE_TRANSPORT_FAILED,
        announce_attempts=journal_mod.MAX_ANNOUNCE_ATTEMPTS,
    )

    pending = [e["drop_id"] for e in journal.terminal_unannounced(lane)]
    assert pending == ["R" * 22]
    assert waiting["state"] == "waiting"

    journal.update(received["drop_id"], announced_at=123.0)
    assert journal.terminal_unannounced(lane) == []


def test_updating_a_missing_entry_is_a_no_op_not_a_crash(journal) -> None:
    assert journal.update("Z" * 22, state="received") is None


# ── claim authorisation binds the routing tuple, never the session key ─────


def test_claim_is_authorised_by_the_routing_tuple(journal, journal_mod, origin_for) -> None:
    origin = origin_for(Platform.TELEGRAM, chat_id="tg-1", user_id="u-1")
    entry = _entry(journal, origin, session_key="key-at-creation")
    journal.update(entry["drop_id"], state=journal_mod.STATE_RECEIVED)

    assert journal_mod.authorize_claim(journal.get(entry["drop_id"]), origin) is None


def test_claim_succeeds_with_no_wake_having_landed(journal, journal_mod, origin_for) -> None:
    """The whole point of §3.3: the wake is the latency path, not the mechanism."""
    origin = origin_for()
    entry = _entry(journal, origin)
    journal.update(entry["drop_id"], state=journal_mod.STATE_RECEIVED)

    stored = journal.get(entry["drop_id"])
    assert stored["announced_at"] is None
    assert stored["announce_attempts"] == 0
    assert journal_mod.authorize_claim(stored, origin) is None


def test_a_drifted_session_key_does_not_refuse_a_legitimate_claim(
    journal, journal_mod, origin_for
) -> None:
    """``session_key`` is re-derived per turn after ``_apply_topic_recovery`` may
    have replaced the source (``gateway/platforms/base.py:3306-3325``, ``:5552``).
    A false refusal destroys a one-shot payload, which is worse than the attack
    it would prevent — so the key is audit only (§8.5)."""
    origin = origin_for()
    entry = _entry(journal, origin, session_key="key-before-rotation")
    journal.update(entry["drop_id"], state=journal_mod.STATE_RECEIVED)

    stored = journal.get(entry["drop_id"])
    assert stored["session_key"] == "key-before-rotation"
    assert journal_mod.authorize_claim(stored, origin) is None, "session_key drift refused a claim"


def test_claim_from_a_different_lane_is_refused(journal, journal_mod, origin_for) -> None:
    mine = origin_for(Platform.TELEGRAM, chat_id="tg-1", user_id="u-1")
    entry = _entry(journal, mine)
    journal.update(entry["drop_id"], state=journal_mod.STATE_RECEIVED)
    stored = journal.get(entry["drop_id"])

    for foreign in (
        origin_for(Platform.DISCORD, chat_id="tg-1", chat_type="channel", user_id="u-1"),
        origin_for(Platform.TELEGRAM, chat_id="tg-2", user_id="u-1"),
        origin_for(Platform.TELEGRAM, chat_id="tg-1", user_id="u-2"),
        origin_for(Platform.TELEGRAM, chat_id="tg-1", user_id="u-1", thread_id="t-9"),
    ):
        refusal = journal_mod.authorize_claim(stored, foreign)
        assert refusal == {"error": "not_authorized"}, foreign.routing_tuple


def test_claim_is_refused_before_the_drop_is_received(journal, journal_mod, origin_for) -> None:
    origin = origin_for()
    entry = _entry(journal, origin)
    assert journal_mod.authorize_claim(entry, origin) == {
        "error": "not_ready",
        "state": "waiting",
    }

    journal.update(entry["drop_id"], state=journal_mod.STATE_EXPIRED)
    assert journal_mod.authorize_claim(journal.get(entry["drop_id"]), origin) == {
        "error": "unavailable",
        "state": "expired",
    }


def test_a_second_claim_is_refused_by_the_journal(journal, journal_mod, origin_for) -> None:
    origin = origin_for()
    entry = _entry(journal, origin)
    journal.update(entry["drop_id"], state=journal_mod.STATE_RECEIVED, claimed_at=100.0)

    refusal = journal_mod.authorize_claim(journal.get(entry["drop_id"]), origin)
    assert refusal["error"] == "unavailable"
    assert "claimed" in refusal.get("detail", "")


# ── M3: a real orphan, not a simulated one ─────────────────────────────────
#
# ``test_a_kill_mid_write_leaves_the_previous_entry_readable`` above monkeypatches
# ``os.replace`` to raise ``KeyboardInterrupt``, which *triggers* ``_write``'s
# ``except BaseException`` cleanup — so the orphan that test is named after can
# never exist. A real SIGKILL runs no cleanup at all, and what it leaves behind is
# a ``.tmp-XXXXXX.json`` file holding a **complete, valid** entry body with the
# same ``drop_id`` as its target.
#
# ``pathlib.Path.glob`` matches dotfiles (unlike ``glob.glob``), so
# ``glob("*.json")`` returned it and ``entries()`` reported the drop twice. Both
# copies then flowed into ``terminal_unannounced``, ``build_announce_text`` named
# the drop twice in one wake, and ``announce_pending`` incremented
# ``announce_attempts`` twice per announce — halving the ``MAX_ANNOUNCE_ATTEMPTS``
# budget. Orphans accumulate across crashes; nothing ever deleted them.


def _real_orphan(journal, drop_id: str = "AAAAAAAAAAAAAAAAAAAAAA"):
    """Exactly what a SIGKILL between ``fsync`` and ``os.replace`` leaves.

    Built by copying a real entry's bytes to a real ``mkstemp`` name in the real
    directory — no monkeypatching, because the defect is that no code runs.
    """
    import tempfile

    good = journal.path_for(drop_id)
    body = good.read_bytes()
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=str(journal.root))
    with os.fdopen(fd, "wb") as handle:
        handle.write(body)
    return Path(tmp_name)


def test_an_orphaned_temp_file_is_not_read_as_a_second_entry(journal, origin_for) -> None:
    """M3. The drop must be reported once, not twice."""
    _entry(journal, origin_for())
    orphan = _real_orphan(journal)
    assert orphan.is_file() and orphan.name.startswith(".tmp-")

    ids = [e["drop_id"] for e in journal.entries()]
    assert ids == ["AAAAAAAAAAAAAAAAAAAAAA"], (
        f"the orphan was read as a duplicate entry: {ids}"
    )
    assert len(journal.entries()) == 1


def test_an_orphan_does_not_double_count_a_terminal_unannounced_drop(
    journal, journal_mod, origin_for
) -> None:
    """The consequence that actually costs something: the announce budget.

    ``announce_pending`` increments ``announce_attempts`` once per entry it is
    handed, so a duplicated entry burns the ``MAX_ANNOUNCE_ATTEMPTS`` budget at
    twice the rate — and a wake that names the same drop twice reads as two
    payloads waiting.
    """
    _entry(journal, origin_for())
    journal.update("AAAAAAAAAAAAAAAAAAAAAA", state=journal_mod.STATE_RECEIVED)
    _real_orphan(journal)

    pending = journal_mod.DropJournal(root=journal.root).terminal_unannounced()
    assert [e["drop_id"] for e in pending] == ["AAAAAAAAAAAAAAAAAAAAAA"]


def test_a_stale_orphan_is_cleaned_up_on_the_next_write(journal, origin_for) -> None:
    """Ignoring them is not enough: they accumulate, one per crash, forever.

    Cleanup is age-gated rather than unconditional, because a *live* temp file
    belonging to a concurrent writer looks exactly the same on disk. The grace has
    to be long enough that no in-flight write can be mistaken for litter.
    """
    _entry(journal, origin_for())
    orphan = _real_orphan(journal)

    # Age it past the grace by moving its mtime, not by sleeping.
    old = time.time() - (journal.ORPHAN_GRACE_SECONDS + 60)
    os.utime(orphan, (old, old))

    journal.update("AAAAAAAAAAAAAAAAAAAAAA", purpose="triggers a write")

    assert not orphan.exists(), "a stale orphan was left to accumulate"
    assert journal.get("AAAAAAAAAAAAAAAAAAAAAA")["purpose"] == "triggers a write"


def test_a_fresh_temp_file_is_never_deleted_by_the_cleanup(journal, origin_for) -> None:
    """A concurrent writer's in-flight temp file must survive another's write.

    Two waiters resolving in the same turn write concurrently — that is why the
    journal is one file per drop in the first place. Unlinking a fresh temp would
    turn this cleanup into the corruption it exists to remove.
    """
    _entry(journal, origin_for())
    fresh = _real_orphan(journal)  # mtime is now

    journal.update("AAAAAAAAAAAAAAAAAAAAAA", purpose="a concurrent write")

    assert fresh.exists(), "an in-flight temp file was deleted by the cleanup"
    # Still not read as an entry, though.
    assert len(journal.entries()) == 1


def test_cleanup_failure_never_breaks_a_write(journal, journal_mod, origin_for, monkeypatch) -> None:
    """Housekeeping is not allowed to be the reason a durable write fails.

    The journal is the only durable thing Drop has. An orphan that cannot be
    unlinked — a read-only directory, a foreign owner — is untidy; a ``create``
    that fails because of it would lose the drop.
    """
    _entry(journal, origin_for())
    orphan = _real_orphan(journal)
    old = time.time() - (journal.ORPHAN_GRACE_SECONDS + 60)
    os.utime(orphan, (old, old))

    def refuse(*_a, **_k):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(journal_mod.Path, "unlink", refuse)
    result = journal.update("AAAAAAAAAAAAAAAAAAAAAA", purpose="still written")
    monkeypatch.undo()

    assert result["purpose"] == "still written"
    assert journal.get("AAAAAAAAAAAAAAAAAAAAAA")["purpose"] == "still written"
