"""Capture and store the REAL ``SessionSource`` for a turn.

One mechanism, one writer, two lookup indices.

**Why not rebuild the source from the bound contextvars?** Because the rebuild is
provably lossy in exactly the fields that decide routing. ``_set_session_env``
propagates platform / chat_id / chat_type / chat_name / thread_id / user_id /
user_name / session_key / message_id / profile and nothing else
(``gateway/run.py:20255-20269``). It drops ``scope_id`` — so
``_thread_metadata_for_source`` cannot derive ``slack_team_id``
(``gateway/platforms/base.py:78-83``) — drops
``parent_chat_id``/``chat_id_alt``/``user_id_alt``, and cannot carry
``delivered_via_upstream_relay``, which is deliberately excluded from
``to_dict`` (``gateway/session.py:194-206``) and is precisely what
``_adapter_for_source`` keys relay delivery off (``gateway/authz_mixin.py:110-119``).
A hand-built source also has no ``_transport_adapter_ref``, so
``_registered_transport_adapter`` returns ``None`` and per-credential transport
provenance is discarded (``:128-149``).

**Why no core change is needed.** ``invoke_hook`` calls ``ret = cb(**kwargs)``
directly and synchronously (``hermes_cli/plugins.py:1933`` via
``hermes_cli/lifecycle.py:11-22``) inside the ``_handle_message`` task, so a
``ContextVar.set()`` here mutates *that* context and is visible for the rest of
the turn — including ``_run_in_executor_with_context``, which snapshots with
``copy_context()`` and runs ``ctx.run`` on the worker
(``gateway/run.py:20276-20285``).

**Why a ContextVar is not enough on its own.** ``copy_context()`` is a copy in
one direction. A ``.set()`` inside the snapshot never escapes back to the
caller, and a later turn gets its own context, so a context-local cannot carry a
source across turns. The registry is the cross-turn path; the ContextVar is only
the same-turn fast path. Both directions are pinned in ``tests/test_sources.py``.

**Why the ContextVar is not trusted.** ``asyncio.create_task`` snapshots the
current context, so a task spawned while a concurrent turn had already set
``_TURN_SOURCE`` inherits that foreign source. Non-internal events overwrite it
within a few statements; **internal** events never run this callback at all
(``gateway/run.py:13633``), so an inherited value can survive a whole wake turn.
``origin.resolve_origin`` therefore verifies whatever it finds against the bound
contextvars and refuses on disagreement.

**Not keyed by ``message_id``.** It is empty on a Discord native slash —
``_build_slash_event`` never sets it
(``plugins/platforms/discord/adapter.py:5814-5856``) — so a ``message_id``-bearing
key is non-unique by construction. That non-uniqueness is the defect that killed
revision 1's origin stamp.

Nothing stored here is secret: a live ``SessionSource``, a weakref to the runner,
a session key, and a timestamp.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
import weakref

logger = logging.getLogger(__name__)

#: ``(platform, profile, chat_id, thread_id)`` — the same tuple claim
#: authorisation binds (§8.5), and the only key available on *every* turn,
#: including an internal wake turn where the capture hook never fires.
RoutingTuple = Tuple[str, str, str, str]

#: Same-turn fast path. Default ``None`` so an un-inherited context reads as
#: "nothing captured here" rather than as someone else's source.
_TURN_SOURCE: ContextVar[Optional[Any]] = ContextVar("hermes_drop_turn_source", default=None)

DEFAULT_MAXLEN = 512
DEFAULT_TTL_SECONDS = 24 * 60 * 60


def _platform_name(platform: Any) -> str:
    """Normalise a ``Platform`` enum or bare string to its wire name."""
    value = getattr(platform, "value", platform)
    return str(value or "")


def routing_tuple_for_source(source: Any) -> RoutingTuple:
    return (
        _platform_name(getattr(source, "platform", None)),
        str(getattr(source, "profile", None) or ""),
        str(getattr(source, "chat_id", None) or ""),
        str(getattr(source, "thread_id", None) or ""),
    )


def routing_tuple_from_context() -> Optional[RoutingTuple]:
    """The routing tuple of the *bound* session, or ``None`` if none is bound.

    Normalised identically to :func:`routing_tuple_for_source` so the two can be
    compared field for field. ``get_session_env`` falls back to ``os.environ``
    only when the ContextVar was never set in this context
    (``gateway/session_context.py:325-331``) — which is the CLI/cron case, not a
    concurrent-gateway case, because ``reset_session_vars()`` runs at handler
    entry (``gateway/run.py:13581-13585``).
    """
    from gateway.session_context import get_session_env

    platform = get_session_env("HERMES_SESSION_PLATFORM").strip()
    chat_id = get_session_env("HERMES_SESSION_CHAT_ID").strip()
    if not platform or not chat_id:
        return None
    return (
        platform,
        get_session_env("HERMES_SESSION_PROFILE").strip(),
        chat_id,
        get_session_env("HERMES_SESSION_THREAD_ID").strip(),
    )


def session_key_from_context() -> str:
    from gateway.session_context import get_session_env

    return get_session_env("HERMES_SESSION_KEY").strip()


@dataclass
class SourceEntry:
    """A stored real source. The field set is a non-secret allowlist (§8.10) and
    ``tests/test_sources.py`` asserts it exactly."""

    source: Any
    runner_ref: Callable[[], Any]
    session_key: str
    stored_at: float


def _dead_ref() -> None:
    return None


class SourceRegistry:
    """Bounded, TTL'd, two-index store of live ``SessionSource`` objects.

    The two indices are genuinely independent, not one index plus an alias. That
    matters for the tier-3 lookup: a ``/new``, a compression rotation, or a
    topic-recovery rewrite can invalidate the routing lane while the session key
    still names the same conversation, so the session-key index has to survive
    the routing entry going away. Both indices are still LRU- and TTL-bounded, so
    neither can grow without limit or serve an arbitrarily old source.

    **Thread-safe by one lock, and it has to be.** This store is read from a
    different thread than it is written from, in ordinary steady state: ``capture``
    and ``DropWaiter._republish`` run on the gateway loop, while ``resolve_origin``
    runs on a ``ThreadPoolExecutor`` worker for every model tool call
    (``gateway/run.py:18604`` -> ``:20276-20285``). Nothing about that is a corner
    case, and ``OrderedDict`` is not safe across it: ``_purge`` iterates
    ``index.items()`` while a concurrent ``_get`` calls ``move_to_end``, which
    bumps the dict version and so counts as a mutation during iteration
    (``RuntimeError``), and at the LRU cap a reader can ``move_to_end`` a key
    another thread just evicted (``KeyError``). Review M1 measured 70 faults in
    four seconds at 40 live lanes with no eviction and no expiry.

    An ``RLock`` rather than a ``Lock``, because the lock-holding methods nest:
    ``put`` calls ``_purge`` and ``_trim``, and ``_get`` calls ``_drop``. A
    non-reentrant lock would deadlock the gateway loop on the first capture.

    The lock is held for the whole of every public method, including the read
    methods and ``keys`` / ``__len__``, because a reader mutates recency and is
    therefore a writer. Contention is not a concern: every critical section is a
    dict operation over a store bounded at ``maxlen``, with no I/O and no await
    inside it.
    """

    def __init__(
        self,
        maxlen: int = DEFAULT_MAXLEN,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.maxlen = maxlen
        self.ttl_seconds = ttl_seconds
        self._clock = clock
        self._by_tuple: "OrderedDict[RoutingTuple, SourceEntry]" = OrderedDict()
        self._by_key: "OrderedDict[str, SourceEntry]" = OrderedDict()
        self._lock = threading.RLock()

    # -- writing ------------------------------------------------------------

    def put(self, source: Any, gateway: Any = None, session_key: Optional[str] = None) -> SourceEntry:
        """Store *source* under both keys. Purges expired entries first."""
        # Resolved before the lock: it reads contextvars/os.environ and has no
        # business inside a critical section.
        key = session_key_from_context() if session_key is None else session_key.strip()
        routing_key = routing_tuple_for_source(source)

        with self._lock:
            now = self._clock()
            self._purge(now)

            entry = SourceEntry(
                source=source,
                runner_ref=weakref.ref(gateway) if gateway is not None else _dead_ref,
                session_key=key,
                stored_at=now,
            )

            self._by_tuple[routing_key] = entry
            self._by_tuple.move_to_end(routing_key)
            self._trim(self._by_tuple)

            # An empty session key would collide across every unrelated session
            # that also lacks one — the same non-uniqueness defect as keying on
            # ``message_id``. Not indexed.
            if key:
                self._by_key[key] = entry
                self._by_key.move_to_end(key)
                self._trim(self._by_key)

            return entry

    # -- reading ------------------------------------------------------------

    def by_routing_tuple(self, key: Optional[RoutingTuple]) -> Optional[SourceEntry]:
        if key is None:
            return None
        with self._lock:
            return self._get(self._by_tuple, key)

    def peek_routing_tuple(self, key: Optional[RoutingTuple]) -> Optional[SourceEntry]:
        """Read a lane **without touching the store**. For observers, not resolvers.

        ``by_routing_tuple`` is a *use*: ``_get`` refreshes LRU order and evicts
        an entry it finds expired. The reconciler's retry gate asks about lanes it
        is not about to use, on every inbound dispatch, so answering it through
        ``by_routing_tuple`` would let a background check reorder the store —
        promoting whichever deferred lane was polled last over the lanes that are
        actually speaking, and doing it under the ``maxlen`` trim that decides
        which lane gets evicted next.

        Expiry is still honoured, because a stale entry is not an answer. It is
        simply left in place for the next real write to purge, rather than
        deleted by a reader.
        """
        if key is None:
            return None
        with self._lock:
            entry = self._by_tuple.get(key)
            if entry is None or self._expired(entry, self._clock()):
                return None
            return entry

    def by_session_key(self, key: Optional[str]) -> Optional[SourceEntry]:
        if not key:
            return None
        with self._lock:
            return self._get(self._by_key, key.strip())

    # -- maintenance --------------------------------------------------------

    def forget_routing_tuple(self, key: RoutingTuple) -> None:
        """Drop one routing entry, leaving the session-key index alone.

        Used when a lane is known to have drifted. Exposed because the
        alternative — waiting for the TTL — would keep serving a stale lane for
        up to 24 h.
        """
        with self._lock:
            self._by_tuple.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._by_tuple.clear()
            self._by_key.clear()

    def keys(self) -> List[Any]:
        with self._lock:
            return list(self._by_tuple.keys()) + list(self._by_key.keys())

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_tuple)

    # -- internals ----------------------------------------------------------
    #
    # Every method below assumes the lock is already held. They are only ever
    # reached from the public methods above, each of which takes it.

    def _get(self, index: "OrderedDict[Any, SourceEntry]", key: Any) -> Optional[SourceEntry]:
        entry = index.get(key)
        if entry is None:
            return None
        if self._expired(entry, self._clock()):
            self._drop(entry)
            return None
        index.move_to_end(key)
        return entry

    def _expired(self, entry: SourceEntry, now: float) -> bool:
        return (now - entry.stored_at) > self.ttl_seconds

    def _purge(self, now: float) -> None:
        for index in (self._by_tuple, self._by_key):
            for key in [k for k, e in index.items() if self._expired(e, now)]:
                index.pop(key, None)

    def _drop(self, entry: SourceEntry) -> None:
        """Remove one entry from both indices, wherever it appears."""
        for index in (self._by_tuple, self._by_key):
            for key in [k for k, e in index.items() if e is entry]:
                index.pop(key, None)

    def _trim(self, index: "OrderedDict[Any, SourceEntry]") -> None:
        while len(index) > self.maxlen:
            index.popitem(last=False)


#: The one production store. ``capture`` writes here; ``resolve_origin`` reads
#: here. The ``registry=`` keyword on both exists for tests, so production keeps
#: a single writer and a single store.
REGISTRY = SourceRegistry()


def turn_source() -> Optional[Any]:
    """The source captured *in this context*, if any. Never verified here."""
    return _TURN_SOURCE.get()


def capture(
    *,
    event: Any = None,
    gateway: Any = None,
    registry: Optional[SourceRegistry] = None,
    session_key: Optional[str] = None,
    **_ignored: Any,
) -> None:
    """The capture half of the ``pre_gateway_dispatch`` callback. Observes only.

    Returns ``None`` unconditionally — never ``{"action": "skip"}``, never
    ``{"action": "rewrite"}``. Since S10 the callback in ``__init__.py`` returns
    ``None`` too: ``/drop`` is dispatched by core to the registered handler, so
    nothing in this plugin transforms a message. Capture stays a pure observation
    regardless, so a change to what ``/drop`` does can never change what gets
    stored.

    Never raises. ``invoke_hook`` would swallow an exception with a warning
    (``hermes_cli/plugins.py:1938-1945``), which would leave the store silently
    half-written and every later origin lookup refusing for no visible reason.

    ``**_ignored`` absorbs the kwargs core passes that this callback does not
    need (``session_store``, ``telemetry_schema_version``) plus any core adds
    later, so a new kwarg upstream cannot turn into a swallowed ``TypeError``.
    """
    source = getattr(event, "source", None) if event is not None else None
    if source is None:
        return None
    try:
        _TURN_SOURCE.set(source)
        (registry if registry is not None else REGISTRY).put(
            source, gateway=gateway, session_key=session_key
        )
    except Exception:
        logger.warning("hermes-drop: source capture failed", exc_info=True)
    return None


__all__ = [
    "DEFAULT_MAXLEN",
    "DEFAULT_TTL_SECONDS",
    "REGISTRY",
    "RoutingTuple",
    "SourceEntry",
    "SourceRegistry",
    "capture",
    "routing_tuple_for_source",
    "routing_tuple_from_context",
    "session_key_from_context",
    "turn_source",
]
