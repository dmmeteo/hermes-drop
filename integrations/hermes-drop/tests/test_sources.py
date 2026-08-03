"""S4 — capturing and storing the REAL ``SessionSource``.

The premise, restated so the tests below read as consequences of it:
reconstructing a source from the bound contextvars is *provably* lossy in
exactly the fields that decide routing. ``_set_session_env`` propagates only
platform / chat_id / chat_type / chat_name / thread_id / user_id / user_name /
session_key / message_id / profile (``gateway/run.py:20255-20269``). It omits
``scope_id`` — so ``_thread_metadata_for_source`` cannot derive
``slack_team_id`` (``gateway/platforms/base.py:78-83``) — omits
``parent_chat_id``/``chat_id_alt``/``user_id_alt``, and cannot carry
``delivered_via_upstream_relay``, which is deliberately excluded from
``to_dict`` (``gateway/session.py:194-206``) and is exactly what
``_adapter_for_source`` keys relay delivery off
(``gateway/authz_mixin.py:110-119``). A hand-built source also has no
``_transport_adapter_ref``, so ``_registered_transport_adapter`` returns
``None`` (``:128-149``).

Hence: capture the real object, store it, and never rebuild one.

── ContextVar propagation, resolved against actual ``copy_context`` behaviour ──

The plan asserts a plugin ContextVar "propagates into the worker thread with no
core change". That is true, and it is only true in one direction. The three
tests below pin all three directions, because the design depends on knowing
which is which:

1. **Forward, into a snapshot.** ``invoke_hook`` calls ``ret = cb(**kwargs)``
   directly and synchronously (``hermes_cli/plugins.py:1933`` via
   ``hermes_cli/lifecycle.py:11-22``), so a ``.set()`` inside the callback
   mutates ``_handle_message``'s own context. ``_run_in_executor_with_context``
   later snapshots with ``copy_context()`` and runs ``ctx.run`` on the worker
   (``gateway/run.py:20276-20285``). The value is in the snapshot. ✔

2. **Backward, out of a snapshot: NO.** ``copy_context`` is a *copy*. A
   ``.set()`` performed inside ``ctx.run`` — or inside a child task — is
   invisible to the caller. This is the reason ``SourceRegistry`` exists at all:
   a context-local alone cannot carry a source from one turn to a later one, so
   the cross-turn path has to be an ordinary module-level store.

3. **Sideways, by inheritance: YES, and that is the hazard.**
   ``asyncio.create_task`` snapshots the *current* context, so a task spawned
   while a concurrent turn had already set ``_TURN_SOURCE`` inherits that
   foreign source. For non-internal events our own callback overwrites it within
   a few statements; for **internal** events the callback never runs
   (``gateway/run.py:13633``), so the inherited value can survive a whole wake
   turn. That is the same failure class ``reset_session_vars`` exists for
   (``gateway/session_context.py:260-305``), and it is why §4's verification is
   mandatory rather than defensive — see ``test_origin.py``.
"""

from __future__ import annotations

import asyncio
import contextvars
import time
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context

import pytest
from gateway.config import Platform

from _stubs import StubAdapter, bind_session_context
from conftest import load_plugin_package


@pytest.fixture
def sources():
    return load_plugin_package().drop.sources


@pytest.fixture
def registry(sources):
    return sources.SourceRegistry()


def make_event(source):
    """A minimal stand-in for ``MessageEvent`` — the hook only reads ``.source``."""

    class _Event:
        pass

    event = _Event()
    event.source = source
    return event


def telegram_source(chat_id: str = "tg-chat-1", thread_id=None):
    adapter = StubAdapter(Platform.TELEGRAM)
    source = adapter.build_source(
        chat_id=chat_id,
        chat_type="dm",
        user_id="tg-user-1",
        thread_id=thread_id,
        message_id="tg-msg-9",
    )
    return adapter, source


# ── capture ────────────────────────────────────────────────────────────────


def test_capture_stores_the_identical_source_object(sources, registry) -> None:
    adapter, source = telegram_source()
    sources.capture(event=make_event(source), gateway=None, registry=registry)

    assert sources.turn_source() is source
    entry = registry.by_routing_tuple(sources.routing_tuple_for_source(source))
    assert entry is not None
    assert entry.source is source, "the registry must hold the real object, not a copy"


def test_capture_preserves_provenance_a_reconstruction_would_lose(sources, registry) -> None:
    adapter = StubAdapter(Platform.SLACK)
    source = adapter.build_source(
        chat_id="C123",
        chat_type="channel",
        user_id="U1",
        thread_id="1712.5",
        scope_id="T-WORKSPACE",
        parent_chat_id="C-PARENT",
        chat_id_alt="C-ALT",
        user_id_alt="U-ALT",
    )
    sources.capture(event=make_event(source), registry=registry)

    stored = registry.by_routing_tuple(sources.routing_tuple_for_source(source)).source
    assert stored.scope_id == "T-WORKSPACE"
    assert stored.parent_chat_id == "C-PARENT"
    assert stored.chat_id_alt == "C-ALT"
    assert stored.user_id_alt == "U-ALT"
    assert stored._transport_adapter_ref() is adapter


def test_capture_never_skips_and_never_rewrites(sources, registry) -> None:
    """Returning a dict here would change what the message does. S4's hook only
    observes. Since S10 the ``pre_gateway_dispatch`` callback in ``__init__.py``
    returns ``None`` too, so no layer of this plugin transforms a message."""
    _, source = telegram_source()
    assert sources.capture(event=make_event(source), registry=registry) is None


def test_capture_tolerates_a_missing_event_or_source(sources, registry) -> None:
    """``invoke_hook`` swallows exceptions with a warning
    (``hermes_cli/plugins.py:1938-1945``), so a raise here would be invisible
    *and* would leave the registry half-written. It must simply not raise."""
    assert sources.capture(registry=registry) is None
    assert sources.capture(event=None, registry=registry) is None
    assert sources.capture(event=make_event(None), registry=registry) is None
    assert len(registry) == 0
    assert sources.turn_source() is None


def test_capture_stores_no_secret_bearing_fields(sources, registry) -> None:
    """Journal/registry contents are a fixed non-secret allowlist (§8.10)."""
    _, source = telegram_source()
    sources.capture(event=make_event(source), registry=registry)
    entry = registry.by_routing_tuple(sources.routing_tuple_for_source(source))

    assert set(vars(entry)) == {"source", "runner_ref", "session_key", "stored_at"}


# ── ContextVar propagation semantics ───────────────────────────────────────


def test_contextvar_reaches_a_worker_thread_through_copy_context(sources, registry) -> None:
    """Direction 1: forward, into a ``copy_context()`` snapshot. This mirrors
    ``_run_in_executor_with_context`` exactly (``gateway/run.py:20276-20285``)."""
    _, source = telegram_source()
    sources.capture(event=make_event(source), registry=registry)

    ctx = copy_context()
    with ThreadPoolExecutor(max_workers=1) as pool:
        observed = pool.submit(ctx.run, sources.turn_source).result(timeout=10)

    assert observed is source


def test_a_set_inside_the_snapshot_does_not_escape_back(sources, registry) -> None:
    """Direction 2: backward — it does NOT propagate. This is why the registry
    is a module-level store and not just a ContextVar."""
    _, outer = telegram_source(chat_id="outer")
    sources.capture(event=make_event(outer), registry=registry)
    _, inner = telegram_source(chat_id="inner")

    ctx = copy_context()

    def set_inside():
        sources.capture(event=make_event(inner), registry=registry)
        return sources.turn_source()

    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(ctx.run, set_inside).result(timeout=10) is inner

    assert sources.turn_source() is outer, "a child context leaked its set upward"
    # ...but the registry DID see it, which is the whole point of having one.
    assert registry.by_routing_tuple(sources.routing_tuple_for_source(inner)).source is inner


@pytest.mark.asyncio
async def test_two_concurrent_turns_do_not_see_each_others_source(sources, registry) -> None:
    _, first = telegram_source(chat_id="tg-A")
    _, second = telegram_source(chat_id="tg-B")
    seen: dict = {}
    gate = asyncio.Event()

    async def turn(name, source):
        sources.capture(event=make_event(source), registry=registry)
        # Interleave deliberately: both tasks have captured before either reads.
        gate.set()
        await gate.wait()
        await asyncio.sleep(0)
        seen[name] = sources.turn_source()

    # Each task gets its own context copy, taken from a context where
    # _TURN_SOURCE is still unset.
    await asyncio.gather(
        asyncio.create_task(turn("A", first), context=contextvars.copy_context()),
        asyncio.create_task(turn("B", second), context=contextvars.copy_context()),
    )

    assert seen["A"] is first
    assert seen["B"] is second


@pytest.mark.asyncio
async def test_a_child_task_inherits_a_foreign_source(sources, registry) -> None:
    """Direction 3: sideways. Documented as a hazard, not a feature — the
    verification in ``resolve_origin`` is what makes it safe."""
    _, foreign = telegram_source(chat_id="foreign")
    sources.capture(event=make_event(foreign), registry=registry)

    async def child():
        return sources.turn_source()

    assert await asyncio.create_task(child()) is foreign


# ── the store ──────────────────────────────────────────────────────────────


def test_routing_tuple_is_the_four_fields_claim_authorisation_shares(sources) -> None:
    adapter = StubAdapter(Platform.DISCORD)
    source = adapter.build_source(
        chat_id="c-1", chat_type="channel", user_id="u", thread_id="t-1", scope_id="g-1"
    )
    source.profile = "secondary"
    assert sources.routing_tuple_for_source(source) == ("discord", "secondary", "c-1", "t-1")


def test_routing_tuple_normalises_absent_profile_and_thread(sources) -> None:
    _, source = telegram_source()
    assert sources.routing_tuple_for_source(source) == ("telegram", "", "tg-chat-1", "")


def test_no_registry_key_is_derived_from_message_id(sources, registry) -> None:
    """``message_id`` is empty on a Discord native slash — ``_build_slash_event``
    never sets it (``plugins/platforms/discord/adapter.py:5814-5856``) — so a
    ``message_id``-bearing key is non-unique by construction. It is the defect
    that killed revision 1's origin stamp, and it must not reappear."""
    adapter = StubAdapter(Platform.DISCORD)
    source = adapter.build_source(chat_id="c-1", chat_type="channel", user_id="u")
    assert source.message_id is None

    sources.capture(event=make_event(source), registry=registry)
    for key in registry.keys():
        assert "message_id" not in str(key)
    assert registry.by_routing_tuple(("discord", "", "c-1", "")) is not None


def test_two_concurrent_drops_in_one_channel_never_produce_an_ambiguous_key(
    sources, registry
) -> None:
    """Both have an empty ``message_id`` and both route to the same place, so they
    share one routing tuple — deliberately. What must not happen is an *empty*
    discriminator silently merging two lanes that differ, so distinct threads
    stay distinct and the shared lane resolves to the newest real source."""
    adapter = StubAdapter(Platform.DISCORD)
    first = adapter.build_source(chat_id="c-1", chat_type="channel", user_id="u")
    second = adapter.build_source(chat_id="c-1", chat_type="channel", user_id="u")
    threaded = adapter.build_source(
        chat_id="c-1", chat_type="thread", user_id="u", thread_id="t-9"
    )

    for src in (first, second, threaded):
        sources.capture(event=make_event(src), registry=registry, session_key="")

    assert sources.routing_tuple_for_source(first) == sources.routing_tuple_for_source(second)
    assert sources.routing_tuple_for_source(threaded) != sources.routing_tuple_for_source(first)
    assert registry.by_routing_tuple(("discord", "", "c-1", "")).source is second
    assert registry.by_routing_tuple(("discord", "", "c-1", "t-9")).source is threaded


def test_registry_evicts_least_recently_used_past_maxlen(sources) -> None:
    registry = sources.SourceRegistry(maxlen=3)
    adapter = StubAdapter(Platform.TELEGRAM)
    made = []
    for i in range(5):
        source = adapter.build_source(chat_id=f"c-{i}", chat_type="dm", user_id="u")
        sources.capture(event=make_event(source), registry=registry, session_key=f"s-{i}")
        made.append(source)

    assert len(registry) == 3
    assert registry.by_routing_tuple(("telegram", "", "c-0", "")) is None
    assert registry.by_routing_tuple(("telegram", "", "c-1", "")) is None
    assert registry.by_routing_tuple(("telegram", "", "c-4", "")).source is made[4]
    # The session-key index is evicted in lockstep, so it can never resolve an
    # entry the routing index has already dropped.
    assert registry.by_session_key("s-0") is None
    assert registry.by_session_key("s-4").source is made[4]


def test_a_lookup_refreshes_recency(sources) -> None:
    registry = sources.SourceRegistry(maxlen=2)
    adapter = StubAdapter(Platform.TELEGRAM)
    a = adapter.build_source(chat_id="a", chat_type="dm", user_id="u")
    b = adapter.build_source(chat_id="b", chat_type="dm", user_id="u")
    sources.capture(event=make_event(a), registry=registry, session_key="sa")
    sources.capture(event=make_event(b), registry=registry, session_key="sb")

    registry.by_routing_tuple(("telegram", "", "a", ""))  # touch a
    c = adapter.build_source(chat_id="c", chat_type="dm", user_id="u")
    sources.capture(event=make_event(c), registry=registry, session_key="sc")

    assert registry.by_routing_tuple(("telegram", "", "a", "")) is not None
    assert registry.by_routing_tuple(("telegram", "", "b", "")) is None


def test_registry_expires_entries_past_the_ttl(sources) -> None:
    clock = {"now": 1000.0}
    registry = sources.SourceRegistry(ttl_seconds=60, clock=lambda: clock["now"])
    adapter = StubAdapter(Platform.TELEGRAM)
    source = adapter.build_source(chat_id="c-1", chat_type="dm", user_id="u")
    sources.capture(event=make_event(source), registry=registry, session_key="s-1")

    clock["now"] = 1059.0
    assert registry.by_routing_tuple(("telegram", "", "c-1", "")) is not None

    clock["now"] = 1061.0
    assert registry.by_routing_tuple(("telegram", "", "c-1", "")) is None
    assert registry.by_session_key("s-1") is None
    assert len(registry) == 0


def test_default_bounds_match_the_plan(sources) -> None:
    registry = sources.SourceRegistry()
    assert registry.maxlen == 512
    assert registry.ttl_seconds == 24 * 60 * 60


def test_a_write_purges_expired_entries(sources) -> None:
    clock = {"now": 0.0}
    registry = sources.SourceRegistry(ttl_seconds=10, clock=lambda: clock["now"])
    adapter = StubAdapter(Platform.TELEGRAM)
    stale = adapter.build_source(chat_id="stale", chat_type="dm", user_id="u")
    sources.capture(event=make_event(stale), registry=registry, session_key="stale")

    clock["now"] = 100.0
    fresh = adapter.build_source(chat_id="fresh", chat_type="dm", user_id="u")
    sources.capture(event=make_event(fresh), registry=registry, session_key="fresh")

    assert len(registry) == 1
    assert registry.by_routing_tuple(("telegram", "", "fresh", "")) is not None


def test_registry_keeps_only_a_weak_reference_to_the_runner(sources, registry) -> None:
    """A strong ref would keep a dead ``GatewayRunner`` — and every adapter and
    open socket it owns — alive for the entry's whole 24 h TTL."""
    import gc

    _, source = telegram_source()

    class Runner:
        pass

    runner = Runner()
    sources.capture(event=make_event(source), gateway=runner, registry=registry)
    entry = registry.by_routing_tuple(sources.routing_tuple_for_source(source))
    assert entry.runner_ref() is runner

    del runner
    gc.collect()
    assert entry.runner_ref() is None


# ── reading the routing tuple back off the bound context ───────────────────


def test_routing_tuple_from_context_matches_the_bound_session(sources) -> None:
    """This is the lookup a wake turn depends on: it is available on *every*
    turn, including an internal one where the capture hook never fires."""
    tokens = bind_session_context(
        platform="telegram", chat_id="tg-chat-1", thread_id="77", profile="secondary"
    )
    try:
        assert sources.routing_tuple_from_context() == ("telegram", "secondary", "tg-chat-1", "77")
    finally:
        from gateway.session_context import clear_session_vars

        clear_session_vars(tokens)


def test_routing_tuple_from_context_is_none_when_nothing_is_bound(sources) -> None:
    assert sources.routing_tuple_from_context() is None


def test_wake_turn_finds_the_initiating_source_by_routing_tuple(sources, registry) -> None:
    """The initiating turn captures; a later internal wake turn — where
    ``pre_gateway_dispatch`` never fires (``gateway/run.py:13633``) — resolves the
    same real source from the bound context alone."""
    adapter = StubAdapter(Platform.TELEGRAM)
    source = adapter.build_source(
        chat_id="tg-chat-1", chat_type="dm", user_id="u-1", thread_id="topic-4"
    )
    sources.capture(event=make_event(source), registry=registry, session_key="sess-1")

    tokens = bind_session_context(
        platform="telegram", chat_id="tg-chat-1", thread_id="topic-4", session_key="sess-1"
    )
    try:
        found = registry.by_routing_tuple(sources.routing_tuple_from_context())
        assert found is not None and found.source is source
    finally:
        from gateway.session_context import clear_session_vars

        clear_session_vars(tokens)


def test_session_key_index_is_a_second_route_to_the_same_entry(sources, registry) -> None:
    _, source = telegram_source()
    sources.capture(event=make_event(source), registry=registry, session_key="sess-abc")

    by_tuple = registry.by_routing_tuple(sources.routing_tuple_for_source(source))
    by_key = registry.by_session_key("sess-abc")
    assert by_key is by_tuple


def test_empty_session_key_is_not_indexed(sources, registry) -> None:
    """An empty key would collide across every unrelated session that also has
    none — the same non-uniqueness defect as keying on ``message_id``."""
    _, source = telegram_source()
    sources.capture(event=make_event(source), registry=registry, session_key="")
    assert registry.by_session_key("") is None
    assert registry.by_routing_tuple(sources.routing_tuple_for_source(source)) is not None


def test_the_module_level_registry_is_the_one_the_hook_writes_to(sources) -> None:
    """``capture`` defaults to the shared registry; the ``registry=`` kwarg exists
    for tests only, so the production path has a single writer and a single
    store."""
    assert isinstance(sources.REGISTRY, sources.SourceRegistry)
    _, source = telegram_source(chat_id=f"shared-{time.monotonic_ns()}")
    try:
        sources.capture(event=make_event(source))
        assert sources.REGISTRY.by_routing_tuple(
            sources.routing_tuple_for_source(source)
        ).source is source
    finally:
        sources.REGISTRY.clear()


# ── M1: concurrent access ──────────────────────────────────────────────────
#
# Production has one writer thread and N reader threads. ``capture`` and
# ``DropWaiter._republish`` run on the gateway loop; ``resolve_origin`` runs on a
# ``ThreadPoolExecutor`` worker for every model tool call
# (``gateway/run.py:18604`` -> ``:20276-20285``). ``_purge`` — called on *every*
# ``put`` — iterated ``index.items()`` in a list comprehension while a reader's
# ``_get`` did ``index.move_to_end(key)``, which bumps the dict version and
# therefore counts as a mutation during iteration.
#
# Neither of the two isolation tests above reaches this: one tests ContextVar
# isolation, the other runs a single worker with no concurrent writer. Nothing
# exercised simultaneous ``put`` / ``_get``, which is ordinary steady state.
#
# These run with **no eviction and no TTL expiry** on purpose. A hammer that
# needed the LRU cap or an expiry to fail could be dismissed as a corner; this
# one is the normal case.


def _hammer(registry, sources, *, lanes: int, seconds: float, readers: int):
    """One writer and *readers* readers over *lanes* live lanes. Returns faults.

    Every exception is captured with its thread role rather than raised, so a
    failure names what raced with what instead of surfacing as whichever thread
    happened to lose first.
    """
    import threading

    adapters_and_sources = [
        telegram_source(chat_id=f"tg-chat-{i}", thread_id=f"t-{i}") for i in range(lanes)
    ]
    keys = [sources.routing_tuple_for_source(s) for _a, s in adapters_and_sources]
    session_keys = [f"sess-{i}" for i in range(lanes)]

    stop = threading.Event()
    faults: list = []
    lock = threading.Lock()

    def record(role: str, exc: BaseException) -> None:
        with lock:
            faults.append((role, type(exc).__name__, str(exc)))

    def writer() -> None:
        i = 0
        try:
            while not stop.is_set():
                _adapter, source = adapters_and_sources[i % lanes]
                registry.put(source, gateway=None, session_key=session_keys[i % lanes])
                i += 1
        except BaseException as exc:  # noqa: BLE001 - the whole point is to see it
            record("writer", exc)

    def reader(n: int) -> None:
        i = 0
        try:
            while not stop.is_set():
                registry.by_routing_tuple(keys[(i + n) % lanes])
                registry.by_session_key(session_keys[(i + n) % lanes])
                i += 1
        except BaseException as exc:  # noqa: BLE001
            record(f"reader-{n}", exc)

    threads = [threading.Thread(target=writer, name="hammer-writer", daemon=True)]
    threads += [
        threading.Thread(target=reader, args=(n,), name=f"hammer-reader-{n}", daemon=True)
        for n in range(readers)
    ]
    for t in threads:
        t.start()
    time.sleep(seconds)
    stop.set()
    for t in threads:
        t.join(timeout=10)
        assert not t.is_alive(), f"{t.name} did not stop"
    return faults


def test_concurrent_reads_during_writes_raise_nothing(sources) -> None:
    """M1. Ordinary steady state: 40 live lanes, no eviction, no expiry.

    Pre-fix this produced ``RuntimeError: OrderedDict mutated during iteration``
    from ``_purge``'s comprehension within a second or two. The write side was
    contained (``capture`` catches and warns) but silently lost the *cross-turn*
    index entry, so a later internal wake turn missed tiers 2 and 3 and
    ``request_private_input`` refused ``no_origin``. The read side was not
    contained at all: ``resolve_origin`` documents "Never raises" and does not
    wrap ``by_routing_tuple``.
    """
    registry = sources.SourceRegistry(maxlen=100_000, ttl_seconds=24 * 60 * 60)
    faults = _hammer(registry, sources, lanes=40, seconds=2.0, readers=4)
    assert faults == [], f"{len(faults)} concurrent-access faults: {faults[:5]}"


def test_concurrent_access_at_the_lru_cap_raises_nothing(sources) -> None:
    """The same, with eviction and expiry both active.

    A tiny ``maxlen`` makes ``_trim`` pop on nearly every write and a short TTL
    makes ``_get``'s expiry branch call ``_drop`` — which itself iterates both
    indices. Pre-fix this added ``KeyError`` from ``move_to_end`` on a key another
    thread had just evicted, on top of the ``RuntimeError``.
    """
    registry = sources.SourceRegistry(maxlen=8, ttl_seconds=0.05)
    faults = _hammer(registry, sources, lanes=40, seconds=2.0, readers=4)
    assert faults == [], f"{len(faults)} concurrent-access faults: {faults[:5]}"


def test_maintenance_operations_are_serialised_against_readers(sources) -> None:
    """``clear``, ``forget_routing_tuple``, ``keys`` and ``len`` race too.

    ``keys()`` builds two lists from both indices and ``clear()`` empties them;
    a reader mid-``_get`` must not see a half-cleared store or raise from it.
    These are on the same lock as the rest, so this pins that the lock actually
    spans them rather than just the obvious pair.
    """
    import threading

    registry = sources.SourceRegistry(maxlen=100_000)
    _adapter, source = telegram_source(chat_id="tg-chat-x", thread_id="t-x")
    key = sources.routing_tuple_for_source(source)

    stop = threading.Event()
    faults: list = []

    def churn() -> None:
        try:
            while not stop.is_set():
                registry.put(source, gateway=None, session_key="sess-x")
                registry.keys()
                len(registry)
                registry.forget_routing_tuple(key)
                registry.clear()
        except BaseException as exc:  # noqa: BLE001
            faults.append((type(exc).__name__, str(exc)))

    def read() -> None:
        try:
            while not stop.is_set():
                registry.by_routing_tuple(key)
                registry.by_session_key("sess-x")
        except BaseException as exc:  # noqa: BLE001
            faults.append((type(exc).__name__, str(exc)))

    threads = [
        threading.Thread(target=churn, daemon=True),
        threading.Thread(target=read, daemon=True),
        threading.Thread(target=read, daemon=True),
    ]
    for t in threads:
        t.start()
    time.sleep(1.5)
    stop.set()
    for t in threads:
        t.join(timeout=10)
    assert faults == [], f"maintenance/read faults: {faults[:5]}"


def test_the_lock_is_reentrant_because_put_calls_purge_which_locks_too(sources) -> None:
    """A plain ``Lock`` would deadlock the first ``put``.

    ``put`` -> ``_purge`` and ``_get`` -> ``_drop`` are both lock-holding methods
    calling lock-holding methods, so the lock has to be an ``RLock``. Asserting
    the *type* pins the reason: a future edit that "simplifies" it to ``Lock``
    would hang the gateway loop on the next capture rather than fail a test
    somewhere subtle.
    """
    import threading

    registry = sources.SourceRegistry()
    assert isinstance(registry._lock, type(threading.RLock())), (
        "put/_purge and _get/_drop nest, so the lock must be reentrant"
    )

    # And it genuinely works: an expiring entry makes _get call _drop under the
    # same lock. Without reentrancy this call never returns.
    registry_short = sources.SourceRegistry(ttl_seconds=0.0)
    _adapter, source = telegram_source(chat_id="tg-chat-r")
    registry_short.put(source, gateway=None, session_key="sess-r")
    time.sleep(0.01)
    assert registry_short.by_routing_tuple(sources.routing_tuple_for_source(source)) is None
