"""What runs when the fast path did not.

The waiter (S7) is the latency path. This is the mechanism that has to be right
when there is no waiter: after a gateway restart, after a wake the busy handler
dropped, after a crash mid-turn. It reads the journal — the only durable thing
Drop has — and drives every entry it finds to the state the world is actually in.

**Why it needs its own trigger.** ``pre_gateway_dispatch`` is the only
``invoke_hook`` site in ``gateway/run.py`` (``:13636``), it fires only for
non-internal events (``:13633``), and no gateway-ready hook exists (``VALID_HOOKS``,
``hermes_cli/plugins.py:135-215``). After a restart with no user message, nothing
would ever run, and the status message would keep advertising a link the
in-memory broker destroyed at startup (``src/broker.js:95-102``). So there are
two triggers — a bounded startup daemon thread and the dispatch hook — behind one
test-and-set latch, which is what makes "exactly once per process" hold no matter
which fires first.

**Why the startup thread writes nothing until it finds a runner.** Plugin
discovery happens in every CLI process. ``hermes plugins list`` must not create
``$HERMES_HOME/state/hermes-drop``, so the journal is never even constructed
until a live ``GatewayRunner`` and its loop exist. Pinned by
``test_reconciler.py::test_a_bounded_poll_that_never_finds_a_runner_exits_quietly``.

**How liveness is decided.** The control protocol has three ops and one uniform
``unavailable`` body, so a destroyed record and a live pending one answer alike —
except in *timing*, which the contract documents as deliberate: ``await`` "blocks
only for a live pending handoff and therefore leaks liveness to its local caller
by construction" (``contract/control-protocol.json``; ``src/broker.js:315-341``).
So the probe is a bounded ``await`` whose *elapsed time* is the verdict. The
misjudgement direction is safe by construction: the broker cannot answer before
its own timer, so an early answer proves the record was not live — while a late
answer to a gone record only mislabels it ``live``, and re-arming a waiter on a
gone record resolves it to ``expired`` a moment later anyway.

**Origin resolution here is not ``resolve_origin``.** That function verifies
against bound session contextvars, which is exactly right inside a turn and
meaningless in a background pass where none are bound. Here the *journal entry's*
routing tuple is the authority, and the source registry is consulted only to find
the live ``SessionSource`` object for that lane — never for drop identity, which
is the journal id and nothing else.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from . import announce as announce_mod
from . import journal as journal_mod
from . import sources as sources_mod

logger = logging.getLogger(__name__)

VERDICT_SUBMITTED = "submitted"
VERDICT_LIVE = "live"
VERDICT_GONE = "gone"
VERDICT_UNKNOWN = "unknown"

#: How long the liveness probe is willing to park. Long enough that a parked
#: answer is unmistakable next to an immediate one over a local socket, short
#: enough that a startup pass over many entries stays quick.
DEFAULT_PROBE_MS = 750

#: An answer arriving before this fraction of the probe window proves the broker
#: did not park, i.e. the record was not live-pending.
_LIVE_FRACTION = 0.5

#: Bounded discovery for the startup trigger: a gateway that has not appeared
#: within a minute is not going to.
DEFAULT_POLL_INTERVAL = 1.0
DEFAULT_MAX_POLLS = 60

#: §3.3's second re-announce condition: ``received`` and still unclaimed past a
#: grace. A wake that landed but was merged into an unrelated turn, or landed in
#: a turn the model never acted on, leaves a payload sitting in the broker until
#: its TTL. Re-announcing is bounded by ``MAX_ANNOUNCE_ATTEMPTS`` like every other
#: announce, so this cannot become a loop.
RECLAIM_GRACE_SECONDS = 900.0

#: How many *failed* passes are retried before the latch stays shut for good.
#:
#: The latch is consumed before a pass runs, so a pass that fails has to release
#: it or reconciliation is dead for the life of the process (review M2). But an
#: unconditional release turns a permanently stuck condition — a full disk, a
#: read-only ``$HERMES_HOME`` — into a reconcile pass on *every inbound message*,
#: each one re-probing every live drop over the control socket. So retry is
#: bounded, in the same shape as ``MAX_ANNOUNCE_ATTEMPTS``: try a few times, then
#: stop and stay quiet. The user still has the edited status message and the model
#: can still claim; what is lost is only the background sweep.
MAX_FAILED_PASSES = 5

#: How many passes in a row may defer before the latch stays shut.
#:
#: Counted the same way as ``MAX_FAILED_PASSES`` — this many passes, then stop —
#: so the two bounds read alike rather than one counting passes and the other
#: counting the re-opens between them.
#:
#: The backstop under :func:`_deferred_pass_can_make_progress`. The gate already
#: refuses to spend a pass until a deferred lane resolves, so in the ordinary
#: restart this is never approached: each retry either drives the lane it was
#: opened for — which is progress, and resets the count — or it does not, and the
#: gate shuts again. What the count bounds is the case the gate cannot see: a lane
#: that resolves when the gate asks and fails to resolve when the pass asks a
#: moment later, over and over. Larger than ``MAX_FAILED_PASSES`` because a
#: deferral is not a fault and costs no probe and no write, and because the number
#: of legitimate retries scales with the number of quiet conversations.
MAX_DEFERRED_PASSES = 20

#: How many times one drop's status edit is retried before it is left alone.
#:
#: A separate, per-drop bound, deliberately not the pass-level one: an adapter
#: that refuses an edit for one message is not a reason to stop reconciling
#: everything else, and three attempts across three passes is already well past
#: the transient-failure case that retrying is for.
MAX_EDIT_RETRIES = 3

_LATCH = threading.Lock()
_started = False
_failed_passes = 0
_deferred_passes = 0
#: Every lane some pass has deferred on and that has not been driven since.
#: Accumulated on the failure path (whose enumeration may have stopped early) and
#: *replaced* by a completed deferred pass (whose enumeration is authoritative).
#: Read for observability whether or not the latch is currently gated on it.
_deferred_lanes: frozenset = frozenset()
#: Is the currently-open latch gated on ``_deferred_lanes``? A failure release is
#: ungated — it must retry in whichever lane speaks next — while still carrying
#: the lanes, so the two accounts stay separate instead of erasing each other.
_deferred_gated = False
#: The deferred budget is gone and the latch will not open again for a deferral.
#: Kept as its own flag so the gate can answer in O(1) instead of walking lanes it
#: has already decided not to act on, on every inbound message, forever.
_deferred_spent = False

#: ``{drop_id: attempts}`` for status edits that failed and are being retried.
#: Process-local on purpose: it is a retry budget, not a fact about the drop, and
#: a new process facing a new adapter has earned a fresh one. Nothing here is
#: durable and nothing here decides an outcome.
_EDIT_RETRIES: Dict[str, int] = {}
_EDIT_LOCK = threading.Lock()

_shutdown = threading.Event()
_startup_thread: Optional[threading.Thread] = None


# ── the one-shot latch and its two triggers ────────────────────────────────


def _claim_trigger() -> bool:
    """Test-and-set. ``True`` exactly once per process — per *successful* pass.

    A pass that fails calls :func:`_note_failed_pass`, which puts the latch back
    so the next dispatch can try again. A pass that succeeds leaves it consumed,
    which is what keeps a busy gateway to one reconcile rather than one per
    message.
    """
    global _started
    with _LATCH:
        if _started:
            return False
        _started = True
        return True


def _note_failed_pass(*, deferred_lanes: Sequence[Any] = ()) -> None:
    """Release the latch after a failed pass, up to ``MAX_FAILED_PASSES``.

    *deferred_lanes* is not the reason for this release — a failure is retried on
    the next dispatch whatever the lanes are doing — but it has to survive it. One
    pass can fail on entry A and defer on entry B, and the two used to erase each
    other: the failure branch cleared the recorded lanes and the ``elif`` meant
    they were never recorded in the first place. So once the failure budget ran
    out, B had nothing left that could re-open the latch, even though B's
    conversation coming back was precisely the event that would have let the pass
    finish. Now the budget being spent falls through to the gated deferred
    release instead of ending reconciliation outright.
    """
    global _started, _failed_passes, _deferred_lanes, _deferred_gated
    with _LATCH:
        # Union, never replace. A pass can fail *before* it enumerates anything —
        # an unreadable journal returns ``failed: ["journal:entries"]`` and no
        # lanes at all — so taking this pass's (empty) list as the truth would
        # discard lanes an earlier pass had legitimately recorded, and once the
        # failure budget ran out there would be nothing left to re-open the latch.
        carried = _deferred_lanes | frozenset(deferred_lanes)
        _deferred_lanes = carried
        _failed_passes += 1
        attempts = _failed_passes
        spent = attempts >= MAX_FAILED_PASSES
        if not spent:
            # Ungated: a failure is retried by whichever lane speaks next, not by
            # the lanes carried above. They stay recorded for the fallback below.
            _deferred_gated = False
            _started = False

    if not spent:
        logger.warning(
            "hermes-drop: reconcile pass %s failed; the next dispatch will retry",
            attempts,
        )
        return

    logger.warning(
        "hermes-drop: %s reconcile passes failed; not retrying on failure again in "
        "this process. Live drops keep their status message and remain claimable; "
        "the background sweep is what stops.",
        attempts,
    )
    if carried:
        _note_deferred_pass(carried, made_progress=False)


def _note_clean_pass() -> None:
    """A pass that drove everything it found. The latch stays consumed.

    Both budgets reset here, and that is the point of having this be a case at
    all rather than a fall-through: a gateway that lives for weeks must not be
    left with reconciliation disabled because five passes failed transiently on
    unrelated days with dozens of clean ones in between.
    """
    global _deferred_lanes, _failed_passes, _deferred_passes
    global _deferred_gated, _deferred_spent
    with _LATCH:
        _deferred_lanes = frozenset()
        _deferred_gated = False
        _deferred_spent = False
        _failed_passes = 0
        _deferred_passes = 0
    with _EDIT_LOCK:
        _EDIT_RETRIES.clear()


def _note_deferred_pass(lanes: Sequence[Any], *, made_progress: bool) -> None:
    """Put the latch back after a pass that had nothing it *could* do yet.

    A pass that drives every entry it finds leaves the latch consumed, and that
    is the property the latch exists for: one reconcile per gateway, not one per
    message. But a pass over lanes the source registry does not know is not that
    pass. It read the journal, found entries it could not attach to a live
    conversation, probed nothing and wrote nothing. ``origin_for_entry`` says of
    exactly this case that ``None`` means "retry at the next trigger", never
    "give up" — and until this existed there was no next trigger, because the one
    attempt the process had was spent on the pass that did nothing.

    After a restart that is the *normal* first pass: the registry is empty until
    a conversation speaks, so every waiting drop was abandoned in ``waiting``
    with its status message still advertising a link the restarted broker had
    already destroyed (``src/broker.js:95-102``) — for the life of the process.

    So the latch goes back, but not unconditionally. The comment on
    ``MAX_FAILED_PASSES`` rules that out for a good reason: an unconditional
    release turns a permanently unresolvable lane into a reconcile pass on
    *every* inbound message, each one re-probing every live drop over the control
    socket. The lanes are recorded instead, and ``trigger_from_event`` refuses to
    spend the latch again until one of them resolves — the same sentence
    ``origin_for_entry`` already made the promise in.

    **Cost.** The gate is not free and is not O(1): every dispatch that arrives
    while a deferral is outstanding runs one registry peek plus one adapter
    resolution *per deferred lane*, i.e. O(N) for N distinct lanes holding
    waiting drops. Both are in-process dictionary work with no I/O, no probe and
    no journal read, and N is bounded by the number of conversations with a live
    drop — but "one dict lookup per message" would be wrong, and the difference
    matters on a gateway with many outstanding drops. ``MAX_DEFERRED_PASSES``
    bounds the other axis: how many times the gate may be believed and then
    disappointed.
    """
    global _started, _deferred_lanes, _deferred_passes, _deferred_gated, _deferred_spent
    with _LATCH:
        if made_progress:
            # The retry did what it was opened for; whatever is left over is a
            # fresh deferral, not a continuation of a stuck one.
            _deferred_passes = 0
        _deferred_passes += 1
        attempts = _deferred_passes
        spent = attempts >= MAX_DEFERRED_PASSES
        # A pass that ran to completion enumerated the whole journal, so its lanes
        # are the whole truth and replace what was carried. (The failure path
        # unions instead, because its enumeration may have stopped early.)
        _deferred_lanes = frozenset(lanes)
        pending = len(_deferred_lanes)
        if spent:
            # ``_deferred_gated`` stays true — this release *was* gated on lanes,
            # and pretending otherwise would make the ungated fast path answer for
            # a state it knows nothing about. What changes is that the gate now
            # has a settled answer, so it stops walking the lanes to re-derive it:
            # that walk is O(N) peeks and adapter resolutions and would run on
            # every inbound message for the life of the process. The lanes stay
            # readable; which conversations were given up on is the useful part.
            _deferred_spent = True
        else:
            _deferred_gated = True
            _started = False

    if spent:
        logger.warning(
            "hermes-drop: %s reconcile passes in a row deferred without making "
            "progress; not re-opening again in this process. The affected drops "
            "keep their status message and remain claimable; the background sweep "
            "is what stops.",
            attempts,
        )
        return
    logger.debug(
        "hermes-drop: reconcile deferred %s unresolvable lane(s); the next turn in "
        "one of them retries",
        pending,
    )


def deferred_retries_spent() -> bool:
    """Has the deferred budget run out? Observability for the O(1) short circuit.

    Distinct from ``not deferred_lanes()``: the lanes are still readable after the
    budget is spent — knowing *which* conversations were given up on is the whole
    value of keeping them — so "spent" cannot be inferred from them and needs its
    own answer.
    """
    with _LATCH:
        return _deferred_spent


def deferred_lanes() -> frozenset:
    """The lanes the latch is currently waiting on, or was when it gave up.

    A read, with no side effect, so an observer — a test, a future status
    command — can tell a gated latch from a spent one without calling
    ``trigger_from_event`` to find out, which would start a pass to answer a
    question about whether a pass would start.
    """
    with _LATCH:
        return _deferred_lanes


def _deferred_pass_can_make_progress(runner: Any = None, *, registry: Any = None) -> bool:
    """Would re-running a *deferred* pass resolve anything yet?

    ``True`` whenever the latch was not re-opened by a deferral, so this gate
    changes nothing for the failed-pass path or for the first pass of a process.

    Otherwise it asks the question the pass itself will ask —
    :func:`origin_for_entry` — and not the weaker "is the lane in the registry?".
    A lane can be registered and still unresolvable: the stored source can
    disagree with its own index, the runner can be gone, ``_adapter_for_source``
    can raise or answer ``None``. Gating on registration alone turned every one
    of those into a reconcile pass on *every* inbound message for as long as the
    condition lasted — the pass-per-message failure ``MAX_FAILED_PASSES`` exists
    to prevent, arriving through the other door. Asking the real question also
    means the gate cannot drift from the resolver: there is one implementation.

    The lookup is the non-mutating one (``peek=True``). This runs on every
    dispatch about lanes it is not going to use, and a reader that refreshed LRU
    order would let a background check decide which lane the registry evicts.

    Two O(1) exits come first, and both matter on a busy gateway: a spent budget
    means the answer is already decided, and an ungated latch means the walk is
    about lanes this release was not conditioned on.
    """
    with _LATCH:
        if _deferred_spent:
            return False
        if not _deferred_gated:
            return True
        lanes = _deferred_lanes
    if not lanes:
        return True
    for lane in lanes:
        entry = {
            "platform": lane[0],
            "profile": lane[1],
            "chat_id": lane[2],
            "thread_id": lane[3],
        }
        try:
            if origin_for_entry(entry, runner=runner, registry=registry, peek=True) is not None:
                return True
        except Exception:  # pragma: no cover - a store or runner that refuses
            # Unknown is not "no": a gate that swallowed a lookup failure would
            # be a quieter version of the bug it exists to fix.
            return True
    return False


def _account_for_pass(summary: Mapping[str, Any]) -> None:
    """Decide what one finished pass did to the latch. The only place that does.

    Three outcomes, kept apart because they used to collapse into two and erase
    each other:

    * **failed** — an entry raised, or the broker did not answer about it
      (``retained`` minus ``unresolved``: an ``unknown`` verdict, or an ``arm``
      that raised). Both cost a probe or a write and both mean something is
      wrong, so both go to the bounded failure budget. The ``unknown`` half used
      to go nowhere at all: a broker that was down for the duration of the pass —
      the exact restart window — left every drop retained and the latch spent,
      with no retry of any kind.
    * **deferred** — entries in lanes that could not be resolved. No probe, no
      write, nothing wrong; gated retry.
    * **clean** — everything found was driven. The latch stays consumed, which is
      the property it exists for.

    A pass can be both failed and deferred. It is then accounted as failed, *and*
    its lanes are carried into the failure release so they still gate a retry
    once the failure budget is spent.
    """
    failed = list(summary.get("failed") or ())
    unresolved = set(summary.get("unresolved") or ())
    undecided = sorted(set(summary.get("retained") or ()) - unresolved - set(failed))
    # Two different reasons a pass wants to run again, both expressed as lanes:
    # an origin that could not be resolved, and a status edit that has to be
    # retried. The second lane *is* resolvable — that is why the edit was
    # attempted at all — so it opens the gate on the next dispatch in it.
    lanes = list(summary.get("unresolved_lanes") or ()) + list(summary.get("retry_lanes") or ())

    if failed or undecided:
        if failed:
            logger.warning("hermes-drop: reconcile pass could not drive %s", failed)
        if undecided:
            logger.warning(
                "hermes-drop: reconcile pass could not decide %s; the broker did not "
                "answer about them, so they stay waiting",
                undecided,
            )
        _note_failed_pass(deferred_lanes=lanes)
        return

    if lanes:
        made_progress = any(
            summary.get(key) for key in ("received", "expired", "rearmed", "announced")
        )
        _note_deferred_pass(lanes, made_progress=made_progress)
        return

    _note_clean_pass()


def reset_for_tests() -> None:
    global _started, _failed_passes, _deferred_passes, _deferred_lanes
    global _deferred_gated, _deferred_spent
    with _LATCH:
        _started = False
        _failed_passes = 0
        _deferred_passes = 0
        _deferred_lanes = frozenset()
        # Every piece of latch state, not most of it: a reset that missed these
        # left the *next* test in the same interpreter with a permanently closed
        # gate, which reads as "the trigger never fired" a long way from here.
        _deferred_gated = False
        _deferred_spent = False
    with _EDIT_LOCK:
        _EDIT_RETRIES.clear()
    _shutdown.clear()


def request_shutdown() -> None:
    """Stop a startup poller that has not found a runner yet.

    **Nothing in the gateway calls this, and nothing can** — review L4 is
    accurate. There is no plugin teardown, unload or gateway-shutdown hook:
    ``VALID_HOOKS`` (``hermes_cli/plugins.py:135-215``) offers ``on_session_end``
    and ``on_session_finalize``, but those fire per *agent session*, so calling
    this from one would stop the poller on some unrelated conversation's turn
    ending. ``PluginManager`` exposes ``register_hook`` and no counterpart
    (``:1177``).

    It is kept, not deleted, because it is used — by ``tests/test_reconciler.py``,
    to stop a bounded poller deterministically instead of waiting out 60 polls —
    and because it is what a lifecycle hook would call the day core grows one.
    ``test_no_gateway_lifecycle_hook_exists_to_wire_shutdown_to`` fails if that
    day arrives, so this comment cannot quietly go stale.

    Not needing it is by design rather than luck: the thread is a daemon, so it
    cannot hold a process open, and it writes nothing until it finds a live runner.
    """
    _shutdown.set()


def _resolve_runner_default() -> Any:
    """Read the live runner handle — without ever *causing* ``gateway.run`` to load.

    Two constraints meet here. The handle must be read per call, because
    ``_gateway_runner_ref`` is rebound during ``GatewayRunner.__init__``
    (``gateway/run.py:5513, 5536``) and a value captured at discovery time is the
    ``lambda: None`` sentinel (``:3121``) forever. But this particular reader runs
    on a background thread in **every** process that loads the plugin, including
    ``hermes plugins list`` — and a plain ``from gateway.run import …`` there would
    drag ~25.7k lines into a CLI that only wanted a plugin listing, a second after
    ``register()`` carefully avoided doing exactly that.

    So the module is only consulted when something else has already imported it.
    That is not a heuristic: the runner handle cannot exist until ``gateway.run``
    is loaded, so "not in ``sys.modules``" is a complete answer, not a guess.
    """
    module = sys.modules.get("gateway.run")
    if module is None:
        return None
    try:
        ref = getattr(module, "_gateway_runner_ref", None)
        return ref() if callable(ref) else None
    except Exception:
        return None


async def _arm_spool() -> None:
    """Purge what a previous process left in the file spool, and start the janitor.

    Here rather than in ``register()`` for the reason ``register()`` avoids every
    other footprint: plugin discovery runs in *every* CLI process, and a recursive
    directory walk in ``hermes plugins list`` is exactly the cost this package
    refuses to pay. This function runs only from a reconcile pass, which happens
    only when a live gateway runner exists.

    Here rather than only on the claim path because the claim path is not enough:
    a gateway that claims files, restarts and never claims again would keep every
    published *and quarantined* directory forever — and a quarantined one is held
    precisely because it may be the only copy of a user's file, on the promise that
    the TTL settles it. Nothing settles it if nothing sweeps.

    Never raises, and costs nothing when file drops are switched off.
    """
    from . import config as config_mod

    if not config_mod.spool_configured():
        return
    try:
        from . import spool as spool_mod

        spool = spool_mod.Spool()
        await asyncio.to_thread(spool_mod.ensure_started, spool)
        spool_mod.ensure_janitor(spool)
    except Exception:  # noqa: BLE001 - a reconcile pass must not fail on housekeeping
        logger.warning("hermes-drop: could not arm the file spool", exc_info=True)


async def _reconcile_for_runner(runner: Any) -> Dict[str, Any]:
    """The production coroutine: build everything from the live runner.

    Deliberately constructed *here* rather than at import or registration time,
    so no journal directory exists until a gateway does.
    """
    from . import waiter as waiter_mod

    await _arm_spool()
    journal = journal_mod.DropJournal()
    return await reconcile(
        journal=journal,
        runner=runner,
        registry=sources_mod.REGISTRY,
        messenger=None,
        arm=waiter_mod.arm_from_reconcile,
    )


def start_startup_trigger(
    *,
    resolve_runner: Optional[Callable[[], Any]] = None,
    reconcile_coro: Optional[Callable[[Any], Any]] = None,
    schedule: Optional[Callable[..., Any]] = None,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    max_polls: int = DEFAULT_MAX_POLLS,
) -> threading.Thread:
    """Start the bounded daemon poller. Returns the thread for tests and shutdown.

    Daemon because a CLI process must exit when its work is done, and this
    thread's whole job may be to discover that there is no gateway.
    """
    resolve = resolve_runner or _resolve_runner_default
    make_coro = reconcile_coro or _reconcile_for_runner

    def _poll() -> None:
        for _ in range(max_polls):
            if _shutdown.is_set():
                return
            try:
                runner = resolve()
            except Exception:  # pragma: no cover - defensive
                runner = None
            loop = getattr(runner, "_gateway_loop", None) if runner is not None else None
            if runner is not None and loop is not None:
                # The same gate the dispatch trigger honours. Normally a no-op —
                # this poller starts before any pass has deferred — but a second
                # ``start_startup_trigger`` in a process that has already deferred
                # would otherwise spend a *gated* re-open ungated, running the
                # pass the gate had just decided was pointless.
                if _deferred_pass_can_make_progress(runner) and _claim_trigger():
                    _schedule_reconcile(make_coro, runner, loop, schedule)
                return
            _shutdown.wait(poll_interval)
        logger.debug(
            "hermes-drop: no gateway runner after %s polls; startup reconcile skipped",
            max_polls,
        )

    thread = threading.Thread(target=_poll, name="hermes-drop-reconcile", daemon=True)
    global _startup_thread
    _startup_thread = thread
    thread.start()
    return thread


async def _run_pass(make_coro: Callable[[Any], Any], runner: Any) -> Optional[Dict[str, Any]]:
    """Await one pass and account for its outcome against the latch.

    Every scheduling path goes through here, so "a failed pass is retried" is one
    rule in one place rather than a property each trigger has to remember. Two
    kinds of failure are treated alike:

    * the pass raised — which ``reconcile`` now contains, so this is the guard for
      a future edit that reintroduces one;
    * the pass completed but reported entries it could not drive
      (``summary["failed"]``) — the ordinary case, and the one the pre-fix code
      could not express at all because the exception escaped instead.

    Everything else a finished pass can mean — undecided entries, deferred lanes,
    a clean sweep — is decided by :func:`_account_for_pass`, in one place.
    """
    try:
        summary = await make_coro(runner)
    except Exception as exc:  # noqa: BLE001 - nothing may escape a bare task
        logger.warning("hermes-drop: reconcile pass raised: %s", exc, exc_info=True)
        _note_failed_pass()
        return None

    if isinstance(summary, Mapping):
        _account_for_pass(summary)
    return summary if isinstance(summary, dict) else None


def _log_pass_future(future: Any) -> None:
    """``add_done_callback`` that retrieves and logs whatever the pass left behind.

    Without this the ``run_coroutine_threadsafe`` path logged **nothing at all**:
    ``_schedule_reconcile`` discarded the ``concurrent.futures.Future``, so an
    exception inside the coroutine was never retrieved and never surfaced. (The
    ``loop.create_task`` path at least produced asyncio's "Task exception was
    never retrieved" at GC — a message with no attribution, arriving whenever the
    collector got round to it.)
    """
    try:
        exc = future.exception()
    except asyncio.CancelledError:
        logger.debug("hermes-drop: the reconcile pass was cancelled")
        return
    except Exception as probe_exc:  # noqa: BLE001 - a callback must not raise
        logger.debug("hermes-drop: could not read the reconcile future: %s", probe_exc)
        return
    if exc is not None:
        logger.warning("hermes-drop: reconcile pass failed: %s", exc, exc_info=exc)


def _schedule_reconcile(
    make_coro: Callable[[Any], Any],
    runner: Any,
    loop: Any,
    schedule: Optional[Callable[..., Any]] = None,
) -> None:
    from agent.async_utils import safe_schedule_threadsafe

    scheduler = schedule or safe_schedule_threadsafe
    # Both callers claim the latch immediately before calling this, so every exit
    # that does not start a pass has to put it back — otherwise the process spends
    # its one attempt on a pass that never ran (review N4, the same
    # latch-accounting shape as M2).
    try:
        coro = _run_pass(make_coro, runner)
    except Exception:  # pragma: no cover - defensive
        logger.warning("hermes-drop: could not build the reconcile coroutine", exc_info=True)
        _note_failed_pass()
        return
    future = scheduler(coro, loop)
    if future is None:
        logger.debug("hermes-drop: gateway loop went away before the reconcile was scheduled")
        # Nothing will ever await it; closing it here keeps the RuntimeWarning
        # out of a log where it would be attributed to nothing.
        coro.close()
        _note_failed_pass()
        return
    try:
        future.add_done_callback(_log_pass_future)
    except Exception:  # pragma: no cover - a Future that refuses a callback
        logger.debug("hermes-drop: could not observe the reconcile future", exc_info=True)


def trigger_from_event(gateway: Any, *, reconcile_coro: Optional[Callable[[Any], Any]] = None) -> bool:
    """The second, idempotent trigger: ``pre_gateway_dispatch``.

    Returns ``True`` only for the call that actually started a reconcile, so a
    second dispatch is provably a no-op rather than merely a cheap one. Never
    raises — ``invoke_hook`` would swallow it with a warning
    (``hermes_cli/plugins.py:1938-1945``) and the store would be left half-written.
    """
    if gateway is None:
        return False
    make_coro = reconcile_coro or _reconcile_for_runner
    # Checked before the latch is claimed: a deferred pass is only worth
    # re-running once one of the lanes it could not resolve is back, and this
    # turn's own lane was published by ``capture`` a statement earlier
    # (``__init__.capture_turn_source``), so the turn that revives a conversation
    # is the turn that reconciles its drops. ``gateway`` is the runner the pass
    # will use, so the gate resolves against the same one.
    if not _deferred_pass_can_make_progress(gateway):
        return False
    if not _claim_trigger():
        return False
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = getattr(gateway, "_gateway_loop", None)
        if loop is None:
            return False
        _schedule_reconcile(make_coro, gateway, loop)
        return True

    try:
        task = loop.create_task(_run_pass(make_coro, gateway))
    except Exception:  # pragma: no cover - defensive
        logger.warning("hermes-drop: could not start the reconcile task", exc_info=True)
        # The latch was already claimed above, so release it: refusing here
        # without releasing would consume the process's one attempt on a failure
        # that never even started a pass.
        _note_failed_pass()
        return False
    task.add_done_callback(_log_pass_future)
    return True


# ── liveness ───────────────────────────────────────────────────────────────


async def probe_liveness(
    drop_id: str,
    *,
    control: Any,
    socket_path: Any = None,
    probe_ms: int = DEFAULT_PROBE_MS,
    clock: Callable[[], float] = time.monotonic,
) -> str:
    """One bounded ``await`` whose elapsed time is the verdict. See the module
    docstring for why timing is the only available signal and why the
    misjudgement direction is the safe one."""
    started = clock()
    try:
        response = await control.await_submission(
            drop_id,
            wait_ms=int(probe_ms),
            socket_path=socket_path,
            timeout=(probe_ms / 1000.0) + 5.0,
        )
    except Exception as exc:  # noqa: BLE001 - the client is supposed not to raise
        logger.warning("hermes-drop: liveness probe raised for %s: %s", drop_id, exc)
        return VERDICT_UNKNOWN
    elapsed_ms = (clock() - started) * 1000.0

    if response.get("ok") and response.get("status") == VERDICT_SUBMITTED:
        return VERDICT_SUBMITTED
    if response.get("error") != "unavailable":
        # broker_unavailable, invalid_request, a malformed line: the broker did
        # not answer about this handoff, so nothing is known about it.
        return VERDICT_UNKNOWN
    return VERDICT_GONE if elapsed_ms < probe_ms * _LIVE_FRACTION else VERDICT_LIVE


# ── terminal transitions ───────────────────────────────────────────────────


async def finalize_terminal(
    *,
    journal: journal_mod.DropJournal,
    origin: Any,
    entry: Mapping[str, Any],
    state: str,
    messenger: Any,
    deliver: Optional[Callable[..., Any]] = None,
    clock: Callable[[], float] = time.time,
) -> Dict[str, Any]:
    """**edit → journal → announce**, in that order, exactly as §3.2 states.

    Edit first because it is the only step the user can see and the only one that
    stops a dead link advertising itself. Journal second because it is the only
    step that must survive. Announce last because it is best-effort and the two
    steps before it already made the outcome true and recoverable.

    Shared by the reconciler and the waiter (S7) so there is one implementation
    of the transition, not two that can drift.
    """
    drop_id = entry["drop_id"]
    current = journal.get(drop_id)
    if current is None:
        return {"error": "gone", "drop_id": drop_id}
    if current.get("state") in journal_mod.TERMINAL_STATES:
        # Journal state is the guard for duplicate resolution: no second edit,
        # and the announce sweep below is a no-op once ``announced_at`` is set.
        return {"ok": True, "drop_id": drop_id, "state": current["state"], "duplicate": True}

    content = (
        current.get("notice_received")
        if state == journal_mod.STATE_RECEIVED
        else current.get("notice_expired")
    )

    edit_failed = False
    if content and current.get("message_id"):
        result = await messenger.update_status(origin, current["message_id"], content)
        edit_failed = "error" in result

    journal.update(drop_id, state=state, edit_failed=edit_failed)
    announced = await announce_mod.announce_pending(
        journal=journal, origin=origin, deliver=deliver, clock=clock
    )
    return {
        "ok": True,
        "drop_id": drop_id,
        "state": state,
        "edit_failed": edit_failed,
        "announced": announced.get("announced", []),
    }


def _note_edit_attempt(drop_id: str) -> int:
    """Count one failed edit retry for *drop_id*, and return the running total."""
    with _EDIT_LOCK:
        attempts = _EDIT_RETRIES.get(drop_id, 0) + 1
        _EDIT_RETRIES[drop_id] = attempts
        return attempts


def _clear_edit_attempts(drop_id: str) -> None:
    with _EDIT_LOCK:
        _EDIT_RETRIES.pop(drop_id, None)


def _edit_attempts(drop_id: str) -> int:
    with _EDIT_LOCK:
        return _EDIT_RETRIES.get(drop_id, 0)


def _note_finalize_edit(
    result: Mapping[str, Any], entry: Mapping[str, Any], summary: Dict[str, List[Any]]
) -> None:
    """Record a terminal transition whose status edit was refused.

    ``finalize_terminal`` already writes ``edit_failed`` and carries on, which is
    correct — the outcome must become durable whether or not chat cooperates. This
    is what turns that flag into work: the lane goes into ``retry_lanes`` so the
    pass is accounted as having something left to do, and the next turn in that
    conversation retries the edit. Without it the pass looked clean, the latch
    stayed consumed, and the user kept a waiting notice for a drop that was over.

    The failure is not counted as a retry: it *is* the first attempt, and
    ``MAX_EDIT_RETRIES`` counts what comes after it.
    """
    if not result.get("edit_failed"):
        return
    drop_id = entry.get("drop_id") or ""
    if _edit_attempts(drop_id) >= MAX_EDIT_RETRIES:
        return
    summary["edit_retry_pending"].append(drop_id)
    summary["retry_lanes"].append(journal_mod.routing_tuple_of(entry))


async def retry_failed_edits(
    *,
    journal: journal_mod.DropJournal,
    entries: Sequence[Mapping[str, Any]],
    runner: Any,
    registry: Any,
    messenger: Any,
    summary: Dict[str, List[Any]],
    skip: Sequence[str] = (),
) -> None:
    """Re-edit the status messages that a terminal transition could not edit.

    ``finalize_terminal`` treats a refused edit as survivable and moves on — the
    journal is written and the announce still happens, which is right, because the
    outcome must become durable whether or not a chat message can be updated. But
    "survivable" was silently turned into "final": nothing ever tried again, so a
    drop whose edit failed once kept its **waiting** notice — the live-looking one,
    with the capability URL still in it — for good, while the journal said the
    drop was over. A URL that stops working but never stops advertising itself is
    the condition this whole design exists to prevent.

    So the flag ``finalize_terminal`` already writes (``edit_failed``) becomes
    work rather than a record. Bounded twice over: ``MAX_EDIT_RETRIES`` per drop,
    and the gate that only re-runs a pass when the lane speaks.

    Deliberately narrow. This edits and clears a flag. It does not re-announce
    (the entry is announced or is not, and ``terminal_unannounced`` already
    decides that), it does not re-transition (the entry is terminal and
    ``finalize_terminal`` refuses a second one), and it never touches a payload —
    so no retry here can duplicate a claim or a delivery.
    """
    skipped = set(skip)
    for entry in entries:
        drop_id = entry.get("drop_id") or ""
        if drop_id in skipped:
            # Its edit failed inside *this* pass; retrying it a statement later
            # would just fail again against the same adapter. It is already in
            # ``retry_lanes``, so the next pass picks it up.
            continue
        if entry.get("state") not in journal_mod.TERMINAL_STATES:
            continue
        if not entry.get("edit_failed"):
            continue
        message_id = entry.get("message_id")
        content = (
            entry.get("notice_received")
            if entry.get("state") == journal_mod.STATE_RECEIVED
            else entry.get("notice_expired")
        )
        if not message_id or not content:
            # Nothing to edit and nothing that will ever make one appear.
            continue
        if _edit_attempts(drop_id) >= MAX_EDIT_RETRIES:
            continue

        lane = journal_mod.routing_tuple_of(entry)
        try:
            origin = origin_for_entry(entry, runner=runner, registry=registry)
            if origin is None:
                summary["unresolved"].append(drop_id)
                summary["unresolved_lanes"].append(lane)
                continue
            result = await messenger.update_status(origin, message_id, content)
            if "error" not in result:
                journal.update(drop_id, edit_failed=False)
                _clear_edit_attempts(drop_id)
                summary["edit_repaired"].append(drop_id)
                continue
            attempts = _note_edit_attempt(drop_id)
            if attempts < MAX_EDIT_RETRIES:
                summary["edit_retry_pending"].append(drop_id)
                summary["retry_lanes"].append(lane)
            else:
                logger.warning(
                    "hermes-drop: gave up re-editing the status message for %s after "
                    "%s attempts. The drop is terminal in the journal and cannot be "
                    "claimed twice; what stays wrong is the message the user can see, "
                    "which still shows the waiting notice.",
                    drop_id,
                    attempts,
                )
        except Exception:  # noqa: BLE001 - as everywhere in a pass, per entry
            logger.warning(
                "hermes-drop: could not retry the status edit for %s", drop_id, exc_info=True
            )
            summary["failed"].append(drop_id)


# ── the pass itself ────────────────────────────────────────────────────────


def origin_for_entry(
    entry: Mapping[str, Any],
    *,
    runner: Any,
    registry: Any = None,
    peek: bool = False,
) -> Optional[Any]:
    """Find the live source and adapter for a journalled lane, or ``None``.

    ``None`` means "retry at the next trigger", never "give up": a gateway
    restart empties the registry, so an unresolvable lane is the *expected*
    state of a startup pass and becomes resolvable the moment that conversation
    speaks again.

    ``peek`` is for the caller that is asking rather than resolving — the retry
    gate, which runs on every dispatch and must not refresh LRU order in a store
    it is only inspecting. It changes the lookup and nothing else, so the gate
    and the pass cannot answer differently.
    """
    from . import origin as origin_mod

    store = registry if registry is not None else sources_mod.REGISTRY
    lane = journal_mod.routing_tuple_of(entry)
    lookup = store.by_routing_tuple
    if peek:
        # ``getattr`` because a caller may pass a store of its own; a registry
        # without the non-mutating read is served by the mutating one rather
        # than refused.
        lookup = getattr(store, "peek_routing_tuple", lookup)
    found = lookup(lane)
    if found is None:
        return None
    source = found.source
    if sources_mod.routing_tuple_for_source(source) != lane:  # pragma: no cover - index invariant
        return None
    if runner is None:
        return None
    try:
        adapter = runner._adapter_for_source(source)
    except Exception:
        logger.warning("hermes-drop: adapter resolution raised during reconcile", exc_info=True)
        return None
    if adapter is None:
        return None
    return origin_mod.Origin(
        source=source,
        adapter=adapter,
        runner=runner,
        routing_tuple=lane,
        reply_anchor=None,
        tier="routing_tuple",
    )


async def reconcile(
    *,
    journal: journal_mod.DropJournal,
    runner: Any,
    registry: Any = None,
    messenger: Any = None,
    control: Any = None,
    arm: Optional[Callable[..., Any]] = None,
    deliver: Optional[Callable[..., Any]] = None,
    socket_path: Any = None,
    probe_ms: int = DEFAULT_PROBE_MS,
    clock: Callable[[], float] = time.time,
) -> Dict[str, Any]:
    """One idempotent pass over the journal. **Never raises** — and now that is
    true of the whole body rather than of the one call that was wrapped.

    Idempotent because every decision reads the durable record first and every
    terminal transition refuses to happen twice. Running this after a waiter has
    already resolved a drop produces no edit, no announce and no claim.

    Every step past ``journal.entries()`` can fail for reasons outside this
    module: ``origin_for_entry`` reads a store shared with other threads,
    ``finalize_terminal`` and ``announce_pending`` write the journal (``OSError``
    on a full or read-only disk, ``JournalRejected`` on a hand-edited entry), and
    the reclaim-grace pass writes too. Containment is **per entry**, not one
    try/except around the loop, because the failure mode that matters is a single
    bad entry silently abandoning every entry behind it: pre-fix, a raise on entry
    N meant entries after N were never driven to terminal and their status
    messages kept advertising dead links (review M2).

    ``summary["failed"]`` names every drop the pass could not drive. It is the
    signal ``_run_pass`` uses to put the one-shot latch back, so a transient
    failure is retried at the next dispatch instead of disabling reconciliation
    for the life of the process.
    """
    from . import control_client
    from . import messenger as messenger_mod

    ctl = control if control is not None else control_client
    post = messenger if messenger is not None else messenger_mod.OriginMessenger()

    # ``unresolved_lanes`` carries routing tuples rather than drop ids: it is what
    # ``_run_pass`` gates the deferred retry on, and the question that gate asks
    # is "is that conversation back?", which is a property of the lane.
    summary: Dict[str, List[Any]] = {
        "received": [],
        "expired": [],
        "transport_failed": [],
        "rearmed": [],
        "retained": [],
        "unresolved": [],
        "unresolved_lanes": [],
        "retry_lanes": [],
        "edit_retry_pending": [],
        "edit_repaired": [],
        "announced": [],
        "failed": [],
    }

    try:
        entries = journal.entries()
    except Exception:
        logger.warning("hermes-drop: journal unreadable during reconcile", exc_info=True)
        summary["failed"].append("journal:entries")
        return summary

    now_ms = clock() * 1000.0

    for entry in entries:
        if entry.get("state") != journal_mod.STATE_WAITING:
            continue
        drop_id = entry.get("drop_id") or ""
        try:
            origin = origin_for_entry(entry, runner=runner, registry=registry)
            if origin is None:
                summary["retained"].append(drop_id)
                summary["unresolved"].append(drop_id)
                summary["unresolved_lanes"].append(journal_mod.routing_tuple_of(entry))
                continue

            if now_ms >= float(entry.get("expires_at_ms") or 0):
                # The broker destroys at expiry (``src/broker.js:95-102``);
                # probing would only confirm what the deadline already says.
                result = await finalize_terminal(
                    journal=journal,
                    origin=origin,
                    entry=entry,
                    state=journal_mod.STATE_EXPIRED,
                    messenger=post,
                    deliver=deliver,
                    clock=clock,
                )
                summary["expired"].append(drop_id)
                summary["announced"].extend(result.get("announced", []))
                _note_finalize_edit(result, entry, summary)
                continue

            verdict = await probe_liveness(
                drop_id, control=ctl, socket_path=socket_path, probe_ms=probe_ms
            )
            if verdict == VERDICT_SUBMITTED:
                result = await finalize_terminal(
                    journal=journal,
                    origin=origin,
                    entry=entry,
                    state=journal_mod.STATE_RECEIVED,
                    messenger=post,
                    deliver=deliver,
                    clock=clock,
                )
                summary["received"].append(drop_id)
                summary["announced"].extend(result.get("announced", []))
                _note_finalize_edit(result, entry, summary)
            elif verdict == VERDICT_GONE:
                result = await finalize_terminal(
                    journal=journal,
                    origin=origin,
                    entry=entry,
                    state=journal_mod.STATE_EXPIRED,
                    messenger=post,
                    deliver=deliver,
                    clock=clock,
                )
                summary["expired"].append(drop_id)
                summary["announced"].extend(result.get("announced", []))
                _note_finalize_edit(result, entry, summary)
            elif verdict == VERDICT_LIVE and arm is not None:
                try:
                    arm(drop_id=drop_id, origin=origin, entry=entry)
                except Exception:
                    logger.warning("hermes-drop: could not re-arm %s", drop_id, exc_info=True)
                    summary["retained"].append(drop_id)
                    continue
                summary["rearmed"].append(drop_id)
            else:
                # unknown, or live with nothing to arm it with: leave it exactly
                # as it is and try again at the next trigger.
                summary["retained"].append(drop_id)
        except Exception:  # noqa: BLE001 - one bad entry must not abandon the rest
            logger.warning(
                "hermes-drop: reconcile could not drive %s; leaving it waiting",
                drop_id,
                exc_info=True,
            )
            summary["failed"].append(drop_id)
            summary["retained"].append(drop_id)
            continue

    # §3.3's second re-announce condition: received, announced, and *still*
    # unclaimed past the grace. Clearing ``announced_at`` re-opens the entry for
    # the sweep below; ``announce_attempts`` is untouched, so the same bound that
    # limits a failing wake limits this one.
    try:
        reclaim_candidates = journal.entries()
    except Exception:
        logger.warning("hermes-drop: journal unreadable during the reclaim sweep", exc_info=True)
        summary["failed"].append("journal:entries")
        reclaim_candidates = []

    # Status messages a terminal transition could not edit, in this process or an
    # earlier one. Fed the same fresh read as the reclaim sweep, and told to skip
    # what this pass just finalised: those failures are already in ``retry_lanes``
    # and a second attempt against the same adapter in the same pass is not a
    # retry, it is the same attempt twice.
    await retry_failed_edits(
        journal=journal,
        entries=reclaim_candidates,
        runner=runner,
        registry=registry,
        messenger=post,
        summary=summary,
        skip=list(summary["expired"]) + list(summary["received"]),
    )

    now = clock()
    for entry in reclaim_candidates:
        if entry.get("state") != journal_mod.STATE_RECEIVED:
            continue
        if entry.get("claimed_at") is not None:
            continue
        announced_at = entry.get("announced_at")
        if announced_at is None:
            continue
        if int(entry.get("announce_attempts") or 0) >= journal_mod.MAX_ANNOUNCE_ATTEMPTS:
            continue
        if now - float(announced_at) > RECLAIM_GRACE_SECONDS:
            try:
                journal.update(entry["drop_id"], announced_at=None)
            except Exception:
                logger.warning(
                    "hermes-drop: could not re-open %s for re-announce",
                    entry.get("drop_id"),
                    exc_info=True,
                )
                summary["failed"].append(entry.get("drop_id") or "")

    # Anything terminal that never got its wake — including entries that were
    # already terminal when this pass started, which is the restart case.
    announced_now = set(summary["announced"])
    try:
        pending = journal.terminal_unannounced()
    except Exception:
        logger.warning("hermes-drop: could not list unannounced entries", exc_info=True)
        summary["failed"].append("journal:terminal_unannounced")
        pending = []

    for entry in pending:
        drop_id = entry.get("drop_id") or ""
        if drop_id in announced_now:
            continue
        try:
            origin = origin_for_entry(entry, runner=runner, registry=registry)
            if origin is None:
                summary["unresolved"].append(drop_id)
                summary["unresolved_lanes"].append(journal_mod.routing_tuple_of(entry))
                continue
            result = await announce_mod.announce_pending(
                journal=journal, origin=origin, deliver=deliver, clock=clock
            )
            for announced_id in result.get("announced", []):
                announced_now.add(announced_id)
                summary["announced"].append(announced_id)
        except Exception:  # noqa: BLE001 - as above, per entry
            logger.warning(
                "hermes-drop: could not announce %s; it stays unannounced",
                drop_id,
                exc_info=True,
            )
            summary["failed"].append(drop_id)
            continue

    return summary


__all__ = [
    "DEFAULT_MAX_POLLS",
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_PROBE_MS",
    "MAX_DEFERRED_PASSES",
    "MAX_EDIT_RETRIES",
    "MAX_FAILED_PASSES",
    "VERDICT_GONE",
    "VERDICT_LIVE",
    "VERDICT_SUBMITTED",
    "VERDICT_UNKNOWN",
    "deferred_lanes",
    "deferred_retries_spent",
    "finalize_terminal",
    "origin_for_entry",
    "probe_liveness",
    "reconcile",
    "request_shutdown",
    "reset_for_tests",
    "retry_failed_edits",
    "start_startup_trigger",
    "trigger_from_event",
]
