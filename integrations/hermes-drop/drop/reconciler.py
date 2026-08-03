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

_LATCH = threading.Lock()
_started = False
_failed_passes = 0
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


def _note_failed_pass() -> None:
    """Release the latch after a failed pass, up to ``MAX_FAILED_PASSES``."""
    global _started, _failed_passes
    with _LATCH:
        _failed_passes += 1
        if _failed_passes >= MAX_FAILED_PASSES:
            logger.warning(
                "hermes-drop: %s reconcile passes failed; not retrying again in this "
                "process. Live drops keep their status message and remain claimable; "
                "the background sweep is what stops.",
                _failed_passes,
            )
            return
        _started = False
        logger.warning(
            "hermes-drop: reconcile pass %s failed; the next dispatch will retry",
            _failed_passes,
        )


def reset_for_tests() -> None:
    global _started, _failed_passes
    with _LATCH:
        _started = False
        _failed_passes = 0
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


async def _reconcile_for_runner(runner: Any) -> Dict[str, Any]:
    """The production coroutine: build everything from the live runner.

    Deliberately constructed *here* rather than at import or registration time,
    so no journal directory exists until a gateway does.
    """
    from . import waiter as waiter_mod

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
                if _claim_trigger():
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
    """
    try:
        summary = await make_coro(runner)
    except Exception as exc:  # noqa: BLE001 - nothing may escape a bare task
        logger.warning("hermes-drop: reconcile pass raised: %s", exc, exc_info=True)
        _note_failed_pass()
        return None

    if isinstance(summary, Mapping) and summary.get("failed"):
        logger.warning(
            "hermes-drop: reconcile pass could not drive %s", list(summary["failed"])
        )
        _note_failed_pass()
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


# ── the pass itself ────────────────────────────────────────────────────────


def origin_for_entry(
    entry: Mapping[str, Any],
    *,
    runner: Any,
    registry: Any = None,
) -> Optional[Any]:
    """Find the live source and adapter for a journalled lane, or ``None``.

    ``None`` means "retry at the next trigger", never "give up": a gateway
    restart empties the registry, so an unresolvable lane is the *expected*
    state of a startup pass and becomes resolvable the moment that conversation
    speaks again.
    """
    from . import origin as origin_mod

    store = registry if registry is not None else sources_mod.REGISTRY
    lane = journal_mod.routing_tuple_of(entry)
    found = store.by_routing_tuple(lane)
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

    summary: Dict[str, List[str]] = {
        "received": [],
        "expired": [],
        "transport_failed": [],
        "rearmed": [],
        "retained": [],
        "unresolved": [],
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
    "MAX_FAILED_PASSES",
    "VERDICT_GONE",
    "VERDICT_LIVE",
    "VERDICT_SUBMITTED",
    "VERDICT_UNKNOWN",
    "finalize_terminal",
    "origin_for_entry",
    "probe_liveness",
    "reconcile",
    "request_shutdown",
    "reset_for_tests",
    "start_startup_trigger",
    "trigger_from_event",
]
