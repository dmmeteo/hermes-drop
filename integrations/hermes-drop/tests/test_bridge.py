"""S5 — the one guarded worker-thread → gateway-loop crossing.

Where the two entry points actually run:

* ``/drop`` is awaited **on** the gateway loop (``gateway/run.py:14697-14698``),
  and so is the ``pre_gateway_dispatch`` hook (``:13636``). Neither may use this
  bridge.
* A model tool handler runs on a ``ThreadPoolExecutor`` worker
  (``gateway/run.py:18604`` → ``:20276-20285``), so it crosses **once**, for the
  whole operation.

Revision 1 of the plan used the bridge *inside* the messenger, which put it on the
``/drop`` and hook paths too — scheduling onto the loop you are currently
blocking is a guaranteed stall for the full timeout on every single invocation.
It also called ``.result()`` directly on ``safe_schedule_threadsafe``'s
``Optional[Future]``, which is an ``AttributeError`` when the loop is gone
(``agent/async_utils.py:41, 56-60``). Both branches are pinned below.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from conftest import load_plugin_package


@pytest.fixture
def bridge_mod():
    return load_plugin_package().drop.bridge


class LoopThread:
    """A live asyncio loop on its own thread, standing in for the gateway loop."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self._ready = threading.Event()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.call_soon(self._ready.set)
        self.loop.run_forever()

    def __enter__(self) -> "LoopThread":
        self.thread.start()
        assert self._ready.wait(timeout=10)
        return self

    def __exit__(self, *exc) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=10)
        self.loop.close()


class Runner:
    def __init__(self, loop=None):
        self._gateway_loop = loop


# ── the happy path ─────────────────────────────────────────────────────────


def test_a_coroutine_runs_on_the_gateway_loop_and_returns_its_value(bridge_mod) -> None:
    with LoopThread() as lt:
        bridge = bridge_mod.SyncBridge(lambda: Runner(lt.loop))

        async def work():
            await asyncio.sleep(0)
            return {"ok": True, "ran_on": id(asyncio.get_running_loop())}

        result = bridge.run(work(), timeout=10)

    assert result["ok"] is True
    assert result["ran_on"] == id(lt.loop)


def test_the_whole_operation_crosses_once(bridge_mod) -> None:
    """One crossing for the whole operation, not one per await. If the count ever
    goes up, something moved the bridge back inside the messenger."""
    crossings = []

    with LoopThread() as lt:
        original = bridge_mod.safe_schedule_threadsafe

        def counting(coro, loop, **kwargs):
            crossings.append(1)
            return original(coro, loop, **kwargs)

        bridge = bridge_mod.SyncBridge(lambda: Runner(lt.loop), scheduler=counting)

        async def work():
            for _ in range(5):
                await asyncio.sleep(0)
            return "done"

        assert bridge.run(work(), timeout=10) == "done"

    assert len(crossings) == 1


# ── the refusals ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_calling_from_the_target_loop_refuses_would_deadlock(bridge_mod) -> None:
    """We ARE the loop. Scheduling onto it and blocking on the future would stall
    for the full timeout, every time."""
    loop = asyncio.get_running_loop()
    bridge = bridge_mod.SyncBridge(lambda: Runner(loop))

    async def work():  # pragma: no cover - must never run
        return "should not happen"

    coro = work()
    result = bridge.run(coro, timeout=10)

    assert result == {"error": "would_deadlock"}
    # The coroutine must be closed, not leaked as "never awaited".
    assert not asyncio.iscoroutine(coro) or coro.cr_frame is None


def test_a_missing_loop_refuses_gateway_unavailable(bridge_mod) -> None:
    bridge = bridge_mod.SyncBridge(lambda: Runner(None))

    async def work():  # pragma: no cover
        return "no"

    coro = work()
    assert bridge.run(coro, timeout=10) == {"error": "gateway_unavailable"}
    assert coro.cr_frame is None


def test_a_missing_runner_refuses_gateway_unavailable(bridge_mod) -> None:
    bridge = bridge_mod.SyncBridge(lambda: None)

    async def work():  # pragma: no cover
        return "no"

    coro = work()
    assert bridge.run(coro, timeout=10) == {"error": "gateway_unavailable"}
    assert coro.cr_frame is None


def test_a_none_future_refuses_gateway_unavailable_rather_than_raising(bridge_mod) -> None:
    """``safe_schedule_threadsafe`` returns ``Optional[Future]`` and yields ``None``
    when the loop is missing or was closed during a shutdown race
    (``agent/async_utils.py:41, 56-60``). Revision 1 called ``.result()`` on it."""
    with LoopThread() as lt:
        bridge = bridge_mod.SyncBridge(
            lambda: Runner(lt.loop),
            scheduler=lambda coro, loop, **kw: (coro.close(), None)[1],
        )

        async def work():  # pragma: no cover
            return "no"

        assert bridge.run(work(), timeout=10) == {"error": "gateway_unavailable"}


def test_a_slow_coroutine_times_out_and_is_cancelled(bridge_mod) -> None:
    """A parked coroutine must not keep running on the gateway loop after the
    caller has given up on it."""
    started = threading.Event()
    cancelled = threading.Event()

    with LoopThread() as lt:
        bridge = bridge_mod.SyncBridge(lambda: Runner(lt.loop))

        async def slow():
            started.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                cancelled.set()
                raise
            return "never"  # pragma: no cover

        result = bridge.run(slow(), timeout=0.25)
        assert started.wait(timeout=5)
        assert cancelled.wait(timeout=5), "the timed-out coroutine was left running"

    assert result == {"error": "gateway_timeout"}


def test_an_exception_inside_the_coroutine_becomes_an_error_not_a_raise(bridge_mod) -> None:
    """A raising tool handler is swallowed at ``gateway/run.py:14701-14702`` and
    falls through to skill-command resolution — resurrecting the ``/skill drop``
    path this design severs. Nothing may escape."""
    with LoopThread() as lt:
        bridge = bridge_mod.SyncBridge(lambda: Runner(lt.loop))

        async def boom():
            raise ValueError("kaboom")

        result = bridge.run(boom(), timeout=10)

    assert result["error"] == "internal_error"
    assert "kaboom" in result["detail"]


# ── budgets ────────────────────────────────────────────────────────────────


def test_the_documented_timeouts_are_create_twenty_and_claim_ten(bridge_mod) -> None:
    """Initiation must always return inside the turn (§3.2: < 20 s)."""
    assert bridge_mod.CREATE_TIMEOUT_SECONDS == 20
    assert bridge_mod.CLAIM_TIMEOUT_SECONDS == 10


def test_the_bridge_resolves_the_runner_lazily(bridge_mod) -> None:
    """The runner handle is read per call, not captured at construction: the
    module-level ``_gateway_runner_ref`` is rebound in ``GatewayRunner.__init__``
    (``gateway/run.py:5513, 5536``), so a bridge built at plugin-discovery time
    would hold the ``lambda: None`` sentinel forever."""
    calls = []

    def resolver():
        calls.append(time.monotonic())
        return None

    bridge = bridge_mod.SyncBridge(resolver)

    async def work():  # pragma: no cover
        return "no"

    bridge.run(work(), timeout=1)
    bridge.run(work(), timeout=1)
    assert len(calls) == 2


def test_gateway_run_is_not_imported_at_bridge_module_scope(bridge_mod) -> None:
    import inspect

    header = inspect.getsource(bridge_mod).split("def ")[0]
    assert "from gateway.run import" not in header
