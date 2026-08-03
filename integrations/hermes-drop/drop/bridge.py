"""The one worker-thread → gateway-loop crossing.

Where each entry point runs, verified against source:

* ``/drop`` is awaited **on** the gateway loop (``gateway/run.py:14697-14698``).
* ``pre_gateway_dispatch`` runs on the gateway loop too (``:13636``).
* A model tool handler runs on a ``ThreadPoolExecutor`` worker, reached via
  ``_run_in_executor_with_context`` (``gateway/run.py:18604`` → ``:20276-20285``).

Only the third needs a bridge, and it crosses **once**, for the whole operation.

Two bugs from revision 1 of the plan are fixed here and pinned by tests:

1. It used the bridge *inside* the messenger, so the ``/drop`` and hook paths hit
   it too — scheduling onto the loop you are currently blocking is a guaranteed
   stall for the full timeout on every invocation. Hence the explicit
   loop-identity check and the ``would_deadlock`` refusal.
2. It called ``.result()`` on ``safe_schedule_threadsafe``'s return value, which is
   ``Optional[Future]`` and is ``None`` when the loop is missing or was closed
   during a shutdown race (``agent/async_utils.py:41, 56-60``) — an
   ``AttributeError``, not an error result.

Nothing escapes as an exception. A raising tool handler is swallowed with a
warning at ``gateway/run.py:14701-14702`` and execution **falls through to
skill-command resolution** at ``:14705+``, so an exception here would silently
become a ``/skill drop`` lookup — resurrecting the exact path this design severs.

Every failure path closes the coroutine, so a refusal never produces a
"coroutine was never awaited" warning or leaks its frame.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any, Callable, Dict, Optional

from agent.async_utils import safe_schedule_threadsafe

logger = logging.getLogger(__name__)

#: Initiation must always return inside the turn (§3.2: < 20 s).
CREATE_TIMEOUT_SECONDS = 20
#: A claim is one control round trip against an in-process broker.
CLAIM_TIMEOUT_SECONDS = 10

ERROR_GATEWAY_UNAVAILABLE = "gateway_unavailable"
ERROR_WOULD_DEADLOCK = "would_deadlock"
ERROR_GATEWAY_TIMEOUT = "gateway_timeout"
ERROR_INTERNAL = "internal_error"


def _default_runner_resolver() -> Any:
    """Read the live runner handle, importing ``gateway.run`` inside the function.

    ``_gateway_runner_ref`` is a module global initialised to a ``lambda: None``
    sentinel (``gateway/run.py:3121``) and rebound during
    ``GatewayRunner.__init__`` (``:5513, 5536``), so it must be read per call —
    a value captured at plugin-discovery time is the sentinel forever.
    """
    try:
        from gateway.run import _gateway_runner_ref

        return _gateway_runner_ref()
    except Exception:
        logger.debug("hermes-drop: no gateway runner available", exc_info=True)
        return None


def _close(coro: Any) -> None:
    if asyncio.iscoroutine(coro):
        coro.close()


class SyncBridge:
    """Run one coroutine on the gateway loop from a worker thread.

    ``runner_resolver`` and ``scheduler`` are injected so the loop-identity and
    ``None``-future branches are reachable in a test without a live gateway. Both
    default to the production path.
    """

    def __init__(
        self,
        runner_resolver: Optional[Callable[[], Any]] = None,
        *,
        scheduler: Callable[..., Optional["concurrent.futures.Future"]] = safe_schedule_threadsafe,
    ) -> None:
        self._resolve_runner = runner_resolver or _default_runner_resolver
        self._schedule = scheduler

    def run(self, coro: Any, *, timeout: float) -> Any:
        runner = self._resolve_runner()
        loop = getattr(runner, "_gateway_loop", None) if runner is not None else None
        if loop is None:
            _close(coro)
            return {"error": ERROR_GATEWAY_UNAVAILABLE}

        try:
            current = asyncio.get_running_loop()
        except RuntimeError:
            current = None

        if current is loop:
            # We ARE the loop. Scheduling onto it and blocking on the future
            # would stall for the whole timeout, deterministically.
            _close(coro)
            return {"error": ERROR_WOULD_DEADLOCK}

        future = self._schedule(coro, loop)
        if future is None:
            # The coroutine is already closed by safe_schedule_threadsafe on
            # every failure path (agent/async_utils.py:41, 56-60).
            return {"error": ERROR_GATEWAY_UNAVAILABLE}

        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            # Cancel, or the coroutine keeps running on the gateway loop after
            # the caller has stopped waiting for it.
            future.cancel()
            logger.warning("hermes-drop: gateway work exceeded %ss; cancelled", timeout)
            return {"error": ERROR_GATEWAY_TIMEOUT}
        except concurrent.futures.CancelledError:
            return {"error": ERROR_GATEWAY_TIMEOUT}
        except Exception as exc:
            logger.warning("hermes-drop: gateway work raised: %s", exc, exc_info=True)
            return {"error": ERROR_INTERNAL, "detail": str(exc)}


__all__ = [
    "CLAIM_TIMEOUT_SECONDS",
    "CREATE_TIMEOUT_SECONDS",
    "ERROR_GATEWAY_TIMEOUT",
    "ERROR_GATEWAY_UNAVAILABLE",
    "ERROR_INTERNAL",
    "ERROR_WOULD_DEADLOCK",
    "SyncBridge",
    "safe_schedule_threadsafe",
]
