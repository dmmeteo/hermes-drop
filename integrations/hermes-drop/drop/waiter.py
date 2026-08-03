"""One task per live drop, parked on the broker's own waiter. Zero polls.

``DropWaiter`` is the **latency path**. Everything it does, the reconciler can
also do from the journal alone (S6) — which is the point: the waiter makes the
status message update in the second the browser submits, and the reconciler makes
that outcome true anyway if the waiter, the loop or the whole gateway is gone.

**Why an ``await`` and not a poll.** ``broker.waitForSubmission`` caps its own
budget at ``expiresAt - now + 50`` and resolves ``unavailable`` at expiry
(``src/broker.js:315-341``), and the control server parks the connection on it
(``src/control-server.js``, ``case 'await'``). So one request, held open on an
``asyncio.open_unix_connection``, covers the whole TTL and self-terminates. There
is no timer, no interval and no second request on either side.

**Order of operations: edit → journal → announce** (§3.2), implemented once in
``reconciler.finalize_terminal`` and shared, so the fast path and the durable path
cannot drift.

**Three outcomes, and the one that must not become a claim.** ``submitted`` →
``received``. A broker answer of ``unavailable`` → ``expired``. *No* answer —
socket gone, malformed line, timeout — is ``transport_failed``: the payload's
fate is genuinely unknown, mirroring ``await``'s exit 1
(``bin/handoff-admin.mjs:31-36``), so the status message is edited to the expired
state but nothing is ever claimed on a guess.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, Optional

from . import journal as journal_mod
from . import reconciler as reconciler_mod
from . import sources as sources_mod

logger = logging.getLogger(__name__)

#: Added to the park budget so the broker's own expiry timer, not ours, is what
#: ends a lapsed wait. The broker already caps at ``expiresAt - now + 50``.
PARK_GRACE_MS = 2_000

#: The client-side backstop against a wedged socket, on top of the park budget.
#: Never the thing that decides an outcome — a timeout here is ``transport_failed``.
CLIENT_MARGIN_SECONDS = 30.0


class WaiterRegistry:
    """``{drop_id: task}``, bounded by the number of live drops.

    Bounded by construction rather than by a cap: a drop leaves the dict when its
    task finishes, and a drop's task always finishes at the TTL at the latest.
    Arming an already-armed drop is refused rather than duplicated — that is what
    makes a reconcile pass safe to run while waiters are already parked.
    """

    def __init__(self) -> None:
        self._tasks: Dict[str, Any] = {}

    def __len__(self) -> int:
        return len(self._tasks)

    def is_armed(self, drop_id: str) -> bool:
        task = self._tasks.get(drop_id)
        return task is not None and not task.done()

    def arm(
        self,
        drop_id: str,
        coro_factory: Callable[[], Any],
        *,
        loop: Any = None,
    ) -> bool:
        """Start one waiter task. ``False`` if this drop already has a live one.

        ``loop`` is for the rare caller that is not on the gateway loop; the
        normal path is already on it, because the tool handlers cross once
        through ``SyncBridge`` for the *whole* operation (``drop/bridge.py``).
        """
        if self.is_armed(drop_id):
            return False

        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        target = loop or running
        if target is None:
            logger.warning("hermes-drop: no loop to arm the waiter for %s", drop_id)
            return False

        try:
            coro = coro_factory()
        except Exception:  # pragma: no cover - defensive
            logger.warning("hermes-drop: could not build the waiter for %s", drop_id, exc_info=True)
            return False

        if running is target:
            task = target.create_task(coro)
        else:
            from agent.async_utils import safe_schedule_threadsafe

            task = safe_schedule_threadsafe(coro, target)
            if task is None:
                logger.warning("hermes-drop: gateway loop unavailable; %s not armed", drop_id)
                return False

        self._tasks[drop_id] = task
        task.add_done_callback(lambda _t, key=drop_id: self._tasks.pop(key, None))
        return True

    def cancel(self, drop_id: str) -> None:
        task = self._tasks.pop(drop_id, None)
        if task is not None and not task.done():
            task.cancel()

    def shutdown(self) -> None:
        """Cancel every live waiter. Cancellation is not a verdict: the journal
        entry stays ``waiting`` and the next startup reconcile picks it up.

        **Nothing in the gateway calls this**, and review L4 is right that §7.1's
        "the handle is kept … for cancellation and shutdown" was half-true. There
        is no plugin teardown or gateway-shutdown hook to call it from — see
        ``reconciler.request_shutdown`` for the full derivation from
        ``VALID_HOOKS``. No hook is invented here to make the sentence true.

        Benign, and specifically so: a waiter lost to a process exit leaves its
        journal entry ``waiting``, which is exactly the state the startup
        reconciler is built to resolve. Losing a waiter costs latency, never an
        outcome. ``cancel`` — which this is built from — *is* on the production
        path, via the done-callback in ``arm``.
        """
        for drop_id in list(self._tasks):
            self.cancel(drop_id)


#: The one production registry, mirroring ``sources.REGISTRY``.
REGISTRY = WaiterRegistry()


class DropWaiter:
    """The parked wait for one drop."""

    def __init__(
        self,
        *,
        journal: journal_mod.DropJournal,
        messenger: Any = None,
        control: Any = None,
        socket_path: Any = None,
        deliver: Optional[Callable[..., Any]] = None,
        clock: Callable[[], float] = time.time,
        registry: Any = None,
    ) -> None:
        from . import control_client
        from . import messenger as messenger_mod

        self._journal = journal
        self._messenger = messenger if messenger is not None else messenger_mod.OriginMessenger()
        self._control = control if control is not None else control_client
        self._socket_path = socket_path
        self._deliver = deliver
        self._clock = clock
        self._sources = registry if registry is not None else sources_mod.REGISTRY

    async def run(self, *, drop_id: str, origin: Any) -> Dict[str, Any]:
        """Park, then resolve. Never raises — this runs as a bare task on the
        gateway loop, where an escaping exception is only a log line and a lost
        drop."""
        try:
            return await self._run(drop_id=drop_id, origin=origin)
        except asyncio.CancelledError:
            # A shutdown, not an outcome. The journal entry stays `waiting`.
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("hermes-drop: waiter for %s failed: %s", drop_id, exc, exc_info=True)
            return {"error": "waiter_failed", "drop_id": drop_id, "detail": str(exc)}

    async def _run(self, *, drop_id: str, origin: Any) -> Dict[str, Any]:
        entry = self._journal.get(drop_id)
        if entry is None:
            return {"error": "gone", "drop_id": drop_id}
        if entry.get("state") in journal_mod.TERMINAL_STATES:
            return {"ok": True, "drop_id": drop_id, "state": entry["state"], "duplicate": True}

        # §4's second writer: an internal wake turn never runs the capture hook
        # (`gateway/run.py:13633`), so the routing-tuple lookup needs an entry a
        # restart did not put there.
        self._republish(origin)

        remaining_ms = float(entry.get("expires_at_ms") or 0) - self._clock() * 1000.0
        if remaining_ms <= 0:
            state = journal_mod.STATE_EXPIRED
        else:
            state = await self._park(drop_id, remaining_ms)

        result = await reconciler_mod.finalize_terminal(
            journal=self._journal,
            origin=origin,
            entry=entry,
            state=state,
            messenger=self._messenger,
            deliver=self._deliver,
            clock=self._clock,
        )
        self._republish(origin)
        return result

    async def _park(self, drop_id: str, remaining_ms: float) -> str:
        wait_ms = int(remaining_ms) + PARK_GRACE_MS
        try:
            response = await self._control.await_submission(
                drop_id,
                wait_ms=wait_ms,
                socket_path=self._socket_path,
                timeout=(wait_ms / 1000.0) + CLIENT_MARGIN_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 - the client is supposed not to raise
            logger.warning("hermes-drop: await raised for %s: %s", drop_id, exc)
            return journal_mod.STATE_TRANSPORT_FAILED

        if response.get("ok") and response.get("status") == "submitted":
            return journal_mod.STATE_RECEIVED
        if response.get("error") == "unavailable":
            # The broker's one body for expired, destroyed, consumed and lapsed.
            return journal_mod.STATE_EXPIRED
        # No answer *about this handoff*: broker_unavailable, invalid_request, a
        # malformed line. Unknown, and unknown never becomes a claim.
        return journal_mod.STATE_TRANSPORT_FAILED

    def _republish(self, origin: Any) -> None:
        try:
            self._sources.put(origin.source, gateway=origin.runner)
        except Exception:  # pragma: no cover - defensive
            logger.debug("hermes-drop: could not re-publish the waiter source", exc_info=True)


def arm_from_reconcile(*, drop_id: str, origin: Any, entry: Any = None) -> bool:
    """The ``arm`` callable the reconciler re-arms live drops with.

    Built here rather than passed in from ``register()`` so the reconciler never
    imports the waiter at module scope, and so a re-arm uses exactly the same
    waiter the initiating path does.
    """
    waiter = DropWaiter(journal=journal_mod.DropJournal())
    return REGISTRY.arm(drop_id, lambda: waiter.run(drop_id=drop_id, origin=origin))


__all__ = [
    "CLIENT_MARGIN_SECONDS",
    "PARK_GRACE_MS",
    "REGISTRY",
    "DropWaiter",
    "WaiterRegistry",
    "arm_from_reconcile",
]
