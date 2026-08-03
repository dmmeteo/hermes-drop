"""Telling the session that something happened. Best-effort, by design.

``deliver_wake`` is the **latency path only** (plan §3.3). A regression there
degrades promptness, not correctness, because the journal is the durable record
and ``claim_private_input`` reads the journal, not the wake.

Two rules make at-least-once delivery safe rather than merely tolerable:

* **Announce the set, not the drop.** One wake names *every* terminal-but-
  unannounced drop in the lane. A queued wake is newline-appended into the
  pending head (``gateway/platforms/base.py:2487-2494``) — a merge core itself
  calls a bug (``gateway/run.py:8593-8600``) — so a wake that is only meaningful
  next to its siblings would be destroyed by it. A self-contained one is not.
* **Bounded attempts.** ``deliver_wake`` raises on failure, and the busy handler
  can silently drop a wake before the internal branch is ever reached
  (``gateway/run.py:8356-8365`` vs ``:8486-8487``). Retrying forever would be a
  loop with no observer; after ``MAX_ANNOUNCE_ATTEMPTS`` the entry stays terminal
  and unannounced, the user still has the edited status message, and the model
  can still claim.

Nothing here carries a capability, a URL or a payload. The wake text names
``drop_id``s, which the contract calls "non-secret and safe to log", and the
purposes the model itself supplied.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from . import journal as journal_mod

logger = logging.getLogger(__name__)

#: Said in the text the model reads, not only in the plan: a repeat notice is
#: possible and harmless, and a missing one is not a lost drop.
AT_LEAST_ONCE_NOTE = (
    "This notice is at-least-once and idempotent: if you have already handled one "
    "of these, ignore it. If no notice arrives, the drop is still recorded and "
    "claim_private_input still works."
)

_STATE_PROSE = {
    journal_mod.STATE_RECEIVED: (
        "received — call claim_private_input with this drop_id, exactly once, "
        "to retrieve the private input"
    ),
    journal_mod.STATE_EXPIRED: "expired — nothing was submitted before the link lapsed",
    journal_mod.STATE_TRANSPORT_FAILED: (
        "did not complete — the broker never answered, so whether anything was "
        "submitted is genuinely unknown; do not claim"
    ),
}


def _default_deliver() -> Callable[..., Any]:
    """Imported inside the call: ``gateway.wake`` is not needed to register the
    plugin, and this module is reached during discovery."""
    from gateway.wake import deliver_wake

    return deliver_wake


def build_announce_text(entries: Sequence[Mapping[str, Any]]) -> str:
    """One self-contained wake for a whole lane."""
    lines = [
        "🔐 Private input update — "
        f"{len(entries)} drop{'s' if len(entries) != 1 else ''} in this conversation "
        "reached a final state:"
    ]
    for entry in entries:
        state = str(entry.get("state") or "")
        purpose = str(entry.get("purpose") or "").strip()
        label = f" ({purpose})" if purpose else ""
        lines.append(
            f"• drop:{entry.get('drop_id')}{label} — "
            f"{_STATE_PROSE.get(state, state)}."
        )
    lines.append(AT_LEAST_ONCE_NOTE)
    return "\n".join(lines)


async def announce_pending(
    *,
    journal: journal_mod.DropJournal,
    origin: Any,
    deliver: Optional[Callable[..., Any]] = None,
    clock: Callable[[], float] | None = None,
) -> Dict[str, Any]:
    """Announce every terminal-but-unannounced drop in *origin*'s lane.

    Never raises: the callers are a background reconcile pass and a long-lived
    waiter task, and an exception escaping either would abandon work the journal
    says still needs doing.
    """
    now = (clock or time.time)()
    pending: List[Dict[str, Any]] = journal.terminal_unannounced(origin.routing_tuple)
    if not pending:
        return {"ok": True, "announced": []}

    text = build_announce_text(pending)
    send = deliver if deliver is not None else _default_deliver()

    try:
        await send(origin.adapter, text=text, source=origin.source)
    except Exception as exc:  # noqa: BLE001 - deliver_wake raises on failure by contract
        logger.warning(
            "hermes-drop: wake delivery failed for %s: %s", origin.routing_tuple, exc
        )
        for entry in pending:
            journal.update(
                entry["drop_id"],
                announce_attempts=int(entry.get("announce_attempts") or 0) + 1,
            )
        return {"error": "announce_failed", "detail": str(exc), "announced": []}

    announced = []
    for entry in pending:
        journal.update(
            entry["drop_id"],
            announced_at=now,
            announce_attempts=int(entry.get("announce_attempts") or 0) + 1,
        )
        announced.append(entry["drop_id"])
    return {"ok": True, "announced": announced}


__all__ = ["AT_LEAST_ONCE_NOTE", "announce_pending", "build_announce_text"]
