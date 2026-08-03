"""The one async domain workflow. Both entry points call *this*, not each other.

``/drop`` and ``request_private_input`` differ only in how they reach here: the
command is already on the gateway loop, the tool crosses once through
``SyncBridge`` for the whole operation (``drop/bridge.py``). Neither re-implements
any of the steps below, which is what makes "the command and the tool are the
same operation" a property rather than an intention.

**create** — mint, post, journal, arm. In that order, and the order is the
argument:

1. *Mint* first, because the notice cannot be rendered without the URL, and the
   broker validates ``notice_platform`` before minting anything
   (``src/control-server.js``), so an unsupported platform costs no handoff.
2. *Post* second. If the post fails the drop is **aborted**: no journal entry, no
   waiter, ``{"error": "post_failed"}``. A live capability whose link was never
   delivered is pure risk (§7.2). The minted handoff is left to lapse at its own
   TTL — the control protocol has no destroy op, and inventing one to cover a
   failed send would be a bigger change than the risk it removes.
3. *Journal* third: from here the drop is recoverable without any live task.
4. *Arm* last, because the waiter is the latency path and everything before it
   already made the outcome durable.

**claim** — the only path by which plaintext enters the conversation, and it
enters as a *tool result*, where ``transform_tool_result`` operates on the string
before it re-enters context (``model_tools.py:1380-1412``); wake text has no
equivalent hook. Durable ``state.db`` exposure is unchanged and still accepted —
this buys a future sanitization seam, not a guarantee (§3.2).

Authorisation is the journal's, not this module's: the routing tuple, never
``session_key`` (§8.5). And it never consults ``announced_at`` — a claim must
work with no wake having landed at all.
"""

from __future__ import annotations

import base64
import binascii
import logging
import time
from typing import Any, Callable, Dict, Optional

from . import journal as journal_mod
from . import render

logger = logging.getLogger(__name__)

ERROR_BROKER_UNAVAILABLE = "broker_unavailable"
ERROR_POST_FAILED = "post_failed"
ERROR_JOURNAL_FAILED = "journal_failed"
ERROR_UNAVAILABLE = "unavailable"

#: Said in the receipt, because the model is the party that has to behave
#: idempotently when a second notice arrives.
RECEIPT_NOTE = (
    "The link is now in this conversation and nowhere else. You will be told when "
    "it is used — that notice is at-least-once and idempotent, so a repeat is "
    "harmless and a missing one loses nothing. Then call claim_private_input with "
    "this drop_id, exactly once."
)


class DropService:
    """Create and claim. Async end to end; nothing here blocks the gateway loop."""

    def __init__(
        self,
        *,
        journal: Optional[journal_mod.DropJournal] = None,
        messenger: Any = None,
        control: Any = None,
        socket_path: Any = None,
        waiters: Any = None,
        deliver: Optional[Callable[..., Any]] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        from . import control_client
        from . import messenger as messenger_mod
        from . import waiter as waiter_mod

        self._journal = journal if journal is not None else journal_mod.DropJournal()
        self._messenger = messenger if messenger is not None else messenger_mod.OriginMessenger()
        self._control = control if control is not None else control_client
        self._socket_path = socket_path
        self._waiters = waiters if waiters is not None else waiter_mod.REGISTRY
        self._deliver = deliver
        self._clock = clock

    # -- create -------------------------------------------------------------

    async def create(
        self,
        origin: Any,
        *,
        ttl_seconds: int,
        purpose: str = "",
        session_key: str = "",
    ) -> Dict[str, Any]:
        """Mint a handoff, post its link into *origin*'s conversation, and arm.

        ``ttl_seconds`` rather than minutes: the minute bound (1..60) is the
        model-facing schema's, enforced in ``drop/tools.py`` before anything gets
        here, and the broker speaks seconds.
        """
        # The platform gate, again, here. Both existing callers check it first
        # (``tools.py``, ``command.py``) and §7.3 requires the refusal to happen
        # "before creating anything" — but that made the invariant a property of
        # every caller remembering rather than of this method. An unsupported
        # platform falls through ``renderer_for`` to ``"plain"``, which the broker
        # accepts (``src/control-server.js:17``), so a third caller would post to
        # an unverified platform silently rather than fail (review L3).
        #
        # Not redundant in the sense that matters: this is the check that is
        # adjacent to the mint, and it is the last one before a capability exists.
        if not render.is_supported(origin.platform_name):
            return render.unsupported_error(origin.platform_name)

        created = await self._control.create(
            ttl_seconds=int(ttl_seconds),
            notice_platform=render.renderer_for(origin.platform_name),
            socket_path=self._socket_path,
        )
        if not created.get("ok"):
            error = created.get("error") or ERROR_BROKER_UNAVAILABLE
            return {
                "error": ERROR_BROKER_UNAVAILABLE if error != "invalid_request" else error,
                "detail": created.get("detail") or "the broker refused to mint a handoff",
            }

        drop_id = created.get("handoff_id") or ""
        notice = created.get("notice") or ""

        self._warn_if_unclaimable(drop_id, created.get("max_plaintext_bytes"))

        posted = await self._messenger.post_status(origin, notice)
        if "error" in posted:
            # Aborted, not degraded. Nothing is journalled and nothing is armed;
            # the handoff lapses at its own TTL, unseen and unusable.
            logger.warning("hermes-drop: aborting drop %s, post failed", drop_id)
            return posted

        message_id = posted["message_id"]

        try:
            self._journal.create_entry(
                drop_id=drop_id,
                origin=origin,
                message_id=message_id,
                expires_at_ms=int(created.get("expires_at") or 0),
                ttl_seconds=int(created.get("ttl_seconds") or ttl_seconds),
                purpose=purpose or "",
                session_key=session_key or "",
                notice_received=created.get("notice_received") or "",
                notice_expired=created.get("notice_expired") or "",
            )
        except Exception as exc:  # noqa: BLE001 - JournalRejected, OSError, anything
            logger.warning("hermes-drop: journal write failed for %s: %s", drop_id, exc)
            # The link is live and nothing durable is watching it. Retire what
            # the user can see rather than leave a link that will never update.
            await self._messenger.update_status(
                origin, message_id, created.get("notice_expired") or ""
            )
            return {"error": ERROR_JOURNAL_FAILED, "detail": str(exc)}

        self._arm(drop_id, origin)

        expires_at_ms = int(created.get("expires_at") or 0)
        return {
            "ok": True,
            "drop_id": drop_id,
            "state": journal_mod.STATE_WAITING,
            "platform": origin.platform_name,
            "purpose": purpose or "",
            "expires_at_ms": expires_at_ms,
            "expires_in_seconds": max(0, int(expires_at_ms / 1000.0 - self._clock())),
            "note": RECEIPT_NOTE,
        }

    @staticmethod
    def _warn_if_unclaimable(drop_id: str, max_plaintext_bytes: Any) -> None:
        """Say so at create time if the broker will accept more than we can read.

        The control client's response limit is a constant, and base64 is ×4/3, so a
        broker configured past ``MAX_CLAIMABLE_PLAINTEXT_BYTES`` can accept a
        payload whose claim response overruns the reader. The claim then comes back
        ``broker_unavailable`` — after ``broker.claim`` has already retired the
        record, so the secret is gone (review N2, the survivor of review H2).

        Deliberately a warning and not a refusal. Aborting every drop would punish
        the common small payload for a ceiling only a large one can reach, and the
        operator who raised ``HANDOFF_MAX_PLAINTEXT_BYTES`` is the only party who
        can lower it again. So the plugin names both numbers in ``agent.log`` while
        the drop is still just a drop. The default (65536, ``src/config.js``) is an
        order of magnitude clear of the ceiling, and a test pins that.
        """
        from . import control_client

        try:
            cap = int(max_plaintext_bytes)
        except (TypeError, ValueError):
            return
        if cap > control_client.MAX_CLAIMABLE_PLAINTEXT_BYTES:
            logger.warning(
                "hermes-drop: the broker accepts up to %d plaintext bytes but a claim "
                "response is only read up to %d (drop %s). A payload above that "
                "ceiling will be destroyed on claim and reported unavailable. Lower "
                "HANDOFF_MAX_PLAINTEXT_BYTES on the broker.",
                cap,
                control_client.MAX_CLAIMABLE_PLAINTEXT_BYTES,
                drop_id,
            )

    def _arm(self, drop_id: str, origin: Any) -> None:
        from . import waiter as waiter_mod

        waiter = waiter_mod.DropWaiter(
            journal=self._journal,
            messenger=self._messenger,
            control=self._control,
            socket_path=self._socket_path,
            deliver=self._deliver,
            clock=self._clock,
        )
        try:
            self._waiters.arm(drop_id, lambda: waiter.run(drop_id=drop_id, origin=origin))
        except Exception:  # pragma: no cover - defensive
            # A drop with no waiter is still a drop: the reconciler resolves it
            # from the journal at the next trigger. Losing the latency path is
            # not worth losing the create for.
            logger.warning("hermes-drop: could not arm a waiter for %s", drop_id, exc_info=True)

    # -- claim --------------------------------------------------------------

    async def claim(self, origin: Any, drop_id: str) -> Dict[str, Any]:
        entry = self._journal.get(drop_id)
        refusal = journal_mod.authorize_claim(entry, origin)
        if refusal is not None:
            return refusal

        result = await self._control.claim(drop_id, socket_path=self._socket_path)
        if not result.get("ok"):
            if result.get("error") == ERROR_BROKER_UNAVAILABLE:
                # The broker did not answer. The payload's fate is unknown, so
                # the drop is *not* marked spent and an identical retry is legal.
                return {"error": ERROR_BROKER_UNAVAILABLE, "detail": result.get("detail") or ""}
            return {"error": ERROR_UNAVAILABLE}

        encoded = result.get("plaintext_b64")
        if not encoded:
            # After a successful claim the broker keeps a payload-free receipt
            # (``src/broker.js:81-91``). That is not a re-delivery and must never
            # be dressed up as one.
            return {"error": ERROR_UNAVAILABLE}

        try:
            plaintext = base64.b64decode(encoded, validate=True).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError) as exc:
            logger.warning("hermes-drop: undecodable payload for %s: %s", drop_id, exc)
            return {"error": ERROR_UNAVAILABLE, "detail": "payload could not be decoded"}

        self._journal.update(drop_id, claimed_at=self._clock())
        return {"ok": True, "drop_id": drop_id, "private_input": plaintext}


__all__ = [
    "ERROR_BROKER_UNAVAILABLE",
    "ERROR_JOURNAL_FAILED",
    "ERROR_POST_FAILED",
    "ERROR_UNAVAILABLE",
    "RECEIPT_NOTE",
    "DropService",
]
