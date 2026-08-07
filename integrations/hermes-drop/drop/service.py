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

Its order is an argument too, and a shorter one: **ask, receive, then record.**
The broker destroys its copy as it answers, so everything before the answer may
fail freely and everything after it holds the only copy there is. That splits the
failures in two. Before: a refusal, and the drop is untouched — including
``response_too_large``, which the broker returns *without consuming* when the
answer would overrun the reader this client advertised (``max_response_bytes``,
``contract/control-protocol.json``). After: bookkeeping, which is no longer
allowed to fail the claim, because a ``claimed_at`` write that raised used to turn
a delivered secret into ``internal_error`` and nothing else.

Authorisation is the journal's, not this module's: the routing tuple, never
``session_key`` (§8.5). And it never consults ``announced_at`` — a claim must
work with no wake having landed at all.
"""

from __future__ import annotations

import base64
import binascii
import logging
import time
from typing import Any, Callable, Dict, Mapping, Optional

from . import journal as journal_mod
from . import render

logger = logging.getLogger(__name__)

ERROR_BROKER_UNAVAILABLE = "broker_unavailable"
ERROR_POST_FAILED = "post_failed"
ERROR_JOURNAL_FAILED = "journal_failed"
ERROR_UNAVAILABLE = "unavailable"
#: The broker sized the claim response against the ceiling this client advertised
#: and refused *before consuming*. Never folded into ``unavailable``: the payload
#: is intact and still claimable, and calling that "unavailable" would spend a
#: drop the broker deliberately did not.
ERROR_RESPONSE_TOO_LARGE = "response_too_large"

#: The broker predates the response-size capability *and* accepts payloads this
#: client could not read back, so a claim could still destroy one. Refused at
#: create, before a link exists to fill in.
ERROR_BROKER_TOO_OLD = "broker_too_old"

#: The standing fix for the size mismatch, in one place so that an operator
#: reading ``agent.log`` is never given two different instructions for the same
#: condition. The cap comes *down*: the reader's ceiling is a constant of this
#: client and cannot be raised.
SIZE_REMEDIATION = "Lower HANDOFF_MAX_PLAINTEXT_BYTES on the broker to %d or less."

#: Added only where a payload can actually be sitting in the broker — the
#: create-time warning (that drop is about to be posted) and the claim-time
#: refusal (something was submitted and is waiting). Deliberately *not* on the
#: ``broker_too_old`` abort: that drop is refused before its link is posted, so
#: nobody was ever asked for a secret and there is nothing to claim. Telling an
#: operator to run the CLI against an empty handoff would send them looking for a
#: payload that does not exist.
CLI_RECOVERY = (
    " A payload already waiting behind this ceiling can be recovered on the broker "
    "host with `handoff-admin claim %s` before it expires, because the admin CLI "
    "reads an unbounded line."
)

#: Said to the model when the payload arrived but ``claimed_at`` could not be
#: written. The secret is already in the result — withholding it would destroy the
#: only remaining copy — so what is left is to stop the retry that the unmarked
#: entry now looks to permit.
UNRECORDED_CLAIM_NOTE = (
    "This secret was delivered, but the local record of the claim could not be "
    "written. Do not call claim_private_input for this drop again: the broker has "
    "already destroyed its copy, so a retry can only fail. Use the value above."
)

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

        refusal = self._guard_claimability(drop_id, created)
        if refusal is not None:
            # Before the post, so there is nothing to retire and nobody has been
            # asked for anything. The minted handoff lapses at its own TTL, unseen
            # — the same argument §7.2 makes for a failed post, one step earlier.
            return refusal

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
    def _guard_claimability(drop_id: str, created: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Two questions, asked while the drop is still only a drop.

        *Can the broker refuse an oversized claim?* Only protocol 2 and above
        can; a version 1 broker takes ``max_response_bytes``, ignores it, and
        destroys the payload as it answers. So the capability is read off the
        ``create`` response (``supports_lossless_claim``) rather than assumed from
        this plugin's own version — the two are installed and upgraded separately.

        *Can this client read back everything the broker will accept?* The control
        client's response limit is a constant and base64 is ×4/3, so a broker
        configured past ``MAX_CLAIMABLE_PLAINTEXT_BYTES`` can accept a payload
        whose claim response overruns the reader (review N2, the survivor of
        review H2).

        Only the *combination* is unsafe, and only that combination is refused.
        Against a version 2 broker an oversized payload is refused before it is
        consumed, so the secret survives and the cost is a round trip — worth a
        warning, not an abort, because aborting would punish the common small
        payload for a ceiling only a large one can reach. Against a version 1
        broker within the readable range nothing is worse than it was under 0.4,
        so the version gap is said once and the drop proceeds. Version 1 *and* an
        unreadable cap is the one case where a claim can still destroy a secret
        with no refusal available anywhere — and there the drop dies here, before
        a link is posted and before anyone types a password into it.

        Returns the refusal to hand back, or ``None`` to carry on.
        """
        from . import control_client

        ceiling = control_client.MAX_CLAIMABLE_PLAINTEXT_BYTES
        lossless = control_client.supports_lossless_claim(created)
        try:
            cap = int(created.get("max_plaintext_bytes"))
        except (TypeError, ValueError):
            # An answer without a usable cap tells us nothing to act on; the
            # version gap, if there is one, is still worth saying.
            cap = None

        if cap is not None and cap > ceiling:
            if not lossless:
                # No CLI recovery advice here on purpose: this drop is refused
                # before its link is posted, so nothing was ever submitted and
                # `handoff-admin claim` would find an empty handoff. The minted
                # one lapses at its TTL, unseen and unusable.
                logger.error(
                    "hermes-drop: refusing drop %s before posting it, and nothing was "
                    "posted or submitted — the handoff simply lapses. The broker speaks "
                    "control protocol %s, which cannot refuse an oversized claim before "
                    "consuming it, and it accepts up to %d plaintext bytes while a claim "
                    "response is only read up to %d — so a large payload would be "
                    "destroyed on claim. Either upgrade the broker to protocol %d or "
                    "newer, or bring its cap into range: " + SIZE_REMEDIATION,
                    drop_id,
                    created.get("protocol_version", 1),
                    cap,
                    ceiling,
                    control_client.PROTOCOL_VERSION,
                    ceiling,
                )
                return {"error": ERROR_BROKER_TOO_OLD}

            logger.warning(
                "hermes-drop: the broker accepts up to %d plaintext bytes but a claim "
                "response is only read up to %d (drop %s). A payload above that ceiling "
                "is refused on claim, not delivered: the secret is left intact in the "
                "broker but this plugin cannot read it back. " + SIZE_REMEDIATION + CLI_RECOVERY,
                cap,
                ceiling,
                drop_id,
                ceiling,
                drop_id,
            )
            return None

        if not lossless:
            # Readable range, old broker: exactly as safe as 0.4 was, which is why
            # this is a note and not a refusal. Said once per drop, in agent.log,
            # because the fix is an upgrade nobody will schedule unprompted.
            logger.warning(
                "hermes-drop: the broker speaks control protocol %s; %d added the "
                "pre-consumption size check that makes an oversized claim a refusal "
                "instead of a destroyed payload (drop %s). Nothing this broker accepts "
                "is too large to read back, so the drop proceeds — but upgrade the "
                "broker to keep it that way if its cap ever changes.",
                created.get("protocol_version", 1),
                control_client.PROTOCOL_VERSION,
                drop_id,
            )
        return None

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
            error = result.get("error")
            if error == ERROR_BROKER_UNAVAILABLE:
                # The broker did not answer. The payload's fate is unknown, so
                # the drop is *not* marked spent and an identical retry is legal.
                return {"error": ERROR_BROKER_UNAVAILABLE, "detail": result.get("detail") or ""}
            if error == ERROR_RESPONSE_TOO_LARGE:
                # Nothing was consumed, by construction (``src/broker.js``). The
                # numbers are an operator's problem — HANDOFF_MAX_PLAINTEXT_BYTES
                # against this client's reader — so they go to agent.log, not to
                # the model, and the drop stays claimable until its TTL lapses.
                # Same remediation sentence as the create-time messages: one
                # condition must not come with two sets of instructions.
                from . import control_client

                logger.error(
                    "hermes-drop: the broker refused to consume drop %s: the claim "
                    "response needs %s bytes and this client reads at most %s. The "
                    "payload is intact and still claimable until the link expires. "
                    + SIZE_REMEDIATION
                    + CLI_RECOVERY,
                    drop_id,
                    result.get("required_bytes"),
                    result.get("max_response_bytes"),
                    control_client.MAX_CLAIMABLE_PLAINTEXT_BYTES,
                    drop_id,
                )
                return {"error": ERROR_RESPONSE_TOO_LARGE}
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

        claimed: Dict[str, Any] = {"ok": True, "drop_id": drop_id, "private_input": plaintext}
        if not self._record_claim(drop_id):
            claimed["note"] = UNRECORDED_CLAIM_NOTE
        return claimed

    def _record_claim(self, drop_id: str) -> bool:
        """Mark the drop spent. ``False`` when the durable record did not take it.

        Deliberately not allowed to fail the claim. By the time this runs the
        broker has retired its record (``src/broker.js``), so this process holds
        the only copy of the secret — and until this returned, an ``OSError`` from
        a full or read-only ``$HERMES_HOME`` propagated out of ``claim`` into
        ``_guarded``, which answered ``internal_error`` and dropped the payload on
        the floor. A bookkeeping failure destroying a secret the system had
        already successfully delivered is a worse outcome than an unmarked entry
        in every case, so the ordering stands and the failure is contained here.

        The unmarked entry is not silently tolerated either: it is an ``ERROR``
        line for the operator, and the caller says so in its result. What it
        cannot cause is a second delivery — ``authorize_claim`` will let the retry
        through, and the broker's payload-free receipt refuses it. That is the
        same one-shot guarantee as always, enforced where it has always been
        enforced, which is why this needs no distributed transaction.
        """
        try:
            if self._journal.update(drop_id, claimed_at=self._clock()) is not None:
                return True
            reason = "the entry was gone"
        except Exception as exc:  # noqa: BLE001 - OSError, JournalRejected, anything
            reason = str(exc)
        logger.error(
            "hermes-drop: delivered drop %s but could not mark it claimed (%s). The "
            "secret was handed to the caller; the durable record still shows it "
            "unclaimed. A retry cannot re-deliver it — the broker keeps only a "
            "payload-free receipt — but the journal now understates what happened.",
            drop_id,
            reason,
        )
        return False


__all__ = [
    "CLI_RECOVERY",
    "ERROR_BROKER_TOO_OLD",
    "ERROR_BROKER_UNAVAILABLE",
    "ERROR_JOURNAL_FAILED",
    "ERROR_POST_FAILED",
    "ERROR_RESPONSE_TOO_LARGE",
    "ERROR_UNAVAILABLE",
    "RECEIPT_NOTE",
    "SIZE_REMEDIATION",
    "UNRECORDED_CLAIM_NOTE",
    "DropService",
]
