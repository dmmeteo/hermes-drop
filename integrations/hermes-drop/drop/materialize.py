"""One file claim, end to end: authorize, transfer, publish — or nothing.

The service half of slice 4. ``file_claim.py`` owns the socket conversation,
``spool.py`` owns the filesystem; this module owns the *policy* — who may claim,
what is published, what is discarded, what is held, and what a caller is allowed
to do next.

**Authorization is performed here, not by the caller.** ``origin`` is a required
argument and ``journal.authorize_claim`` runs before a staging directory or a
transfer lease exists, so an unauthorized claim costs neither. That is deliberate
rather than defensive: a "thin wrapper" at slice 5 that forgot the check would
otherwise ship an unauthenticated file-claim tool, and the routing tuple — never
``session_key`` (§8.5) — is the same rule the text path uses in
``DropService.claim``. ``DropService.claim_files`` adds the other half a tool
needs: the durable record of a spent drop.

**The order is the argument.** Authorize, stage, transfer, publish:

1. *Authorize first.* Before anything exists, so a refusal costs nothing and
   consumes nothing.
2. *Stage second.* The private directory exists before ``begin_file_claim`` does.
   A spool that cannot be used therefore costs a refusal and nothing else — the
   alternative discovers it after a lease was granted and a container was streamed
   to nowhere.
3. *Transfer third*, straight into the staging directory through the chunk sink.
   Each file is fsynced and re-verified from disk before its frame is acked, so
   nothing this side acknowledges is unwritten — and because that check precedes
   the ack, a failure leaves the payload the broker's, intact and claimable.
4. *Publish last*, on the broker's ``commit → ok`` and never on this side's own
   self-check. The broker holds the manifest and never sent the digests
   (``contract/control-protocol.json`` → ``file_claim.digests_are_not_echoed``),
   so its ok is the verification verdict; the publish is one rename after it.

**Every refusal says what may happen next**, because the caller cannot work it
out from an error code and getting it wrong destroys files:

``retry_safe``
    The payload was provably not consumed, so the same claim may be attempted
    again.
``mark_spent``
    The broker has retired the payload, so the durable record should show the
    drop as used and a retry can only fail.

The pair is never both true, and ``transfer_indeterminate`` is the one verdict
where both are false: the commit went out and no answer came back, so the payload
may or may not have been retired. Publishing would assert a verification that
never happened, retrying could compound it, and marking it spent could throw away
a live drop — so the bytes are quarantined, the drop id is logged for an operator,
and the TTL settles it (contract, ``file_claim.client_verdicts``).

**A cancellation is one of the ways that happens.** ``CancelledError`` is a
``BaseException``, so no ``except Exception`` sees it, and the commit line is
flushed by ``writer.close()`` on the way out of ``receive_file_claim`` — a gateway
shutdown or an abandoned turn in that window used to leave the broker's payload
retired and this side's staging directory *deleted*, with an exception instead of
a verdict and nothing logged. So the commit-written signal is read from the
receiver's own ``progress`` dict, the bytes are held with a synchronous rename that
cannot be interrupted by the cancellation that triggered it, and the cancellation
then propagates as it must.

**Nothing that leaves here carries a byte of content.** The result is paths,
labels, sizes and digests: safe for a tool result, ``state.db`` and a log line.
Contents are never returned, never journalled and never logged, and the transfer
runs with ``keep_bytes=False`` so they are not even retained in memory.

**``name`` and ``type`` are untrusted display text, and slice 5 has to treat them
that way.** They are whatever the uploader called the file: sanitized for *path*
safety and for control characters, capped at 255 bytes, and otherwise arbitrary —
up to and including a sentence that reads like an instruction. A tool result must
present them as clearly delimited data, and a tool description should say the
model may not act on them. The same goes for ``path``: it is a name, not a
descriptor, and its integrity rests on the spool's ancestor chain (``spool.py``).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, Mapping, Optional, Sequence

from . import spool as spool_mod
from .control_client import (
    BROKER_UNAVAILABLE,
    TRANSFER_FAILED,
    TRANSFER_INDETERMINATE,
    PathLike,
)

logger = logging.getLogger(__name__)

#: The drop is over: claimed already, expired, or never existed. When the *broker*
#: says so the durable record may be marked spent; when the journal says so there
#: is nothing to mark.
ERROR_UNAVAILABLE = "unavailable"
ERROR_BROKER_UNAVAILABLE = BROKER_UNAVAILABLE
ERROR_INVALID_REQUEST = "invalid_request"

#: Journal refusals, forwarded with their own (local, useful) details.
ERROR_NOT_AUTHORIZED = "not_authorized"
ERROR_NOT_READY = "not_ready"

#: Verdicts produced by the receiver, forwarded with this module's policy fields.
ERROR_TRANSFER_FAILED = TRANSFER_FAILED
ERROR_TRANSFER_INDETERMINATE = TRANSFER_INDETERMINATE

#: There is nowhere private to write. Raised before the transfer begins, so the
#: drop is untouched — an operator problem, not a model one.
ERROR_SPOOL_UNAVAILABLE = "spool_unavailable"

#: The spool is holding as many claims as its byte budget allows. Nothing is
#: wrong; the same claim will work shortly.
ERROR_SPOOL_BUSY = "spool_busy"

#: The bytes could not be written, or could not be proved to have landed. Nothing
#: was acked past the failure, so the payload is still the broker's.
ERROR_SPOOL_WRITE_FAILED = "spool_write_failed"

#: The bytes arrived and were verified, and then could not be made reachable.
#: The one refusal after which the payload is gone and nothing can be retried.
ERROR_SPOOL_PUBLISH_FAILED = "spool_publish_failed"

#: Fixed, local, and free of paths, labels and exception text. ``safe_errors``
#: replaces these on the way to a model anyway; they exist for ``agent.log`` and
#: for a caller that logs the verdict it got.
_DETAILS = {
    ERROR_SPOOL_UNAVAILABLE: "the local file staging area is not usable",
    ERROR_SPOOL_BUSY: "too many file claims are already in flight",
    ERROR_SPOOL_WRITE_FAILED: "the files could not be written to local storage",
    ERROR_SPOOL_PUBLISH_FAILED: "the files could not be published after they were verified",
    ERROR_TRANSFER_FAILED: "the transfer did not complete",
    ERROR_TRANSFER_INDETERMINATE: "the transfer ended without a verdict",
    ERROR_UNAVAILABLE: "this drop is no longer available",
    ERROR_BROKER_UNAVAILABLE: "the private-input service is not reachable",
    ERROR_INVALID_REQUEST: "the request was not usable",
}

#: ``(retry_safe, mark_spent)`` per code. Written as a table because the two
#: fields are a policy and a policy that lives in branches drifts.
_POLICY = {
    ERROR_SPOOL_UNAVAILABLE: (True, False),
    ERROR_SPOOL_BUSY: (True, False),
    ERROR_SPOOL_WRITE_FAILED: (True, False),
    ERROR_SPOOL_PUBLISH_FAILED: (False, True),
    ERROR_TRANSFER_FAILED: (True, False),
    ERROR_TRANSFER_INDETERMINATE: (False, False),
    ERROR_UNAVAILABLE: (False, True),
    ERROR_BROKER_UNAVAILABLE: (True, False),
    ERROR_INVALID_REQUEST: (False, False),
}

#: A receive callable with ``file_claim.receive_file_claim``'s signature.
Receiver = Callable[..., Awaitable[Mapping[str, Any]]]


def _refusal(error: str, drop_id: str) -> Dict[str, Any]:
    retry_safe, mark_spent = _POLICY.get(error, (False, False))
    return {
        # ``ok`` is present and false, matching ``file_claim``'s and
        # ``control_client``'s verdict dicts: a caller that branches on
        # ``result.get("ok")`` must not have to know which of the three it is
        # holding.
        "ok": False,
        "error": error,
        "detail": _DETAILS.get(error, "the file claim could not be completed"),
        "drop_id": drop_id,
        "retry_safe": retry_safe,
        "mark_spent": mark_spent,
    }


def _from_authorization(refusal: Mapping[str, Any], drop_id: str) -> Dict[str, Any]:
    """A journal refusal, with the policy fields a caller needs added.

    The journal's ``detail`` is kept: "no such drop" and "already claimed; the
    payload is destroyed" are locally authored, and the model needs to tell them
    apart. ``mark_spent`` is always false here — the journal is the thing that
    would be marked, and it has already answered — and only ``not_ready`` is
    retryable, because that drop has simply not been submitted yet.
    """
    result = dict(refusal)
    code = str(result.get("error") or ERROR_UNAVAILABLE)
    result["ok"] = False
    result["drop_id"] = drop_id
    result["retry_safe"] = code == ERROR_NOT_READY
    result["mark_spent"] = False
    return result


async def materialize_file_claim(
    drop_id: str,
    origin: Any,
    *,
    journal: Optional[Any] = None,
    socket_path: Optional[PathLike] = None,
    spool: Optional[spool_mod.Spool] = None,
    receive: Optional[Receiver] = None,
    lease_ms: Optional[int] = None,
    timeout: Optional[float] = None,
) -> Dict[str, Any]:
    """Claim one file drop into the spool. Never returns without a verdict.

    On success::

        {"ok": True, "drop_id": ..., "claim_id": ..., "expires_at": <epoch s>,
         "files": [{"path": "/abs/path", "name": "config.json", "type": "...",
                    "size": 1234, "sha256": "<64 hex>"}]}

    ``path`` is the agent attachment boundary: a Hermes tool can read or attach it
    without a byte entering the transcript. ``name`` is the submitted filename as
    an untrusted *label* — it never appeared in a path — and it is sanitized again
    here because it is about to enter a model's context.

    Every other answer is a refusal carrying ``retry_safe`` and ``mark_spent``;
    none of them carries ``files``, so a partial claim can never be mistaken for
    a small one. The only thing that propagates instead of answering is
    ``CancelledError``, and it does so *after* the received bytes are safe.
    """
    if journal is None:
        from . import journal as journal_mod

        journal = journal_mod.DropJournal()

    refusal = _authorize(journal, drop_id, origin)
    if refusal is not None:
        return refusal

    spool = spool if spool is not None else spool_mod.Spool()
    receiver: Receiver = receive if receive is not None else _default_receiver()

    # The startup purge (blocking, latched) and the periodic sweep. Both are
    # armed here *and* from the reconciler's pass; a claim is the backstop, since
    # plugin discovery runs in every CLI process and a directory walk in
    # ``hermes --help`` would be a footprint nobody asked for.
    await asyncio.to_thread(spool_mod.ensure_started, spool)
    spool_mod.ensure_janitor(spool)

    # The receiver's own view of whether the commit went out. Passed in rather
    # than inferred, because the difference between "before the commit" and
    # "after" is the difference between discarding the bytes and holding them.
    progress: Dict[str, Any] = {"commit_written": False}
    kwargs: Dict[str, Any] = {
        "socket_path": socket_path,
        "lease_ms": lease_ms,
        "keep_bytes": False,
        "progress": progress,
    }
    if timeout is not None:
        kwargs["timeout"] = timeout

    try:
        async with spool.stage() as claim:

            async def on_chunk(index, entry, chunk, done) -> None:
                await claim.accept(index, entry, chunk, done)

            try:
                result = await receiver(drop_id, on_chunk=on_chunk, **kwargs)
            except asyncio.CancelledError:
                _hold_on_cancel(claim, drop_id, bool(progress.get("commit_written")))
                raise
            except spool_mod.StagingFailed as exc:
                # The sink stopped the conversation before an ack, so the broker
                # kept the payload. Logged without a label or a byte in it.
                logger.warning(
                    "hermes-drop: staging the files for drop %s failed (%s). Nothing was "
                    "acknowledged, so the drop was not consumed and may be claimed again.",
                    drop_id,
                    exc,
                )
                return _refusal(ERROR_SPOOL_WRITE_FAILED, drop_id)
            except Exception:  # noqa: BLE001 - see the verdict argument below
                # A bug on this side, anywhere in the transfer. Whether the commit
                # had gone out is exactly what is not known, so this takes the
                # indeterminate verdict rather than guessing: publish nothing,
                # retry nothing, mark nothing spent. Erring this way costs a
                # conservative verdict on a claim that may still be live, which is
                # the same direction ``file_claim`` errs when it sets
                # ``commit_written`` before the write.
                logger.error(
                    "hermes-drop: the file claim for drop %s failed unexpectedly. It is "
                    "not known whether the service delivered the files, so nothing was "
                    "published and nothing may be retried.",
                    drop_id,
                    exc_info=True,
                )
                await _hold(claim, drop_id)
                return _refusal(ERROR_TRANSFER_INDETERMINATE, drop_id)

            if not isinstance(result, Mapping) or not result.get("ok"):
                return await _refused(claim, drop_id, result)

            try:
                return await _publish(claim, drop_id, result)
            except asyncio.CancelledError:
                # Past the commit by construction: the publish only runs after it.
                _hold_on_cancel(claim, drop_id, True)
                raise
    except spool_mod.SpoolBusy as exc:
        logger.warning("hermes-drop: refusing a file claim for drop %s: %s", drop_id, exc)
        return _refusal(ERROR_SPOOL_BUSY, drop_id)
    except spool_mod.SpoolUnsafe as exc:
        logger.error(
            "hermes-drop: refusing to claim files for drop %s: %s. The drop was not "
            "touched and can be claimed once the spool root is usable.",
            drop_id,
            exc,
        )
        return _refusal(ERROR_SPOOL_UNAVAILABLE, drop_id)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 - a service boundary may not raise
        # Only reachable from the staging lifecycle itself (creation, or the
        # cleanup on the way out). Indeterminate for the same reason as above: a
        # failure here could equally have followed a successful publish, and
        # ``retry_safe`` on a drop that was consumed is the one wrong answer.
        logger.error(
            "hermes-drop: the spool lifecycle for drop %s failed unexpectedly",
            drop_id,
            exc_info=True,
        )
        return _refusal(ERROR_TRANSFER_INDETERMINATE, drop_id)


def _authorize(journal: Any, drop_id: str, origin: Any) -> Optional[Dict[str, Any]]:
    """The journal's verdict on whether *origin* may claim *drop_id*.

    Not the caller's job, and not a later slice's: this runs before a directory or
    a lease exists. A journal that cannot even be read is a refusal too — failing
    closed here costs a retry, and failing open would drive somebody else's bytes
    to disk.
    """
    from . import journal as journal_mod

    try:
        entry = journal.get(drop_id)
    except Exception:  # noqa: BLE001 - an unreadable journal must not authorize
        logger.warning(
            "hermes-drop: could not read the durable record for drop %s; refusing the "
            "file claim rather than proceeding unauthorized",
            drop_id,
            exc_info=True,
        )
        return _refusal(ERROR_BROKER_UNAVAILABLE, drop_id)

    refusal = journal_mod.authorize_claim(entry, origin)
    if refusal is None:
        return None
    return _from_authorization(refusal, drop_id)


def _default_receiver() -> Receiver:
    """Imported at call time, like the rest of this package's cross-module use,
    so importing the service does not drag the socket client in."""
    from . import file_claim

    return file_claim.receive_file_claim


async def _refused(claim: spool_mod.StagingClaim, drop_id: str, result: Any) -> Dict[str, Any]:
    """The receiver said no. Which no it was decides what happens to the bytes."""
    error = str((result or {}).get("error") or "") if isinstance(result, Mapping) else ""

    if error == ERROR_TRANSFER_INDETERMINATE:
        held = await _hold(claim, drop_id)
        logger.error(
            "hermes-drop: the file claim for drop %s ended without a verdict (%s). It is "
            "not known whether the service delivered the files, so nothing was published, "
            "nothing will be retried and the drop is not marked spent. %s Check the drop "
            "id above against the service before its link expires.",
            drop_id,
            (result.get("reason") if isinstance(result, Mapping) else "") or "no reason given",
            "The received bytes are held out of reach and are deleted at the spool TTL."
            if held
            else "The received bytes could not be held and were discarded.",
        )
        return _refusal(ERROR_TRANSFER_INDETERMINATE, drop_id)

    if error in (ERROR_TRANSFER_FAILED, ERROR_BROKER_UNAVAILABLE, ERROR_UNAVAILABLE,
                 ERROR_INVALID_REQUEST):
        # Staging is discarded by the context manager on the way out.
        return _refusal(error, drop_id)

    # An error code this module has never heard of. Fail closed on both policy
    # fields: neither a retry nor a spent-marking may be inferred from a verdict
    # nobody has reviewed.
    logger.warning(
        "hermes-drop: the file claim for drop %s was refused with an unrecognised error "
        "(%r). Treating it as neither retryable nor spent.",
        drop_id,
        error or None,
    )
    return _refusal(ERROR_UNAVAILABLE if error == "" else error, drop_id)


async def _publish(
    claim: spool_mod.StagingClaim, drop_id: str, result: Mapping[str, Any]
) -> Dict[str, Any]:
    """The commit was accepted. From here this process holds the only copy."""
    try:
        _cross_check(claim, result.get("files"))
        published = await claim.publish(drop_id)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - the verdict is fixed by the commit
        # Broad on purpose: past ``commit → ok`` the payload is gone whatever went
        # wrong here, so there is exactly one honest verdict and a bug in this
        # module must not be able to dress it up as a retryable failure.
        held = await _hold(claim, drop_id)
        logger.error(
            "hermes-drop: the files for drop %s were verified and committed, and then "
            "could not be published (%s). The service has already destroyed its copy, so "
            "this cannot be retried. %s",
            drop_id,
            exc,
            "The bytes are held out of reach and are deleted at the spool TTL."
            if held
            else "The bytes could not be held and were discarded.",
        )
        return _refusal(ERROR_SPOOL_PUBLISH_FAILED, drop_id)

    logger.info(
        "hermes-drop: materialized %d file(s), %d bytes, for drop %s; the paths expire at %d",
        len(published["files"]),
        sum(entry["size"] for entry in published["files"]),
        drop_id,
        published["expires_at"],
    )
    return {
        "ok": True,
        "drop_id": drop_id,
        "claim_id": published["claim_id"],
        "expires_at": published["expires_at"],
        "files": published["files"],
    }


def _cross_check(claim: spool_mod.StagingClaim, received: Any) -> None:
    """The spool's own digests against the ones the receiver committed.

    Not belt and braces: this exact disagreement has already happened once. A
    predecessor of ``ChunkSink`` handed its consumer an empty accumulator while
    computing digests from the stream, so the commit verified, the broker retired
    the payload, and a spool built on it would have published empty files over the
    only copy (``drop/file_claim.py``). The two digest sets are computed on
    different paths — one from the socket, one re-read from disk — so comparing
    them is what makes that class of bug loud instead of silent.

    Lined up by **index**, via the order the sink was called in, rather than by
    position in the manifest: the broker names the next index in its ack answer, so
    arrival order is its business, and a positional comparison would fail a perfect
    transfer *after* the commit — total loss where there was no fault at all.
    """
    if not isinstance(received, list):
        raise StagingMismatch("the receiver reported no file list")
    arrival = claim.arrival_order()
    staged = {entry["index"]: entry for entry in claim.entries()}
    if len(received) != len(staged) or len(arrival) != len(staged):
        raise StagingMismatch(
            f"the receiver reported {len(received)} file(s) and {len(staged)} were staged"
        )
    for position, theirs in enumerate(received):
        if not isinstance(theirs, Mapping):
            raise StagingMismatch(f"the receiver's entry {position} is not a file")
        index = arrival[position]
        mine = staged.get(index)
        if mine is None:  # pragma: no cover - lengths already agreed
            raise StagingMismatch(f"nothing was staged for file {index}")
        if mine["size"] != theirs.get("size"):
            raise StagingMismatch(f"file {index} was {mine['size']} bytes on disk")
        if mine["sha256"] != theirs.get("sha256"):
            raise StagingMismatch(f"file {index} does not match the committed digest")


class StagingMismatch(spool_mod.StagingFailed):
    """The receiver's account of the transfer and the disk's do not agree."""


async def _hold(claim: spool_mod.StagingClaim, drop_id: str) -> bool:
    """Quarantine the staged bytes; discard them if even that fails.

    ``True`` when they are being held. Never raises: it is called on paths that
    are already reporting a failure, and a second one must not replace the first.
    """
    try:
        return bool(await claim.quarantine())
    except Exception:  # noqa: BLE001 - a failed hold must not mask the verdict
        logger.warning(
            "hermes-drop: could not hold the received bytes for drop %s; discarding them",
            drop_id,
            exc_info=True,
        )
        try:
            await claim.discard()
        except Exception:  # noqa: BLE001 - best effort, and the sweeper is the backstop
            logger.debug("hermes-drop: could not discard staging either", exc_info=True)
        return False


def _hold_on_cancel(claim: spool_mod.StagingClaim, drop_id: str, after_commit: bool) -> None:
    """Deal with the bytes on a cancellation, without awaiting anything.

    Synchronous on purpose. ``asyncio.shield`` does not help here: the shielded
    await still raises ``CancelledError`` in a cancelled task, so the rename could
    be left unfinished — and this is the one path where an unfinished rename is a
    user's files gone. One rename plus one ``fsync`` on this thread is a few
    microseconds and is guaranteed to complete before the cancellation propagates.

    Before the commit, discarding is correct: nothing was consumed and the drop is
    still claimable. After it, the payload may already be retired, so the bytes are
    held exactly as an indeterminate verdict would hold them — and said out loud,
    because the caller is getting an exception rather than a verdict and this log
    line is the only trace an operator will have.

    Past the *publishing rename* it is neither. ``publish`` runs on a worker
    thread, so the rename can complete while a cancellation is already pending on
    the awaiting task: the claim is on disk, complete and the caller's, and the
    ``await`` still raises. Quarantining is correctly a no-op there, so the "held
    out of reach" sentence was reporting the opposite of what happened — and it
    named nothing an operator could look under. The published claim id is the one
    thing that line has to carry.
    """
    if claim.published:
        logger.error(
            "hermes-drop: the file claim for drop %s was cancelled after its files had "
            "already been published as claim %s. They are complete on disk under that "
            "claim id and are removed at the spool TTL, but no verdict reached the "
            "caller. The drop was consumed, so it cannot be claimed again.",
            drop_id,
            claim.claim_id,
        )
        return
    if not after_commit:
        logger.warning(
            "hermes-drop: the file claim for drop %s was cancelled before its commit; "
            "nothing was consumed and the drop can be claimed again.",
            drop_id,
        )
        return
    try:
        held = claim.quarantine_now()
    except Exception:  # noqa: BLE001 - nothing may replace the cancellation
        held = ""
        logger.debug("hermes-drop: could not hold bytes on cancellation", exc_info=True)
    logger.error(
        "hermes-drop: the file claim for drop %s was cancelled after its commit was "
        "written, so it is not known whether the service delivered the files. Nothing was "
        "published, nothing may be retried and the drop is not marked spent. %s",
        drop_id,
        "The received bytes are held out of reach and are deleted at the spool TTL."
        if held
        else "The received bytes could not be held.",
    )


__all__ = [
    "ERROR_BROKER_UNAVAILABLE",
    "ERROR_INVALID_REQUEST",
    "ERROR_NOT_AUTHORIZED",
    "ERROR_NOT_READY",
    "ERROR_SPOOL_BUSY",
    "ERROR_SPOOL_PUBLISH_FAILED",
    "ERROR_SPOOL_UNAVAILABLE",
    "ERROR_SPOOL_WRITE_FAILED",
    "ERROR_TRANSFER_FAILED",
    "ERROR_TRANSFER_INDETERMINATE",
    "ERROR_UNAVAILABLE",
    "StagingMismatch",
    "materialize_file_claim",
]
