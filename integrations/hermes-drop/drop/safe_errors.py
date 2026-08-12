"""One refusal vocabulary, for both entry points.

``command.py`` has had this discipline since S10: a refusal that reaches a human
in a chat message "says what happened and nothing else — never a ``detail``
string from the broker, an adapter or an exception, which can carry socket paths
and internals". The tool path had no equivalent (review L1). ``post_status``
builds its ``detail`` from ``str(exc)`` or ``result.error``, ``DropService.create``
returns that dict verbatim, ``_as_tool_result`` serialises it, and it enters the
model's context — and ``logger.warning(..., exc_info=True)`` puts it in
``agent.log`` besides.

Adapter error text is adapter-controlled, which is the part that cannot be argued
away: Telegram redacts through ``_redact_telegram_error_text``, Discord uses raw
``str(e)``, and nothing in this repo governs either. A socket path, an internal
hostname or an echoed request body reaching the model is a leak into durable
``state.db`` context.

**What this module does not do.** It does not blanket-scrub every ``detail``.
Some details are authored *here*, carry no foreign string, and are the difference
between a model that corrects itself and one that retries the same mistake —
``"minutes must be between 1 and 60, got 90"`` is the clearest case. So the rule
is an allowlist of error codes whose detail is known-local, and everything else
gets the fixed sentence for its code. Unknown codes are replaced, not forwarded:
a code this module has never heard of is exactly the case where the detail's
provenance is unknown.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping

#: Fixed, caller-facing reasons, keyed by error code. Shared with ``command.py``,
#: which renders them into a sentence for a human; the tool path uses them as the
#: replacement ``detail`` beside the machine-readable code.
SAFE_REASONS: Dict[str, str] = {
    "broker_unavailable": "the private-input service is not reachable right now",
    # Deliberately says the payload survived: this is the one refusal after which
    # retrying identically is pointless but the drop is *not* spent, and a model
    # told only "it could not be completed" would either give up on a live secret
    # or ask the user to send it again in the chat.
    #
    # The remediation is the model's, not the operator's: the reader's ceiling is
    # a constant of this plugin, so nothing the model can do makes this value
    # arrive — a shorter one through a new link is the whole of its options. The
    # operator's half (lower the broker cap, or recover this drop with the admin
    # CLI) is in `agent.log`, phrased once in `service.SIZE_REMEDIATION`.
    "response_too_large": (
        "the value is too large for this client to receive; it is still held by "
        "the private-input service until the link expires, so nothing was lost — "
        "ask for a shorter value through a new link, and tell the operator the "
        "broker's size limit is set higher than the plugin can read back"
    ),
    # Also a refusal the model can act on, and the only action is to stop: a
    # retry mints another link against the same broker with the same gap.
    "broker_too_old": (
        "the private-input service is running a version too old to guarantee the "
        "secret survives being read, and it is configured to accept values larger "
        "than this plugin can read back; no link was posted — the operator has to "
        "upgrade the service or lower its size limit before this can be used"
    ),
    # ── file claims (``drop/materialize.py``) ──────────────────────────────
    # Each of these has a different next move for the model, which is the whole
    # reason they are separate codes: try again, stop, or stop and tell someone.
    # None of them may name a path — a spool path in a detail is exactly the kind
    # of local internal that lands in durable context for no benefit.
    "spool_unavailable": (
        "the local staging area for files is not usable, so nothing was downloaded "
        "and the files are still held by the private-input service; tell the "
        "operator the plugin cannot write to its configured spool directory"
    ),
    "spool_busy": (
        "too many file transfers are already in progress locally, so this one was not "
        "started; nothing was lost and the same claim will work again shortly"
    ),
    # Deliberately says the drop survived: the bytes are never acknowledged past a
    # failed write, so the service still holds them and one more attempt is legal.
    "spool_write_failed": (
        "the files could not be written to local storage, so nothing was delivered; "
        "the drop was not used up, so this can be tried once more, and if it fails "
        "again tell the operator the plugin cannot write to its spool directory"
    ),
    # The one file refusal after which the payload is gone. Retrying is not just
    # useless, it is misleading: the service answers as though the drop had been
    # claimed, because it had.
    "spool_publish_failed": (
        "the files arrived and were verified but could not be handed over, and the "
        "private-input service has already destroyed its copy; this cannot be tried "
        "again and the user has to be asked for the files through a new link"
    ),
    "transfer_failed": (
        "the file transfer did not complete, so nothing was delivered; the drop was "
        "not used up, so this can be tried once more"
    ),
    # Neither a success nor a failure, and the model must not round it to either.
    "transfer_indeterminate": (
        "the file transfer ended without a verdict, so it is not known whether the "
        "files were delivered; nothing was saved, it must not be tried again, and "
        "the operator needs the drop id to check what happened"
    ),
    "post_failed": "the link could not be posted into this conversation",
    "journal_failed": "the durable record could not be written, so the link was retired",
    "edit_failed": "the status message could not be updated",
    "invalid_request": "the request was not usable",
    "gateway_unavailable": "the gateway is not available",
    "gateway_timeout": "it took too long",
    "would_deadlock": "the gateway is not available",
    "internal_error": "something went wrong on this side",
}

DEFAULT_REASON = "it could not be completed"

#: Codes whose ``detail`` is authored in this package, contains no broker,
#: adapter or exception string, and is useful to the caller. Everything else has
#: its detail replaced — including any code not listed anywhere here, so a new
#: error path fails closed rather than forwarding an unreviewed string.
LOCAL_DETAIL_ERRORS = frozenset(
    {
        # drop/tools.py argument validation, and the broker's own field-level
        # refusals. Names the bound that was exceeded; no foreign text.
        "invalid_request",
        # drop/journal.py::authorize_claim. "no such drop" / "already claimed;
        # the payload is destroyed" — the model needs to tell these apart.
        "unavailable",
        "not_ready",
        # Deliberately detail-free already: naming the owning lane would describe
        # a conversation the caller is not in.
        "not_authorized",
        # drop/render.py::unsupported_error. Carries `platform`, not a detail.
        "platform_unsupported",
        # drop/origin.py refusals. Fixed strings about verification, no internals.
        "no_origin",
        "origin_mismatch",
        "origin_unverified",
        "no_adapter",
        "invalid_duration",
    }
)


def _as_bool(value: Any) -> bool:
    """A policy flag, and only a literal ``True`` is one.

    ``bool()`` was the wrong direction here. Every producer in this package writes
    a real boolean out of ``materialize._POLICY``, so nothing legitimate is lost —
    but ``bool()`` turns ``"no"``, ``0.1`` and ``[0]`` into ``True``, and for
    ``mark_spent`` that is the destructive answer: it tells a caller to write a
    live drop off as used up. Anything that is not the boolean itself fails
    closed.
    """
    return value is True


def _as_safe_id(value: Any) -> str:
    """A drop id, coerced to the shape this package mints them in.

    Filtered rather than trusted: the field is on the allowlist because *this*
    package puts a minted id there, and a value that arrived from anywhere else
    must not be able to ride out as a path fragment or an unbounded string.
    """
    text = "".join(ch for ch in str(value) if ch.isalnum() or ch in "_-")
    return text[:64]


def _as_note(value: Any) -> str:
    """A locally authored sentence. Bounded, and stripped of anything structural."""
    return " ".join(str(value).split())[:400]


#: Keys that may accompany an error out to the caller, each with the coercion that
#: makes forwarding it safe. ``platform`` and ``state`` are values this package
#: chose from a closed set. The four file-claim fields are here because a caller
#: cannot act correctly without them: ``retry_safe`` and ``mark_spent`` are
#: booleans computed from ``materialize._POLICY`` and are the difference between
#: retrying a live drop and abandoning it, ``drop_id`` is the identifier the safe
#: reason itself tells the model to hand an operator, and ``ok`` is what a caller
#: branches on. All are locally generated or closed-set — the criterion this
#: allowlist has always stated — and each is coerced so a foreign value cannot
#: ride along in its place.
#:
#: ``note`` is the one free-text field, and it is on this list only under a rule
#: that has to be kept by hand: **a note must be a constant authored in this
#: package**. Today that is exactly the four ``*_NOTE`` constants in
#: ``drop/service.py``; no broker, adapter or journal dict carrying a ``note``
#: reaches here. Forwarding one that came from a peer would be handing a remote
#: sentence straight to a model, which is the thing every other entry here is
#: shaped to prevent — ``_as_note`` bounds and flattens it, but it cannot tell you
#: who wrote it.
_SAFE_ERROR_FIELDS = (
    ("platform", None),
    ("state", None),
    ("ok", _as_bool),
    ("retry_safe", _as_bool),
    ("mark_spent", _as_bool),
    ("drop_id", _as_safe_id),
    ("note", _as_note),
)


def safe_detail(error: Any) -> str:
    """The fixed sentence for *error*, or the generic one."""
    return SAFE_REASONS.get(str(error or ""), DEFAULT_REASON)


def sanitize_tool_result(result: Any) -> Any:
    """Return *result* fit to enter a model's context.

    Success dicts pass through untouched — nothing on them comes from a broker or
    an adapter, and ``claim``'s ``private_input`` must obviously survive. Error
    dicts are rebuilt from the code up: the code, a detail whose provenance is
    known, and the two closed-set fields a caller may need to branch on.
    """
    if not isinstance(result, Mapping):
        return result
    error = result.get("error")
    if not error:
        return result

    code = str(error)
    sanitized: Dict[str, Any] = {"error": code}

    detail = result.get("detail")
    if code in LOCAL_DETAIL_ERRORS:
        if detail:
            sanitized["detail"] = str(detail)
    else:
        sanitized["detail"] = safe_detail(code)

    for key, coerce in _SAFE_ERROR_FIELDS:
        if key in result and result[key] is not None:
            sanitized[key] = coerce(result[key]) if coerce is not None else result[key]

    return sanitized


__all__ = [
    "DEFAULT_REASON",
    "LOCAL_DETAIL_ERRORS",
    "SAFE_REASONS",
    "_SAFE_ERROR_FIELDS",
    "safe_detail",
    "sanitize_tool_result",
]
