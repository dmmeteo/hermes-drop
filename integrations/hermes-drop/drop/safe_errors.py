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

#: Keys that may accompany an error out to the caller. ``platform`` and ``state``
#: are values this package chose from a closed set; anything else on an error dict
#: is either a detail (handled above) or something new that has not been reviewed.
_SAFE_ERROR_KEYS = ("platform", "state")


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

    for key in _SAFE_ERROR_KEYS:
        if key in result and result[key] is not None:
            sanitized[key] = result[key]

    return sanitized


__all__ = [
    "DEFAULT_REASON",
    "LOCAL_DETAIL_ERRORS",
    "SAFE_REASONS",
    "safe_detail",
    "sanitize_tool_result",
]
