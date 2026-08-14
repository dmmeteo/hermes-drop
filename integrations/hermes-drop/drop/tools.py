"""The three tool handlers. Thin on purpose: every gate, then ``DropService``.

Order of operations, and why it is this order:

1. **Validate arguments.** ``minutes`` outside 1..60 is refused, not clamped.
   The schema bounds it, but a schema is advisory to a model; refusing means the
   broker's own ``maxTtlSeconds`` check is never the first line of defence, and
   the user never silently gets a different lifetime than the conversation agreed.
2. **Resolve and verify the origin** (``origin.resolve_origin``). Fail closed on
   ``no_origin`` / ``origin_mismatch`` / ``origin_unverified`` /
   ``gateway_unavailable`` / ``no_adapter``.
3. **Gate on the platform** (``render.is_supported``) — *before* anything is
   minted. An unsupported platform is refused by name, never degraded to a plain
   notice and never redirected to a platform that is supported.
4. **Cross to the gateway loop once**, through ``SyncBridge``, for the *whole*
   operation — and only from here. A model tool handler runs on a
   ``ThreadPoolExecutor`` worker (``gateway/run.py:18604`` → ``:20276-20285``);
   ``DropService`` is async end to end and must run on the loop the adapters and
   the waiter live on.

The runner for the bridge is taken from the **resolved origin**, not resolved a
second time: the origin already holds the runner it verified the adapter against,
and looking it up again could pick up a different one mid-shutdown.

Nothing here formats a link, a capability or a payload. ``request_private_input``
returns a non-secret receipt; ``claim_private_input`` returns the plaintext as a
tool result, which is the one and only path by which it reaches the model (§3.2);
``send_private_output`` runs the other way — its *arguments* carry the secret and its
result carries none of it, no value, no code and no URL.

**Every result leaves through ``safe_errors.sanitize_tool_result``.** A refusal
here is a *tool result*, so it enters the model's context and from there durable
``state.db`` — and ``post_status``'s ``detail`` is ``str(exc)`` or an adapter's own
error string, which can carry a socket path or internals nothing in this repo
governs (review L1). The command path has had a fixed refusal vocabulary since
S10; this is the same table applied at the other entry point. Success results pass
through untouched, ``private_input`` included.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Mapping, Optional

from . import bridge as bridge_mod
from . import origin as origin_module
from . import render
from . import safe_errors

logger = logging.getLogger(__name__)

#: Matches ``REQUEST_PRIVATE_INPUT``'s schema bounds and the broker's
#: ``maxTtlSeconds: 3600`` (``src/config.js:10``).
MIN_MINUTES = 1
MAX_MINUTES = 60
DEFAULT_MINUTES = 30

#: ``purpose`` is a label for the audit journal, not a place to put content. The
#: bound keeps a runaway model string out of the durable record; the URL check is
#: the second line of defence behind the journal's own (§8.10).
MAX_PURPOSE_CHARS = 120

#: The sentinel ``resolve_origin`` uses to mean "resolve the runner yourself".
_RUNNER_UNSET = origin_module._RUNNER_UNSET


def _invalid(detail: str) -> Dict[str, Any]:
    return {"error": "invalid_request", "detail": detail}


def _parse_minutes(raw: Any) -> Any:
    """Return an int in range, or an ``invalid_request`` dict."""
    if raw is None:
        return DEFAULT_MINUTES
    # bool is an int subclass; True would silently become 1 minute.
    if isinstance(raw, bool) or not isinstance(raw, int):
        return _invalid(f"minutes must be a whole number between {MIN_MINUTES} and {MAX_MINUTES}")
    if not (MIN_MINUTES <= raw <= MAX_MINUTES):
        return _invalid(f"minutes must be between {MIN_MINUTES} and {MAX_MINUTES}, got {raw}")
    return raw


def _parse_purpose(raw: Any) -> Any:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        return _invalid("purpose must be a string")
    purpose = raw.strip()
    if len(purpose) > MAX_PURPOSE_CHARS:
        return _invalid(f"purpose must be at most {MAX_PURPOSE_CHARS} characters")
    if "://" in purpose:
        return _invalid("purpose is a short label for the audit journal, not a URL")
    return purpose


def _resolved_origin(runner: Any) -> Any:
    if runner is _RUNNER_UNSET:
        return origin_module.resolve_origin()
    return origin_module.resolve_origin(runner=runner)


def _bridge_for(origin: Any, bridge: Any) -> Any:
    if bridge is not None:
        return bridge
    return bridge_mod.SyncBridge(runner_resolver=lambda: origin.runner)


def _service_for(service: Any) -> Any:
    if service is not None:
        return service
    from . import service as service_mod

    return service_mod.DropService()


def request_private_input(
    args: Optional[Mapping[str, Any]] = None,
    *,
    runner: Any = _RUNNER_UNSET,
    service: Any = None,
    bridge: Any = None,
) -> Dict[str, Any]:
    args = args or {}

    minutes = _parse_minutes(args.get("minutes"))
    if isinstance(minutes, dict):
        return minutes

    purpose = _parse_purpose(args.get("purpose"))
    if isinstance(purpose, dict):
        return purpose

    resolved = _resolved_origin(runner)
    if isinstance(resolved, dict):
        return resolved

    if not render.is_supported(resolved.platform_name):
        # Before create, on purpose. An unsupported platform must not consume a
        # handoff on its way to being refused (§7.3).
        return render.unsupported_error(resolved.platform_name)

    from . import sources

    return safe_errors.sanitize_tool_result(
        _bridge_for(resolved, bridge).run(
            _service_for(service).create(
                resolved,
                ttl_seconds=minutes * 60,
                purpose=purpose,
                session_key=sources.session_key_from_context(),
            ),
            timeout=bridge_mod.CREATE_TIMEOUT_SECONDS,
        )
    )


def send_private_output(
    args: Optional[Mapping[str, Any]] = None,
    *,
    runner: Any = _RUNNER_UNSET,
    service: Any = None,
    bridge: Any = None,
) -> Dict[str, Any]:
    """The outbound direction: hand the user a secret instead of typing it in chat.

    The same five steps in the same order as ``request_private_input`` — validate,
    resolve and verify the origin, gate on the platform, cross once through the
    bridge — because the reasons for that order do not change with the direction.
    What does change is the cost of getting it wrong, and it changes in one specific
    way worth naming: an inbound drop delivered to the wrong conversation *asks* a
    stranger for a credential, while an outbound one **gives** them one. Same gates,
    higher stakes, no shortcuts.

    **The arguments carry the secret, and this is the seam where that is true.** It
    is not avoidable in general — Hermes cannot hand over a value it was not given —
    and it is why the ``generate`` field exists: for a value that is being *created*
    rather than relayed, the request says "make me a 24-character password" and the
    plaintext never enters a tool argument, a model turn or a durable transcript at
    all. See the ``send_outbound`` docstring in ``drop/service.py`` and the risk this
    does not close, stated plainly in ``SECURITY.md``.

    Nothing this returns carries a value, a code or a URL. The result is labels, a
    deadline and a drop id, and it goes out through ``sanitize_tool_result`` like
    every other tool result on this surface.
    """
    args = args or {}

    minutes = _parse_minutes(args.get("minutes"))
    if isinstance(minutes, dict):
        return minutes

    # Refused here rather than deeper, because "no fields" is the one argument
    # mistake that would otherwise reach the payload builder as a bare
    # `not_an_object` and read to a model like a schema problem.
    fields = args.get("fields")
    if fields is None:
        return _invalid("fields is required: send at least one labelled value")

    resolved = _resolved_origin(runner)
    if isinstance(resolved, dict):
        return resolved

    if not render.is_supported(resolved.platform_name):
        # Before the payload is built and before anything is minted (§7.3). An
        # unsupported platform is refused by name, never degraded to a plain notice
        # and never redirected to a platform that is supported.
        return render.unsupported_error(resolved.platform_name)

    return safe_errors.sanitize_tool_result(
        _bridge_for(resolved, bridge).run(
            _service_for(service).send_outbound(
                resolved,
                fields=fields,
                title=args.get("title"),
                ttl_seconds=minutes * 60,
            ),
            timeout=bridge_mod.CREATE_TIMEOUT_SECONDS,
        )
    )


def claim_private_input(
    args: Optional[Mapping[str, Any]] = None,
    *,
    runner: Any = _RUNNER_UNSET,
    service: Any = None,
    bridge: Any = None,
) -> Dict[str, Any]:
    args = args or {}

    drop_id = args.get("drop_id")
    if not isinstance(drop_id, str) or not drop_id.strip():
        return _invalid("drop_id is required and must be a non-empty string")

    # Claim needs no adapter and no send — only the routing tuple — so it is
    # unaffected by the wake-turn limitation that can make a *new* drop refuse
    # (§4, "Known bounded limitation"). It still resolves the origin, because
    # claim authorisation binds the routing tuple (§8.5).
    resolved = _resolved_origin(runner)
    if isinstance(resolved, dict):
        return resolved

    return safe_errors.sanitize_tool_result(
        _bridge_for(resolved, bridge).run(
            _service_for(service).claim(resolved, drop_id.strip()),
            timeout=bridge_mod.CLAIM_TIMEOUT_SECONDS,
        )
    )


__all__ = [
    "DEFAULT_MINUTES",
    "MAX_MINUTES",
    "MAX_PURPOSE_CHARS",
    "MIN_MINUTES",
    "claim_private_input",
    "request_private_input",
    "send_private_output",
]
