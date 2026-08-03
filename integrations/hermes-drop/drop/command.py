"""The ``/drop`` entry point. One handler, and it *is* the operation.

``/drop`` is deterministic as of slice S10: no model turn, no prose, no second
interpretation of what the user asked for. The handler is ``async``, so the
gateway awaits it on the gateway loop (``gateway/run.py:14726-14728``) and it
reaches ``DropService`` the same way the tool does — the tool crosses a
worker-thread boundary once through ``SyncBridge`` (``drop/bridge.py``), the
command is already there. Neither re-implements a step of the workflow. That is
what makes "the command and the tool are the same operation" a property rather
than an intention.

What made this possible is Tier 2, in the Hermes checkout on branch
``drop/plugin-command-origin`` (S9). Core now binds this turn's session identity
around plugin slash-command dispatch —
``_set_session_env_from_source(source, _quick_key)`` at ``gateway/run.py:14721``
— so the origin resolved from the captured real ``SessionSource`` has an
authoritative context to be *verified* against (§4). Before that binding existed
the handler could find a real source and had nothing to check it against, and
``resolve_origin`` refused ``origin_unverified``; S8 therefore routed ``/drop``
through the model with a ``pre_gateway_dispatch`` text rewrite. That interim is
**deleted**: the hook captures and nothing else, and the plugin has no expression
anywhere that turns ``/drop`` into text for the model. The plugin keeps working
with or without Tier 2 — without it the handler refuses ``origin_unverified``
rather than guessing a destination.

Three rules the handler obeys without exception:

1. **Nothing escapes.** A raising slash-command handler is swallowed with a
   ``logger.warning`` at ``gateway/run.py:14731-14732`` and execution *falls
   through to skill-command resolution* at ``:14735+`` — so one uncaught
   exception silently becomes a ``/skill drop`` lookup, reloading the prose that
   named Discord and chose a platform (plan §1, link 2). Every failure is caught
   and reported through ``OriginMessenger`` instead.
2. **It returns ``None``.** ``return str(result) if result else None``
   (``:14729``) means any returned string is posted as a second message beside
   the status message. The status message *is* the reply.
3. **It never names a destination.** The origin is resolved and verified exactly
   as the tool resolves it; there is no expression in this module that can
   produce a chat id.

The duration asymmetry is deliberate and stated rather than inherited: a numeric
duration outside 1..60 is **clamped** here and **refused** in the tool
(``drop/tools.py::_parse_minutes``). ``/drop 90m`` is a person making a rough
request, and the deadline they get is rendered into the status message they are
already looking at, so the clamp is visible. ``minutes=90`` from the model is a
violation of a schema that states its own bounds, and a model that drifts past a
stated bound must be told, not quietly accommodated.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Union

from . import origin as origin_module
from . import render
from . import safe_errors
from .tools import DEFAULT_MINUTES, MAX_MINUTES, MIN_MINUTES

logger = logging.getLogger(__name__)

#: The registered command name, and the only text the hook reacts to.
COMMAND_NAME = "drop"

#: Bracketed, and that is load-bearing on both verified platforms. Telegram's
#: menu builder skips a command whose hint starts with ``<``
#: (``_requires_argument``, ``hermes_cli/commands.py:533-535``), so brackets are
#: what make the duration *optional* rather than the command invisible; Discord
#: builds an optional ``args`` field for any non-empty hint.
ARGS_HINT = "[10m]"

DESCRIPTION = "Ask for a secret through a one-shot encrypted web form, in this conversation"

ERROR_INVALID_DURATION = "invalid_duration"

#: ``[0-9]`` rather than ``\d``: ``\d`` matches Unicode decimal digits, so
#: ``/drop ٥`` would parse as five minutes through a character set the user
#: cannot have meant to type into a bot command. Pinned by a test.
_DURATION_RE = re.compile(
    r"^([0-9]{1,6})\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours)?$",
    re.IGNORECASE,
)

#: Anything longer is not a duration. Bounding the input before the regex keeps a
#: pathological argument from being a parsing problem at all.
MAX_ARGS_CHARS = 32

_HOUR_SUFFIXES = frozenset({"h", "hr", "hrs", "hour", "hours"})

DURATION_HELP = (
    f"/drop takes an optional duration between {MIN_MINUTES} and {MAX_MINUTES} minutes, "
    "for example /drop 10m."
)

#: Fixed, user-facing reasons. A refusal reaches a human in a chat message, so it
#: says what happened and nothing else — never a ``detail`` string from the
#: broker, an adapter or an exception, which can carry socket paths and internals.
#:
#: The table lives in ``drop/safe_errors.py`` since review L1, because the *tool*
#: path needs the same vocabulary and two copies would drift. Re-exported under
#: the old names so this module reads as it did.
_SAFE_REASONS = safe_errors.SAFE_REASONS
_DEFAULT_REASON = safe_errors.DEFAULT_REASON

_PREFIX = "🔐 "


def parse_duration(raw: Any) -> Union[int, Dict[str, str]]:
    """Minutes in ``1..60``, or an ``invalid_duration`` refusal.

    Empty means the default. A number in range is itself, out of range is
    clamped, and anything that is not a number followed by an optional minute or
    hour suffix is refused — refused rather than defaulted, because silently
    treating ``/drop banana`` as a 30-minute link would hand out a capability the
    user did not ask for.
    """
    if raw is None:
        return DEFAULT_MINUTES
    text = str(raw).strip()
    if not text:
        return DEFAULT_MINUTES
    if len(text) > MAX_ARGS_CHARS:
        return {"error": ERROR_INVALID_DURATION, "detail": DURATION_HELP}

    match = _DURATION_RE.match(text)
    if match is None:
        return {"error": ERROR_INVALID_DURATION, "detail": DURATION_HELP}

    value = int(match.group(1))
    if (match.group(2) or "").lower() in _HOUR_SUFFIXES:
        value *= 60
    return max(MIN_MINUTES, min(MAX_MINUTES, value))


# ── the handler ────────────────────────────────────────────────────────────


async def _say(origin: Any, messenger: Any, text: str) -> None:
    """Report to the conversation the request came from. Never raises.

    ``post_status`` already converts every adapter failure into a result dict
    (``drop/messenger.py``), and there is nothing useful to do with one: the
    message we could not send was itself the report of a failure.
    """
    from . import messenger as messenger_mod

    sender = messenger if messenger is not None else messenger_mod.OriginMessenger()
    await sender.post_status(origin, text)


def _reason_for(result: Any) -> str:
    error = ""
    if isinstance(result, dict):
        error = str(result.get("error") or "")
    return _SAFE_REASONS.get(error, _DEFAULT_REASON)


async def _handle(
    user_args: str,
    *,
    runner: Any,
    service: Any,
    messenger: Any,
) -> None:
    if runner is origin_module._RUNNER_UNSET:
        resolved = origin_module.resolve_origin()
    else:
        resolved = origin_module.resolve_origin(runner=runner)

    if isinstance(resolved, dict):
        # Nothing resolved means there is no conversation to answer in — the CLI
        # row of §6 — or nothing authoritative to verify it against, which is what
        # a gateway running without Tier 2 gives (``origin_unverified``). Refusing
        # silently is the only honest option: the alternative is guessing a
        # destination, which is the incident.
        logger.info("hermes-drop: /drop refused: %s", resolved.get("error"))
        return None

    # Origin first, then arguments, because every refusal below is a chat
    # message and the origin is what makes one possible. The tool orders these
    # the other way round for the mirror-image reason: its refusals are tool
    # results, which need no destination.
    minutes = parse_duration(user_args)
    if isinstance(minutes, dict):
        await _say(resolved, messenger, _PREFIX + DURATION_HELP)
        return None

    if not render.is_supported(resolved.platform_name):
        # Refused by name, before anything is minted, and never redirected to a
        # platform that *is* supported (§7.3).
        await _say(
            resolved,
            messenger,
            f"{_PREFIX}Private input is not supported on {resolved.platform_name} yet, "
            "so no link was created.",
        )
        return None

    if service is None:
        from . import service as service_mod

        service = service_mod.DropService()

    from . import sources

    result = await service.create(
        resolved,
        ttl_seconds=minutes * 60,
        purpose="",
        session_key=sources.session_key_from_context(),
    )

    if isinstance(result, dict) and result.get("error"):
        await _say(
            resolved,
            messenger,
            f"{_PREFIX}Could not start a private input link: {_reason_for(result)}.",
        )
    return None


async def handle(
    user_args: str = "",
    *,
    runner: Any = origin_module._RUNNER_UNSET,
    service: Any = None,
    messenger: Any = None,
) -> None:
    """The registered ``/drop`` handler. Always ``None``, never raises.

    ``runner`` / ``service`` / ``messenger`` are injection points for tests; core
    calls ``plugin_handler(user_args)`` positionally (``gateway/run.py:14696``)
    and every default is the production path.
    """
    try:
        return await _handle(user_args or "", runner=runner, service=service, messenger=messenger)
    except Exception:  # noqa: BLE001 - deliberate catch-all; see the module docstring
        logger.warning("hermes-drop: /drop failed", exc_info=True)
        # Best effort, and deliberately after the log: if this raises too, the
        # outer guard in ``__init__.py`` still returns None and nothing reaches
        # skill-command resolution.
        await _report_failure(runner, messenger)
        return None


async def _report_failure(runner: Any, messenger: Any) -> None:
    try:
        if runner is origin_module._RUNNER_UNSET:
            resolved = origin_module.resolve_origin()
        else:
            resolved = origin_module.resolve_origin(runner=runner)
        if isinstance(resolved, dict):
            return
        await _say(
            resolved,
            messenger,
            f"{_PREFIX}Could not start a private input link: {_DEFAULT_REASON}.",
        )
    except Exception:  # noqa: BLE001 - a report of a failure must not fail loudly
        logger.warning("hermes-drop: could not report a /drop failure", exc_info=True)


__all__ = [
    "ARGS_HINT",
    "COMMAND_NAME",
    "DESCRIPTION",
    "DURATION_HELP",
    "ERROR_INVALID_DURATION",
    "MAX_ARGS_CHARS",
    "handle",
    "parse_duration",
]
