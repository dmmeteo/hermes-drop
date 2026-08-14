"""Hermes Drop — origin-bound private input.

Source of truth is this repo (``secure-secret-handoff``); the installer
symlinks this directory into ``$HERMES_HOME/plugins/hermes-drop``. A live-only
plugin is exactly what produced the unversioned, untested
``hermes-drop-command`` that this replaces.

**Module-scope import discipline.** This file, and every module it reaches at
import time, must stay free of ``gateway.run``. Plugin discovery happens in
every CLI process, and the runner handle is a module global rebound during
``GatewayRunner.__init__`` — see ``drop/__init__.py`` for the full reasoning
and the test that enforces it.

Implemented so far: S3 (discovery, config gate, control client), S4
(``SourceRegistry`` and the origin hard gate), S5 (async messenger, sync
bridge, render matrix), S6 (journal, reconciler), S7 (``DropWaiter``,
``DropService``), S8 (entry points), S10 (deterministic ``/drop``).

**``/drop`` is deterministic, and this file is where that is visible.** The
``pre_gateway_dispatch`` callback captures the real ``SessionSource`` and carries
the reconciler's second trigger — nothing else. The registered async handler is
the initiator: core dispatches it inside the session context Tier 2 binds
(``_set_session_env_from_source`` at ``gateway/run.py:14721``, Hermes branch
``drop/plugin-command-origin``) and it calls ``DropService`` directly. No model
turn is involved, and no text the user did not type is ever produced.

Without Tier 2 the plugin still loads and still works: the handler finds a real
source, has no bound context to verify it against, and refuses
``origin_unverified`` rather than guessing a destination.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Mapping, Optional

from . import drop as drop  # noqa: PLC0414 - re-exported for callers and tests
from .drop import config as drop_config
from .drop import schemas

logger = logging.getLogger(__name__)


def drop_check_fn() -> bool:
    """Process-constant configuration gate — see ``drop/config.py``."""
    return drop_config.control_socket_configured()


def _as_tool_result(payload: Mapping[str, Any]) -> str:
    """Tool results are strings. JSON keeps them machine-readable for the model
    without inventing prose that could drift from what actually happened."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _guarded(impl_name: str, args: Optional[Mapping[str, Any]], session_id: str = "") -> str:
    """Call a handler and turn anything that escapes into an error result.

    Nothing may raise out of these. A raising slash-command handler is swallowed
    with a ``logger.warning`` at ``gateway/run.py:14701-14702`` and execution
    **falls through to skill-command resolution** at ``:14705+`` — so an exception
    would silently become a ``/skill drop`` lookup, resurrecting the exact prose
    path this design severs (plan §1, link 2).

    ``vault.redact_tool_result`` runs **inside** this try, on the dict, before
    ``_as_tool_result`` makes it a string. That string is what core appends to
    ``messages`` and flushes straight into ``state.db``
    (``agent/tool_executor.py:1894-1901``), so this is the last moment at which
    the two copies can be separated — see ``drop/vault.py`` for why no core hook
    is early enough or late enough to do it instead. Being inside the try is the
    fail-closed half: a vault that cannot stash lands in ``internal_error``
    rather than returning the plaintext.
    """
    from .drop import safe_errors, tools, vault

    try:
        impl = getattr(tools, impl_name)
        return _as_tool_result(
            vault.redact_tool_result(
                safe_errors.sanitize_tool_result(impl(args or {})),
                session_id=session_id,
            )
        )
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all, see docstring
        # ``str(exc)`` is exactly the kind of string review L1 is about: an
        # exception message can carry a socket path, an internal hostname or an
        # echoed request body, and a tool result enters the model's context and
        # from there durable ``state.db``. It is logged (where an operator can see
        # it) and *not* returned.
        logger.warning("hermes-drop: %s failed: %s", impl_name, exc, exc_info=True)
        return _as_tool_result(
            {"error": "internal_error", "detail": safe_errors.safe_detail("internal_error")}
        )


def request_private_input(args: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> str:
    return _guarded("request_private_input", args, _session_id(kwargs))


def claim_private_input(args: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> str:
    return _guarded("claim_private_input", args, _session_id(kwargs))


def send_private_output(args: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> str:
    """The outbound direction, through the same guard as the other two.

    It goes through ``_guarded`` unchanged, and the two things that pass through
    it are worth being explicit about because this handler is the one that runs
    backwards:

    * ``vault.redact_tool_result`` finds no ``private_input`` field here and returns
      the receipt untouched — correctly, because an outbound result carries no value
      to redact. The invariant it enforces ("no plugin tool result carries a secret
      field") holds for this handler by construction rather than by substitution.
    * ``safe_errors.sanitize_tool_result`` still matters as much as ever: a refusal
      from this path can carry an adapter's own error string out of ``post_status``,
      and that is a leak into durable context regardless of which way the secret was
      travelling.

    What ``_guarded`` cannot do anything about is the *arguments*: they carry the
    plaintext, core persists a tool call before the handler runs, and no seam in this
    plugin sits earlier than that. ``generate`` is the mitigation, not a fix — see
    ``drop/tools.py::send_private_output`` and ``SECURITY.md``.
    """
    return _guarded("send_private_output", args, _session_id(kwargs))


def _session_id(kwargs: Mapping[str, Any]) -> str:
    """The session a tool result belongs to, as core hands it to the handler.

    ``registry.dispatch`` forwards its kwargs straight to the handler
    (``tools/registry.py:694``) and the caller passes ``session_id=agent.session_id``
    (``agent/tool_executor.py:1678``, ``:1748``) — the *same* value that reaches
    ``llm_request`` middleware (``agent/conversation_loop.py:2103``). That is what
    makes the vault's session binding meaningful rather than decorative.
    """
    return str(kwargs.get("session_id") or "")


async def drop_command(user_args: str = "", **kwargs: Any) -> None:
    """The ``/drop`` handler. Async, so the gateway awaits it on the gateway loop
    (``gateway/run.py:14726-14728``) and it reaches ``DropService`` directly.

    Core calls this with one positional string and nothing else (``:14726``); the
    origin comes from the captured real source verified against the session
    context bound at ``:14721``, never from an argument.

    Always returns ``None``: a returned string is posted as a second message
    (``return str(result) if result else None``, ``:14729``) and the status
    message is already the reply. It never raises either — an exception here is
    swallowed at ``:14731-14732`` and execution *falls through to skill-command
    resolution* at ``:14735+``, so a raise would silently become a ``/skill
    drop`` lookup. ``drop.command.handle`` catches everything; this is the second
    guard, and it exists because the cost of the first one being wrong is the
    incident.
    """
    from .drop import command

    try:
        return await command.handle(user_args, **kwargs)
    except Exception:  # noqa: BLE001 - deliberate catch-all, see the docstring
        logger.warning("hermes-drop: /drop handler failed", exc_info=True)
        return None


def capture_turn_source(**kwargs: Any) -> None:
    """``pre_gateway_dispatch`` callback: capture the REAL ``SessionSource`` and
    carry the reconciler's second trigger. Two observations, no verdict.

    **It returns ``None`` unconditionally**, and that is the S10 property. Core
    acts on ``skip`` / ``rewrite`` / ``allow`` (``gateway/run.py:13648-13668``);
    returning any of them would put Drop back in the business of deciding what a
    message means before auth has run. ``skip`` would make Drop an
    unauthenticated command surface — the hook fires before auth and pairing
    (``:13633`` vs ``:13670``) — and ``rewrite`` was S8's interim, which turned
    ``/drop`` into a sentence for the model because a plugin command handler had
    no bound session context to verify its origin against. Tier 2 (S9) binds one,
    so the handler initiates directly and this callback observes only. Nothing in
    the plugin can now produce text the user did not type.

    The reconcile trigger rides here because this is the only ``invoke_hook``
    site in ``gateway/run.py`` (``:13636``) and there is no gateway-ready hook
    (``hermes_cli/plugins.py:135-215``). It is latched to one run per process and
    shares that latch with the startup poller, so a busy gateway does not start a
    reconcile per message.
    """
    from .drop import reconciler
    from .drop.sources import capture

    capture(**kwargs)
    try:
        reconciler.trigger_from_event(kwargs.get("gateway"))
    except Exception:  # noqa: BLE001 - a hook must never raise; see drop/sources.py
        logger.warning("hermes-drop: reconcile trigger failed", exc_info=True)

    return None


def register(ctx: Any) -> None:
    """Plugin entry point.

    Both tools are registered ``is_async=False``. An ``is_async=True`` handler
    is bridged onto a *private* loop by ``model_tools._run_async``
    (``model_tools.py:97-137``) — not the gateway loop — so declaring async
    would buy a useless loop and still require the explicit bridge in
    ``drop/bridge.py``.
    """
    ctx.register_hook("pre_gateway_dispatch", capture_turn_source)

    # The other half of durable sanitization. The tool handlers hand core a
    # placeholder; this puts the plaintext back into the provider payload only
    # (``drop/vault.py``). Guarded with ``getattr`` because ``register()``
    # raising takes the tools and ``/drop`` down with it — a core without
    # middleware support must degrade to "the model cannot read the secret",
    # never to "the plugin failed to load" and never to a durable plaintext.
    from .drop import vault

    register_middleware = getattr(ctx, "register_middleware", None)
    if callable(register_middleware):
        register_middleware(vault.MIDDLEWARE_KIND, vault.llm_request_middleware)
    else:
        logger.warning(
            "hermes-drop: this Hermes has no ctx.register_middleware, so a claimed "
            "secret cannot be substituted into the model request. Claims will return "
            "a placeholder. Nothing is written to durable state either way."
        )

    # One registration reaches the Discord picker, the Telegram menu, the CLI and
    # plain typed text on every platform (``hermes_cli/plugins.py:548-600``).
    # ``args_hint`` is imported rather than repeated: a ``<``-prefixed hint would
    # drop the command from Telegram's menu entirely
    # (``_requires_argument``, ``hermes_cli/commands.py:533-535``).
    from .drop import command as drop_command_module

    ctx.register_command(
        drop_command_module.COMMAND_NAME,
        drop_command,
        description=drop_command_module.DESCRIPTION,
        args_hint=drop_command_module.ARGS_HINT,
    )

    # The startup trigger for the reconciler. It polls for a live runner and
    # gives up quietly if none appears, so a CLI process that merely discovers
    # plugins neither blocks nor writes anything: the journal is not even
    # constructed until a gateway and its loop exist (``drop/reconciler.py``).
    from .drop import reconciler

    reconciler.start_startup_trigger()

    ctx.register_tool(
        name=schemas.REQUEST_PRIVATE_INPUT["name"],
        toolset=schemas.TOOLSET,
        schema=schemas.REQUEST_PRIVATE_INPUT,
        handler=request_private_input,
        check_fn=drop_check_fn,
        is_async=False,
        description="Ask for a secret through a one-shot encrypted web form.",
        emoji="🔐",
    )
    ctx.register_tool(
        name=schemas.CLAIM_PRIVATE_INPUT["name"],
        toolset=schemas.TOOLSET,
        schema=schemas.CLAIM_PRIVATE_INPUT,
        handler=claim_private_input,
        check_fn=drop_check_fn,
        is_async=False,
        description="Retrieve the private input for a drop reported as received.",
        emoji="🔐",
    )
    # The outbound direction (docs/OUTBOUND_SECRET_DROP_MVP.md). A third *new* tool
    # name, never an override of a built-in: `allow_tool_override` is deliberately
    # absent from this plugin's config and must stay absent (plugin.yaml).
    ctx.register_tool(
        name=schemas.SEND_PRIVATE_OUTPUT["name"],
        toolset=schemas.TOOLSET,
        schema=schemas.SEND_PRIVATE_OUTPUT,
        handler=send_private_output,
        check_fn=drop_check_fn,
        is_async=False,
        description="Give the user a secret through a one-time encrypted link.",
        emoji="🔐",
    )


__all__ = [
    "capture_turn_source",
    "claim_private_input",
    "drop_check_fn",
    "drop_command",
    "register",
    "request_private_input",
    "send_private_output",
]
