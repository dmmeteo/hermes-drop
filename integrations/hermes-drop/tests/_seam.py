"""The real gateway dispatch seam, driven from this repo.

Slice S10's whole claim is about a *core* control path: with Tier 2 applied
(Hermes branch ``drop/plugin-command-origin``, commits ``2f487f61a8`` and
``6fd0876edd``), ``/drop`` is dispatched by
``GatewayRunner._handle_message`` → the plugin branch at ``gateway/run.py:14690``
→ ``_check_slash_access(source, plugin_command)`` at ``:14707`` →
``_set_session_env_from_source(source, _quick_key)`` at ``:14721`` →
``await plugin_handler(user_args)`` at ``:14726-14728``. Every property S10 has
to prove — no model turn, one service call, the origin verified against a
*bound* context, denial before the handler, no fall-through to
``/skill drop`` — is a property of that block.

So the tests do not transcribe it. They call the real
``GatewayRunner._handle_message`` on a bare runner built the way the Hermes
checkout's own S9 tests build one
(``tests/gateway/test_plugin_command_context.py::_make_runner``), with three
substitutions and no others:

* ``adapters`` are :class:`_stubs.StubAdapter`s — real ``build_source``
  provenance, recording send/edit, no network. The gateway resolves them through
  the real ``_adapter_for_source``.
* ``_handle_message_with_agent`` is an ``AsyncMock``. It is the *single* place
  ``_handle_message`` enters the agent (``gateway/run.py:14940``), so "the model
  was never asked" is exactly "this mock was never awaited".
* ``gateway.run._gateway_runner_ref`` is pointed at the runner, which is how
  production hands the plugin its runner (``drop/origin.py::_resolve_runner``).

``DropService`` is injected by monkeypatching the class the handler
instantiates, never by passing kwargs: core calls ``plugin_handler(user_args)``
positionally with one string (``:14726``), so a test that passed injection
kwargs would be testing a signature production cannot use.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, Optional
from unittest.mock import AsyncMock, MagicMock

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.base import MessageEvent

from _stubs import StubAdapter

#: Bumped per built event. ``_handle_message`` is a deduplicating pipeline and a
#: test that drives several turns must not have the second one mistaken for a
#: retransmission of the first.
_MESSAGE_SEQ = [0]


def make_gateway_runner(
    adapters: Dict[Platform, Any],
    *,
    gateway_loop: Any = None,
    platform_extra: Optional[Dict[str, Any]] = None,
    authorized: bool = True,
):
    """A bare, real ``GatewayRunner`` wired for the cold dispatch path.

    Field-for-field the Hermes checkout's S9 harness
    (``tests/gateway/test_plugin_command_context.py``), so the seam under test
    here is the seam S9 pinned there — not a second, friendlier arrangement of
    it. ``GatewayRunner`` is built with ``object.__new__`` deliberately:
    ``__init__`` opens sockets and loads a profile.
    """
    from gateway.run import GatewayRunner
    from gateway.session import SessionEntry, build_session_key

    platforms = list(adapters)
    runner = object.__new__(GatewayRunner)
    runner.config = GatewayConfig(
        platforms={
            platform: PlatformConfig(
                enabled=True, token="***", extra=dict(platform_extra or {})
            )
            for platform in platforms
        }
    )
    runner.adapters = dict(adapters)
    runner._profile_adapters = {}
    runner._gateway_loop = gateway_loop
    runner._voice_mode = {}
    runner.hooks = SimpleNamespace(
        emit=AsyncMock(),
        emit_collect=AsyncMock(return_value=[]),
        loaded_hooks=False,
    )
    session_entry = SessionEntry(
        session_key="agent:main:stub",
        session_id="sess-1",
        created_at=datetime.now(),
        updated_at=datetime.now(),
        platform=platforms[0],
        chat_type="dm",
        total_tokens=0,
    )
    runner.session_store = MagicMock()
    # Real key derivation, so a test compares against the gateway's own answer
    # rather than freezing a key format.
    runner.session_store._generate_session_key = build_session_key
    runner.session_store.get_or_create_session.return_value = session_entry
    runner.session_store.load_transcript.return_value = []
    runner.session_store.has_any_sessions.return_value = True
    runner.session_store.append_to_transcript = MagicMock()
    runner.session_store.rewrite_transcript = MagicMock()
    runner.session_store.update_session = MagicMock()
    runner._running_agents = {}
    runner._running_agents_ts = {}
    runner._session_run_generation = {}
    runner._pending_messages = {}
    runner._pending_approvals = {}
    runner._session_sources = {}
    runner._session_db = MagicMock()
    runner._session_db.get_session_title.return_value = None
    runner._session_db.get_session.return_value = None
    runner._reasoning_config = None
    runner._provider_routing = {}
    runner._fallback_model = None
    runner._show_reasoning = False
    runner._is_user_authorized = lambda _source: authorized
    runner._should_send_voice_reply = lambda *_a, **_kw: False
    runner._send_voice_reply = AsyncMock()
    runner._capture_gateway_honcho_if_configured = lambda *_a, **_kw: None
    runner._emit_gateway_run_progress = AsyncMock()
    # The two observation points for "no model turn was dispatched".
    # ``_handle_message_with_agent`` is the only agent entry from
    # ``_handle_message`` (``gateway/run.py:14940``).
    runner._handle_message_with_agent = AsyncMock(return_value=None)
    runner._run_agent = AsyncMock(return_value=None)
    return runner


def lane(
    platform: Platform,
    *,
    chat_id: str,
    chat_type: str = "dm",
    user_id: str = "u-1",
    thread_id: Optional[str] = None,
    message_id: Optional[str] = None,
    extra_adapters: Iterable[Platform] = (),
    gateway_loop: Any = None,
    platform_extra: Optional[Dict[str, Any]] = None,
    authorized: bool = True,
):
    """One originating conversation, plus any *other* adapters on the runner.

    The extra adapters are the incident's shape: a second platform that is live,
    configured and reachable, and must receive nothing.
    """
    adapter = StubAdapter(platform)
    adapters: Dict[Platform, Any] = {platform: adapter}
    others: Dict[Platform, Any] = {}
    for other in extra_adapters:
        others[other] = StubAdapter(other)
    adapters.update(others)

    runner = make_gateway_runner(
        adapters,
        gateway_loop=gateway_loop,
        platform_extra=platform_extra,
        authorized=authorized,
    )
    source = adapter.build_source(
        chat_id=chat_id,
        chat_type=chat_type,
        user_id=user_id,
        thread_id=thread_id,
        message_id=message_id,
    )
    return SimpleNamespace(
        adapter=adapter, runner=runner, source=source, others=others
    )


def event(text: str, source: Any, *, message_id: Optional[str] = "") -> MessageEvent:
    """A real ``MessageEvent``.

    ``message_id=None`` is the Discord native-slash shape — ``_build_slash_event``
    never sets one (``plugins/platforms/discord/adapter.py:5814-5856``).
    """
    _MESSAGE_SEQ[0] += 1
    if message_id == "":
        message_id = f"m-{_MESSAGE_SEQ[0]}"
    return MessageEvent(text=text, source=source, message_id=message_id)


def dispatch(runner: Any, evt: MessageEvent, *, loop: Any, timeout: float = 30):
    """Drive the real ``_handle_message`` on the gateway loop, and return its reply.

    The gateway loop is where the plugin handler is awaited in production
    (``gateway/run.py:14726-14728``), so the whole turn runs there — the same
    loop the adapters and the waiter live on.
    """
    return asyncio.run_coroutine_threadsafe(
        runner._handle_message(evt), loop
    ).result(timeout=timeout)


def install_service(monkeypatch, plugin_module: Any, service: Any) -> None:
    """Make the handler's own ``DropService()`` construction return *service*.

    The handler receives one positional string from core and nothing else, so
    this is the only injection point that leaves the production call shape
    intact.
    """
    monkeypatch.setattr(
        plugin_module.drop.service, "DropService", lambda **_kw: service
    )


def install_runner_handle(monkeypatch, runner: Any) -> None:
    """Point ``gateway.run._gateway_runner_ref`` at *runner*.

    This is production's path: ``drop/origin.py::_resolve_runner`` imports the
    handle inside the function precisely because it is rebound during
    ``GatewayRunner.__init__`` (``gateway/run.py:5513, 5536``).
    """
    import gateway.run as gateway_run

    monkeypatch.setattr(gateway_run, "_gateway_runner_ref", lambda: runner)


def install_plugin_for_real(
    monkeypatch, hermes_home: Path, plugin_dir: Path
) -> Any:
    """Install and discover the plugin through the real ``PluginManager``.

    No core function is patched: ``register(ctx)`` runs for real, so the
    ``pre_gateway_dispatch`` callback is in ``manager._hooks`` and ``/drop`` is
    in ``manager._plugin_commands``. ``invoke_hook`` and
    ``get_plugin_command_handler`` — the two functions ``_handle_message``
    actually calls — therefore find the real registrations.

    Returns the module object the manager loaded. It is a *second* module object
    for the package ``__init__`` (``_load_directory_module`` re-execs the spec),
    but every submodule under it is the already-imported one, so
    ``drop.sources.REGISTRY`` and friends are shared with the test's own handle
    — asserted in ``test_gateway_seam.py``.
    """
    import sys

    from hermes_cli.plugins import discover_plugins, _reset_plugin_managers_for_tests

    _reset_plugin_managers_for_tests()
    link = hermes_home / "plugins" / "hermes-drop"
    if not link.exists():
        link.symlink_to(plugin_dir, target_is_directory=True)
    (hermes_home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - hermes-drop\n", encoding="utf-8"
    )
    empty_bundled = hermes_home / "empty-bundled"
    empty_bundled.mkdir(exist_ok=True)
    monkeypatch.setenv("HERMES_BUNDLED_PLUGINS", str(empty_bundled))

    discover_plugins(force=True)
    module = sys.modules["hermes_plugins.hermes_drop"]
    return module


__all__ = [
    "dispatch",
    "event",
    "install_plugin_for_real",
    "install_runner_handle",
    "install_service",
    "lane",
    "make_gateway_runner",
]
