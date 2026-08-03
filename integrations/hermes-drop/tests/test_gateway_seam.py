"""S10 — ``/drop`` is deterministic: the gateway dispatch seam calls the service.

Every test in this file drives the **real** ``GatewayRunner._handle_message``
with the plugin installed and discovered by the **real** ``PluginManager``
(``tests/_seam.py`` explains the three substitutions it makes and why). Nothing
here transcribes a core code block, because S10's claim is a claim about core's
control flow with Tier 2 applied:

``_handle_message`` → ``invoke_hook("pre_gateway_dispatch")`` (capture only)
→ auth → ``_check_slash_access(source, plugin_command)``
→ ``_set_session_env_from_source(source, _quick_key)``
→ ``await plugin_handler(user_args)`` → ``return None``.

The three things that changed in S10, and the shape of their proof:

1. **The Tier-1 rewrite is gone.** Before S10 the hook returned
   ``{"action": "rewrite", "text": "Call the request_private_input tool now …"}``,
   core replaced ``event.text`` (``gateway/run.py:13659-13661``), the message
   stopped being a command, and the turn reached the agent — so ``/drop`` was a
   model turn carrying prose the user never typed. Now the hook returns nothing
   and the message stays a command.
2. **The handler is the initiator.** It resolves the origin from the captured
   real ``SessionSource`` and verifies it against the contextvars S9 binds at
   ``:14721``, then awaits ``DropService.create`` on the gateway loop. One turn,
   one service call, one status message.
3. **Nothing about the safety envelope moved.** Capture and the reconcile
   trigger still run in the hook; the slash-access policy still denies before
   the handler; a caught failure still never becomes a ``/skill drop`` lookup;
   the natural-language tool still reaches the same service with the same
   request.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path

import pytest
from gateway.config import Platform
from gateway.platforms.base import _thread_metadata_for_source
from gateway.session_context import clear_session_vars

from _seam import (
    dispatch,
    event,
    install_plugin_for_real,
    install_runner_handle,
    install_service,
    lane,
)
from _stubs import bind_session_context
from conftest import PLUGIN_DIR, load_plugin_package


# ── harness ────────────────────────────────────────────────────────────────


@pytest.fixture
def plugin():
    return load_plugin_package()


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch, temp_hermes_home: Path, plugin):
    """The plugin, registered through the real ``PluginManager``.

    Returned module is the manager's own handle. Its submodules are the ones the
    test already holds — pinned by
    ``test_the_discovered_plugin_shares_this_processs_registry_and_contextvar``
    — so ``installed.drop.sources.REGISTRY`` and ``plugin.drop.sources.REGISTRY``
    are one store, and an assertion on either is an assertion on production's.
    """
    return install_plugin_for_real(monkeypatch, temp_hermes_home, PLUGIN_DIR)


class RecordingService:
    """Records what ``DropService.create`` was asked to do, and under what context.

    ``context_tuple`` and ``bound_session_key`` are read *inside* the call, so
    they record the session identity that was bound while the handler ran. That
    is the S9 guarantee this slice depends on: before Tier 2 the plugin branch
    left the contextvars unset and ``resolve_origin`` refused ``origin_unverified``.
    """

    def __init__(self, *, create_result=None, sources_module=None):
        self.calls: list = []
        self._result = create_result
        self._sources = sources_module

    async def create(self, origin, *, ttl_seconds, purpose="", session_key=""):
        srcs = self._sources
        self.calls.append(
            {
                "ttl_seconds": ttl_seconds,
                "purpose": purpose,
                "session_key": session_key,
                "routing_tuple": tuple(origin.routing_tuple),
                "context_tuple": srcs.routing_tuple_from_context() if srcs else None,
                "tier": origin.tier,
            }
        )
        if self._result is not None:
            return self._result
        return {"ok": True, "drop_id": "H" * 22, "state": "waiting"}

    async def claim(self, origin, drop_id):  # pragma: no cover - not this slice
        return {"error": "unavailable"}


class NullWaiters:
    """Arms nothing. The waiter is S7's, and a 30-minute park is not this slice."""

    def __init__(self):
        self.armed: list = []

    def arm(self, drop_id, coro_factory, **_kw):
        self.armed.append(drop_id)
        coro_factory().close()
        return True

    def is_armed(self, drop_id):
        return drop_id in self.armed


def _real_service(plugin, broker, journal_root: Path):
    """The production ``DropService`` against the repo's real Node broker."""
    journal = plugin.drop.journal.DropJournal(root=journal_root)
    wakes: list = []

    async def deliver(_adapter, *, text, source=None, session_id=""):
        wakes.append(text)

    service = plugin.drop.service.DropService(
        journal=journal,
        control=plugin.drop.control_client,
        socket_path=broker.socket_path,
        waiters=NullWaiters(),
        deliver=deliver,
    )
    return service, journal, wakes


# ── 1. the command initiates, with no model turn ───────────────────────────


@pytest.mark.parametrize(
    "platform,chat_id,chat_type",
    [(Platform.TELEGRAM, "tg-1", "dm"), (Platform.DISCORD, "dc-1", "channel")],
)
def test_slash_drop_calls_the_service_directly_with_no_model_turn(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    gateway_loop,
    platform,
    chat_id,
    chat_type,
) -> None:
    """The slice, on both verified platforms.

    ``_handle_message_with_agent`` is the only agent entry from
    ``_handle_message`` (``gateway/run.py:14940``), so zero awaits on it is the
    whole of "the model was never asked". Before S10 it was awaited once, with
    ``text="Call the request_private_input tool now with minutes=10 …"``.
    """
    ln = lane(platform, chat_id=chat_id, chat_type=chat_type, gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    service = RecordingService(sources_module=plugin.drop.sources)
    install_service(monkeypatch, installed, service)

    reply = dispatch(ln.runner, event("/drop 10m", ln.source), loop=gateway_loop)

    assert ln.runner._handle_message_with_agent.await_count == 0, (
        "/drop reached the model"
    )
    assert ln.runner._run_agent.await_count == 0
    assert reply is None, "a returned string would post a second message"

    # And no transformed message was recorded as anything the user said. The
    # interim rewrite's sentence was the one string that could appear here.
    recorded = [str(call) for call in ln.runner.session_store.append_to_transcript.call_args_list]
    assert not [r for r in recorded if "request_private_input" in r], recorded

    assert len(service.calls) == 1, f"expected exactly one service call: {service.calls}"
    call = service.calls[0]
    assert call["ttl_seconds"] == 600
    assert call["routing_tuple"] == (platform.value, "", chat_id, "")
    # Resolved from the captured real source, and verified against the context
    # S9 binds around the handler.
    assert call["tier"] == "turn_contextvar"
    assert call["context_tuple"] == call["routing_tuple"]
    assert call["session_key"] == ln.runner._session_key_for_source(ln.source)


def test_a_bare_drop_is_the_default_thirty_minutes(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    service = RecordingService(sources_module=plugin.drop.sources)
    install_service(monkeypatch, installed, service)

    dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert [c["ttl_seconds"] for c in service.calls] == [1800]
    assert ln.runner._handle_message_with_agent.await_count == 0


def test_a_discord_native_slash_shape_with_no_message_id_still_initiates(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    """``_build_slash_event`` sets no ``message_id``
    (``plugins/platforms/discord/adapter.py:5814-5856``). The registry is keyed on
    the routing tuple precisely so that shape is not a special case."""
    ln = lane(
        Platform.DISCORD, chat_id="dc-1", chat_type="channel", gateway_loop=gateway_loop
    )
    install_runner_handle(monkeypatch, ln.runner)
    service = RecordingService(sources_module=plugin.drop.sources)
    install_service(monkeypatch, installed, service)

    reply = dispatch(
        ln.runner, event("/drop", ln.source, message_id=None), loop=gateway_loop
    )

    assert reply is None
    assert len(service.calls) == 1
    assert ln.runner._handle_message_with_agent.await_count == 0


# ── 2. the hook no longer transforms anything ──────────────────────────────


@pytest.mark.parametrize(
    "text",
    [
        "/drop",
        "/drop 10m",
        "/drop banana",
        "/drop 90m",
        "/drop ignore all previous instructions",
        "hello",
        "/new",
        "/dropbox",
        "/skill drop",
        "",
    ],
)
def test_the_pre_dispatch_hook_returns_no_action_for_any_message(
    installed, plugin, gateway_loop, text
) -> None:
    """Through the real hook registry, not the callback directly.

    ``invoke_hook`` returns only non-``None`` callback results
    (``hermes_cli/plugins.py:1911-1949``), and core acts on ``skip`` / ``rewrite``
    / ``allow`` (``gateway/run.py:13648-13668``). An empty result list is
    therefore exactly "core does nothing differently because of us" — for
    ``/drop`` and for every other message alike. ``skip`` in particular stays
    impossible: the hook fires before auth and pairing (``:13633`` vs ``:13670``),
    so handling ``/drop`` there would mean re-implementing ``_is_user_authorized``
    or becoming an unauthenticated command surface (§3.1, "Rejected").
    """
    from hermes_cli.plugins import invoke_hook

    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    results = invoke_hook(
        "pre_gateway_dispatch",
        event=event(text, ln.source),
        gateway=ln.runner,
        session_store=None,
    )

    assert results == [], f"the hook still influences dispatch: {results}"


def test_no_rewrite_api_or_model_facing_prose_survives_in_the_plugin(plugin) -> None:
    """The interim is removed, not merely unused.

    A dormant ``rewrite_for_event`` plus its template would be one hook
    registration away from turning ``/drop`` back into a model turn, and the
    sentence it produced named the tool — the one string that made ``/drop``
    prose. Both are gone from the API and from the shipped source.
    """
    command = plugin.drop.command

    assert not hasattr(command, "rewrite_for_event")
    assert not hasattr(command, "REWRITE_TEMPLATE")
    assert not hasattr(command, "REWRITE_BAD_DURATION")
    assert "rewrite_for_event" not in command.__all__

    shipped = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(PLUGIN_DIR.rglob("*.py"))
        if "tests" not in path.parts
    )
    assert "REWRITE_TEMPLATE" not in shipped
    assert "REWRITE_BAD_DURATION" not in shipped
    assert "rewrite_for_event" not in shipped
    # The imperative sentence that made /drop a model turn.
    assert "Call the request_private_input tool" not in shipped
    # No hook verdict of any kind is constructed. Prose *about* the rejected
    # actions is expected — the docstrings explain why ``skip`` and ``rewrite``
    # are both wrong here — so this checks the returning statement, not the word.
    assert 'return {"action"' not in shipped


def test_the_hook_still_captures_the_source_and_still_triggers_the_reconciler(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    """Capture and the reconcile trigger are S4/S6 behaviour and must be untouched.

    The reconcile trigger rides in this hook because ``pre_gateway_dispatch`` is
    the only ``invoke_hook`` site in ``gateway/run.py`` (``:13636``) and no
    gateway-ready hook exists (``hermes_cli/plugins.py:135-215``). Deleting the
    rewrite must not have taken either with it.
    """
    triggers: list = []
    monkeypatch.setattr(
        plugin.drop.reconciler,
        "trigger_from_event",
        lambda gateway, **_kw: triggers.append(gateway) or False,
    )
    service = RecordingService(sources_module=plugin.drop.sources)
    install_service(monkeypatch, installed, service)

    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)

    dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert triggers == [ln.runner], "the reconcile trigger no longer fires"
    # The REAL object was stored, under the routing tuple the claim binds.
    entry = plugin.drop.sources.REGISTRY.by_routing_tuple(
        plugin.drop.sources.routing_tuple_for_source(ln.source)
    )
    assert entry is not None and entry.source is ln.source


def test_the_discovered_plugin_shares_this_processs_registry_and_contextvar(
    installed, plugin
) -> None:
    """Why an assertion on ``plugin.drop.*`` is an assertion on what ran.

    ``PluginManager._load_directory_module`` re-execs the package ``__init__``
    (``hermes_cli/plugins.py:1882-1886``), so the manager's module object is not
    this test's. Every submodule under it is, because the submodule names are
    already in ``sys.modules``.
    """
    assert installed is not plugin
    assert installed.drop.sources is plugin.drop.sources
    assert installed.drop.command is plugin.drop.command
    assert installed.drop.service is plugin.drop.service


# ── 3. one turn, one status message, in the authoritative lane ─────────────


@pytest.mark.parametrize(
    "platform,chat_id,chat_type,thread_id,other",
    [
        (Platform.TELEGRAM, "tg-1", "dm", "5", Platform.DISCORD),
        (Platform.DISCORD, "dc-1", "thread", "t-9", Platform.TELEGRAM),
    ],
)
def test_one_drop_posts_exactly_one_status_message_in_its_own_lane(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    gateway_loop,
    tmp_path: Path,
    real_broker,
    platform,
    chat_id,
    chat_type,
    thread_id,
    other,
) -> None:
    """The incident, inverted, through the real seam and the real broker.

    A second platform is live on the same runner and must receive nothing. The
    lane is not merely "the right chat": the ``metadata`` on the send is the one
    ``_thread_metadata_for_source`` derives from the **real** source — Telegram's
    DM-topic id plus its reply anchor, Discord's ``thread_id`` — which is exactly
    what a source rebuilt from contextvars cannot produce.
    """
    ln = lane(
        platform,
        chat_id=chat_id,
        chat_type=chat_type,
        thread_id=thread_id,
        message_id="anchor-1",
        extra_adapters=[other],
        gateway_loop=gateway_loop,
    )
    install_runner_handle(monkeypatch, ln.runner)
    service, journal, _wakes = _real_service(plugin, real_broker, tmp_path / "journal")
    install_service(monkeypatch, installed, service)

    reply = dispatch(ln.runner, event("/drop 5m", ln.source), loop=gateway_loop)

    assert reply is None
    assert ln.runner._handle_message_with_agent.await_count == 0
    assert len(ln.adapter.sent) == 1, f"expected one status message: {ln.adapter.sent}"
    assert len(journal.entries()) == 1, "expected exactly one journalled drop"
    assert ln.adapter.edited == [], "nothing is edited at initiation"

    posted = ln.adapter.sent[0]
    assert posted.chat_id == ln.source.chat_id
    expected_metadata = _thread_metadata_for_source(ln.source, "anchor-1")
    assert posted.metadata == expected_metadata
    assert posted.metadata and posted.metadata["thread_id"] == thread_id
    if platform is Platform.TELEGRAM:
        assert posted.metadata["direct_messages_topic_id"] == thread_id
        assert posted.metadata["telegram_reply_to_message_id"] == "anchor-1"

    for adapter in ln.others.values():
        assert adapter.sent == [], "a second platform received a message"

    # The broker rendered for THIS platform, chosen from the render table by the
    # origin's own platform name — never by a configured default.
    #
    # Both verified platforms emit a masked Markdown link now (review H1: the
    # telegram renderer's HTML was escaped and *displayed* by MarkdownV2, capability
    # and all). So the link shape no longer distinguishes them — the deadline form
    # does, and that is what is asserted per platform below.
    assert "](" in posted.content, f"a masked Markdown link on every platform: {posted.content}"
    if platform is Platform.TELEGRAM:
        assert "<" not in posted.content, "no HTML tag, and nothing that could become one"
        assert "<t:" not in posted.content, "a Discord relative stamp would be literal here"
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} UTC", posted.content), (
            f"telegram gets an absolute deadline: {posted.content}"
        )
    else:
        assert re.search(r"<t:\d{10}:R>", posted.content), (
            f"discord delegates the countdown to a relative stamp: {posted.content}"
        )


def test_two_drops_in_one_lane_are_two_independent_drops(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    gateway_loop,
    tmp_path: Path,
    real_broker,
) -> None:
    """No shared state makes a second ``/drop`` an echo of the first, and no
    single ``/drop`` produces two of anything."""
    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    service, journal, _ = _real_service(plugin, real_broker, tmp_path / "journal")
    install_service(monkeypatch, installed, service)

    dispatch(ln.runner, event("/drop 5m", ln.source), loop=gateway_loop)
    dispatch(ln.runner, event("/drop 6m", ln.source), loop=gateway_loop)

    assert len(ln.adapter.sent) == 2
    entries = journal.entries()
    assert len(entries) == 2
    assert len({e["drop_id"] for e in entries}) == 2
    assert ln.runner._handle_message_with_agent.await_count == 0


# ── 4. the slash-access policy still gates the command ─────────────────────

ADMIN = "111"
NON_ADMIN = "999"


def test_access_denial_applies_to_the_normalized_command_before_the_handler(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    """S9's commit 2, seen from the plugin's side.

    The gate now runs at the plugin sink on the **normalized** name that is
    actually dispatched (``gateway/run.py:14707``). ``/drop`` needs no
    normalization, so what this pins is the property that matters here: with
    ``allow_admin_from`` configured, a non-admin's ``/drop`` is refused *before*
    the handler — nothing minted, nothing posted, no model turn. The
    underscore-form bypass itself is pinned in the Hermes checkout's own
    ``tests/gateway/test_plugin_command_access.py``.
    """
    ln = lane(
        Platform.TELEGRAM,
        chat_id="tg-1",
        user_id=NON_ADMIN,
        gateway_loop=gateway_loop,
        platform_extra={"allow_admin_from": [ADMIN], "user_allowed_commands": []},
    )
    install_runner_handle(monkeypatch, ln.runner)
    service = RecordingService(sources_module=plugin.drop.sources)
    install_service(monkeypatch, installed, service)

    reply = dispatch(ln.runner, event("/drop 10m", ln.source), loop=gateway_loop)

    assert reply is not None and "⛔" in reply
    assert "/drop is admin-only here" in reply
    assert service.calls == [], "a denied command reached the service"
    assert ln.adapter.sent == [], "a denied command posted into the chat"
    assert ln.runner._handle_message_with_agent.await_count == 0


def test_an_admin_still_runs_drop_under_the_same_policy(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    ln = lane(
        Platform.TELEGRAM,
        chat_id="tg-1",
        user_id=ADMIN,
        gateway_loop=gateway_loop,
        platform_extra={"allow_admin_from": [ADMIN], "user_allowed_commands": []},
    )
    install_runner_handle(monkeypatch, ln.runner)
    service = RecordingService(sources_module=plugin.drop.sources)
    install_service(monkeypatch, installed, service)

    reply = dispatch(ln.runner, event("/drop 10m", ln.source), loop=gateway_loop)

    assert reply is None
    assert len(service.calls) == 1


def test_an_unauthorized_user_never_reaches_the_handler(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    """Auth runs after the hook and before dispatch (``gateway/run.py:13670``).

    The hook still captures — it fires before auth by design, so plugins can see
    unauthorized traffic — but nothing downstream of auth happens.
    """
    ln = lane(
        Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop, authorized=False
    )
    install_runner_handle(monkeypatch, ln.runner)
    service = RecordingService(sources_module=plugin.drop.sources)
    install_service(monkeypatch, installed, service)

    reply = dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert reply is None
    assert service.calls == []
    assert ln.adapter.sent == []
    assert ln.runner._handle_message_with_agent.await_count == 0


# ── 5. no echo, and no fall-through to /skill drop ─────────────────────────


def _spy_on_skill_resolution(monkeypatch) -> list:
    """Record any attempt to resolve ``/drop`` as a skill or bundle command.

    Core reaches skill resolution when the plugin handler *raises*
    (``gateway/run.py:14731-14732`` swallows it and execution continues at
    ``:14735+``). ``/skill drop`` is the prose path that named Discord and chose
    a platform — the incident's proximate cause — so an exception escaping the
    handler is not a degraded ``/drop``, it is the old one.
    """
    calls: list = []

    from agent import skill_bundles, skill_commands

    monkeypatch.setattr(
        skill_commands,
        "resolve_skill_command_key",
        lambda command: calls.append(("skill", command)) and None,
    )
    monkeypatch.setattr(
        skill_bundles,
        "resolve_bundle_command_key",
        lambda command: calls.append(("bundle", command)) and None,
    )
    return calls


def test_a_successful_drop_produces_no_echo_and_no_skill_resolution(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    skill_calls = _spy_on_skill_resolution(monkeypatch)
    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    service = RecordingService(sources_module=plugin.drop.sources)
    install_service(monkeypatch, installed, service)

    reply = dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert reply is None
    assert skill_calls == [], f"execution fell through to skill resolution: {skill_calls}"
    assert len(service.calls) == 1


def test_a_caught_internal_failure_reports_itself_and_resolves_no_skill(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    """The single most important test in the file.

    A raising handler is swallowed with a warning at ``gateway/run.py:14731-14732``
    and execution *continues* into skill resolution. The handler therefore
    catches everything, reports through ``OriginMessenger``, and returns ``None``.
    """
    skill_calls = _spy_on_skill_resolution(monkeypatch)

    class ExplodingService:
        async def create(self, *_a, **_kw):
            raise RuntimeError("simulated failure deep in the workflow")

    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    install_service(monkeypatch, installed, ExplodingService())

    reply = dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert reply is None
    assert skill_calls == [], "an internal failure became a /skill drop lookup"
    assert ln.runner._handle_message_with_agent.await_count == 0
    assert len(ln.adapter.sent) == 1, "the handler must report its own failure"
    posted = ln.adapter.sent[0].content
    assert "simulated failure" not in posted, "internals must not reach the chat"


# ── 6. the natural-language tool is still the same operation ───────────────


@pytest.mark.parametrize(
    "platform,chat_id,chat_type",
    [(Platform.TELEGRAM, "tg-1", "dm"), (Platform.DISCORD, "dc-1", "channel")],
)
def test_the_command_and_the_tool_make_the_same_service_call(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    gateway_loop,
    platform,
    chat_id,
    chat_type,
) -> None:
    """The plan's central safety argument, re-proven now that the command no
    longer travels through the model.

    The two reach ``DropService`` by genuinely different routes — the command is
    dispatched on the gateway loop by core, the tool crosses a worker-thread
    boundary once through ``SyncBridge`` — and must arrive with the same request.
    """
    ln = lane(platform, chat_id=chat_id, chat_type=chat_type, gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)

    from_command = RecordingService(sources_module=plugin.drop.sources)
    install_service(monkeypatch, installed, from_command)
    dispatch(ln.runner, event("/drop 10m", ln.source), loop=gateway_loop)

    # The tool path: a bound session context (the agent path binds it at
    # ``gateway/run.py:15641``) and the same captured source.
    from_tool = RecordingService(sources_module=plugin.drop.sources)
    session_key = ln.runner._session_key_for_source(ln.source)
    tokens = bind_session_context(
        platform=platform.value, chat_id=chat_id, session_key=session_key
    )
    try:
        plugin.drop.sources.capture(
            event=event("", ln.source), gateway=ln.runner, session_key=session_key
        )
        result = plugin.drop.tools.request_private_input(
            {"minutes": 10}, runner=ln.runner, service=from_tool
        )
    finally:
        clear_session_vars(tokens)

    assert result["ok"] is True
    assert from_command.calls == from_tool.calls != []


# ── 7. no secret escapes the deterministic path ────────────────────────────


def test_no_capability_escapes_the_deterministic_command_path(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    gateway_loop,
    tmp_path: Path,
    real_broker,
    caplog,
) -> None:
    """§8.8 over the seam-driven path: the capability lives in the status message
    and nowhere else.

    The full lifecycle sweep — payload included, through a real HPKE submit and
    a real claim — is ``test_command.py::test_no_capability_or_payload_escapes_the_command_path``.
    This one guards the part S10 changed: what the *gateway seam* itself can now
    see and log on the way in.
    """
    caplog.set_level(logging.DEBUG)
    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    service, journal, wakes = _real_service(plugin, real_broker, tmp_path / "journal")
    install_service(monkeypatch, installed, service)

    dispatch(ln.runner, event("/drop 5m", ln.source), loop=gateway_loop)

    posted = ln.adapter.sent[0].content
    link = re.search(r'https?://[^\s"<>]+#([A-Za-z0-9_-]+)', posted)
    assert link, f"no capability link in the posted notice: {posted!r}"
    capability = link.group(1)

    journalled = "\n".join(
        p.read_text(encoding="utf-8") for p in journal.root.glob("*.json")
    )
    logged = "\n".join(record.getMessage() for record in caplog.records)
    entry = journal.entries()[0]

    assert capability not in journalled, "the capability reached the journal"
    assert capability not in logged, "the capability reached the logs"
    assert capability not in json.dumps(entry, default=str)
    assert wakes == [], "nothing is announced at initiation"
    assert capability in posted, "the status message is the one place it belongs"
