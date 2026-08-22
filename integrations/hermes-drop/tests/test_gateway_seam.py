"""S12 — ``/drop`` is a **stock** skill command, and this is that seam.

Every test here drives the real ``GatewayRunner._handle_message`` with the
plugin installed through the real ``PluginManager`` and the Drop skill visible
to the real ``scan_skill_commands``. Nothing transcribes a core code block: the
claim is a claim about core's own control flow, unpatched.

``_handle_message`` → ``invoke_hook("pre_gateway_dispatch")`` (capture only)
→ auth → quick commands → plugin commands (**none**, we register none)
→ ``resolve_skill_command_key("drop")`` → ``build_skill_invocation_message``
→ ``event.text`` replaced → falls through → ``_handle_message_with_agent``.

What that buys, and what it costs, stated plainly:

* **Buys.** No core patch. The origin the tools resolve is bound by core's own
  ``_set_session_env`` on the agent path, which has always been there — Drop no
  longer needs a session-context binding around plugin dispatch, and the plugin
  no longer needs a slash command at all. It also buys the prompt: a non-empty
  ``/drop <prompt>`` is a sentence the *user typed*, carried verbatim into the
  turn, rather than a duration grammar the user has to learn.
* **Costs.** A skill command is not covered by ``_check_slash_access`` — that
  gate runs for registry-known commands, quick commands and *plugin* commands
  only. ``allow_admin_from`` / ``user_allowed_commands`` therefore no longer
  restrict ``/drop``. This is pinned below as a fact rather than papered over.
  It is not a new capability: the same authorized user could always reach
  ``request_private_input`` by asking for it in plain language, so the
  enforceable controls are authorization (which still gates the whole message)
  and the per-platform skill/toolset switches — not the slash policy.

Nothing about the safety envelope moved: capture and the reconcile trigger
still run in the hook and it still returns no verdict; nothing is minted before
the model turn; the tools still resolve an authoritative origin and post into
the originating lane and nowhere else.
"""

from __future__ import annotations

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
    lane,
)
from _stubs import bind_session_context
from conftest import PLUGIN_DIR, REPO_ROOT

SKILL_DIR = REPO_ROOT / "integrations" / "drop-skill"


# ── harness ────────────────────────────────────────────────────────────────


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch, temp_hermes_home: Path):
    """The plugin, registered through the real ``PluginManager``.

    **Take every module handle from this fixture, never from a separate
    import.** ``PluginManager._load_directory_module`` evicts every
    ``sys.modules`` entry under the package prefix before re-execing the spec
    (``hermes_cli/plugins.py:4993-4995``), so a handle captured before discovery
    is a *different* module object afterwards — same name, separate state. That
    divergence is what made this file's predecessor fail 20 ways in one process
    and pass one test at a time.
    """
    return install_plugin_for_real(monkeypatch, temp_hermes_home, PLUGIN_DIR)


@pytest.fixture
def plugin(installed):
    """The module the manager actually loaded. See ``installed``."""
    return installed


@pytest.fixture
def skill_installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The Drop skill where core's scanner will find it.

    ``tools.skills_tool.SKILLS_DIR`` is resolved from ``HERMES_HOME`` at import
    time, so a per-test ``HERMES_HOME`` cannot move it; rebinding the constant is
    what core reads.
    """
    import agent.skill_commands as skill_commands
    import tools.skills_tool as skills_tool

    root = tmp_path / "skills"
    (root / "hermes-drop").mkdir(parents=True)
    (root / "hermes-drop" / "drop").symlink_to(SKILL_DIR, target_is_directory=True)
    monkeypatch.setattr(skills_tool, "SKILLS_DIR", root)
    skill_commands._skill_commands = {}
    skill_commands._skill_commands_platform = None
    try:
        yield root
    finally:
        skill_commands._skill_commands = {}
        skill_commands._skill_commands_platform = None


class RecordingService:
    """Records what ``DropService.create`` was asked to do, and under what context.

    ``context_tuple`` is read *inside* the call, so it records the session
    identity bound while the tool ran — the property the origin verification
    depends on.
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
    """Arms nothing. A 30-minute park is not this slice."""

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


def _as_tool_turn(plugin, ln, service, *, args=None, tool="request_private_input"):
    """Run a Drop tool the way the agent path runs it.

    The agent path binds this turn's identity before the tool executes
    (``_set_session_env``), and the capture callback has already stored the real
    source. Both are reproduced here, and nothing else is: the tool itself is the
    production one.
    """
    session_key = ln.runner._session_key_for_source(ln.source)
    tokens = bind_session_context(
        platform=ln.source.platform.value,
        chat_id=ln.source.chat_id,
        thread_id=str(ln.source.thread_id or ""),
        profile=str(ln.source.profile or ""),
        session_key=session_key,
        chat_type=str(ln.source.chat_type or ""),
        user_id=str(ln.source.user_id or ""),
        message_id=str(ln.source.message_id or ""),
    )
    try:
        plugin.drop.sources.capture(
            event=event("", ln.source), gateway=ln.runner, session_key=session_key
        )
        return getattr(plugin.drop.tools, tool)(
            args or {}, runner=ln.runner, service=service
        )
    finally:
        clear_session_vars(tokens)


# ── 1. /drop becomes an ordinary agent turn ────────────────────────────────


@pytest.mark.parametrize(
    "platform,chat_id,chat_type",
    [(Platform.TELEGRAM, "tg-1", "dm"), (Platform.DISCORD, "dc-1", "channel")],
)
def test_a_bare_slash_drop_reaches_the_agent_with_the_skill_loaded(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    skill_installed,
    gateway_loop,
    platform,
    chat_id,
    chat_type,
) -> None:
    """The slice, on both verified platforms.

    ``_handle_message_with_agent`` is the only agent entry from
    ``_handle_message``, so exactly one await on it is "the turn reached the
    model" — carrying the skill, in the conversation it was typed in.
    """
    ln = lane(platform, chat_id=chat_id, chat_type=chat_type, gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)

    reply = dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert reply is None, "a returned string would post instead of running the turn"
    assert ln.runner._handle_message_with_agent.await_count == 1, "/drop never reached the agent"

    dispatched_event = ln.runner._handle_message_with_agent.await_args.args[0]
    assert 'The user has invoked the "drop" skill' in dispatched_event.text
    assert "request_private_input" in dispatched_event.text
    assert "send_private_output" in dispatched_event.text


def test_a_prompt_reaches_the_turn_verbatim(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, skill_installed, gateway_loop
) -> None:
    """Direction follows meaning, so the sentence has to survive the trip intact
    — and be recoverable, or memory stores the skill body instead of the ask."""
    from agent.skill_commands import extract_user_instruction_from_skill_message

    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    prompt = "generate an admin password for staging and send it to me"

    dispatch(ln.runner, event(f"/drop {prompt}", ln.source), loop=gateway_loop)

    text = ln.runner._handle_message_with_agent.await_args.args[0].text
    assert text.endswith(prompt)
    assert extract_user_instruction_from_skill_message(text) == prompt


def test_nothing_is_minted_by_the_dispatch_itself(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    skill_installed,
    gateway_loop,
    tmp_path: Path,
    real_broker,
) -> None:
    """The dispatch mints nothing and posts nothing.

    Under the old plugin-command path the handler *was* the operation and a link
    existed by the time dispatch returned. Now dispatch only loads a skill: no
    broker call, no journal entry, no chat message until the model decides to
    call a tool. That is the pre-auth-mint question answered structurally —
    there is no code on the dispatch path that can mint.
    """
    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    _service, journal, _wakes = _real_service(plugin, real_broker, tmp_path / "journal")

    dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert ln.adapter.sent == [], "dispatch posted into the chat"
    assert journal.entries() == [], "dispatch minted a drop"


def test_a_discord_native_slash_shape_with_no_message_id_still_routes(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, skill_installed, gateway_loop
) -> None:
    """``_build_slash_event`` sets no ``message_id``. Not a special case."""
    ln = lane(
        Platform.DISCORD, chat_id="dc-1", chat_type="channel", gateway_loop=gateway_loop
    )
    install_runner_handle(monkeypatch, ln.runner)

    reply = dispatch(
        ln.runner, event("/drop", ln.source, message_id=None), loop=gateway_loop
    )

    assert reply is None
    assert ln.runner._handle_message_with_agent.await_count == 1


def test_an_unknown_drop_variant_is_not_a_command_we_own(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, skill_installed, gateway_loop
) -> None:
    """Exactly one command, and the removed family stays removed.

    ``/drop-secret`` resolves to nothing, so core answers with its own
    unknown-command notice instead of loading the skill.
    """
    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)

    reply = dispatch(ln.runner, event("/drop-secret", ln.source), loop=gateway_loop)

    assert reply is not None and "Unknown command" in reply
    assert ln.runner._handle_message_with_agent.await_count == 0


# ── 2. the plugin owns no command surface at all ───────────────────────────


def test_the_plugin_registers_no_slash_command_so_the_skill_is_reachable(
    installed,
) -> None:
    """Plugin dispatch runs *before* skill dispatch. One registration here and
    every ``/drop`` in production would go back to a pre-agent handler."""
    from hermes_cli.plugins import get_plugin_commands

    assert get_plugin_commands() == {}


def test_no_command_module_prose_survives_in_the_plugin(plugin) -> None:
    """The deterministic-command era is removed, not merely unused.

    A dormant handler plus its duration grammar would be one ``register_command``
    away from shadowing the skill again.
    """
    assert not hasattr(plugin, "drop_command")
    assert not hasattr(plugin.drop, "command")

    shipped = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(PLUGIN_DIR.rglob("*.py"))
        if "tests" not in path.parts
    )
    for gone in ("parse_duration", "DURATION_HELP", "ARGS_HINT", "register_command("):
        assert gone not in shipped, f"{gone} still ships"
    # No hook verdict of any kind is constructed. Prose *about* the rejected
    # actions is expected — the docstrings explain why ``skip`` and ``rewrite``
    # are both wrong here — so this checks the returning statement, not the word.
    assert 'return {"action"' not in shipped


# ── 3. the hook still observes, and still decides nothing ──────────────────


@pytest.mark.parametrize(
    "text",
    [
        "/drop",
        "/drop here is my api key",
        "/drop give me the staging password",
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
    """``invoke_hook`` returns only non-``None`` callback results, and core acts
    on ``skip`` / ``rewrite`` / ``allow``. An empty list is exactly "core does
    nothing differently because of us" — for ``/drop`` and every other message
    alike. ``skip`` in particular stays impossible: the hook fires before auth
    and pairing, so handling ``/drop`` there would make Drop an unauthenticated
    command surface."""
    from hermes_cli.plugins import invoke_hook

    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    results = invoke_hook(
        "pre_gateway_dispatch",
        event=event(text, ln.source),
        gateway=ln.runner,
        session_store=None,
    )

    assert results == [], f"the hook still influences dispatch: {results}"


def test_the_hook_still_captures_the_source_and_still_triggers_the_reconciler(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, skill_installed, gateway_loop
) -> None:
    """Capture and the reconcile trigger are S4/S6 behaviour and must be untouched.

    The reconcile trigger rides in this hook because ``pre_gateway_dispatch`` is
    the only ``invoke_hook`` site in ``gateway/run.py`` and no gateway-ready hook
    exists. Moving the command must not have taken either with it — the *tool*
    path depends on the captured real source just as the command did.
    """
    triggers: list = []
    # Patch the module owned by the callback that PluginManager actually
    # registered. PluginManager reloads directory packages during discovery, so
    # a separately imported package handle may legitimately be a stale object.
    from hermes_cli.plugins import get_plugin_manager
    import sys

    callbacks = get_plugin_manager()._hooks.get("pre_gateway_dispatch", [])
    callback = next(
        (item[1] if isinstance(item, tuple) else item)
        for item in callbacks
        if getattr((item[1] if isinstance(item, tuple) else item), "__name__", "")
        == "capture_turn_source"
    )
    callback_module = sys.modules[callback.__module__]
    monkeypatch.setattr(
        callback_module.drop.reconciler,
        "trigger_from_event",
        lambda gateway, **_kw: triggers.append(gateway) or False,
    )

    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)

    dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert triggers == [ln.runner], "the reconcile trigger no longer fires"
    # The REAL object was stored, under the routing tuple the claim binds.
    entry = callback_module.drop.sources.REGISTRY.by_routing_tuple(
        callback_module.drop.sources.routing_tuple_for_source(ln.source)
    )
    assert entry is not None and entry.source is ln.source


# ── 4. authorization, and the policy that no longer applies ────────────────

ADMIN = "111"
NON_ADMIN = "999"


def test_an_unauthorized_user_never_reaches_the_agent(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, skill_installed, gateway_loop
) -> None:
    """Auth runs after the hook and before dispatch.

    The hook still captures — it fires before auth by design — but nothing
    downstream of auth happens: no skill is loaded, no turn is run.
    """
    ln = lane(
        Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop, authorized=False
    )
    install_runner_handle(monkeypatch, ln.runner)

    reply = dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert reply is None
    assert ln.adapter.sent == []
    assert ln.runner._handle_message_with_agent.await_count == 0


def test_the_slash_access_policy_does_not_cover_a_skill_command(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, skill_installed, gateway_loop
) -> None:
    """Documented, not claimed away.

    ``_check_slash_access`` runs for registry-known commands, quick commands and
    plugin commands. A skill command reaches none of those sinks, so an
    authorized non-admin runs ``/drop`` even with ``allow_admin_from`` set and
    ``user_allowed_commands`` empty — where the old plugin command was denied.

    This is a real difference and it is the price of the stock seam. It is not a
    new capability: the same user could always reach ``request_private_input`` by
    asking in plain language, which no slash policy sees either. The operator
    controls that *do* apply are authorization (above) and the per-platform skill
    switch (``skills.platform_disabled``, ``hermes skills config``), which core
    checks in the skill branch itself.
    """
    ln = lane(
        Platform.TELEGRAM,
        chat_id="tg-1",
        user_id=NON_ADMIN,
        gateway_loop=gateway_loop,
        platform_extra={"allow_admin_from": [ADMIN], "user_allowed_commands": []},
    )
    install_runner_handle(monkeypatch, ln.runner)

    reply = dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    assert reply is None
    assert ln.runner._handle_message_with_agent.await_count == 1


def test_disabling_the_skill_for_a_platform_refuses_the_command(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, skill_installed, gateway_loop
) -> None:
    """The operator control that replaces the slash-access gate, exercised."""
    import agent.skill_utils as skill_utils
    import gateway.run as gateway_run

    monkeypatch.setattr(
        skill_utils, "get_disabled_skill_names", lambda platform=None: {"drop"}
    )
    monkeypatch.setattr(
        gateway_run, "_get_plat_disabled", lambda platform=None: {"drop"}, raising=False
    )

    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)

    reply = dispatch(ln.runner, event("/drop", ln.source), loop=gateway_loop)

    # Stock core intentionally hides disabled skill commands as unknown.
    assert reply is not None and "Unknown command" in reply
    assert ln.runner._handle_message_with_agent.await_count == 0


# ── 5. one drop, one status message, in the authoritative lane ─────────────


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
    """The incident, inverted, through the real tool and the real broker.

    A second platform is live on the same runner and must receive nothing. The
    lane is not merely "the right chat": the ``metadata`` on the send is the one
    ``_thread_metadata_for_source`` derives from the **real** captured source —
    Telegram's DM-topic id plus its reply anchor, Discord's ``thread_id`` — which
    is exactly what a source rebuilt from contextvars cannot produce.
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

    result = _as_tool_turn(plugin, ln, service, args={"minutes": 5})

    assert result.get("ok") is True, result
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
    """No shared state makes a second drop an echo of the first, and no single
    drop produces two of anything."""
    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    service, journal, _ = _real_service(plugin, real_broker, tmp_path / "journal")

    _as_tool_turn(plugin, ln, service, args={"minutes": 5})
    _as_tool_turn(plugin, ln, service, args={"minutes": 6})

    assert len(ln.adapter.sent) == 2
    entries = journal.entries()
    assert len(entries) == 2
    assert len({e["drop_id"] for e in entries}) == 2


# ── 6. the tool resolves an authoritative origin on the agent path ─────────


@pytest.mark.parametrize(
    "platform,chat_id,chat_type",
    [(Platform.TELEGRAM, "tg-1", "dm"), (Platform.DISCORD, "dc-1", "channel")],
)
def test_the_tool_resolves_the_bound_turn_context_and_nothing_else(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    gateway_loop,
    platform,
    chat_id,
    chat_type,
) -> None:
    """What the removed core patch used to provide, provided by core already.

    The patch existed because a plugin *command* ran between
    ``reset_session_vars()`` and ``_set_session_env``, with nothing bound. A tool
    runs after the binding, so the origin resolved from the captured real source
    has an authoritative context to be verified against — tier
    ``turn_contextvar``, and the two tuples agree.
    """
    ln = lane(platform, chat_id=chat_id, chat_type=chat_type, gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    service = RecordingService(sources_module=plugin.drop.sources)

    result = _as_tool_turn(plugin, ln, service, args={"minutes": 10})

    assert result["ok"] is True
    assert len(service.calls) == 1
    call = service.calls[0]
    assert call["ttl_seconds"] == 600
    assert call["routing_tuple"] == (platform.value, "", chat_id, "")
    assert call["tier"] == "turn_contextvar"
    assert call["context_tuple"] == call["routing_tuple"]
    assert call["session_key"] == ln.runner._session_key_for_source(ln.source)


# ── 7. no capability escapes ───────────────────────────────────────────────


def test_no_capability_escapes_the_tool_path(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    gateway_loop,
    tmp_path: Path,
    real_broker,
    caplog,
) -> None:
    """§8.8: the capability lives in the status message and nowhere else."""
    caplog.set_level(logging.DEBUG)
    ln = lane(Platform.TELEGRAM, chat_id="tg-1", gateway_loop=gateway_loop)
    install_runner_handle(monkeypatch, ln.runner)
    service, journal, wakes = _real_service(plugin, real_broker, tmp_path / "journal")

    result = _as_tool_turn(plugin, ln, service, args={"minutes": 5})

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
    assert capability not in json.dumps(result), "the tool result carried the capability"
    assert wakes == [], "nothing is announced at initiation"
    assert capability in posted, "the status message is the one place it belongs"
