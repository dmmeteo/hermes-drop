"""The ``/drop`` entry point: registration, argument handling, refusals, leaks.

Everything here drives the **real** gateway dispatch seam —
``GatewayRunner._handle_message`` with the plugin registered through the real
``PluginManager`` (``tests/_seam.py``). Slice S8 tested the handler against a
transcription of ``gateway/run.py``'s plugin branch because the branch was not
yet reachable in production; S10 deleted the interim rewrite that made it
unreachable, so the transcription is gone with it. A copy of a control-flow block
is a second thing to keep in sync, and the whole point of S9/S10 is that the real
block now does the right thing.

Two claims are under test here; the seam-level properties of S10 (no model turn,
no transformed prose, denial before the handler, no skill fall-through) live in
``test_gateway_seam.py``.

**One operation, two doors.** ``/drop 10m`` and ``request_private_input`` with
``minutes=10`` must reach ``DropService.create`` with *identical* arguments. Not
"equivalent", not "similar": the same ``ttl_seconds``, the same ``purpose``, the
same routing tuple, on the same loop. If the two ever diverge the plan's central
safety argument — that the command is the tool — becomes a comment rather than a
property.

**Every refusal is answered in the originating conversation, or nowhere.** A bad
duration, an unsupported platform, a service error and an internal exception each
produce exactly one message, in the lane the request came from, naming no
internals — and never a redirect to a platform that happens to work.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import re
import time
from pathlib import Path

import pytest
from gateway.config import Platform
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


@pytest.fixture
def plugin():
    return load_plugin_package()


@pytest.fixture
def command(plugin):
    return plugin.drop.command


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch, temp_hermes_home: Path, plugin):
    """The plugin registered through the real ``PluginManager``.

    Also the fixture that makes ``/drop`` reachable: ``_handle_message`` looks the
    handler up with ``get_plugin_command_handler`` (``gateway/run.py:14697``).
    """
    return install_plugin_for_real(monkeypatch, temp_hermes_home, PLUGIN_DIR)


# ── harness ────────────────────────────────────────────────────────────────


class RecordingService:
    """Records exactly what ``DropService.create`` was asked to do.

    The recorded shape is the comparison surface for "the command and the tool
    are the same operation", so it deliberately captures the routing tuple —
    where the link would go — alongside the arguments.
    """

    def __init__(self, *, create_result=None):
        self.calls: list = []
        self._result = create_result

    async def create(self, origin, *, ttl_seconds, purpose="", session_key=""):
        self.calls.append(
            {
                "ttl_seconds": ttl_seconds,
                "purpose": purpose,
                "session_key": session_key,
                "routing_tuple": tuple(origin.routing_tuple),
            }
        )
        if self._result is not None:
            return self._result
        return {
            "ok": True,
            "drop_id": "H" * 22,
            "state": "waiting",
            "platform": origin.platform_name,
            "purpose": purpose,
            "expires_at_ms": int(time.time() * 1000) + ttl_seconds * 1000,
            "expires_in_seconds": ttl_seconds,
            "note": "",
        }

    async def claim(self, origin, drop_id):  # pragma: no cover - not this slice
        return {"error": "unavailable"}


def _telegram_lane(*, loop, chat_id: str = "tg-1", extra_adapters=()):
    return lane(
        Platform.TELEGRAM,
        chat_id=chat_id,
        chat_type="dm",
        gateway_loop=loop,
        extra_adapters=extra_adapters,
    )


def _discord_lane(*, loop, chat_id: str = "dc-1", extra_adapters=()):
    return lane(
        Platform.DISCORD,
        chat_id=chat_id,
        chat_type="channel",
        gateway_loop=loop,
        extra_adapters=extra_adapters,
    )


def _drop_turn(monkeypatch, installed, ln, text: str, *, service=None):
    """One whole ``/drop`` turn through core's own dispatch.

    ``_handle_message`` fires the capture hook (``gateway/run.py:13636``),
    authorizes, applies the slash-access policy, binds this turn's session
    identity (``:14721``) and awaits the handler on the gateway loop
    (``:14726-14728``) — all of it real. The service is injected by replacing the
    class the handler constructs, because core hands the handler one positional
    string and nothing else.
    """
    install_runner_handle(monkeypatch, ln.runner)
    if service is not None:
        install_service(monkeypatch, installed, service)
    return dispatch(ln.runner, event(text, ln.source), loop=ln.runner._gateway_loop)


# ── registration ───────────────────────────────────────────────────────────


def test_drop_is_registered_exactly_once_as_an_async_command(installed) -> None:
    """Exactly one ``drop`` key, and it is ours.

    Two registrations is not a cosmetic problem: ``_plugin_commands`` is a dict
    keyed by name (``hermes_cli/plugins.py:594``), so a second registration would
    silently *replace* the first and the surviving handler would be whichever
    plugin loaded last. That is precisely the state slice S11/M2 has to leave
    behind when it removes ``hermes-drop-command``.
    """
    from hermes_cli.plugins import get_plugin_commands

    commands = get_plugin_commands()

    drop_keys = [name for name in commands if "drop" in name]
    assert drop_keys == ["drop"], f"expected exactly one drop command, saw {sorted(commands)}"

    entry = commands["drop"]
    assert entry["plugin"] == "hermes-drop"
    assert inspect.iscoroutinefunction(entry["handler"]), "the handler must be async (§6)"


def test_the_args_hint_is_bracketed_so_telegram_treats_the_duration_as_optional(
    installed,
) -> None:
    """``args_hint="[10m]"`` is load-bearing on both verified platforms.

    Telegram's menu builder skips a command whose hint starts with ``<``
    (``_requires_argument``, ``hermes_cli/commands.py:533-535``), so a bracketed
    hint is what makes ``/drop`` appear with an *optional* argument; Discord
    builds an optional ``args`` field for any non-empty hint.
    """
    from hermes_cli.plugins import get_plugin_commands

    hint = get_plugin_commands()["drop"]["args_hint"]

    assert hint == "[10m]"
    assert not hint.startswith("<"), "a <-prefixed hint drops the command from Telegram's menu"


# ── duration parsing ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("", 30),
        ("   ", 30),
        (None, 30),
        ("10", 10),
        ("10m", 10),
        ("10 m", 10),
        ("10min", 10),
        ("10 minutes", 10),
        ("1h", 60),
        ("1 hour", 60),
        ("60", 60),
        ("1", 1),
    ],
)
def test_a_usable_duration_parses_to_minutes(command, raw, expected) -> None:
    assert command.parse_duration(raw) == expected


@pytest.mark.parametrize("raw,expected", [("0", 1), ("0m", 1), ("90m", 60), ("2h", 60), ("999", 60)])
def test_a_numeric_duration_out_of_range_is_clamped_into_one_to_sixty(
    command, raw, expected
) -> None:
    """Clamped here, *refused* in the tool — and the asymmetry is deliberate.

    ``/drop 90m`` is a person making a rough request, and the deadline they get
    is rendered into the status message they are looking at, so a clamp is
    visible rather than silent. ``minutes=90`` from the model is a schema
    violation (``drop/schemas.py`` bounds it 1..60), and a model that drifts past
    a stated bound must be told, not quietly accommodated
    (``drop/tools.py::_parse_minutes``).
    """
    assert command.parse_duration(raw) == expected


@pytest.mark.parametrize(
    "raw", ["banana", "10x", "m", "1.5m", "-5", "10m please", "1e3", "x" * 40, "٥"]
)
def test_an_unparseable_duration_is_refused_rather_than_guessed(command, raw) -> None:
    result = command.parse_duration(raw)
    assert isinstance(result, dict) and result["error"] == "invalid_duration", raw


# ── nothing reconstructs or re-derives an origin ────────────────────────────


def test_no_origin_stamp_and_no_origin_conflict_survive_anywhere(plugin) -> None:
    """Revision 1's stamp is gone, and stays gone.

    It compared two values derived from the same ``SessionSource``, so it was
    unreachable within a turn, absent across turns, keyed on a ``message_id``
    that is empty for Discord native slashes, and never evicted. §4's mandatory
    verification — the captured source against the contextvars core binds at
    ``gateway/run.py:14721`` — replaces it.
    """
    sources = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(PLUGIN_DIR.rglob("*.py"))
        if "tests" not in path.parts
    )
    assert "origin_stamp" not in sources
    assert "origin_conflict" not in sources


# ── the command and the tool are one operation ─────────────────────────────


@pytest.mark.parametrize(
    "make_lane,platform,chat_id",
    [(_telegram_lane, "telegram", "tg-1"), (_discord_lane, "discord", "dc-1")],
)
def test_the_command_and_the_tool_make_the_same_service_call(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    gateway_loop,
    make_lane,
    platform,
    chat_id,
) -> None:
    """The claim of the slice, on both verified platforms.

    Same ``ttl_seconds``, same ``purpose``, same routing tuple. The tool crosses
    a worker-thread boundary through ``SyncBridge``; the command is dispatched by
    core on the gateway loop. Two genuinely different routes, one request.
    """
    ln = make_lane(loop=gateway_loop, chat_id=chat_id)

    from_command = RecordingService()
    _drop_turn(monkeypatch, installed, ln, "/drop 10m", service=from_command)

    from_tool = RecordingService()
    session_key = ln.runner._session_key_for_source(ln.source)
    tokens = bind_session_context(
        platform=platform, chat_id=chat_id, session_key=session_key
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
    assert from_command.calls[0]["ttl_seconds"] == 600
    assert from_command.calls[0]["routing_tuple"][2] == chat_id


def test_a_bare_drop_is_the_default_thirty_minutes_on_both_paths(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    ln = _telegram_lane(loop=gateway_loop)

    from_command = RecordingService()
    _drop_turn(monkeypatch, installed, ln, "/drop", service=from_command)

    from_tool = RecordingService()
    session_key = ln.runner._session_key_for_source(ln.source)
    tokens = bind_session_context(
        platform="telegram", chat_id="tg-1", session_key=session_key
    )
    try:
        plugin.drop.sources.capture(
            event=event("", ln.source), gateway=ln.runner, session_key=session_key
        )
        plugin.drop.tools.request_private_input({}, runner=ln.runner, service=from_tool)
    finally:
        clear_session_vars(tokens)

    assert from_command.calls == from_tool.calls
    assert from_command.calls[0]["ttl_seconds"] == 1800


def test_the_command_never_names_a_destination(
    monkeypatch: pytest.MonkeyPatch, installed, gateway_loop
) -> None:
    """``/drop`` in a Discord channel with a Telegram adapter also live posts on
    Discord and nowhere else — the incident, inverted."""
    ln = _discord_lane(loop=gateway_loop, extra_adapters=[Platform.TELEGRAM])

    service = RecordingService()
    _drop_turn(monkeypatch, installed, ln, "/drop", service=service)

    assert service.calls[0]["routing_tuple"][0] == "discord"
    assert ln.others[Platform.TELEGRAM].sent == [], "a second adapter received a message"


# ── the handler is a dead end for exceptions ───────────────────────────────


def test_a_successful_handler_returns_none_so_the_gateway_posts_no_echo(
    monkeypatch: pytest.MonkeyPatch, installed, gateway_loop
) -> None:
    """``return str(result) if result else None`` (``gateway/run.py:14729``) —
    a returned receipt string would double-post next to the status message."""
    ln = _telegram_lane(loop=gateway_loop)
    returned = _drop_turn(monkeypatch, installed, ln, "/drop", service=RecordingService())

    assert returned is None
    assert (str(returned) if returned else None) is None


def test_the_handler_delivers_its_own_error_when_the_service_refuses(
    monkeypatch: pytest.MonkeyPatch, installed, gateway_loop
) -> None:
    ln = _telegram_lane(loop=gateway_loop)
    service = RecordingService(
        create_result={"error": "broker_unavailable", "detail": "/run/x.sock"}
    )

    returned = _drop_turn(monkeypatch, installed, ln, "/drop", service=service)

    assert returned is None
    assert len(ln.adapter.sent) == 1
    posted = ln.adapter.sent[0].content
    assert "not reachable" in posted
    assert "/run/x.sock" not in posted, "a raw detail string is not a user-facing reason"


def test_an_unusable_duration_is_answered_in_the_chat_and_mints_nothing(
    monkeypatch: pytest.MonkeyPatch, installed, gateway_loop
) -> None:
    ln = _telegram_lane(loop=gateway_loop)
    service = RecordingService()

    returned = _drop_turn(monkeypatch, installed, ln, "/drop banana", service=service)

    assert returned is None
    assert service.calls == [], "a bad duration must not reach the broker"
    assert len(ln.adapter.sent) == 1 and "1 and 60 minutes" in ln.adapter.sent[0].content


def test_an_unsupported_platform_is_refused_by_name_and_never_redirected(
    monkeypatch: pytest.MonkeyPatch, installed, gateway_loop
) -> None:
    ln = lane(
        Platform.MATRIX,
        chat_id="!room:example.org",
        chat_type="group",
        extra_adapters=[Platform.TELEGRAM],
        gateway_loop=gateway_loop,
    )
    service = RecordingService()

    returned = _drop_turn(monkeypatch, installed, ln, "/drop", service=service)

    assert returned is None
    assert service.calls == []
    assert ln.others[Platform.TELEGRAM].sent == [], (
        "never a redirect to a platform that *is* supported"
    )
    assert len(ln.adapter.sent) == 1 and "matrix" in ln.adapter.sent[0].content


def test_with_no_resolvable_origin_the_handler_says_nothing_anywhere(
    monkeypatch: pytest.MonkeyPatch, installed, plugin, gateway_loop
) -> None:
    """There is no chat message to post into, so there is nothing to say and
    nowhere to say it (§6, the CLI row). Silence, not a guess at a destination.

    Dispatched directly rather than through ``_handle_message``, because the seam
    always captures: this is the CLI/TUI shape, where nothing captured a source
    and no session context is bound.
    """
    ln = _telegram_lane(loop=gateway_loop)
    service = RecordingService()

    async def _turn():
        return await plugin.drop_command("", runner=ln.runner, service=service)

    assert asyncio.run_coroutine_threadsafe(_turn(), gateway_loop).result(15) is None
    assert service.calls == []
    assert ln.adapter.sent == []


# ── leak sweep over a real command-path run ────────────────────────────────


class NullWaiters:
    def __init__(self):
        self.armed: list = []

    def arm(self, drop_id, coro_factory, **kw):
        self.armed.append(drop_id)
        coro_factory().close()
        return True

    def is_armed(self, drop_id):
        return drop_id in self.armed


def test_no_capability_or_payload_escapes_the_command_path(
    monkeypatch: pytest.MonkeyPatch,
    installed,
    plugin,
    gateway_loop,
    tmp_path: Path,
    real_public_broker,
    caplog,
) -> None:
    """§8.8/§8.9 as an exact-string sweep, then a shape check, over the *command*
    entry point end to end — now with the turn driven by core's own dispatch:
    ``/drop`` → mint → post → park → real HPKE submit → edit → journal →
    announce → claim, plus two error paths.

    The capability is allowed in exactly one place — the status message — and the
    payload in exactly one — the claim tool result. Everything else is searched
    for both exact strings. The shape check then removes the known (non-secret)
    handoff id and asserts no other 22-character base64url run survives, which is
    what would catch a *second* capability nobody thought to look for. Logs are
    swept for the exact strings but excluded from the shape check: they carry
    filesystem paths whose segments are legitimately 22+ base64url characters.
    """
    caplog.set_level(logging.DEBUG)
    payload = "e2e-marker-3f91c2-payload"

    ln = _telegram_lane(loop=gateway_loop)
    adapter, runner, source = ln.adapter, ln.runner, ln.source
    journal = plugin.drop.journal.DropJournal(root=tmp_path / "hermes-drop")
    wakes: list = []

    async def deliver(adapter_arg, *, text, source=None, session_id=""):
        wakes.append(text)

    service = plugin.drop.service.DropService(
        journal=journal,
        control=plugin.drop.control_client,
        socket_path=real_public_broker.socket_path,
        waiters=NullWaiters(),
        deliver=deliver,
    )

    assert _drop_turn(monkeypatch, installed, ln, "/drop 1m", service=service) is None

    posted = adapter.sent[0].content
    link = re.search(r'https?://[^\s"<>]+#([A-Za-z0-9_-]+)', posted)
    assert link, f"no capability link in the posted notice: {posted!r}"
    capability = link.group(1)
    drop_id = journal.entries()[0]["drop_id"]

    # Drive the drop to a terminal state through the real broker, on the same
    # loop the command ran on.
    origin = plugin.drop.origin.Origin(
        source=source,
        adapter=adapter,
        runner=runner,
        routing_tuple=plugin.drop.sources.routing_tuple_for_source(source),
        reply_anchor=None,
        tier="turn_contextvar",
    )
    waiter = plugin.drop.waiter.DropWaiter(
        journal=journal,
        control=plugin.drop.control_client,
        socket_path=real_public_broker.socket_path,
        deliver=deliver,
    )

    async def _park_and_submit():
        parked = asyncio.ensure_future(waiter.run(drop_id=drop_id, origin=origin))
        await asyncio.sleep(0.2)
        loop = asyncio.get_running_loop()
        submitted = await loop.run_in_executor(
            None, real_public_broker.submit, link.group(0), payload
        )
        assert submitted == "SUBMITTED sent", submitted
        return await asyncio.wait_for(parked, timeout=30)

    parked_result = asyncio.run_coroutine_threadsafe(
        _park_and_submit(), gateway_loop
    ).result(45)
    assert parked_result["state"] == "received"

    # Two error paths, so their user-facing text is in the sweep too.
    _drop_turn(monkeypatch, installed, ln, "/drop banana", service=service)
    _drop_turn(
        monkeypatch,
        installed,
        ln,
        "/drop 5m",
        service=RecordingService(create_result={"error": "broker_unavailable"}),
    )

    session_key = runner._session_key_for_source(source)
    tokens = bind_session_context(
        platform="telegram", chat_id="tg-1", session_key=session_key
    )
    try:
        plugin.drop.sources.capture(
            event=event("", source), gateway=runner, session_key=session_key
        )
        claimed = plugin.drop.tools.claim_private_input(
            {"drop_id": drop_id}, runner=runner, service=service
        )
    finally:
        clear_session_vars(tokens)
    assert claimed["private_input"] == payload

    journalled = "\n".join(p.read_text(encoding="utf-8") for p in journal.root.glob("*.json"))
    logged = "\n".join(record.getMessage() for record in caplog.records)
    announced = "\n".join(wakes)
    edited = "\n".join(e.content for e in adapter.edited)
    errors = "\n".join(m.content for m in adapter.sent[1:])

    for haystack, name in (
        (journalled, "the journal"),
        (announced, "the announce text"),
        (edited, "the edit results"),
        (errors, "the error paths"),
        (logged, "the logs"),
    ):
        assert capability not in haystack, f"the capability reached {name}"
        assert payload not in haystack, f"the payload reached {name}"

    assert capability in posted, "the status message is the one place it belongs"
    assert payload in json.dumps(claimed), "the claim result is the one place it belongs"
    assert announced and edited and errors, "the sweep must run over non-empty haystacks"

    # Shape check: with the one known non-secret 22-char token removed, nothing
    # 22-character-shaped may remain. Both the handoff id and the capability are
    # 22 base64url characters (../tickets/09, Decision 5).
    assert len(drop_id) == 22 and len(capability) == 22
    shaped = "\n".join((journalled, announced, edited, errors)).replace(drop_id, "")
    stray = re.search(r"[A-Za-z0-9_-]{22}", shaped)
    assert stray is None, f"an unexplained 22-character token survived: {stray}"
