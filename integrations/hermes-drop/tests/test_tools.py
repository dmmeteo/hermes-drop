"""S5/S7 — the tool handlers, end to end.

What is proved here: origin resolution and verification (S4), the platform gate
refusing **before** anything is minted (S5), argument handling, and — since S7 —
the real operation, driven the way production drives it.

"The way production drives it" is the point of the ``gateway_loop`` fixture. A
model tool handler runs on a ``ThreadPoolExecutor`` worker
(``gateway/run.py:18604`` → ``:20276-20285``) and crosses to the gateway loop
once, through ``SyncBridge``. A test that awaited ``DropService`` directly would
skip that crossing entirely, and the crossing is where two of revision 1's bugs
lived (scheduling onto the loop you are blocking; ``.result()`` on an
``Optional[Future]``).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest
from gateway.config import Platform

from _stubs import StubAdapter, StubRunner, bind_session_context
from conftest import load_plugin_package


@pytest.fixture
def plugin():
    return load_plugin_package()


@pytest.fixture
def tools(plugin):
    return plugin.drop.tools


class _Event:
    def __init__(self, source):
        self.source = source


@pytest.fixture
def turn(plugin):
    """Capture a real source and bind the matching session context."""
    from gateway.session_context import clear_session_vars

    tokens: list = []

    def _make(platform: Platform, chat_id: str = "chat-1", loop=None, **kwargs):
        adapter = StubAdapter(platform)
        runner = StubRunner({platform: adapter}, gateway_loop=loop)
        source = adapter.build_source(chat_id=chat_id, chat_type="dm", user_id="u", **kwargs)
        plugin.drop.sources.capture(event=_Event(source), gateway=runner, session_key="s")
        tokens.extend(
            bind_session_context(platform=platform.value, chat_id=chat_id, session_key="s")
        )
        return runner, adapter

    yield _make
    if tokens:
        clear_session_vars(tokens)


class FakeControl:
    """The broker's answers, without the broker. The real one is exercised in
    ``test_service.py``; here the subject is the handler and the crossing."""

    def __init__(self, *, claim_answer=None):
        self.claim_answer = claim_answer
        self.calls: list = []

    async def create(
        self,
        *,
        ttl_seconds=None,
        notice_platform=None,
        payload_kind=None,
        socket_path=None,
        timeout=None,
    ):
        self.calls.append({"op": "create", "ttl_seconds": ttl_seconds})
        return {
            "ok": True,
            "handoff_id": "H" * 22,
            "url": "http://127.0.0.1:8080/#Q2FwYWJpbGl0eVN0cmluZ0FB",
            "expires_at": int(time.time() * 1000) + (ttl_seconds or 1800) * 1000,
            "ttl_seconds": ttl_seconds or 1800,
            "notice": "🔐 open http://127.0.0.1:8080/#Q2FwYWJpbGl0eVN0cmluZ0FB",
            "notice_received": "✓ **Private input received**",
            "notice_expired": "✕ **Private input link expired**",
        }

    async def await_submission(self, handoff_id, *, wait_ms, socket_path=None, timeout=None):
        self.calls.append({"op": "await", "handoff_id": handoff_id})
        return {"ok": False, "error": "unavailable"}

    async def claim(self, handoff_id, *, wait_ms=0, socket_path=None, timeout=None):
        self.calls.append({"op": "claim", "handoff_id": handoff_id})
        return self.claim_answer or {"ok": False, "error": "unavailable"}


class NullWaiters:
    def __init__(self):
        self.armed: list = []

    def arm(self, drop_id, coro_factory, **kw):
        self.armed.append(drop_id)
        coro_factory().close()
        return True

    def is_armed(self, drop_id):
        return drop_id in self.armed


@pytest.fixture
def service_for(plugin, tmp_path: Path):
    def _make(control=None, waiters=None):
        return plugin.drop.service.DropService(
            journal=plugin.drop.journal.DropJournal(root=tmp_path / "hermes-drop"),
            control=control or FakeControl(),
            waiters=waiters or NullWaiters(),
        )

    return _make


@pytest.fixture
def no_broker_calls(plugin, monkeypatch):
    """Record every control-protocol call so 'refused before create' is provable."""
    calls: list = []

    async def spy(payload, **kwargs):
        calls.append(payload)
        return {"ok": False, "error": "unavailable"}

    monkeypatch.setattr(plugin.drop.control_client, "control_request", spy)
    return calls


# ── the platform gate fires before anything is minted ──────────────────────


def test_an_unsupported_platform_refuses_before_create(tools, turn, no_broker_calls) -> None:
    runner, adapter = turn(Platform.MATRIX, chat_id="!room:example.org")

    result = tools.request_private_input({}, runner=runner)

    assert result == {"error": "platform_unsupported", "platform": "matrix"}
    assert no_broker_calls == [], "a handoff was minted for an unsupported platform"
    assert adapter.sent == [], "an unsupported platform still got a message"


def test_an_unsupported_platform_is_never_redirected_to_a_supported_one(
    tools, turn, no_broker_calls
) -> None:
    """The incident as a rule: never a silent fallback, never a redirect."""
    matrix = StubAdapter(Platform.MATRIX)
    telegram = StubAdapter(Platform.TELEGRAM)
    plugin = load_plugin_package()
    source = matrix.build_source(chat_id="!room:example.org", chat_type="group", user_id="u")
    runner = StubRunner({Platform.MATRIX: matrix, Platform.TELEGRAM: telegram})
    plugin.drop.sources.capture(event=_Event(source), gateway=runner, session_key="s")
    tokens = bind_session_context(
        platform="matrix", chat_id="!room:example.org", session_key="s"
    )
    try:
        result = tools.request_private_input({}, runner=runner)
    finally:
        from gateway.session_context import clear_session_vars

        clear_session_vars(tokens)

    assert result["error"] == "platform_unsupported"
    assert telegram.sent == []
    assert matrix.sent == []


def test_the_cli_refuses_because_there_is_no_chat_message_to_post(
    tools, turn, no_broker_calls
) -> None:
    """Correct, not a gap (§6): the CLI has nothing to post into or edit."""
    runner, _ = turn(Platform.LOCAL, chat_id="cli")
    assert tools.request_private_input({}, runner=runner)["error"] == "platform_unsupported"


# ── origin refusals reach the model unchanged ──────────────────────────────


def test_no_origin_refuses_and_mints_nothing(tools, no_broker_calls) -> None:
    runner = StubRunner({Platform.TELEGRAM: StubAdapter(Platform.TELEGRAM)})
    tokens = bind_session_context(platform="telegram", chat_id="c", session_key="s")
    try:
        assert tools.request_private_input({}, runner=runner) == {"error": "no_origin"}
    finally:
        from gateway.session_context import clear_session_vars

        clear_session_vars(tokens)
    assert no_broker_calls == []


def test_origin_mismatch_refuses_and_mints_nothing(plugin, tools, no_broker_calls) -> None:
    telegram = StubAdapter(Platform.TELEGRAM)
    discord = StubAdapter(Platform.DISCORD)
    runner = StubRunner({Platform.TELEGRAM: telegram, Platform.DISCORD: discord})
    foreign = discord.build_source(chat_id="discord-chat", chat_type="channel", user_id="other")
    plugin.drop.sources.capture(event=_Event(foreign), gateway=runner, session_key="foreign")

    tokens = bind_session_context(platform="telegram", chat_id="tg-chat", session_key="mine")
    try:
        assert tools.request_private_input({}, runner=runner) == {"error": "origin_mismatch"}
    finally:
        from gateway.session_context import clear_session_vars

        clear_session_vars(tokens)

    assert no_broker_calls == []
    assert discord.sent == [] and telegram.sent == []


def test_an_unverifiable_origin_refuses(plugin, tools, no_broker_calls) -> None:
    telegram = StubAdapter(Platform.TELEGRAM)
    runner = StubRunner({Platform.TELEGRAM: telegram})
    source = telegram.build_source(chat_id="c", chat_type="dm", user_id="u")
    plugin.drop.sources.capture(event=_Event(source), gateway=runner, session_key="s")

    assert tools.request_private_input({}, runner=runner) == {"error": "origin_unverified"}
    assert no_broker_calls == []


# ── argument handling ──────────────────────────────────────────────────────


def test_claim_requires_a_non_empty_drop_id(tools, turn, no_broker_calls) -> None:
    runner, _ = turn(Platform.TELEGRAM)
    for args in ({}, {"drop_id": ""}, {"drop_id": None}, {"drop_id": 7}):
        result = tools.claim_private_input(args, runner=runner)
        assert result["error"] == "invalid_request", args
    assert no_broker_calls == []


def test_minutes_outside_one_to_sixty_is_refused_rather_than_clamped(
    tools, turn, no_broker_calls
) -> None:
    """The schema bounds it, but a schema is advisory to a model. Refusing keeps
    the broker's own ``maxTtlSeconds`` check from being the first line of
    defence, and never silently gives the user a different lifetime than the one
    the conversation agreed on."""
    runner, _ = turn(Platform.TELEGRAM)
    for minutes in (0, -5, 61, 10_000, "thirty", 1.5):
        result = tools.request_private_input({"minutes": minutes}, runner=runner)
        assert result["error"] == "invalid_request", minutes
    assert no_broker_calls == []


def test_a_purpose_that_is_a_url_or_an_essay_is_refused(tools, turn, no_broker_calls) -> None:
    """``purpose`` is a short label for the audit journal. A URL there is the one
    shape that could smuggle a capability into the durable record (§8.10), and an
    unbounded string is a runaway model, not a label."""
    runner, _ = turn(Platform.TELEGRAM)
    for bad in ("https://example.invalid/#cap", "x" * 500, 7):
        assert tools.request_private_input({"purpose": bad}, runner=runner)["error"] == (
            "invalid_request"
        )
    assert no_broker_calls == []


# ── the real operation, through the real worker-thread crossing ────────────


def test_request_posts_the_link_and_returns_a_non_secret_receipt(
    tools, turn, service_for, gateway_loop
) -> None:
    runner, adapter = turn(Platform.TELEGRAM, loop=gateway_loop)
    waiters = NullWaiters()

    result = tools.request_private_input(
        {"minutes": 10, "purpose": "deploy token"},
        runner=runner,
        service=service_for(waiters=waiters),
    )

    assert result["ok"] is True
    assert result["drop_id"] == "H" * 22
    assert result["state"] == "waiting"
    assert len(adapter.sent) == 1 and adapter.sent[0].chat_id == "chat-1"
    assert waiters.armed == ["H" * 22]

    blob = json.dumps(result)
    assert "://" not in blob and "#" not in blob


def test_minutes_reaches_the_broker_as_seconds(tools, turn, service_for, gateway_loop) -> None:
    runner, _ = turn(Platform.TELEGRAM, loop=gateway_loop)
    control = FakeControl()
    tools.request_private_input({"minutes": 7}, runner=runner, service=service_for(control))
    assert control.calls[0] == {"op": "create", "ttl_seconds": 420}


def test_claim_returns_the_payload_only_through_the_tool_result(
    tools, turn, service_for, gateway_loop, plugin, tmp_path
) -> None:
    import base64

    runner, _ = turn(Platform.TELEGRAM, loop=gateway_loop)
    control = FakeControl(
        claim_answer={
            "ok": True,
            "handoff_id": "H" * 22,
            "plaintext_b64": base64.b64encode(b"e2e-marker-8ad31f").decode("ascii"),
        }
    )
    service = service_for(control)
    tools.request_private_input({}, runner=runner, service=service)
    journal = plugin.drop.journal.DropJournal(root=tmp_path / "hermes-drop")
    journal.update("H" * 22, state="received")

    result = tools.claim_private_input({"drop_id": "H" * 22}, runner=runner, service=service)

    assert result["private_input"] == "e2e-marker-8ad31f"
    assert journal.get("H" * 22)["claimed_at"] is not None


def test_claiming_an_unknown_drop_is_uniformly_unavailable(
    tools, turn, service_for, gateway_loop
) -> None:
    runner, _ = turn(Platform.TELEGRAM, loop=gateway_loop)
    result = tools.claim_private_input({"drop_id": "Z" * 22}, runner=runner, service=service_for())
    assert result["error"] == "unavailable"
    assert "private_input" not in result


def test_a_gateway_with_no_loop_refuses_rather_than_blocking(
    tools, turn, service_for
) -> None:
    """``SyncBridge`` has nowhere to schedule the operation. Refusing is the whole
    point of the loop-identity and ``None``-future branches (``drop/bridge.py``)."""
    runner, adapter = turn(Platform.TELEGRAM)  # no gateway_loop
    result = tools.request_private_input({}, runner=runner, service=service_for())

    assert result["error"] == "gateway_unavailable"
    assert adapter.sent == []


# ── the registered handlers ────────────────────────────────────────────────


def test_the_registered_handler_returns_json_and_never_raises(plugin, turn) -> None:
    """``registry`` calls ``entry.handler(args, **kwargs)``
    (``tools/registry.py:692-694``) and the result is stringified into the
    conversation, so it has to be a string the model can parse."""
    turn(Platform.TELEGRAM)
    raw = plugin.request_private_input({})
    assert isinstance(raw, str)
    parsed = json.loads(raw)
    assert "error" in parsed


def test_the_registered_handler_tolerates_no_arguments_at_all(plugin, turn) -> None:
    turn(Platform.TELEGRAM)
    assert json.loads(plugin.request_private_input())["error"]
    assert json.loads(plugin.claim_private_input())["error"] == "invalid_request"


def test_handlers_swallow_internal_failures(plugin, monkeypatch, turn) -> None:
    """An exception escaping a slash-command handler is swallowed with a warning
    at ``gateway/run.py:14701-14702`` and execution **falls through to
    skill-command resolution** at ``:14705+`` — so a raise would silently become a
    ``/skill drop`` lookup, resurrecting the exact path this plan severs."""
    turn(Platform.TELEGRAM)

    def boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(plugin.drop.tools, "request_private_input", boom)
    parsed = json.loads(plugin.request_private_input({}))
    assert parsed["error"] == "internal_error"


def test_no_capability_or_payload_string_can_reach_a_tool_result(
    tools, turn, service_for, gateway_loop
) -> None:
    """§8.8: the capability appears exactly twice — the broker's ``create``
    response and the chat message. Never in a tool result.

    The sweep is over the *real* run now: the same capability string the broker
    returned and the messenger posted must be absent from what the model sees."""
    capability = "Q2FwYWJpbGl0eVN0cmluZ0FB"
    runner, adapter = turn(Platform.TELEGRAM, loop=gateway_loop)

    result = tools.request_private_input(
        {"purpose": "deploy token"}, runner=runner, service=service_for()
    )

    assert capability in adapter.sent[0].content, "the chat message is where it belongs"
    blob = json.dumps(result)
    assert capability not in blob
    assert "#" not in blob
    assert "http://" not in blob and "https://" not in blob
    assert re.search(r"[A-Za-z0-9_-]{22}", blob).group(0) == "H" * 22, (
        "the only 22-character token in the receipt is the non-secret handoff id"
    )

# ── L1: the tool path's refusal vocabulary ─────────────────────────────────
#
# ``command.py`` has had ``_SAFE_REASONS`` since S10, "because a refusal reaches a
# human in a chat message, so it says what happened and nothing else — never a
# ``detail`` string from the broker, an adapter or an exception, which can carry
# socket paths and internals". The tool path had no equivalent: ``post_status``
# builds ``detail`` from ``str(exc)`` or ``result.error``, ``DropService.create``
# returns it verbatim, and ``_as_tool_result`` puts it in the model's context — and
# from there in durable ``state.db``.
#
# §8.8's exact-string sweep in ``test_command.py`` could not see this: it sweeps
# the *command* path, and its "error paths" haystack is the two safe-reason
# messages, never a ``post_failed`` detail. So the leak is forced here.

LEAKY_DETAIL = "connect /run/handoff/control.sock: internal-broker.svc.local secret-in-body"


class LeakyMessenger:
    """An adapter-shaped failure whose error string carries internals.

    Not a strawman: Discord's ``send`` surfaces ``str(HTTPException)`` unredacted,
    and adapter error text is adapter-controlled — nothing in this repo governs
    what ends up in it.
    """

    async def post_status(self, origin, content):
        return {"error": "post_failed", "detail": LEAKY_DETAIL, "platform": origin.platform_name}

    async def update_status(self, origin, message_id, content):
        return {"ok": True, "message_id": message_id}


def test_a_forced_post_failed_detail_never_reaches_the_model(
    plugin, tools, turn, gateway_loop, tmp_path: Path
) -> None:
    """L1. The exact-string sweep the command path gets, on the tool path.

    Real journal, real ``create`` shape, real handler and real crossing; only the
    messenger fails, with a detail built to look like the ones that actually leak —
    a socket path and an internal hostname.
    """
    runner, adapter = turn(Platform.TELEGRAM, chat_id="tg-1", loop=gateway_loop)

    service = plugin.drop.service.DropService(
        journal=plugin.drop.journal.DropJournal(root=tmp_path / "leak"),
        messenger=LeakyMessenger(),
        control=FakeControl(),
        waiters=NullWaiters(),
    )

    result = tools.request_private_input({"minutes": 5}, runner=runner, service=service)

    assert result["error"] == "post_failed", result
    serialised = json.dumps(result)
    assert LEAKY_DETAIL not in serialised, f"the adapter detail reached the model: {serialised}"
    assert "/run/handoff" not in serialised, "a socket path reached the model"
    assert "internal-broker" not in serialised, "an internal hostname reached the model"
    # And it still says something useful, in the same words the chat path uses.
    assert result["detail"] == plugin.drop.safe_errors.SAFE_REASONS["post_failed"]


def test_the_outer_guard_does_not_return_an_exception_string(plugin, monkeypatch) -> None:
    """``_guarded``'s ``internal_error`` used to carry ``str(exc)`` straight out.

    Driven through the registered handler in the package root — the function core
    actually calls — because that is where the catch-all lives. The failure is
    induced where a real one would surface: inside the tools module the guard
    reaches for.
    """
    import types as _types

    broken = _types.SimpleNamespace()

    def _boom(*_a, **_k):
        raise RuntimeError(LEAKY_DETAIL)

    broken.request_private_input = _boom
    monkeypatch.setattr(plugin.drop, "tools", broken)

    raw = plugin.request_private_input({"minutes": 5})

    payload = json.loads(raw)
    assert payload["error"] == "internal_error"
    assert LEAKY_DETAIL not in raw, f"the exception string reached the model: {raw}"
    assert payload["detail"] == plugin.drop.safe_errors.SAFE_REASONS["internal_error"]


def test_locally_authored_details_are_still_forwarded(tools, turn) -> None:
    """Sanitising must not blind the model to its own mistake.

    ``"minutes must be between 1 and 60, got 90"`` is authored in this package,
    contains no foreign string, and is the difference between a model that corrects
    itself and one that retries the same call. A blanket scrub would be a
    regression dressed as a hardening.
    """
    runner, _adapter = turn(Platform.TELEGRAM, chat_id="tg-1")
    result = tools.request_private_input({"minutes": 90}, runner=runner)

    assert result["error"] == "invalid_request"
    assert "90" in result["detail"], result
    assert "between 1 and 60" in result["detail"]


def test_an_unknown_error_code_has_its_detail_replaced(plugin) -> None:
    """Fail closed: a code nobody has reviewed is a code whose detail is unknown."""
    sanitize = plugin.drop.safe_errors.sanitize_tool_result
    out = sanitize({"error": "brand_new_failure", "detail": LEAKY_DETAIL})

    assert out["error"] == "brand_new_failure"
    assert LEAKY_DETAIL not in json.dumps(out)
    assert out["detail"] == plugin.drop.safe_errors.DEFAULT_REASON


def test_sanitizing_never_touches_a_successful_result(plugin) -> None:
    """The claim result is the one place a payload belongs, and it must survive."""
    sanitize = plugin.drop.safe_errors.sanitize_tool_result
    success = {"ok": True, "drop_id": "Z" * 22, "private_input": "s3cret-value"}
    assert sanitize(success) == success

    receipt = {"ok": True, "drop_id": "Z" * 22, "state": "waiting", "note": "…", "purpose": "p"}
    assert sanitize(receipt) == receipt


def test_the_two_entry_points_share_one_refusal_table(plugin) -> None:
    """Two copies of this vocabulary would drift, and the drift would be silent."""
    import importlib

    # ``drop.command`` is imported lazily on the dispatch path, so it may not be an
    # attribute of the package yet in a process that has only used the tools.
    command = importlib.import_module(plugin.drop.__name__ + ".command")

    assert command._SAFE_REASONS is plugin.drop.safe_errors.SAFE_REASONS
    assert command._DEFAULT_REASON == plugin.drop.safe_errors.DEFAULT_REASON


def test_a_broker_unavailable_detail_is_replaced_on_the_tool_path(
    plugin, tools, turn, gateway_loop, tmp_path: Path
) -> None:
    """The other foreign-detail source: the control client's own transport text.

    ``control_request`` builds ``detail`` from the socket path and the OS error, so
    ``broker_unavailable`` names ``/run/handoff/control.sock`` by construction.
    Useful in ``agent.log``; not something to hand the model.
    """
    runner, _adapter = turn(Platform.TELEGRAM, chat_id="tg-1", loop=gateway_loop)

    class RefusingControl:
        async def create(self, **kw):
            return {
                "ok": False,
                "error": "broker_unavailable",
                "detail": "/run/handoff/control.sock not accepting connections: ECONNREFUSED",
            }

    service = plugin.drop.service.DropService(
        journal=plugin.drop.journal.DropJournal(root=tmp_path / "j2"),
        control=RefusingControl(),
        waiters=NullWaiters(),
    )

    result = tools.request_private_input({"minutes": 5}, runner=runner, service=service)
    assert result["error"] == "broker_unavailable"
    assert "/run/handoff" not in json.dumps(result), result
    assert result["detail"] == plugin.drop.safe_errors.SAFE_REASONS["broker_unavailable"]


# ── L3: the platform gate inside create ────────────────────────────────────


def test_create_refuses_an_unsupported_platform_on_its_own(plugin, tmp_path: Path) -> None:
    """L3. §7.3's "refuse before creating anything" as a property of ``create``.

    Both existing callers gate first, so this is unreachable through them — which
    was the finding: the invariant depended on every caller remembering, and an
    unsupported platform falls through ``renderer_for`` to ``"plain"``, a value the
    broker *accepts* (``src/control-server.js:17``). So a third caller would have
    posted to an unverified platform silently. ``create`` is called directly here,
    exactly as that third caller would.
    """
    import asyncio as _asyncio

    minted: list = []

    class CountingControl:
        async def create(self, **kw):
            minted.append(kw)
            return {"ok": True, "handoff_id": "Q" * 22}

    adapter = StubAdapter(Platform.SLACK)
    runner = StubRunner({Platform.SLACK: adapter})
    source = adapter.build_source(chat_id="C-1", chat_type="channel", user_id="U-1")
    origin = plugin.drop.origin.Origin(
        source=source,
        adapter=adapter,
        runner=runner,
        routing_tuple=plugin.drop.sources.routing_tuple_for_source(source),
        reply_anchor=None,
        tier="routing_tuple",
    )

    service = plugin.drop.service.DropService(
        journal=plugin.drop.journal.DropJournal(root=tmp_path / "gate"),
        control=CountingControl(),
        waiters=NullWaiters(),
    )

    result = _asyncio.run(service.create(origin, ttl_seconds=600))

    assert result == {"error": "platform_unsupported", "platform": "slack"}
    assert minted == [], "an unsupported platform consumed a handoff on its way to a refusal"
    assert adapter.sent == [], "and nothing was posted to it"


def test_create_still_serves_both_verified_platforms(plugin, tmp_path: Path) -> None:
    """The gate must not be a blanket refusal — a guard that refuses everything
    passes the test above and breaks the product."""
    import asyncio as _asyncio

    for platform in (Platform.TELEGRAM, Platform.DISCORD):
        adapter = StubAdapter(platform)
        runner = StubRunner({platform: adapter})
        source = adapter.build_source(chat_id="c-1", chat_type="dm", user_id="u-1")
        origin = plugin.drop.origin.Origin(
            source=source,
            adapter=adapter,
            runner=runner,
            routing_tuple=plugin.drop.sources.routing_tuple_for_source(source),
            reply_anchor=None,
            tier="routing_tuple",
        )
        service = plugin.drop.service.DropService(
            journal=plugin.drop.journal.DropJournal(root=tmp_path / f"ok-{platform.value}"),
            control=FakeControl(),
            waiters=NullWaiters(),
        )
        result = _asyncio.run(service.create(origin, ttl_seconds=600))
        assert result.get("ok") is True, (platform, result)


# ── L4: the shutdown hooks that have no caller ─────────────────────────────


def test_no_gateway_lifecycle_hook_exists_to_wire_shutdown_to() -> None:
    """L4, pinned rather than papered over.

    ``WaiterRegistry.shutdown`` and ``reconciler.request_shutdown`` have no
    production caller, and the honest reason is that core offers nowhere to call
    them from: ``VALID_HOOKS`` has no plugin-teardown, plugin-unload or
    gateway-shutdown entry, and the session hooks it does have fire per *agent
    session* — calling shutdown from one would stop Drop's poller and cancel every
    live waiter because some unrelated conversation ended.

    This test is the tripwire. If core gains a real lifecycle hook it fails, and
    whoever sees it should wire the two functions up and correct §7.1. Until then
    the docstrings say "no caller, and here is why" rather than implying one.
    """
    from hermes_cli.plugins import VALID_HOOKS

    lifecycle = {
        name
        for name in VALID_HOOKS
        if ("shutdown" in name or "teardown" in name or "unload" in name)
        or name in {"on_gateway_stop", "on_gateway_ready", "post_gateway_dispatch"}
    }
    assert lifecycle == set(), (
        f"core now offers {sorted(lifecycle)} — wire WaiterRegistry.shutdown and "
        "reconciler.request_shutdown to it and update §7.1"
    )

    # And the session hooks that do exist are not substitutes: they fire per agent
    # session, not per process.
    assert {"on_session_end", "on_session_finalize"} <= VALID_HOOKS
