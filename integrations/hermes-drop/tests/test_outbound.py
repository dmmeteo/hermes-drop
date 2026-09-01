"""The outbound adapter: Hermes → the user, through the origin conversation.

The direction reverses, so what has to be proved reverses with it. Inbound, the
question was "did the *request* for a secret reach the right conversation, and did
the plaintext reach only the model". Outbound, the plaintext starts on this side and
the questions are:

* **Where does the link go?** Only to the resolved origin's own chat id. There is no
  destination field on the schema and no expression in this path that produces a chat
  id other than ``origin.source.chat_id``. A misrouted inbound drop asks a stranger
  for a password; a misrouted outbound one hands them one.
* **What leaves this process?** A link, a code and a fixed sentence, in the chat
  message. Not a value, not a label, not a title — the notice is Markdown going to a
  platform that renders links, and a model-composed title would forge one.
* **What comes back to the model?** Labels, a deadline, a drop id, a note. No value,
  no code, no URL.
* **What is written down?** Nothing. No journal entry and no waiter, deliberately —
  there is no submission to wait for and no later claim to authorise.
* **What survives a failure?** A refusal before the broker is touched mints nothing.
  A failed post aborts, and the minted drop lapses at its TTL rather than being
  posted twice or minted again.

The last two tests boot the real Node broker, so the payload this side builds is
minted by the real store and read back by the real browser client.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path

import pytest
from gateway.config import Platform

from _stubs import StubAdapter, StubRunner, bind_session_context
from conftest import load_plugin_package

REPO_ROOT = Path(__file__).resolve().parents[3]

CANON = [
    {"label": "Login", "type": "text", "value": "ops@example.test"},
    {"label": "Password", "type": "secret", "value": "example-not-a-real-secret-xyzzy"},
    {"label": "Console", "type": "url", "value": "https://openrouter.test/keys"},
]


@pytest.fixture
def plugin():
    return load_plugin_package()


@pytest.fixture
def lane(plugin):
    """A resolved origin for one platform, plus the adapter that records its sends."""

    def _make(platform: Platform = Platform.TELEGRAM, chat_id: str = "tg-1", **kw):
        thread_id = kw.pop("thread_id", "")
        adapter = StubAdapter(platform, **kw)
        runner = StubRunner({platform: adapter})
        source = adapter.build_source(
            chat_id=chat_id, chat_type="dm", user_id="u-1", thread_id=thread_id
        )
        plugin.drop.sources.REGISTRY.put(source, gateway=runner, session_key="s")
        origin = plugin.drop.origin.Origin(
            source=source,
            adapter=adapter,
            runner=runner,
            routing_tuple=plugin.drop.sources.routing_tuple_for_source(source),
            reply_anchor=None,
            tier="turn_contextvar",
        )
        return origin, adapter

    return _make


class FakeControl:
    """The broker's outbound answers, without the broker.

    The real one is booted at the bottom of this file; here the subject is the
    workflow and the ordering, which a real broker would only make slower to drive.
    """

    def __init__(self, *, answer=None, notice="🔐 the notice"):
        self.answer = answer
        self.notice = notice
        self.calls: list = []

    async def create_outbound_drop(
        self, *, payload_json, ttl_seconds=None, notice_platform=None, socket_path=None, timeout=None
    ):
        self.calls.append(
            {
                "payload_json": payload_json,
                "ttl_seconds": ttl_seconds,
                "notice_platform": notice_platform,
            }
        )
        if self.answer is not None:
            return self.answer
        expires = int(time.time() * 1000) + (ttl_seconds or 1800) * 1000
        return {
            "ok": True,
            "drop_id": "D" * 22,
            "url": "http://127.0.0.1:8080/#r." + "c" * 22 + "." + "k" * 43,
            "code": "071",
            "code_length": 3,
            "max_code_attempts": 3,
            "expires_at": expires,
            "ttl_seconds": ttl_seconds or 1800,
            "protocol_version": 2,
            "outbound_protocol": 1,
            "payload_format": "structured",
            "field_count": len(json.loads(payload_json)["fields"]),
            "notice": self.notice,
        }


def service_for(plugin, control, *, journal_root: Path):
    return plugin.drop.service.DropService(
        journal=plugin.drop.journal.DropJournal(root=journal_root),
        control=control,
        clock=lambda: 1_000_000.0,
    )


# ── the workflow ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_it_posts_one_message_to_the_origin_lane_and_nowhere_else(
    plugin, lane, tmp_path
) -> None:
    origin, adapter = lane(Platform.TELEGRAM, "tg-42")
    other = StubAdapter(Platform.DISCORD)
    control = FakeControl()
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    result = await service.send_outbound(origin, fields=CANON, title="Access", ttl_seconds=1800)

    assert result["ok"] is True
    assert len(adapter.sent) == 1, "one message, and it is never edited afterwards"
    assert adapter.sent[0].chat_id == "tg-42", "the origin's own chat id"
    assert adapter.sent[0].content == control.notice
    assert other.sent == [], "and nothing anywhere else"
    assert adapter.edited == [], "an outbound notice has no second state to be edited into"


@pytest.mark.asyncio
async def test_the_receipt_carries_labels_and_never_a_value_a_code_or_a_url(
    plugin, lane, tmp_path
) -> None:
    origin, _adapter = lane()
    control = FakeControl()
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    result = await service.send_outbound(origin, fields=CANON, ttl_seconds=1800)

    assert result["labels"] == ["Login", "Password", "Console"]
    assert result["state"] == "delivered"
    assert result["drop_id"] == "D" * 22
    assert result["generated_values"] == 0
    assert result["expires_in_seconds"] > 0

    serialized = json.dumps(result)
    for forbidden in ["xyzzy", "ops@example.test", "openrouter.test", "071", "http://", "#r."]:
        assert forbidden not in serialized, f"{forbidden} must not reach the model"
    # And the note tells the model the one thing it would otherwise get wrong.
    assert "Do NOT repeat the values in chat" in result["note"]


@pytest.mark.asyncio
async def test_nothing_durable_is_written_and_no_waiter_is_armed(plugin, lane, tmp_path) -> None:
    """Deliberate, not unfinished — see ``send_outbound``'s docstring."""
    origin, _adapter = lane()
    journal_root = tmp_path / "j"
    control = FakeControl()
    service = service_for(plugin, control, journal_root=journal_root)

    result = await service.send_outbound(origin, fields=CANON, ttl_seconds=1800)
    assert result["ok"] is True

    journal = plugin.drop.journal.DropJournal(root=journal_root)
    assert journal.get("D" * 22) is None, "an outbound drop is not a journalled handoff"
    assert journal.terminal_unannounced(origin.routing_tuple) == []
    assert plugin.drop.waiter.REGISTRY.is_armed("D" * 22) is False


@pytest.mark.asyncio
async def test_the_payload_reaches_the_broker_as_structured_json(plugin, lane, tmp_path) -> None:
    origin, _adapter = lane(Platform.DISCORD, "dc-1")
    control = FakeControl()
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    await service.send_outbound(origin, fields=CANON, title="Access", ttl_seconds=600)

    call = control.calls[0]
    assert call["ttl_seconds"] == 600
    assert call["notice_platform"] == "discord", "the renderer for the origin's platform"
    payload = json.loads(call["payload_json"])
    assert payload["v"] == 1
    assert payload["title"] == "Access"
    assert [field["label"] for field in payload["fields"]] == ["Login", "Password", "Console"]
    assert [field["type"] for field in payload["fields"]] == ["text", "secret", "url"]


@pytest.mark.asyncio
async def test_a_generated_field_is_asked_for_rather_than_sent(plugin, lane, tmp_path) -> None:
    origin, _adapter = lane()
    control = FakeControl()
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    result = await service.send_outbound(
        origin,
        fields=[
            {"label": "Login", "type": "text", "value": "ops@example.test"},
            {"label": "Password", "type": "secret", "generate": {"length": 32}},
        ],
        ttl_seconds=1800,
    )

    assert result["ok"] is True
    assert result["generated_values"] == 1
    payload = json.loads(control.calls[0]["payload_json"])
    # The whole point: no value on the wire, so none in a tool argument, a model turn
    # or a durable transcript either.
    assert "value" not in payload["fields"][1]
    assert payload["fields"][1]["generate"] == {"kind": "password", "length": 32}


# ── the refusals ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_unsupported_platform_is_refused_before_anything_is_built(
    plugin, lane, tmp_path
) -> None:
    origin, adapter = lane(Platform.SLACK, "sl-1")
    control = FakeControl()
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    result = await service.send_outbound(origin, fields=CANON, ttl_seconds=1800)

    assert result == {"error": "platform_unsupported", "platform": "slack"}
    assert control.calls == [], "nothing was minted"
    assert adapter.sent == [], "and nothing was posted"


@pytest.mark.asyncio
async def test_a_bad_payload_is_refused_without_touching_the_broker(
    plugin, lane, tmp_path
) -> None:
    origin, adapter = lane()
    control = FakeControl()
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    result = await service.send_outbound(
        origin,
        fields=[{"label": "Password", "value": "example-not-a-real-secret-xyzzy "}],
        ttl_seconds=1800,
    )

    assert result["error"] == "invalid_request"
    assert "bad_value" in result["detail"]
    # The rule, and never the value it was broken by.
    assert "xyzzy" not in json.dumps(result)
    assert control.calls == []
    assert adapter.sent == []


@pytest.mark.asyncio
async def test_a_broker_reason_is_reported_as_drift_and_still_told_to_the_model(
    plugin, lane, tmp_path, caplog
) -> None:
    """The broker refused what this side accepted: the two schemas have drifted.

    An operator has to hear about it in those words, because it is a real defect —
    and the model still gets the rule, because the rule is the only thing it can act
    on.
    """
    origin, adapter = lane()
    control = FakeControl(answer={"ok": False, "error": "invalid_request", "reason": "bad_label"})
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    with caplog.at_level(logging.ERROR):
        result = await service.send_outbound(origin, fields=CANON, ttl_seconds=1800)

    assert result["error"] == "invalid_request"
    assert "bad_label" in result["detail"]
    assert "drifted" in caplog.text
    assert adapter.sent == []


@pytest.mark.asyncio
async def test_a_broker_that_cannot_hand_a_secret_out_is_refused_before_the_post(
    plugin, lane, tmp_path, caplog
) -> None:
    origin, adapter = lane()
    # A broker that minted the drop but advertises no outbound revision, and one that
    # answered without the notice the link and the code live in. Both are refused
    # before the post, because a link posted against unknown one-shot guarantees is a
    # secret with no stated lifetime.
    for answer in [
        {
            "ok": True,
            "drop_id": "D" * 22,
            "url": "http://x/#r",
            "code": "001",
            "expires_at": 0,
            "notice": "n",
        },
        {
            "ok": True,
            "drop_id": "D" * 22,
            "url": "http://x/#r",
            "code": "001",
            "expires_at": 0,
            "outbound_protocol": 1,
        },
    ]:
        control = FakeControl(answer=answer)
        service = service_for(plugin, control, journal_root=tmp_path / "j")
        with caplog.at_level(logging.ERROR):
            result = await service.send_outbound(origin, fields=CANON, ttl_seconds=1800)
        assert result == {"error": "outbound_unsupported"}, answer
        assert adapter.sent == [], "nothing was posted"


@pytest.mark.asyncio
async def test_an_unreachable_broker_is_a_refusal_and_not_a_delivery(
    plugin, lane, tmp_path
) -> None:
    origin, adapter = lane()
    control = FakeControl(
        answer={"ok": False, "error": "broker_unavailable", "detail": "/run/x.sock not there"}
    )
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    result = await service.send_outbound(origin, fields=CANON, ttl_seconds=1800)

    assert result["error"] == "broker_unavailable"
    assert adapter.sent == []


@pytest.mark.asyncio
async def test_a_failed_post_aborts_and_does_not_post_or_mint_twice(
    plugin, lane, tmp_path
) -> None:
    origin, adapter = lane(send_ok=False)
    control = FakeControl()
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    result = await service.send_outbound(origin, fields=CANON, ttl_seconds=1800)

    assert result["error"] == "post_failed"
    assert len(control.calls) == 1, "one mint, never a second for the same secret"
    assert len(adapter.sent) == 1, "one attempt, never a retry into the conversation"
    # The drop lapses at its TTL, unseen — there is no destroy op. Stated in
    # ``send_outbound``'s docstring and accepted for this slice.


@pytest.mark.asyncio
async def test_no_value_label_title_or_code_reaches_a_log_line(
    plugin, lane, tmp_path, caplog
) -> None:
    origin, _adapter = lane()
    control = FakeControl()
    service = service_for(plugin, control, journal_root=tmp_path / "j")

    with caplog.at_level(logging.DEBUG):
        await service.send_outbound(
            origin,
            fields=[{"label": "Label xyzzy", "type": "secret", "value": "value-xyzzy"}],
            title="Title xyzzy",
            ttl_seconds=1800,
        )
        # ...and on the failure path, which is the one most likely to explain itself
        # by quoting what it was given.
        failing, _ = lane(send_ok=False, chat_id="tg-9")
        await service.send_outbound(
            failing,
            fields=[{"label": "Label xyzzy", "type": "secret", "value": "value-xyzzy"}],
            ttl_seconds=1800,
        )

    assert "xyzzy" not in caplog.text, caplog.text
    assert "071" not in caplog.text, "and never the code"


# ── the tool handler ───────────────────────────────────────────────────────


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


class RecordingService:
    def __init__(self):
        self.calls: list = []

    async def send_outbound(self, origin, *, fields, title, ttl_seconds):
        self.calls.append(
            {
                "fields": fields,
                "title": title,
                "ttl_seconds": ttl_seconds,
                "routing_tuple": origin.routing_tuple,
            }
        )
        return {"ok": True, "state": "delivered", "labels": [f["label"] for f in fields]}


class DirectBridge:
    """Runs the coroutine here. The worker-thread crossing itself is proved in
    ``test_bridge.py``; this file's subject is the handler's gates."""

    def run(self, coro, timeout=None):
        import asyncio

        return asyncio.new_event_loop().run_until_complete(coro)


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ({}, "fields is required"),
        ({"fields": CANON, "minutes": 0}, "minutes must be between"),
        ({"fields": CANON, "minutes": 61}, "minutes must be between"),
        ({"fields": CANON, "minutes": True}, "minutes must be a whole number"),
        ({"fields": CANON, "minutes": "30"}, "minutes must be a whole number"),
    ],
)
def test_the_tool_refuses_bad_arguments_before_resolving_anything(
    plugin, turn, args, expected
) -> None:
    turn(Platform.TELEGRAM, "tg-1")
    service = RecordingService()
    result = plugin.drop.tools.send_private_output(args, service=service, bridge=DirectBridge())
    assert result["error"] == "invalid_request"
    assert expected in result["detail"]
    assert service.calls == []


def test_the_tool_defaults_to_thirty_minutes_and_passes_the_origin_through(
    plugin, turn
) -> None:
    runner, _adapter = turn(Platform.TELEGRAM, "tg-1")
    service = RecordingService()

    result = plugin.drop.tools.send_private_output(
        {"fields": CANON, "title": "Access"}, runner=runner, service=service, bridge=DirectBridge()
    )

    assert result["ok"] is True
    assert service.calls[0]["ttl_seconds"] == 30 * 60
    assert service.calls[0]["title"] == "Access"
    assert service.calls[0]["routing_tuple"] == ("telegram", "", "tg-1", "")


def test_the_tool_refuses_an_unsupported_platform_by_name(plugin, turn) -> None:
    runner, _adapter = turn(Platform.SLACK, "sl-1")
    service = RecordingService()

    result = plugin.drop.tools.send_private_output(
        {"fields": CANON}, runner=runner, service=service, bridge=DirectBridge()
    )

    assert result == {"error": "platform_unsupported", "platform": "slack"}
    assert service.calls == []


def test_the_tool_refuses_with_no_verified_origin_rather_than_guessing_one(plugin) -> None:
    """No captured source and no bound context: fail closed, never a default lane."""
    service = RecordingService()
    result = plugin.drop.tools.send_private_output(
        {"fields": CANON}, service=service, bridge=DirectBridge()
    )
    assert "error" in result
    assert result["error"] in {"no_origin", "origin_unverified", "gateway_unavailable", "no_adapter"}
    assert service.calls == []


# ── the schema and the registration ────────────────────────────────────────


def test_the_schema_names_no_destination_and_takes_only_the_three_arguments(plugin) -> None:
    schema = plugin.drop.schemas.SEND_PRIVATE_OUTPUT
    assert set(schema["parameters"]["properties"]) == {"fields", "title", "minutes"}
    assert schema["parameters"]["required"] == ["fields"]

    # The recursive walk test_schemas.py runs, applied to the field shape as well:
    # nothing anywhere in this schema may be a destination.
    def walk(node, path="$"):
        if isinstance(node, dict):
            for key, value in node.items():
                yield f"{path}.{key}", key
                yield from walk(value, f"{path}.{key}")
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                yield from walk(value, f"{path}[{index}]")
        else:
            yield path, node

    for path, value in walk(schema):
        if not isinstance(value, str) or path.endswith((".description", ".name")):
            continue
        assert value not in plugin.drop.schemas.FORBIDDEN_DESTINATION_FIELDS, (path, value)


def test_the_schema_bounds_match_what_the_payload_builder_enforces(plugin) -> None:
    """A schema is advisory to a model, so it must not promise more than the
    validator allows — a model told 64 fields are fine would meet a refusal."""
    schema = plugin.drop.schemas.SEND_PRIVATE_OUTPUT["parameters"]["properties"]
    payload = plugin.drop.outbound_payload

    assert schema["fields"]["maxItems"] == payload.MAX_FIELDS
    assert schema["fields"]["minItems"] == 1
    items = schema["fields"]["items"]["properties"]
    assert items["label"]["maxLength"] == payload.MAX_LABEL_CHARS
    assert items["value"]["maxLength"] == payload.MAX_VALUE_BYTES
    assert items["type"]["enum"] == list(payload.FIELD_TYPES)
    assert items["generate"]["properties"]["kind"]["enum"] == list(payload.GENERATE_KINDS)
    assert items["generate"]["properties"]["length"]["minimum"] == payload.MIN_GENERATE_LENGTH
    assert items["generate"]["properties"]["length"]["maximum"] == payload.MAX_GENERATE_LENGTH
    assert schema["title"]["maxLength"] == payload.MAX_TITLE_CHARS


def test_the_description_tells_the_model_the_two_things_it_must_not_do(plugin) -> None:
    description = plugin.drop.schemas.SEND_PRIVATE_OUTPUT["description"]
    assert "instead of writing it in the chat" in description
    assert "never repeat the values in chat" in description
    assert "cannot choose where the link goes" in description


def test_the_plugin_registers_the_third_tool_and_still_no_send_message(plugin) -> None:
    registered: list = []

    class Ctx:
        class manifest:
            name = "hermes-drop"
            key = "hermes-drop"
            source = "user"

        def register_tool(self, name, **kwargs):
            registered.append(name)

        def register_hook(self, hook_name, callback):
            pass

        def register_command(self, name, handler, description="", args_hint=""):
            registered.append(f"/{name}")

    plugin.register(Ctx())
    assert sorted(registered) == [
        "claim_private_input",
        "request_private_input",
        "send_private_output",
    ]
    assert not any("send_message" in name for name in registered)


def test_the_manifest_lists_what_register_registers(plugin) -> None:
    """``plugin.yaml``'s tool list is kept in step by hand, so it is asserted."""
    manifest = (REPO_ROOT / "integrations" / "hermes-drop" / "plugin.yaml").read_text("utf-8")
    for name in ["request_private_input", "claim_private_input", "send_private_output"]:
        assert f"- {name}" in manifest


def test_the_guarded_handler_returns_a_json_string_with_no_value_in_it(plugin, turn) -> None:
    """The entry point core actually calls, including the vault and safe-error seams.

    Driven through an *argument* refusal because that is the one that lands before
    origin resolution: the bare handler resolves its own runner, and there is no live
    gateway in this process to resolve one from. What is being proved is the wrapper —
    a JSON string, a sanitized error, and no argument value in it — not the workflow,
    which the service tests above drive directly.
    """
    turn(Platform.TELEGRAM, "tg-1")

    raw = plugin.send_private_output({"fields": CANON, "minutes": 0}, session_id="sess-1")
    result = json.loads(raw)
    assert result["error"] == "invalid_request"
    assert "minutes must be between" in result["detail"]
    # The arguments carried a secret and the result does not echo one back.
    assert "xyzzy" not in raw
    assert "ops@example.test" not in raw

    # ...and a handler with no verified origin fails closed rather than guessing a lane.
    closed = json.loads(plugin.send_private_output({"fields": CANON}, session_id="sess-1"))
    assert closed["error"] in {
        "no_origin",
        "origin_unverified",
        "gateway_unavailable",
        "no_adapter",
    }


# ── against the real broker ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_whole_outbound_path_against_the_real_broker(
    plugin, lane, tmp_path, real_public_broker
) -> None:
    """Build, mint, post, then reveal the way the browser does.

    No fake anywhere in the middle: the real payload builder, the real control client,
    the real Node broker and store, the real reveal client. What is proved is the one
    thing a stub cannot — that the credential a model handed this tool is the
    credential the page shows, and that the message posted into the conversation is
    enough on its own to get there.
    """
    origin, adapter = lane(Platform.TELEGRAM, "tg-real")
    service = plugin.drop.service.DropService(
        journal=plugin.drop.journal.DropJournal(root=tmp_path / "j"),
        socket_path=real_public_broker.socket_path,
    )

    result = await service.send_outbound(
        origin,
        fields=[
            {"label": "Login", "type": "text", "value": "ops@example.test"},
            {"label": "Password", "type": "secret", "value": "example-not-a-real-secret-xyzzy"},
            {"label": "Fresh key", "type": "secret", "generate": {"kind": "hex", "length": 32}},
        ],
        title="Real access",
        ttl_seconds=120,
    )

    assert result["ok"] is True, result
    assert result["labels"] == ["Login", "Password", "Fresh key"]
    assert result["generated_values"] == 1

    # Exactly one message, into the origin's own chat, and it carries the link and a
    # 3-digit code and no value.
    assert len(adapter.sent) == 1
    notice = adapter.sent[0].content
    assert adapter.sent[0].chat_id == "tg-real"
    assert "xyzzy" not in notice
    assert "ops@example.test" not in notice
    assert "expires in 2 min." in notice.lower()

    url = next(part for part in notice.split() if "#r." in part).strip("()[]")
    code = json.loads(_reveal(url, _code_from(notice), real_public_broker.base_url))
    assert code["status"] == "revealed"

    payload = json.loads(code["plaintext"])
    assert payload["title"] == "Real access"
    by_label = {field["label"]: field for field in payload["fields"]}
    assert by_label["Password"]["value"] == "example-not-a-real-secret-xyzzy"
    assert by_label["Login"]["type"] == "text"
    # The generated value exists, is the right shape, and was never in this process.
    assert len(by_label["Fresh key"]["value"]) == 32
    assert all(char in "0123456789abcdef" for char in by_label["Fresh key"]["value"])

    # ...and the drop is spent: a second reveal with the same code is refused.
    again = json.loads(_reveal(url, _code_from(notice), real_public_broker.base_url))
    assert again["status"] == "unavailable"


def _code_from(notice: str) -> str:
    import re

    match = re.search(r"`(\d{3})`", notice) or re.search(r"Code: (\d{3})", notice)
    assert match, notice
    return match.group(1)


def _reveal(url: str, code: str, origin: str) -> str:
    """Reveal through the repo's own browser client, in node.

    Hand-rolling AES-GCM here would test the test. Arguments go through the
    environment because ``node -e`` puts no script path in ``process.argv``.
    """
    script = (
        "const {revealSecret}=await import('./src/client/reveal-client.js');"
        "const {parseOutboundFragment}=await import('./src/outbound-envelope.js');"
        "const url=process.env.DROP_URL;"
        "const parsed=parseOutboundFragment(url.slice(url.indexOf('#')+1));"
        "if(!parsed)throw new Error('unparseable fragment: '+url);"
        "const out=await revealSecret({...parsed,code:process.env.DROP_CODE,"
        "origin:process.env.DROP_ORIGIN});"
        "process.stdout.write(JSON.stringify(out));"
    )
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=str(REPO_ROOT),
        env={**os.environ, "DROP_URL": url, "DROP_CODE": code, "DROP_ORIGIN": origin},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout
