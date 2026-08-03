"""S5 — the async-native messenger.

Two asymmetries drive every test here, and both are properties of the real
adapter ABC rather than choices this code made:

* ``send`` **takes** ``metadata``. It is in the ABC
  (``gateway/platforms/base.py:3477-3496``), and it is what carries thread/topic
  routing — Telegram DM topics, Slack ``team_id`` — derived from the *real*
  source by ``_thread_metadata_for_source`` (``:66-97``).

* ``edit_message`` **does not**. The ABC signature is
  ``(chat_id, message_id, content, *, finalize=False)`` (``:3533-3540``), and
  ``metadata=`` exists on only three of nine adapters (discord, telegram, slack);
  it is absent on matrix, mattermost, whatsapp, google_chat, dingtalk and feishu.
  Passing it there is a ``TypeError`` — a crash, not a degradation. Revision 1 of
  the plan got this wrong, and the retraction is why the ``expected`` rendering
  tier was cut.

``StubAdapter.edit_message`` therefore has no ``metadata`` parameter either, so
the mistake fails here before it can fail in production.

Everything is ``await``-ed directly. There is no blocking call on the gateway
loop anywhere in Drop (plan §7.1); the one worker-thread crossing lives in
``bridge.py`` and is tested separately.
"""

from __future__ import annotations

import inspect
import sys

import pytest
from gateway.config import Platform

from _stubs import StubAdapter, StubRunner, bind_session_context
from conftest import load_plugin_package


@pytest.fixture
def plugin():
    return load_plugin_package()


@pytest.fixture
def messenger(plugin):
    return plugin.drop.messenger.OriginMessenger()


@pytest.fixture
def origin_for():
    """Build a verified ``Origin`` for a platform, with the real provenance."""
    from gateway.session_context import clear_session_vars

    tokens: list = []
    plugin = load_plugin_package()

    def _make(platform: Platform, **source_kwargs):
        adapter = StubAdapter(platform, **source_kwargs.pop("adapter_kwargs", {}))
        others = source_kwargs.pop("other_adapters", {})
        adapters = {platform: adapter}
        adapters.update(others)
        runner = StubRunner(adapters)
        source = adapter.build_source(**source_kwargs)
        plugin.drop.sources.capture(event=_Event(source), gateway=runner, session_key="s")
        tokens.extend(
            bind_session_context(
                platform=platform.value,
                chat_id=str(source_kwargs["chat_id"]),
                thread_id=str(source_kwargs.get("thread_id") or ""),
                session_key="s",
                message_id=str(source_kwargs.get("message_id") or ""),
            )
        )
        origin = plugin.drop.origin.resolve_origin(runner=runner)
        assert not isinstance(origin, dict), origin
        return origin, adapter, others

    yield _make
    if tokens:
        clear_session_vars(tokens)


class _Event:
    def __init__(self, source):
        self.source = source


# ── the destination ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_goes_to_the_origin_chat_and_nowhere_else(origin_for, messenger) -> None:
    other = StubAdapter(Platform.DISCORD)
    origin, adapter, others = origin_for(
        Platform.TELEGRAM,
        chat_id="tg-1",
        chat_type="dm",
        user_id="u",
        other_adapters={Platform.DISCORD: other},
    )

    result = await messenger.send(origin, "the link")

    assert result.success is True
    assert [(m.chat_id, m.content) for m in adapter.sent] == [("tg-1", "the link")]
    assert other.sent == []


@pytest.mark.asyncio
async def test_chat_id_is_only_ever_the_origin_source_chat_id(origin_for, messenger) -> None:
    """§7.2. There is no other expression that can produce a chat id in Drop."""
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u"
    )
    await messenger.send(origin, "x")
    assert adapter.sent[0].chat_id == origin.source.chat_id


# ── metadata: on send, never on edit ───────────────────────────────────────


@pytest.mark.asyncio
async def test_send_carries_thread_metadata(origin_for, messenger) -> None:
    origin, adapter, _ = origin_for(
        Platform.DISCORD,
        chat_id="c-1",
        chat_type="thread",
        user_id="u",
        thread_id="t-1",
        scope_id="g-1",
    )
    await messenger.send(origin, "x")
    assert adapter.sent[0].metadata == {"thread_id": "t-1"}


@pytest.mark.asyncio
async def test_telegram_dm_topic_metadata_is_present(origin_for, messenger) -> None:
    """The Telegram DM-topic lane needs ``direct_messages_topic_id`` plus a reply
    anchor (``gateway/platforms/base.py:88-96``). Both come off the real source."""
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM,
        chat_id="tg-1",
        chat_type="dm",
        user_id="u",
        thread_id="5",
        message_id="m-42",
    )
    await messenger.send(origin, "x")

    metadata = adapter.sent[0].metadata
    assert metadata["thread_id"] == "5"
    assert metadata["direct_messages_topic_id"] == "5"
    assert metadata["telegram_dm_topic_reply_fallback"] is True
    assert metadata["telegram_reply_to_message_id"] == "m-42"


@pytest.mark.asyncio
async def test_slack_team_id_comes_from_the_real_sources_scope_id(origin_for, messenger) -> None:
    """``scope_id`` is one of the fields ``_set_session_env`` drops, so this only
    works because the real source was kept rather than rebuilt."""
    origin, adapter, _ = origin_for(
        Platform.SLACK,
        chat_id="C1",
        chat_type="channel",
        user_id="U1",
        thread_id="1712.5",
        scope_id="T-WORKSPACE",
    )
    await messenger.send(origin, "x")
    assert adapter.sent[0].metadata["slack_team_id"] == "T-WORKSPACE"


@pytest.mark.asyncio
async def test_edit_passes_no_metadata(origin_for, messenger) -> None:
    """``StubAdapter.edit_message`` has no ``metadata`` parameter, mirroring six of
    the nine real adapters. If the messenger ever passes one, this raises
    ``TypeError`` instead of quietly working on the three that accept it."""
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u", thread_id="5"
    )
    result = await messenger.edit(origin, "msg-1", "edited")

    assert result.success is True
    assert [(e.chat_id, e.message_id, e.content) for e in adapter.edited] == [
        ("tg-1", "msg-1", "edited")
    ]


def test_the_stub_really_would_reject_metadata_on_edit() -> None:
    """Guard on the guard: if ``StubAdapter.edit_message`` ever grew a
    ``metadata`` parameter, the test above would stop proving anything."""
    params = inspect.signature(StubAdapter.edit_message).parameters
    assert "metadata" not in params
    assert "metadata" in inspect.signature(StubAdapter.send).parameters


def test_messenger_source_never_mentions_metadata_on_an_edit_call(plugin) -> None:
    src = inspect.getsource(plugin.drop.messenger)
    edit_body = src.split("async def edit", 1)[1]
    assert "metadata=" not in edit_body.split("async def", 1)[0]


# ── the edit target ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_edit_targets_the_message_id_captured_at_send_time(
    origin_for, messenger
) -> None:
    """Never a ``fetch_messages`` search: that needs Discord's MESSAGE_CONTENT
    privileged intent (``tools/discord_tool.py:791-799``) and would silently
    no-op without it."""
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u"
    )
    sent = await messenger.send(origin, "waiting")
    await messenger.edit(origin, sent.message_id, "received")

    assert adapter.edited[0].message_id == sent.message_id == "stub-msg-1"


@pytest.mark.asyncio
async def test_messenger_never_deletes(plugin, origin_for, messenger) -> None:
    """Variant A: edit in place through three fixed states. Never delete."""
    src = inspect.getsource(plugin.drop.messenger)
    assert "delete_message" not in src


# ── the two failure contracts ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_failed_post_is_reported_as_post_failed(origin_for, messenger) -> None:
    """§7.2: ``send`` fails → abort the drop. A live capability whose link was
    never delivered is pure risk, so the caller must be able to tell."""
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM,
        chat_id="tg-1",
        chat_type="dm",
        user_id="u",
        adapter_kwargs={"send_ok": False, "send_error": "429 flood wait"},
    )
    outcome = await messenger.post_status(origin, "waiting")

    assert outcome == {
        "error": "post_failed",
        "detail": "429 flood wait",
        "platform": "telegram",
    }


@pytest.mark.asyncio
async def test_a_raising_adapter_is_also_post_failed(origin_for, messenger) -> None:
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u"
    )

    async def boom(*args, **kwargs):
        raise RuntimeError("socket reset")

    adapter.send = boom
    outcome = await messenger.post_status(origin, "waiting")

    assert outcome["error"] == "post_failed"
    assert "socket reset" in outcome["detail"]


@pytest.mark.asyncio
async def test_a_successful_post_returns_the_message_id(origin_for, messenger) -> None:
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u"
    )
    assert await messenger.post_status(origin, "waiting") == {
        "ok": True,
        "message_id": "stub-msg-1",
    }


@pytest.mark.asyncio
async def test_a_failed_edit_is_edit_failed_and_does_not_raise(
    origin_for, messenger
) -> None:
    """§7.2: ``edit`` fails → record ``edit_failed`` and continue. The state the
    edit would have shown no longer matters; the capability is already dead. What
    must not happen is an exception escaping into the waiter task."""
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM,
        chat_id="tg-1",
        chat_type="dm",
        user_id="u",
        adapter_kwargs={"edit_ok": False, "edit_error": "message not found"},
    )
    outcome = await messenger.update_status(origin, "msg-1", "expired")

    assert outcome == {
        "error": "edit_failed",
        "detail": "message not found",
        "platform": "telegram",
    }


@pytest.mark.asyncio
async def test_a_raising_edit_is_also_edit_failed(origin_for, messenger) -> None:
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u"
    )

    async def boom(*args, **kwargs):
        raise TypeError("edit_message() got an unexpected keyword argument 'metadata'")

    adapter.edit_message = boom
    outcome = await messenger.update_status(origin, "msg-1", "expired")
    assert outcome["error"] == "edit_failed"


@pytest.mark.asyncio
async def test_an_unsupported_edit_stub_degrades_rather_than_crashing(
    origin_for, messenger
) -> None:
    """The base ABC's default returns ``SendResult(success=False,
    error="Not supported")`` (``gateway/platforms/base.py:3559``) — a platform
    that cannot edit is an ``edit_failed``, not an exception."""
    from gateway.platforms.base import SendResult

    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u"
    )

    async def not_supported(*args, **kwargs):
        return SendResult(success=False, error="Not supported")

    adapter.edit_message = not_supported
    assert (await messenger.update_status(origin, "m", "x"))["error"] == "edit_failed"


# ── what must not be reachable ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_message_tool_is_never_imported(origin_for, messenger) -> None:
    """``send_message`` is the tool whose home-channel default caused the
    incident (``tools/send_message_tool.py:446-465``)."""
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u"
    )
    await messenger.send(origin, "x")
    await messenger.edit(origin, "stub-msg-1", "y")

    assert "tools.send_message_tool" not in sys.modules


def _executable_source(path) -> str:
    """Return a file's source with comments and string literals removed.

    The sweep below has to distinguish *citing* a dangerous seam from *calling*
    one. Drop's modules deliberately name ``send_message_tool.py:446-465`` and
    ``config.get_home_channel(platform)`` in prose, because the reasoning for
    every refusal is the incident those two produced, and a reader who cannot
    find the citation cannot check the claim. A raw substring grep would make
    documenting the vulnerability indistinguishable from reintroducing it, so
    comments and strings are tokenized out first and only executable code is
    searched.
    """
    import io
    import tokenize

    # Blank comment/string spans *in place* rather than re-joining surviving
    # tokens: a token-joined rebuild separates `os` `.` `environ`, so a dotted
    # needle like "os.environ" would silently never match and the sweep would
    # pass by accident.
    ignored = {tokenize.COMMENT, tokenize.STRING}
    for name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):  # py3.12+
        if hasattr(tokenize, name):
            ignored.add(getattr(tokenize, name))

    raw = path.read_bytes()
    grid = [list(line) for line in raw.decode("utf-8").splitlines(keepends=True)]
    for token in tokenize.tokenize(io.BytesIO(raw).readline):
        if token.type not in ignored:
            continue
        (srow, scol), (erow, ecol) = token.start, token.end
        for row in range(srow, erow + 1):
            line = grid[row - 1]
            start = scol if row == srow else 0
            end = ecol if row == erow else len(line)
            for i in range(start, min(end, len(line))):
                if line[i] != "\n":
                    line[i] = " "
    return "".join("".join(line) for line in grid)


def test_the_plugin_reads_no_credentials(plugin) -> None:
    """Adapter-mediated send/edit means no token read anywhere: no
    ``os.environ`` credential lookup, no ``get_env_value_prefer_dotenv``, no
    ``agent.secret_scope`` (§8.4). Research 09's raw Discord REST ``PATCH`` plus
    profile-token resolution is superseded by ``adapter.edit_message``."""
    from pathlib import Path

    plugin_dir = Path(plugin.__file__).parent
    forbidden = (
        "get_env_value_prefer_dotenv",
        "secret_scope",
        "get_secret",
        "DISCORD_BOT_TOKEN",
        "TELEGRAM_BOT_TOKEN",
        "send_message_tool",
        "get_home_channel",
        "home_channel",
        "requests",
        "httpx",
        "aiohttp",
    )
    offences = []
    for path in sorted(plugin_dir.rglob("*.py")):
        if "tests" in path.parts:
            continue
        code = _executable_source(path)
        for needle in forbidden:
            if needle in code:
                offences.append((path.name, needle))
    assert offences == [], offences


def test_the_plugin_touches_os_environ_only_for_its_own_configuration(plugin) -> None:
    """``os.environ`` is read in exactly one place — the control-socket path in
    ``drop/config.py`` — and never for a credential. Stated as a bound rather
    than a blanket ban, because banning it outright would be a claim the code
    does not make."""
    from pathlib import Path

    plugin_dir = Path(plugin.__file__).parent
    users = []
    for path in sorted(plugin_dir.rglob("*.py")):
        if "tests" in path.parts:
            continue
        code = _executable_source(path)
        if "os.environ" in code or "getenv" in code:
            users.append(path.name)
    assert users == ["config.py"], users


# ── M7: finalize=True on every edit ────────────────────────────────────────
#
# ``edit`` used to call ``edit_message(chat_id, message_id, content)`` and leave
# ``finalize`` at its default ``False``. On Telegram that picks the branch that
# calls ``edit_message_text(text=content)`` with **no** ``parse_mode``
# (``plugins/platforms/telegram/adapter.py:4755-4761``); only the
# ``finalize=True`` branch runs ``format_message`` + ``MARKDOWN_V2``
# (``:4765-4771``). So ``✓ **Private input received**`` landed with its asterisks
# showing. Discord was unaffected — its ``edit_message`` formats regardless.
#
# It also invalidated the E2E-1 gate as written: the plan asserted the message
# "reads exactly ``✕ **Private input link expired**``", which is precisely the
# literal string a *broken* render produces, so the gate could not tell correct
# from incorrect.
#
# ``finalize`` is safe to pass everywhere, unlike ``metadata``: it is on the ABC
# (``gateway/platforms/base.py:3533-3540``) and keyword-only on all nine adapters.
# The tests below pin both halves of that — that we pass it, and that passing it
# is universally accepted.


@pytest.mark.asyncio
async def test_edit_finalizes_so_telegram_applies_a_parse_mode(origin_for, messenger) -> None:
    """M7. Every edit Drop makes is a final edit — there is no streaming here."""
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u"
    )
    await messenger.edit(origin, "msg-1", "✓ **Private input received**")

    assert adapter.edited[0].finalize is True, (
        "without finalize=True Telegram edits with no parse_mode and the ** shows"
    )


@pytest.mark.asyncio
async def test_update_status_finalizes_too(origin_for, messenger) -> None:
    """The wrapper the reconciler and the waiter actually call, not just ``edit``."""
    origin, adapter, _ = origin_for(
        Platform.TELEGRAM, chat_id="tg-1", chat_type="dm", user_id="u"
    )
    result = await messenger.update_status(origin, "msg-1", "✕ **Private input link expired**")

    assert result["ok"] is True
    assert [e.finalize for e in adapter.edited] == [True]


def test_finalize_is_keyword_only_on_every_real_adapter() -> None:
    """Why ``finalize`` is safe to pass where ``metadata`` is not.

    ``metadata`` exists on three of nine adapters, so passing it is a
    ``TypeError`` on the other six. ``finalize`` is on the ABC and on all nine —
    asserted here against the real modules rather than taken on trust, because the
    fix above depends on it.
    """
    import importlib

    from gateway.platforms.base import BasePlatformAdapter

    base = inspect.signature(BasePlatformAdapter.edit_message).parameters
    assert base["finalize"].kind is inspect.Parameter.KEYWORD_ONLY

    checked = 0
    for name, cls_name in (
        ("telegram", "TelegramAdapter"),
        ("discord", "DiscordAdapter"),
        ("slack", "SlackAdapter"),
        ("matrix", "MatrixAdapter"),
        ("mattermost", "MattermostAdapter"),
        ("whatsapp", "WhatsAppAdapter"),
        ("google_chat", "GoogleChatAdapter"),
        ("dingtalk", "DingTalkAdapter"),
        ("feishu", "FeishuAdapter"),
    ):
        try:
            module = importlib.import_module(f"plugins.platforms.{name}.adapter")
        except Exception:  # pragma: no cover - a platform's SDK is not installed
            continue
        cls = getattr(module, cls_name, None)
        if cls is None or not hasattr(cls, "edit_message"):  # pragma: no cover
            continue
        params = inspect.signature(cls.edit_message).parameters
        assert "finalize" in params, f"{name} has no finalize parameter"
        assert params["finalize"].kind is inspect.Parameter.KEYWORD_ONLY, name
        checked += 1

    assert checked >= 2, f"only {checked} real adapters were importable; expected at least 2"


def test_messenger_source_passes_finalize_on_the_edit_call(plugin) -> None:
    """Pinned in the source too, next to the ``metadata`` guard above.

    The two rules are a matched pair and easy to conflate — ``metadata`` must
    never be passed to ``edit_message``, ``finalize`` must always be — so both are
    asserted the same way.
    """
    src = inspect.getsource(plugin.drop.messenger)
    edit_body = src.split("async def edit", 1)[1].split("async def", 1)[0]
    assert "finalize=True" in edit_body
    assert "metadata=" not in edit_body
