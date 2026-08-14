"""The seam the stub adapter cannot see: renderer output × the REAL adapter.

Every other test in this suite stops at ``StubAdapter.send``, which records a
string and returns success for any string at all. That makes it faithful to the
*interface* and silent about the *behaviour* — and the behaviour is where the
notice actually gets turned into what a human sees. Two HIGH/MEDIUM review
findings (H1, M7) lived in exactly that blind spot.

So this file crosses it, with nothing stubbed on either side:

* the notice comes from the **real Node broker** (``src/notice.js`` via the
  ``create`` control op), not from a Python literal that could drift from it;
* the formatting comes from the **real adapters'** ``format_message``
  (``plugins/platforms/{telegram,discord}/adapter.py``), not from a
  reimplementation of MarkdownV2.

**What "rendered" means here.** Telegram's ``send`` posts
``format_message(content)`` with ``parse_mode=MARKDOWN_V2``
(``plugins/platforms/telegram/adapter.py:4321-4460``). Under MarkdownV2 a
``[text](url)`` is a hyperlink whose *target* is not displayed, a ``\\<`` is
displayed as a bare ``<``, and everything else is displayed as written. So the
assertions below are written against a model of the **visible** string —
:func:`visible_text` — rather than against the raw wire bytes. That distinction
is the whole finding: the pre-fix HTML notice contained no unescaped URL on the
wire, and displayed the capability in full.

The property under test is §8.8's: the capability appears exactly twice, and
neither of them is somewhere a person or a push notification can read it.

The outbound notice (``src/outbound-notice.js``) is crossed here too, and it raises
the stakes of the same finding. Its fragment carries the **decryption key** as well
as the capability, so a renderer that displayed the URL would put the key itself on a
lock screen. It also has the opposite requirement in one place: the 3-digit code
*must* be readable, because a person has to type it. And it is the one message built
from a payload a model composed, so a title of ``x](https://evil.test) [click here``
would forge a link if anything of the payload reached the text — which is why nothing
does but the field count.
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

import pytest

from conftest import load_plugin_package

from plugins.platforms.discord.adapter import DiscordAdapter
from plugins.platforms.telegram.adapter import TelegramAdapter, _strip_mdv2

#: ``[display](target)``. Non-greedy target, no nesting — which is all the
#: renderers emit and all Telegram's own link regex accepts.
_MD_LINK = re.compile(r"\[([^\]]+)\]\(([^()]*)\)")


def visible_text(formatted: str) -> str:
    """What a Telegram client actually displays for a MarkdownV2 message.

    Two transformations, in the order the client applies them:

    1. A masked link shows its display text and hides its target.
    2. A ``\\x`` escape shows ``x``. ``_strip_mdv2`` is the adapter's **own**
       unescaper — the one it uses for its plain-text fallback — so this models
       Telegram with Telegram's code rather than with a guess.
    """
    return _strip_mdv2(_MD_LINK.sub(r"\1", formatted))


def telegram_adapter() -> TelegramAdapter:
    """A real adapter with no bot and no config.

    ``object.__new__`` on purpose, and it is the adapter's own documented test
    shape — ``send`` reads its degradation flag with ``getattr(self, ...,
    False)`` precisely because "tests build adapters via object.__new__() (no
    __init__)" (``adapter.py:4334``). ``format_message`` touches no instance
    state at all, so this exercises the real function, not a stub of it.
    """
    return object.__new__(TelegramAdapter)


def discord_adapter() -> DiscordAdapter:
    return object.__new__(DiscordAdapter)


@pytest.fixture
def notices(real_broker):
    """One real ``create`` per verified platform, straight off the broker.

    Returns ``{platform: (created_dict, capability)}``. The capability is split
    out of the minted URL rather than invented, so the assertions below are made
    against the token that actually authorises this handoff.
    """
    plugin = load_plugin_package()
    control_client = plugin.drop.control_client

    out = {}
    for platform in ("telegram", "discord"):
        created = asyncio.run(
            control_client.create(
                ttl_seconds=1800,
                notice_platform=platform,
                socket_path=real_broker.socket_path,
            )
        )
        assert created.get("ok"), created
        url = created["url"]
        assert "#" in url, url
        out[platform] = (created, url.split("#", 1)[1])
    return out


# ── H1: the waiting notice on Telegram ─────────────────────────────────────


def test_telegram_waiting_notice_hides_the_capability_from_visible_text(notices) -> None:
    """H1. The capability must never be displayed, on either verified platform.

    Before the fix the ``telegram`` renderer emitted ``<a href="…">``. MarkdownV2
    has no notion of an HTML tag, so ``format_message`` escaped the angle
    brackets and Telegram displayed the *whole URL, fragment included*, as plain
    text — in the message body, in the push notification, and on a lock screen.
    """
    created, capability = notices["telegram"]
    formatted = telegram_adapter().format_message(created["notice"])
    shown = visible_text(formatted)

    assert capability not in shown, (
        "the capability is displayed to the user. §8.8 allows it to appear "
        "exactly twice — in the URL bar of whoever opens the form, and inside "
        f"the link target — and never as readable text.\nrendered:\n{shown}"
    )
    assert created["url"] not in shown, "the URL itself must not be readable either"


def test_telegram_waiting_notice_is_a_real_markdownv2_link(notices) -> None:
    """The capability is hidden *because* it is a link target — not by accident.

    Asserted on the wire form, because that is what ``parse_mode=MARKDOWN_V2``
    is handed. ``format_message`` step 3 translates a standard Markdown link
    into a MarkdownV2 one and escapes only ``\\`` and ``)`` inside the target
    (``adapter.py:7535-7541``), so the URL survives intact in the target and
    nowhere else.
    """
    created, _capability = notices["telegram"]
    formatted = telegram_adapter().format_message(created["notice"])

    assert f"]({created['url']})" in formatted, (
        f"expected a masked MarkdownV2 link carrying the URL; got:\n{formatted}"
    )
    # And exactly one occurrence, so a second copy cannot have leaked in.
    assert formatted.count(created["url"]) == 1


def test_telegram_waiting_notice_displays_no_literal_markup(notices) -> None:
    """No HTML tag, and no unconverted ``**``, survives to the display layer."""
    created, _ = notices["telegram"]
    shown = visible_text(telegram_adapter().format_message(created["notice"]))

    for tag in ("<b>", "</b>", "<a ", "</a>", "<code>", "</code>", "href="):
        assert tag not in shown, f"literal {tag!r} is displayed to the user:\n{shown}"
    assert "**" not in shown, "an unconverted bold marker is displayed"
    assert "<t:" not in shown, "a Discord relative stamp would be literal here"


def test_telegram_waiting_notice_still_says_everything_it_has_to(notices) -> None:
    """The fix must not have quietly dropped content along with the markup."""
    created, _ = notices["telegram"]
    shown = visible_text(telegram_adapter().format_message(created["notice"]))

    assert "Private input" in shown
    assert "open the secure form" in shown, "the link needs visible display text"
    assert f"drop:{created['handoff_id']}" in shown, "the audit tag survives"
    assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} UTC", shown), (
        f"an absolute UTC deadline, since Telegram re-renders nothing:\n{shown}"
    )


def test_discord_waiting_notice_survives_its_own_format_message(notices) -> None:
    """Discord was never broken; this pins that it stays that way.

    ``DiscordAdapter.format_message`` is a table-to-bullets pass and otherwise a
    passthrough (``adapter.py:5197-5205``), so the masked link and the
    ``<t:UNIX:R>`` stamp reach Discord verbatim.
    """
    created, capability = notices["discord"]
    formatted = discord_adapter().format_message(created["notice"])

    assert f"]({created['url']})" in formatted, "masked link preserved"
    assert re.search(r"<t:\d{10}:R>", formatted), "relative stamp preserved"
    # Discord hides a masked link's target, so the capability is not displayed.
    assert capability not in _MD_LINK.sub(r"\1", formatted)


def test_neither_verified_platform_renders_the_capability_twice(notices) -> None:
    """§8.8's counting property, held against the real formatters."""
    for platform, adapter in (
        ("telegram", telegram_adapter()),
        ("discord", discord_adapter()),
    ):
        created, capability = notices[platform]
        formatted = adapter.format_message(created["notice"])
        assert formatted.count(capability) == 1, (
            f"{platform}: the capability appears {formatted.count(capability)} "
            "times in one message"
        )


# ── M7: the two quiet states, edited in ────────────────────────────────────


def test_quiet_notices_render_as_bold_through_a_finalizing_edit(notices) -> None:
    """M7. ``edit_message`` only formats when ``finalize=True``.

    With ``finalize=False`` Telegram's ``edit_message`` calls
    ``edit_message_text(text=content)`` with **no** ``parse_mode``
    (``adapter.py:4755-4761``), so ``✓ **Private input received**`` lands with
    its asterisks showing. Only the ``finalize=True`` branch runs
    ``format_message`` + ``MARKDOWN_V2`` (``:4765-4771``).

    This asserts the formatting half — that the raw contract string really does
    become MarkdownV2 bold. ``test_messenger.py`` asserts the other half: that
    ``OriginMessenger.edit`` passes ``finalize=True``.
    """
    adapter = telegram_adapter()
    created, _ = notices["telegram"]

    for key, raw in (
        ("notice_received", "✓ **Private input received**"),
        ("notice_expired", "✕ **Private input link expired**"),
    ):
        # The raw contract is unchanged — pinned here against the real broker so
        # a "fix" to the rendering cannot quietly rewrite the wire contract.
        assert created[key] == raw

        formatted = adapter.format_message(raw)
        assert "**" not in formatted, f"{key}: ** must be converted, not displayed"
        body = raw.split("**")[1]
        assert f"*{body}*" in formatted, (
            f"{key}: expected MarkdownV2 bold *{body}*; got {formatted!r}"
        )
        # And nothing is lost from what the user reads.
        assert body in visible_text(formatted)


def test_quiet_notices_stay_on_the_legacy_markdownv2_edit_path(notices) -> None:
    """Neither quiet notice is rich-eligible, so ``finalize=True`` is predictable.

    ``finalize=True`` first offers the content to Bot API 10.1's rich edit
    (``adapter.py:4705-4712``), which would bypass ``format_message`` entirely.
    It only triggers for tables, GFM task lists, ``<details>`` and block math
    (``_needs_rich_rendering``). Asserting that none of Drop's content qualifies
    is what makes the ``finalize=True`` fix a one-branch change rather than two
    behaviours depending on the bot's API version.
    """
    adapter = telegram_adapter()
    created, _ = notices["telegram"]

    for content in (
        created["notice"],
        created["notice_received"],
        created["notice_expired"],
    ):
        assert not adapter._needs_rich_rendering(content), (
            f"unexpectedly rich-eligible, so the edit path forks: {content!r}"
        )


# ── the outbound notice: the key must never be readable, the code must be ──


@pytest.fixture
def outbound_notices(real_broker):
    """One real ``create_outbound_drop`` per verified platform, off the broker.

    Returns ``{platform: (created_dict, fragment)}``. The fragment is split out of
    the minted URL rather than invented, so the assertions are made against the
    capability *and the decryption key* that actually open this drop.

    The payload deliberately carries a hostile title and label: this is the one
    notice built from something a model composed, and the message is Markdown going
    to a platform that renders links.
    """
    import base64
    import json

    plugin = load_plugin_package()
    control_client = plugin.drop.control_client

    payload = json.dumps(
        {
            "v": 1,
            "title": "x](https://evil.test) [click here",
            "fields": [
                {"label": "Login", "type": "text", "value": "ops@example.test"},
                {"label": "Inject](https://evil.test)", "type": "secret", "value": "xyzzy"},
            ],
        }
    )

    out = {}
    for platform in ("telegram", "discord"):
        created = asyncio.run(
            control_client.control_request(
                {
                    "op": "create_outbound_drop",
                    "plaintext_b64": base64.b64encode(payload.encode()).decode(),
                    "payload_format": "structured",
                    "notice_platform": platform,
                    "ttl_seconds": 1800,
                },
                socket_path=real_broker.socket_path,
            )
        )
        assert created.get("ok"), created
        url = created["url"]
        assert "#" in url, url
        out[platform] = (created, url.split("#", 1)[1])
    return out


def test_telegram_outbound_notice_hides_the_capability_and_the_key(outbound_notices) -> None:
    """The H1 property, with more to lose: this fragment holds the decryption key.

    An outbound link's fragment is ``r.<capability>.<key>``. The capability alone
    cannot open the payload — the code and a claim are needed — but the *key* is the
    only copy of the thing that decrypts it, because the broker zero-filled its own.
    Displaying the URL would put it in the message body, the push notification and
    the lock-screen preview.
    """
    created, fragment = outbound_notices["telegram"]
    shown = visible_text(telegram_adapter().format_message(created["notice"]))

    assert fragment not in shown, f"the capability and key are displayed:\n{shown}"
    assert created["url"] not in shown, "the URL itself must not be readable either"
    # And the key on its own, not merely the whole fragment.
    assert fragment.split(".")[-1] not in shown, "the decryption key is displayed"


def test_the_outbound_code_is_readable_because_a_person_has_to_type_it(
    outbound_notices,
) -> None:
    """The one thing in this message that MUST survive to the visible layer.

    Hiding the code would make the drop unopenable, which is the failure mode a
    "hide everything" reading of H1 would produce. It is emitted as a backticked
    span so its leading zeros are unambiguous and it is tappable to copy.
    """
    for platform, adapter in (
        ("telegram", telegram_adapter()),
        ("discord", discord_adapter()),
    ):
        created, _fragment = outbound_notices[platform]
        formatted = adapter.format_message(created["notice"])
        shown = visible_text(formatted)
        assert created["code"] in shown, f"{platform}: the code must be readable:\n{shown}"
        assert len(created["code"]) == 3


def test_the_outbound_notice_quotes_nothing_a_model_composed(outbound_notices) -> None:
    """The payload's title and labels were hostile. Neither reaches the message.

    A model-composed string in a Markdown message going to a platform that renders
    links is a forged link waiting to happen, and escaping it correctly for MarkdownV2
    *and* for whatever ``format_message`` then does to it is the same
    double-translation H1 was. So the notice quotes nothing but the field count — and
    this is the test that holds that through the real formatter rather than through
    the renderer alone.
    """
    for platform, adapter in (
        ("telegram", telegram_adapter()),
        ("discord", discord_adapter()),
    ):
        created, _fragment = outbound_notices[platform]
        formatted = adapter.format_message(created["notice"])
        shown = visible_text(formatted)

        for hostile in ("evil.test", "click here", "Inject", "xyzzy", "ops@example.test"):
            assert hostile not in formatted, f"{platform}: {hostile} reached the wire"
            assert hostile not in shown, f"{platform}: {hostile} reached the display"

        # Exactly one link target, and it is the drop's own.
        targets = _MD_LINK.findall(formatted) if platform == "discord" else None
        if targets is not None:
            assert [target for _text, target in targets] == [created["url"]]
        # What IS derived from the payload is a number.
        assert "2 labelled values" in shown


def test_the_outbound_notice_says_what_it_has_to_and_shows_no_literal_markup(
    outbound_notices,
) -> None:
    created, _fragment = outbound_notices["telegram"]
    shown = visible_text(telegram_adapter().format_message(created["notice"]))

    assert "Private value from Hermes" in shown
    assert "not posted here" in shown
    assert "Open your one-time drop" in shown, "the link needs visible display text"
    assert "reveal it once" in shown.lower(), "one reveal only"
    assert "cannot be opened again" in shown, "and what that means afterwards"
    assert f"drop:{created['drop_id']}" in shown, "the audit tag survives"
    assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} UTC", shown), (
        f"an absolute UTC deadline, since Telegram re-renders nothing:\n{shown}"
    )

    for tag in ("<b>", "</b>", "<a ", "</a>", "<code>", "</code>", "href="):
        assert tag not in shown, f"literal {tag!r} is displayed to the user:\n{shown}"
    assert "**" not in shown, "an unconverted bold marker is displayed"
    assert "<t:" not in shown, "a Discord relative stamp would be literal here"


def test_discord_outbound_notice_keeps_its_link_and_its_relative_stamp(
    outbound_notices,
) -> None:
    created, fragment = outbound_notices["discord"]
    formatted = discord_adapter().format_message(created["notice"])

    assert f"]({created['url']})" in formatted, "masked link preserved"
    assert re.search(r"<t:\d{10}:R>", formatted), "relative stamp preserved"
    assert fragment not in _MD_LINK.sub(r"\1", formatted), "and the key is not displayed"


def test_the_outbound_notice_is_never_rich_eligible(outbound_notices) -> None:
    """Same reason as the quiet states: a rich-edit fork would bypass
    ``format_message`` entirely, and every assertion above with it."""
    adapter = telegram_adapter()
    created, _fragment = outbound_notices["telegram"]
    assert not adapter._needs_rich_rendering(created["notice"])
