"""S5 — the rendering matrix, and refusing *before* anything is created.

``waitingNotice`` throws for anything but discord/telegram/plain
(``src/notice.js``), and S1 added ``plain``. That must not be how an unsupported
platform is discovered: by the time the broker refuses, the turn has already
spent itself, and by the time it *accepts* a plain notice, the platform's edit
path is still unverified.

So the table here is the only place tiers live, it has exactly two of them, and
an unsupported platform is refused **before** ``create`` — never silently
degraded, and never redirected to a platform that *is* supported. That last
clause is the incident restated as a rule.

Revision 1's third ``expected`` tier is cut: it promised an ``edit_message`` call
carrying ``metadata`` that would ``TypeError`` on six of nine adapters, and Slack
additionally needs an operator manifest update
(``hermes_cli/commands.py:1355-1380``).
"""

from __future__ import annotations

import json

import pytest
from gateway.config import Platform

from conftest import REPO_ROOT, load_plugin_package

CONTRACT = json.loads((REPO_ROOT / "contract" / "control-protocol.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def render():
    return load_plugin_package().drop.render


def test_only_two_tiers_exist(render) -> None:
    assert set(render.TIERS) == {"verified", "unsupported"}


def test_discord_and_telegram_are_the_supported_platforms(render) -> None:
    assert sorted(render.supported_platforms()) == ["discord", "telegram"]


@pytest.mark.parametrize(
    "platform,renderer",
    [("discord", "discord"), ("telegram", "telegram")],
)
def test_supported_platforms_map_to_their_own_renderer(render, platform, renderer) -> None:
    entry = render.entry_for(platform)
    assert entry["renderer"] == renderer
    assert entry["tier"] == "verified"


@pytest.mark.parametrize(
    "platform",
    ["slack", "matrix", "mattermost", "whatsapp", "google_chat", "dingtalk", "feishu", "signal", "cli", "local"],
)
def test_every_other_platform_is_unsupported_and_renders_plain(render, platform) -> None:
    entry = render.entry_for(platform)
    assert entry["tier"] == "unsupported"
    assert entry["renderer"] == "plain"
    assert render.is_supported(platform) is False


def test_an_unknown_platform_is_unsupported_rather_than_an_error(render) -> None:
    """A platform Hermes gains tomorrow must default to refusing, not to guessing."""
    assert render.entry_for("some-future-platform")["tier"] == "unsupported"


def test_every_renderer_named_is_one_the_broker_actually_accepts(render) -> None:
    """The renderer name is sent to the broker as ``notice_platform``; a value the
    broker does not accept is ``invalid_request`` and mints nothing."""
    accepted = set(CONTRACT["notice_platforms"])
    for platform in render.TABLE:
        assert render.entry_for(platform)["renderer"] in accepted
    assert render.entry_for("matrix")["renderer"] in accepted


def test_the_refusal_names_the_platform(render) -> None:
    assert render.unsupported_error("matrix") == {
        "error": "platform_unsupported",
        "platform": "matrix",
    }


def test_e2e_evidence_is_recorded_as_not_yet_present(render) -> None:
    """``verified`` here means "this is the tier the plan assigns", not "a live run
    happened". The E2E gates are S11/M7 and are operator-run, so the table says so
    rather than letting a green test suite imply a green platform."""
    for platform in render.supported_platforms():
        assert render.entry_for(platform)["e2e_evidence"] is None


def test_platform_enum_values_resolve_too(render) -> None:
    """Callers hold ``Platform`` enums as often as strings."""
    assert render.entry_for(Platform.TELEGRAM)["tier"] == "verified"
    assert render.entry_for(Platform.MATRIX)["tier"] == "unsupported"


def test_no_platform_maps_to_a_different_platforms_channel(render) -> None:
    """There is no redirect anywhere in the table — the failure mode the incident
    was made of."""
    for platform, entry in render.TABLE.items():
        assert entry["renderer"] in {platform, "plain"}
