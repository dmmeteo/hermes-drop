"""``/drop [prompt]`` is a **stock** Hermes skill command, not a plugin command.

The whole point of this slice is that Drop needs no core patch. Core already
has a surface that turns ``/<name> [prompt]`` into an ordinary authenticated
agent turn: ``scan_skill_commands`` auto-registers one slash command per skill,
``resolve_skill_command_key`` resolves the typed name, and
``build_skill_invocation_message`` rewrites ``event.text`` so the message falls
through to normal processing (``gateway/run.py``, the "Skill slash commands"
block). Auth, pairing and the slash-access policy have already run by then, and
``_set_session_env`` binds this turn's identity on the agent path — which is
exactly the authoritative context the tools resolve their origin against.

So the properties this file pins are:

1. the repo ships a skill whose name is ``drop``, so core registers ``/drop``;
2. nothing in core already owns the name (auto-registration is skipped on a
   collision, silently — ``scan_skill_commands``);
3. the plugin registers **no** slash command, because plugin dispatch runs
   *before* skill dispatch and would shadow it;
4. the invocation message carries the user's prompt verbatim and recoverably,
   which is what keeps memory clean and the cache prefix stable;
5. no duration syntax and no destination survive anywhere on the surface.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import PLUGIN_DIR, REPO_ROOT, load_plugin_package

SKILL_DIR = REPO_ROOT / "integrations" / "drop-skill"
SKILL_MD = SKILL_DIR / "SKILL.md"


@pytest.fixture
def plugin():
    return load_plugin_package()


@pytest.fixture
def skills_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A throwaway skills root with the repo's Drop skill linked into it.

    ``tools.skills_tool.SKILLS_DIR`` is a module constant resolved from
    ``HERMES_HOME`` at import time, so a per-test ``HERMES_HOME`` cannot move it.
    Rebinding the constant is what core itself reads, and it is undone by
    ``monkeypatch`` — the scan cache is reset either way by the autouse fixture
    below.
    """
    import tools.skills_tool as skills_tool

    root = tmp_path / "skills"
    (root / "hermes-drop").mkdir(parents=True)
    (root / "hermes-drop" / "drop").symlink_to(SKILL_DIR, target_is_directory=True)
    monkeypatch.setattr(skills_tool, "SKILLS_DIR", root)
    return root


@pytest.fixture(autouse=True)
def _reset_skill_command_cache():
    """``scan_skill_commands`` writes module globals; leave none behind."""
    import agent.skill_commands as skill_commands

    yield
    skill_commands._skill_commands = {}
    skill_commands._skill_commands_platform = None


def _frontmatter() -> dict:
    from tools.skills_tool import _parse_frontmatter

    frontmatter, _body = _parse_frontmatter(SKILL_MD.read_text(encoding="utf-8"))
    return frontmatter


def _body() -> str:
    from tools.skills_tool import _parse_frontmatter

    _frontmatter, body = _parse_frontmatter(SKILL_MD.read_text(encoding="utf-8"))
    return body


# ── 1. the skill exists and core will name its command ``drop`` ────────────


def test_the_repo_ships_a_skill_whose_name_is_drop() -> None:
    assert SKILL_MD.is_file(), f"no SKILL.md at {SKILL_MD}"
    assert _frontmatter().get("name") == "drop"


def test_no_core_command_owns_the_name_so_auto_registration_is_not_skipped() -> None:
    """``scan_skill_commands`` skips a skill whose slug collides with a built-in,
    and it does so with a ``logger.warning`` nobody reads. If core ever takes
    ``/drop``, this test is where that is discovered."""
    from hermes_cli.commands import resolve_command

    assert resolve_command("drop") is None


def test_the_scan_registers_slash_drop_for_our_skill(skills_dir: Path) -> None:
    from agent.skill_commands import scan_skill_commands

    commands = scan_skill_commands()

    assert "/drop" in commands, f"scan found {sorted(commands)}"
    assert commands["/drop"]["name"] == "drop"
    assert Path(commands["/drop"]["skill_md_path"]).resolve() == SKILL_MD.resolve()


def test_the_typed_name_resolves_through_cores_own_resolver(skills_dir: Path) -> None:
    """Both spellings, because Telegram's command menu round-trips underscores."""
    from agent.skill_commands import resolve_skill_command_key, scan_skill_commands

    scan_skill_commands()

    assert resolve_skill_command_key("drop") == "/drop"
    assert resolve_skill_command_key("_drop_".strip("_")) == "/drop"


# ── 2. the plugin must not shadow it ───────────────────────────────────────


def test_the_plugin_registers_no_slash_command(monkeypatch, temp_hermes_home, plugin) -> None:
    """Plugin dispatch runs *before* skill dispatch in ``_handle_message``.

    A surviving plugin ``drop`` command would win every time and the skill would
    be unreachable — so "the plugin registers nothing" is not tidiness, it is the
    mechanism.
    """
    from _seam import install_plugin_for_real
    from hermes_cli.plugins import get_plugin_commands

    install_plugin_for_real(monkeypatch, temp_hermes_home, PLUGIN_DIR)

    assert get_plugin_commands() == {}


def test_the_plugin_exposes_no_command_entry_points(plugin) -> None:
    assert not hasattr(plugin, "drop_command")
    assert not hasattr(plugin.drop, "command")


def test_the_manifest_promises_no_commands() -> None:
    import yaml

    manifest = yaml.safe_load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8"))

    assert "provides_commands" not in manifest


# ── 3. the invocation message ──────────────────────────────────────────────


def test_a_bare_drop_loads_the_skill_with_no_instruction(skills_dir: Path) -> None:
    from agent.skill_commands import (
        build_skill_invocation_message,
        extract_user_instruction_from_skill_message,
        scan_skill_commands,
    )

    scan_skill_commands()
    message = build_skill_invocation_message("/drop", "")

    assert message is not None
    assert "request_private_input" in message
    # No instruction means memory stores nothing for this turn, rather than
    # storing the whole skill body.
    assert extract_user_instruction_from_skill_message(message) in (None, "")


def test_a_prompt_reaches_the_model_verbatim_and_recoverably(skills_dir: Path) -> None:
    """The prompt is the only volatile part of the turn.

    Recoverability is what keeps memory providers storing what the user asked
    instead of the skill body, and the marker it is recovered by is the same one
    ``append_user_instruction`` registers as the prompt-cache prefix boundary —
    so this assertion is also the cache-validity assertion.
    """
    from agent.skill_commands import (
        build_skill_invocation_message,
        extract_user_instruction_from_skill_message,
        scan_skill_commands,
    )

    scan_skill_commands()
    prompt = "generate an admin password for the staging box and send it to me"
    message = build_skill_invocation_message("/drop", prompt)

    assert message is not None
    assert message.endswith(prompt)
    assert extract_user_instruction_from_skill_message(message) == prompt


# ── 4. removed surface ─────────────────────────────────────────────────────


DURATION_SHAPES = ("/drop 10m", "/drop 30m", "[10m]", "args_hint", "parse_duration")


def test_no_ttl_command_syntax_survives_on_the_skill_surface() -> None:
    body = _body()
    for shape in DURATION_SHAPES:
        assert shape not in body, f"{shape!r} is still documented in the skill"


def test_the_command_module_is_gone() -> None:
    assert not (PLUGIN_DIR / "drop" / "command.py").exists()


def test_the_skill_names_no_destination() -> None:
    """The same absence the schemas enforce, on the prose the model reads.

    A skill body that mentioned a channel or a chat id would be teaching the
    model a parameter that does not exist, and the first thing it would do with
    it is hallucinate one.
    """
    from conftest import load_plugin_package as _load

    forbidden = _load().drop.schemas.FORBIDDEN_DESTINATION_FIELDS
    body = _body().lower()

    for name in sorted(forbidden):
        assert f"{name}=" not in body, f"the skill names a destination argument: {name}"
        assert f'"{name}"' not in body, f"the skill names a destination argument: {name}"


def test_the_skill_teaches_all_three_tools_and_the_inbound_fallback() -> None:
    body = _body()

    assert "request_private_input" in body
    assert "claim_private_input" in body
    assert "send_private_output" in body
    assert "generate" in body, "the skill must prefer service-generated values"
    # The ambiguity rule of the decided contract: clarify, else inbound.
    assert "inbound" in body.lower()
