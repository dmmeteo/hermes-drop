"""S3 — ``bin/install-hermes-drop.sh``, exercised against a temp profile only.

Nothing here touches the operator's real profile: every invocation is handed a
``HERMES_HOME`` under ``tmp_path``, and ``test_isolation.py`` independently
asserts that the real one was never written. The installer is deliberately
never run against the live profile in S3 — that is S11/M2, behind an operator
gate.

The behaviours pinned are the ones that make rollback and audit possible
(plan §9): a symlink back to the repo so the repo stays the source of truth, a
timestamped config backup before any edit, ``plugins.enabled`` maintained
without ever writing ``allow_tool_override``, idempotence, and an
``--uninstall`` that is complete on its own.

Three of those changed with the independent review, and the tests below changed
with them:

* **M4 — the edit is surgical.** ``config.yaml`` is no longer round-tripped
  through ``yaml.safe_dump``, which destroyed every operator comment (21 → 0 on
  the live profile, and a 232-line diff for a one-line change). It is validated by
  a parser and edited by whole-line change instead
  (``bin/hermes-drop-config-edit.py``), and an ambiguous layout is **refused**
  rather than guessed at.
* **M4 — the install is transactional.** The config is validated and edited
  *before* anything is created, and a creation failure rolls the edit back. The
  old order — symlink first — left a half-install whenever the config step failed.
* **L6 — ``--uninstall`` performs the inverse edit, not a snapshot restore.** It
  removes exactly one entry from ``plugins.enabled``. It used to ``mv`` the newest
  backup over ``config.yaml``, which discarded every operator change made since
  install and resurrected the legacy plugin the install had retired. So
  "``--uninstall`` leaves config.yaml byte-identical to before install" is no
  longer the property under test — and asserting it was what kept the defect
  looking correct.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from conftest import PLUGIN_DIR, REPO_ROOT

INSTALLER = REPO_ROOT / "bin" / "install-hermes-drop.sh"


def run_installer(*args: str, home: Path, expect_ok: bool = True) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["HERMES_HOME"] = str(home)
    result = subprocess.run(
        [str(INSTALLER), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
        timeout=60,
    )
    if expect_ok:
        assert result.returncode == 0, f"rc={result.returncode}\n{result.stdout}\n{result.stderr}"
    return result


@pytest.fixture
def profile(tmp_path: Path) -> Path:
    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "plugins": {"enabled": ["hermes-drop-command", "spotify"]},
                "model": {"default": "keep-me"},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return home


def read_config(home: Path) -> dict:
    return yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))


def test_install_symlinks_the_repo_source(profile: Path) -> None:
    run_installer("install", home=profile)

    link = profile / "plugins" / "hermes-drop"
    assert link.is_symlink(), "install must link, not copy — the repo is the source of truth"
    assert link.resolve() == PLUGIN_DIR.resolve()
    assert (link / "plugin.yaml").is_file()


def test_install_enables_the_plugin_and_retires_the_legacy_command_plugin(profile: Path) -> None:
    run_installer("install", home=profile)

    enabled = read_config(profile)["plugins"]["enabled"]
    assert "hermes-drop" in enabled
    assert "hermes-drop-command" not in enabled, (
        "two enabled plugins would both rewrite /drop and fight over the same text"
    )
    assert "spotify" in enabled, "unrelated entries must survive"


def test_install_never_writes_allow_tool_override(profile: Path) -> None:
    """Drop registers new names and must never replace a built-in
    (``hermes_cli/plugins.py:439-445, 469-491``)."""
    run_installer("install", home=profile)
    assert "allow_tool_override" not in (profile / "config.yaml").read_text(encoding="utf-8")


def test_install_backs_up_the_config_before_editing_it(profile: Path) -> None:
    original = (profile / "config.yaml").read_text(encoding="utf-8")
    run_installer("install", home=profile)

    backups = sorted((profile).glob("config.yaml.hermes-drop-backup-*"))
    assert len(backups) == 1, f"expected exactly one backup, saw {backups}"
    assert backups[0].read_text(encoding="utf-8") == original


def test_install_preserves_unrelated_config(profile: Path) -> None:
    run_installer("install", home=profile)
    assert read_config(profile)["model"]["default"] == "keep-me"


def test_install_is_idempotent(profile: Path) -> None:
    run_installer("install", home=profile)
    first = read_config(profile)
    run_installer("install", home=profile)
    second = read_config(profile)

    assert first == second
    assert second["plugins"]["enabled"].count("hermes-drop") == 1
    assert (profile / "plugins" / "hermes-drop").is_symlink()


def test_copy_pins_a_real_directory_not_a_link(profile: Path) -> None:
    run_installer("--copy", home=profile)

    target = profile / "plugins" / "hermes-drop"
    assert target.is_dir() and not target.is_symlink()
    assert (target / "plugin.yaml").is_file()
    assert not (target / "tests").exists(), "tests are not part of an installed plugin"


def test_uninstall_removes_the_link_and_the_enabled_entry(profile: Path) -> None:
    """Review L6 changed what this test should assert.

    It used to require ``config.yaml`` to be byte-identical to the pre-install
    file, which is only achievable by restoring a snapshot — and that is the defect:
    a snapshot restore discards every operator change made since install, and it
    resurrects ``hermes-drop-command``, the legacy plugin install deliberately
    retired. What uninstall owes is the *inverse edit*, not a rewind.
    """
    run_installer("install", home=profile)
    run_installer("--uninstall", home=profile)

    assert not (profile / "plugins" / "hermes-drop").exists()
    enabled = read_config(profile)["plugins"]["enabled"]
    assert "hermes-drop" not in enabled, "the enabled entry outlived the plugin directory"
    assert "spotify" in enabled, "an unrelated entry was disturbed"
    assert "hermes-drop-command" not in enabled, (
        "restoring a snapshot would resurrect the legacy plugin install retired"
    )


def test_uninstall_removes_a_copied_install_too(profile: Path) -> None:
    run_installer("--copy", home=profile)
    run_installer("--uninstall", home=profile)
    assert not (profile / "plugins" / "hermes-drop").exists()


def test_install_refuses_without_an_explicit_hermes_home(tmp_path: Path) -> None:
    """The installer never guesses ``~/.hermes``. Profile rule 1 aside, guessing
    is how a test run or a mistyped command installs into the live profile."""
    env = dict(os.environ)
    env.pop("HERMES_HOME", None)
    result = subprocess.run(
        [str(INSTALLER), "install"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
        timeout=60,
    )
    assert result.returncode != 0
    assert "HERMES_HOME" in result.stderr


def test_install_refuses_a_hermes_home_that_does_not_exist(tmp_path: Path) -> None:
    result = run_installer("install", home=tmp_path / "absent", expect_ok=False)
    assert result.returncode != 0
    assert "does not exist" in result.stderr


def test_install_states_the_operator_actions_it_does_not_take(profile: Path) -> None:
    result = run_installer("install", home=profile)
    out = result.stdout
    assert "not done here" in out
    for phrase in ("restart", "docker", "skill"):
        assert phrase in out.lower(), f"installer never mentions {phrase}"


def test_preflight_still_works_and_is_unchanged_in_scope(tmp_path: Path) -> None:
    """S2's read-only preflight must survive S3's additions."""
    socket_dir = tmp_path / "run"
    socket_dir.mkdir(mode=0o700)
    env = dict(os.environ)
    env["HANDOFF_SOCKET_DIR"] = str(socket_dir)
    env["HANDOFF_SOCKET_UID"] = str(os.getuid())
    env["HANDOFF_SOCKET_GID"] = str(os.getgid())
    result = subprocess.run(
        [str(INSTALLER), "--preflight"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "nothing was created" in result.stdout


# ── M4: the edit is surgical, and the install is transactional ──────────────
#
# The config edit used to round-trip the whole document through
# ``yaml.safe_dump``. Semantically faithful, operationally hostile: against the
# live 749-line profile that turned 21 comment lines into 0, 749 lines into 727,
# and produced a 232-line diff for a one-line change — while the script's own
# comment promised "a diff of the operator's config stays readable" (review M4).
#
# And the ordering was wrong: the symlink was created *before* the config edit, so
# a config failure under ``set -e`` exited with the plugin linked and the config
# not naming it. A half-install.

COMMENTED_CONFIG = """\
# Hermes profile config. Hand-maintained — mind the comments.
model:
  default: keep-me   # do not change this

plugins:
  # Load order matters here.
  disabled: []
  enabled:
    - hermes-drop-command   # legacy, retiring
    - local-llm-polished
  entries:
    local-llm-polished:
      allow_tool_override: false

# Trailing comment at the end of the file.
session_reset:
  mode: both
"""


@pytest.fixture
def commented_profile(tmp_path: Path) -> Path:
    home = tmp_path / "commented-home"
    home.mkdir()
    (home / "config.yaml").write_text(COMMENTED_CONFIG, encoding="utf-8")
    return home


def comment_lines(text: str) -> list:
    return [line for line in text.splitlines() if line.strip().startswith("#")]


def test_install_preserves_every_comment(commented_profile: Path) -> None:
    """M4. The assertion the old implementation could not pass."""
    before = (commented_profile / "config.yaml").read_text(encoding="utf-8")
    run_installer("install", home=commented_profile)
    after = (commented_profile / "config.yaml").read_text(encoding="utf-8")

    assert comment_lines(after) == comment_lines(before), (
        "comments were lost or reordered:\n"
        f"before={comment_lines(before)}\nafter={comment_lines(after)}"
    )
    assert "# do not change this" in after, "an inline comment was dropped"
    assert "# Trailing comment at the end of the file." in after


def test_install_changes_only_the_plugins_enabled_lines(commented_profile: Path) -> None:
    """Everything outside the list is byte-identical, not merely equivalent.

    "Semantics preserved" was already true of ``safe_dump``; that is what made the
    old behaviour arguable. This is the stronger property: every other line of the
    operator's file is the same bytes it was.
    """
    before = (commented_profile / "config.yaml").read_text(encoding="utf-8").splitlines()
    run_installer("install", home=commented_profile)
    after = (commented_profile / "config.yaml").read_text(encoding="utf-8").splitlines()

    changed_before = [ln for ln in before if ln not in after]
    changed_after = [ln for ln in after if ln not in before]

    assert changed_before == ["    - hermes-drop-command   # legacy, retiring"], changed_before
    assert changed_after == ["    - hermes-drop"], changed_after


def test_the_diff_stays_small_on_a_large_realistic_config(tmp_path: Path) -> None:
    """The finding was measured on a 749-line file; the fix is measured the same way.

    Built rather than copied from the operator's real profile — this suite may not
    read ``~/.hermes`` (``test_isolation.py`` asserts it) — but with the same shape:
    many top-level keys, comments scattered through, and the plugins block in the
    middle rather than at the end.
    """
    home = tmp_path / "big-home"
    home.mkdir()
    chunks = ["# generated profile\n"]
    for i in range(60):
        chunks.append(f"# section {i}\nsection_{i}:\n  key_a: value-{i}\n  key_b: '{i}'\n")
        if i == 30:
            chunks.append(
                "plugins:\n"
                "  # load order matters\n"
                "  disabled: []\n"
                "  enabled:\n"
                "    - hermes-drop-command\n"
                "    - local-llm-polished\n"
            )
    original = "".join(chunks)
    (home / "config.yaml").write_text(original, encoding="utf-8")
    assert len(original.splitlines()) > 200

    run_installer("install", home=home)
    edited = (home / "config.yaml").read_text(encoding="utf-8")

    import difflib

    diff = [
        line
        for line in difflib.unified_diff(original.splitlines(), edited.splitlines(), n=0)
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]
    assert len(diff) <= 4, f"a one-line change produced a {len(diff)}-line diff: {diff}"
    assert len(edited.splitlines()) == len(original.splitlines())
    assert comment_lines(edited) == comment_lines(original)


def test_install_creates_nothing_when_the_config_cannot_be_edited(tmp_path: Path) -> None:
    """M4's half-install: the config is validated *before* anything is created.

    Pre-fix the symlink went in first, so a config failure under ``set -e`` left the
    plugin linked and the config not naming it — the worst of both, and the state
    an operator is least likely to notice.
    """
    home = tmp_path / "broken-home"
    home.mkdir()
    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - a\n   bad-indent: oops\n", encoding="utf-8"
    )

    result = run_installer("install", home=home, expect_ok=False)

    assert result.returncode != 0, result.stdout
    assert not (home / "plugins" / "hermes-drop").exists(), (
        "a failed config edit left the plugin directory behind"
    )
    assert not (home / "plugins").exists() or list((home / "plugins").iterdir()) == []
    assert "refusing to edit plugins.enabled" in result.stderr or "could not be" in result.stderr


def test_install_rolls_the_config_back_when_the_plugin_cannot_be_created(
    profile: Path,
) -> None:
    """The other half of transactional: creation fails *after* the config edit.

    A file where the ``plugins`` directory should be makes ``mkdir -p`` fail, which
    is the cheapest faithful stand-in for a permissions or disk failure at that
    point. Either both steps happened or neither did.
    """
    original = (profile / "config.yaml").read_text(encoding="utf-8")
    (profile / "plugins").write_text("not a directory", encoding="utf-8")

    result = run_installer("install", home=profile, expect_ok=False)

    assert result.returncode != 0
    assert (profile / "config.yaml").read_text(encoding="utf-8") == original, (
        "the config edit was not rolled back after the plugin directory failed"
    )
    assert "rolled back" in result.stderr, result.stderr
    assert sorted(profile.glob("config.yaml.hermes-drop-backup-*")) == [], (
        "a rolled-back install left its backup behind as litter"
    )


# ── M4: refusing an ambiguous layout rather than rewriting it ──────────────


@pytest.mark.parametrize(
    "config_text,reason",
    [
        ("plugins:\n  enabled:\n    - a\nplugins:\n  enabled:\n    - b\n", "two plugins keys"),
        ("base: &anchor\n  enabled: [a]\nplugins: *anchor\n", "an alias"),
        ("plugins:\n  enabled: [a,\n    b]\n", "a multi-line flow sequence"),
        ("plugins:\n  enabled:\n    - name: a\n      opt: 1\n", "a non-scalar entry"),
        ("plugins:\n  enabled:\n    -\n", "an empty entry"),
        ("plugins:\n  enabled: not-a-list\n", "a scalar where a list belongs"),
    ],
)
def test_an_ambiguous_layout_is_refused_and_nothing_is_written(
    tmp_path: Path, config_text: str, reason: str
) -> None:
    """Refusing is the feature. A line editor that guesses at an unfamiliar layout
    is exactly the "corruption waiting to happen" the original comment feared."""
    home = tmp_path / f"amb-{abs(hash(reason))}"
    home.mkdir()
    (home / "config.yaml").write_text(config_text, encoding="utf-8")

    result = run_installer("install", home=home, expect_ok=False)

    assert result.returncode != 0, f"{reason} was not refused"
    assert (home / "config.yaml").read_text(encoding="utf-8") == config_text, (
        f"{reason}: the file was modified despite the refusal"
    )
    assert not (home / "plugins" / "hermes-drop").exists()
    assert "by hand" in result.stderr, f"{reason}: the refusal must say what to do instead"


def test_a_flow_sequence_is_edited_in_place(tmp_path: Path) -> None:
    """A single-line flow sequence is unambiguous, so it is edited, not refused."""
    home = tmp_path / "flow-home"
    home.mkdir()
    (home / "config.yaml").write_text(
        "# keep me\nplugins:\n  enabled: [hermes-drop-command, spotify]  # inline\nmodel:\n  default: m\n",
        encoding="utf-8",
    )

    run_installer("install", home=home)
    text = (home / "config.yaml").read_text(encoding="utf-8")

    assert read_config(home)["plugins"]["enabled"] == ["spotify", "hermes-drop"]
    assert "# keep me" in text and "# inline" in text, text
    assert "[spotify, hermes-drop]" in text, text


def test_a_slash_in_a_plugin_id_is_an_ordinary_scalar_not_an_ambiguous_layout(
    tmp_path: Path,
) -> None:
    """The live refusal: ``- dashboard_auth/basic`` was read as a *non-scalar entry*.

    It is nothing of the sort — it is a plain YAML scalar that happens to contain a
    ``/``, which is not a YAML indicator character anywhere in a plain scalar. The
    line scanner's character class simply did not list it, so a real profile whose
    ``plugins.enabled`` names a namespaced plugin could not be installed into at
    all: exit 3, "refusing to edit plugins.enabled", nothing written.

    Refusing an unfamiliar *layout* is the feature. Refusing an unfamiliar
    *character inside a value* is a bug, and the difference is the whole point of
    the parser cross-check that runs beside the scan.
    """
    home = tmp_path / "slash-home"
    home.mkdir()
    original = (
        "plugins:\n"
        "  enabled:\n"
        "    - dashboard_auth/basic  # namespaced, and perfectly ordinary\n"
        "    - hermes-drop-command\n"
        "model:\n"
        "  default: keep-me\n"
    )
    (home / "config.yaml").write_text(original, encoding="utf-8")

    run_installer("install", home=home)

    enabled = read_config(home)["plugins"]["enabled"]
    assert enabled == ["dashboard_auth/basic", "hermes-drop"], enabled
    text = (home / "config.yaml").read_text(encoding="utf-8")
    assert "# namespaced, and perfectly ordinary" in text, text
    assert read_config(home)["model"]["default"] == "keep-me"


@pytest.mark.parametrize(
    "value",
    [
        "vendor/plugin",
        "a/b/c",
        '"quoted/value"',
        "'single/quoted'",
        "plain.dotted-id",
    ],
)
def test_ordinary_scalars_survive_the_round_trip(tmp_path: Path, value: str) -> None:
    """Whatever the scan accepts, the parser cross-check must agree it read."""
    home = tmp_path / f"scalar-{abs(hash(value))}"
    home.mkdir()
    (home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - %s\n" % value, encoding="utf-8"
    )

    run_installer("install", home=home)

    enabled = read_config(home)["plugins"]["enabled"]
    assert enabled == [yaml.safe_load(value), "hermes-drop"], enabled


@pytest.mark.parametrize(
    "config_text,reason",
    [
        ("plugins:\n  enabled:\n    - &a spotify\n    - b\n", "an anchored entry"),
        ("plugins:\n  enabled:\n    - !!str spotify\n", "a tagged entry"),
        ("plugins:\n  enabled:\n    - [a, b]\n", "a nested flow sequence"),
        ("plugins:\n  enabled:\n    - {a: b}\n", "a nested flow mapping"),
        ("base: &b\n  x: 1\nplugins:\n  <<: *b\n  enabled:\n    - a\n", "a merge key"),
    ],
)
def test_real_yaml_machinery_inside_the_list_is_still_refused(
    tmp_path: Path, config_text: str, reason: str
) -> None:
    """Widening the scalar class must not widen what counts as a *layout*.

    An anchor, an alias, a tag, a merge key or a nested collection all mean
    something the line scanner cannot see from the line it is on. Those stay
    refusals; only the character class inside a plain scalar moved.
    """
    home = tmp_path / f"unsafe-{abs(hash(reason))}"
    home.mkdir()
    (home / "config.yaml").write_text(config_text, encoding="utf-8")

    result = run_installer("install", home=home, expect_ok=False)

    assert result.returncode != 0, f"{reason} was not refused"
    assert (home / "config.yaml").read_text(encoding="utf-8") == config_text, (
        f"{reason}: the file was modified despite the refusal"
    )
    assert not (home / "plugins" / "hermes-drop").exists()


# ── N3: the edit lands atomically, or not at all ───────────────────────────


def test_the_config_edit_is_applied_by_rename_not_by_truncation(profile: Path) -> None:
    """A kill between truncate and write must not be able to leave a stub.

    ``open(path, "w")`` truncates the operator's ``config.yaml`` in place and then
    writes; interrupted in the middle it leaves a partial document, recoverable
    only from the backup taken moments earlier. A temp-write plus ``os.replace``
    makes the change atomic on POSIX, and the observable difference is the inode:
    a rename installs a *new* file over the old name.

    ``drop/journal.py`` already writes this way for exactly this reason.
    """
    config = profile / "config.yaml"
    before = config.stat().st_ino

    run_installer("install", home=profile)

    assert config.stat().st_ino != before, (
        "config.yaml was written in place; an interrupted write could truncate it"
    )
    strays = [
        p.name
        for p in profile.iterdir()
        if p.name != "config.yaml" and not p.name.startswith("config.yaml.hermes-drop-backup-")
        and p.name != "plugins"
    ]
    assert strays == [], f"the atomic write left temporary files behind: {strays}"


def test_the_config_edit_preserves_the_files_mode(profile: Path) -> None:
    """A rename must not hand the operator ``mkstemp``'s 0600 in place of their own
    permissions — the config may legitimately be group-readable."""
    config = profile / "config.yaml"
    config.chmod(0o640)

    run_installer("install", home=profile)

    assert config.stat().st_mode & 0o777 == 0o640, oct(config.stat().st_mode & 0o777)


def test_an_absent_plugins_block_is_appended_not_rewritten(tmp_path: Path) -> None:
    """Nothing to edit surgically, so the change is a pure append."""
    home = tmp_path / "noplugins-home"
    home.mkdir()
    original = "# a config with no plugins block\nmodel:\n  default: keep-me\n"
    (home / "config.yaml").write_text(original, encoding="utf-8")

    run_installer("install", home=home)
    text = (home / "config.yaml").read_text(encoding="utf-8")

    assert text.startswith(original), "the existing document was rewritten, not appended to"
    assert read_config(home)["plugins"]["enabled"] == ["hermes-drop"]
    assert read_config(home)["model"]["default"] == "keep-me"


# ── L6: uninstall is surgical, and never a time machine ────────────────────


def test_uninstall_removes_only_the_hermes_drop_entry(commented_profile: Path) -> None:
    """L6. One entry out of ``plugins.enabled``; every other byte stays."""
    run_installer("install", home=commented_profile)
    installed = (commented_profile / "config.yaml").read_text(encoding="utf-8")

    run_installer("--uninstall", home=commented_profile)
    text = (commented_profile / "config.yaml").read_text(encoding="utf-8")

    assert "hermes-drop" not in read_config(commented_profile)["plugins"]["enabled"]
    assert read_config(commented_profile)["plugins"]["enabled"] == ["local-llm-polished"]
    assert comment_lines(text) == comment_lines(installed), "uninstall lost comments"
    removed = [ln for ln in installed.splitlines() if ln not in text.splitlines()]
    assert removed == ["    - hermes-drop"], removed


def test_uninstall_keeps_operator_changes_made_after_install(profile: Path) -> None:
    """L6's real damage: ``mv``-ing a backup over config.yaml discards later edits.

    A backup is a snapshot of a moment. Restoring it silently reverts everything
    the operator did since — a new MCP server, a model change, an allowlist entry —
    none of which has anything to do with Drop.
    """
    run_installer("install", home=profile)

    # An operator change after install, of the kind the old --uninstall ate.
    config = profile / "config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8") + "mcp_servers:\n  added_later: {url: 'https://x'}\n",
        encoding="utf-8",
    )

    run_installer("--uninstall", home=profile)
    after = read_config(profile)

    assert "added_later" in (after.get("mcp_servers") or {}), (
        "--uninstall reverted an unrelated operator change"
    )
    assert "hermes-drop" not in after["plugins"]["enabled"]
    assert "spotify" in after["plugins"]["enabled"]
    # And the legacy plugin install retired is NOT resurrected.
    assert "hermes-drop-command" not in after["plugins"]["enabled"]


def test_uninstall_removes_the_entry_when_install_was_a_config_no_op(profile: Path) -> None:
    """L6's second half: no backup existed, so the old code left a dangling entry.

    The second install is a config no-op and takes no backup. ``--uninstall`` then
    had nothing to restore, removed the plugin directory, and left ``hermes-drop``
    in ``plugins.enabled`` pointing at nothing.
    """
    run_installer("install", home=profile)
    run_installer("install", home=profile)  # no-op; takes no backup

    run_installer("--uninstall", home=profile)

    assert "hermes-drop" not in read_config(profile)["plugins"]["enabled"], (
        "the plugin directory went but the enabled entry stayed, pointing at nothing"
    )
    assert not (profile / "plugins" / "hermes-drop").exists()


def test_uninstall_does_not_consume_the_backup_it_finds(profile: Path) -> None:
    """Backups are audit artefacts now, not a restore source. They are kept."""
    run_installer("install", home=profile)
    install_backups = sorted(profile.glob("config.yaml.hermes-drop-backup-*"))
    assert len(install_backups) == 1

    result = run_installer("--uninstall", home=profile)

    assert install_backups[0].exists(), "the install backup was consumed"
    assert "no config.yaml backup was restored" in result.stdout.lower()


def test_uninstall_is_idempotent(profile: Path) -> None:
    run_installer("install", home=profile)
    run_installer("--uninstall", home=profile)
    first = read_config(profile)
    result = run_installer("--uninstall", home=profile)
    assert read_config(profile) == first
    assert "was not in plugins.enabled" in result.stdout


# ── L7: no hardcoded default-profile interpreter ────────────────────────────


def test_the_installer_never_names_the_default_profile_path() -> None:
    """L7. The one line that contradicted the script's own header.

    ``resolve_python`` ended with ``$HOME/.hermes/hermes-agent/venv/bin/python``, in
    a script whose premise is that ``~/.hermes`` is never guessed. Only an
    interpreter, so harmless in effect — but it meant
    ``HERMES_HOME=/srv/profiles/staging install`` could run the default profile's
    python. Any remaining reference must be *derived* from ``$HERMES_HOME``.
    """
    source = INSTALLER.read_text(encoding="utf-8")
    interpreter_block = source.split("resolve_python()", 1)[1].split("\n}", 1)[0]

    assert "$HOME/.hermes" not in interpreter_block, (
        "resolve_python still names the default profile directly"
    )
    assert "$home/hermes-agent" in interpreter_block, (
        "the profile-derived fallback should come from the named HERMES_HOME"
    )
    # And the usage text still points at the override rather than at a fixed path.
    assert "HERMES_DROP_PYTHON" in source


def test_the_interpreter_override_is_honoured(profile: Path, tmp_path: Path) -> None:
    """``HERMES_DROP_PYTHON`` is the documented escape hatch, so it must work.

    A wrapper that records being called and then delegates: proof the script ran
    *this* interpreter rather than falling through to one it found itself.
    """
    marker = tmp_path / "chosen-interpreter.log"
    wrapper = tmp_path / "python-wrapper"
    wrapper.write_text(
        "#!/bin/sh\n" f'printf "called\\n" >> "{marker}"\n' f'exec "{sys.executable}" "$@"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)

    env = dict(os.environ)
    env["HERMES_HOME"] = str(profile)
    env["HERMES_DROP_PYTHON"] = str(wrapper)
    result = subprocess.run(
        [str(INSTALLER), "install"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
        timeout=60,
    )

    assert result.returncode == 0, result.stderr
    assert marker.exists(), "HERMES_DROP_PYTHON was ignored"
    assert "hermes-drop" in read_config(profile)["plugins"]["enabled"]


def test_a_missing_interpreter_is_a_clear_preflight_failure(profile: Path, tmp_path: Path) -> None:
    """With no usable python anywhere, the script says so and names the override —
    rather than reaching for a path it happens to know about."""
    # A PATH with the coreutils the script needs and no python at all.
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for tool in (
        # `env` and `bash` for the shebang itself; the rest are what the script calls.
        "env", "bash", "sh", "basename", "cat", "cp", "date", "ln", "ls", "mkdir",
        "rm", "sort", "stat", "tail", "tar",
    ):
        found = shutil.which(tool)
        if found:
            (fake_bin / tool).symlink_to(found)

    env = dict(os.environ)
    env["HERMES_HOME"] = str(profile)
    env["PATH"] = str(fake_bin)
    env.pop("HERMES_DROP_PYTHON", None)
    env.pop("VIRTUAL_ENV", None)

    result = subprocess.run(
        [str(INSTALLER), "install"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
        timeout=60,
    )

    assert result.returncode != 0
    assert "HERMES_DROP_PYTHON" in result.stderr, result.stderr
    assert "PyYAML" in result.stderr
    assert not (profile / "plugins" / "hermes-drop").exists(), (
        "the interpreter check must fail before anything is created"
    )
