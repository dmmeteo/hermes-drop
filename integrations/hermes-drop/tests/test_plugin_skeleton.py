"""S3 — plugin skeleton: discovery, toolset gating, and the config gate.

Four things are pinned here, each because it is load-bearing for a later slice:

* **Symlink discovery.** The installer links ``$HERMES_HOME/plugins/hermes-drop``
  at the in-repo source rather than copying it, so the repo stays the source of
  truth (plan §9). Core's scanner filters on ``child.is_dir()``
  (``hermes_cli/plugins.py:1542-1546``), which follows symlinks — but that is an
  incidental property of an ``is_dir()`` call, not a documented promise, so it
  gets a test.

* **Toolset reaches Discord *and* Telegram with no config edit.** A new plugin
  toolset defaults on per platform unless ``known_plugin_toolsets`` already
  records that platform (``hermes_cli/tools_config.py:2323-2342``).

* **The ``check_fn`` verdict is process-constant.** A gate that probed a live
  socket would flap across a broker restart and mutate the tool schema
  mid-conversation, which the prompt cache treats as a new prefix (plan §5.2).

* **No ``gateway.run`` at plugin module scope.** ``gateway/run.py`` is ~25.7k
  lines and gets pulled into every CLI process that merely *discovers* plugins;
  worse, a module-scope ``from gateway.run import _gateway_runner_ref`` would
  permanently capture the ``lambda: None`` sentinel (``gateway/run.py:3121``)
  because the real ref is rebound later in ``GatewayRunner.__init__``
  (``:5513, 5536``).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from conftest import HERMES_CHECKOUT, PLUGIN_DIR, load_plugin_package


@pytest.fixture
def installed_profile(temp_hermes_home: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A temp profile with hermes-drop symlinked in and enabled."""
    (temp_hermes_home / "plugins" / "hermes-drop").symlink_to(PLUGIN_DIR, target_is_directory=True)
    (temp_hermes_home / "config.yaml").write_text(
        "plugins:\n  enabled:\n    - hermes-drop\n",
        encoding="utf-8",
    )
    # Keep bundled discovery out of the picture: this asserts user-dir symlink
    # discovery, and loading the checkout's real bundled plugins would drag in
    # unrelated modules and unrelated failure modes.
    empty_bundled = temp_hermes_home / "empty-bundled"
    empty_bundled.mkdir()
    monkeypatch.setenv("HERMES_BUNDLED_PLUGINS", str(empty_bundled))
    return temp_hermes_home


def test_symlinked_plugin_is_discovered_and_loaded(installed_profile: Path) -> None:
    from hermes_cli.plugins import PluginManager

    manager = PluginManager()
    manager.discover_and_load(force=True)

    entries = {p["key"]: p for p in manager.list_plugins()}
    assert "hermes-drop" in entries, f"hermes-drop not discovered; saw {sorted(entries)}"
    entry = entries["hermes-drop"]
    assert entry["enabled"] is True, entry["error"]
    assert entry["error"] is None
    assert entry["tools"] >= 1


def test_plugin_toolset_reaches_discord_and_telegram_with_no_config_edit(
    installed_profile: Path,
) -> None:
    from hermes_cli.plugins import discover_plugins
    from hermes_cli.tools_config import _get_platform_tools

    discover_plugins(force=True)

    # A profile that has run `hermes tools` for discord (recording spotify only)
    # and has never run it for telegram. Neither records hermes_drop, so the
    # toolset defaults on for both.
    config = {
        "plugins": {"enabled": ["hermes-drop"]},
        "known_plugin_toolsets": {"cli": ["spotify"], "discord": ["spotify"]},
    }

    for platform in ("discord", "telegram"):
        enabled = _get_platform_tools(config, platform)
        assert "hermes_drop" in enabled, (
            f"hermes_drop toolset not enabled for {platform}: {sorted(enabled)}"
        )


def test_toolset_is_disabled_when_the_operator_has_turned_it_off(
    installed_profile: Path,
) -> None:
    """The default-on rule must still honour an explicit operator decision."""
    from hermes_cli.plugins import discover_plugins
    from hermes_cli.tools_config import _get_platform_tools

    discover_plugins(force=True)
    config = {
        "plugins": {"enabled": ["hermes-drop"]},
        # `hermes tools` was saved for discord and hermes_drop was NOT picked:
        # known-but-absent means the user disabled it.
        "known_plugin_toolsets": {"discord": ["spotify", "hermes_drop"]},
        "platform_toolsets": {"discord": ["spotify"]},
    }
    assert "hermes_drop" not in _get_platform_tools(config, "discord")


def test_check_fn_is_process_constant_across_socket_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = tmp_path / "run" / "control.sock"
    socket_path.parent.mkdir(mode=0o700)
    socket_path.write_bytes(b"")  # stand-in for a live socket file
    monkeypatch.setenv("HERMES_DROP_CONTROL_SOCKET", str(socket_path))

    plugin = load_plugin_package()
    check_fn = plugin.drop_check_fn

    first = check_fn()
    socket_path.unlink()
    second = check_fn()

    assert first is True
    assert second is first, "check_fn flapped when the socket disappeared"


def _run_in_fresh_interpreter(body: str) -> subprocess.CompletedProcess:
    script = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, {str(HERMES_CHECKOUT)!r})
        sys.path.insert(0, {str(PLUGIN_DIR.parent.parent / 'integrations' / 'hermes-drop' / 'tests')!r})
        from conftest import load_plugin_package
        {textwrap.indent(textwrap.dedent(body), '        ').lstrip()}
        """
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(HERMES_CHECKOUT)
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(HERMES_CHECKOUT),
        env=env,
        timeout=120,
    )


def test_register_does_not_import_gateway_run_at_module_scope() -> None:
    result = _run_in_fresh_interpreter(
        """
        import sys

        class FakeManifest:
            name = "hermes-drop"
            key = "hermes-drop"
            source = "user"

        class FakeCtx:
            manifest = FakeManifest()
            def __init__(self):
                self.tools = []
                self.hooks = []
                self.commands = []
            def register_tool(self, name, toolset, schema, handler, **kw):
                self.tools.append((name, toolset, kw))
            def register_hook(self, hook_name, callback):
                self.hooks.append(hook_name)
            def register_command(self, name, handler, description="", args_hint=""):
                self.commands.append(name)

        plugin = load_plugin_package()
        assert "gateway.run" not in sys.modules, "gateway.run imported at plugin import"
        ctx = FakeCtx()
        plugin.register(ctx)
        assert "gateway.run" not in sys.modules, "gateway.run imported by register()"
        assert ctx.tools, "register() registered no tools"
        print("OK", len(ctx.tools))
        """
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert result.stdout.strip().startswith("OK")


def test_check_fn_verdict_latches_at_first_call() -> None:
    """Latched means latched: a socket configured *after* the first call is
    deliberately not picked up, because a verdict that can change is a verdict
    that can rebuild the tool schema mid-conversation."""
    result = _run_in_fresh_interpreter(
        """
        import os
        os.environ.pop("HERMES_DROP_CONTROL_SOCKET", None)
        os.environ["HERMES_DROP_CONTROL_SOCKET"] = ""
        plugin = load_plugin_package()
        first = plugin.drop_check_fn()
        os.environ["HERMES_DROP_CONTROL_SOCKET"] = "/tmp/does-not-matter.sock"
        second = plugin.drop_check_fn()
        assert first is False, first
        assert second is False, "verdict changed after first call"
        print("OK")
        """
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
