"""Shared fixtures for the hermes-drop plugin tests.

These tests live in *this* repo, not in the hermes-agent checkout, so none of
that checkout's ``tests/conftest.py`` applies. Every isolation invariant it
provides has to be re-established here, deliberately and visibly:

1. **Hermetic ``HERMES_HOME``.** Set to a throwaway tempdir *before any hermes
   module is imported*, for the same reason hermes' own conftest does it at
   import time rather than in a fixture: ``hermes_cli.main`` calls
   ``setup_logging()`` at module scope, which resolves ``get_hermes_home()``
   and attaches rotating file handlers. Binding it in a fixture would be too
   late — the handler would already hold an absolute path into the operator's
   real ``~/.hermes/logs``. **No test in this directory may write under
   ``~/.hermes``.** ``test_isolation.py`` asserts that.

2. **No inherited session identity.** ``HERMES_SESSION_*`` is stripped so the
   operator's live gateway session cannot satisfy an origin lookup that should
   have refused.

3. **Repo-root import path.** The hermes checkout is put on ``sys.path`` so
   ``gateway.*`` / ``hermes_cli.*`` import. ``scripts/run_tests.sh`` already
   runs each file with ``cwd`` at the checkout root, so this is belt and
   braces for anyone running ``pytest`` on a single file directly.

4. **Plugin package loaded the way core loads it.** ``load_plugin_package()``
   mirrors ``PluginManager._load_directory_module``
   (``hermes_cli/plugins.py:1865-1887``) exactly: a namespace parent named
   ``hermes_plugins``, a spec built with ``submodule_search_locations``, and
   the module registered as ``hermes_plugins.hermes_drop``. Tests therefore
   exercise the same import shape production does — including the relative
   imports inside the package — rather than a ``sys.path`` shortcut that would
   hide an import bug until install time.
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
PLUGIN_DIR = TESTS_DIR.parent
REPO_ROOT = PLUGIN_DIR.parent.parent
HERMES_CHECKOUT = Path(os.environ.get("HERMES_AGENT_CHECKOUT") or (Path.home() / ".hermes" / "hermes-agent"))

# ── 1. Hermetic HERMES_HOME, bound before any hermes import ────────────────
_SESSION_HERMES_HOME = tempfile.mkdtemp(prefix="hermes-drop-test-home-")
os.environ["HERMES_HOME"] = _SESSION_HERMES_HOME

#: The operator's real profile root, captured for the isolation guard. Nothing
#: in this suite may create or modify anything under it.
REAL_HERMES_HOME = Path.home() / ".hermes"

#: The plugin id the installer manages. Named here so the isolation guard can
#: look for it without importing the plugin.
PLUGIN_ID_UNDER_TEST = "hermes-drop"


def real_profile_signature() -> dict:
    """A cheap fingerprint of everything this suite could plausibly disturb.

    The guard used to assert that ``plugins/hermes-drop`` was simply *absent*,
    which was right while the plugin was unreleased and is wrong now: anyone who
    installs Hermes Drop and then runs its tests has it present, legitimately, and
    would see a failure describing a defect that is not there.

    What was always meant — the file's own docstring says so — is that the suite
    must not *change* the real profile. So the signature is taken once at session
    start and compared at the end. A pre-existing install is fine; an install, an
    uninstall or a config edit that happens during the run is not.
    """
    signature: dict = {}

    config = REAL_HERMES_HOME / "config.yaml"
    try:
        stat = config.stat()
        signature["config.yaml"] = (stat.st_size, stat.st_mtime_ns)
    except OSError:
        signature["config.yaml"] = None

    plugin = REAL_HERMES_HOME / "plugins" / PLUGIN_ID_UNDER_TEST
    try:
        link_stat = plugin.lstat()
        target = os.readlink(plugin) if os.path.islink(plugin) else "<directory>"
        signature["plugins/hermes-drop"] = (target, link_stat.st_mtime_ns)
    except OSError:
        signature["plugins/hermes-drop"] = None

    signature["config backups"] = sorted(
        path.name for path in REAL_HERMES_HOME.glob("config.yaml.hermes-drop-backup-*")
    )
    signature["journal"] = sorted(
        path.name for path in (REAL_HERMES_HOME / "state" / "hermes-drop").glob("*.json")
    )
    return signature


#: Taken at import time — before any test imports hermes, boots a plugin manager
#: or runs the installer. Compared in ``test_isolation.py``.
REAL_PROFILE_AT_SESSION_START = real_profile_signature()

# ── 2. Strip inherited session identity and drop-specific config ───────────
for _name in list(os.environ):
    if _name.startswith("HERMES_SESSION_") or _name.startswith("HERMES_DROP_"):
        del os.environ[_name]

# ── 3. Make the hermes checkout importable ─────────────────────────────────
if HERMES_CHECKOUT.is_dir() and str(HERMES_CHECKOUT) not in sys.path:
    sys.path.insert(0, str(HERMES_CHECKOUT))


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001 - pytest hook
    shutil.rmtree(_SESSION_HERMES_HOME, ignore_errors=True)


# ── 4. Load the plugin package exactly as core does ────────────────────────

_NS_PARENT = "hermes_plugins"
_MODULE_NAME = f"{_NS_PARENT}.hermes_drop"


def load_plugin_package(plugin_dir: Path = PLUGIN_DIR) -> types.ModuleType:
    """Import the plugin the way ``PluginManager._load_directory_module`` does.

    Idempotent within a process: a second call returns the already-imported
    module, mirroring ``sys.modules`` semantics in a live gateway.
    """
    existing = sys.modules.get(_MODULE_NAME)
    if existing is not None:
        return existing

    if _NS_PARENT not in sys.modules:
        ns_pkg = types.ModuleType(_NS_PARENT)
        ns_pkg.__path__ = []  # type: ignore[attr-defined]
        ns_pkg.__package__ = _NS_PARENT
        sys.modules[_NS_PARENT] = ns_pkg

    init_file = plugin_dir / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        _MODULE_NAME,
        init_file,
        submodule_search_locations=[str(plugin_dir)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__package__ = _MODULE_NAME
    module.__path__ = [str(plugin_dir)]  # type: ignore[attr-defined]
    sys.modules[_MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def plugin_module() -> types.ModuleType:
    return load_plugin_package()


@pytest.fixture(autouse=True)
def _reset_plugin_turn_state():
    """Clear the per-turn ContextVar and the shared registry around every test.

    ``scripts/run_tests_parallel.py`` gives each *file* a fresh interpreter, but
    tests within a file share one process and one context — and ``_TURN_SOURCE``
    is exactly the kind of module-level ContextVar that leaks across them. Left
    unreset, a source captured by test A satisfies tier 1 in test B and the
    origin verification refuses for a reason that has nothing to do with test B.

    Production does not need this, and the asymmetry is worth stating: for a
    non-internal event the capture callback overwrites ``_TURN_SOURCE`` within a
    few statements of the turn starting, and for an internal event — where the
    callback never runs (``gateway/run.py:13633``) — an inherited value is caught
    by the mandatory verification in ``resolve_origin`` rather than trusted. A
    test has neither of those, so it gets an explicit reset.
    """
    module = sys.modules.get(_MODULE_NAME)
    if module is None:
        yield
        return
    srcs = module.drop.sources
    srcs._TURN_SOURCE.set(None)
    srcs.REGISTRY.clear()
    try:
        yield
    finally:
        srcs._TURN_SOURCE.set(None)
        srcs.REGISTRY.clear()


@pytest.fixture
def temp_hermes_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fresh throwaway ``HERMES_HOME`` for one test.

    Also clears ``hermes_cli.config``'s mtime/size cache, which is keyed on the
    config path — without that a previous test's config for a *different*
    tempdir can be served for this one when both are written inside the same
    filesystem-timestamp granularity.
    """
    home = tmp_path / "hermes-home"
    (home / "plugins").mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    _clear_config_cache()
    yield home
    _clear_config_cache()


def _clear_config_cache() -> None:
    try:
        from hermes_cli import config as hermes_config
    except Exception:
        return
    for attr in ("_CONFIG_CACHE", "_config_cache", "_LOAD_CONFIG_CACHE"):
        cache = getattr(hermes_config, attr, None)
        if isinstance(cache, dict):
            cache.clear()


# ── Real Node broker, for the control-client tests ─────────────────────────


class BrokerHandle:
    def __init__(self, socket_path: Path, proc: subprocess.Popen, base_url: str = ""):
        self.socket_path = socket_path
        self.proc = proc
        self.base_url = base_url

    def submit(self, url: str, plaintext: str, timeout: float = 30.0) -> str:
        """Submit through the real browser-facing client, in the harness.

        ``--public`` mode only. The envelope, the capability header and the
        one-shot semantics are the production ones (``src/client/handoff-client.js``),
        so a waiter parked on a real ``await`` is woken by a real submission.
        """
        encoded = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        assert self.proc.stdin is not None
        self.proc.stdin.write(f"SUBMIT {url} {encoded}\n")
        self.proc.stdin.flush()
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline().strip()
        return line

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

    def crash(self) -> None:
        """SIGKILL. Not ``stop()``.

        ``stop()`` sends SIGTERM, the harness runs its shutdown hook, the control
        server closes and unlinks its socket. A restart-recovery test must not
        rely on any of that having happened: a broker that dies for real runs no
        hook and leaves the socket file behind. ``startControlServer`` removes a
        stale one before it listens (``src/control-server.js:85``), which is what
        makes booting again on the same path the *production* behaviour rather
        than a test convenience.
        """
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=10)


def _boot_broker(tmp_path: Path, *, public: bool):
    """Boot the repo's actual Node broker on a temp socket.

    Skips rather than fails when ``node`` is absent: a missing toolchain is an
    environment fact, not a defect in the code under test. When node IS present
    this is a genuine cross-language check against
    ``contract/control-protocol.json`` rather than against a fake that was
    written to agree with it.
    """
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; cannot boot the real broker")

    socket_dir = tmp_path / ("run-public" if public else "run")
    # ``exist_ok`` because a restart reuses the directory *and* the socket path:
    # the plugin has one configured path and a broker that comes back has to come
    # back on it. See ``restartable_public_broker``.
    #
    # The chmod is not belt and braces. ``mkdir(mode=…)`` is subject to umask on
    # creation and is ignored entirely when the directory already exists, so a
    # restarted broker's socket directory would keep whatever mode the first
    # ``mkdir`` happened to land on. 0700 before the socket exists is the same
    # ordering ``prepareSocketDir`` argues for (``src/control-server.js:35-54``):
    # the socket is created by ``listen()`` with the process umask and can only be
    # tightened afterwards, so the directory has to be closed first.
    socket_dir.mkdir(mode=0o700, exist_ok=True)
    socket_dir.chmod(0o700)
    socket_path = socket_dir / "control.sock"
    harness = TESTS_DIR / "broker_harness.mjs"

    argv = [node, str(harness), str(socket_path)]
    if public:
        argv.append("--public")

    proc = subprocess.Popen(
        argv,
        cwd=str(REPO_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    handle = BrokerHandle(socket_path, proc)

    deadline = time.monotonic() + 30
    ready = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            handle.stop()
            pytest.fail(f"broker harness exited early: {proc.stderr.read()}")
        line = proc.stdout.readline()
        if line.startswith("READY "):
            ready = True
            if not public:
                break
        elif line.startswith("BASE_URL "):
            handle.base_url = line.split(" ", 1)[1].strip()
            break
    if not ready or (public and not handle.base_url):  # pragma: no cover - wedged harness
        handle.stop()
        pytest.fail("broker harness never reported READY")

    return handle


@pytest.fixture
def real_broker(tmp_path: Path):
    """Control socket only — no port is opened."""
    handle = _boot_broker(tmp_path, public=False)
    try:
        yield handle
    finally:
        handle.stop()


@pytest.fixture
def real_public_broker(tmp_path: Path):
    """Control socket **and** the public listener, so a real submit is possible.

    Loopback on an ephemeral port, dialled only by the harness process itself.
    This is the one fixture that can prove the full loop: mint → post → park on
    a real ``await`` → real HPKE submission → wake → claim.
    """
    handle = _boot_broker(tmp_path, public=True)
    try:
        yield handle
    finally:
        handle.stop()


@pytest.fixture
def restartable_public_broker(tmp_path: Path):
    """Boot public brokers on demand, all on the **same** control socket path.

    The one fixture that can express a restart. ``real_public_broker`` yields a
    single handle and stops it, which is right for every test that treats the
    broker as a fixed part of the world; this one hands back a callable so a test
    can kill a broker and boot its replacement where the plugin will still look
    for it. Each handle is stopped at teardown, including one already killed.
    """
    handles: list = []

    def boot() -> BrokerHandle:
        handle = _boot_broker(tmp_path, public=True)
        handles.append(handle)
        return handle

    try:
        yield boot
    finally:
        for handle in handles:
            handle.stop()


@pytest.fixture
def gateway_loop():
    """A real asyncio loop on its own thread, standing in for ``_gateway_loop``.

    The tool handlers run on a ``ThreadPoolExecutor`` worker
    (``gateway/run.py:18604`` → ``:20276-20285``) and cross to the gateway loop
    once, through ``SyncBridge``. A test that awaited the service directly would
    skip that crossing entirely — and the crossing is where two of revision 1's
    bugs lived.
    """
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, name="test-gateway-loop", daemon=True)
    thread.start()
    try:
        yield loop
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5)
        loop.close()
