"""Where the broker's control socket is, and whether Drop is configured at all.

**The gate is process-constant on purpose** (plan §5.2). ``check_fn`` results
decide whether a tool's schema is in the prompt. A gate that probed the live
socket would flip to ``False`` every time ``docker compose up`` restarted the
broker and back to ``True`` a second later, adding and removing a tool
*mid-conversation* — which invalidates the per-conversation prompt cache prefix
that ``AGENTS.md`` treats as sacred. Core already TTL-caches ``check_fn`` for
30 s with a 60 s failure grace (``tools/registry.py:216-218``), so a
plugin-side cache would be dead weight on top of a gate that should not be
probing in the first place.

So the verdict answers a *configuration* question — "is a control socket path
configured?" — which is rung 3 of the Footprint Ladder, and it is latched at
first call.

**Honest note on how much that gate actually filters.** Because there is a
documented default path, the answer is ``True`` unless the operator explicitly
sets ``HERMES_DROP_CONTROL_SOCKET=""`` (or ``plugins.entries.hermes-drop.control_socket: ""``)
to opt out. This is a kill switch, not a discovery mechanism. Whether the broker
is *reachable* is a runtime condition and is reported as
``{"error": "broker_unavailable"}`` from the call site — never by removing the
tool from the schema.
"""

from __future__ import annotations

import os
from typing import Optional

#: Environment override. An explicitly empty value means "not configured" and
#: switches the tools off; unset means "fall through".
CONTROL_SOCKET_ENV = "HERMES_DROP_CONTROL_SOCKET"

#: Plugin id used for ``plugins.entries.<id>`` lookups in config.yaml.
PLUGIN_ID = "hermes-drop"

#: Config key under ``plugins.entries.hermes-drop``.
CONTROL_SOCKET_CONFIG_KEY = "control_socket"

#: Documented default, matching ``contract/control-protocol.json``
#: ``transport.default_socket_path`` and ``compose.yml``'s bind mount.
DEFAULT_CONTROL_SOCKET = "/run/handoff/control.sock"

# Latched at first read. `None` means "not yet resolved"; a resolved value is
# either a non-empty path string or "" for explicitly-not-configured.
_latched_socket_path: Optional[str] = None


def _read_plugin_config_socket() -> Optional[str]:
    """Return the configured socket path from config.yaml, or ``None``.

    Imported lazily: ``hermes_cli.config`` is not needed to *register* the
    plugin, only to answer the gate, and plugin registration happens in every
    CLI process.
    """
    try:
        from hermes_cli.config import load_config

        cfg = load_config() or {}
    except Exception:
        return None
    entries = (cfg.get("plugins") or {}).get("entries") or {}
    entry = entries.get(PLUGIN_ID) or {}
    if not isinstance(entry, dict) or CONTROL_SOCKET_CONFIG_KEY not in entry:
        return None
    raw = entry.get(CONTROL_SOCKET_CONFIG_KEY)
    return "" if raw is None else str(raw).strip()


def _resolve_control_socket_path() -> str:
    env_raw = os.environ.get(CONTROL_SOCKET_ENV)
    if env_raw is not None:
        return env_raw.strip()

    configured = _read_plugin_config_socket()
    if configured is not None:
        return configured

    return DEFAULT_CONTROL_SOCKET


def control_socket_path() -> str:
    """The control socket path, latched at first resolution.

    Latching is not an optimisation — it is what makes :func:`control_socket_configured`
    process-constant. The gate and the call site must agree on one path for the
    life of the process, or a tool could be advertised against one socket and
    invoked against another.
    """
    global _latched_socket_path
    if _latched_socket_path is None:
        _latched_socket_path = _resolve_control_socket_path()
    return _latched_socket_path


def control_socket_configured() -> bool:
    """Process-constant ``check_fn`` verdict. Never touches the filesystem."""
    return bool(control_socket_path())
