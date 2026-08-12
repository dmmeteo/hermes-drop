"""Where the broker's control socket is, where claimed files land, and whether
Drop is configured at all.

Two questions with deliberately different answers about *when* they are resolved:
the socket path is latched for the life of the process (below), and the spool root
and TTL are resolved per call (:func:`spool_root`). The asymmetry is the point —
one of them decides whether a tool is in the prompt, and the other does not.

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
from pathlib import Path
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

#: Where claimed files are materialized (``drop/spool.py``). Env override, then
#: ``plugins.entries.hermes-drop.spool_root``, then a profile-scoped default. An
#: explicitly empty value means "not configured", and unlike the socket that is
#: not merely a kill switch for a tool: with no root there is nowhere private to
#: put bytes, so a file claim must refuse rather than pick somewhere.
SPOOL_ROOT_ENV = "HERMES_DROP_SPOOL_ROOT"
SPOOL_ROOT_CONFIG_KEY = "spool_root"

#: How long a published claim directory may live. 15 minutes is the MVP's
#: figure (``docs/FILE_TRANSFER_MVP.md``): long enough for a model to read or
#: attach what it asked for, short enough that a forgotten claim is not bytes at
#: rest for the life of the gateway.
SPOOL_TTL_ENV = "HERMES_DROP_SPOOL_TTL_SECONDS"
SPOOL_TTL_CONFIG_KEY = "spool_ttl_seconds"
DEFAULT_SPOOL_TTL_SECONDS = 900
MIN_SPOOL_TTL_SECONDS = 60
MAX_SPOOL_TTL_SECONDS = 3600

# Latched at first read. `None` means "not yet resolved"; a resolved value is
# either a non-empty path string or "" for explicitly-not-configured.
_latched_socket_path: Optional[str] = None


def _read_plugin_config(key: str) -> Optional[str]:
    """Return ``plugins.entries.hermes-drop.<key>`` from config.yaml, or ``None``.

    ``None`` means "the key is absent", which is different from an explicitly
    empty value — the caller has to be able to tell "unset, fall through" from
    "set to nothing on purpose".

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
    if not isinstance(entry, dict) or key not in entry:
        return None
    raw = entry.get(key)
    return "" if raw is None else str(raw).strip()


def _read_plugin_config_socket() -> Optional[str]:
    return _read_plugin_config(CONTROL_SOCKET_CONFIG_KEY)


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


def spool_root() -> str:
    """Where claimed files are materialized. ``""`` when explicitly disabled.

    **Resolved per call, and deliberately not latched.** The socket path is
    latched because ``check_fn`` has to be process-constant for the life of a
    prompt cache prefix; nothing about a tool schema depends on where the spool
    is, and a latched value would follow a profile switch into the wrong
    profile's directory — the same argument ``journal.journal_root`` makes.

    Never creates anything: resolving a path in a CLI process that merely
    discovered the plugin must not leave a directory behind.
    """
    env_raw = os.environ.get(SPOOL_ROOT_ENV)
    if env_raw is not None:
        return env_raw.strip()

    configured = _read_plugin_config(SPOOL_ROOT_CONFIG_KEY)
    if configured is not None:
        return configured

    return str(_default_spool_root())


def _default_spool_root() -> str:
    """``$HERMES_HOME/state/hermes-drop/spool``.

    ``get_hermes_home()``, never ``Path.home()`` (``AGENTS.md`` profile rule 1),
    and a sibling of the journal rather than a subdirectory of it: the journal
    globs its own directory for entries, and a directory full of file bytes has
    no business living where a reader is looking for records.

    Outside a Hermes process there is no profile to be scoped to, so this fails
    closed to "not configured" instead of guessing at a path.
    """
    try:
        from hermes_constants import get_hermes_home

        return str(Path(get_hermes_home()) / "state" / "hermes-drop" / "spool")
    except Exception:  # pragma: no cover - a non-Hermes interpreter
        return ""


def spool_configured() -> bool:
    return bool(spool_root())


def spool_ttl_seconds() -> int:
    """How long a published claim survives, clamped rather than refused.

    A clamp and not a refusal because this is an optional knob on a path that
    already holds the only copy of somebody's file: a typo must not be able to
    turn "delete after 15 minutes" into "delete immediately" or "keep for a
    day", and it must not be able to make claiming impossible either.
    """
    raw = os.environ.get(SPOOL_TTL_ENV)
    if raw is None:
        raw = _read_plugin_config(SPOOL_TTL_CONFIG_KEY)
    if raw is None or str(raw).strip() == "":
        return DEFAULT_SPOOL_TTL_SECONDS
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return DEFAULT_SPOOL_TTL_SECONDS
    return max(MIN_SPOOL_TTL_SECONDS, min(MAX_SPOOL_TTL_SECONDS, value))
