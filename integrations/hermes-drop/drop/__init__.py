"""Hermes Drop internals.

Import discipline for this whole package: **nothing here may import
``gateway.run`` at module scope.** Two reasons, both verified against source:

1. ``gateway/run.py`` is ~25.7k lines. Plugin discovery runs in *every* CLI
   process, so a module-scope import would pull the entire gateway into
   ``hermes plugins list``.
2. ``_gateway_runner_ref`` is a module global initialised to a
   ``lambda: None`` sentinel (``gateway/run.py:3121``) and **rebound** during
   ``GatewayRunner.__init__`` (``:5513, 5536``). A ``from gateway.run import
   _gateway_runner_ref`` executed at discovery time — before any runner exists
   — would permanently capture the sentinel. Core's own consumer imports it
   inside the function for exactly this reason
   (``tools/send_message_tool.py:1823``).

``test_plugin_skeleton.py::test_register_does_not_import_gateway_run_at_module_scope``
enforces rule 1 in a fresh interpreter.
"""

from __future__ import annotations

from . import (  # noqa: F401
    announce,
    bridge,
    config,
    control_client,
    journal,
    messenger,
    origin,
    reconciler,
    render,
    schemas,
    service,
    sources,
    tools,
    vault,
    waiter,
)

__all__ = [
    "announce",
    "bridge",
    "config",
    "control_client",
    "journal",
    "messenger",
    "origin",
    "reconciler",
    "render",
    "schemas",
    "service",
    "sources",
    "tools",
    "vault",
    "waiter",
]
