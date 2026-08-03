"""Resolve the origin, or refuse. There is no third outcome.

There is no branch anywhere in this module where a missing value becomes a
default, a home channel, or a configured platform. That is the incident restated
as code: ``/drop`` in Telegram put its link in a Discord channel because the only
generic send available fell back to ``config.get_home_channel(platform)`` when no
chat id was given (``tools/send_message_tool.py:446-465``).

Resolution order (plan §4), then a **mandatory** verification:

1. ``sources.turn_source()`` — the same-turn ContextVar.
2. ``REGISTRY.by_routing_tuple(routing_tuple_from_context())`` — the wake-turn
   path, available even on internal turns where the capture hook never fires
   (``gateway/run.py:13633``).
3. ``REGISTRY.by_session_key(HERMES_SESSION_KEY)`` — for a lane that drifted.
4. Nothing → ``no_origin``.

Whatever is found must then agree with the bound contextvars on
``(platform, profile, chat_id, thread_id)``, or it is refused. This is *not*
revision 1's deleted cross-turn origin stamp, which compared two values derived
from the same ``SessionSource`` and was unreachable by construction. It is
reachable two ways, both tested: an inherited foreign ``_TURN_SOURCE`` on an
internal turn, and a stale store entry after ``_apply_topic_recovery`` rewrote the
lane (``gateway/platforms/base.py:3306-3325``, called ``:5552``).

**Known bounded limitation, stated rather than hidden.** On an internal wake turn
the routing-tuple lookup is the real path; if the lane was rewritten between
initiation and wake, tier 2 misses, tier 3's entry disagrees, and this refuses.
The consequence is that the model cannot open a *new* drop during a continuation
turn and says so; the user types ``/drop``. Claiming is unaffected — it needs no
adapter and no send, only the routing tuple.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

from . import sources

logger = logging.getLogger(__name__)

#: Distinguishes "caller did not supply a runner, resolve one" from "caller
#: supplied ``None``, i.e. there is no runner".
_RUNNER_UNSET = object()

#: Every refusal this module can produce. Each is a *runtime* condition; none of
#: them is ever expressed by changing the tool schema.
ERROR_NO_ORIGIN = "no_origin"
ERROR_ORIGIN_MISMATCH = "origin_mismatch"
ERROR_ORIGIN_UNVERIFIED = "origin_unverified"
ERROR_GATEWAY_UNAVAILABLE = "gateway_unavailable"
ERROR_NO_ADAPTER = "no_adapter"


@dataclass(frozen=True)
class Origin:
    """A resolved, verified origin.

    Frozen on purpose: a mutable origin is a mutable destination, and the whole
    guarantee of this design is that the chat id cannot change after resolution.
    """

    source: Any
    adapter: Any
    runner: Any
    routing_tuple: Tuple[str, str, str, str]
    reply_anchor: Optional[str]
    #: Which lookup tier answered — ``turn_contextvar`` | ``routing_tuple`` |
    #: ``session_key``. Recorded for audit, never used to relax verification.
    tier: str

    @property
    def platform_name(self) -> str:
        return self.routing_tuple[0]

    @property
    def profile(self) -> str:
        return self.routing_tuple[1]

    @property
    def chat_id(self) -> str:
        return self.routing_tuple[2]

    @property
    def thread_id(self) -> str:
        return self.routing_tuple[3]


def _err(error: str, **extra: Any) -> Dict[str, Any]:
    return {"error": error, **extra}


def _resolve_runner() -> Any:
    """Read the live runner handle.

    ``_gateway_runner_ref`` is imported **inside this function**, never at module
    scope. It is a module global initialised to a ``lambda: None`` sentinel
    (``gateway/run.py:3121``) and rebound during ``GatewayRunner.__init__``
    (``:5513, 5536``); a module-scope import executed during plugin discovery —
    which happens at process start, before any runner exists — would capture the
    sentinel permanently. Core's own consumer imports it inside the function for
    exactly this reason (``tools/send_message_tool.py:1823``). It also keeps
    ``gateway/run.py`` (~25.7k lines) out of every CLI process that merely
    discovers plugins.
    """
    try:
        from gateway.run import _gateway_runner_ref

        return _gateway_runner_ref()
    except Exception:
        logger.debug("hermes-drop: no gateway runner available", exc_info=True)
        return None


def resolve_origin(
    *,
    registry: Optional[sources.SourceRegistry] = None,
    runner: Any = _RUNNER_UNSET,
) -> Union[Origin, Dict[str, Any]]:
    """Return an :class:`Origin`, or a ``{"error": ...}`` dict. Never raises."""
    store = registry if registry is not None else sources.REGISTRY

    context_tuple = sources.routing_tuple_from_context()
    session_key = sources.session_key_from_context()

    source: Any = None
    tier = ""

    captured = sources.turn_source()
    if captured is not None:
        source, tier = captured, "turn_contextvar"

    if source is None:
        entry = store.by_routing_tuple(context_tuple)
        if entry is not None:
            source, tier = entry.source, "routing_tuple"

    if source is None and session_key:
        entry = store.by_session_key(session_key)
        if entry is not None:
            source, tier = entry.source, "session_key"

    if source is None:
        # Deliberately NOT reconstructed from ``context_tuple``, even though it
        # would be enough to build a plausible-looking source. See the module
        # docstring: the rebuild is lossy in the fields that decide routing.
        return _err(ERROR_NO_ORIGIN)

    if context_tuple is None:
        # Nothing to verify against. This is today's plugin slash-command path,
        # where ``reset_session_vars()`` has run (``gateway/run.py:13581-13585``)
        # and ``_set_session_env`` has not (``:15641``). Refusing is a deliberate
        # strengthening of §4, which names only ``no_origin`` and
        # ``origin_mismatch``: accepting an unverifiable origin would reintroduce
        # exactly the unverified-identity gap Tier 2 (slice S9) exists to close.
        return _err(ERROR_ORIGIN_UNVERIFIED)

    found_tuple = sources.routing_tuple_for_source(source)
    if found_tuple != context_tuple:
        logger.warning(
            "hermes-drop: refusing origin, captured lane %s does not match bound lane %s",
            found_tuple,
            context_tuple,
        )
        return _err(ERROR_ORIGIN_MISMATCH)

    live_runner = _resolve_runner() if runner is _RUNNER_UNSET else runner
    if live_runner is None:
        return _err(ERROR_GATEWAY_UNAVAILABLE)

    try:
        # The REAL object goes in, so the relay branch
        # (``delivered_via_upstream_relay``) and the transport-provenance branch
        # (``_transport_adapter_ref``) both work, and a stamped secondary profile
        # fails closed (``gateway/authz_mixin.py:80-149``).
        adapter = live_runner._adapter_for_source(source)
    except Exception:
        logger.warning("hermes-drop: adapter resolution raised", exc_info=True)
        return _err(ERROR_NO_ADAPTER)

    if adapter is None:
        return _err(ERROR_NO_ADAPTER)

    return Origin(
        source=source,
        adapter=adapter,
        runner=live_runner,
        routing_tuple=found_tuple,
        reply_anchor=(str(getattr(source, "message_id", None)) if getattr(source, "message_id", None) else None),
        tier=tier,
    )


__all__ = [
    "ERROR_GATEWAY_UNAVAILABLE",
    "ERROR_NO_ADAPTER",
    "ERROR_NO_ORIGIN",
    "ERROR_ORIGIN_MISMATCH",
    "ERROR_ORIGIN_UNVERIFIED",
    "Origin",
    "resolve_origin",
]
