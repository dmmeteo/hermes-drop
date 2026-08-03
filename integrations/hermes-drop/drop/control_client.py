"""Async AF_UNIX client for the broker's control protocol.

Wire format and every constant below are the shared fixture
``contract/control-protocol.json``, which the Node server is held against by
``test/control-protocol.test.js`` and this client is held against by
``tests/test_control_client.py``. One fixture, two languages, no drift.

**Async by construction.** ``asyncio.open_unix_connection`` only — never
``socket.connect``, never a thread. Drop runs its sends and its multi-minute
waits on the gateway loop, so a blocking call here would stall every other
session on that loop (plan §7.1).

**Never raises.** Every failure comes back as a dict, because the callers are a
tool handler and a long-lived waiter task, and an exception escaping either one
is worse than an error string: a raising slash-command handler is swallowed at
``gateway/run.py:14701-14702`` and *falls through to skill resolution*,
resurrecting the ``/skill drop`` path this whole design exists to sever.

**Carries no secret.** The one op that returns plaintext (``claim``) hands the
caller a base64 line and nothing here logs, journals, or re-formats it.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, Mapping, Optional, Sequence, Union

from .config import DEFAULT_CONTROL_SOCKET, control_socket_path

#: contract/control-protocol.json -> transport.max_request_bytes
MAX_REQUEST_BYTES = 4096

#: contract/control-protocol.json -> notice_platforms
NOTICE_PLATFORMS: Sequence[str] = ("discord", "telegram", "plain")

#: contract/control-protocol.json -> errors
ERRORS: Sequence[str] = ("invalid_request", "unavailable")

#: Local-only error kinds. These are *transport* verdicts the client itself
#: produces; the broker never sends them. Kept distinct from ERRORS so a caller
#: can tell "the broker answered" from "the broker did not".
BROKER_UNAVAILABLE = "broker_unavailable"

DEFAULT_TIMEOUT_SECONDS = 10.0

#: A response line is bounded too, and this constant is the bound that is
#: **actually applied** — it is passed to ``open_unix_connection`` as the
#: ``StreamReader`` limit, so ``readline`` refuses to buffer past it.
#:
#: It has to be set deliberately, because asyncio's default is 65536 and a
#: ``claim`` response is base64 of the broker's ``maxPlaintextBytes``
#: (65536, ``src/config.js:11``) — 87,384 bytes, comfortably past that default.
#: Left at the default, any plaintext over roughly 49 KB made ``readline`` raise
#: ``ValueError`` *after* ``broker.claim`` had already detached and retired the
#: payload: the secret was destroyed and the caller was told ``internal_error``
#: (review H2). 1 MiB is generous headroom over the base64 ceiling and still
#: refuses to buffer an unbounded stream from a compromised socket.
#:
#: Pinned from both sides by ``tests/test_control_client.py``: a real
#: ``maxPlaintextBytes``-sized claim must round-trip byte for byte, and a line
#: past *this* limit must still come back as a dict.
MAX_RESPONSE_BYTES = 1024 * 1024

#: Room for the JSON around the payload: ``{"ok":true,"plaintext_b64":"…"}`` and a
#: newline, with generous slack for any field the protocol grows.
_CLAIM_ENVELOPE_SLACK_BYTES = 4096

#: The largest broker ``maxPlaintextBytes`` whose base64 claim response still fits
#: inside :data:`MAX_RESPONSE_BYTES` — the read limit is a constant, so this is the
#: bound it implies (review N2). base64 is ×4/3.
#:
#: Above this the *payload is destroyed*: ``broker.claim`` retires the record
#: before the response is written, so a response the client cannot read is a
#: secret nobody gets. Nothing here can raise the ceiling — it is a property of
#: the constant above — so the plugin's job is to notice at *create* time, while a
#: drop is still only a drop, rather than at claim time when it is a loss.
#: ``compose.yml`` pins 65536, an order of magnitude clear of it.
MAX_CLAIMABLE_PLAINTEXT_BYTES = ((MAX_RESPONSE_BYTES - _CLAIM_ENVELOPE_SLACK_BYTES) // 4) * 3

PathLike = Union[str, "os.PathLike[str]"]


def _err(error: str, detail: str) -> Dict[str, Any]:
    return {"ok": False, "error": error, "detail": detail}


async def control_request(
    payload: Mapping[str, Any],
    *,
    socket_path: Optional[PathLike] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Send one request line, read one response line, return the parsed dict.

    ``socket_path`` defaults to the latched configured path so a caller cannot
    accidentally talk to a socket the ``check_fn`` gate never approved.
    """
    path = str(socket_path) if socket_path is not None else control_socket_path()
    if not path:
        return _err(BROKER_UNAVAILABLE, "no control socket is configured")

    try:
        line = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as exc:
        return {"ok": False, "error": "invalid_request", "detail": f"unserialisable request: {exc}"}

    if len(line) > MAX_REQUEST_BYTES:
        return {
            "ok": False,
            "error": "invalid_request",
            "detail": "request exceeds max_request_bytes",
        }

    try:
        return await asyncio.wait_for(_exchange(path, line), timeout=timeout)
    except asyncio.TimeoutError:
        return _err(BROKER_UNAVAILABLE, f"{path} timed out after {timeout:g}s")
    except (OSError, ConnectionError) as exc:
        return _err(BROKER_UNAVAILABLE, f"{path} not accepting connections: {exc}")
    except ValueError as exc:
        # The backstop for the module's "Never raises" promise. ``_exchange``
        # already converts the one ValueError it expects — an overrun past
        # MAX_RESPONSE_BYTES — into a dict at the point it happens, so reaching
        # here means something below produced one unexpectedly. It is still a
        # transport verdict rather than an exception on the gateway loop: a
        # raising claim is how review H2 destroyed a payload the broker had
        # already retired.
        return _err(BROKER_UNAVAILABLE, f"{path} answered unreadably: {exc}")


async def _exchange(path: str, line: bytes) -> Dict[str, Any]:
    # ``limit=`` is load-bearing, not decoration: asyncio's default StreamReader
    # limit is 65536, and a `claim` response is base64 of up to 65536 plaintext
    # bytes = 87,384. See MAX_RESPONSE_BYTES.
    reader, writer = await asyncio.open_unix_connection(path, limit=MAX_RESPONSE_BYTES)
    try:
        writer.write(line)
        await writer.drain()
        try:
            raw = await reader.readline()
        except ValueError as exc:
            # ``readline`` raises ValueError past the limit — asyncio's
            # ``LimitOverrunError`` is a ValueError subclass. Converted here,
            # where the cause is unambiguous, so the caller gets the same
            # ``broker_unavailable`` verdict as any other transport fault
            # instead of an exception escaping a module documented not to raise.
            return _err(BROKER_UNAVAILABLE, f"{path} answered with an oversized line: {exc}")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            # The server closes its side after one exchange; a reset here is
            # the protocol working, not a failure worth reporting.
            pass

    if not raw:
        return _err(BROKER_UNAVAILABLE, f"{path} closed without answering")

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _err(BROKER_UNAVAILABLE, f"{path} answered with malformed JSON: {exc}")

    if not isinstance(parsed, dict):
        return _err(BROKER_UNAVAILABLE, f"{path} answered with a non-object line")
    return parsed


async def create(
    *,
    ttl_seconds: Optional[int] = None,
    notice_platform: Optional[str] = None,
    socket_path: Optional[PathLike] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Mint one handoff. With ``notice_platform`` the response also carries all
    three notice strings, so posting the waiting message and later editing it
    into a quiet state needs exactly one round trip."""
    request: Dict[str, Any] = {"op": "create"}
    if ttl_seconds is not None:
        request["ttl_seconds"] = int(ttl_seconds)
    if notice_platform is not None:
        request["notice_platform"] = notice_platform
    return await control_request(request, socket_path=socket_path, timeout=timeout)


async def await_submission(
    handoff_id: str,
    *,
    wait_ms: int,
    socket_path: Optional[PathLike] = None,
    timeout: float,
) -> Dict[str, Any]:
    """Park on the broker's own submission waiter — zero polls on either edge.

    ``timeout`` must exceed ``wait_ms``; the broker self-terminates the wait at
    the handoff's expiry (``src/broker.js:315-341``), so the client timeout is
    only a backstop against a wedged socket.
    """
    return await control_request(
        {"op": "await", "handoff_id": handoff_id, "wait_ms": int(wait_ms)},
        socket_path=socket_path,
        timeout=timeout,
    )


async def claim(
    handoff_id: str,
    *,
    wait_ms: int = 0,
    socket_path: Optional[PathLike] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    """Consume the payload exactly once. The only op that returns plaintext."""
    return await control_request(
        {"op": "claim", "handoff_id": handoff_id, "wait_ms": int(wait_ms)},
        socket_path=socket_path,
        timeout=timeout,
    )


__all__ = [
    "BROKER_UNAVAILABLE",
    "DEFAULT_CONTROL_SOCKET",
    "DEFAULT_TIMEOUT_SECONDS",
    "ERRORS",
    "MAX_CLAIMABLE_PLAINTEXT_BYTES",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "NOTICE_PLATFORMS",
    "await_submission",
    "claim",
    "control_request",
    "create",
]
