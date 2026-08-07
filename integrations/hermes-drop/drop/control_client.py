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

#: contract/control-protocol.json -> version. The protocol *this client*
#: implements, not the one it is talking to — see :func:`supports_lossless_claim`.
PROTOCOL_VERSION = 2

#: contract/control-protocol.json -> errors
ERRORS: Sequence[str] = ("invalid_request", "response_too_large", "unavailable")

#: The broker refused *before consuming* because the answer would not fit in the
#: ``max_response_bytes`` this client advertised. Named because it is the one
#: broker error a caller must not treat like ``unavailable``: the payload is
#: untouched and still claimable, so marking the drop spent would manufacture the
#: loss the refusal just prevented.
RESPONSE_TOO_LARGE = "response_too_large"

#: Local-only error kinds. These are *transport* verdicts the client itself
#: produces; the broker never sends them. Kept distinct from ERRORS so a caller
#: can tell "the broker answered" from "the broker did not".
BROKER_UNAVAILABLE = "broker_unavailable"

DEFAULT_TIMEOUT_SECONDS = 10.0

#: contract/control-protocol.json -> transport.max_response_bytes
#:
#: A response line is bounded too, and this constant is the bound that is
#: **actually applied** — it is passed to ``open_unix_connection`` as the
#: ``StreamReader`` limit, so ``readline`` refuses to buffer past it — *and* the
#: bound this client declares on every ``claim``, so the broker sizes its answer
#: against it before consuming anything. One number doing both jobs is the point:
#: a limit the reader enforces but never states is a limit the broker can only
#: discover by destroying a payload.
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
#: ``maxPlaintextBytes``-sized claim must round-trip byte for byte, a line past
#: *this* limit must still come back as a dict, and a claim the broker sizes past
#: it must come back as ``response_too_large`` with the payload still there.
MAX_RESPONSE_BYTES = 1024 * 1024

#: contract/control-protocol.json -> transport.min_response_bytes
#:
#: The floor the broker puts under an advertised ceiling. Nothing here goes
#: anywhere near it — this client advertises a megabyte — but it is the number
#: that makes the refusal *readable*: every non-payload line, ``response_too_large``
#: included, fits inside it, so no conforming client is ever answered with a
#: refusal it cannot buffer. Pinned against the fixture by the tests.
MIN_RESPONSE_BYTES = 1024

#: Every size in this module is of the whole line as written to the socket,
#: **newline included** (contract ``transport.size_convention``). That is not a
#: detail: ``StreamReader`` applies its limit to the line plus its separator, so a
#: broker that counted the newline out would size a claim as fitting when the
#: reader would refuse it by one byte. ``src/control-server.js``'s
#: ``claimResponseBytes`` counts it in, and a test reads a line of exactly the
#: limit to prove the two conventions are the same one.

#: Room for the JSON around the payload: ``{"ok":true,"plaintext_b64":"…"}`` and a
#: newline, with generous slack for any field the protocol grows.
_CLAIM_ENVELOPE_SLACK_BYTES = 4096

#: The largest broker ``maxPlaintextBytes`` whose base64 claim response still fits
#: inside :data:`MAX_RESPONSE_BYTES` — the read limit is a constant, so this is the
#: bound it implies (review N2). base64 is ×4/3, with slack for the JSON envelope,
#: so it is deliberately a little under what the broker's own exact arithmetic
#: (``claimPayloadBudget``, ``src/control-server.js``) will allow.
#:
#: Above this a claim is *refused* rather than delivered: the broker sizes the
#: answer against the advertised ceiling and answers ``response_too_large`` with
#: the record untouched. That is no longer a destroyed secret — it used to be,
#: before the ceiling was on the wire — but it is still an undeliverable one, and
#: the user has already typed it into the form by then. So the plugin's job is
#: unchanged: notice at *create* time, while a drop is still only a drop.
#: ``compose.yml`` pins 65536, an order of magnitude clear of it.
MAX_CLAIMABLE_PLAINTEXT_BYTES = ((MAX_RESPONSE_BYTES - _CLAIM_ENVELOPE_SLACK_BYTES) // 4) * 3

PathLike = Union[str, "os.PathLike[str]"]


def _err(error: str, detail: str) -> Dict[str, Any]:
    return {"ok": False, "error": error, "detail": detail}


def supports_lossless_claim(created: Optional[Mapping[str, Any]]) -> bool:
    """Does the broker that answered *created* refuse an oversized claim?

    Only protocol 2 and above sizes a claim response before consuming it. A
    version 1 broker accepts ``max_response_bytes``, ignores it, and destroys the
    payload as it answers — so sending the field proves nothing, and the answer
    has to be read rather than assumed. This repo ships both halves together but
    a Hermes-side plugin does not: it is installed once and upgraded on its own
    schedule, against whatever broker is deployed.

    Absence is the version 1 answer, because version 1 published no version at
    all. Anything that is not an ``int`` (a ``bool`` included, which ``int``
    otherwise admits) is treated the same way: unknown is not "probably fine"
    when the thing being decided is whether a secret can be destroyed.
    """
    if not isinstance(created, Mapping):
        return False
    version = created.get("protocol_version")
    if isinstance(version, bool) or not isinstance(version, int):
        return False
    return version >= PROTOCOL_VERSION


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
    """Consume the payload exactly once. The only op that returns plaintext.

    Always advertises :data:`MAX_RESPONSE_BYTES`, which is the same limit
    ``_exchange`` hands ``open_unix_connection``. A broker that cannot fit its
    answer inside it answers ``response_too_large`` and consumes nothing, so the
    one line this client could fail to read is a line it is never sent.
    """
    return await control_request(
        {
            "op": "claim",
            "handoff_id": handoff_id,
            "wait_ms": int(wait_ms),
            "max_response_bytes": MAX_RESPONSE_BYTES,
        },
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
    "MIN_RESPONSE_BYTES",
    "NOTICE_PLATFORMS",
    "PROTOCOL_VERSION",
    "RESPONSE_TOO_LARGE",
    "await_submission",
    "claim",
    "control_request",
    "create",
    "supports_lossless_claim",
]
