"""Async AF_UNIX receiver for the broker's framed file claim.

The Python half of ``begin_file_claim`` / ``commit_file_claim``
(``contract/control-protocol.json`` -> ``file_claim``, and
``src/control-server.js``). It exists at this slice to prove the framing is a
protocol rather than a Node implementation detail: the same conversation, driven
from a different language, against the real broker.

**What it is not.** It is not the spool boundary. It writes no files, creates no
directories, generates no storage names and publishes nothing — that is the next
slice's job, and it is the one that has to be atomic. This module streams the bytes
to a callback and stops, so nothing here can leak a filename into a path or a byte
into durable state.

**Async by construction**, exactly like ``control_client``:
``asyncio.open_unix_connection`` only. Drop's waits run on the gateway loop and a
42 MiB transfer is long enough that doing it in a blocking call would stall every
other session on that loop.

**Never raises.** Every failure comes back as a dict, for the same reason the
control client does it: the callers are a tool handler and a long-lived task, and
an exception escaping either is worse than an error string.

**Never reports success it did not verify, and never reports a failure it cannot
rule on.** The digests it commits are computed over the bytes it actually received,
never copied from the metadata — the metadata does not contain them, deliberately. A
refusal the broker *spoke* means nothing was consumed, so a caller may safely retry.
A connection that closed before the answer is a different thing: if the commit had
already gone out, the payload may have been retired, so the verdict is
``transfer_indeterminate`` and the only safe response is to publish nothing, retry
nothing and mark nothing spent (contract, ``file_claim.client_verdicts``).
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Union

from .config import control_socket_path
from .control_client import (
    BROKER_UNAVAILABLE,
    TRANSFER_FAILED,
    TRANSFER_INDETERMINATE,
    PathLike,
)

#: contract/control-protocol.json -> file_claim.conversation: a uint32 big-endian
#: length in front of each file's bytes.
FRAME_HEADER_BYTES = 4

#: How much of a frame is read at once. Bounded so a 42 MiB file is hashed and
#: handed on in pieces rather than assembled twice in memory.
CHUNK_BYTES = 256 * 1024

#: The metadata line is bounded by the container's manifest ceiling (~6.4 KB at
#: five files), so this is generous. It is stated because ``StreamReader``'s
#: default limit is a footgun on this socket — see ``control_client``'s
#: ``MAX_RESPONSE_BYTES`` for the review that made that concrete.
MAX_LINE_BYTES = 1024 * 1024

DEFAULT_TIMEOUT_SECONDS = 120.0

#: A chunk sink is called **repeatedly per file**, with
#: ``(index, entry, chunk, done)`` — the file's position in the manifest, its
#: metadata entry, the bytes that just arrived, and whether this was the last chunk
#: of that file. Returning an awaitable is allowed so a real consumer can write to
#: disk without blocking the loop.
#:
#: Per chunk and not per file, deliberately. A per-file signature can only be honest
#: if the whole file is first assembled in memory, which is the opposite of what a
#: 42 MiB transfer needs and was how an earlier version of this module ended up
#: handing its sink *zero* bytes whenever nothing was being retained: the digest was
#: computed from the stream while the callback got the empty accumulator. The commit
#: verified, the broker retired the payload, and a spool built on it would have
#: published empty files over the only copy. Streaming the chunks makes the honest
#: path the only path — there is no accumulator to forget to fill.
#:
#: A zero-byte file still calls the sink exactly once, with ``b""`` and
#: ``done=True``, so a consumer that creates files in the callback creates that one
#: too.
ChunkSink = Callable[
    [int, Mapping[str, Any], bytes, bool], Union[None, Awaitable[None]]
]


def _err(error: str, detail: str, **extra: Any) -> Dict[str, Any]:
    return {"ok": False, "error": error, "detail": detail, **extra}


async def _read_exactly(reader: asyncio.StreamReader, count: int) -> bytes:
    """``readexactly`` without the exception: short means the peer went away."""
    try:
        return await reader.readexactly(count)
    except asyncio.IncompleteReadError as exc:
        return exc.partial


async def receive_file_claim(
    handoff_id: str,
    *,
    socket_path: Optional[PathLike] = None,
    lease_ms: Optional[int] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    on_chunk: Optional[ChunkSink] = None,
    keep_bytes: bool = True,
) -> Dict[str, Any]:
    """Run one whole file claim and return a verdict dict.

    On success::

        {"ok": True, "handoff_id": ..., "status": "claimed", "bytes": N,
         "files": [{"name": ..., "size": N, "type": ..., "sha256": "<hex>",
                    "bytes": b"..."}]}

    ``on_chunk`` (see :data:`ChunkSink`) receives every byte as it arrives, whatever
    ``keep_bytes`` is set to — it is the streaming path, and it is where a spool
    writes from. ``keep_bytes`` only decides whether each entry *also* carries the
    assembled ``bytes``; a 42 MiB consumer sets it false and keeps nothing.

    On failure the broker's own ``error`` (``transfer_failed``, ``unavailable``,
    ``invalid_request``) comes back with its ``reason``; a local ``transfer_failed``
    for a failure that provably preceded the commit; ``broker_unavailable`` for a
    socket that was never usable; or ``transfer_indeterminate`` when the commit was
    written and no answer was read. Only the first two mean nothing was consumed.
    """
    path = str(socket_path) if socket_path is not None else control_socket_path()
    if not path:
        return _err(BROKER_UNAVAILABLE, "no control socket is configured")

    # Mutable, because the one thing the timeout handler below has to know is
    # whether the commit had already gone out — and that is decided inside `_claim`.
    progress: Dict[str, Any] = {"commit_written": False}

    try:
        return await asyncio.wait_for(
            _claim(path, handoff_id, lease_ms, on_chunk, keep_bytes, progress),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        if progress["commit_written"]:
            # The commit is out and this client stopped waiting. The broker may have
            # accepted it, retired the payload and had only the answer go unread, so
            # nothing here may claim the payload survived.
            return _err(
                TRANSFER_INDETERMINATE,
                f"{path} did not answer the commit within {timeout:g}s",
                reason="client_timeout_after_commit",
            )
        # Before the commit there is nothing to be ambiguous about. The lease is
        # bounded on the broker's side too, so the transfer this client abandons here
        # is one the broker gives back on its own deadline.
        return _err(TRANSFER_FAILED, f"{path} transfer timed out after {timeout:g}s",
                    reason="client_timeout")
    except (OSError, ConnectionError) as exc:
        if progress["commit_written"]:
            return _err(
                TRANSFER_INDETERMINATE,
                f"{path} connection failed after the commit was written: {exc}",
                reason="transport_after_commit",
            )
        return _err(BROKER_UNAVAILABLE, f"{path} not accepting connections: {exc}")
    except ValueError as exc:
        return _err(BROKER_UNAVAILABLE, f"{path} answered unreadably: {exc}")


async def _claim(
    path: str,
    handoff_id: str,
    lease_ms: Optional[int],
    on_chunk: Optional[ChunkSink],
    keep_bytes: bool,
    progress: Dict[str, Any],
) -> Dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(path, limit=MAX_LINE_BYTES)
    try:
        begin: Dict[str, Any] = {"op": "begin_file_claim", "handoff_id": handoff_id}
        if lease_ms is not None:
            begin["lease_ms"] = int(lease_ms)
        writer.write(json.dumps(begin, separators=(",", ":")).encode("utf-8") + b"\n")
        await writer.drain()

        raw = await reader.readline()
        if not raw:
            return _err(TRANSFER_FAILED, f"{path} closed without answering",
                        reason="connection_closed")
        try:
            metadata = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return _err(TRANSFER_FAILED, f"{path} answered with malformed JSON: {exc}",
                        reason="malformed_metadata")
        if not isinstance(metadata, dict):
            return _err(TRANSFER_FAILED, f"{path} answered with a non-object line",
                        reason="malformed_metadata")
        if not metadata.get("ok"):
            # The broker's own refusal, forwarded verbatim: `unavailable` means the
            # drop is over, `transfer_failed` means it is not.
            return dict(metadata)

        entries = metadata.get("files")
        if not isinstance(entries, list):
            return _err(TRANSFER_FAILED, "metadata carried no file list",
                        reason="malformed_metadata")

        files: List[Dict[str, Any]] = []
        received = 0
        # One frame at a time, each acked before the broker sends the next. The ack is
        # what makes receipt size-independent: the broker stops and waits, so no socket
        # buffer can answer on this receiver's behalf (contract, ``file_claim.receipt``).
        index: Optional[int] = 0
        while index is not None:
            entry = entries[index] if 0 <= index < len(entries) else None
            if not isinstance(entry, dict) or not isinstance(entry.get("size"), int):
                return _err(TRANSFER_FAILED, "metadata entry is not a file",
                            reason="malformed_metadata")
            header = await _read_exactly(reader, FRAME_HEADER_BYTES)
            if len(header) < FRAME_HEADER_BYTES:
                return _err(TRANSFER_FAILED, f"frame {index} header truncated",
                            reason="truncated")
            frame_length = int.from_bytes(header, "big")
            if frame_length != entry["size"]:
                # The advertised size and the framed length are two statements about
                # the same number; a disagreement is a broken transport, not
                # something to reconcile in favour of either one.
                return _err(TRANSFER_FAILED,
                            f"frame {index} length {frame_length} != advertised size",
                            reason="frame_length_mismatch")

            digest = hashlib.sha256()
            collected = bytearray() if keep_bytes else None
            remaining = frame_length
            # An empty file is one call with `b""`, so a consumer that creates files
            # in the callback creates that one too. Everything else is one call per
            # chunk, and the digest and the sink see the *same* bytes on the same
            # pass — there is no accumulator that can be filled for one and not the
            # other.
            if frame_length == 0 and on_chunk is not None:
                await _deliver(on_chunk, index, entry, b"", True)
            while remaining > 0:
                chunk = await _read_exactly(reader, min(CHUNK_BYTES, remaining))
                if not chunk:
                    return _err(TRANSFER_FAILED, f"frame {index} truncated",
                                reason="truncated")
                digest.update(chunk)
                if collected is not None:
                    collected.extend(chunk)
                remaining -= len(chunk)
                received += len(chunk)
                if on_chunk is not None:
                    await _deliver(on_chunk, index, entry, chunk, remaining == 0)

            files.append(
                {
                    "name": entry.get("name"),
                    "type": entry.get("type"),
                    "size": frame_length,
                    "sha256": digest.hexdigest(),
                    **({"bytes": bytes(collected)} if collected is not None else {}),
                }
            )

            # The ack, over the bytes that actually arrived. The broker checks it
            # against the manifest — which it holds and this client was never given —
            # before it writes anything else.
            ack = {
                "op": "ack_frame",
                "transfer_id": metadata.get("transfer_id"),
                "index": index,
                "size": frame_length,
                "sha256": digest.hexdigest(),
            }
            writer.write(json.dumps(ack, separators=(",", ":")).encode("utf-8") + b"\n")
            await writer.drain()

            ack_line = await reader.readline()
            if not ack_line:
                return _err(TRANSFER_FAILED, f"frame {index} ack was not answered",
                            reason="connection_closed", index=index)
            try:
                answered = json.loads(ack_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                return _err(TRANSFER_FAILED, f"frame {index} ack answered unreadably: {exc}",
                            reason="malformed_answer", index=index)
            if not isinstance(answered, dict) or not answered.get("ok"):
                # The broker's own refusal, forwarded verbatim.
                return dict(answered) if isinstance(answered, dict) else _err(
                    TRANSFER_FAILED, f"frame {index} ack answered with a non-object line",
                    reason="malformed_answer", index=index
                )
            next_index = answered.get("next_index")
            if next_index is not None and not isinstance(next_index, int):
                return _err(TRANSFER_FAILED, "ack answered with a non-integer next_index",
                            reason="malformed_answer", index=index)
            index = next_index

        commit = {
            "op": "commit_file_claim",
            "handoff_id": handoff_id,
            "transfer_id": metadata.get("transfer_id"),
            "received_bytes": received,
            # Computed here, over what arrived. The broker never sent these, which
            # is what makes the commit evidence rather than an echo.
            "digests": [file["sha256"] for file in files],
        }
        # Set BEFORE the write, deliberately. ``transport.close()`` flushes what is
        # already buffered, so a cancellation landing between the write and the flag
        # could deliver the commit while this client still reported
        # ``transfer_failed``/``client_timeout`` — the exact confusion the
        # indeterminate verdict exists to prevent. Erring the other way costs a
        # conservative verdict on a commit that never left, which is the safe
        # direction: the caller publishes nothing and retries nothing either way.
        progress["commit_written"] = True
        writer.write(json.dumps(commit, separators=(",", ":")).encode("utf-8") + b"\n")
        await writer.drain()

        answer_line = await reader.readline()
        if not answer_line:
            # The broker closes without a final line when a lease is lost under a
            # receiver — but this close came *after* a commit went out, so it may
            # equally be a commit that was accepted with only the answer lost. That is
            # unknown, not failed: see `file_claim.client_verdicts` in the contract.
            return _err(
                TRANSFER_INDETERMINATE,
                "connection closed before the commit was answered",
                reason="commit_answer_lost",
            )
        try:
            answer = json.loads(answer_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return _err(TRANSFER_INDETERMINATE, f"commit answered with malformed JSON: {exc}",
                        reason="malformed_answer")
        if not isinstance(answer, dict) or not answer.get("ok"):
            return dict(answer) if isinstance(answer, dict) else _err(
                TRANSFER_INDETERMINATE, "commit answered with a non-object line",
                reason="malformed_answer"
            )

        return {
            "ok": True,
            "handoff_id": answer.get("handoff_id"),
            "status": answer.get("status"),
            "transfer_id": metadata.get("transfer_id"),
            "lease_expires_at": metadata.get("lease_expires_at"),
            "bytes": answer.get("bytes"),
            "file_count": answer.get("files"),
            "files": files,
        }
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            # The server closes its side after the conversation; a reset here is the
            # protocol working, not a failure worth reporting.
            pass


async def _deliver(
    on_chunk: ChunkSink, index: int, entry: Mapping[str, Any], chunk: bytes, done: bool
) -> None:
    """Hand one chunk to the sink, awaiting it if it is a coroutine.

    A sink that writes to disk wants to be async; one that counts bytes does not.
    Both are allowed, and neither is guessed at by signature.
    """
    result = on_chunk(index, entry, chunk, done)
    if inspect.isawaitable(result):
        await result


__all__ = [
    "CHUNK_BYTES",
    "ChunkSink",
    "DEFAULT_TIMEOUT_SECONDS",
    "FRAME_HEADER_BYTES",
    "MAX_LINE_BYTES",
    "receive_file_claim",
]
