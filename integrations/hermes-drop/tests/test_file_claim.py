"""Slice 3 interoperability — the framed file claim, driven from Python.

The Node suite (``test/file-claim-transfer.test.js``) proves the protocol against
a Node receiver. That leaves one thing unproven, and it is the thing that matters
most for the slice after this one: whether the framing is a *protocol* or an
accident of two halves written in the same language on the same afternoon. So
these tests drive the real broker — booted by ``broker_harness.mjs``, submitted to
through the real browser-facing client — with a receiver that shares no code with
it at all.

What is deliberately absent: any spool. Nothing here writes a file, creates a
directory or generates a storage name. That is slice 4, and it is the slice whose
whole difficulty is being atomic; a half-built version of it here would be the
worst of both.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

from conftest import REPO_ROOT, load_plugin_package

CONTRACT = json.loads((REPO_ROOT / "contract" / "control-protocol.json").read_text(encoding="utf-8"))

#: Distinctive, so a leak into an error string or a log is visible, and one file
#: large enough to cross the chunk boundary the receiver reads in.
FILES = [
    ("client-secrets.env", b"PGPASSWORD=example-not-a-real-secret\n"),
    ("payload.bin", bytes(range(256)) * 2048),
    ("empty.txt", b""),
]


@pytest.fixture(scope="module")
def plugin():
    return load_plugin_package()


@pytest.fixture(scope="module")
def control_client(plugin):
    return plugin.drop.control_client


@pytest.fixture(scope="module")
def file_claim(plugin):
    return plugin.drop.file_claim


async def _submitted_file_drop(control_client, broker, files=FILES, ttl_seconds=120):
    """Mint a ``files`` drop and get a real container into it. Returns its id."""
    created = await control_client.control_request(
        {"op": "create", "ttl_seconds": ttl_seconds, "payload_kind": "files"},
        socket_path=broker.socket_path,
    )
    assert created["ok"] is True, created
    assert control_client.supports_file_claim(created) is True
    # The submit runs in the harness process, over real HTTP, through the same
    # client the browser bundle ships.
    assert broker.submit_files(created["url"], list(files)) == "SUBMITTED received"
    return created


def test_client_constants_match_the_shared_contract_fixture(control_client, file_claim) -> None:
    assert control_client.FILE_CLAIM_PROTOCOL == CONTRACT["file_claim"]["protocol"]
    # The op that makes receipt size-independent has to be in the shared fixture, or a
    # third implementation would stream and never ack.
    assert "ack_frame" in CONTRACT["ops"]
    assert "send buffer" in CONTRACT["file_claim"]["receipt"]
    assert control_client.TRANSFER_FAILED in control_client.ERRORS
    # A verdict this side produces, so it is named by the contract but deliberately
    # absent from the broker's own error vocabulary.
    assert control_client.TRANSFER_INDETERMINATE in CONTRACT["file_claim"]["client_verdicts"]
    assert control_client.TRANSFER_INDETERMINATE not in control_client.ERRORS
    assert control_client.TRANSFER_INDETERMINATE not in CONTRACT["errors"]
    assert file_claim.FRAME_HEADER_BYTES == 4
    # The framing this client implements is the framing the fixture describes, and
    # the fixture is what a third implementation would read.
    assert "uint32 big-endian" in " ".join(CONTRACT["file_claim"]["conversation"])


def test_the_capability_is_read_from_the_wire_not_assumed(control_client) -> None:
    """A broker that mints file drops is not necessarily one that can transfer them.

    That was literally true for one release, which is why absence means "cannot"
    rather than "probably fine". A plugin checks this *before* posting a link.
    """
    assert control_client.supports_file_claim({"ok": True, "file_claim_protocol": 1}) is True
    assert control_client.supports_file_claim({"ok": True, "file_claim_protocol": 99}) is True
    assert control_client.supports_file_claim({"ok": True, "file_claim_protocol": 0}) is False
    # A slice-2 broker: it advertises the payload kind and publishes no transfer.
    assert control_client.supports_file_claim({"ok": True, "payload_kinds": ["text", "files"]}) is False
    assert control_client.supports_file_claim({"file_claim_protocol": True}) is False
    assert control_client.supports_file_claim({"file_claim_protocol": "1"}) is False
    assert control_client.supports_file_claim(None) is False


@pytest.mark.asyncio
async def test_a_python_receiver_transfers_every_byte_and_retires_the_drop(
    control_client, file_claim, real_public_broker
) -> None:
    created = await _submitted_file_drop(control_client, real_public_broker)

    result = await file_claim.receive_file_claim(
        created["handoff_id"], socket_path=real_public_broker.socket_path
    )

    assert result["ok"] is True, result
    assert result["status"] == "claimed"
    assert result["file_count"] == len(FILES)
    assert result["bytes"] == sum(len(content) for _, content in FILES)
    for entry, (name, content) in zip(result["files"], FILES):
        assert entry["name"] == name, "names arrive in manifest order"
        assert entry["size"] == len(content)
        assert entry["bytes"] == content, "byte for byte, across a language boundary"
        assert entry["sha256"] == hashlib.sha256(content).hexdigest()

    # And exactly once: a second transfer cannot recover the bytes.
    again = await file_claim.receive_file_claim(
        created["handoff_id"], socket_path=real_public_broker.socket_path
    )
    assert again["ok"] is False
    assert again["error"] == "unavailable"


@pytest.mark.asyncio
async def test_the_streaming_path_delivers_real_bytes_with_nothing_retained(
    control_client, file_claim, real_public_broker
) -> None:
    """The shape slice 4 needs, on the exact settings slice 4 will use.

    ``keep_bytes=False`` is what lets a 42 MiB drop reach a disk without a 42 MiB
    Python buffer beside it. An earlier version of this module handed the sink the
    empty accumulator on precisely this setting while computing its digests from the
    stream: the commit verified, the broker retired the payload, and a spool would
    have published empty files over the only copy. So this test asserts the bytes,
    not the verdict — a green verdict was exactly what that bug produced.
    """
    created = await _submitted_file_drop(control_client, real_public_broker)
    digests: dict = {}
    counts: dict = {}
    calls: dict = {}
    finals: dict = {}
    names: list = []

    async def on_chunk(index, entry, chunk, done):
        if index not in digests:
            digests[index] = hashlib.sha256()
            counts[index] = 0
            calls[index] = 0
            names.append(entry["name"])
        digests[index].update(chunk)
        counts[index] += len(chunk)
        calls[index] += 1
        finals[index] = done

    result = await file_claim.receive_file_claim(
        created["handoff_id"],
        socket_path=real_public_broker.socket_path,
        on_chunk=on_chunk,
        keep_bytes=False,
    )

    assert result["ok"] is True, result
    assert names == [name for name, _ in FILES], "one sink sequence per file, in order"
    for index, (name, content) in enumerate(FILES):
        assert counts[index] == len(content), f"{name}: sink got {counts[index]} of {len(content)}"
        assert digests[index].hexdigest() == hashlib.sha256(content).hexdigest()
        assert finals[index] is True, f"{name}: the last chunk must say so"
    # The 512 KiB file must arrive in pieces at a 256 KiB chunk size: a single call
    # would mean the whole file was assembled somewhere first.
    assert calls[1] > 1, f"expected a chunked delivery, got {calls[1]} call(s)"
    # ...and the empty file still gets exactly one call, so a consumer that creates
    # files in the callback creates that one too.
    assert calls[2] == 1 and counts[2] == 0

    for entry in result["files"]:
        assert "bytes" not in entry, "keep_bytes=False must retain nothing"
        assert entry["sha256"], "and the digest is still what the commit carried"


@pytest.mark.asyncio
async def test_the_receiver_acks_each_frame_before_the_next_arrives(
    control_client, file_claim, real_public_broker
) -> None:
    """The step that makes receipt independent of the socket send buffer.

    The broker sends one frame and stops. A receiver has to read it and hash it to
    say anything the broker will accept, and the digest is checked against a manifest
    the receiver was never given — so a receiver cannot reach the commit without
    having read every frame, whether the drop is 16 bytes or 42 MiB.

    Driven at the wire here rather than through ``receive_file_claim`` so the
    alternation itself is what is asserted, not the client's use of it.
    """
    created = await _submitted_file_drop(control_client, real_public_broker)

    reader, writer = await asyncio.open_unix_connection(
        str(real_public_broker.socket_path), limit=file_claim.MAX_LINE_BYTES
    )
    try:
        writer.write(
            json.dumps({"op": "begin_file_claim", "handoff_id": created["handoff_id"]}).encode()
            + b"\n"
        )
        await writer.drain()
        metadata = json.loads(await reader.readline())
        assert metadata["ok"] is True, metadata

        # A commit now, with every digest correct, must be refused: no frame is acked.
        writer.write(
            json.dumps(
                {
                    "op": "commit_file_claim",
                    "handoff_id": created["handoff_id"],
                    "transfer_id": metadata["transfer_id"],
                    "received_bytes": metadata["total_bytes"],
                    "digests": [hashlib.sha256(content).hexdigest() for _, content in FILES],
                }
            ).encode()
            + b"\n"
        )
        await writer.drain()
        # Frame 0 is ahead of the answer; drain exactly it.
        first = FILES[0][1]
        await reader.readexactly(file_claim.FRAME_HEADER_BYTES + len(first))
        refused = json.loads(await reader.readline())
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass

    assert refused == {"ok": False, "error": "invalid_request"}, refused

    # ...and the honest receiver, which acks every frame, still gets the bytes.
    honest = await file_claim.receive_file_claim(
        created["handoff_id"], socket_path=real_public_broker.socket_path
    )
    assert honest["ok"] is True, honest
    assert [entry["bytes"] for entry in honest["files"]] == [content for _, content in FILES]


@pytest.mark.asyncio
async def test_a_bad_frame_ack_is_refused_and_the_drop_survives(
    control_client, file_claim, real_public_broker
) -> None:
    """An ack the broker cannot match to its manifest ends the transfer, not the drop."""
    created = await _submitted_file_drop(control_client, real_public_broker)

    reader, writer = await asyncio.open_unix_connection(
        str(real_public_broker.socket_path), limit=file_claim.MAX_LINE_BYTES
    )
    try:
        writer.write(
            json.dumps({"op": "begin_file_claim", "handoff_id": created["handoff_id"]}).encode()
            + b"\n"
        )
        await writer.drain()
        metadata = json.loads(await reader.readline())
        first = metadata["files"][0]
        await reader.readexactly(file_claim.FRAME_HEADER_BYTES + first["size"])
        writer.write(
            json.dumps(
                {
                    "op": "ack_frame",
                    "transfer_id": metadata["transfer_id"],
                    "index": 0,
                    "size": first["size"],
                    "sha256": "0" * 64,
                }
            ).encode()
            + b"\n"
        )
        await writer.drain()
        refused = json.loads(await reader.readline())
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass

    assert refused["ok"] is False
    assert refused["error"] == control_client.TRANSFER_FAILED
    assert refused["reason"] == "frame_ack_mismatch"

    honest = await file_claim.receive_file_claim(
        created["handoff_id"], socket_path=real_public_broker.socket_path
    )
    assert honest["ok"] is True, honest


@pytest.mark.asyncio
async def test_a_refused_transfer_leaves_the_drop_claimable(
    control_client, file_claim, real_public_broker
) -> None:
    """The property the whole two-phase design exists for, from the other language.

    A commit with a digest the receiver did not compute is refused, and the refusal
    is ``transfer_failed`` — which a caller must NOT treat like ``unavailable``,
    because the payload is still there. Proved by then collecting it honestly.
    """
    created = await _submitted_file_drop(control_client, real_public_broker)

    reader, writer = await asyncio.open_unix_connection(
        str(real_public_broker.socket_path), limit=file_claim.MAX_LINE_BYTES
    )
    try:
        writer.write(
            json.dumps({"op": "begin_file_claim", "handoff_id": created["handoff_id"]}).encode()
            + b"\n"
        )
        await writer.drain()
        metadata = json.loads(await reader.readline())
        assert metadata["ok"] is True, metadata

        # Read and ack every frame properly — the failure under test is the commit,
        # not the read, so the transfer has to get all the way to being committable.
        for index, entry in enumerate(metadata["files"]):
            header = await reader.readexactly(file_claim.FRAME_HEADER_BYTES)
            assert int.from_bytes(header, "big") == entry["size"]
            body = await reader.readexactly(entry["size"]) if entry["size"] else b""
            writer.write(
                json.dumps(
                    {
                        "op": "ack_frame",
                        "transfer_id": metadata["transfer_id"],
                        "index": index,
                        "size": entry["size"],
                        "sha256": hashlib.sha256(body).hexdigest(),
                    }
                ).encode()
                + b"\n"
            )
            await writer.drain()
            answered = json.loads(await reader.readline())
            assert answered["ok"] is True, answered

        writer.write(
            json.dumps(
                {
                    "op": "commit_file_claim",
                    "handoff_id": created["handoff_id"],
                    "transfer_id": metadata["transfer_id"],
                    "received_bytes": metadata["total_bytes"],
                    "digests": ["0" * 64 for _ in metadata["files"]],
                }
            ).encode()
            + b"\n"
        )
        await writer.drain()
        refused = json.loads(await reader.readline())
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass

    assert refused == {"ok": False, "error": "transfer_failed", "reason": "digest_mismatch"}

    honest = await file_claim.receive_file_claim(
        created["handoff_id"], socket_path=real_public_broker.socket_path
    )
    assert honest["ok"] is True, honest
    assert [entry["bytes"] for entry in honest["files"]] == [content for _, content in FILES]


@pytest.mark.asyncio
async def test_a_disconnected_receiver_gives_the_lease_straight_back(
    control_client, file_claim, real_public_broker
) -> None:
    """A receiver that hangs up mid-conversation must not cost a minute's wait.

    The lease is bounded, but the disconnect is supposed to release it immediately —
    otherwise the next receiver waits out a deadline for a payload already sitting
    there. Half-close and hard close are both tried, because they are different
    edges on the server's side.
    """
    for close in ("half", "hard"):
        # A fresh drop per edge: the first one gets claimed by the assertion below,
        # and a claimed drop would make the second case prove nothing.
        created = await _submitted_file_drop(control_client, real_public_broker)

        reader, writer = await asyncio.open_unix_connection(
            str(real_public_broker.socket_path), limit=file_claim.MAX_LINE_BYTES
        )
        writer.write(
            json.dumps({"op": "begin_file_claim", "handoff_id": created["handoff_id"]}).encode()
            + b"\n"
        )
        await writer.drain()
        metadata = json.loads(await reader.readline())
        assert metadata["ok"] is True, metadata
        if close == "half":
            writer.write_eof()
            await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass

        # No sleep-and-hope: the next transfer is the assertion. If the lease had not
        # come back it would be refused with `transfer_in_progress`.
        for attempt in range(50):
            result = await file_claim.receive_file_claim(
                created["handoff_id"], socket_path=real_public_broker.socket_path
            )
            if result.get("reason") != "transfer_in_progress":
                break
            await asyncio.sleep(0.05)

        assert result["ok"] is True, f"{close} close: {result}"
        assert result["bytes"] == sum(len(content) for _, content in FILES)
        assert [entry["bytes"] for entry in result["files"]] == [c for _, c in FILES]


@pytest.mark.asyncio
async def test_a_text_drop_cannot_be_transferred(
    control_client, file_claim, real_public_broker
) -> None:
    created = await control_client.create(
        ttl_seconds=60, socket_path=real_public_broker.socket_path
    )
    assert created["ok"] is True, created

    result = await file_claim.receive_file_claim(
        created["handoff_id"], socket_path=real_public_broker.socket_path
    )
    assert result["ok"] is False
    assert result["error"] == "unavailable", "the uniform refusal, not a kind mismatch"


async def _fake_broker(tmp_path, file_claim, *, files, after_commit):
    """A minimal broker that speaks the framing and then misbehaves on purpose.

    The one thing the real broker cannot be made to do reliably is *not answer* a
    commit it accepted — that is a lost packet, not a code path. So the two verdicts
    that depend on it are proved against a server that speaks the documented
    conversation up to the commit and then does whatever ``after_commit`` says.
    Everything else in this file runs against the real broker.
    """
    socket_path = str(tmp_path / "fake-control.sock")

    async def serve(reader, writer):
        await reader.readline()  # the begin
        entries = [{"name": name, "size": len(content), "type": ""} for name, content in files]
        writer.write(
            json.dumps(
                {
                    "ok": True,
                    "handoff_id": "abcdefghijklmnopqrstuv",
                    "transfer_id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "lease_expires_at": 0,
                    "total_bytes": sum(len(content) for _, content in files),
                    "files": entries,
                }
            ).encode()
            + b"\n"
        )
        # One frame, then wait for its ack, exactly as the real broker does.
        for index, (_, content) in enumerate(files):
            writer.write(len(content).to_bytes(file_claim.FRAME_HEADER_BYTES, "big"))
            writer.write(content)
            await writer.drain()
            ack = json.loads(await reader.readline())
            assert ack["op"] == "ack_frame" and ack["index"] == index, ack
            assert ack["sha256"] == hashlib.sha256(content).hexdigest(), "the ack must be honest"
            last = index == len(files) - 1
            writer.write(
                json.dumps(
                    {"ok": True, "index": index, "next_index": None if last else index + 1}
                ).encode()
                + b"\n"
            )
            await writer.drain()
        await reader.readline()  # the commit, which is deliberately never answered
        await after_commit(writer)

    server = await asyncio.start_unix_server(serve, path=socket_path)
    return server, socket_path


@pytest.mark.asyncio
async def test_a_commit_with_no_answer_is_indeterminate_not_failed(
    tmp_path, file_claim, control_client
) -> None:
    """The verdict that must not lie in either direction.

    ``commit_file_claim`` is one-shot, non-idempotent and not requeryable, so a
    receiver that wrote one and read no answer knows nothing about what happened to
    the payload. Calling that ``transfer_failed`` would assert it survived — which is
    what the contract's ``transfer_failed`` promises and what slice 4 would act on by
    retrying and then recording a spent drop, discarding files it had already
    received.
    """
    async def close_without_answering(writer):
        writer.close()

    server, socket_path = await _fake_broker(
        tmp_path, file_claim, files=[("a.bin", b"payload")], after_commit=close_without_answering
    )
    try:
        result = await file_claim.receive_file_claim(
            "abcdefghijklmnopqrstuv", socket_path=socket_path, timeout=5.0
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result["ok"] is False
    assert result["error"] == control_client.TRANSFER_INDETERMINATE, result
    assert result["reason"] == "commit_answer_lost"
    assert result["error"] != control_client.TRANSFER_FAILED
    assert result["error"] not in control_client.ERRORS, "the broker never says this; the client does"


@pytest.mark.asyncio
async def test_a_timeout_after_the_commit_is_indeterminate_too(
    tmp_path, file_claim, control_client
) -> None:
    """Same unknown, reached by this client's own deadline instead of a close.

    A timeout *before* the commit is an honest ``transfer_failed`` — nothing was
    consumed, and the broker gives the lease back on its own deadline. After the
    commit the two cases are indistinguishable from here, so they get the same verdict.
    """
    async def never_answer(writer):
        await asyncio.sleep(10)
        writer.close()

    server, socket_path = await _fake_broker(
        tmp_path, file_claim, files=[("a.bin", b"payload")], after_commit=never_answer
    )
    try:
        result = await file_claim.receive_file_claim(
            "abcdefghijklmnopqrstuv", socket_path=socket_path, timeout=0.5
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result["ok"] is False
    assert result["error"] == control_client.TRANSFER_INDETERMINATE, result
    assert result["reason"] == "client_timeout_after_commit"


@pytest.mark.asyncio
async def test_a_frame_that_disagrees_with_the_manifest_is_refused(
    tmp_path, file_claim
) -> None:
    """Both receivers refuse a mis-framed transfer on the same terms.

    Unreachable against this broker, which writes the advertised size as the frame
    length. It is checked because reading the framed length instead would
    mis-attribute the remainder to the next file and surface as a ``size_mismatch``
    pointing at the receiver rather than at the framing.
    """
    socket_path = str(tmp_path / "misframe.sock")

    async def serve(reader, writer):
        await reader.readline()
        writer.write(
            json.dumps(
                {
                    "ok": True,
                    "handoff_id": "abcdefghijklmnopqrstuv",
                    "transfer_id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "lease_expires_at": 0,
                    "total_bytes": 8,
                    "files": [{"name": "lie.bin", "size": 8, "type": ""}],
                }
            ).encode()
            + b"\n"
        )
        writer.write((4).to_bytes(4, "big"))  # says 4, the manifest said 8
        writer.write(b"\x01\x01\x01\x01")
        await writer.drain()

    server = await asyncio.start_unix_server(serve, path=socket_path)
    try:
        result = await file_claim.receive_file_claim(
            "abcdefghijklmnopqrstuv", socket_path=socket_path, timeout=5.0
        )
    finally:
        server.close()
        await server.wait_closed()

    assert result["ok"] is False
    assert result["error"] == "transfer_failed", result
    assert result["reason"] == "frame_length_mismatch"


@pytest.mark.asyncio
async def test_no_control_socket_configured_is_a_dict_not_a_raise(file_claim) -> None:
    """Same discipline as the control client: nothing here may raise at a caller."""
    result = await file_claim.receive_file_claim("abcdefghijklmnopqrstuv", socket_path="")
    assert result["ok"] is False
    assert result["error"] == "broker_unavailable"

    missing = await file_claim.receive_file_claim(
        "abcdefghijklmnopqrstuv", socket_path="/tmp/hermes-drop-no-such.sock", timeout=2.0
    )
    assert missing["ok"] is False
    assert missing["error"] == "broker_unavailable"
