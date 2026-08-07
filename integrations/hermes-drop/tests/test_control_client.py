"""S3 — the async AF_UNIX control client, against the REAL broker.

``real_broker`` boots this repo's actual ``createBroker`` +
``startControlServer`` (see ``broker_harness.mjs``), not a Python re-implementation
of the wire format. That is the point: the only way a Python client and a Node
server can drift is if one of them is a fixture, so neither is.

The client is async by construction — ``asyncio.open_unix_connection``, no
``socket.connect``, no thread. Plan §7.1: there is no blocking call on the
gateway loop anywhere in Drop.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from conftest import REPO_ROOT, load_plugin_package

CONTRACT = json.loads((REPO_ROOT / "contract" / "control-protocol.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def control_client():
    return load_plugin_package().drop.control_client


def test_client_defaults_match_the_shared_contract_fixture(control_client) -> None:
    """The fixture is the single source of truth across both languages (S1)."""
    transport = CONTRACT["transport"]
    assert control_client.DEFAULT_CONTROL_SOCKET == transport["default_socket_path"]
    assert control_client.MAX_REQUEST_BYTES == transport["max_request_bytes"]
    assert set(control_client.NOTICE_PLATFORMS) == set(CONTRACT["notice_platforms"])
    assert set(control_client.ERRORS) == set(CONTRACT["errors"])


@pytest.mark.asyncio
async def test_create_returns_all_three_notices_in_one_round_trip(
    control_client, real_broker
) -> None:
    response = await control_client.control_request(
        {"op": "create", "ttl_seconds": 60, "notice_platform": "telegram"},
        socket_path=real_broker.socket_path,
    )

    assert response["ok"] is True, response
    assert len(response["handoff_id"]) == 22
    assert response["url"].count("#") == 1
    for key in ("notice", "notice_received", "notice_expired"):
        assert response[key], f"missing {key}"


@pytest.mark.asyncio
async def test_unsupported_notice_platform_is_refused_and_mints_nothing(
    control_client, real_broker
) -> None:
    response = await control_client.control_request(
        {"op": "create", "notice_platform": "matrix"},
        socket_path=real_broker.socket_path,
    )
    assert response == {"ok": False, "error": "invalid_request"}


@pytest.mark.asyncio
async def test_claim_of_an_unknown_handoff_is_uniformly_unavailable(
    control_client, real_broker
) -> None:
    response = await control_client.control_request(
        {"op": "claim", "handoff_id": "A" * 22},
        socket_path=real_broker.socket_path,
    )
    assert response == {"ok": False, "error": "unavailable"}


@pytest.mark.asyncio
async def test_a_missing_socket_is_broker_unavailable_not_an_exception(
    control_client, tmp_path: Path
) -> None:
    """Unreachability is a runtime condition, never a schema condition (§5.2)."""
    response = await control_client.control_request(
        {"op": "create"},
        socket_path=tmp_path / "nope" / "control.sock",
    )
    assert response["ok"] is False
    assert response["error"] == "broker_unavailable"
    assert "nope" in response["detail"]


@pytest.mark.asyncio
async def test_an_oversized_request_is_refused_client_side(
    control_client, real_broker
) -> None:
    """The server would answer invalid_request anyway; refusing locally keeps a
    4 KiB-plus line off the wire and makes the failure attributable."""
    response = await control_client.control_request(
        {"op": "create", "pad": "x" * (control_client.MAX_REQUEST_BYTES + 1)},
        socket_path=real_broker.socket_path,
    )
    assert response == {
        "ok": False,
        "error": "invalid_request",
        "detail": "request exceeds max_request_bytes",
    }


@pytest.mark.asyncio
async def test_concurrent_requests_do_not_interleave_responses(
    control_client, real_broker
) -> None:
    """One request line out, one response line back, then the server closes —
    so N concurrent creates must yield N distinct handoffs."""
    responses = await asyncio.gather(
        *(
            control_client.control_request(
                {"op": "create", "ttl_seconds": 60}, socket_path=real_broker.socket_path
            )
            for _ in range(8)
        )
    )
    ids = [r["handoff_id"] for r in responses]
    assert all(r["ok"] for r in responses), responses
    assert len(set(ids)) == 8


@pytest.mark.asyncio
async def test_the_named_op_helpers_round_trip_against_the_real_broker(
    control_client, real_broker
) -> None:
    """``create`` / ``await_submission`` / ``claim`` are thin, so they are tested
    for the thing thinness gets wrong: field names and defaults."""
    created = await control_client.create(
        ttl_seconds=60, notice_platform="discord", socket_path=real_broker.socket_path
    )
    assert created["ok"] is True
    handoff_id = created["handoff_id"]

    # Nobody has submitted, and wait_ms defaults to 0, so both of these answer
    # `unavailable` immediately rather than parking.
    awaited = await control_client.await_submission(
        handoff_id, wait_ms=0, socket_path=real_broker.socket_path, timeout=5
    )
    assert awaited == {"ok": False, "error": "unavailable"}

    claimed = await control_client.claim(handoff_id, socket_path=real_broker.socket_path)
    assert claimed == {"ok": False, "error": "unavailable"}


@pytest.mark.asyncio
async def test_a_negative_wait_is_refused_by_the_broker_as_invalid_request(
    control_client, real_broker
) -> None:
    response = await control_client.await_submission(
        "A" * 22, wait_ms=-1, socket_path=real_broker.socket_path, timeout=5
    )
    assert response == {"ok": False, "error": "invalid_request"}


@pytest.mark.asyncio
async def test_timeout_reports_broker_unavailable_and_leaves_no_open_socket(
    control_client, tmp_path: Path
) -> None:
    """A server that accepts but never answers must not park the caller forever."""
    socket_dir = tmp_path / "run"
    socket_dir.mkdir(mode=0o700)
    socket_path = socket_dir / "silent.sock"

    async def never_answer(reader, writer):  # noqa: ARG001
        await asyncio.sleep(30)

    server = await asyncio.start_unix_server(never_answer, path=str(socket_path))
    try:
        response = await control_client.control_request(
            {"op": "create"}, socket_path=socket_path, timeout=0.25
        )
    finally:
        server.close()
        await server.wait_closed()

    assert response["ok"] is False
    assert response["error"] == "broker_unavailable"
    assert "timed out" in response["detail"]


# ── H2: the response-line ceiling ──────────────────────────────────────────
#
# Every claim test above this point uses a tiny payload, which is exactly how the
# review found the defect: ``asyncio.open_unix_connection`` was called with the
# default ``StreamReader`` ``limit=65536``, ``readline()`` raises ``ValueError``
# past it, and ``control_request`` caught only ``TimeoutError`` / ``OSError`` /
# ``ConnectionError``. So a claim of a 50-64 KB secret raised out of a module
# whose docstring says "Never raises" — *after* ``broker.claim`` had already
# detached the plaintext and retired the record. The payload was destroyed and
# the model was told ``internal_error``.
#
# The broker's ceiling is ``maxPlaintextBytes`` (65536, ``src/config.js:11``),
# base64 of which is 87,384 bytes — comfortably past the old limit. These three
# tests pin the ceiling from both sides: a real full-size payload must survive
# byte for byte, and a line past the *new* limit must still come back as a dict.


def _max_plaintext_bytes() -> int:
    """The broker's own cap, read from the broker's own config module.

    Not hardcoded: if ``src/config.js`` ever raises ``maxPlaintextBytes``, this
    test must follow it rather than quietly keep testing the old ceiling.
    """
    import subprocess

    out = subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            "import {DEFAULTS} from './src/config.js';"
            "process.stdout.write(String(DEFAULTS.maxPlaintextBytes))",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    return int(out.stdout.strip())


@pytest.mark.asyncio
async def test_a_max_size_payload_is_claimed_back_byte_for_byte(
    control_client, real_public_broker
) -> None:
    """The whole loop at the broker's exact ceiling: mint → submit → claim.

    ``maxPlaintextBytes`` exactly, because ``broker.js:172`` refuses on ``>`` —
    so this is the largest payload the system accepts, and the one the old
    ``StreamReader`` limit destroyed. The assertion is byte equality, not
    "roughly recovered": a one-shot secret that comes back truncated is the same
    incident as one that comes back not at all.
    """
    size = _max_plaintext_bytes()
    assert size == 65536, f"the ceiling moved; this test is calibrated to it (got {size})"

    # ASCII, so utf-8 length is byte length and the harness's base64 round trip is
    # lossless. Non-repeating in 64-byte blocks so a truncation or a re-ordering
    # cannot coincidentally still compare equal.
    block = "".join(chr(33 + (i % 90)) for i in range(64))
    plaintext = (block * (size // 64 + 1))[:size]
    assert len(plaintext.encode("utf-8")) == size

    created = await control_client.create(
        ttl_seconds=60, socket_path=real_public_broker.socket_path
    )
    assert created["ok"] is True, created
    assert created["max_plaintext_bytes"] == size

    submitted = real_public_broker.submit(created["url"], plaintext)
    assert submitted == "SUBMITTED sent", submitted

    claimed = await control_client.claim(
        created["handoff_id"], socket_path=real_public_broker.socket_path
    )
    # Before the fix this line raised ValueError("Separator is found, but chunk
    # is longer than limit") instead of returning anything at all.
    assert isinstance(claimed, dict), f"the client must always return a dict, got {claimed!r}"
    assert claimed.get("ok") is True, claimed

    import base64

    recovered = base64.b64decode(claimed["plaintext_b64"], validate=True)
    assert len(recovered) == size, f"{len(recovered)} bytes came back, not {size}"
    assert recovered == plaintext.encode("utf-8"), "the payload came back altered"


@pytest.mark.asyncio
async def test_a_full_size_claim_survives_the_service_layer_too(
    control_client, real_public_broker, tmp_path: Path
) -> None:
    """The same size through ``DropService.claim``, which is what the tool calls.

    ``service.claim`` decodes with ``errors="replace"`` and then journals
    ``claimed_at``. A raise from the client skipped that write entirely, leaving
    ``authorize_claim`` willing to permit a retry that could only ever get
    ``unavailable`` from the retired record — the "false refusal destroys it"
    failure of §8.5. This asserts the payload arrives *and* the drop is marked
    spent, which is the pair that makes a second claim honest.
    """
    plugin = load_plugin_package()
    drop = plugin.drop
    from _stubs import StubAdapter, StubRunner
    from gateway.config import Platform

    size = _max_plaintext_bytes()
    plaintext = "".join(chr(33 + (i % 90)) for i in range(size))

    adapter = StubAdapter(Platform.DISCORD)
    runner = StubRunner({Platform.DISCORD: adapter})
    source = adapter.build_source(
        chat_id="c-1", user_id="u-1", chat_type="dm", message_id="m-1"
    )
    origin = drop.origin.Origin(
        source=source,
        adapter=adapter,
        runner=runner,
        routing_tuple=drop.sources.routing_tuple_for_source(source),
        reply_anchor=None,
        tier="routing_tuple",
    )

    journal = drop.journal.DropJournal(root=tmp_path / "journal")
    service = drop.service.DropService(
        journal=journal,
        control=drop.control_client,
        socket_path=real_public_broker.socket_path,
        waiters=drop.waiter.WaiterRegistry(),
    )

    created = await control_client.create(
        ttl_seconds=60, socket_path=real_public_broker.socket_path
    )
    drop_id = created["handoff_id"]
    journal.create_entry(
        drop_id=drop_id,
        origin=origin,
        message_id="m-notice",
        expires_at_ms=int(created["expires_at"]),
        ttl_seconds=60,
    )
    journal.update(drop_id, state=drop.journal.STATE_RECEIVED)

    assert real_public_broker.submit(created["url"], plaintext) == "SUBMITTED sent"

    result = await service.claim(origin, drop_id)
    assert result.get("ok") is True, result
    assert result["private_input"] == plaintext
    assert journal.get(drop_id)["claimed_at"] is not None, (
        "a successful claim must mark the drop spent, or a retry looks legal"
    )


@pytest.mark.asyncio
async def test_a_line_past_max_response_bytes_is_a_dict_not_a_raise(
    control_client, tmp_path: Path
) -> None:
    """Past the *new* ceiling it is still a verdict, never an exception.

    ``MAX_RESPONSE_BYTES`` is the ``StreamReader`` limit now, so overrunning it
    surfaces as ``ValueError`` (``LimitOverrunError`` is a subclass) from
    ``readline`` — which ``control_request`` must contain like any other
    transport fault. A compromised or wedged socket streaming unbounded data is
    the case the bound exists for, and it must not become an exception on the
    gateway loop.
    """
    socket_dir = tmp_path / "run"
    socket_dir.mkdir(mode=0o700)
    socket_path = socket_dir / "flood.sock"

    async def flood(reader, writer):
        await reader.readline()
        # One line, no newline until well past the limit.
        writer.write(b'{"ok":true,"pad":"' + b"x" * (control_client.MAX_RESPONSE_BYTES + 4096))
        await writer.drain()
        writer.write(b'"}\n')
        await writer.drain()

    server = await asyncio.start_unix_server(flood, path=str(socket_path))
    try:
        response = await control_client.control_request(
            {"op": "create"}, socket_path=socket_path, timeout=20
        )
    finally:
        server.close()
        await server.wait_closed()

    assert isinstance(response, dict), f"must not raise; got {response!r}"
    assert response["ok"] is False
    assert response["error"] == "broker_unavailable", response


@pytest.mark.asyncio
async def test_the_stream_limit_is_max_response_bytes_not_asyncios_default(
    control_client, tmp_path: Path
) -> None:
    """A line between asyncio's 65536 default and ``MAX_RESPONSE_BYTES`` parses.

    This is the test that distinguishes "the ValueError is caught" from "the
    limit was actually raised". Catching alone would turn a legitimate 87 KB
    claim response into ``broker_unavailable`` — no crash, but the payload is
    still lost. Only a raised limit lets it through, so ``MAX_RESPONSE_BYTES``
    has to be real (review L5) rather than a dead constant checked after the
    fact.
    """
    assert control_client.MAX_RESPONSE_BYTES > 65536, (
        "the constant must exceed asyncio's StreamReader default to mean anything"
    )

    socket_dir = tmp_path / "run"
    socket_dir.mkdir(mode=0o700)
    socket_path = socket_dir / "big.sock"

    pad = "y" * (65536 * 2)  # comfortably past the old ceiling, under the new one

    async def answer_big(reader, writer):
        await reader.readline()
        writer.write(json.dumps({"ok": True, "pad": pad}).encode("utf-8") + b"\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(answer_big, path=str(socket_path))
    try:
        response = await control_client.control_request(
            {"op": "create"}, socket_path=socket_path, timeout=20
        )
    finally:
        server.close()
        await server.wait_closed()

    assert response["ok"] is True, response
    assert response["pad"] == pad, "the whole line has to survive, not a prefix of it"


# ── N2: the bound the constant implies, and the broker default against it ──


def test_the_claimable_ceiling_follows_from_the_response_limit(control_client) -> None:
    """``MAX_CLAIMABLE_PLAINTEXT_BYTES`` must be the real implication of the limit.

    Not a second hand-chosen number: base64 of a payload at the ceiling, plus the
    JSON around it, has to fit in what ``readline`` will buffer. Recomputed here
    from the constant rather than restated, so raising one and forgetting the other
    fails.
    """
    ceiling = control_client.MAX_CLAIMABLE_PLAINTEXT_BYTES
    encoded = 4 * ((ceiling + 2) // 3)  # base64, padded

    assert encoded < control_client.MAX_RESPONSE_BYTES, (
        "a payload at the ceiling does not fit in the response limit"
    )
    assert control_client.MAX_RESPONSE_BYTES - encoded >= 1024, (
        "no room left for the JSON envelope around the payload"
    )
    # One block past the ceiling must not fit, or the ceiling is not the ceiling.
    assert 4 * ((ceiling + 3 + 2) // 3) + 4096 > control_client.MAX_RESPONSE_BYTES


# ── the response-size capability: refuse before consuming ──────────────────
#
# Everything above this line is damage control: the reader's limit is real, the
# overrun is caught, and ``create`` warns when the broker's cap is out of reach.
# None of it saves a payload that is *already* too big — ``broker.claim`` retires
# the record before writing the line, so by the time ``readline`` gives up the
# secret is gone. The only fix is for the broker to know the ceiling before it
# consumes anything, which means the ceiling has to be on the wire.


def test_the_reader_ceiling_is_a_shared_constant(control_client) -> None:
    """One number, in the fixture, on both sides. Not two that happen to agree."""
    assert control_client.MAX_RESPONSE_BYTES == CONTRACT["transport"]["max_response_bytes"]
    assert control_client.MIN_RESPONSE_BYTES == CONTRACT["transport"]["min_response_bytes"]
    assert control_client.MIN_RESPONSE_BYTES <= control_client.MAX_RESPONSE_BYTES
    assert control_client.RESPONSE_TOO_LARGE in CONTRACT["errors"]
    assert control_client.RESPONSE_TOO_LARGE in control_client.ERRORS


def test_the_protocol_version_this_client_implements_is_the_fixtures(control_client) -> None:
    assert control_client.PROTOCOL_VERSION == CONTRACT["version"]


def test_lossless_claim_is_decided_from_the_wire_not_assumed(control_client) -> None:
    """A plugin is installed once and upgraded on its own schedule, so the broker
    it talks to may predate the response-size capability. Absence is the pre-2
    answer — a v1 broker sends no version field at all — and it must read as "no",
    never as "probably fine"."""
    assert control_client.supports_lossless_claim({"ok": True, "protocol_version": 2}) is True
    assert control_client.supports_lossless_claim({"ok": True, "protocol_version": 99}) is True
    assert control_client.supports_lossless_claim({"ok": True, "protocol_version": 1}) is False
    assert control_client.supports_lossless_claim({"ok": True}) is False
    assert control_client.supports_lossless_claim({"protocol_version": "2"}) is False
    assert control_client.supports_lossless_claim(None) is False


@pytest.mark.asyncio
async def test_the_real_broker_states_its_protocol_version_at_create(
    control_client, real_broker
) -> None:
    created = await control_client.create(ttl_seconds=60, socket_path=real_broker.socket_path)

    assert created["ok"] is True, created
    assert created["protocol_version"] == control_client.PROTOCOL_VERSION
    assert control_client.supports_lossless_claim(created) is True


@pytest.mark.asyncio
async def test_a_line_of_exactly_the_limit_including_its_newline_is_readable(
    control_client, tmp_path: Path
) -> None:
    """The convention behind ``required_bytes``, pinned against asyncio itself.

    The broker counts the terminating newline in the size it compares against the
    advertised ceiling. That is only sound if a ``StreamReader`` with ``limit=N``
    can actually read a line of exactly ``N`` bytes *including* the newline —
    asyncio raises ``LimitOverrunError`` on ``line + separator`` exceeding the
    limit, not on the line alone, so an off-by-one here would refuse claims that
    fit or, worse, permit one that does not.
    """
    socket_dir = tmp_path / "run"
    socket_dir.mkdir(mode=0o700)
    socket_path = socket_dir / "exact.sock"

    limit = 512
    body = json.dumps({"ok": True, "pad": ""}, separators=(",", ":")).encode("utf-8")
    pad = limit - len(body) - 1  # -1 for the newline that has to fit as well
    line = json.dumps({"ok": True, "pad": "z" * pad}, separators=(",", ":")).encode("utf-8") + b"\n"
    assert len(line) == limit

    async def answer(reader, writer):
        await reader.readline()
        writer.write(line)
        await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(answer, path=str(socket_path))
    try:
        connection = await asyncio.open_unix_connection(str(socket_path), limit=limit)
        rd, wr = connection
        wr.write(b'{"op":"create"}\n')
        await wr.drain()
        raw = await rd.readline()
        wr.close()
    finally:
        server.close()
        await server.wait_closed()

    assert len(raw) == limit, "a line of exactly the limit, newline included, must come back whole"


@pytest.mark.asyncio
async def test_the_size_oracle_agrees_across_both_languages(
    control_client, real_public_broker
) -> None:
    """``required_bytes`` computed here must be the number the broker computes.

    Same arithmetic, written independently on the Python side: the JSON envelope
    around an empty payload, plus four base64 characters per three payload bytes,
    plus the newline. If the two ever disagree, one of them is refusing claims
    that fit or admitting ones that do not — and the second half of this test is
    the boundary itself, one byte either side of the number.
    """
    plaintext = "size-oracle-" + ("k" * 1500)  # past the minimum ceiling, so both sides bind
    payload_bytes = len(plaintext.encode("utf-8"))

    created = await control_client.create(
        ttl_seconds=60, socket_path=real_public_broker.socket_path
    )
    handoff_id = created["handoff_id"]
    envelope = len(
        json.dumps(
            {"ok": True, "handoff_id": handoff_id, "plaintext_b64": ""}, separators=(",", ":")
        ).encode("utf-8")
    ) + 1
    required = envelope + 4 * -(-payload_bytes // 3)

    assert real_public_broker.submit(created["url"], plaintext) == "SUBMITTED sent"

    refused = await control_client.control_request(
        {"op": "claim", "handoff_id": handoff_id, "max_response_bytes": required - 1},
        socket_path=real_public_broker.socket_path,
    )
    assert refused["error"] == control_client.RESPONSE_TOO_LARGE, refused
    assert refused["required_bytes"] == required, "the two languages disagree on the line size"

    claimed = await control_client.control_request(
        {"op": "claim", "handoff_id": handoff_id, "max_response_bytes": required},
        socket_path=real_public_broker.socket_path,
    )
    assert claimed.get("ok") is True, claimed
    assert (
        len(json.dumps(claimed, separators=(",", ":")).encode("utf-8")) + 1 == required
    ), "and the real line is exactly what both of them predicted"


@pytest.mark.asyncio
async def test_a_ceiling_below_the_minimum_is_a_caller_mistake(
    control_client, real_broker
) -> None:
    """Below the minimum the broker could not answer *anything* the caller could
    read, refusals included, so the request is refused as the configuration
    mistake it is rather than honoured into a guaranteed transport fault."""
    response = await control_client.control_request(
        {
            "op": "claim",
            "handoff_id": "A" * 22,
            "max_response_bytes": control_client.MIN_RESPONSE_BYTES - 1,
        },
        socket_path=real_broker.socket_path,
    )
    assert response == {"ok": False, "error": "invalid_request"}


@pytest.mark.asyncio
async def test_claim_advertises_the_ceiling_it_can_actually_read(
    control_client, tmp_path: Path
) -> None:
    """The client's limit is only useful to the broker if the broker is told.

    Asserted against a stub that records the request line rather than against the
    real broker, because what is under test is the *request* — that ``claim``
    states the same bound ``_exchange`` passes to ``open_unix_connection``, so the
    broker's pre-consumption check is calibrated to the reader that will actually
    have to buffer the answer.
    """
    socket_dir = tmp_path / "run"
    socket_dir.mkdir(mode=0o700)
    socket_path = socket_dir / "echo.sock"
    seen: list = []

    async def record(reader, writer):
        seen.append(json.loads(await reader.readline()))
        writer.write(b'{"ok":false,"error":"unavailable"}\n')
        await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(record, path=str(socket_path))
    try:
        await control_client.claim("A" * 22, socket_path=socket_path)
    finally:
        server.close()
        await server.wait_closed()

    assert seen == [
        {
            "op": "claim",
            "handoff_id": "A" * 22,
            "wait_ms": 0,
            "max_response_bytes": control_client.MAX_RESPONSE_BYTES,
        }
    ]


@pytest.mark.asyncio
async def test_a_claim_past_the_advertised_ceiling_is_refused_not_destroyed(
    control_client, real_public_broker
) -> None:
    """The window itself, closed, proved across both languages.

    A ceiling below the response size used to be an unreadable line *after* the
    record was retired. Now the broker sizes the answer first and refuses, so the
    same payload is still there for a reader that can hold it — which the second
    half of this test performs, byte for byte, against the same handoff.
    """
    # Comfortably past what the minimum ceiling can carry (~723 bytes of
    # plaintext), so the refusal comes from the size check rather than from the
    # floor under an advertised ceiling.
    plaintext = "reader-ceiling-marker-" + ("q" * 2048)

    created = await control_client.create(
        ttl_seconds=60, socket_path=real_public_broker.socket_path
    )
    assert created["ok"] is True, created
    assert real_public_broker.submit(created["url"], plaintext) == "SUBMITTED sent"

    refused = await control_client.control_request(
        {
            "op": "claim",
            "handoff_id": created["handoff_id"],
            "max_response_bytes": control_client.MIN_RESPONSE_BYTES,
        },
        socket_path=real_public_broker.socket_path,
    )
    assert refused["ok"] is False
    assert refused["error"] == control_client.RESPONSE_TOO_LARGE, refused
    assert (
        refused["required_bytes"]
        > refused["max_response_bytes"]
        == control_client.MIN_RESPONSE_BYTES
    )
    assert (
        len(json.dumps(refused, separators=(",", ":")).encode("utf-8")) + 1
        <= control_client.MIN_RESPONSE_BYTES
    ), "the refusal itself has to fit in the ceiling that produced it"
    assert plaintext not in json.dumps(refused), "a refusal is not a delivery"

    claimed = await control_client.claim(
        created["handoff_id"], socket_path=real_public_broker.socket_path
    )
    assert claimed.get("ok") is True, claimed
    import base64

    assert base64.b64decode(claimed["plaintext_b64"]).decode("utf-8") == plaintext


def test_the_broker_default_cap_is_claimable(control_client) -> None:
    """The live configuration is inside the bound, and stays inside it.

    ``HANDOFF_MAX_PLAINTEXT_BYTES`` is operator-settable, so this cannot be a
    guarantee — ``DropService.create`` warns when a running broker advertises more
    than the client can read. What it *can* pin is that the shipped default never
    silently crosses the line: raise ``maxPlaintextBytes`` in ``src/config.js``
    past the ceiling and this test says so.
    """
    default_cap = _max_plaintext_bytes()
    assert default_cap <= control_client.MAX_CLAIMABLE_PLAINTEXT_BYTES, (
        f"the broker's default cap ({default_cap}) exceeds what a claim response "
        f"can carry ({control_client.MAX_CLAIMABLE_PLAINTEXT_BYTES}); a full-size "
        "payload would be destroyed on claim"
    )
