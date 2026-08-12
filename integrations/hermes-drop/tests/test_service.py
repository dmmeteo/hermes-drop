"""S7 — ``DropService``: the one workflow both entry points call.

Two things are being proved here.

**The receipt is non-secret.** ``request_private_input`` returns a drop id, a
deadline and a state. The capability appears exactly twice in the whole system —
the broker's ``create`` response and the chat message (§8.8) — and a tool result
is neither. Plaintext reaches the model only as a ``claim_private_input`` result.

**The failure order is the one §7.2 argues for.** A failed *post* aborts the drop
outright: no journal entry, no waiter, nothing armed. A live capability whose
link was never delivered is pure risk. A failed *edit* does not abort anything —
by then the capability is already dead and only the durable record still matters.

The last two tests run against the real Node broker with its public listener, so
the full loop — mint, post, park on a real AF_UNIX ``await``, real HPKE
submission from the real browser client, wake, claim — happens end to end with no
fake in the middle. That is the CI stand-in for gate E2E-2; it proves the path,
not that a live platform accepted an edit.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
from pathlib import Path

import pytest
from gateway.config import Platform

from _stubs import StubAdapter, StubRunner, bind_session_context
from conftest import load_plugin_package

pytestmark = pytest.mark.asyncio


@pytest.fixture
def plugin():
    return load_plugin_package()


@pytest.fixture
def journal(plugin, tmp_path: Path):
    return plugin.drop.journal.DropJournal(root=tmp_path / "hermes-drop")


@pytest.fixture
def lane(plugin):
    def _make(platform: Platform = Platform.TELEGRAM, chat_id: str = "tg-1", **kw):
        thread_id = kw.pop("thread_id", "")
        adapter = StubAdapter(platform, **kw)
        runner = StubRunner({platform: adapter})
        source = adapter.build_source(
            chat_id=chat_id, chat_type="dm", user_id="u-1", thread_id=thread_id
        )
        plugin.drop.sources.REGISTRY.put(source, gateway=runner, session_key="s")
        origin = plugin.drop.origin.Origin(
            source=source,
            adapter=adapter,
            runner=runner,
            routing_tuple=plugin.drop.sources.routing_tuple_for_source(source),
            reply_anchor=None,
            tier="turn_contextvar",
        )
        return origin, adapter

    return _make


class FakeControl:
    def __init__(self, *, created=None, claim_answer=None, await_answer=None):
        self.created = created
        self.claim_answer = claim_answer
        self.await_answer = await_answer or {"ok": False, "error": "unavailable"}
        self.calls: list = []

    async def create(self, *, ttl_seconds=None, notice_platform=None, payload_kind=None, socket_path=None, timeout=None):
        self.calls.append({"op": "create", "ttl_seconds": ttl_seconds, "platform": notice_platform, "payload_kind": payload_kind})
        if self.created is not None:
            return self.created
        expires = int(time.time() * 1000) + (ttl_seconds or 1800) * 1000
        return {
            "ok": True,
            "handoff_id": "H" * 22,
            "url": "http://127.0.0.1:8080/#Q2FwYWJpbGl0eVN0cmluZ0FB",
            "expires_at": expires,
            "ttl_seconds": ttl_seconds or 1800,
            "max_plaintext_bytes": 8192,
            # A real broker states the protocol it speaks; the plugin decides
            # whether the claim boundary is lossless from *this*, not from hope.
            "protocol_version": 2,
            "notice": "🔐 open the secure form http://127.0.0.1:8080/#Q2FwYWJpbGl0eVN0cmluZ0FB",
            "notice_received": "✓ **Private input received**",
            "notice_expired": "✕ **Private input link expired**",
        }

    async def await_submission(self, handoff_id, *, wait_ms, socket_path=None, timeout=None):
        self.calls.append({"op": "await", "handoff_id": handoff_id})
        return self.await_answer

    async def claim(self, handoff_id, *, wait_ms=0, socket_path=None, timeout=None):
        self.calls.append({"op": "claim", "handoff_id": handoff_id})
        return self.claim_answer or {"ok": False, "error": "unavailable"}


def _created(**overrides):
    """A broker ``create`` response, with the fields a test wants overridden.

    Written out rather than mutated in place so a test that drops
    ``protocol_version`` is *saying* "a pre-2 broker", which is the case half of
    these tests exist for.
    """
    created = {
        "ok": True,
        "handoff_id": "H" * 22,
        "url": "http://127.0.0.1:8080/#Q2FwYWJpbGl0eVN0cmluZ0FB",
        "expires_at": int(time.time() * 1000) + 600_000,
        "ttl_seconds": 600,
        "max_plaintext_bytes": 8192,
        "protocol_version": 2,
        "notice": "🔐 open the secure form",
        "notice_received": "✓ **Private input received**",
        "notice_expired": "✕ **Private input link expired**",
    }
    created.update(overrides)
    for key, value in list(created.items()):
        if value is None:
            del created[key]
    return created


class NullWaiters:
    """Records arming without starting anything, so create() is testable alone."""

    def __init__(self):
        self.armed: list = []

    def arm(self, drop_id, coro_factory, **kw):
        self.armed.append(drop_id)
        coro = coro_factory()
        coro.close()
        return True

    def is_armed(self, drop_id):
        return drop_id in self.armed


def _service(plugin, journal, control, waiters=None, **kw):
    return plugin.drop.service.DropService(
        journal=journal,
        control=control,
        waiters=waiters if waiters is not None else NullWaiters(),
        deliver=kw.pop("deliver", None),
        **kw,
    )


# ── create ─────────────────────────────────────────────────────────────────


async def test_create_posts_the_link_journals_and_arms_a_waiter(
    plugin, journal, lane
) -> None:
    origin, adapter = lane()
    control = FakeControl()
    waiters = NullWaiters()

    receipt = await _service(plugin, journal, control, waiters).create(
        origin, ttl_seconds=600, purpose="deploy token", session_key="sess-9"
    )

    assert receipt["ok"] is True
    assert receipt["drop_id"] == "H" * 22
    assert receipt["state"] == "waiting"
    assert control.calls[0] == {"op": "create", "ttl_seconds": 600, "platform": "telegram", "payload_kind": "universal"}

    assert len(adapter.sent) == 1
    assert adapter.sent[0].chat_id == "tg-1"
    assert "#Q2FwYWJpbGl0eVN0cmluZ0FB" in adapter.sent[0].content, "the link must reach the chat"

    stored = journal.get("H" * 22)
    assert stored["state"] == "waiting"
    assert stored["message_id"] == "stub-msg-1"
    assert stored["purpose"] == "deploy token"
    assert stored["session_key"] == "sess-9"
    assert waiters.armed == ["H" * 22]


async def test_the_receipt_carries_no_capability_url_or_payload(
    plugin, journal, lane
) -> None:
    origin, _ = lane()
    receipt = await _service(plugin, journal, FakeControl()).create(origin, ttl_seconds=1800)

    blob = json.dumps(receipt)
    assert "://" not in blob and "#" not in blob
    assert "Q2FwYWJpbGl0eVN0cmluZ0FB" not in blob
    for absent in ("url", "capability", "notice", "plaintext", "plaintext_b64"):
        assert absent not in receipt


async def test_the_receipt_tells_the_model_the_contract(plugin, journal, lane) -> None:
    """at-least-once and idempotent, said where the model actually reads it."""
    origin, _ = lane()
    receipt = await _service(plugin, journal, FakeControl()).create(origin, ttl_seconds=1800)

    assert "at-least-once" in receipt["note"]
    assert "claim_private_input" in receipt["note"]
    assert receipt["expires_in_seconds"] > 0


async def test_a_failed_post_aborts_the_drop_entirely(plugin, journal, lane) -> None:
    """§7.2: a live capability whose link was never delivered is pure risk."""
    origin, adapter = lane(send_ok=False)
    waiters = NullWaiters()

    result = await _service(plugin, journal, FakeControl(), waiters).create(origin, ttl_seconds=300)

    assert result["error"] == "post_failed"
    assert journal.entries() == [], "a drop nobody can see must not be tracked"
    assert waiters.armed == [], "nothing to wait for"


async def test_a_send_that_reports_no_message_id_is_a_failed_post(
    plugin, journal, lane
) -> None:
    """An edit needs a target. A success with no id cannot be edited into a
    terminal state, so it fails now rather than silently 30 minutes later."""
    origin, _ = lane(next_message_id="")
    result = await _service(plugin, journal, FakeControl()).create(origin, ttl_seconds=300)

    assert result["error"] == "post_failed"
    assert journal.entries() == []


async def test_an_unreachable_broker_refuses_before_anything_is_posted(
    plugin, journal, lane
) -> None:
    origin, adapter = lane()
    control = FakeControl(created={"ok": False, "error": "broker_unavailable", "detail": "no socket"})

    result = await _service(plugin, journal, control).create(origin, ttl_seconds=300)

    assert result["error"] == "broker_unavailable"
    assert adapter.sent == []
    assert journal.entries() == []


async def test_a_journal_refusal_retires_the_link_it_cannot_track(
    plugin, journal, lane, monkeypatch
) -> None:
    """If the durable record cannot be written, the capability must not be left
    live and unwatched: the status message is edited to the expired state on the
    way out."""
    origin, adapter = lane()

    def refuse(**kwargs):
        raise plugin.drop.journal.JournalRejected("simulated")

    monkeypatch.setattr(journal, "create_entry", refuse)
    result = await _service(plugin, journal, FakeControl()).create(origin, ttl_seconds=300)

    assert result["error"] == "journal_failed"
    assert [e.content for e in adapter.edited] == ["✕ **Private input link expired**"]


async def test_a_telegram_topic_lane_sends_with_thread_metadata(
    plugin, journal, lane
) -> None:
    origin, adapter = lane(Platform.TELEGRAM, "tg-dm", thread_id="topic-7")
    await _service(plugin, journal, FakeControl()).create(origin, ttl_seconds=300)

    metadata = adapter.sent[0].metadata
    assert metadata, "thread/topic routing must come from the real source"
    assert journal.get("H" * 22)["thread_id"] == "topic-7"


# ── claim ──────────────────────────────────────────────────────────────────


async def _received_entry(plugin, journal, origin, control):
    await _service(plugin, journal, control).create(origin, ttl_seconds=300, purpose="deploy token")
    journal.update("H" * 22, state=plugin.drop.journal.STATE_RECEIVED)
    return journal.get("H" * 22)


async def test_claim_returns_the_payload_once_and_marks_it_spent(
    plugin, journal, lane
) -> None:
    origin, _ = lane()
    import base64

    control = FakeControl(
        claim_answer={
            "ok": True,
            "handoff_id": "H" * 22,
            "plaintext_b64": base64.b64encode(b"e2e-marker-8ad31f").decode("ascii"),
        }
    )
    await _received_entry(plugin, journal, origin, control)
    service = _service(plugin, journal, control)

    first = await service.claim(origin, "H" * 22)
    assert first["ok"] is True
    assert first["private_input"] == "e2e-marker-8ad31f"
    assert journal.get("H" * 22)["claimed_at"] is not None

    second = await service.claim(origin, "H" * 22)
    assert second["error"] == "unavailable"
    assert "private_input" not in second
    assert len([c for c in control.calls if c["op"] == "claim"]) == 1, "no second broker claim"


async def test_claim_succeeds_with_no_wake_having_landed(plugin, journal, lane) -> None:
    origin, _ = lane()
    import base64

    control = FakeControl(
        claim_answer={"ok": True, "handoff_id": "H" * 22, "plaintext_b64": base64.b64encode(b"x").decode()}
    )
    entry = await _received_entry(plugin, journal, origin, control)
    assert entry["announced_at"] is None

    result = await _service(plugin, journal, control).claim(origin, "H" * 22)
    assert result["ok"] is True


async def test_claim_from_a_different_lane_is_refused_without_touching_the_broker(
    plugin, journal, lane
) -> None:
    origin, _ = lane(Platform.TELEGRAM, "tg-1")
    control = FakeControl()
    await _received_entry(plugin, journal, origin, control)
    foreign, _ = lane(Platform.DISCORD, "dc-1")

    result = await _service(plugin, journal, control).claim(foreign, "H" * 22)

    assert result == {"error": "not_authorized"}
    assert [c for c in control.calls if c["op"] == "claim"] == []


async def test_claim_before_the_drop_is_received_is_not_ready(plugin, journal, lane) -> None:
    origin, _ = lane()
    control = FakeControl()
    await _service(plugin, journal, control).create(origin, ttl_seconds=300)

    result = await _service(plugin, journal, control).claim(origin, "H" * 22)
    assert result["error"] == "not_ready"
    assert [c for c in control.calls if c["op"] == "claim"] == []


async def test_an_unknown_drop_id_is_uniformly_unavailable(plugin, journal, lane) -> None:
    origin, _ = lane()
    result = await _service(plugin, journal, FakeControl()).claim(origin, "Z" * 22)
    assert result["error"] == "unavailable"


async def test_a_transport_failure_during_claim_does_not_spend_the_drop(
    plugin, journal, lane
) -> None:
    origin, _ = lane()
    control = FakeControl(claim_answer={"ok": False, "error": "broker_unavailable", "detail": "gone"})
    await _received_entry(plugin, journal, origin, control)

    result = await _service(plugin, journal, control).claim(origin, "H" * 22)

    assert result["error"] == "broker_unavailable"
    assert journal.get("H" * 22)["claimed_at"] is None, "an unanswered claim is not a claim"


async def test_a_payload_free_receipt_is_not_a_re_delivery(plugin, journal, lane) -> None:
    """After a successful claim the broker keeps a payload-free receipt
    (``src/broker.js:81-91``). An ``ok`` with no plaintext must never be dressed
    up as a delivery."""
    origin, _ = lane()
    control = FakeControl(claim_answer={"ok": True, "handoff_id": "H" * 22})
    await _received_entry(plugin, journal, origin, control)

    result = await _service(plugin, journal, control).claim(origin, "H" * 22)

    assert result["error"] == "unavailable"
    assert "private_input" not in result


# ── the whole loop, against the real broker ────────────────────────────────


async def test_the_full_loop_runs_against_the_real_broker(
    plugin, journal, lane, real_public_broker
) -> None:
    origin, adapter = lane()
    control = plugin.drop.control_client
    service = plugin.drop.service.DropService(
        journal=journal,
        control=control,
        socket_path=real_public_broker.socket_path,
        waiters=NullWaiters(),
    )

    receipt = await service.create(origin, ttl_seconds=300, purpose="deploy token")
    assert receipt["ok"] is True

    # The browser gets the link the only way anyone does: from the chat message.
    # (Telegram's renderer wraps it in an ``<a href>``, so this parses it out the
    # way a client would rather than assuming a bare URL.)
    posted = adapter.sent[0].content
    match = re.search(r'https?://[^\s"<>]+#[A-Za-z0-9_-]+', posted)
    assert match, f"no capability link in the posted notice: {posted!r}"
    url = match.group(0)

    deliver_calls: list = []

    async def deliver(adapter_arg, *, text, source=None, session_id=""):
        deliver_calls.append(text)

    waiter = plugin.drop.waiter.DropWaiter(
        journal=journal,
        control=control,
        socket_path=real_public_broker.socket_path,
        deliver=deliver,
    )
    parked = asyncio.ensure_future(waiter.run(drop_id=receipt["drop_id"], origin=origin))
    await asyncio.sleep(0.2)  # let the park reach the broker before submitting

    loop = asyncio.get_running_loop()
    submitted = await loop.run_in_executor(
        None, real_public_broker.submit, url, "e2e-marker-8ad31f"
    )
    assert submitted == "SUBMITTED sent", submitted

    result = await asyncio.wait_for(parked, timeout=30)
    assert result["state"] == "received", result
    assert [e.content for e in adapter.edited] == ["✓ **Private input received**"]
    assert len(deliver_calls) == 1

    claimed = await service.claim(origin, receipt["drop_id"])
    assert claimed["ok"] is True
    assert claimed["private_input"] == "e2e-marker-8ad31f"

    second = await service.claim(origin, receipt["drop_id"])
    assert second["error"] == "unavailable"


async def test_combined_files_full_loop_materializes_privately_and_leaks_only_to_model_result(
    plugin, journal, lane, real_public_broker, tmp_path, caplog
) -> None:
    canary = "combined-private-canary-4f9182"
    binary = bytes([0, 255, 1, 128, 42])
    origin, adapter = lane()
    spool_root = tmp_path / "private-spool"
    spool_root.mkdir(mode=0o700)
    spool = plugin.drop.spool.Spool(root=spool_root)
    service = plugin.drop.service.DropService(
        journal=journal, control=plugin.drop.control_client,
        socket_path=real_public_broker.socket_path, waiters=NullWaiters(), spool=spool)

    receipt = await service.create(origin, ttl_seconds=300, purpose="combined e2e")
    posted = adapter.sent[0].content
    url = re.search(r'https?://[^\s"<>]+#[A-Za-z0-9_-]+', posted).group(0)
    loop = asyncio.get_running_loop()
    waiter = plugin.drop.waiter.DropWaiter(
        journal=journal, control=plugin.drop.control_client,
        socket_path=real_public_broker.socket_path, deliver=lambda *args, **kwargs: None)
    parked = asyncio.create_task(waiter.run(drop_id=receipt["drop_id"], origin=origin))
    await asyncio.sleep(0.1)
    submitted = await loop.run_in_executor(None, real_public_broker.submit_combined, url, canary,
                                           [("secret-original.bin", binary), ("empty-original", b"")])
    assert submitted == "SUBMITTED received"
    wake = await asyncio.wait_for(parked, 10)
    assert wake["state"] == "received"

    wrong_origin, _ = lane(chat_id="wrong-chat")
    before = set(spool_root.iterdir())
    refused = await service.claim_files(wrong_origin, receipt["drop_id"])
    assert refused["ok"] is False
    assert set(spool_root.iterdir()) == before, "wrong origin must not begin/stage a transfer"

    result = await service.claim_files(origin, receipt["drop_id"])
    assert result["ok"] is True and result["private_input"] == canary, result
    assert len(result["files"]) == 2
    claim_dir = Path(result["files"][0]["path"]).parent
    assert claim_dir.stat().st_mode & 0o777 == 0o700
    assert claim_dir.parent == spool_root
    assert all(Path(item["path"]).stat().st_mode & 0o777 == 0o600 for item in result["files"])
    assert all(Path(item["path"]).name not in {"secret-original.bin", "empty-original"}
               for item in result["files"])
    assert Path(result["files"][0]["path"]).read_bytes() == binary
    assert Path(result["files"][1]["path"]).read_bytes() == b""
    assert result["files"][0]["sha256"] == hashlib.sha256(binary).hexdigest()

    second = await service.claim_files(origin, receipt["drop_id"])
    assert second["ok"] is False
    # The model result legitimately contains private_input. Every serialized/logged/
    # durable surface must not; file bytes exist only at the randomized safe paths.
    safe_paths = {item["path"] for item in result["files"]}
    surfaces = [caplog.text, json.dumps(journal.entries()), posted,
                json.dumps([e.content for e in adapter.edited]), json.dumps(refused), json.dumps(second),
                "\n".join(str(path) for path in spool_root.rglob("*"))]
    for surface in surfaces:
        assert canary not in surface and "secret-original.bin" not in surface
    for path in spool_root.rglob("*"):
        if path.is_file() and str(path) not in safe_paths:
            assert canary.encode() not in path.read_bytes()


async def test_a_real_expiry_wakes_the_parked_waiter_without_polling(
    plugin, journal, lane, real_public_broker
) -> None:
    """The park self-terminates at the handoff's own expiry
    (``src/broker.js:315-341``) — one request, no timer of ours."""
    origin, adapter = lane()
    control = plugin.drop.control_client
    service = plugin.drop.service.DropService(
        journal=journal,
        control=control,
        socket_path=real_public_broker.socket_path,
        waiters=NullWaiters(),
    )
    receipt = await service.create(origin, ttl_seconds=2)
    assert receipt["ok"] is True

    waiter = plugin.drop.waiter.DropWaiter(
        journal=journal,
        control=control,
        socket_path=real_public_broker.socket_path,
        deliver=_noop_deliver,
    )
    started = time.monotonic()
    result = await asyncio.wait_for(
        waiter.run(drop_id=receipt["drop_id"], origin=origin), timeout=30
    )
    elapsed = time.monotonic() - started

    assert result["state"] == "expired"
    assert 1.0 < elapsed < 15.0, f"the park did not track the real deadline ({elapsed:.1f}s)"
    assert [e.content for e in adapter.edited] == ["✕ **Private input link expired**"]


async def _noop_deliver(adapter, *, text, source=None, session_id=""):
    return None


async def test_nothing_secret_reaches_the_journal_the_wake_or_the_logs(
    plugin, journal, lane, real_public_broker, caplog
) -> None:
    """§8.8/§8.9 as an exact-string sweep over a real run.

    The capability and the payload are both known here, so this is not a shape
    check: the two exact strings are searched for in every durable file, every
    wake text, every tool-visible result and every log record emitted while the
    drop ran. The capability is allowed in exactly one place — the chat message —
    and the payload in exactly one — the claim result."""
    import logging

    caplog.set_level(logging.DEBUG)
    payload = "e2e-marker-8ad31f-payload"
    origin, adapter = lane()
    control = plugin.drop.control_client
    wakes: list = []

    async def deliver(adapter_arg, *, text, source=None, session_id=""):
        wakes.append(text)

    service = plugin.drop.service.DropService(
        journal=journal,
        control=control,
        socket_path=real_public_broker.socket_path,
        waiters=NullWaiters(),
        deliver=deliver,
    )
    receipt = await service.create(origin, ttl_seconds=60, purpose="deploy token")
    posted = adapter.sent[0].content
    url = re.search(r'https?://[^\s"<>]+#([A-Za-z0-9_-]+)', posted)
    capability = url.group(1)

    waiter = plugin.drop.waiter.DropWaiter(
        journal=journal,
        control=control,
        socket_path=real_public_broker.socket_path,
        deliver=deliver,
    )
    parked = asyncio.ensure_future(waiter.run(drop_id=receipt["drop_id"], origin=origin))
    await asyncio.sleep(0.2)
    loop = asyncio.get_running_loop()
    assert (
        await loop.run_in_executor(None, real_public_broker.submit, url.group(0), payload)
        == "SUBMITTED sent"
    )
    await asyncio.wait_for(parked, timeout=30)
    claimed = await service.claim(origin, receipt["drop_id"])
    assert claimed["private_input"] == payload

    journalled = "\n".join(
        path.read_text(encoding="utf-8") for path in journal.root.glob("*.json")
    )
    logged = "\n".join(record.getMessage() for record in caplog.records)

    for haystack, name in (
        (journalled, "the journal"),
        ("\n".join(wakes), "the wake text"),
        (logged, "the logs"),
        (json.dumps(receipt), "the create receipt"),
    ):
        assert capability not in haystack, f"the capability reached {name}"
        assert payload not in haystack, f"the payload reached {name}"

    assert capability in posted, "the chat message is the one place it belongs"
    assert payload in json.dumps(claimed), "the claim result is the one place it belongs"


# ── N2: an oversized broker cap is named at create time, not discovered at claim


async def test_create_warns_when_the_broker_accepts_more_than_a_claim_can_carry(
    plugin, journal, lane, caplog
) -> None:
    """The operator raised ``HANDOFF_MAX_PLAINTEXT_BYTES`` past what we can read.

    The failure this warns about is silent and terminal: ``broker.claim`` retires
    the record before writing the response, so a response the control client
    refuses to buffer is a destroyed secret reported as ``broker_unavailable``.
    Saying it at create time — with both numbers, while nothing is at stake yet —
    is the difference between a config note and an incident.
    """
    import logging

    ceiling = plugin.drop.control_client.MAX_CLAIMABLE_PLAINTEXT_BYTES
    origin, _adapter = lane()
    control = FakeControl(created=_created(max_plaintext_bytes=ceiling + 1))

    with caplog.at_level(logging.WARNING):
        receipt = await _service(plugin, journal, control).create(origin, ttl_seconds=600)

    assert receipt["ok"] is True, "a warning, not a refusal — small payloads still work"
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert str(ceiling) in logged and str(ceiling + 1) in logged, logged
    assert "HANDOFF_MAX_PLAINTEXT_BYTES" in logged, logged

    # The warning has to describe what actually happens now. It said "destroyed
    # on claim and reported unavailable" long after the broker started refusing
    # before it consumes anything — a stale warning is worse than none, because an
    # operator acts on it.
    assert "destroy" not in logged.lower(), logged
    assert "unavailable" not in logged.lower(), logged
    assert "refus" in logged.lower(), "say what the broker will really do"
    # And it has to be actionable in the same words the claim-time refusal uses.
    # This drop *is* about to be posted, so a payload can end up stuck behind the
    # ceiling and the CLI really can fetch it — unlike the broker_too_old abort.
    assert "handoff-admin claim" in logged, "name the recovery an operator can run"
    assert plugin.drop.service.SIZE_REMEDIATION % ceiling in logged, "one wording, everywhere"


async def test_create_says_nothing_when_the_broker_cap_fits(
    plugin, journal, lane, caplog
) -> None:
    """The default path stays quiet. A warning that fires on every drop is noise,
    and noise is how the one that matters gets missed."""
    import logging

    origin, _adapter = lane()

    with caplog.at_level(logging.WARNING):
        receipt = await _service(plugin, journal, FakeControl()).create(origin, ttl_seconds=600)

    assert receipt["ok"] is True
    assert "HANDOFF_MAX_PLAINTEXT_BYTES" not in "\n".join(
        record.getMessage() for record in caplog.records
    )


# ── the lossless claim boundary ────────────────────────────────────────────
#
# Two ways a claim that the broker answered could still end in a lost secret:
# the answer is bigger than this client can read (the broker retires the record
# before writing it), and the local bookkeeping after a *successful* read fails.
# The first is now refused on the wire before anything is consumed; the second
# must never discard a payload that is already in hand.


class OneShotControl(FakeControl):
    """A claim answers once and is a payload-free receipt thereafter.

    ``FakeControl`` re-delivers on every call, which no real broker does
    (``src/broker.js`` retires to a receipt). Anything asserting "and a retry gets
    nothing" has to model the receipt, or it is asserting against the fake.
    """

    def __init__(self, **kw):
        super().__init__(**kw)
        self._spent = False

    async def claim(self, handoff_id, *, wait_ms=0, socket_path=None, timeout=None):
        self.calls.append({"op": "claim", "handoff_id": handoff_id})
        if self._spent:
            return {"ok": False, "error": "unavailable"}
        self._spent = True
        return self.claim_answer or {"ok": False, "error": "unavailable"}


async def test_a_response_too_large_refusal_leaves_the_drop_claimable(
    plugin, journal, lane
) -> None:
    """The broker refused before consuming, so this is not a spent drop.

    It is also not ``broker_unavailable``: the broker answered, and it answered
    about *this reader*, not about the handoff. Marking the drop spent here would
    convert a refusal that cost nothing into the loss it exists to prevent.
    """
    origin, _ = lane()
    control = FakeControl(
        claim_answer={
            "ok": False,
            "error": "response_too_large",
            "required_bytes": 2_000_000,
            "max_response_bytes": 1_048_576,
        }
    )
    await _received_entry(plugin, journal, origin, control)

    result = await _service(plugin, journal, control).claim(origin, "H" * 22)

    assert result["error"] == "response_too_large", result
    assert "private_input" not in result
    assert journal.get("H" * 22)["claimed_at"] is None, "a refused claim is not a claim"
    assert journal.get("H" * 22)["state"] == plugin.drop.journal.STATE_RECEIVED

    # Still claimable — by a reader that can hold it, or by the admin CLI, until
    # the handoff's own TTL lapses.
    import base64

    working = FakeControl(
        claim_answer={
            "ok": True,
            "handoff_id": "H" * 22,
            "plaintext_b64": base64.b64encode(b"still-here-4f21").decode("ascii"),
        }
    )
    retried = await _service(plugin, journal, working).claim(origin, "H" * 22)
    assert retried["ok"] is True
    assert retried["private_input"] == "still-here-4f21"


async def test_a_refusal_reaching_the_model_names_no_broker_internals(plugin) -> None:
    """``response_too_large`` is a tool result, so it goes through the same gate
    every other refusal does. A code the vocabulary has never heard of gets the
    generic sentence, which would tell the model nothing about what to do."""
    sanitized = plugin.drop.safe_errors.sanitize_tool_result(
        {
            "error": "response_too_large",
            "detail": "required 2000000 bytes, this client reads 1048576",
        }
    )
    assert sanitized["error"] == "response_too_large"
    assert sanitized["detail"] != plugin.drop.safe_errors.DEFAULT_REASON
    assert "2000000" not in sanitized["detail"], "byte counts are for agent.log, not the model"


async def test_a_journal_failure_after_a_read_does_not_discard_the_secret(
    plugin, journal, lane, caplog
) -> None:
    """The payload is already in hand and the broker has already destroyed its
    copy. A failed ``claimed_at`` write is a bookkeeping problem; letting it raise
    turned it into ``internal_error`` and lost the only remaining copy."""
    import base64
    import logging

    origin, _ = lane()
    control = OneShotControl(
        claim_answer={
            "ok": True,
            "handoff_id": "H" * 22,
            "plaintext_b64": base64.b64encode(b"survives-bookkeeping-9c").decode("ascii"),
        }
    )
    await _received_entry(plugin, journal, origin, control)

    class UnwritableJournal:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def update(self, drop_id, **changes):
            if "claimed_at" in changes:
                raise OSError("[Errno 30] Read-only file system")
            return self._inner.update(drop_id, **changes)

    service = _service(plugin, UnwritableJournal(journal), control)

    with caplog.at_level(logging.ERROR):
        result = await service.claim(origin, "H" * 22)

    assert result["ok"] is True, result
    assert result["private_input"] == "survives-bookkeeping-9c"
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "H" * 22 in logged, logged
    assert "survives-bookkeeping-9c" not in logged, "the secret must not reach agent.log"

    # Honest about what it could not do: the entry is genuinely unmarked, so the
    # model is told rather than left to infer it from a silent success.
    assert journal.get("H" * 22)["claimed_at"] is None
    assert result.get("note"), "a claim that could not be recorded says so"

    # And the unmarked entry cannot become a second delivery: authorisation lets
    # the retry through, and the broker's receipt is what stops it.
    retry = await service.claim(origin, "H" * 22)
    assert retry["error"] == "unavailable"
    assert "private_input" not in retry


# ── mixed versions: a 0.5 plugin against a 0.4 broker ──────────────────────
#
# The two halves of this repo ship together; an installed plugin and a deployed
# broker do not. A broker that predates the response-size capability ignores
# ``max_response_bytes`` and destroys an oversized payload exactly as it always
# did — so the plugin must not treat "I sent a ceiling" as "the boundary is
# lossless". It reads the answer instead: ``protocol_version``, in the response
# every drop already starts with.


async def test_a_pre_2_broker_that_can_overrun_the_reader_is_refused_before_posting(
    plugin, journal, lane, caplog
) -> None:
    """The one genuinely unsafe combination, refused while nothing is at stake.

    Old broker *and* a cap above what this client can read: the payload would be
    destroyed on claim with no refusal available, and the user would have typed it
    in by then. So the drop dies before the link is posted — no message, no
    journal entry, no waiter — which is the same argument §7.2 makes for a failed
    post, applied one step earlier.
    """
    import logging

    ceiling = plugin.drop.control_client.MAX_CLAIMABLE_PLAINTEXT_BYTES
    origin, adapter = lane()
    waiters = NullWaiters()
    control = FakeControl(
        created=_created(protocol_version=None, max_plaintext_bytes=ceiling + 1)
    )

    with caplog.at_level(logging.WARNING):
        result = await _service(plugin, journal, control, waiters).create(origin, ttl_seconds=600)

    assert result["error"] == plugin.drop.service.ERROR_BROKER_TOO_OLD, result
    assert adapter.sent == [], "nothing may be posted for a drop that cannot be claimed back"
    assert journal.entries() == []
    assert waiters.armed == []

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert str(ceiling) in logged and str(ceiling + 1) in logged, logged
    assert "HANDOFF_MAX_PLAINTEXT_BYTES" in logged, logged
    assert "upgrade" in logged.lower(), "name the fix, which is the broker's version"

    # And it must not send the operator after a payload that cannot exist. This
    # drop was refused before its link was posted: nothing was shown to anyone and
    # nothing was submitted, so the handoff is empty and simply lapses.
    assert "handoff-admin claim" not in logged, logged
    assert "lapse" in logged.lower(), "say what becomes of the handoff that was minted"


async def test_a_pre_2_broker_within_the_readable_range_still_works(
    plugin, journal, lane, caplog
) -> None:
    """Refusing every drop against an old broker would be an upgrade held hostage
    to a ceiling only a large payload can reach. Within the range this client can
    read, a 0.4 broker is exactly as safe as it was under 0.4 — so the drop
    proceeds and the version gap is said once, in ``agent.log``."""
    import logging

    origin, adapter = lane()
    control = FakeControl(created=_created(protocol_version=None))

    with caplog.at_level(logging.WARNING):
        receipt = await _service(plugin, journal, control).create(origin, ttl_seconds=600)

    assert receipt["ok"] is True, receipt
    assert len(adapter.sent) == 1
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "protocol" in logged.lower(), logged
    assert "HANDOFF_MAX_PLAINTEXT_BYTES" not in logged, "not the cap warning; the version one"


async def test_a_version_2_broker_says_nothing_at_all(plugin, journal, lane, caplog) -> None:
    """The supported path is silent. A warning on every drop is noise, and noise
    is how the one that matters gets missed."""
    import logging

    origin, _ = lane()

    with caplog.at_level(logging.WARNING):
        receipt = await _service(plugin, journal, FakeControl()).create(origin, ttl_seconds=600)

    assert receipt["ok"] is True
    assert [r.getMessage() for r in caplog.records] == []


async def test_every_refusal_this_task_adds_reaches_the_model_with_a_reason(plugin) -> None:
    """A code with no entry gets ``DEFAULT_REASON``, which tells a model nothing
    it can act on. Both new codes have to name the remediation, and neither may
    contradict the operator-facing log line."""
    safe_errors = plugin.drop.safe_errors
    service = plugin.drop.service

    for code in (service.ERROR_RESPONSE_TOO_LARGE, service.ERROR_BROKER_TOO_OLD):
        reason = safe_errors.SAFE_REASONS.get(code)
        assert reason, f"{code} has no fixed sentence"
        assert reason != safe_errors.DEFAULT_REASON
        sanitized = safe_errors.sanitize_tool_result({"error": code, "detail": "1048576 bytes"})
        assert sanitized["detail"] == reason, "the broker's numbers never reach the model"

    # The single remediation that is actually true for an oversized payload: the
    # value cannot come back through the plugin at all, so a shorter one is the
    # only thing the model can do. "Raise the limit" would be wrong twice — the
    # reader's ceiling is a constant, and the broker's cap has to come *down*.
    too_large = safe_errors.SAFE_REASONS[service.ERROR_RESPONSE_TOO_LARGE]
    assert "shorter" in too_large
    assert "raise" not in too_large.lower(), too_large



async def test_universal_files_claim_dispatches_internally_after_authorization(plugin, journal, lane, monkeypatch) -> None:
    origin, _ = lane(); control = FakeControl(); await _received_entry(plugin, journal, origin, control)
    journal.update("H" * 22, payload_kind="files")
    calls = []
    async def materialize(drop_id, claimed_origin, **kwargs):
        calls.append((drop_id, claimed_origin)); return {"ok": True, "files": [{"path": "/safe/spool/f.bin", "name": "f.bin", "type": "", "size": 0, "sha256": "0" * 64, "expires_at": 1}], "mark_spent": True}
    monkeypatch.setattr(plugin.drop.materialize, "materialize_file_claim", materialize)
    result = await _service(plugin, journal, control).claim(origin, "H" * 22)
    assert result["files"][0]["path"].startswith("/safe/spool/")
    assert calls == [("H" * 22, origin)]
    assert not [call for call in control.calls if call["op"] == "claim"]


async def test_universal_files_wrong_origin_refuses_before_claim_or_staging(plugin, journal, lane, monkeypatch) -> None:
    origin, _ = lane(); control = FakeControl(); await _received_entry(plugin, journal, origin, control); journal.update("H" * 22, payload_kind="files")
    staged = []
    async def materialize(*args, **kwargs): staged.append(args); raise AssertionError("must not stage")
    monkeypatch.setattr(plugin.drop.materialize, "materialize_file_claim", materialize)
    foreign, _ = lane(Platform.DISCORD, "foreign")
    result = await _service(plugin, journal, control).claim(foreign, "H" * 22)
    assert result == {"error": "not_authorized"}; assert staged == []; assert not [c for c in control.calls if c["op"] == "claim"]
