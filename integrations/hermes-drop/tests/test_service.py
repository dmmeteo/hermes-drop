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
import json
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

    async def create(self, *, ttl_seconds=None, notice_platform=None, socket_path=None, timeout=None):
        self.calls.append({"op": "create", "ttl_seconds": ttl_seconds, "platform": notice_platform})
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
    assert control.calls[0] == {"op": "create", "ttl_seconds": 600, "platform": "telegram"}

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
    control = FakeControl(
        created={
            "ok": True,
            "handoff_id": "H" * 22,
            "url": "http://127.0.0.1:8080/#Q2FwYWJpbGl0eVN0cmluZ0FB",
            "expires_at": int(time.time() * 1000) + 600_000,
            "ttl_seconds": 600,
            "max_plaintext_bytes": ceiling + 1,
            "notice": "🔐 open the secure form",
            "notice_received": "✓ **Private input received**",
            "notice_expired": "✕ **Private input link expired**",
        }
    )

    with caplog.at_level(logging.WARNING):
        receipt = await _service(plugin, journal, control).create(origin, ttl_seconds=600)

    assert receipt["ok"] is True, "a warning, not a refusal — small payloads still work"
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert str(ceiling) in logged and str(ceiling + 1) in logged, logged
    assert "HANDOFF_MAX_PLAINTEXT_BYTES" in logged, logged


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
