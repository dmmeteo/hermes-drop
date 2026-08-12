"""S7 — ``DropWaiter`` and the failure matrix, one test per row.

The waiter is one ``asyncio`` task per live drop on the gateway loop, holding an
open ``await`` against the broker's own in-process waiter — **zero polls on
either edge** (``src/broker.js:315-341``; the park self-terminates at the
handoff's expiry). On resolution it does three things in a fixed order:

    edit  →  journal  →  announce

Edit first because it is the only step the user can see and the only one that
stops a dead link advertising itself. Journal second because it is the only step
that must survive. Announce last because it is best-effort — at-least-once and
idempotent, never exactly-once (plan §3.3).

Two rows of the matrix cannot be reproduced from outside core and are modelled
rather than executed: a wake merged into a pending user message
(``gateway/platforms/base.py:2487-2494``) and a wake dropped by the busy
handler's auth gate or drain branch (``gateway/run.py:8356-8365``, ``:8368-8393``).
Each of those tests says so in its docstring and asserts the property that makes
the row survivable, which is the property we actually control: the journal is
unaffected and the next trigger re-announces.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest
from gateway.config import Platform

from _stubs import StubAdapter, StubRunner
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
        adapter = StubAdapter(platform, **kw)
        runner = StubRunner({platform: adapter})
        source = adapter.build_source(chat_id=chat_id, chat_type="dm", user_id="u-1")
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


def _waiting(journal, origin, *, drop_id="A" * 22, expires_in_ms=600_000, purpose="deploy token"):
    return journal.create_entry(
        drop_id=drop_id,
        origin=origin,
        message_id=f"msg-{drop_id[:4]}",
        expires_at_ms=int(time.time() * 1000) + expires_in_ms,
        ttl_seconds=1800,
        purpose=purpose,
        session_key="s",
        notice_received="✓ **Private input received**",
        notice_expired="✕ **Private input link expired**",
    )


class FakeControl:
    """Counts every round trip, so "no polling" is an assertion, not a claim."""

    def __init__(self, *, answer=None, claim_answer=None, park_s: float = 0.0):
        self.answer = answer if answer is not None else {"ok": False, "error": "unavailable"}
        self.claim_answer = claim_answer
        self.park_s = park_s
        self.await_calls: list = []
        self.claim_calls: list = []

    async def await_submission(self, handoff_id, *, wait_ms, socket_path=None, timeout=None):
        self.await_calls.append({"handoff_id": handoff_id, "wait_ms": wait_ms})
        if self.park_s:
            await asyncio.sleep(self.park_s)
        return self.answer

    async def claim(self, handoff_id, *, wait_ms=0, socket_path=None, timeout=None):
        self.claim_calls.append(handoff_id)
        return self.claim_answer or {"ok": False, "error": "unavailable"}


class FakeDeliver:
    def __init__(self, *, fails: bool = False):
        self.fails = fails
        self.calls: list = []

    async def __call__(self, adapter, *, text, source=None, session_id=""):
        self.calls.append({"adapter": adapter, "text": text, "source": source})
        if self.fails:
            raise RuntimeError("wake refused")


def _waiter(plugin, journal, control, deliver, **kw):
    return plugin.drop.waiter.DropWaiter(
        journal=journal, control=control, deliver=deliver, **kw
    )


# ── the matrix ─────────────────────────────────────────────────────────────


async def test_normal_submit_edits_journals_and_announces_once(
    plugin, journal, lane
) -> None:
    origin, adapter = lane()
    entry = _waiting(journal, origin)
    control = FakeControl(answer={"ok": True, "handoff_id": entry["drop_id"], "status": "submitted"})
    deliver = FakeDeliver()

    result = await _waiter(plugin, journal, control, deliver).run(
        drop_id=entry["drop_id"], origin=origin
    )

    assert result["state"] == "received"
    stored = journal.get(entry["drop_id"])
    assert stored["state"] == "received"
    assert [e.content for e in adapter.edited] == ["✓ **Private input received**"]
    assert len(deliver.calls) == 1
    # The payload reaches the model only through claim_private_input (§3.2).
    assert control.claim_calls == []
    assert "plaintext" not in deliver.calls[0]["text"]


async def test_expiry_edits_journals_announces_and_never_claims(
    plugin, journal, lane
) -> None:
    origin, adapter = lane()
    entry = _waiting(journal, origin)
    control = FakeControl(answer={"ok": False, "error": "unavailable"})
    deliver = FakeDeliver()

    result = await _waiter(plugin, journal, control, deliver).run(
        drop_id=entry["drop_id"], origin=origin
    )

    assert result["state"] == "expired"
    assert journal.get(entry["drop_id"])["state"] == "expired"
    assert [e.content for e in adapter.edited] == ["✕ **Private input link expired**"]
    assert control.claim_calls == [], "expiry must never attempt a claim"
    assert "expired" in deliver.calls[0]["text"]


async def test_a_transport_failure_never_claims_on_a_guess(plugin, journal, lane) -> None:
    """The broker restarted mid-wait, so the answer never came. That is
    ``unknown``, and it mirrors ``await``'s exit 1 (``bin/handoff-admin.mjs:31-36``):
    the payload's fate is genuinely unknown, so the one thing that must not
    happen is a claim."""
    origin, adapter = lane()
    entry = _waiting(journal, origin)
    control = FakeControl(
        answer={"ok": False, "error": "broker_unavailable", "detail": "socket gone"}
    )
    deliver = FakeDeliver()

    result = await _waiter(plugin, journal, control, deliver).run(
        drop_id=entry["drop_id"], origin=origin
    )

    assert result["state"] == "transport_failed"
    assert journal.get(entry["drop_id"])["state"] == "transport_failed"
    # The link must stop advertising itself either way.
    assert [e.content for e in adapter.edited] == ["✕ **Private input link expired**"]
    assert control.claim_calls == []
    assert "did not complete" in deliver.calls[0]["text"]
    assert "do not claim" in deliver.calls[0]["text"]


async def test_a_gateway_restart_mid_wait_is_recovered_by_the_reconciler(
    plugin, journal, lane
) -> None:
    """The waiter is a task on a loop that no longer exists; nothing announced it,
    nothing edited it. S6's reconciler is the mechanism, and it is idempotent."""
    origin, adapter = lane()
    entry = _waiting(journal, origin, expires_in_ms=-1)  # the TTL lapsed while down
    deliver = FakeDeliver()
    plugin.drop.reconciler.reset_for_tests()

    summary = await plugin.drop.reconciler.reconcile(
        journal=journal,
        runner=origin.runner,
        registry=plugin.drop.sources.REGISTRY,
        messenger=plugin.drop.messenger.OriginMessenger(),
        control=FakeControl(),
        deliver=deliver,
    )

    assert summary["expired"] == [entry["drop_id"]]
    assert journal.get(entry["drop_id"])["state"] == "expired"
    assert len(adapter.edited) == 1 and len(deliver.calls) == 1


async def test_two_drops_resolving_in_one_turn_are_both_journalled_and_named(
    plugin, journal, lane
) -> None:
    """Both terminal states journalled, both claimable, and no drop can be lost
    to the boundary-merging append at ``gateway/platforms/base.py:2487-2494``.

    "Self-contained" is a claim about *what is still outstanding*, not about
    repetition: an announce that already landed is not repeated (that is the
    duplicate-announce row), but an announce that did **not** land leaves its
    drop unannounced, so the next wake carries it too. Both halves are asserted
    here, because only the second one is what makes a merge survivable."""
    origin, adapter = lane()
    first = _waiting(journal, origin, drop_id="A" * 22, purpose="deploy token")
    second = _waiting(journal, origin, drop_id="B" * 22, purpose="ssh key")
    deliver = FakeDeliver()

    submitted = FakeControl(answer={"ok": True, "handoff_id": "A" * 22, "status": "submitted"})
    lapsed = FakeControl(answer={"ok": False, "error": "unavailable"})
    await _waiter(plugin, journal, submitted, deliver).run(drop_id=first["drop_id"], origin=origin)
    await _waiter(plugin, journal, lapsed, deliver).run(drop_id=second["drop_id"], origin=origin)

    assert journal.get("A" * 22)["state"] == "received"
    assert journal.get("B" * 22)["state"] == "expired"
    assert len(adapter.edited) == 2
    assert [call["text"].count("drop:") for call in deliver.calls] == [1, 1]
    assert "A" * 22 in deliver.calls[0]["text"]
    assert "B" * 22 in deliver.calls[1]["text"]
    for drop_id in ("A" * 22, "B" * 22):
        assert journal.get(drop_id)["announced_at"] is not None

    assert (
        plugin.drop.journal.authorize_claim(journal.get("A" * 22), origin) is None
    ), "a received drop stays claimable after a sibling resolved"


async def test_a_lost_first_wake_makes_the_second_one_name_both_drops(
    plugin, journal, lane
) -> None:
    """The row's real content: the wake that *does* land is complete with respect
    to everything still outstanding, so a dropped, merged or drain-queued
    predecessor loses nothing."""
    origin, _ = lane()
    first = _waiting(journal, origin, drop_id="A" * 22, purpose="deploy token")
    second = _waiting(journal, origin, drop_id="B" * 22, purpose="ssh key")

    lost = FakeDeliver(fails=True)
    await _waiter(
        plugin,
        journal,
        FakeControl(answer={"ok": True, "handoff_id": "A" * 22, "status": "submitted"}),
        lost,
    ).run(drop_id=first["drop_id"], origin=origin)
    assert journal.get("A" * 22)["announced_at"] is None

    landed = FakeDeliver()
    await _waiter(
        plugin, journal, FakeControl(answer={"ok": False, "error": "unavailable"}), landed
    ).run(drop_id=second["drop_id"], origin=origin)

    text = landed.calls[0]["text"]
    assert "A" * 22 in text and "B" * 22 in text
    assert journal.get("A" * 22)["announced_at"] is not None


async def test_a_merged_wake_leaves_the_journal_intact_and_stays_claimable(
    plugin, journal, lane
) -> None:
    """Core's merge cannot be executed from here — it happens inside
    ``_handle_message``'s busy path. What is asserted is the property that makes
    a merge survivable and that this code owns: the wake text is complete on its
    own, the journal is untouched by delivery, and the claim never consulted the
    wake."""
    origin, _ = lane()
    entry = _waiting(journal, origin)
    deliver = FakeDeliver()
    control = FakeControl(answer={"ok": True, "handoff_id": entry["drop_id"], "status": "submitted"})

    await _waiter(plugin, journal, control, deliver).run(drop_id=entry["drop_id"], origin=origin)

    text = deliver.calls[0]["text"]
    assert entry["drop_id"] in text and "claim_private_input" in text
    assert "at-least-once" in text
    stored = journal.get(entry["drop_id"])
    assert stored["state"] == "received"
    assert plugin.drop.journal.authorize_claim(stored, origin) is None


async def test_a_dropped_wake_leaves_the_entry_unannounced_for_the_next_trigger(
    plugin, journal, lane
) -> None:
    """The busy handler returns ``True`` — handled, silently dropped — for an
    unauthorised source *before* the internal branch is reached
    (``gateway/run.py:8356-8365`` vs ``:8486-8487``), and the drain branch queues
    and posts chat noise instead (``:8368-8393``). ``deliver_wake`` raising is the
    observable form of both here."""
    origin, adapter = lane()
    entry = _waiting(journal, origin)
    deliver = FakeDeliver(fails=True)
    control = FakeControl(answer={"ok": True, "handoff_id": entry["drop_id"], "status": "submitted"})

    await _waiter(plugin, journal, control, deliver).run(drop_id=entry["drop_id"], origin=origin)

    stored = journal.get(entry["drop_id"])
    assert stored["state"] == "received", "the durable record does not depend on the wake"
    assert stored["announced_at"] is None
    assert stored["announce_attempts"] == 1
    assert len(adapter.edited) == 1

    # The next trigger re-announces it, unchanged.
    plugin.drop.reconciler.reset_for_tests()
    good = FakeDeliver()
    summary = await plugin.drop.reconciler.reconcile(
        journal=journal,
        runner=origin.runner,
        registry=plugin.drop.sources.REGISTRY,
        messenger=plugin.drop.messenger.OriginMessenger(),
        control=FakeControl(),
        deliver=good,
    )
    assert summary["announced"] == [entry["drop_id"]]
    assert journal.get(entry["drop_id"])["announced_at"] is not None


async def test_a_duplicate_resolution_edits_once_and_announces_once(
    plugin, journal, lane
) -> None:
    """Journal state is the guard: no second edit, no second announce, no claim."""
    origin, adapter = lane()
    entry = _waiting(journal, origin)
    deliver = FakeDeliver()
    control = FakeControl(answer={"ok": True, "handoff_id": entry["drop_id"], "status": "submitted"})

    first = await _waiter(plugin, journal, control, deliver).run(
        drop_id=entry["drop_id"], origin=origin
    )
    second = await _waiter(plugin, journal, control, deliver).run(
        drop_id=entry["drop_id"], origin=origin
    )

    assert first["state"] == "received"
    assert second.get("duplicate") is True
    assert len(adapter.edited) == 1
    assert len(deliver.calls) == 1
    assert control.claim_calls == []


async def test_a_lost_edit_is_journalled_and_does_not_stop_the_announce(
    plugin, journal, lane
) -> None:
    origin, adapter = lane(edit_ok=False)
    entry = _waiting(journal, origin)
    deliver = FakeDeliver()
    control = FakeControl(answer={"ok": True, "handoff_id": entry["drop_id"], "status": "submitted"})

    result = await _waiter(plugin, journal, control, deliver).run(
        drop_id=entry["drop_id"], origin=origin
    )

    assert result["edit_failed"] is True
    stored = journal.get(entry["drop_id"])
    assert stored["state"] == "received" and stored["edit_failed"] is True
    assert len(deliver.calls) == 1
    assert plugin.drop.journal.authorize_claim(stored, origin) is None


async def test_concurrent_drops_on_two_platforms_never_cross_talk(
    plugin, journal, lane
) -> None:
    tg_origin, tg_adapter = lane(Platform.TELEGRAM, "tg-1")
    dc_origin, dc_adapter = lane(Platform.DISCORD, "dc-1")
    tg = _waiting(journal, tg_origin, drop_id="T" * 22)
    dc = _waiting(journal, dc_origin, drop_id="D" * 22)
    deliver = FakeDeliver()

    await asyncio.gather(
        _waiter(
            plugin,
            journal,
            FakeControl(answer={"ok": True, "handoff_id": "T" * 22, "status": "submitted"}),
            deliver,
        ).run(drop_id=tg["drop_id"], origin=tg_origin),
        _waiter(
            plugin, journal, FakeControl(answer={"ok": False, "error": "unavailable"}), deliver
        ).run(drop_id=dc["drop_id"], origin=dc_origin),
    )

    assert [e.message_id for e in tg_adapter.edited] == ["msg-TTTT"]
    assert [e.message_id for e in dc_adapter.edited] == ["msg-DDDD"]
    assert {e.chat_id for e in tg_adapter.edited} == {"tg-1"}
    assert {e.chat_id for e in dc_adapter.edited} == {"dc-1"}
    assert journal.get("T" * 22)["state"] == "received"
    assert journal.get("D" * 22)["state"] == "expired"

    texts = {id(call["source"]): call["text"] for call in deliver.calls}
    assert "D" * 22 not in texts[id(tg_origin.source)]
    assert "T" * 22 not in texts[id(dc_origin.source)]


async def test_the_waiter_parks_once_and_never_polls(plugin, journal, lane) -> None:
    origin, _ = lane()
    entry = _waiting(journal, origin, expires_in_ms=120_000)
    control = FakeControl(answer={"ok": False, "error": "unavailable"})

    await _waiter(plugin, journal, control, FakeDeliver()).run(
        drop_id=entry["drop_id"], origin=origin
    )

    assert len(control.await_calls) == 1, "the wait is one parked await, not a poll loop"
    # The park is budgeted from the handoff's own deadline, so the broker's
    # self-termination at expiry (src/broker.js:315-341) is what ends it.
    assert 100_000 < control.await_calls[0]["wait_ms"] <= 125_000


async def test_the_waiter_re_puts_its_source_for_a_later_wake_turn(
    plugin, journal, lane
) -> None:
    """§4's second writer: an internal wake turn never runs the capture hook
    (``gateway/run.py:13633``), so the routing-tuple lookup has to find something
    a restart did not put there."""
    origin, _ = lane()
    entry = _waiting(journal, origin)
    plugin.drop.sources.REGISTRY.clear()
    control = FakeControl(answer={"ok": True, "handoff_id": entry["drop_id"], "status": "submitted"})

    await _waiter(plugin, journal, control, FakeDeliver()).run(
        drop_id=entry["drop_id"], origin=origin
    )

    found = plugin.drop.sources.REGISTRY.by_routing_tuple(origin.routing_tuple)
    assert found is not None and found.source is origin.source


async def test_a_telegram_dm_topic_lane_survives_the_round_trip(plugin, journal, lane) -> None:
    """§8.5's named case: the wake turn's routing tuple must equal the initiating
    turn's for the one lane where ``_apply_topic_recovery`` actually rewrites."""
    adapter = StubAdapter(Platform.TELEGRAM)
    runner = StubRunner({Platform.TELEGRAM: adapter})
    source = adapter.build_source(
        chat_id="tg-dm", chat_type="dm", user_id="u-1", thread_id="topic-7"
    )
    origin = plugin.drop.origin.Origin(
        source=source,
        adapter=adapter,
        runner=runner,
        routing_tuple=plugin.drop.sources.routing_tuple_for_source(source),
        reply_anchor="anchor-1",
        tier="turn_contextvar",
    )
    entry = _waiting(journal, origin)
    control = FakeControl(answer={"ok": True, "handoff_id": entry["drop_id"], "status": "submitted"})

    await _waiter(plugin, journal, control, FakeDeliver()).run(
        drop_id=entry["drop_id"], origin=origin
    )

    stored = journal.get(entry["drop_id"])
    assert plugin.drop.journal.routing_tuple_of(stored) == origin.routing_tuple
    assert stored["thread_id"] == "topic-7"
    assert plugin.drop.journal.authorize_claim(stored, origin) is None


# ── the task registry ──────────────────────────────────────────────────────


async def test_arming_the_same_drop_twice_starts_one_task(plugin, journal, lane) -> None:
    origin, adapter = lane()
    entry = _waiting(journal, origin)
    registry = plugin.drop.waiter.WaiterRegistry()
    control = FakeControl(answer={"ok": False, "error": "unavailable"}, park_s=0.05)
    waiter = _waiter(plugin, journal, control, FakeDeliver())

    first = registry.arm(entry["drop_id"], lambda: waiter.run(drop_id=entry["drop_id"], origin=origin))
    second = registry.arm(entry["drop_id"], lambda: waiter.run(drop_id=entry["drop_id"], origin=origin))

    assert first is True and second is False
    assert len(registry) == 1
    await asyncio.sleep(0.2)
    assert len(control.await_calls) == 1
    assert len(registry) == 0, "a finished waiter must not stay in the registry"


async def test_shutdown_cancels_every_live_waiter(plugin, journal, lane) -> None:
    origin, _ = lane()
    entry = _waiting(journal, origin)
    registry = plugin.drop.waiter.WaiterRegistry()
    control = FakeControl(park_s=30)
    waiter = _waiter(plugin, journal, control, FakeDeliver())

    registry.arm(entry["drop_id"], lambda: waiter.run(drop_id=entry["drop_id"], origin=origin))
    await asyncio.sleep(0.05)
    registry.shutdown()
    await asyncio.sleep(0.05)

    assert len(registry) == 0
    assert journal.get(entry["drop_id"])["state"] == "waiting", "cancellation is not a verdict"


# ── the seam that must not silently move ───────────────────────────────────


async def test_deliver_wake_import_shape_is_pinned() -> None:
    """``deliver_wake`` is the latency path only, but a rename must fail a test
    rather than production (plan §3.3)."""
    import inspect

    from gateway.wake import deliver_wake

    assert inspect.iscoroutinefunction(deliver_wake)
    params = inspect.signature(deliver_wake).parameters
    assert list(params)[0] == "adapter"
    assert params["text"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["source"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["source"].default is None



async def test_universal_wait_records_only_payload_kind_in_journal_and_wake(plugin, journal, lane) -> None:
    origin, _ = lane(); entry = _waiting(journal, origin); deliver = FakeDeliver()
    canary = "FILE-BYTES-CANARY-91f2"
    answer = {"ok": True, "handoff_id": entry["drop_id"], "status": "submitted", "payload_kind": "files"}
    await _waiter(plugin, journal, FakeControl(answer=answer), deliver).run(drop_id=entry["drop_id"], origin=origin)
    stored = journal.get(entry["drop_id"])
    assert stored["payload_kind"] == "files"
    assert set(stored) == set(entry), "payload_kind is the only schema addition and was present blank"
    assert stored["payload_kind"] != entry["payload_kind"]
    representations = repr(stored) + repr(deliver.calls) + repr(answer)
    assert canary not in representations
