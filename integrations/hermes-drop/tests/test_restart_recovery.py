"""S11 — restart recovery, end to end, across both languages.

Task 5 of the security MVP: ``create → broker restart → reconcile``. Everything
else in this suite pins one seam; this pins the *sequence*, because the failure
it is about only exists between the parts.

The sequence, and why each step is the real thing rather than a stand-in:

1. **create** — the production ``DropService`` with production defaults, so the
   journal is the ``$HERMES_HOME``-scoped one, the control client is the real
   AF_UNIX client, the socket path comes from ``HERMES_DROP_CONTROL_SOCKET``
   through the real config latch, and the waiter is the real ``REGISTRY``. It
   mints against this repo's actual Node broker (``broker_harness.mjs`` in
   ``--public`` mode, i.e. ``src/main.js``'s whole entry point).
2. **the gateway goes down** — the waiter is cancelled through the production
   ``WaiterRegistry.shutdown`` and the source registry is cleared. That is the
   documented consequence of a process exit: "a waiter lost to a process exit
   leaves its journal entry ``waiting``" (``drop/waiter.py``), and a restarted
   gateway knows no lanes until a conversation speaks.
3. **the user submits anyway** — through the real browser client
   (``src/client/handoff-client.js``), real HPKE, into a broker nobody is
   watching. This is what makes the claim assertions mean something: there *was*
   a secret, and it is the broker's in-memory copy that the restart destroys.
   It is deliberately *not* evidence about redaction — the drop is never claimed,
   so the plaintext never reaches this process at all. What this file can pin
   about the durable record is that the **capability**, which did pass through
   here, is not in it.
4. **the broker crashes** — SIGKILL, no shutdown hook, and its replacement boots
   on the same socket path because that is the only path the plugin has.
5. **reconcile** — through the production triggers, in production order: the
   startup poller finds the runner, then ``pre_gateway_dispatch``'s trigger fires
   once the lane is published again.

Two substitutions, both platform transport and nothing else:

* ``StubAdapter`` for the send/edit surface — real ``build_source`` provenance,
  no network, no bot credential (``_stubs.py``).
* ``announce._default_deliver`` for the wake, which would otherwise be
  ``gateway.wake.deliver_wake`` reaching into a live gateway. The reconciler,
  the journal, the messenger, the control client and the broker are all real.

**This test found a production bug** (fixed in the same change; see
``reconciler._note_deferred_pass``): the one-shot latch was consumed by the
startup pass even when that pass could not resolve a single lane, which after a
restart is the *normal* startup pass. The documented recovery — "an unresolvable
lane … becomes resolvable the moment that conversation speaks"
(``reconciler.origin_for_entry``) — could therefore never happen, and the drop
kept its ``waiting`` entry and its live-looking status message for the life of
the gateway process.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from pathlib import Path

import pytest
from gateway.config import Platform

from _stubs import StubAdapter, StubRunner
from conftest import load_plugin_package

#: Submitted for real, into a broker that is about to die holding it. It is
#: asserted on only by absence, and that absence is a *weak* claim by
#: construction: this drop is never claimed, so the plaintext never enters this
#: process. See the sweep at the end of the test for what is and is not proved.
SECRET = "e2e-restart-marker-7c1d55-never-delivered"

#: The capability rides in the ``#fragment`` of a masked Markdown link, so the
#: closing paren of ``[text](url)`` bounds it.
_LINK = re.compile(r'https?://[^\s"<>()]+#[A-Za-z0-9_-]+')


@pytest.fixture
def plugin():
    return load_plugin_package()


@pytest.fixture
def clean_reconciler(plugin):
    """The module-level latch is process-global; this test drives it for real."""
    mod = plugin.drop.reconciler
    mod.reset_for_tests()
    try:
        yield mod
    finally:
        # ``request_shutdown`` stops a startup poller that has not found a runner
        # yet, so a test that fails before its poller resolves does not leave one
        # polling for the rest of the session. Ordered before the reset, which
        # clears the shutdown event again for the next test.
        mod.request_shutdown()
        mod.reset_for_tests()


@pytest.fixture
def quiet_waiters(plugin):
    """Cancel any waiter this test armed, however it ends.

    ``waiter.REGISTRY`` is the one production singleton with no autouse reset in
    ``conftest`` (the source registry and the turn ContextVar have one). A test
    that arms a real waiter and then fails an assertion would otherwise leave a
    task parked on a control socket that is about to be deleted, and the next
    test in the file would inherit it.
    """
    registry = plugin.drop.waiter.REGISTRY
    try:
        yield registry
    finally:
        registry.shutdown()


def _wait_until(predicate, message: str, *, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError(message)


def test_a_broker_restart_expires_the_drop_and_its_secret_can_never_be_claimed(
    monkeypatch: pytest.MonkeyPatch,
    plugin,
    clean_reconciler,
    quiet_waiters,
    gateway_loop,
    temp_hermes_home: Path,
    restartable_public_broker,
) -> None:
    reconciler = clean_reconciler
    journal_mod = plugin.drop.journal
    waiter_mod = plugin.drop.waiter

    def on_loop(coro, timeout: float = 45.0):
        """Everything runs on the gateway loop, because production does."""
        return asyncio.run_coroutine_threadsafe(coro, gateway_loop).result(timeout)

    # ── the world ──────────────────────────────────────────────────────────
    broker = restartable_public_broker()
    monkeypatch.setenv("HERMES_DROP_CONTROL_SOCKET", str(broker.socket_path))
    # The config latch is process-constant by design (``drop/config.py``), so it
    # has to be re-opened for the test's own socket rather than worked around.
    monkeypatch.setattr(plugin.drop.config, "_latched_socket_path", None)

    wakes: list = []

    async def record_wake(_adapter, *, text, source=None, session_id=""):
        wakes.append(text)

    monkeypatch.setattr(plugin.drop.announce, "_default_deliver", lambda: record_wake)

    adapter = StubAdapter(Platform.TELEGRAM)
    runner = StubRunner({Platform.TELEGRAM: adapter}, gateway_loop=gateway_loop)
    source = adapter.build_source(chat_id="tg-restart", chat_type="dm", user_id="u-1")
    lane = plugin.drop.sources.routing_tuple_for_source(source)
    plugin.drop.sources.REGISTRY.put(source, gateway=runner, session_key="s-1")
    origin = plugin.drop.origin.Origin(
        source=source,
        adapter=adapter,
        runner=runner,
        routing_tuple=lane,
        reply_anchor=None,
        tier="routing_tuple",
    )

    # ── 1. create, with production defaults throughout ─────────────────────
    service = plugin.drop.service.DropService()
    created = on_loop(
        service.create(origin, ttl_seconds=300, purpose="deploy token", session_key="s-1")
    )
    assert created["ok"] is True, created
    drop_id = created["drop_id"]

    journal = journal_mod.DropJournal()
    entry = journal.get(drop_id)
    assert entry is not None and entry["state"] == journal_mod.STATE_WAITING
    assert len(adapter.sent) == 1, f"one status message, not {adapter.sent}"
    assert adapter.edited == [], "nothing is edited at initiation"
    assert waiter_mod.REGISTRY.is_armed(drop_id), "the latency path was never armed"

    posted = adapter.sent[0].content
    link = _LINK.search(posted)
    assert link, f"no capability link in the posted notice: {posted!r}"

    # ── 2. the gateway process goes down ───────────────────────────────────
    # Cancellation is not a verdict (``WaiterRegistry.shutdown``): the entry must
    # still be ``waiting``, which is exactly the state the reconciler exists for.
    gateway_loop.call_soon_threadsafe(waiter_mod.REGISTRY.shutdown)
    _wait_until(lambda: len(waiter_mod.REGISTRY) == 0, "the waiter was never cancelled")
    assert journal.get(drop_id)["state"] == journal_mod.STATE_WAITING
    # A restarted gateway has an empty source registry until a lane speaks.
    plugin.drop.sources.REGISTRY.clear()

    # ── 3. the user submits, with nobody watching ──────────────────────────
    assert broker.submit(link.group(0), SECRET) == "SUBMITTED sent"

    # ── 4. the broker crashes and comes back empty, on the same socket ─────
    broker.crash()
    restarted = restartable_public_broker()
    assert restarted.socket_path == broker.socket_path, "a restart must reuse the path"

    # A crash-orphaned journal temp file. Note whose crash: the journal is written
    # by *this* process (``DropJournal._write``), so this artefact is what a killed
    # **gateway** leaves behind mid-write, not the broker SIGKILL above — the two
    # arrive together in a host-level failure, which is why it is planted here.
    # It holds a complete, valid body with the same ``drop_id`` as its target, so
    # it must read as junk rather than as a second entry (review M3).
    #
    # Written and read directly against the journal: this is a pin on
    # ``DropJournal.entries()``, which is where the exclusion lives. The reconcile
    # assertions further down then show the same file does not double the drop in
    # a pass — that is the consequence, and this is the mechanism.
    orphan = journal.root / ".tmp-crash0001.json"
    orphan.write_text(json.dumps(journal.get(drop_id)), encoding="utf-8")
    assert len(journal.entries()) == 1, "an orphaned temp file read as an entry"

    # ── 5a. the restarted gateway's startup pass: no lane is known yet ─────
    passes: list = []
    production_pass = reconciler._reconcile_for_runner

    async def observed(found_runner):
        """Observes the production pass; substitutes nothing."""
        summary = await production_pass(found_runner)
        passes.append(summary)
        return summary

    monkeypatch.setattr(reconciler, "_reconcile_for_runner", observed)

    reconciler.start_startup_trigger(
        resolve_runner=lambda: runner, poll_interval=0.01, max_polls=500
    )
    _wait_until(lambda: len(passes) == 1, "the startup reconcile never ran")

    assert passes[0]["unresolved"] == [drop_id], passes[0]
    assert passes[0]["unresolved_lanes"] == [lane], passes[0]
    assert passes[0]["failed"] == [], passes[0]
    assert journal.get(drop_id)["state"] == journal_mod.STATE_WAITING
    assert adapter.edited == [], "an unresolvable lane must not be edited blind"

    # Wait for the *accounting*, not for the pass: ``_run_pass`` records the
    # summary and only then decides what the pass did to the latch, so
    # ``len(passes) == 1`` is one statement too early. ``deferred_lanes()`` is a
    # pure read of that decision — polling ``trigger_from_event`` instead would
    # be polling a function whose whole job is to have a side effect, and would
    # start the pass it is asking about the moment the answer changed.
    _wait_until(
        lambda: reconciler.deferred_lanes() == frozenset({lane}),
        "the startup pass never recorded its unresolvable lane",
    )

    # Now one synchronous assertion, with no time budget in it: the lane is still
    # silent, so a dispatch must not spend a pass on it. This is the half that
    # keeps a busy gateway to one reconcile rather than one per message.
    assert reconciler.trigger_from_event(runner) is False, (
        "a dispatch ran a pass that could not have made progress"
    )
    assert len(passes) == 1

    # ── 5b. the conversation speaks: capture, then the dispatch trigger ────
    plugin.drop.sources.REGISTRY.put(source, gateway=runner, session_key="s-1")
    assert reconciler.trigger_from_event(runner) is True, (
        "the deferred pass was never retried: the one-shot latch was spent on a "
        "startup pass that could not resolve a single lane"
    )
    _wait_until(lambda: len(passes) == 2, "the retry pass never ran")

    # ── the three things task 5 asks to be confirmed ───────────────────────
    summary = passes[1]
    assert summary["expired"] == [drop_id], summary
    assert summary["failed"] == [], summary

    # (a) the visible waiting message became the expired notice, in place.
    stored = journal.get(drop_id)
    assert [e.content for e in adapter.edited] == ["✕ **Private input link expired**"]
    assert adapter.edited[0].content == stored["notice_expired"]
    assert adapter.edited[0].message_id == stored["message_id"]
    assert adapter.edited[0].chat_id == source.chat_id
    assert len(adapter.sent) == 1, "a second status message was posted"
    # The link is gone from what the user can see — no URL, no capability, no id.
    assert not _LINK.search(adapter.edited[0].content), adapter.edited[0].content
    assert link.group(0) not in adapter.edited[0].content
    assert drop_id not in adapter.edited[0].content

    # (b) the old secret cannot be claimed — refused by the journal, and gone
    #     from the broker underneath it.
    refusal = on_loop(service.claim(origin, drop_id))
    assert refusal == {"error": "unavailable", "state": journal_mod.STATE_EXPIRED}
    assert "private_input" not in refusal
    direct = on_loop(
        plugin.drop.control_client.claim(drop_id, socket_path=restarted.socket_path)
    )
    assert direct.get("ok") is not True, direct
    assert "plaintext_b64" not in direct, "the restarted broker still held a payload"

    # (c) no orphaned waiter, and nothing still looks live.
    assert len(waiter_mod.REGISTRY) == 0
    assert waiter_mod.REGISTRY.is_armed(drop_id) is False
    assert summary["rearmed"] == [], summary
    assert stored["state"] == journal_mod.STATE_EXPIRED
    assert stored["claimed_at"] is None
    assert stored["announced_at"] is not None, "terminal but never announced"
    assert (
        on_loop(
            reconciler.probe_liveness(
                drop_id,
                control=plugin.drop.control_client,
                socket_path=restarted.socket_path,
                probe_ms=400,
            )
        )
        == reconciler.VERDICT_GONE
    )

    # ── the orphan is still ignored, and the pass is safe to repeat ────────
    assert orphan.exists(), "precondition: the orphan is inside the sweep grace"
    assert [e["drop_id"] for e in journal.entries()] == [drop_id]
    assert len(wakes) == 1, f"one wake, not {wakes}"
    assert wakes[0].count(drop_id) == 1, "the orphan doubled the drop in the wake"

    repeat = on_loop(reconciler._reconcile_for_runner(runner))
    assert repeat["expired"] == [] and repeat["announced"] == [], repeat
    assert repeat["failed"] == [], repeat
    assert [e.content for e in adapter.edited] == ["✕ **Private input link expired**"]
    assert len(wakes) == 1, "a repeated pass announced twice"
    assert journal.get(drop_id) == stored, "a repeated pass rewrote the entry"

    # ── what the durable record holds, and what it must not ────────────────
    #
    # The capability is the assertion with teeth. It *did* pass through this
    # process — the broker minted it, the notice carried it, the messenger posted
    # it — so the journal not holding it is a property of the journal's URL guard
    # (``journal._URLISH``), not an accident of the scenario.
    serialized = {
        path.name: path.read_text(encoding="utf-8") for path in sorted(journal.root.iterdir())
    }
    assert serialized, "nothing was written at all"
    for name, blob in serialized.items():
        assert link.group(0) not in blob, name
        assert "http" not in blob, name

    # The plaintext, by contrast, is a *weak* check and is labelled as one: this
    # drop was never claimed, so the secret never entered this process and no
    # regression in redaction could put it here. It stays as a cheap invariant on
    # the unclaimed path — "a drop nobody claimed leaves no trace" — and is not
    # evidence that claiming is safe. That is ``test_sanitization.py`` and the
    # leak sweep in ``test_command.py``, which claim a real payload first.
    visible = "\n".join(
        [m.content for m in adapter.sent] + [e.content for e in adapter.edited] + wakes
    )
    assert SECRET not in visible
    for name, blob in serialized.items():
        assert SECRET not in blob, name
