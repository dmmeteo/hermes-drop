"""S6 — the reconciler, and the two triggers that can start it.

Why a reconciler exists at all: ``pre_gateway_dispatch`` is the only ``invoke_hook``
site in ``gateway/run.py`` (``:13636``), it fires only for non-internal events
(``:13633``), and no gateway-ready hook exists (``VALID_HOOKS``,
``hermes_cli/plugins.py:135-215``). So after a restart, with no user message,
nothing would ever run — and the status message would keep advertising a link the
in-memory broker destroyed at startup (``src/broker.js:95-102``).

Hence two triggers, both idempotent: a bounded startup daemon thread, and the
dispatch hook. Both are latched by one test-and-set, so "exactly once per
process" holds no matter which fires first or how often either fires.

The reconciler is written **before** the waiter on purpose. The waiter is the
latency path; this is the mechanism that has to be correct when the waiter is
gone — after a gateway restart, after a dropped wake, after a crash mid-turn.
"""

from __future__ import annotations

import asyncio
import json
import threading
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
def reconciler(plugin):
    mod = plugin.drop.reconciler
    mod.reset_for_tests()
    yield mod
    mod.reset_for_tests()


@pytest.fixture
def journal(plugin, tmp_path: Path):
    return plugin.drop.journal.DropJournal(root=tmp_path / "hermes-drop")


@pytest.fixture
def lane(plugin):
    """A resolvable lane: a real source in the registry plus a runner that owns
    the adapter. This is the shape the reconciler must work from — it runs
    outside any turn, so there are no bound contextvars to verify against and the
    journal entry's own routing tuple is the authority."""

    def _make(platform: Platform = Platform.TELEGRAM, chat_id: str = "tg-1", **kw):
        adapter = StubAdapter(platform, **kw)
        runner = StubRunner({platform: adapter})
        source = adapter.build_source(chat_id=chat_id, chat_type="dm", user_id="u-1")
        plugin.drop.sources.REGISTRY.put(source, gateway=runner, session_key="s")
        return runner, adapter, source

    return _make


def _origin(plugin, source, adapter, runner):
    return plugin.drop.origin.Origin(
        source=source,
        adapter=adapter,
        runner=runner,
        routing_tuple=plugin.drop.sources.routing_tuple_for_source(source),
        reply_anchor=None,
        tier="routing_tuple",
    )


def _waiting(journal, plugin, source, adapter, runner, *, drop_id="A" * 22, expires_in_ms=600_000):
    return journal.create_entry(
        drop_id=drop_id,
        origin=_origin(plugin, source, adapter, runner),
        message_id=f"msg-{drop_id[:4]}",
        expires_at_ms=int(time.time() * 1000) + expires_in_ms,
        ttl_seconds=1800,
        purpose="deploy token",
        session_key="s",
        notice_received="✓ **Private input received**",
        notice_expired="✕ **Private input link expired**",
    )


class FakeControl:
    """Stands in for the async control client, and counts every round trip.

    ``park_ms`` is what makes the liveness verdict testable: the broker leaks
    liveness by timing and only by timing — ``await`` blocks *only* for a live
    pending handoff (``contract/control-protocol.json`` error_notes, and
    ``src/broker.js:315-341``). A gone record answers immediately; a live one
    answers when the probe window runs out.
    """

    def __init__(self, *, answer=None, park_ms: float = 0.0, raises: bool = False):
        self.answer = answer if answer is not None else {"ok": False, "error": "unavailable"}
        self.park_ms = park_ms
        self.raises = raises
        self.calls: list = []

    async def await_submission(self, handoff_id, *, wait_ms, socket_path=None, timeout=None):
        self.calls.append({"handoff_id": handoff_id, "wait_ms": wait_ms})
        if self.raises:
            raise OSError("socket gone")
        if self.park_ms:
            await asyncio.sleep(min(self.park_ms, wait_ms) / 1000.0)
        return self.answer


class FakeArmer:
    def __init__(self):
        self.armed: list = []

    def __call__(self, *, drop_id, origin, entry):
        self.armed.append(drop_id)


class FakeDeliver:
    """Stands in for ``gateway.wake.deliver_wake``, which raises on failure."""

    def __init__(self, *, fails: bool = False):
        self.fails = fails
        self.calls: list = []

    async def __call__(self, adapter, *, text, source=None, session_id=""):
        self.calls.append({"adapter": adapter, "text": text, "source": source})
        if self.fails:
            raise RuntimeError("wake refused")


async def _reconcile(reconciler, journal, plugin, runner, **kw):
    kw.setdefault("control", FakeControl())
    kw.setdefault("arm", FakeArmer())
    kw.setdefault("deliver", FakeDeliver())
    kw.setdefault("probe_ms", 60)
    return await reconciler.reconcile(
        journal=journal,
        runner=runner,
        registry=plugin.drop.sources.REGISTRY,
        messenger=plugin.drop.messenger.OriginMessenger(),
        **kw,
    )


# ── triggers ───────────────────────────────────────────────────────────────


async def test_the_startup_daemon_finds_the_runner_and_runs_exactly_once(
    reconciler,
) -> None:
    loop = asyncio.get_running_loop()
    runner = StubRunner({}, gateway_loop=loop)
    ran = []
    done = threading.Event()

    async def fake_reconcile(found_runner):
        ran.append(found_runner)
        done.set()

    thread = reconciler.start_startup_trigger(
        resolve_runner=lambda: runner,
        reconcile_coro=fake_reconcile,
        poll_interval=0.01,
        max_polls=50,
    )
    for _ in range(200):
        if done.is_set():
            break
        await asyncio.sleep(0.01)
    thread.join(timeout=5)

    assert ran == [runner]
    assert thread.daemon is True, "a startup poller must never hold the process open"

    # A second startup trigger in the same process is latched out.
    second = reconciler.start_startup_trigger(
        resolve_runner=lambda: runner, reconcile_coro=fake_reconcile, poll_interval=0.01
    )
    second.join(timeout=5)
    await asyncio.sleep(0.05)
    assert ran == [runner], "the reconcile ran twice"


async def test_a_second_dispatch_trigger_is_a_no_op(reconciler) -> None:
    ran: list = []

    async def fake_reconcile(runner):
        ran.append(runner)

    runner = StubRunner({}, gateway_loop=asyncio.get_running_loop())

    assert reconciler.trigger_from_event(runner, reconcile_coro=fake_reconcile) is True
    assert reconciler.trigger_from_event(runner, reconcile_coro=fake_reconcile) is False
    assert reconciler.trigger_from_event(runner, reconcile_coro=fake_reconcile) is False
    await asyncio.sleep(0.05)

    assert ran == [runner]


async def test_startup_and_dispatch_triggers_share_one_latch(reconciler) -> None:
    ran: list = []

    async def fake_reconcile(runner):
        ran.append(runner)

    runner = StubRunner({}, gateway_loop=asyncio.get_running_loop())
    assert reconciler.trigger_from_event(runner, reconcile_coro=fake_reconcile) is True

    thread = reconciler.start_startup_trigger(
        resolve_runner=lambda: runner, reconcile_coro=fake_reconcile, poll_interval=0.01
    )
    thread.join(timeout=5)
    await asyncio.sleep(0.05)
    assert ran == [runner]


async def test_a_bounded_poll_that_never_finds_a_runner_exits_quietly(
    reconciler, tmp_path: Path, monkeypatch
) -> None:
    """The CLI case. ``hermes plugins list`` loads this plugin; there is no
    gateway, there never will be, and nothing may be written on the way to
    finding that out."""
    home = tmp_path / "cli-home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    polls: list = []

    def never() -> None:
        polls.append(1)
        return None

    thread = reconciler.start_startup_trigger(
        resolve_runner=never, poll_interval=0.001, max_polls=5
    )
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert len(polls) == 5, "the poll is bounded and it polled its bound"
    assert list(home.iterdir()) == [], "the startup trigger wrote into HERMES_HOME"
    assert not (home / "state").exists()


async def test_the_startup_poller_never_pulls_gateway_run_into_a_cli_process(
    reconciler,
) -> None:
    """``register()`` is careful not to import ``gateway.run``
    (``test_plugin_skeleton.py``), and the poller it starts must not undo that a
    second later on a background thread — it runs in **every** process that loads
    the plugin, including ``hermes plugins list``. Reading the handle out of
    ``sys.modules`` is not a heuristic: the runner cannot exist before the module
    is loaded."""
    import subprocess
    import sys as _sys
    import textwrap

    from conftest import HERMES_CHECKOUT, PLUGIN_DIR

    script = textwrap.dedent(
        f"""
        import os, sys, time
        sys.path.insert(0, {str(HERMES_CHECKOUT)!r})
        sys.path.insert(0, {str(PLUGIN_DIR / 'tests')!r})
        from conftest import load_plugin_package

        plugin = load_plugin_package()
        thread = plugin.drop.reconciler.start_startup_trigger(
            poll_interval=0.01, max_polls=20
        )
        thread.join(timeout=10)
        assert "gateway.run" not in sys.modules, "the startup poller imported gateway.run"
        print("OK")
        """
    )
    env = dict(__import__("os").environ)
    env["PYTHONPATH"] = str(HERMES_CHECKOUT)
    result = subprocess.run(
        [_sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(HERMES_CHECKOUT),
        env=env,
        timeout=120,
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert result.stdout.strip().endswith("OK")


async def test_registering_the_plugin_writes_nothing_under_hermes_home(
    plugin, reconciler, tmp_path: Path, monkeypatch
) -> None:
    home = tmp_path / "register-home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))

    class Ctx:
        def __init__(self):
            self.tools, self.hooks, self.commands = [], [], []

        def register_tool(self, name, toolset, schema, handler, **kw):
            self.tools.append(name)

        def register_hook(self, hook_name, callback):
            self.hooks.append(hook_name)

        def register_command(self, name, handler, **kw):
            self.commands.append(name)

    plugin.register(Ctx())
    reconciler.request_shutdown()
    await asyncio.sleep(0.05)

    assert list(home.iterdir()) == [], "register() touched HERMES_HOME"


# ── waiting entries ────────────────────────────────────────────────────────


async def test_a_waiting_entry_whose_broker_record_is_gone_expires(
    reconciler, journal, plugin, lane
) -> None:
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    deliver = FakeDeliver()
    control = FakeControl(answer={"ok": False, "error": "unavailable"}, park_ms=0)

    summary = await _reconcile(
        reconciler, journal, plugin, runner, control=control, deliver=deliver
    )

    assert summary["expired"] == [entry["drop_id"]]
    stored = journal.get(entry["drop_id"])
    assert stored["state"] == "expired"
    assert [e.content for e in adapter.edited] == ["✕ **Private input link expired**"]
    assert adapter.edited[0].message_id == "msg-AAAA"
    assert stored["announced_at"] is not None
    assert len(deliver.calls) == 1


async def test_a_waiting_entry_that_is_still_live_is_re_armed_not_expired(
    reconciler, journal, plugin, lane
) -> None:
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    armer = FakeArmer()
    deliver = FakeDeliver()
    # Parks for the whole probe window, which is what a live pending record does.
    control = FakeControl(answer={"ok": False, "error": "unavailable"}, park_ms=60)

    summary = await _reconcile(
        reconciler, journal, plugin, runner, control=control, arm=armer, deliver=deliver
    )

    assert summary["rearmed"] == [entry["drop_id"]]
    assert armer.armed == [entry["drop_id"]]
    assert journal.get(entry["drop_id"])["state"] == "waiting"
    assert adapter.edited == [], "a live drop's status message must not be touched"
    assert deliver.calls == [], "nothing terminal happened, so nothing is announced"


async def test_a_waiting_entry_already_submitted_becomes_received(
    reconciler, journal, plugin, lane
) -> None:
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    control = FakeControl(answer={"ok": True, "handoff_id": entry["drop_id"], "status": "submitted"})

    summary = await _reconcile(reconciler, journal, plugin, runner, control=control)

    assert summary["received"] == [entry["drop_id"]]
    assert journal.get(entry["drop_id"])["state"] == "received"
    assert [e.content for e in adapter.edited] == ["✓ **Private input received**"]


async def test_an_entry_past_its_deadline_expires_without_a_broker_round_trip(
    reconciler, journal, plugin, lane
) -> None:
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner, expires_in_ms=-1000)
    control = FakeControl()

    summary = await _reconcile(reconciler, journal, plugin, runner, control=control)

    assert summary["expired"] == [entry["drop_id"]]
    assert control.calls == [], "a lapsed deadline needs no probe; the broker already destroyed it"


async def test_a_transport_failure_during_the_probe_retains_the_entry(
    reconciler, journal, plugin, lane
) -> None:
    """Never claim on a guess, and never bury one either: unknown means unknown."""
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    control = FakeControl(answer={"ok": False, "error": "broker_unavailable", "detail": "no socket"})
    armer = FakeArmer()

    summary = await _reconcile(
        reconciler, journal, plugin, runner, control=control, arm=armer
    )

    assert summary["retained"] == [entry["drop_id"]]
    assert journal.get(entry["drop_id"])["state"] == "waiting"
    assert adapter.edited == []
    assert armer.armed == []


async def test_an_unavailable_adapter_keeps_the_entry_waiting_for_the_next_start(
    reconciler, journal, plugin, lane
) -> None:
    """A gateway restart empties the source registry, so the startup pass can
    genuinely have no adapter for a lane. Retaining is the only safe answer: the
    dispatch trigger runs again the moment that conversation speaks."""
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    plugin.drop.sources.REGISTRY.clear()

    first = await _reconcile(reconciler, journal, plugin, runner)

    assert first["retained"] == [entry["drop_id"]]
    assert first["unresolved"] == [entry["drop_id"]]
    assert journal.get(entry["drop_id"])["state"] == "waiting"
    assert adapter.edited == []

    # Next start: the lane is resolvable again and the same entry is handled.
    plugin.drop.sources.REGISTRY.put(source, gateway=runner, session_key="s")
    second = await _reconcile(
        reconciler, journal, plugin, runner, control=FakeControl(park_ms=0)
    )
    assert second["expired"] == [entry["drop_id"]]


# ── announcing ─────────────────────────────────────────────────────────────


async def test_a_terminal_unannounced_entry_is_re_announced(
    reconciler, journal, plugin, lane
) -> None:
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    journal.update(entry["drop_id"], state="received")
    deliver = FakeDeliver()

    summary = await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)

    assert summary["announced"] == [entry["drop_id"]]
    assert len(deliver.calls) == 1
    stored = journal.get(entry["drop_id"])
    assert stored["announced_at"] is not None
    assert stored["announce_attempts"] == 1
    assert adapter.edited == [], "already terminal: no second edit"


async def test_announce_failure_is_bounded_and_leaves_the_entry_claimable(
    reconciler, journal, plugin, lane
) -> None:
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    journal.update(entry["drop_id"], state="received")
    deliver = FakeDeliver(fails=True)

    attempts = 0
    for _ in range(plugin.drop.journal.MAX_ANNOUNCE_ATTEMPTS + 3):
        reconciler.reset_for_tests()
        await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)
        attempts = journal.get(entry["drop_id"])["announce_attempts"]

    assert attempts == plugin.drop.journal.MAX_ANNOUNCE_ATTEMPTS
    assert len(deliver.calls) == plugin.drop.journal.MAX_ANNOUNCE_ATTEMPTS
    stored = journal.get(entry["drop_id"])
    assert stored["announced_at"] is None
    # The wake never landed; the claim path is unaffected. That is §3.3's point.
    origin = _origin(plugin, source, adapter, runner)
    assert plugin.drop.journal.authorize_claim(stored, origin) is None


async def test_one_wake_names_every_pending_drop_in_the_lane(
    reconciler, journal, plugin, lane
) -> None:
    """§3.3 mechanism 2: announce the set, not the drop. A wake merged into an
    unrelated pending user message (``gateway/platforms/base.py:2487-2494``) is
    still complete on its own."""
    runner, adapter, source = lane()
    first = _waiting(journal, plugin, source, adapter, runner, drop_id="A" * 22)
    second = _waiting(journal, plugin, source, adapter, runner, drop_id="B" * 22)
    journal.update(first["drop_id"], state="received")
    journal.update(second["drop_id"], state="expired")
    deliver = FakeDeliver()

    summary = await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)

    assert sorted(summary["announced"]) == ["A" * 22, "B" * 22]
    assert len(deliver.calls) == 1, "one self-contained wake, not one per drop"
    text = deliver.calls[0]["text"]
    assert "A" * 22 in text and "B" * 22 in text
    assert "claim_private_input" in text


async def test_the_wake_text_carries_no_capability_url_or_payload(
    reconciler, journal, plugin, lane
) -> None:
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    journal.update(entry["drop_id"], state="received")
    deliver = FakeDeliver()

    await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)

    text = deliver.calls[0]["text"]
    assert "://" not in text and "#" not in text
    assert "at-least-once" in text, "the contract wording belongs where the model reads it"


async def test_a_received_drop_still_unclaimed_past_the_grace_is_announced_again(
    reconciler, journal, plugin, lane
) -> None:
    """§3.3's second re-announce condition. A wake that landed but was merged into
    an unrelated turn leaves a payload sitting in the broker until its TTL; a
    second, bounded notice is the recovery."""
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    stale = time.time() - reconciler.RECLAIM_GRACE_SECONDS - 1
    journal.update(entry["drop_id"], state="received", announced_at=stale, announce_attempts=1)
    deliver = FakeDeliver()

    summary = await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)

    assert summary["announced"] == [entry["drop_id"]]
    assert journal.get(entry["drop_id"])["announce_attempts"] == 2

    # Claimed, or freshly announced, and it is left alone.
    journal.update(entry["drop_id"], announced_at=stale, claimed_at=time.time())
    reconciler.reset_for_tests()
    again = await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)
    assert again["announced"] == []


async def test_two_lanes_never_cross_talk(reconciler, journal, plugin, lane) -> None:
    tg_runner, tg_adapter, tg_source = lane(Platform.TELEGRAM, "tg-1")
    dc_runner, dc_adapter, dc_source = lane(Platform.DISCORD, "dc-1")
    both = StubRunner({Platform.TELEGRAM: tg_adapter, Platform.DISCORD: dc_adapter})
    plugin.drop.sources.REGISTRY.put(tg_source, gateway=both, session_key="tg")
    plugin.drop.sources.REGISTRY.put(dc_source, gateway=both, session_key="dc")

    tg = _waiting(journal, plugin, tg_source, tg_adapter, both, drop_id="T" * 22)
    dc = _waiting(journal, plugin, dc_source, dc_adapter, both, drop_id="D" * 22)
    journal.update(tg["drop_id"], state="received")
    journal.update(dc["drop_id"], state="expired")
    deliver = FakeDeliver()

    await _reconcile(reconciler, journal, plugin, both, deliver=deliver)

    assert len(deliver.calls) == 2, "one wake per lane"
    by_source = {id(call["source"]): call["text"] for call in deliver.calls}
    assert "T" * 22 in by_source[id(tg_source)] and "D" * 22 not in by_source[id(tg_source)]
    assert "D" * 22 in by_source[id(dc_source)] and "T" * 22 not in by_source[id(dc_source)]


# ── idempotence ────────────────────────────────────────────────────────────


async def test_reconciling_twice_edits_once_and_announces_once(
    reconciler, journal, plugin, lane
) -> None:
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner)
    deliver = FakeDeliver()

    await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)
    reconciler.reset_for_tests()
    second = await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)

    assert len(adapter.edited) == 1
    assert len(deliver.calls) == 1
    assert second["expired"] == [] and second["announced"] == []
    assert journal.get(entry["drop_id"])["state"] == "expired"


async def test_a_lost_edit_does_not_stop_the_journal_or_the_announce(
    reconciler, journal, plugin, lane
) -> None:
    """§7.2: the state the edit would have shown no longer matters; the
    capability is already dead. What must not happen is the durable record and
    the notification being lost with it."""
    runner, adapter, source = lane(edit_ok=False)
    entry = _waiting(journal, plugin, source, adapter, runner)
    deliver = FakeDeliver()

    summary = await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)

    assert summary["expired"] == [entry["drop_id"]]
    stored = journal.get(entry["drop_id"])
    assert stored["state"] == "expired"
    assert stored["edit_failed"] is True
    assert len(deliver.calls) == 1


# ── against the real broker ────────────────────────────────────────────────


async def test_the_liveness_verdict_matches_a_real_broker(
    reconciler, real_broker, plugin
) -> None:
    """The only mechanism that can tell a destroyed record from a live one is the
    timing leak the contract documents: ``await`` blocks *only* for a live pending
    handoff. This is that claim, checked against the real Node broker rather than
    against a fake that was written to agree with it."""
    control = plugin.drop.control_client
    created = await control.create(ttl_seconds=60, socket_path=real_broker.socket_path)
    assert created["ok"] is True, created

    live = await reconciler.probe_liveness(
        created["handoff_id"],
        control=control,
        socket_path=real_broker.socket_path,
        probe_ms=400,
    )
    gone = await reconciler.probe_liveness(
        "Z" * 22, control=control, socket_path=real_broker.socket_path, probe_ms=400
    )

    assert live == reconciler.VERDICT_LIVE
    assert gone == reconciler.VERDICT_GONE


async def test_an_unreachable_socket_is_unknown_not_gone(reconciler, plugin, tmp_path) -> None:
    verdict = await reconciler.probe_liveness(
        "A" * 22,
        control=plugin.drop.control_client,
        socket_path=tmp_path / "nothing-here.sock",
        probe_ms=50,
    )
    assert verdict == reconciler.VERDICT_UNKNOWN


# ── M2: a failing pass must not disable reconciliation for the process ─────
#
# Only ``journal.entries()`` was wrapped. Everything else in the pass could
# raise: ``origin_for_entry`` -> the source store, ``finalize_terminal`` ->
# ``journal.update`` -> ``_write`` (``OSError`` on a full or read-only disk,
# ``JournalRejected`` on a hand-edited entry), the reclaim-grace ``update``, and
# ``announce_pending``'s two ``update`` calls.
#
# What made that a MEDIUM rather than a nuisance is the latch: it is test-and-set
# and consumed *before* the pass runs, so a raise on entry N meant entries after
# N were never driven to terminal, ``announced_at`` stayed ``None`` forever, and
# **no second reconcile could ever be triggered in that gateway process** — the
# dispatch hook returned ``False`` on every subsequent message. Near-silently:
# ``_schedule_reconcile`` threw the future away, so the threadsafe path logged
# nothing at all.


class ExplodingJournal:
    """A journal whose ``update`` fails for one drop, exactly as a bad disk does.

    Wraps a real ``DropJournal`` rather than replacing it, so every read is
    genuine and only the one write that is supposed to fail does.
    """

    def __init__(self, inner, *, fail_for, exc=None, times=None):
        self._inner = inner
        self._fail_for = set(fail_for)
        self._exc = exc if exc is not None else OSError(28, "No space left on device")
        self._times = times
        self.attempts: list = []

    # -- the failing surface ------------------------------------------------

    def update(self, drop_id, **changes):
        self.attempts.append(drop_id)
        if drop_id in self._fail_for:
            if self._times is None or self.attempts.count(drop_id) <= self._times:
                raise self._exc
        return self._inner.update(drop_id, **changes)

    # -- everything else is the real journal --------------------------------

    def __getattr__(self, name):
        return getattr(self._inner, name)


async def test_a_failing_entry_does_not_stop_the_rest_of_the_pass(
    reconciler, journal, plugin, lane
) -> None:
    """M2. Entry B must still be driven to terminal when entry A's write fails.

    Pre-fix the ``OSError`` from A's ``journal.update`` propagated out of
    ``reconcile``, so B kept advertising a live link indefinitely — and nothing
    in the logs said why.
    """
    runner, adapter, source = lane()
    # Both past their deadline, so both take the no-round-trip expiry path.
    _waiting(journal, plugin, source, adapter, runner, drop_id="A" * 22, expires_in_ms=-1000)
    _waiting(journal, plugin, source, adapter, runner, drop_id="B" * 22, expires_in_ms=-1000)

    exploding = ExplodingJournal(journal, fail_for={"A" * 22})
    summary = await _reconcile(reconciler, exploding, plugin, runner)

    assert isinstance(summary, dict), "reconcile must return a summary, never raise"
    assert journal.get("B" * 22)["state"] == plugin.drop.journal.STATE_EXPIRED, (
        "the entry behind the failing one was never driven to terminal"
    )
    assert "A" * 22 in summary["failed"], summary
    assert "B" * 22 in summary["expired"], summary


async def test_reconcile_returns_a_summary_even_when_every_entry_fails(
    reconciler, journal, plugin, lane
) -> None:
    """"Never raises" has to be true of the whole body, not of one call in it."""
    runner, adapter, source = lane()
    _waiting(journal, plugin, source, adapter, runner, drop_id="C" * 22, expires_in_ms=-1000)

    exploding = ExplodingJournal(journal, fail_for={"C" * 22})
    summary = await _reconcile(reconciler, exploding, plugin, runner)

    assert isinstance(summary, dict)
    assert summary["failed"] == ["C" * 22]
    # The entry is untouched, so the next pass sees exactly the same work.
    assert journal.get("C" * 22)["state"] == plugin.drop.journal.STATE_WAITING


async def test_a_failed_pass_releases_the_latch_so_a_later_dispatch_retries(
    reconciler, journal, plugin, lane
) -> None:
    """The core of M2: a failed pass must leave the process able to try again.

    ``trigger_from_event`` consumes the latch *before* the pass runs, so without
    an explicit release the second dispatch returns ``False`` forever. This
    asserts the retry both happens and *succeeds* — the transient disk failure is
    configured to clear after one attempt, so the second pass drives the entry to
    terminal, which is what "recovers" has to mean.
    """
    runner, adapter, source = lane()
    _waiting(journal, plugin, source, adapter, runner, drop_id="D" * 22, expires_in_ms=-1000)

    # Fails on the first update only; the second pass writes normally.
    exploding = ExplodingJournal(journal, fail_for={"D" * 22}, times=1)

    async def pass_one(_runner):
        return await _reconcile(reconciler, exploding, plugin, runner)

    assert reconciler.trigger_from_event(runner, reconcile_coro=pass_one) is True
    await asyncio.sleep(0.2)
    assert journal.get("D" * 22)["state"] == plugin.drop.journal.STATE_WAITING, (
        "precondition: the first pass failed to finalise"
    )

    # THE assertion. Pre-fix this was False and reconciliation was dead for the
    # life of the process.
    assert reconciler.trigger_from_event(runner, reconcile_coro=pass_one) is True, (
        "a failed pass permanently consumed the one-shot latch"
    )
    await asyncio.sleep(0.2)
    assert journal.get("D" * 22)["state"] == plugin.drop.journal.STATE_EXPIRED, (
        "the retry ran but did not recover the entry"
    )


async def test_a_successful_pass_still_consumes_the_latch_exactly_once(
    reconciler, journal, plugin, lane
) -> None:
    """The release must be conditional, or "exactly once per process" is gone.

    A gateway handling a message a second gets one reconcile, not one per
    message. This is the property the latch exists for, and the M2 fix must not
    trade it away to get retry-on-failure.
    """
    runner, _adapter, _source = lane()
    runs: list = []

    async def clean_pass(_runner):
        runs.append(1)
        return await _reconcile(reconciler, journal, plugin, runner)

    assert reconciler.trigger_from_event(runner, reconcile_coro=clean_pass) is True
    await asyncio.sleep(0.2)
    for _ in range(5):
        assert reconciler.trigger_from_event(runner, reconcile_coro=clean_pass) is False
    await asyncio.sleep(0.1)
    assert len(runs) == 1, f"a clean pass ran {len(runs)} times"


async def test_repeated_failures_stop_releasing_the_latch(reconciler, journal, plugin, lane) -> None:
    """Retry is bounded, so a permanently full disk is not a reconcile per message.

    Unbounded release would turn a stuck condition into a pass on every inbound
    message — each one re-probing every live drop over the control socket. The
    bound is the same shape as ``MAX_ANNOUNCE_ATTEMPTS``: try, then stop and stay
    quiet.
    """
    runner, adapter, source = lane()
    _waiting(journal, plugin, source, adapter, runner, drop_id="E" * 22, expires_in_ms=-1000)
    exploding = ExplodingJournal(journal, fail_for={"E" * 22})  # never recovers

    async def always_fails(_runner):
        return await _reconcile(reconciler, exploding, plugin, runner)

    granted = 0
    for _ in range(reconciler.MAX_FAILED_PASSES + 4):
        if reconciler.trigger_from_event(runner, reconcile_coro=always_fails):
            granted += 1
        await asyncio.sleep(0.05)

    assert granted == reconciler.MAX_FAILED_PASSES, (
        f"expected exactly {reconciler.MAX_FAILED_PASSES} attempts, got {granted}"
    )
    assert reconciler.trigger_from_event(runner, reconcile_coro=always_fails) is False


async def test_the_threadsafe_scheduler_logs_the_futures_exception(
    reconciler, plugin, caplog
) -> None:
    """M2's silent half: ``_schedule_reconcile`` discarded the future.

    The ``run_coroutine_threadsafe`` path returns a
    ``concurrent.futures.Future``, and dropping it means a raise inside the
    coroutine is never retrieved and never logged — the failure is invisible in
    ``agent.log``. (The ``loop.create_task`` path at least got asyncio's
    "Task exception was never retrieved" at GC.) A done-callback fixes both.
    """
    import logging

    loop = asyncio.get_running_loop()

    async def boom(_runner):
        raise RuntimeError("reconcile blew up")

    with caplog.at_level(logging.WARNING):
        # Called the way the startup thread calls it: from off the loop, with an
        # explicit loop handle, so the threadsafe branch is the one under test.
        await asyncio.to_thread(reconciler._schedule_reconcile, boom, object(), loop)
        await asyncio.sleep(0.3)

    assert any("reconcile blew up" in r.getMessage() for r in caplog.records), (
        f"the future's exception was swallowed; saw {[r.getMessage() for r in caplog.records]}"
    )


async def test_a_scheduler_that_cannot_schedule_releases_the_latch(reconciler, plugin) -> None:
    """N4: ``safe_schedule_threadsafe`` returning ``None`` consumed the attempt.

    The caller claims the latch and *then* asks the scheduler to run the pass. When
    the gateway loop has gone away the scheduler answers ``None`` — no pass ran, no
    pass ever will — but ``_note_failed_pass`` was not called, so the process's one
    attempt was spent on a pass that never started. That is the same
    latch-accounting shape as review M2, in the one direction still open.

    The orphaned coroutine matters too: never awaited, it surfaces later as a
    ``RuntimeWarning`` attributed to nothing in particular.
    """
    handed: list = []

    def loop_is_gone(coro, _loop):
        handed.append(coro)
        return None

    async def never_runs(_runner):  # pragma: no cover - the point is that it does not
        return {}

    assert reconciler._claim_trigger() is True, "the fixture did not reset the latch"
    reconciler._schedule_reconcile(never_runs, object(), object(), loop_is_gone)

    assert reconciler._claim_trigger() is True, (
        "the latch stayed consumed after a pass that never started"
    )
    assert handed and handed[0].cr_frame is None, (
        "the un-schedulable coroutine was left open, and will warn at collection"
    )


async def test_a_raise_inside_the_pass_still_releases_the_latch(reconciler, plugin) -> None:
    """Belt and braces: even a raise ``reconcile`` cannot catch must not latch shut.

    ``reconcile`` contains its own failures now, so this exercises the guard
    around it rather than a reachable path — the one that has to hold if a future
    edit introduces a raise above the containment.
    """
    calls: list = []

    async def boom(_runner):
        calls.append(1)
        raise RuntimeError("nope")

    runner = object()
    assert reconciler.trigger_from_event(runner, reconcile_coro=boom) is True
    await asyncio.sleep(0.2)
    assert reconciler.trigger_from_event(runner, reconcile_coro=boom) is True
    await asyncio.sleep(0.2)
    assert len(calls) == 2


# ── the latch's three outcomes, and the two that used to be one ────────────
#
# A finished pass can mean three different things, and before this they collapsed
# into "failed or not". ``_account_for_pass`` is the single place that decides,
# and these are its cases.


async def test_an_undecided_probe_retries_and_is_bounded(
    reconciler, journal, plugin, lane
) -> None:
    """A broker that is down for the whole pass must not end reconciliation.

    ``broker_unavailable`` is ``VERDICT_UNKNOWN``: the entry is retained, nothing
    is written and nothing is claimed on a guess. That part was always right. What
    was missing is what happens *next* — the pass reported no ``failed`` entries,
    so the one-shot latch stayed consumed and no later dispatch could try again,
    for the life of the gateway process. A broker being down for the duration of
    one pass is the ordinary restart window, so the drop kept a live-looking
    status message forever.

    Retry is bounded exactly like a failed pass: an undecided probe costs a round
    trip, so a permanently unreachable broker must not become one pass per
    inbound message.
    """
    runner, adapter, source = lane()
    entry = _waiting(journal, plugin, source, adapter, runner, drop_id="U" * 22)
    control = FakeControl(answer={"ok": False, "error": "broker_unavailable", "detail": "no socket"})

    async def undecided(_runner):
        return await _reconcile(reconciler, journal, plugin, runner, control=control)

    granted = 0
    for _ in range(reconciler.MAX_FAILED_PASSES + 4):
        if reconciler.trigger_from_event(runner, reconcile_coro=undecided):
            granted += 1
        await asyncio.sleep(0.05)

    assert granted == reconciler.MAX_FAILED_PASSES, (
        f"an undecided pass granted {granted} attempts, not {reconciler.MAX_FAILED_PASSES}"
    )
    # Never a verdict, at any point: unknown stays unknown.
    assert journal.get(entry["drop_id"])["state"] == plugin.drop.journal.STATE_WAITING
    assert adapter.edited == []


async def test_a_registered_lane_that_cannot_resolve_an_adapter_is_not_a_pass_per_message(
    reconciler, journal, plugin, lane
) -> None:
    """The gate asks ``origin_for_entry``, not "is the lane in the registry?".

    A lane can be registered and still unresolvable — here the runner driving the
    pass owns no adapter for it, which is what a half-started gateway looks like.
    Gating on registration alone would answer "yes, retry" to every inbound
    message for as long as that lasted: a reconcile pass per message, which is
    the failure ``MAX_FAILED_PASSES`` exists to prevent, reached by another door.
    """
    _runner, _adapter, source = lane()
    adapterless = StubRunner({}, gateway_loop=asyncio.get_running_loop())
    entry = _waiting(journal, plugin, source, _adapter, _runner, drop_id="V" * 22)
    lane_key = plugin.drop.sources.routing_tuple_for_source(source)

    async def cannot_resolve(_runner):
        return await _reconcile(reconciler, journal, plugin, adapterless)

    assert reconciler.trigger_from_event(adapterless, reconcile_coro=cannot_resolve) is True
    await asyncio.sleep(0.2)

    assert reconciler.deferred_lanes() == frozenset({lane_key}), (
        "the pass did not record the lane it deferred on"
    )
    assert plugin.drop.sources.REGISTRY.by_routing_tuple(lane_key) is not None, (
        "precondition: the lane IS registered; only the adapter is missing"
    )
    for _ in range(10):
        assert reconciler.trigger_from_event(adapterless, reconcile_coro=cannot_resolve) is False, (
            "a registered lane with no adapter re-ran the pass on every dispatch"
        )
    assert journal.get(entry["drop_id"])["state"] == plugin.drop.journal.STATE_WAITING

    # And the moment the adapter is there, the same lane opens the gate again.
    assert reconciler.trigger_from_event(_runner, reconcile_coro=cannot_resolve) is True


async def test_the_deferred_gate_does_not_reorder_the_source_registry(
    reconciler, journal, plugin, lane
) -> None:
    """The gate is an observer. It must not decide which lane is evicted next.

    ``by_routing_tuple`` refreshes LRU order; the gate runs on every dispatch
    about lanes it is not going to use, so it reads through ``peek_routing_tuple``
    instead.
    """
    _runner, _adapter, source = lane(chat_id="tg-first")
    adapterless = StubRunner({}, gateway_loop=asyncio.get_running_loop())
    _waiting(journal, plugin, source, _adapter, _runner, drop_id="W" * 22)

    other = StubAdapter(Platform.TELEGRAM)
    newer = other.build_source(chat_id="tg-second", chat_type="dm", user_id="u-2")
    plugin.drop.sources.REGISTRY.put(newer, gateway=_runner, session_key="s2")

    async def cannot_resolve(_r):
        return await _reconcile(reconciler, journal, plugin, adapterless)

    assert reconciler.trigger_from_event(adapterless, reconcile_coro=cannot_resolve) is True
    await asyncio.sleep(0.2)

    # Put the *other* lane at the tail before the snapshot. Without this the
    # deferred lane is already last — the pass itself touched it through the
    # resolving lookup — and a gate that moved it to the end again would be
    # undetectable. The eviction ``_trim`` performs is decided by exactly this
    # order, so "undetectable here" is not "harmless there".
    plugin.drop.sources.REGISTRY.put(newer, gateway=_runner, session_key="s2")
    before = plugin.drop.sources.REGISTRY.keys()
    for _ in range(5):
        reconciler.trigger_from_event(adapterless, reconcile_coro=cannot_resolve)
    assert plugin.drop.sources.REGISTRY.keys() == before, (
        "the retry gate reordered or evicted entries in the source registry"
    )


async def test_a_pass_that_both_fails_and_defers_keeps_both_accounts(
    reconciler, journal, plugin, lane
) -> None:
    """Neither outcome may erase the other.

    Entry A's write fails (bounded retry). Entry B is in a lane the runner cannot
    resolve (gated retry). Accounting them as one meant the failure branch cleared
    B's lane, so when the failure budget ran out B had nothing left to re-open the
    latch — even though B's conversation coming back was exactly the event that
    would have let the pass finish.
    """
    runner, adapter, source = lane(chat_id="tg-a")
    _waiting(journal, plugin, source, adapter, runner, drop_id="X" * 22, expires_in_ms=-1000)

    quiet_adapter = StubAdapter(Platform.DISCORD)
    quiet_runner = StubRunner({Platform.DISCORD: quiet_adapter})
    quiet_source = quiet_adapter.build_source(chat_id="dc-quiet", chat_type="dm", user_id="u-9")
    quiet_lane = plugin.drop.sources.routing_tuple_for_source(quiet_source)
    _waiting(journal, plugin, quiet_source, quiet_adapter, quiet_runner, drop_id="Y" * 22)
    # Only A's lane is registered: B is the restart case, and it must survive A.
    plugin.drop.sources.REGISTRY.forget_routing_tuple(quiet_lane)

    exploding = ExplodingJournal(journal, fail_for={"X" * 22})  # never recovers

    async def fails_and_defers(_runner):
        return await _reconcile(reconciler, exploding, plugin, runner)

    granted = 0
    for _ in range(reconciler.MAX_FAILED_PASSES + 2):
        if reconciler.trigger_from_event(runner, reconcile_coro=fails_and_defers):
            granted += 1
        await asyncio.sleep(0.05)

    assert granted == reconciler.MAX_FAILED_PASSES, granted
    assert reconciler.deferred_lanes() == frozenset({quiet_lane}), (
        "the failure budget erased the lane the same pass deferred on"
    )
    # The spent failure budget is not the end of reconciliation: B's lane coming
    # back still opens the gate.
    assert reconciler.trigger_from_event(runner, reconcile_coro=fails_and_defers) is False
    plugin.drop.sources.REGISTRY.put(quiet_source, gateway=quiet_runner, session_key="s9")
    assert reconciler.trigger_from_event(quiet_runner, reconcile_coro=fails_and_defers) is True, (
        "a deferred lane could not revive a pass whose failure budget was spent"
    )


async def test_deferred_re_opens_are_bounded_and_then_cost_nothing(
    reconciler, journal, plugin, lane, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backstop under the gate, and what the gate must stop doing after it.

    The gate normally makes the bound unreachable: a retry either drives the lane
    it was opened for — progress, which resets the count — or the gate shuts
    again. What is bounded here is the case the gate cannot see: a lane that
    resolves when the gate asks and does not when the pass asks a moment later.

    Once the budget is spent the answer is settled, and re-deriving it is pure
    cost: the walk is O(N deferred lanes) of registry peeks and adapter
    resolutions, and it would run on *every inbound message* for the life of the
    process. So "spent" is its own state, answered in O(1), while the lanes stay
    readable — which conversations were given up on is exactly what an operator
    would want to know.
    """
    runner, adapter, source = lane()
    _waiting(journal, plugin, source, adapter, runner, drop_id="Z" * 22)
    lane_key = plugin.drop.sources.routing_tuple_for_source(source)

    async def always_defers(_runner):
        # Resolvable to the gate (the lane is registered and the runner owns the
        # adapter), unresolvable to the pass.
        return await _reconcile(reconciler, journal, plugin, StubRunner({}))

    granted = 0
    for _ in range(reconciler.MAX_DEFERRED_PASSES + 5):
        if reconciler.trigger_from_event(runner, reconcile_coro=always_defers):
            granted += 1
        await asyncio.sleep(0.02)

    assert granted == reconciler.MAX_DEFERRED_PASSES, (
        f"deferred re-opens are unbounded: {granted} granted"
    )
    assert reconciler.deferred_retries_spent() is True
    assert reconciler.deferred_lanes() == frozenset({lane_key}), (
        "the lanes stopped being readable once the budget was spent"
    )

    # The part that is not just bookkeeping: no work per dispatch, forever after.
    peeks: list = []
    registry = plugin.drop.sources.REGISTRY
    real_peek = registry.peek_routing_tuple
    monkeypatch.setattr(
        registry,
        "peek_routing_tuple",
        lambda key: peeks.append(key) or real_peek(key),
    )
    for _ in range(25):
        assert reconciler.trigger_from_event(runner, reconcile_coro=always_defers) is False
    assert peeks == [], (
        f"the gate kept walking {len(peeks)} lanes per dispatch after giving up"
    )


class UnreadableJournal:
    """A journal whose ``entries()`` raises — a read-only or vanished state dir.

    The failure that matters about it: ``reconcile`` returns *immediately* with
    ``failed: ["journal:entries"]`` and no lanes at all, because it never got far
    enough to enumerate one.
    """

    def __init__(self, inner):
        self._inner = inner

    def entries(self):
        raise OSError(13, "Permission denied")

    def __getattr__(self, name):
        return getattr(self._inner, name)


async def test_a_failed_pass_that_enumerates_nothing_keeps_the_lanes_it_never_saw(
    reconciler, journal, plugin, lane
) -> None:
    """A failure must not erase a deferral it had no opportunity to observe.

    An unreadable journal reports ``failed`` and *no* ``unresolved_lanes`` — not
    because there are none, but because it never enumerated. Taking that empty
    list as the truth discarded lanes an earlier pass had legitimately recorded,
    and once the failure budget ran out those drops had nothing left that could
    re-open the latch. The lanes are unioned instead, so the fallback at the end
    of the budget still has something to gate on.
    """
    runner, adapter, source = lane()
    _waiting(journal, plugin, source, adapter, runner, drop_id="J" * 22)
    lane_key = plugin.drop.sources.routing_tuple_for_source(source)

    async def defers(_r):
        return await _reconcile(reconciler, journal, plugin, runner)

    unreadable = UnreadableJournal(journal)

    async def fails_blind(_r):
        return await _reconcile(reconciler, unreadable, plugin, runner)

    # One pass that genuinely defers, so there is a lane on record.
    plugin.drop.sources.REGISTRY.clear()
    assert reconciler.trigger_from_event(runner, reconcile_coro=defers) is True
    await asyncio.sleep(0.2)
    assert reconciler.deferred_lanes() == frozenset({lane_key})

    # Then nothing but blind failures, right through the budget.
    plugin.drop.sources.REGISTRY.put(source, gateway=runner, session_key="s")
    for _ in range(reconciler.MAX_FAILED_PASSES):
        reconciler.trigger_from_event(runner, reconcile_coro=fails_blind)
        await asyncio.sleep(0.05)

    assert reconciler.deferred_lanes() == frozenset({lane_key}), (
        "a failure that enumerated nothing erased the lane a previous pass deferred on"
    )
    # The failure budget is spent, so the carried lane is now the only thing that
    # can revive reconciliation — and it can.
    plugin.drop.sources.REGISTRY.clear()
    assert reconciler.trigger_from_event(runner, reconcile_coro=defers) is False
    plugin.drop.sources.REGISTRY.put(source, gateway=runner, session_key="s")
    assert reconciler.trigger_from_event(runner, reconcile_coro=defers) is True, (
        "the carried lane could not revive a pass whose failure budget was spent"
    )


# ── a status edit that failed is work, not a flag ──────────────────────────


def _expired_with_a_refused_edit(journal, plugin, lane, **kw):
    """One drop past its deadline in a lane whose adapter refuses edits."""
    runner, adapter, source = lane(edit_ok=False, **kw)
    entry = _waiting(
        journal, plugin, source, adapter, runner, drop_id="E" * 21 + "1", expires_in_ms=-1000
    )
    return runner, adapter, source, entry


async def test_a_refused_status_edit_is_retried_until_it_lands(
    reconciler, journal, plugin, lane
) -> None:
    """The stale-URL bug: a refused edit left the *waiting* notice up for good.

    ``finalize_terminal`` writes the journal and announces even when the edit is
    refused, which is right — the outcome has to become durable whether or not
    chat cooperates. But nothing ever tried the edit again, so the message the
    user could see kept advertising a live-looking capability URL for a drop the
    journal had already closed. The pass reported no failures, so the latch stayed
    consumed and no later pass could have fixed it either.

    The retry must not duplicate anything: the wake is announced once, the state
    is written once, and no claim is involved at any point.
    """
    runner, adapter, source, entry = _expired_with_a_refused_edit(journal, plugin, lane)
    lane_key = plugin.drop.sources.routing_tuple_for_source(source)
    deliver = FakeDeliver()

    async def a_pass(_r):
        return await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)

    assert reconciler.trigger_from_event(runner, reconcile_coro=a_pass) is True
    await asyncio.sleep(0.2)

    stored = journal.get(entry["drop_id"])
    assert stored["state"] == plugin.drop.journal.STATE_EXPIRED
    assert stored["edit_failed"] is True
    assert len(adapter.edited) == 1, "the first attempt is the transition's own edit"
    assert len(deliver.calls) == 1
    assert reconciler.deferred_lanes() == frozenset({lane_key}), (
        "a refused edit left the pass looking clean, so nothing would retry it"
    )

    # The adapter recovers — a rate limit lifting, a permission restored.
    adapter._edit_ok = True
    assert reconciler.trigger_from_event(runner, reconcile_coro=a_pass) is True
    await asyncio.sleep(0.2)

    repaired = journal.get(entry["drop_id"])
    assert repaired["edit_failed"] is False, "the retry did not clear the flag"
    assert len(adapter.edited) == 2, "the status message was never re-edited"
    assert adapter.edited[-1].content == entry["notice_expired"]
    assert adapter.edited[-1].message_id == entry["message_id"]

    # Nothing was duplicated by the repair.
    assert len(deliver.calls) == 1, "the retry announced the drop a second time"
    assert repaired["state"] == plugin.drop.journal.STATE_EXPIRED
    assert repaired["claimed_at"] is None
    assert repaired["announced_at"] == stored["announced_at"]
    assert repaired["announce_attempts"] == stored["announce_attempts"]

    # And with nothing left outstanding the latch goes back to one-shot.
    assert reconciler.deferred_lanes() == frozenset()
    assert reconciler.trigger_from_event(runner, reconcile_coro=a_pass) is False


async def test_status_edit_retries_are_bounded(reconciler, journal, plugin, lane) -> None:
    """An adapter that refuses forever must not be retried forever.

    Per drop, not per pass: one message that cannot be edited is no reason to stop
    reconciling everything else, so the budget is ``MAX_EDIT_RETRIES`` attempts on
    that drop and the pass stays clean once they are used up.
    """
    runner, adapter, source, entry = _expired_with_a_refused_edit(journal, plugin, lane)
    deliver = FakeDeliver()

    async def a_pass(_r):
        return await _reconcile(reconciler, journal, plugin, runner, deliver=deliver)

    for _ in range(reconciler.MAX_EDIT_RETRIES + 3):
        await a_pass(runner)

    assert len(adapter.edited) == 1 + reconciler.MAX_EDIT_RETRIES, (
        f"unbounded edit retries: {len(adapter.edited)} attempts"
    )
    # The drop is untouched apart from the flag, and nothing was re-announced.
    stored = journal.get(entry["drop_id"])
    assert stored["state"] == plugin.drop.journal.STATE_EXPIRED
    assert stored["edit_failed"] is True
    assert stored["claimed_at"] is None
    assert len(deliver.calls) == 1

    # A pass with the budget used up is clean: it leaves the latch alone.
    summary = await a_pass(runner)
    assert summary["edit_retry_pending"] == []
    assert summary["retry_lanes"] == []
    assert summary["failed"] == []
