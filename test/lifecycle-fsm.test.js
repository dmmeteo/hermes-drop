// Lifecycle — the broker's state machine, pinned as a machine rather than as a
// collection of per-seam behaviours.
//
// The seam tests already assert what each endpoint answers on its own happy and
// unhappy paths. What is asserted here is the thing none of them can see alone:
// that `pending → submitted → claimed`, plus `→ destroyed` from every live
// state, is the *whole* machine — that every seam agrees on which state a
// handoff is in, that no operation moves it along an edge the machine does not
// have, and that the two things that must never be true twice (one delivery, one
// claim) hold under arbitrary interleavings.
//
// Vocabulary used throughout:
//   pending    minted, key pair live, no payload
//   submitted  one envelope opened, payload held, key pair gone
//   claimed    payload handed over once; a payload-free receipt survives the TTL
//   gone       destroyed *and* unreachable — `destroy` drops the record from both
//              indexes, so `destroyed` has no externally observable form beyond
//              the absence of the record. Tests spell it `gone` for that reason.
//
// One state is deliberately absent from this file: `transferring`, the substate a
// file drop enters while its container is being streamed to a local receiver. It
// is unreachable for a text drop — the whole machine here — and it is pinned as a
// machine of its own in test/file-claim-transfer.test.js. What this file does
// assert about it is the boundary: the two file-claim ops appear in the malformed
// battery below, so a text handoff cannot be moved by them from any state.
//
// The broker is driven through its real seams wherever one exists (the browser
// client for metadata/submit, the control socket for await/claim) so that what is
// pinned is the machine an operator and a browser actually meet. The in-process
// broker object is used only for two things a seam cannot express: expiry at a
// chosen instant, and calls too malformed to survive a seam's own validation.
//
// No test here prints or persists plaintext beyond the single equality check that
// a claim returned what was submitted.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { afterEach, beforeEach, describe, it } from 'node:test';

import {
  fetchMetadata,
  sealEnvelope,
  submitEnvelope,
} from '../src/client/handoff-client.js';
import { splitHandoffUrl, startTestBroker } from './helpers/harness.js';

const CONTRACT = JSON.parse(
  await readFile(new URL('../contract/control-protocol.json', import.meta.url), 'utf8'),
);
const MIN_RESPONSE_BYTES = CONTRACT.transport.min_response_bytes;
/** The only error strings any seam may answer with. */
const ERROR_VOCABULARY = new Set(CONTRACT.errors);

const SECRET = 'PGPASSWORD=example-not-a-real-secret\nsecond line\tünïcode ✓';
const OTHER_SECRET = 'a different payload entirely';
// Large enough that its claim response cannot fit inside the smallest ceiling the
// broker accepts, so a `response_too_large` refusal is provoked with a ceiling
// that is itself valid rather than with a caller mistake.
const BIG_SECRET = 'k'.repeat(4096);

// Long enough that nothing lapses on its own during a test; expiry in this file
// is always something a test asks for explicitly.
const TTL_SECONDS = 120;

/** Every state a live test broker's sweeper must not reach on its own. */
function testBroker(overrides = {}) {
  // The sweeper is parked so that expiry is only ever what a test triggers:
  // either lazily, by touching a handoff whose TTL has really lapsed, or by
  // sweeping at a chosen instant. A background sweep would make both racy.
  return startTestBroker({ sweepIntervalMs: 3_600_000, ...overrides });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

describe('lifecycle: the broker state machine', () => {
  let broker;
  /** The in-process broker, for expiry at a chosen instant and sub-seam calls. */
  let core;
  let logLines;

  beforeEach(async () => {
    logLines = [];
    const capture = (level) => (message) => logLines.push(`${level} ${message}`);
    broker = await testBroker({
      logger: { info: capture('info'), warn: capture('warn'), error: capture('error') },
    });
    core = broker.broker;
  });

  afterEach(async () => {
    await broker.stop();
  });

  /**
   * A freshly minted handoff plus the two envelopes every row of the matrix
   * needs: the one that wins, and a well-formed one for the same handoff that
   * must never be accepted after it. Both are sealed while the handoff is still
   * pending, because sealing needs the metadata only a pending handoff publishes.
   */
  async function mint({
    plaintext = SECRET,
    otherPlaintext = OTHER_SECRET,
    ttlSeconds = TTL_SECONDS,
  } = {}) {
    const created = await broker.control({ op: 'create', ttl_seconds: ttlSeconds });
    const capability = splitHandoffUrl(created.url).capability;
    const metadata = await fetchMetadata({ capability, origin: broker.baseUrl });
    const winner = await sealEnvelope({ capability, metadata, plaintext });
    const other = await sealEnvelope({ capability, metadata, plaintext: otherPlaintext });
    return {
      id: created.handoff_id,
      capability,
      metadata,
      winner,
      other,
      plaintext,
      otherPlaintext,
      expiresAt: created.expires_at,
    };
  }

  const send = (handoff, envelope) =>
    submitEnvelope({ capability: handoff.capability, envelope, origin: broker.baseUrl });

  /** What the machine looks like from outside: a state name, or `gone`. */
  function observe(handoffId) {
    const snapshot = broker.testSnapshot(handoffId);
    return snapshot === null ? 'gone' : snapshot.state;
  }

  /** Expiry, at an instant of the test's choosing, exactly as the sweeper does it. */
  function expireEverything() {
    core.sweep(Date.now() + TTL_SECONDS * 1000 + 1);
  }

  /** Drives a fresh handoff into `state` and hands it back with its envelopes. */
  async function at(state, options) {
    const handoff = await mint(options);
    if (state === 'pending') return handoff;

    assert.equal(await send(handoff, handoff.winner), 'received');
    if (state === 'submitted') return handoff;

    if (state === 'claimed') {
      const claimed = await broker.control({ op: 'claim', handoff_id: handoff.id });
      assert.equal(claimed.ok, true, JSON.stringify(claimed));
      return handoff;
    }
    if (state === 'gone') {
      expireEverything();
      return handoff;
    }
    throw new Error(`no such state: ${state}`);
  }

  // ── the canonical sequence ───────────────────────────────────────────────
  //
  // One handoff walked end to end, with everything the record is allowed to hold
  // checked at each stop. The per-state matrix below says what each *seam*
  // answers; this says what the *record* is.

  describe('pending → submitted → claimed', () => {
    it('holds the key pair, then the payload, then neither', async () => {
      const handoff = await mint();

      const minted = broker.testSnapshot(handoff.id);
      assert.equal(minted.state, 'pending');
      assert.equal(minted.hasPrivateKey, true, 'pending owns the only copy of the key');
      assert.equal(minted.hasPlaintext, false, 'nothing has been submitted yet');
      assert.equal(minted.aeadFailures, 0);
      assert.equal(minted.waiters, 0);

      assert.equal(await send(handoff, handoff.winner), 'received');

      const submitted = broker.testSnapshot(handoff.id);
      assert.equal(submitted.state, 'submitted');
      assert.equal(submitted.hasPrivateKey, false, 'the key dies the moment the AEAD succeeds');
      assert.equal(submitted.hasPlaintext, true);
      assert.equal(submitted.plaintextBytes, Buffer.byteLength(SECRET, 'utf8'));

      const claimed = await broker.control({ op: 'claim', handoff_id: handoff.id });
      assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), SECRET);

      const receipt = broker.testSnapshot(handoff.id);
      assert.equal(receipt.state, 'claimed');
      assert.equal(receipt.hasPrivateKey, false);
      assert.equal(receipt.hasPlaintext, false, 'the receipt keeps no payload');
      assert.equal(receipt.plaintextBytes, 0);
      assert.equal(receipt.expiresAt, minted.expiresAt, 'claiming does not extend the lifetime');
      assert.ok(!receipt.serialized.includes(SECRET));

      expireEverything();
      assert.equal(observe(handoff.id), 'gone', 'the receipt lapses with the TTL like anything else');
    });

    it('never advertises a payload it no longer has, at any step', async () => {
      // hasPlaintext is exactly "state === submitted" and hasPrivateKey exactly
      // "state === pending" — the two facts every deletion guarantee rests on.
      const handoff = await mint();
      const steps = [
        () => {},
        async () => assert.equal(await send(handoff, handoff.winner), 'received'),
        async () => assert.equal((await broker.control({ op: 'claim', handoff_id: handoff.id })).ok, true),
        () => expireEverything(),
      ];

      for (const step of steps) {
        await step();
        const snapshot = broker.testSnapshot(handoff.id);
        if (snapshot === null) continue;
        assert.equal(
          snapshot.hasPrivateKey,
          snapshot.state === 'pending',
          `key material outside pending: ${snapshot.state}`,
        );
        assert.equal(
          snapshot.hasPlaintext,
          snapshot.state === 'submitted',
          `payload outside submitted: ${snapshot.state}`,
        );
      }
    });
  });

  // ── the state × operation matrix ─────────────────────────────────────────
  //
  // One row per state, one column per operation, each on its own fresh handoff.
  // `answer` is what the seam says; `then` is the state the handoff is in
  // afterwards. Every cell that reads `unavailable` is the same generic refusal —
  // the content invariant the whole design rests on.
  //
  // `submitOther` against `pending` is not a duplicate: it is simply a first
  // submit that happens to carry the second envelope, and it wins like any other.

  const MATRIX = {
    pending: {
      metadata: { answer: 'ok', then: 'pending' },
      submitWinner: { answer: 'received', then: 'submitted' },
      submitOther: { answer: 'received', then: 'submitted' },
      await: { answer: 'unavailable', then: 'pending' },
      claim: { answer: 'unavailable', then: 'pending' },
    },
    submitted: {
      metadata: { answer: 'unavailable', then: 'submitted' },
      submitWinner: { answer: 'received', then: 'submitted' },
      submitOther: { answer: 'unavailable', then: 'submitted' },
      await: { answer: 'submitted', then: 'submitted' },
      claim: { answer: 'ok', then: 'claimed' },
    },
    claimed: {
      metadata: { answer: 'unavailable', then: 'claimed' },
      submitWinner: { answer: 'received', then: 'claimed' },
      submitOther: { answer: 'unavailable', then: 'claimed' },
      await: { answer: 'unavailable', then: 'claimed' },
      claim: { answer: 'unavailable', then: 'claimed' },
    },
    gone: {
      metadata: { answer: 'unavailable', then: 'gone' },
      submitWinner: { answer: 'unavailable', then: 'gone' },
      submitOther: { answer: 'unavailable', then: 'gone' },
      await: { answer: 'unavailable', then: 'gone' },
      claim: { answer: 'unavailable', then: 'gone' },
    },
  };

  /** Runs one operation and normalises its answer to a single word. */
  async function apply(operation, handoff) {
    switch (operation) {
      case 'metadata': {
        const metadata = await fetchMetadata({
          capability: handoff.capability,
          origin: broker.baseUrl,
        });
        return metadata === null ? 'unavailable' : 'ok';
      }
      case 'submitWinner':
        return send(handoff, handoff.winner);
      case 'submitOther':
        return send(handoff, handoff.other);
      case 'await': {
        // Long enough that a pending handoff really does park on the waiter and
        // come back on the timeout, rather than short-circuiting.
        const response = await broker.control({
          op: 'await',
          handoff_id: handoff.id,
          wait_ms: 150,
        });
        return response.ok ? response.status : response.error;
      }
      case 'claim': {
        const response = await broker.control({ op: 'claim', handoff_id: handoff.id });
        if (!response.ok) return response.error;
        assert.equal(
          Buffer.from(response.plaintext_b64, 'base64').toString('utf8'),
          handoff.plaintext,
          'a successful claim must return exactly what was submitted',
        );
        return 'ok';
      }
      default:
        throw new Error(`no such operation: ${operation}`);
    }
  }

  for (const [state, row] of Object.entries(MATRIX)) {
    it(`answers every operation the same way from ${state}`, async () => {
      for (const [operation, expected] of Object.entries(row)) {
        const handoff = await at(state);
        assert.equal(
          await apply(operation, handoff),
          expected.answer,
          `${operation} on a ${state} handoff`,
        );
        assert.equal(
          observe(handoff.id),
          expected.then,
          `${operation} left a ${state} handoff in the wrong state`,
        );
      }
    });
  }

  // ── the transitions the matrix cells stand for ───────────────────────────

  it('delivers once and only once, however many identical retries arrive', async () => {
    const handoff = await at('submitted');

    // The retry that lost its response, before and after the claim: the same
    // receipt every time, and never a second payload.
    assert.equal(await send(handoff, handoff.winner), 'received');
    const claimed = await broker.control({ op: 'claim', handoff_id: handoff.id });
    assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), SECRET);

    for (let retry = 0; retry < 3; retry += 1) {
      assert.equal(await send(handoff, handoff.winner), 'received', `retry ${retry}`);
      assert.equal(observe(handoff.id), 'claimed');
      assert.equal(broker.testSnapshot(handoff.id).hasPlaintext, false);
    }

    const second = await broker.control({ op: 'claim', handoff_id: handoff.id });
    assert.deepEqual(second, { ok: false, error: 'unavailable' });
  });

  it('refuses a different envelope from every state after the first one wins', async () => {
    for (const state of ['submitted', 'claimed']) {
      const handoff = await at(state);
      assert.equal(await send(handoff, handoff.other), 'unavailable', state);
      assert.equal(observe(handoff.id), state, `a refused submit must not move a ${state} handoff`);
    }
  });

  it('lets exactly one of many concurrent claims win', async () => {
    const handoff = await at('submitted');

    const outcomes = await Promise.all(
      Array.from({ length: 6 }, () => broker.control({ op: 'claim', handoff_id: handoff.id })),
    );
    const delivered = outcomes.filter((outcome) => outcome.ok);
    assert.equal(delivered.length, 1, 'exactly one claim may carry the payload');
    assert.equal(Buffer.from(delivered[0].plaintext_b64, 'base64').toString('utf8'), SECRET);
    for (const refused of outcomes.filter((outcome) => !outcome.ok)) {
      assert.deepEqual(refused, { ok: false, error: 'unavailable' });
    }
    assert.equal(observe(handoff.id), 'claimed');
  });

  it('kills the form the instant the payload lands, not when it is claimed', async () => {
    const handoff = await at('submitted');
    // Reloading the page must not resurrect it, and neither must claiming.
    assert.equal(await apply('metadata', handoff), 'unavailable');
    await broker.control({ op: 'claim', handoff_id: handoff.id });
    assert.equal(await apply('metadata', handoff), 'unavailable');
  });

  // ── expiry from every live state ─────────────────────────────────────────

  describe('expiry', () => {
    for (const state of ['pending', 'submitted', 'claimed']) {
      it(`destroys a ${state} handoff and answers every seam alike afterwards`, async () => {
        const handoff = await at(state);
        assert.equal(observe(handoff.id), state);

        expireEverything();

        assert.equal(observe(handoff.id), 'gone', 'expiry drops the record from both indexes');
        for (const operation of ['metadata', 'submitWinner', 'submitOther', 'await', 'claim']) {
          assert.equal(
            await apply(operation, handoff),
            'unavailable',
            `${operation} after a ${state} handoff expired`,
          );
        }
        assert.ok(
          logLines.some((line) => line.includes(`hid=${handoff.id}`) && line.includes('expired')),
          'expiry is logged, by id and reason',
        );
      });
    }

    it('expires a handoff nobody swept, the moment it is next touched', async () => {
      // The sweeper is parked in this suite, so this is the lazy path in
      // `live()` on its own: a TTL that has really lapsed, and the first seam to
      // look at the record is the one that destroys it.
      //
      // The TTL has to outlast minting — a create, a metadata round trip and two
      // HPKE seals — so it is deliberately generous, and the wait is taken from
      // the handoff's own deadline rather than guessed.
      const handoff = await at('submitted', { ttlSeconds: 1.5 });
      await sleep(Math.max(0, handoff.expiresAt - Date.now()) + 50);

      assert.equal(observe(handoff.id), 'submitted', 'nothing has touched it yet');
      assert.deepEqual(await broker.control({ op: 'claim', handoff_id: handoff.id }), {
        ok: false,
        error: 'unavailable',
      });
      assert.equal(observe(handoff.id), 'gone', 'the touch is what destroys it');
    });

    it('releases a parked waiter when the handoff expires under it', async () => {
      // A full-length TTL on purpose: what ends this wait is the expiry the test
      // triggers, not a deadline it has to race the setup against.
      const handoff = await at('pending');
      const waiting = broker.control({ op: 'await', handoff_id: handoff.id, wait_ms: 10_000 });

      await sleep(120);
      assert.equal(broker.testSnapshot(handoff.id).waiters, 1, 'the subscription is parked');
      expireEverything();

      assert.deepEqual(await waiting, { ok: false, error: 'unavailable' });
      assert.equal(observe(handoff.id), 'gone');
    });

    it('leaves no waiter attached once a subscription is answered', async () => {
      const handoff = await at('pending');
      // Timed out rather than woken: the closure must still be detached, or a
      // handoff accumulates one per lost subscriber for the rest of its TTL.
      await broker.control({ op: 'await', handoff_id: handoff.id, wait_ms: 60 });
      assert.equal(broker.testSnapshot(handoff.id).waiters, 0);

      const woken = broker.control({ op: 'await', handoff_id: handoff.id, wait_ms: 10_000 });
      await sleep(60);
      assert.equal(await send(handoff, handoff.winner), 'received');
      assert.equal((await woken).status, 'submitted');
      assert.equal(broker.testSnapshot(handoff.id).waiters, 0);
    });

    it('destroys everything on shutdown, whatever state it is in', async () => {
      const instance = await testBroker();
      const ids = [];
      for (const state of ['pending', 'submitted']) {
        const created = await instance.control({ op: 'create', ttl_seconds: TTL_SECONDS });
        const capability = splitHandoffUrl(created.url).capability;
        if (state === 'submitted') {
          const metadata = await fetchMetadata({ capability, origin: instance.baseUrl });
          const envelope = await sealEnvelope({ capability, metadata, plaintext: SECRET });
          await submitEnvelope({ capability, envelope, origin: instance.baseUrl });
        }
        ids.push({ id: created.handoff_id, snapshot: instance.testSnapshot });
      }

      instance.broker.destroyAll();
      for (const { id, snapshot } of ids) assert.equal(snapshot(id), null);
      await instance.stop();
    });
  });

  // ── the size refusal is not a transition ─────────────────────────────────

  describe('a claim refused for size', () => {
    it('leaves the handoff exactly as submitted, by every measure', async () => {
      const handoff = await at('submitted', { plaintext: BIG_SECRET });
      const before = broker.testSnapshot(handoff.id);

      const refused = await broker.control({
        op: 'claim',
        handoff_id: handoff.id,
        max_response_bytes: MIN_RESPONSE_BYTES,
      });
      assert.equal(refused.error, 'response_too_large', JSON.stringify(refused));

      const after = broker.testSnapshot(handoff.id);
      assert.equal(after.state, 'submitted', 'a refusal is not a claim');
      assert.equal(after.hasPlaintext, true);
      assert.equal(after.plaintextBytes, before.plaintextBytes, 'not a byte was touched');
      assert.equal(after.hasPrivateKey, false);
      assert.equal(after.expiresAt, before.expiresAt);
    });

    it('keeps every other seam answering exactly as a submitted handoff does', async () => {
      const handoff = await at('submitted', { plaintext: BIG_SECRET });
      await broker.control({
        op: 'claim',
        handoff_id: handoff.id,
        max_response_bytes: MIN_RESPONSE_BYTES,
      });

      assert.equal(await apply('metadata', handoff), 'unavailable');
      assert.equal(await apply('await', handoff), 'submitted', 'still waiting to be collected');
      assert.equal(await apply('submitWinner', handoff), 'received', 'the retry is still idempotent');
      assert.equal(await apply('submitOther', handoff), 'unavailable');
      assert.equal(observe(handoff.id), 'submitted');
    });

    it('is repeatable, and costs nothing each time', async () => {
      const handoff = await at('submitted', { plaintext: BIG_SECRET });
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const refused = await broker.control({
          op: 'claim',
          handoff_id: handoff.id,
          max_response_bytes: MIN_RESPONSE_BYTES,
        });
        assert.equal(refused.error, 'response_too_large', `attempt ${attempt}`);
        assert.equal(observe(handoff.id), 'submitted');
      }

      // And a reader that can hold it still gets it, intact.
      const claimed = await broker.control({ op: 'claim', handoff_id: handoff.id });
      assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), BIG_SECRET);
      assert.equal(observe(handoff.id), 'claimed');
    });

    it('still lapses at its TTL, refusals or not', async () => {
      const handoff = await at('submitted', { plaintext: BIG_SECRET });
      await broker.control({
        op: 'claim',
        handoff_id: handoff.id,
        max_response_bytes: MIN_RESPONSE_BYTES,
      });
      expireEverything();
      assert.equal(observe(handoff.id), 'gone', 'a refusal does not pin the payload past its TTL');
    });
  });

  // ── malformed calls move nothing ─────────────────────────────────────────

  describe('malformed calls', () => {
    /** Everything a caller can get wrong that a seam still has to answer for. */
    async function battery(handoff) {
      const answers = [];
      const record = (label, value) => answers.push([label, value]);

      // Control seam: ill-typed and unknown requests.
      for (const [label, request] of [
        ['unknown op', { op: 'nonsense' }],
        ['no op at all', {}],
        ['claim without an id', { op: 'claim' }],
        ['claim with a numeric id', { op: 'claim', handoff_id: 42 }],
        ['claim with a null id', { op: 'claim', handoff_id: null }],
        ['await without an id', { op: 'await' }],
        ['await with a numeric id', { op: 'await', handoff_id: 42 }],
        // Not in this list, deliberately: `wait_ms: null`. JSON has no NaN and no
        // undefined, so an absent optional field and an explicitly null one are
        // the same line on the wire, and both mean the documented default of 0.
        // A `claim` carrying one is a perfectly ordinary claim — it belongs in
        // the matrix above, not in a battery whose whole point is that nothing
        // in it may move the machine.
        ['negative wait', { op: 'await', handoff_id: handoff.id, wait_ms: -1 }],
        ['unparseable wait', { op: 'await', handoff_id: handoff.id, wait_ms: 'soon' }],
        ['claim with a negative wait', { op: 'claim', handoff_id: handoff.id, wait_ms: -1 }],
        ['claim with an object wait', { op: 'claim', handoff_id: handoff.id, wait_ms: {} }],
        ['claim with a null ceiling', {
          op: 'claim',
          handoff_id: handoff.id,
          max_response_bytes: null,
        }],
        ['claim with a fractional ceiling', {
          op: 'claim',
          handoff_id: handoff.id,
          max_response_bytes: 4096.5,
        }],
        ['claim under the floor', {
          op: 'claim',
          handoff_id: handoff.id,
          max_response_bytes: MIN_RESPONSE_BYTES - 1,
        }],
        ['create with a zero ttl', { op: 'create', ttl_seconds: 0 }],
        ['create with a negative ttl', { op: 'create', ttl_seconds: -60 }],
        ['create with an over-policy ttl', { op: 'create', ttl_seconds: 999_999 }],
        ['create for an unknown platform', { op: 'create', notice_platform: 'irc' }],
        // The file-claim ops, against the text machine they have no business in.
        // A text drop has no container to transfer, so every one of these is a
        // refusal from a state that must not move — including the commit, which is
        // the one call in the protocol that can retire a payload and is here
        // precisely because it must never do so for a caller with no lease.
        ['begin a transfer with no id', { op: 'begin_file_claim' }],
        ['begin a transfer with a numeric id', { op: 'begin_file_claim', handoff_id: 42 }],
        ['begin a transfer on a text drop', { op: 'begin_file_claim', handoff_id: handoff.id }],
        ['commit a transfer nobody began', {
          op: 'commit_file_claim',
          handoff_id: handoff.id,
          transfer_id: 'AAAAAAAAAAAAAAAAAAAAAA',
          received_bytes: 0,
          digests: [],
        }],
      ]) {
        record(label, await broker.control(request));
      }

      // Below the seams: values the socket's own JSON framing would never let
      // through, put straight to the broker so the machine answers for them too.
      for (const [label, value] of [
        ['metadata(undefined)', await core.metadata(undefined)],
        ['metadata(null)', await core.metadata(null)],
        ['metadata(42)', await core.metadata(42)],
        ['metadata("")', await core.metadata('')],
        ['metadata(short)', await core.metadata('AAAA')],
        ['metadata(non-base64url)', await core.metadata('!'.repeat(22))],
        ['submit(null capability)', await core.submit(null, handoff.winner)],
        ['submit(no envelope)', await core.submit(handoff.capability, null)],
        ['submit(string envelope)', await core.submit(handoff.capability, 'nope')],
        ['submit(empty envelope)', await core.submit(handoff.capability, {})],
        ['claim(undefined)', core.claim(undefined)],
        ['claim(object id)', core.claim({})],
        ['create(null ttl)', await core.create({ ttlSeconds: null })],
        ['create(string ttl)', await core.create({ ttlSeconds: '60' })],
        ['create(infinite ttl)', await core.create({ ttlSeconds: Number.POSITIVE_INFINITY })],
      ]) {
        record(label, value);
      }
      return answers;
    }

    for (const state of ['pending', 'submitted', 'claimed', 'gone']) {
      it(`refuses them all from ${state} without moving the handoff`, async () => {
        const handoff = await at(state);
        const answers = await battery(handoff);

        for (const [label, answer] of answers) {
          assert.equal(answer.ok, false, `${label} must be refused, not accepted`);
          assert.ok(
            ERROR_VOCABULARY.has(answer.error),
            `${label} answered outside the contract's vocabulary: ${answer.error}`,
          );
          assert.ok(!('plaintext_b64' in answer), `${label} must not carry a payload`);
          assert.ok(!('url' in answer), `${label} must not have minted anything`);
        }
        assert.equal(observe(handoff.id), state, 'not one malformed call may move the machine');
      });
    }

    it('still completes normally after being battered', async () => {
      const handoff = await at('pending');
      await battery(handoff);

      assert.equal(await send(handoff, handoff.winner), 'received');
      const claimed = await broker.control({ op: 'claim', handoff_id: handoff.id });
      assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), SECRET);
    });

    it('does not count a malformed envelope against the AEAD budget', async () => {
      // Shape rejections are free; only a well-formed envelope that fails to
      // decrypt spends one of the three attempts that destroy the handoff.
      const handoff = await at('pending');
      for (let attempt = 0; attempt < 5; attempt += 1) {
        assert.deepEqual(
          await core.submit(handoff.capability, { ...handoff.winner, v: 2 }),
          { ok: false, error: 'unavailable' },
          `attempt ${attempt}`,
        );
      }
      assert.equal(broker.testSnapshot(handoff.id).aeadFailures, 0);
      assert.equal(observe(handoff.id), 'pending');
    });
  });

  // ── property: arbitrary sequences keep the machine's invariants ──────────
  //
  // The matrix pins each cell; this pins that there are no other cells. Random
  // operation sequences are run against real handoffs and, after every single
  // operation, the machine is checked against the invariants that make the
  // deletion guarantees true:
  //
  //   1. the observable state is one of four, and only ever moves along an edge
  //      the machine actually has;
  //   2. key material exists exactly in `pending`, the payload exactly in
  //      `submitted` — so "destroyed" and "claimed" are checkable, not asserted;
  //   3. the payload is delivered at most once, and what comes back is byte-for
  //      -byte what went in;
  //   4. no answer but a successful claim ever carries plaintext, and every
  //      refusal uses the contract's own vocabulary.

  describe('property: random operation sequences', () => {
    const LEGAL_EDGES = {
      pending: new Set(['pending', 'submitted', 'gone']),
      submitted: new Set(['submitted', 'claimed', 'gone']),
      claimed: new Set(['claimed', 'gone']),
      gone: new Set(['gone']),
    };

    /** Deterministic PRNG: a failure here is reproducible from its seed alone. */
    function mulberry32(seed) {
      return function next() {
        seed = (seed + 0x6d2b79f5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      };
    }

    function flipLastByte(base64url) {
      const bytes = Buffer.from(base64url, 'base64url');
      bytes[bytes.length - 1] ^= 0xff;
      return bytes.toString('base64url');
    }

    const OPERATIONS = [
      'metadata',
      'submitWinner',
      'submitWinner',
      'submitOther',
      'submitTampered',
      'submitMalformed',
      'await',
      'claim',
      'claim',
      'claimTooSmall',
      'expire',
    ];

    const SEEDS = [0x5eed_1e55, 0x0c7_0be7, 0x1337_c0de];

    it('never breaks an invariant, over randomised runs from three seeds', async () => {
      // Both payloads are big enough that their response cannot fit the smallest
      // ceiling, so `claimTooSmall` is a real refusal wherever it lands in a
      // sequence — and distinct, so "what came back is what went in" is a real
      // check on *which* envelope won rather than a tautology.
      const plaintext = BIG_SECRET;
      const otherPlaintext = `other-${BIG_SECRET}`;
      // What the sequences actually reached. A generator that stopped producing
      // interesting sequences would still pass every invariant below — vacuously
      // — so the run is held to having visited the whole machine.
      const visited = new Set();

      for (let run = 0; run < 12; run += 1) {
        const seed = SEEDS[run % SEEDS.length];
        const random = mulberry32(seed + run);
        const handoff = await mint({ plaintext, otherPlaintext });
        let state = 'pending';
        let deliveries = 0;
        // Whichever envelope wins the single pending → submitted transition is
        // the only thing a claim may ever return.
        let submitted = null;
        const trail = [];

        for (let step = 0; step < 9; step += 1) {
          const operation = OPERATIONS[Math.floor(random() * OPERATIONS.length)];
          trail.push(operation);
          const where = `run ${run} seed 0x${(seed + run).toString(16)}: ${trail.join(' → ')}`;

          // The two browser-facing seams answer with a word rather than a record,
          // so they are lifted into the same shape as the control ops — including
          // their refusal, which has to be in the contract's vocabulary too.
          const asAnswer = (word, success) =>
            word === success ? { ok: true } : { ok: false, error: word };

          let answer;
          switch (operation) {
            case 'metadata':
              answer = asAnswer(await apply('metadata', handoff), 'ok');
              break;
            case 'submitWinner':
            case 'submitOther': {
              const isWinner = operation === 'submitWinner';
              const envelope = isWinner ? handoff.winner : handoff.other;
              answer = asAnswer(await send(handoff, envelope), 'received');
              if (answer.ok && state === 'pending') {
                submitted = isWinner ? plaintext : otherPlaintext;
              }
              break;
            }
            case 'submitTampered':
              answer = await core.submit(handoff.capability, {
                ...handoff.winner,
                ct: flipLastByte(handoff.winner.ct),
              });
              break;
            case 'submitMalformed':
              answer = await core.submit(handoff.capability, { ...handoff.winner, suite: 'nope' });
              break;
            case 'await':
              answer = await broker.control({ op: 'await', handoff_id: handoff.id, wait_ms: 0 });
              break;
            case 'claim':
              answer = await broker.control({ op: 'claim', handoff_id: handoff.id });
              break;
            case 'claimTooSmall':
              answer = await broker.control({
                op: 'claim',
                handoff_id: handoff.id,
                max_response_bytes: MIN_RESPONSE_BYTES,
              });
              break;
            case 'expire':
              expireEverything();
              answer = { ok: true };
              break;
            default:
              throw new Error(operation);
          }

          // (4) nothing but a claim carries plaintext, and refusals stay in vocabulary.
          if ('plaintext_b64' in answer) {
            assert.ok(operation === 'claim', `${where}: ${operation} returned a payload`);
            deliveries += 1;
            assert.equal(
              Buffer.from(answer.plaintext_b64, 'base64').toString('utf8'),
              submitted,
              `${where}: delivered bytes are not the ones the winning envelope carried`,
            );
          }
          if (answer.ok === false) {
            assert.ok(
              ERROR_VOCABULARY.has(answer.error),
              `${where}: answered '${answer.error}', outside the contract`,
            );
          }
          if (operation === 'claimTooSmall' && answer.error === 'response_too_large') {
            assert.equal(state, 'submitted', `${where}: only a submitted handoff can be too large`);
          }

          // (1) and (2): the machine, after the operation.
          const next = observe(handoff.id);
          visited.add(next);
          assert.ok(
            LEGAL_EDGES[state].has(next),
            `${where}: illegal transition ${state} → ${next}`,
          );
          const snapshot = broker.testSnapshot(handoff.id);
          if (snapshot !== null) {
            assert.equal(
              snapshot.hasPrivateKey,
              next === 'pending',
              `${where}: key material in ${next}`,
            );
            assert.equal(
              snapshot.hasPlaintext,
              next === 'submitted',
              `${where}: payload residency wrong in ${next}`,
            );
            for (const secret of [plaintext, otherPlaintext]) {
              assert.ok(!snapshot.serialized.includes(secret), `${where}: plaintext in the record`);
            }
          }
          state = next;

          // (3) at most one delivery, ever.
          assert.ok(deliveries <= 1, `${where}: the payload was delivered ${deliveries} times`);
        }
      }

      assert.deepEqual(
        [...visited].sort(),
        ['claimed', 'gone', 'pending', 'submitted'],
        'the sequences must reach every state, or the invariants above prove nothing',
      );
      for (const line of logLines) {
        assert.ok(!line.includes(BIG_SECRET.slice(0, 32)), `plaintext leaked into a log: ${line}`);
      }
    });

    it('lets a claim win at most once under concurrent everything', async () => {
      // The same invariant with no ordering at all: every operation issued at
      // once, repeatedly, against a handoff that is live the whole time.
      for (let run = 0; run < 5; run += 1) {
        const handoff = await mint();
        const outcomes = await Promise.all([
          send(handoff, handoff.winner),
          send(handoff, handoff.winner),
          send(handoff, handoff.other),
          broker.control({ op: 'claim', handoff_id: handoff.id }),
          broker.control({ op: 'claim', handoff_id: handoff.id }),
          broker.control({ op: 'await', handoff_id: handoff.id, wait_ms: 200 }),
          apply('metadata', handoff),
        ]);

        const delivered = outcomes.filter((outcome) => outcome?.plaintext_b64 !== undefined);
        assert.ok(delivered.length <= 1, `run ${run}: ${delivered.length} deliveries`);
        for (const claim of delivered) {
          assert.equal(Buffer.from(claim.plaintext_b64, 'base64').toString('utf8'), SECRET);
        }
        assert.ok(['pending', 'submitted', 'claimed'].includes(observe(handoff.id)));
      }
    });
  });
});
