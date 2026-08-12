// The process-wide live-file byte budget — the thing that stops many pending
// file drops from turning the broker into an unbounded memory sink.
//
// The accounting model these tests pin, stated once and enforced everywhere:
//
//   RESERVE  one reservation is taken at `create`, synchronously, before any
//            await, and it is the largest plaintext the drop could ever hold —
//            the whole container ceiling, not what was actually sent, which
//            nobody knows yet. Creation is refused when it would not fit.
//   HOLD     `submit` does NOT release. That is the whole point: at submit the
//            broker really is holding those bytes, so releasing there would let
//            the process exceed the budget it just enforced.
//   RELEASE  exactly once, at the first terminal event for the record — the
//            retirement a claim performs, or `destroy` for expiry, AEAD/container
//            failure budget, and shutdown. A claimed receipt holds no payload,
//            so it holds no reservation either.
//
// Text drops reserve nothing: their cap is `HANDOFF_MAX_PLAINTEXT_BYTES` and the
// budget is deliberately not a shared pool with it.
//
// Nothing here allocates a real 42 MiB payload. A reservation is arithmetic
// performed at create time, which is exactly why it can be tested at the real
// shipped defaults without the memory the defaults describe.
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { fetchMetadata, sealEnvelope, submitEnvelope } from '../src/client/handoff-client.js';
import { DEFAULTS } from '../src/config.js';
import { DEFAULT_FILE_LIMITS, fileContainerCeiling } from '../src/file-container.js';
import {
  claimFileDrop,
  createFileDrop,
  splitHandoffUrl,
  startTestBroker,
} from './helpers/harness.js';

const MIB = 1024 * 1024;
const TTL_SECONDS = 120;
const utf8 = (text) => new TextEncoder().encode(text);
const SAMPLE_FILES = [{ name: 'note.txt', type: 'text/plain', bytes: utf8('a small file') }];

/**
 * One drop reserves the largest plaintext it could ever hold — the whole container
 * ceiling, header and manifest included, not just the file bytes. Reserving only
 * `maxTotalBytes` would let the broker hold up to 6,447 bytes per drop more than
 * it accounted for, which is small but makes the stated invariant ("the
 * reservation *is* the worst case") false. Four of these fit the shipped budget
 * exactly; the fifth must not.
 */
const DEFAULT_DROP_BYTES = fileContainerCeiling(DEFAULT_FILE_LIMITS);
const DEFAULT_BUDGET_BYTES = 4 * DEFAULT_DROP_BYTES;

/**
 * The whole report on a broker holding nothing, spelled out once. Asserted as a
 * *complete* object rather than field by field, so a counter added later has to be
 * accounted for here — which is how `submitLeases`/`leasedBytes` arrived: a
 * universal drop's file lane reserves per submission
 * (docs/UNIVERSAL_DROP_DELIVERY_PLAN.md, U1), and a reservation held by an unread
 * body is the one thing the totals cannot distinguish on their own.
 */
const EMPTY_BUDGET = {
  limitBytes: DEFAULT_BUDGET_BYTES,
  reservedBytes: 0,
  reservedBytesFromRecords: 0,
  availableBytes: DEFAULT_BUDGET_BYTES,
  reservations: 0,
  submitLeases: 0,
  leasedBytes: 0,
  reservationBytes: DEFAULT_DROP_BYTES,
};

function testBroker(overrides = {}) {
  return startTestBroker({ sweepIntervalMs: 3_600_000, ...overrides });
}

describe('the live-file budget', () => {
  let broker;
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
   * The budget as the broker reports it, plus the invariant that makes the counter
   * trustworthy: the running total must equal the sum of what the live records
   * actually hold. `reserved + available === limit` is true by construction —
   * `availableBytes` is computed as the difference — so it proves nothing on its
   * own; the sum-over-records comparison is what catches a missed release, a
   * double release of unequal amounts, or a reservation that drifted from the
   * ceiling it is supposed to bound.
   */
  function budget() {
    const reported = core.fileBudget();
    assert.equal(
      reported.reservedBytesFromRecords,
      reported.reservedBytes,
      'the running counter and the live records must agree, byte for byte',
    );
    assert.equal(
      reported.reservedBytes + reported.availableBytes,
      reported.limitBytes,
      'the counter and the remaining headroom must always add up to the limit',
    );
    assert.ok(reported.reservedBytes >= 0, 'a reservation counter may never go negative');
    return reported;
  }

  it('reports the shipped budget and nothing reserved on a fresh broker', () => {
    assert.deepEqual(budget(), EMPTY_BUDGET);
    assert.equal(DEFAULTS.maxLiveFileBytes, DEFAULT_BUDGET_BYTES, 'and it is the shipped default');
  });

  it('reserves the whole container ceiling, not just the file-byte total', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const reserved = broker.testSnapshot(drop.id).reservedBytes;

    assert.equal(reserved, DEFAULT_DROP_BYTES);
    assert.ok(
      reserved > drop.metadata.max_total_bytes,
      'the header and the manifest ceiling are bytes the broker will really hold',
    );
    assert.equal(reserved - drop.metadata.max_total_bytes, 6447);
  });

  it('reserves one drop`s advertised maximum at create, not what was sent', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });

    assert.equal(budget().reservedBytes, DEFAULT_DROP_BYTES);
    assert.equal(budget().reservations, 1);
    assert.equal(broker.testSnapshot(drop.id).reservedBytes, DEFAULT_DROP_BYTES);

    // A twelve-byte submission does not shrink it: the bytes are resident now.
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');
    assert.equal(
      budget().reservedBytes,
      DEFAULT_DROP_BYTES,
      'submit is a hold, not a release — the broker is holding the payload from here',
    );
  });

  it('reserves the same maximum for a drop that narrowed only its file count', async () => {
    // Narrowing `max_files` says nothing about total bytes: one file may still be
    // the whole 42 MiB, so the reservation is unchanged and deliberately so.
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS, maxFiles: 1 });
    assert.equal(drop.metadata.max_files, 1);
    assert.equal(budget().reservedBytes, DEFAULT_DROP_BYTES);
  });

  it('lets exactly four fully reserved drops live at the shipped defaults', async () => {
    for (let index = 0; index < 4; index += 1) {
      const created = await broker.control({ op: 'create', payload_kind: 'files' });
      assert.equal(created.ok, true, `drop ${index} must fit`);
    }
    assert.equal(budget().availableBytes, 0);

    const refused = await broker.control({ op: 'create', payload_kind: 'files' });
    assert.deepEqual(
      refused,
      { ok: false, error: 'unavailable' },
      'the fifth drop is refused with the uniform body, minting nothing',
    );
    assert.ok(!('url' in refused), 'and no handoff is burned on the way out');
    assert.equal(budget().reservations, 4, 'a refusal reserves nothing');
    assert.ok(
      logLines.some((line) => /live_file_budget/.test(line)),
      'the refusal is logged locally, by reason',
    );
  });

  it('never refuses a text drop for a full file budget', async () => {
    for (let index = 0; index < 4; index += 1) {
      assert.equal((await broker.control({ op: 'create', payload_kind: 'files' })).ok, true);
    }
    assert.equal(budget().availableBytes, 0);

    const text = await broker.control({ op: 'create' });
    assert.equal(text.ok, true, 'the secret path has its own cap and its own memory profile');
    assert.equal(budget().reservedBytes, DEFAULT_BUDGET_BYTES, 'and reserves nothing');
  });

  it('releases the reservation when a pending drop expires', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(budget().reservedBytes, DEFAULT_DROP_BYTES);

    core.sweep(Date.now() + TTL_SECONDS * 1000 + 1);

    assert.equal(broker.testSnapshot(drop.id), null);
    assert.deepEqual(budget(), EMPTY_BUDGET);
  });

  it('releases the reservation when a submitted drop expires', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');
    assert.equal(budget().reservedBytes, DEFAULT_DROP_BYTES);

    core.sweep(Date.now() + TTL_SECONDS * 1000 + 1);
    assert.equal(budget().reservedBytes, 0);
    assert.equal(budget().reservations, 0);
  });

  it('releases the reservation when the container-failure budget destroys the drop', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const { sealBytesEnvelope } = await import('../src/client/handoff-client.js');
    const junk = await sealBytesEnvelope({
      capability: drop.capability,
      metadata: drop.metadata,
      bytes: utf8('not a container'),
      version: 2,
    });

    for (let attempt = 0; attempt < 3; attempt += 1) await drop.send(junk);
    assert.equal(broker.testSnapshot(drop.id), null, 'destroyed');
    assert.equal(budget().reservedBytes, 0);
  });

  it('releases the reservation when the payload is claimed', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');
    assert.equal(budget().reservedBytes, DEFAULT_DROP_BYTES);

    // The real claim path: a framed transfer over the control socket, committed
    // with digests the receiver computed. Nothing else retires a file payload, so
    // nothing else can prove the reservation is given back when one does.
    const claimed = await claimFileDrop(broker, drop.id);
    assert.equal(claimed.ok, true, JSON.stringify(claimed));
    assert.equal(claimed.fileCount, 1);
    assert.equal(claimed.bytes, SAMPLE_FILES[0].bytes.length);
    assert.ok(
      !('plaintext_b64' in claimed),
      'no seam on this path base64s a payload into a line; the bytes came over the stream',
    );

    assert.equal(broker.testSnapshot(drop.id).state, 'claimed');
    assert.equal(broker.testSnapshot(drop.id).hasPlaintext, false);
    assert.equal(
      budget().reservedBytes,
      0,
      'a payload-free receipt holds no bytes, so it holds no reservation',
    );
    assert.equal(broker.testSnapshot(drop.id).reservedBytes, 0);
  });

  it('releases exactly once, however many terminal events follow', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');

    assert.equal((await claimFileDrop(broker, drop.id)).ok, true);
    assert.equal(budget().reservedBytes, 0);
    // A second claim, then expiry, then shutdown: the receipt is destroyed once
    // more but its reservation was already given back.
    assert.equal((await claimFileDrop(broker, drop.id)).ok, false);
    core.sweep(Date.now() + TTL_SECONDS * 1000 + 1);
    core.destroyAll();
    assert.equal(budget().reservedBytes, 0, 'no double release, and no negative counter');
    assert.equal(budget().reservations, 0);
  });

  it('releases every reservation on shutdown, whatever state each drop is in', async () => {
    const pending = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const submitted = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await submitted.send(await submitted.seal(SAMPLE_FILES)), 'received');
    assert.equal(budget().reservedBytes, 2 * DEFAULT_DROP_BYTES);

    core.destroyAll();

    assert.equal(broker.testSnapshot(pending.id), null);
    assert.equal(broker.testSnapshot(submitted.id), null);
    assert.equal(budget().reservedBytes, 0);
    assert.equal(budget().reservations, 0);
  });

  it('frees headroom for the next drop as soon as one lapses', async () => {
    // A short-lived drop plus three full-length ones fills the budget exactly.
    const shortLived = await broker.control({
      op: 'create',
      payload_kind: 'files',
      ttl_seconds: 30,
    });
    assert.equal(shortLived.ok, true);
    for (let index = 0; index < 3; index += 1) {
      const created = await broker.control({
        op: 'create',
        payload_kind: 'files',
        ttl_seconds: TTL_SECONDS,
      });
      assert.equal(created.ok, true, `drop ${index} must fit`);
    }
    assert.deepEqual(await broker.control({ op: 'create', payload_kind: 'files' }), {
      ok: false,
      error: 'unavailable',
    });

    // Sweep at an instant only the short-lived drop has passed.
    core.sweep(Date.now() + 31_000);
    assert.equal(broker.testSnapshot(shortLived.handoff_id), null);
    assert.equal(budget().reservedBytes, 3 * DEFAULT_DROP_BYTES);

    const next = await broker.control({ op: 'create', payload_kind: 'files' });
    assert.equal(next.ok, true, 'the freed slot is immediately usable');
    assert.equal(budget().availableBytes, 0);
  });
});

/** One reservation under the narrowed 1 MiB-per-drop limits used below. */
const NARROW_DROP_BYTES = fileContainerCeiling({
  maxFiles: DEFAULT_FILE_LIMITS.maxFiles,
  maxFileBytes: MIB,
  maxTotalBytes: MIB,
});

describe('the live-file budget under concurrency', () => {
  let broker;
  let core;

  beforeEach(async () => {
    // A small budget so the race is over a handful of slots rather than a
    // rounding error, and narrow-only: every value is at or under the default.
    // The budget is stated as three whole reservations rather than three megabytes,
    // because a reservation is the container ceiling and not the byte total.
    broker = await testBroker({
      sweepIntervalMs: 3_600_000,
      maxFileBytes: MIB,
      maxFileTotalBytes: MIB,
      maxLiveFileBytes: 3 * NARROW_DROP_BYTES,
    });
    core = broker.broker;
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('admits exactly as many concurrent creations as the budget holds', async () => {
    const attempts = await Promise.all(
      Array.from({ length: 24 }, () => broker.control({ op: 'create', payload_kind: 'files' })),
    );

    const admitted = attempts.filter((attempt) => attempt.ok);
    const refused = attempts.filter((attempt) => !attempt.ok);
    assert.equal(admitted.length, 3, 'the budget is enforced before the first await, so it holds');
    for (const attempt of refused) {
      assert.deepEqual(attempt, { ok: false, error: 'unavailable' });
    }
    const reported = core.fileBudget();
    assert.equal(reported.reservedBytes, 3 * NARROW_DROP_BYTES);
    assert.equal(reported.reservedBytesFromRecords, reported.reservedBytes);
    assert.equal(reported.availableBytes, 0);
    assert.equal(reported.reservations, 3);
  });

  it('never exceeds the budget across interleaved creation and expiry', async () => {
    const limit = core.fileBudget().limitBytes;
    for (let round = 0; round < 6; round += 1) {
      const attempts = await Promise.all([
        broker.control({ op: 'create', payload_kind: 'files' }),
        broker.control({ op: 'create', payload_kind: 'files' }),
        broker.control({ op: 'create', payload_kind: 'files' }),
        broker.control({ op: 'create' }),
      ]);
      assert.ok(attempts.some((attempt) => attempt.ok), `round ${round} admitted nothing at all`);
      assert.ok(core.fileBudget().reservedBytes <= limit, `round ${round} overshot the budget`);
      // Lapse everything, then go again: the headroom has to come back or the
      // next round admits nothing.
      core.sweep(Date.now() + 3_600_000);
      assert.equal(core.fileBudget().reservedBytes, 0, `round ${round} leaked a reservation`);
    }
  });

  it('gives a slot back to a waiting creator once a drop is destroyed', async () => {
    for (let index = 0; index < 3; index += 1) {
      assert.equal((await broker.control({ op: 'create', payload_kind: 'files' })).ok, true);
    }
    assert.equal((await broker.control({ op: 'create', payload_kind: 'files' })).ok, false);

    core.destroyAll();
    assert.equal((await broker.control({ op: 'create', payload_kind: 'files' })).ok, true);
    assert.equal(core.fileBudget().reservedBytes, NARROW_DROP_BYTES);
  });

  it('keeps the text path on its own ceiling and behaviour throughout', async () => {
    const created = await broker.control({ op: 'create' });
    const capability = splitHandoffUrl(created.url).capability;
    const metadata = await fetchMetadata({ capability, origin: broker.baseUrl });
    assert.equal(metadata.max_plaintext_bytes, 65536);

    const envelope = await sealEnvelope({ capability, metadata, plaintext: 'still a secret' });
    assert.equal(
      await submitEnvelope({ capability, envelope, origin: broker.baseUrl }),
      'received',
    );
    const claimed = await broker.control({ op: 'claim', handoff_id: created.handoff_id });
    assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), 'still a secret');
    assert.equal(core.fileBudget().reservedBytes, 0);
  });
});
