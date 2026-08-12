// Slice 3 of docs/FILE_TRANSFER_MVP.md — the lossless local transfer protocol.
//
// One property is what this whole file exists for:
//
//   the broker does not retire a byte until the receiver has fully received it,
//   verified it, and said so.
//
// Everything else follows from taking that seriously. A transfer is a *lease* on
// a submitted drop rather than a claim of it, so `submitted → transferring →
// claimed` has a real middle state, and every way the middle can fail —
// disconnect, truncation, a lapsed lease, a digest that does not match, a commit
// from a connection that does not own the lease — has to put the record back to
// `submitted` with its payload intact. Each of those is a test below, and each
// asserts the same two things afterwards: the drop is still `submitted`, and a
// second, honest transfer still gets the right bytes.
//
// The tests drive a real Unix socket end to end: a real broker, the real control
// server, the real `src/file-claim-client.js` receiver reading real length-framed
// binary. Nothing here fakes the transport, because framing, backpressure and
// half-closed connections are exactly what could be wrong.
//
// No test prints or persists file bytes beyond the equality checks that a
// transfer delivered what was submitted, and the filenames used are distinctive
// so a leak into a log line is visible.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { fetchMetadata } from '../src/client/handoff-client.js';
import { controlRequest } from '../src/control-client.js';
import { receiveFileClaim } from '../src/file-claim-client.js';
import { MAX_MANIFEST_BYTES } from '../src/file-container.js';
import { createFileDrop, startTestBroker } from './helpers/harness.js';
import { hostileFileClaim } from './helpers/hostile-receiver.js';

const CONTRACT = JSON.parse(
  await readFile(new URL('../contract/control-protocol.json', import.meta.url), 'utf8'),
);
/** What the broker may say. */
const ERROR_VOCABULARY = new Set(CONTRACT.errors);
/**
 * What a *receiver* may conclude: the broker's vocabulary plus the verdicts only a
 * client can produce. `transfer_indeterminate` is not in `errors` because the broker
 * never sends it — a receiver that read no answer has to be able to say something
 * the socket did not.
 */
const CLIENT_VERDICTS = new Set([...CONTRACT.errors, ...CONTRACT.file_claim.client_verdicts]);

const TTL_SECONDS = 120;
const utf8 = (text) => new TextEncoder().encode(text);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** Distinctive enough that a leak into a log line or a snapshot is unmissable. */
const FILES = [
  { name: 'client-secrets.env', type: 'text/plain', bytes: utf8('PGPASSWORD=example-not-real\n') },
  { name: 'notes.md', type: 'text/markdown', bytes: utf8('# second file\nline two\n') },
];

function testBroker(overrides = {}) {
  return startTestBroker({ sweepIntervalMs: 3_600_000, ...overrides });
}

describe('file claim: the framed transfer', () => {
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
   * A file drop already `submitted`, with its files and the envelope that won to
   * hand — the envelope because "an identical retry is still idempotent" is a rule
   * about *that* envelope, and every `seal` produces a different one.
   */
  async function submitted(files = FILES, options = {}) {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS, ...options });
    const envelope = await drop.seal(files);
    assert.equal(await drop.send(envelope), 'received');
    assert.equal(broker.testSnapshot(drop.id).state, 'submitted');
    return { ...drop, files, envelope };
  }

  /** The production receiver: the options a real one has, and no hooks. */
  const claim = (handoffId, options) =>
    receiveFileClaim(broker.controlSocketPath, handoffId, options);

  /** The misbehaving one (test/helpers/hostile-receiver.js). */
  const hostile = (handoffId, options) =>
    hostileFileClaim(broker.controlSocketPath, handoffId, options);

  const observe = (handoffId) => broker.testSnapshot(handoffId)?.state ?? 'gone';

  /** Everything a refused transfer must leave behind, checked in one place. */
  function stillClaimable(drop, note) {
    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'submitted', `${note}: the drop must be back to submitted`);
    assert.equal(snapshot.hasPlaintext, true, `${note}: the payload must be intact`);
    assert.equal(snapshot.transfer, null, `${note}: the lease must be gone`);
    assert.ok(snapshot.reservedBytes > 0, `${note}: an unclaimed drop still holds its reservation`);
  }

  /** ...and that a later honest receiver really does get the bytes. */
  async function completesLater(drop) {
    const retry = await claim(drop.id);
    assert.equal(retry.ok, true, `a retry after a refusal must succeed: ${JSON.stringify(retry)}`);
    assert.deepEqual(
      retry.files.map((file) => file.bytes),
      drop.files.map((file) => Buffer.from(file.bytes)),
      'and it must get the same bytes the browser submitted',
    );
    assert.equal(observe(drop.id), 'claimed');
  }

  // ── the happy path ───────────────────────────────────────────────────────

  it('pins the contract combined frame indexes, totals and digests to the actual wire', async () => {
    const text = 'wire-private-canary';
    const textBytes = utf8(text);
    const files = [
      { name: 'wire.bin', type: '', bytes: Uint8Array.from([0, 255, 17]) },
      { name: 'empty', type: '', bytes: new Uint8Array() },
    ];
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await (await import('./helpers/harness.js')).sealFileEnvelope({
      capability: drop.capability, metadata: drop.metadata, files, text,
    });
    assert.equal(await drop.send(envelope), 'received');
    const acks = [];
    const result = await hostile(drop.id, { mutateAck: (ack) => { acks.push({ ...ack }); return ack; } });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(acks.map(({ index, size, sha256 }) => ({ index, size, sha256 })), [
      { index: 0, size: textBytes.length, sha256: sha256Hex(textBytes) },
      { index: 1, size: 3, sha256: sha256Hex(files[0].bytes) },
      { index: 2, size: 0, sha256: sha256Hex(files[1].bytes) },
    ]);
    assert.equal(result.bytes, textBytes.length + 3);
    assert.match(CONTRACT.file_claim.conversation[3], /File 0 has frame index 0.*frame index 1/);
    assert.match(CONTRACT.file_claim.conversation[6], /all frames.*private_text.*first/);
    assert.match(CONTRACT.file_claim.digests_are_not_echoed, /sole digest exception is private_text\.sha256/);
  });

  it('streams every file, in order, and retires the drop exactly once', async () => {
    const drop = await submitted();
    const result = await claim(drop.id);

    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.status, 'claimed');
    assert.equal(result.files.length, 2);
    assert.equal(result.bytes, FILES.reduce((sum, file) => sum + file.bytes.length, 0));
    assert.equal(result.totalBytes, result.bytes);

    for (const [index, file] of result.files.entries()) {
      assert.equal(file.name, FILES[index].name, 'names arrive in manifest order');
      assert.equal(file.type, FILES[index].type);
      assert.equal(file.size, FILES[index].bytes.length);
      assert.equal(file.frameLength, file.size, 'the frame length is the advertised size');
      assert.deepEqual(file.bytes, Buffer.from(FILES[index].bytes), 'byte for byte');
      assert.equal(file.sha256, sha256Hex(FILES[index].bytes));
    }

    const receipt = broker.testSnapshot(drop.id);
    assert.equal(receipt.state, 'claimed');
    assert.equal(receipt.hasPlaintext, false, 'the receipt keeps no payload');
    assert.equal(receipt.transfer, null);
    assert.equal(receipt.reservedBytes, 0, 'and holds no reservation');

    const second = await claim(drop.id);
    assert.equal(second.ok, false, 'a second transfer cannot recover the bytes');
    assert.equal(second.error, 'unavailable');
  });

  it('carries an empty file as a zero-length frame', async () => {
    // Empty files are allowed by the MVP; empty submissions are not. A zero-length
    // frame is the one frame whose header is the entire frame.
    const files = [
      { name: 'empty.txt', type: 'text/plain', bytes: new Uint8Array(0) },
      { name: 'after-empty.bin', type: '', bytes: utf8('the frame after an empty one') },
    ];
    const drop = await submitted(files);
    const result = await claim(drop.id);

    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.files[0].size, 0);
    assert.equal(result.files[0].frameLength, 0);
    assert.equal(result.files[0].bytes.length, 0);
    assert.equal(result.files[0].sha256, sha256Hex(new Uint8Array(0)));
    assert.deepEqual(result.files[1].bytes, Buffer.from(files[1].bytes), 'the next frame still aligns');
  });

  it('does not put a digest in the metadata line, so a commit is evidence', async () => {
    // The receiver must compute what it commits. Handing it the manifest's own
    // digests would make the ACK something it could produce without reading a byte.
    const drop = await submitted();
    let seen = null;
    await hostile(drop.id, {
      onMetadata: (metadata) => {
        seen = metadata;
      },
    });

    assert.ok(seen, 'the metadata line arrived');
    assert.equal(typeof seen.transfer_id, 'string');
    assert.match(seen.transfer_id, /^[A-Za-z0-9_-]{22}$/);
    assert.equal(typeof seen.lease_expires_at, 'number');
    for (const entry of seen.files) {
      assert.deepEqual(
        Object.keys(entry).sort(),
        ['name', 'size', 'type'],
        'a name, a size and a hint — nothing else, and no digest',
      );
    }
    assert.ok(!JSON.stringify(seen).includes(sha256Hex(FILES[0].bytes)));
  });

  it('holds the payload through the whole transfer and retires it only at commit', async () => {
    const drop = await submitted();
    const observedDuringStream = [];

    const result = await hostile(drop.id, {
      afterFrames: () => {
        const snapshot = broker.testSnapshot(drop.id);
        observedDuringStream.push(snapshot.state);
        assert.equal(snapshot.hasPlaintext, true, 'every byte is still held when the frames are out');
        // Every frame acked, nothing retired: the state the commit is allowed from,
        // and the only state it is allowed from.
        assert.equal(snapshot.transfer.ackedBytes, snapshot.transfer.totalBytes);
        assert.equal(snapshot.transfer.nextFrame, FILES.length, 'all frames acknowledged');
      },
    });

    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(observedDuringStream, ['transferring'], 'the substate is real and observable');
    assert.equal(observe(drop.id), 'claimed');
  });

  // ── one lease, bound to one connection ───────────────────────────────────

  it('lets only one lease exist at a time, and the holder still completes', async () => {
    const drop = await submitted();
    let refused = null;

    const held = hostile(drop.id, {
      afterFrames: async () => {
        refused = await claim(drop.id);
      },
    });

    const result = await held;
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(refused.ok, false, 'a second lease is refused');
    assert.equal(refused.error, 'transfer_failed');
    assert.equal(refused.reason, 'transfer_in_progress');
    assert.ok(
      ERROR_VOCABULARY.has(refused.error),
      'and refused inside the contract vocabulary',
    );
  });

  it('tells every transfer that met a live lease that the lease is live', async () => {
    // The lease is deliberately *held* while the others try, so there is no
    // ambiguity about what they met: the payload is right there, and `unavailable`
    // is not an acceptable answer to any of them. The contract entitles a client to
    // read `unavailable` as "this drop is over", and slice 4's reconciliation would
    // record a fully claimable payload as spent — the exact manufactured loss the
    // two-phase design exists to prevent.
    const drop = await submitted();
    let losers = [];

    const winner = await hostile(drop.id, {
      afterFrames: async () => {
        losers = await Promise.all(Array.from({ length: 5 }, () => claim(drop.id)));
      },
    });

    assert.equal(winner.ok, true, JSON.stringify(winner));
    assert.equal(losers.length, 5);
    for (const refused of losers) {
      assert.deepEqual(
        { error: refused.error, reason: refused.reason },
        { error: 'transfer_failed', reason: 'transfer_in_progress' },
        `a busy lease must say so: ${JSON.stringify(refused)}`,
      );
      assert.ok(ERROR_VOCABULARY.has(refused.error));
    }
    assert.equal(observe(drop.id), 'claimed');
  });

  it('lets exactly one of many concurrent transfers win', async () => {
    // No ordering imposed at all, so a loser may have met a live lease *or* arrived
    // after the winner retired the payload — the two deterministic tests around this
    // one pin which refusal each of those gets. What this one pins is the invariant
    // that survives any interleaving: one delivery, and never a second.
    const drop = await submitted();
    const outcomes = await Promise.all(Array.from({ length: 6 }, () => claim(drop.id)));

    const delivered = outcomes.filter((outcome) => outcome.ok);
    assert.equal(delivered.length, 1, `exactly one transfer may commit: ${JSON.stringify(outcomes)}`);
    assert.deepEqual(
      delivered[0].files.map((file) => file.bytes),
      FILES.map((file) => Buffer.from(file.bytes)),
    );
    for (const refused of outcomes.filter((outcome) => !outcome.ok)) {
      assert.ok(
        ERROR_VOCABULARY.has(refused.error),
        `outside the vocabulary: ${JSON.stringify(refused)}`,
      );
      assert.ok(!('files' in refused), 'and a refusal never carries bytes');
    }
    assert.equal(observe(drop.id), 'claimed');
  });

  it('answers a transfer that starts inside another one\'s manifest pass the same way', async () => {
    // The deterministic form of the race above, in-process: both begins are started
    // in one tick, so the second necessarily arrives while the first is still
    // hashing the container — a window as long as a SHA-256 pass over 42 MiB. The
    // gate *after* that await has to answer the same way the gate before it does.
    const drop = await submitted();
    const owners = [{}, {}];
    const [first, second] = await Promise.all(
      owners.map((owner) => core.beginFileClaim(drop.id, { owner })),
    );

    const winner = first.ok ? first : second;
    const loser = first.ok ? second : first;
    assert.equal(winner.ok, true, JSON.stringify({ first, second }));
    assert.deepEqual(
      { error: loser.error, reason: loser.reason },
      { error: 'transfer_failed', reason: 'transfer_in_progress' },
      'the post-await gate must not answer `unavailable` about a payload that is right there',
    );
    // ...and the payload the loser was told about is, in fact, right there.
    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'transferring');
    assert.equal(snapshot.hasPlaintext, true);

    core.abandonFileClaim(drop.id, winner.transfer_id, 'test');
    stillClaimable(drop, 'an abandoned in-process lease');
  });

  it('answers a transfer that arrives after the payload is gone with `unavailable`', async () => {
    // The other half of the pair above, sequential so there is no ambiguity: this
    // drop really is over, and `unavailable` is the honest answer.
    const drop = await submitted();
    assert.equal((await claim(drop.id)).ok, true);

    const late = await claim(drop.id);
    assert.equal(late.ok, false);
    assert.equal(late.error, 'unavailable');
    assert.equal(late.reason, undefined, 'nothing about a transfer: there is no payload to transfer');
  });

  it('refuses a commit from a connection that does not hold the lease', async () => {
    // The lease is the connection. A caller that learns the ids — they are not
    // secret — still cannot commit from anywhere else, so there is no lease token
    // to steal and none to forge.
    const drop = await submitted();
    let stolen = null;

    const result = await hostile(drop.id, {
      afterFrames: async ({ metadata }) => {
        stolen = await controlRequest(broker.controlSocketPath, {
          op: 'commit_file_claim',
          handoff_id: drop.id,
          transfer_id: metadata.transfer_id,
          received_bytes: metadata.total_bytes,
          digests: FILES.map((file) => sha256Hex(file.bytes)),
        });
      },
    });

    assert.deepEqual(stolen, { ok: false, error: 'invalid_request' }, 'no lease, no commit');
    assert.equal(result.ok, true, 'and the real holder still commits');
    assert.equal(observe(drop.id), 'claimed');
  });

  it('refuses a commit that names a different transfer', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      mutateCommit: (commit) => ({ ...commit, transfer_id: 'AAAAAAAAAAAAAAAAAAAAAA' }),
    });

    assert.equal(result.ok, false);
    assert.equal(result.error, 'transfer_failed');
    assert.equal(result.reason, 'transfer_id_mismatch');
    stillClaimable(drop, 'a mismatched transfer id');
    await completesLater(drop);
  });

  it('refuses a commit on a connection that never began a transfer', async () => {
    const drop = await submitted();
    const answer = await controlRequest(broker.controlSocketPath, {
      op: 'commit_file_claim',
      handoff_id: drop.id,
      transfer_id: 'AAAAAAAAAAAAAAAAAAAAAA',
      received_bytes: 0,
      digests: [],
    });

    assert.deepEqual(answer, { ok: false, error: 'invalid_request' });
    stillClaimable(drop, 'a commit with no lease');
    await completesLater(drop);
  });

  it('refuses a second begin on a connection that already holds a lease', async () => {
    const drop = await submitted();
    let second = null;

    const result = await hostile(drop.id, {
      afterFrames: async (state, control) => {
        await control.writeLine({ op: 'begin_file_claim', handoff_id: drop.id });
        second = await control.readLine();
      },
    });

    assert.deepEqual(JSON.parse(second), { ok: false, error: 'invalid_request' });
    // The connection is ended by that refusal, so the transfer it was holding is
    // abandoned rather than committed — and the drop survives it.
    assert.equal(result.ok, false, JSON.stringify(result));
    stillClaimable(drop, 'a second begin on one connection');
    await completesLater(drop);
  });

  // ── the failure edges the doc names ──────────────────────────────────────

  it('returns a disconnect mid-stream to submitted, with every byte intact', async () => {
    const drop = await submitted([
      { name: 'big.bin', type: '', bytes: new Uint8Array(512 * 1024).fill(7) },
    ]);

    const result = await hostile(drop.id, {
      // Read a prefix, then hang up: the shape of a receiver whose process died
      // halfway through writing to a spool.
      stopReadingAfterBytes: 4096,
      afterFrames: () => 'abort',
    });
    assert.equal(result.ok, false);

    for (let attempt = 0; attempt < 50 && observe(drop.id) !== 'submitted'; attempt += 1) {
      await sleep(20);
    }
    stillClaimable(drop, 'a disconnect mid-stream');
    await completesLater(drop);
  });

  it('returns a receiver that never commits to submitted', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, { afterFrames: () => 'skip-commit' });
    assert.equal(result.ok, false);
    assert.equal(result.reason, 'not_committed');

    for (let attempt = 0; attempt < 50 && observe(drop.id) !== 'submitted'; attempt += 1) {
      await sleep(20);
    }
    stillClaimable(drop, 'a transfer that was never committed');
    await completesLater(drop);
  });

  it('refuses a truncated transfer at the frame that was truncated', async () => {
    // The whole transfer arrives and the byte count is honest — this receiver lost the
    // tail on its way to disk, which is the failure a size check alone cannot see.
    // With per-frame acks it is caught at the frame rather than at the commit, so the
    // broker stops writing instead of streaming the rest of a transfer that is already
    // doomed, and the refusal names the frame.
    const drop = await submitted([
      { name: 'truncated.bin', type: '', bytes: new Uint8Array(64 * 1024).fill(3) },
      { name: 'never-sent.bin', type: '', bytes: new Uint8Array(64 * 1024).fill(4) },
    ]);

    const result = await hostile(drop.id, { truncateAfterBytes: 1024 });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'transfer_failed');
    assert.equal(result.reason, 'frame_ack_mismatch');
    assert.equal(result.index, 0, 'and it says which frame');
    stillClaimable(drop, 'a truncated write');
    await completesLater(drop);
  });

  it('refuses a commit whose byte count does not match what was sent', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      mutateCommit: (commit) => ({ ...commit, received_bytes: commit.received_bytes - 1 }),
    });

    assert.equal(result.ok, false);
    assert.equal(result.error, 'transfer_failed');
    assert.equal(result.reason, 'size_mismatch');
    stillClaimable(drop, 'a short byte count');
    await completesLater(drop);
  });

  it('refuses a commit whose digests do not match the container', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      mutateCommit: (commit) => ({ ...commit, digests: [commit.digests[0], '0'.repeat(64)] }),
    });

    assert.equal(result.ok, false);
    assert.equal(result.error, 'transfer_failed');
    assert.equal(result.reason, 'digest_mismatch');
    stillClaimable(drop, 'a wrong digest');
    await completesLater(drop);
  });

  it('refuses a commit with the right digests in the wrong order', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      mutateCommit: (commit) => ({ ...commit, digests: [...commit.digests].reverse() }),
    });

    assert.equal(result.ok, false);
    assert.equal(result.reason, 'digest_mismatch', 'order is part of the manifest, not a detail');
    stillClaimable(drop, 'reordered digests');
    await completesLater(drop);
  });

  it('refuses a commit with the wrong number of digests', async () => {
    const drop = await submitted();
    for (const digests of [[], [FILES.map((file) => sha256Hex(file.bytes))[0]]]) {
      const result = await hostile(drop.id, { mutateCommit: (commit) => ({ ...commit, digests }) });
      assert.equal(result.ok, false, JSON.stringify(result));
      assert.equal(result.reason, 'digest_mismatch');
      stillClaimable(drop, `${digests.length} digests`);
    }
    await completesLater(drop);
  });

  // ── turn-taking ──────────────────────────────────────────────────────────
  //
  // The conversation is numbered, and a receiver that speaks out of turn is
  // refused. This is not pedantry about ordering: the broker's own byte counter is
  // fed by socket write completions, which mean the kernel accepted the bytes and
  // *not* that the peer read them. For any payload that fits the socket buffer, a
  // caller that never issues a read can satisfy that counter. Turn-taking is what
  // makes "the commit came after the frames" true rather than merely likely.

  it('refuses a commit pipelined behind the begin, unread', async () => {
    const drop = await submitted();
    // Digests computed from content this caller already knows — the one way a
    // commit can be correct without reading a byte.
    const result = await hostile(drop.id, {
      pipelineCommit: {
        transfer_id: 'AAAAAAAAAAAAAAAAAAAAAA',
        received_bytes: FILES.reduce((sum, file) => sum + file.bytes.length, 0),
        digests: FILES.map((file) => sha256Hex(file.bytes)),
      },
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'invalid_request', 'out of turn is a caller mistake');
    stillClaimable(drop, 'a pipelined commit');
    await completesLater(drop);
  });

  it('refuses a commit that names the real transfer id but precedes the frames', async () => {
    // The transfer id is the real one, read off the metadata line, so the id check
    // cannot be what refuses this. What refuses it is *when* it arrived: before a
    // single frame byte was read, which means the digests describe content this
    // caller already had rather than bytes it received. Without turn-taking this is
    // the case that retires a drop nobody read.
    const body = new Uint8Array(256 * 1024).fill(11);
    const drop = await submitted([{ name: 'unread.bin', type: '', bytes: body }]);

    const result = await hostile(drop.id, {
      commitAfterMetadata: (metadata) => ({
        transfer_id: metadata.transfer_id,
        received_bytes: metadata.total_bytes,
        digests: [sha256Hex(body)],
      }),
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'invalid_request', 'out of turn is a caller mistake');
    stillClaimable(drop, 'a commit written before the frames were read');
    await completesLater(drop);
  });

  it('does not pretend an empty drop can be received wrongly', async () => {
    // Worth stating because the turn-taking rule invites the opposite reading: a drop
    // of only empty files has no bytes to receive, so a receiver that read the
    // manifest has everything there is — names and zero-length content. Committing it
    // after only the metadata loses nothing, and the digests of empty files are a
    // public constant, so there is nothing here for the rule to protect. The rule is
    // about payloads, and this is a drop without one.
    const drop = await submitted([{ name: 'empty-a.txt', type: '', bytes: new Uint8Array(0) }]);
    const result = await claim(drop.id);
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.bytes, 0);
    assert.equal(result.files[0].bytes.length, 0);
  });

  // ── receipt is size-independent ──────────────────────────────────────────
  //
  // The rule this section pins used to hold only above the socket send buffer. The
  // broker's byte counter was fed by write completions, and a write completes when
  // the kernel takes the bytes — so for any payload under ~208 KiB (a tunable, not a
  // constant) every frame "completed" before the receiver read one, and a receiver
  // that committed straight after the metadata was accepted. Above it, refused. A
  // rule that is silently absent for the most common drop sizes is worse than none.
  //
  // The per-frame ack removes the dependence: the broker sends one frame and stops,
  // and no kernel can produce the answer.

  it('refuses a commit before the frames are acked, at every size', async () => {
    // Deliberately spanning the send buffer on this host and every host: two orders
    // of magnitude below it, either side of it, and well above. The point is that the
    // *same* refusal appears at all of them.
    for (const size of [0, 16, 4096, 65_536, 131_072, 196_608, 262_144, 1_048_576]) {
      const body = new Uint8Array(size).fill(0x5a);
      const drop = await submitted([{ name: `sweep-${size}.bin`, type: '', bytes: body }]);

      const result = await hostile(drop.id, {
        // Read the manifest, ack nothing, commit on the strength of a digest this
        // caller computed from content it already had.
        ackFrames: false,
        commitAfterMetadata: (metadata) => ({
          transfer_id: metadata.transfer_id,
          received_bytes: metadata.total_bytes,
          digests: [sha256Hex(body)],
        }),
      });

      assert.equal(result.ok, false, `${size} B was accepted: ${JSON.stringify(result)}`);
      assert.equal(
        result.error,
        'invalid_request',
        `${size} B must be refused the same way as every other size`,
      );
      stillClaimable(drop, `an unacked commit at ${size} B`);
      await completesLater(drop);
    }
  });

  it('requires an ack even for a frame with no bytes in it', async () => {
    // The empty-file drop used to be the one case where committing off the manifest
    // was harmless *and* accepted. It is still harmless — there is nothing to lose —
    // but it is no longer a special case, because a uniform rule is easier to rely on
    // than one with an exception a consumer has to remember.
    const drop = await submitted([
      { name: 'empty-a.txt', type: '', bytes: new Uint8Array(0) },
      { name: 'empty-b.txt', type: '', bytes: new Uint8Array(0) },
    ]);

    const early = await hostile(drop.id, {
      ackFrames: false,
      commitAfterMetadata: (metadata) => ({
        transfer_id: metadata.transfer_id,
        received_bytes: 0,
        digests: [sha256Hex(new Uint8Array(0)), sha256Hex(new Uint8Array(0))],
      }),
    });
    assert.equal(early.ok, false, JSON.stringify(early));
    assert.equal(early.error, 'invalid_request');
    stillClaimable(drop, 'an unacked commit on an all-empty drop');

    // ...and the honest receiver, which acks both empty frames, still gets it.
    const result = await claim(drop.id);
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.bytes, 0);
    assert.equal(result.files.length, 2);
  });

  it('walks the frames one ack at a time, and says which one it is waiting on', async () => {
    const drop = await submitted();
    const seen = [];

    const result = await hostile(drop.id, {
      onFrameAck: (answer) => seen.push([answer.index, answer.next_index]),
    });

    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(
      seen,
      [
        [0, 1],
        [1, null],
      ],
      'each ack names the frame it acked and the one now outstanding; null means commit next',
    );
  });

  it('refuses an ack whose digest is not the manifest\'s', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      mutateAck: (ack) => (ack.index === 0 ? { ...ack, sha256: '0'.repeat(64) } : ack),
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'transfer_failed');
    assert.equal(result.reason, 'frame_ack_mismatch');
    stillClaimable(drop, 'a wrong frame digest');
    await completesLater(drop);
  });

  it('refuses an ack whose size is not the manifest\'s', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      mutateAck: (ack) => ({ ...ack, size: ack.size + 1 }),
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.reason, 'frame_ack_mismatch');
    stillClaimable(drop, 'a wrong frame size');
    await completesLater(drop);
  });

  it('refuses an ack for a frame that is not the outstanding one', async () => {
    const drop = await submitted();
    for (const index of [1, 7, -1]) {
      const result = await hostile(drop.id, {
        mutateAck: (ack) => (ack.index === 0 ? { ...ack, index } : ack),
      });
      assert.equal(result.ok, false, `index ${index}: ${JSON.stringify(result)}`);
      // A negative or absurd index is ill-typed enough to be a caller mistake; an
      // in-range but wrong one is a statement about the transfer. Either way nothing
      // is consumed, which is what the drop's state proves below.
      assert.ok(
        (result.error === 'transfer_failed' && result.reason === 'frame_ack_out_of_order') ||
          result.error === 'invalid_request',
        `index ${index} answered ${JSON.stringify(result)}`,
      );
      stillClaimable(drop, `an ack for frame ${index}`);
    }
    await completesLater(drop);
  });

  it('refuses an ack that names a different transfer', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      mutateAck: (ack) => ({ ...ack, transfer_id: 'AAAAAAAAAAAAAAAAAAAAAA' }),
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'transfer_failed');
    assert.equal(result.reason, 'transfer_id_mismatch');
    stillClaimable(drop, 'an ack for another transfer');
    await completesLater(drop);
  });

  it('refuses an ack when no frame is outstanding', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      // One more ack after the last frame has already been acked, before the commit.
      extraAckBeforeCommit: true,
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'invalid_request');
    stillClaimable(drop, 'an ack with nothing outstanding');
    await completesLater(drop);
  });

  it('rolls back when the receiver disappears while an ack is outstanding', async () => {
    // The broker is parked waiting for an ack it will never get. Nothing was
    // consumed, and the lease must come back without waiting out its deadline.
    const drop = await submitted([
      { name: 'first.bin', type: '', bytes: utf8('frame zero') },
      { name: 'second.bin', type: '', bytes: new Uint8Array(64 * 1024).fill(3) },
    ]);

    const result = await hostile(drop.id, {
      afterFrameRead: ({ index }) => (index === 0 ? 'abort' : undefined),
    });
    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'transfer_failed', 'nothing was committed, so nothing is unknown');

    for (let attempt = 0; attempt < 50 && observe(drop.id) !== 'submitted'; attempt += 1) {
      await sleep(20);
    }
    stillClaimable(drop, 'a receiver that vanished mid-ack');
    await completesLater(drop);
  });

  it('rolls back when the lease lapses while an ack is outstanding', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      leaseMs: 250,
      // Sit on the first frame past the lease deadline instead of acking it.
      afterFrameRead: async ({ index }) => {
        if (index === 0) await sleep(600);
      },
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'transfer_failed');
    stillClaimable(drop, 'a lease that lapsed mid-ack');
    assert.ok(
      logLines.some((line) => line.includes('lease_timeout') && line.includes(`hid=${drop.id}`)),
      'and it is diagnosable locally',
    );
    await completesLater(drop);
  });

  it('accepts the ordinary receiver, which speaks strictly in turn', async () => {
    // The other side of the same rule: enforcing it must cost nothing legitimate.
    const drop = await submitted();
    const result = await claim(drop.id);
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(observe(drop.id), 'claimed');
  });

  it('commits at most once when two commits arrive together', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, { commitTimes: 2 });

    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(
      result.answers.filter((answer) => answer.ok).length,
      1,
      'exactly one commit may be accepted',
    );
    assert.equal(observe(drop.id), 'claimed');
    assert.equal(broker.testSnapshot(drop.id).hasPlaintext, false);
  });

  // ── the one outcome nobody may guess ─────────────────────────────────────

  it('reports an unread commit answer as indeterminate, not as a failure', async () => {
    // The commit is one-shot, non-idempotent and not requeryable. A receiver that
    // wrote one and read no answer therefore knows *nothing* about what the broker
    // did — and here the broker did accept it. Reporting `transfer_failed` would
    // assert the payload survived, which is false; reporting success would assert it
    // was verified, which the receiver cannot know either.
    const drop = await submitted();
    const result = await hostile(drop.id, {
      // Hang up once the broker has demonstrably accepted the commit, with its
      // answer sitting unread in the socket. That is the dangerous case rather than
      // a merely possible one: the payload is gone and the receiver was told nothing.
      afterCommit: async () => {
        for (let attempt = 0; attempt < 200 && observe(drop.id) !== 'claimed'; attempt += 1) {
          await sleep(10);
        }
        return 'abort';
      },
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'transfer_indeterminate');
    assert.equal(result.reason, 'commit_answer_lost');
    assert.ok(CLIENT_VERDICTS.has(result.error), 'and it is a verdict the contract names');
    assert.ok(!ERROR_VOCABULARY.has(result.error), 'but not one the broker ever sends');

    // The broker really did retire it, which is exactly why the verdict must not
    // claim otherwise.
    assert.equal(observe(drop.id), 'claimed');
    assert.equal(broker.testSnapshot(drop.id).hasPlaintext, false);
  });

  it('keeps `transfer_failed` for failures that provably preceded the commit', async () => {
    // The distinction has to cut both ways, or it buys nothing: an abort *before*
    // the commit is a real refusal, and the payload really is still there.
    const drop = await submitted();
    const result = await hostile(drop.id, { afterFrames: () => 'abort' });

    assert.equal(result.error, 'transfer_failed', JSON.stringify(result));
    for (let attempt = 0; attempt < 50 && observe(drop.id) !== 'submitted'; attempt += 1) {
      await sleep(20);
    }
    stillClaimable(drop, 'an abort before the commit');
    await completesLater(drop);
  });

  // ── the bounded lease ────────────────────────────────────────────────────

  it('never advertises a lease deadline past the handoff it is on', async () => {
    // `lease_expires_at` is documented as the moment the frames and the commit must
    // both have landed by. A deadline past the handoff's own expiry is one the
    // broker cannot honour: it would stream up to 42 MiB and then destroy the
    // payload under a receiver that did everything right.
    const drop = await submitted(FILES, { ttlSeconds: 3 });
    let leaseExpiresAt = null;
    await hostile(drop.id, {
      onMetadata: (metadata) => {
        leaseExpiresAt = metadata.lease_expires_at;
        return 'abort';
      },
    });

    assert.ok(leaseExpiresAt !== null, 'the lease was granted');
    assert.ok(
      leaseExpiresAt <= drop.expiresAt,
      `lease overshoots the handoff by ${leaseExpiresAt - drop.expiresAt}ms`,
    );
    assert.ok(
      leaseExpiresAt > Date.now(),
      'and it is still a usable deadline rather than one already past',
    );
    assert.ok(
      broker.config.fileClaimLeaseMs > 3_000,
      'the configured lease is longer than this TTL, so the clamp is what produced that',
    );
  });

  it('refuses a begin before streaming when too little of the TTL is left', async () => {
    // An honest refusal now beats a full transfer that cannot be committed. The
    // drop is not consumed and not destroyed — it simply lapses on its own clock.
    const drop = await submitted([
      { name: 'large.bin', type: '', bytes: new Uint8Array(256 * 1024).fill(9) },
    ]);
    // Wind the handoff's deadline to just inside the minimum useful remainder.
    core.testSetExpiry(drop.id, Date.now() + 200);

    const result = await claim(drop.id);
    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'transfer_failed');
    assert.equal(result.reason, 'handoff_expiring');
    assert.equal(result.phase, 'begin', 'refused before a single frame moved');

    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'submitted', 'not consumed, and not destroyed either');
    assert.equal(snapshot.transfer, null, 'and no lease was taken on the way out');
  });

  it('returns a lapsed lease to submitted and closes the connection under it', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      leaseMs: 250,
      // Sit on the lease past its deadline, then try to commit anyway.
      afterFrames: () => sleep(600),
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.error, 'transfer_failed');
    stillClaimable(drop, 'a lapsed lease');
    assert.ok(
      logLines.some((line) => line.includes('lease_timeout') && line.includes(`hid=${drop.id}`)),
      'the timeout is diagnosable locally, by id and reason',
    );
    await completesLater(drop);
  });

  it('lets a caller narrow the lease and never widen it', async () => {
    const drop = await submitted();
    const configured = broker.config.fileClaimLeaseMs;
    let narrowed = null;
    let widened = null;

    await hostile(drop.id, {
      leaseMs: 5_000,
      onMetadata: (metadata) => {
        narrowed = metadata.lease_expires_at - Date.now();
      },
      afterFrames: () => 'abort',
    });
    for (let attempt = 0; attempt < 50 && observe(drop.id) !== 'submitted'; attempt += 1) {
      await sleep(20);
    }

    await hostile(drop.id, {
      leaseMs: configured * 10,
      onMetadata: (metadata) => {
        widened = metadata.lease_expires_at - Date.now();
      },
      afterFrames: () => 'abort',
    });

    assert.ok(narrowed <= 5_000 + 50, `a narrowed lease is honoured: ${narrowed}ms`);
    assert.ok(widened <= configured + 50, `a widened lease is clamped: ${widened}ms`);
  });

  it('refuses an unusable lease_ms without taking a lease', async () => {
    const drop = await submitted();
    for (const lease_ms of [0, -1, 1.5, '5000', null, {}]) {
      const answer = await controlRequest(broker.controlSocketPath, {
        op: 'begin_file_claim',
        handoff_id: drop.id,
        lease_ms,
      });
      assert.deepEqual(
        answer,
        { ok: false, error: 'invalid_request' },
        `lease_ms ${JSON.stringify(lease_ms)} must be refused`,
      );
      assert.equal(broker.testSnapshot(drop.id).transfer, null, 'and take no lease on the way out');
    }
    stillClaimable(drop, 'an unusable lease_ms');
    await completesLater(drop);
  });

  // ── the cost of retrying ─────────────────────────────────────────────────

  it('lets a transient failure be retried, and stops an unbounded retry loop', async () => {
    // Every granted lease costs a full SHA-256 pass over the container, and
    // `abandonFileClaim` deliberately restores the drop for free — so without a
    // bound, one caller can buy that pass for the whole TTL. The bound has to leave
    // room for the retries a real receiver needs (a crash, a lapsed lease) while
    // refusing a loop.
    const drop = await submitted();
    const budget = broker.config.maxTransferAttempts;
    assert.ok(budget >= 4, 'a transient failure must be retriable more than once');

    for (let attempt = 0; attempt < budget - 1; attempt += 1) {
      const abandoned = await hostile(drop.id, { afterFrames: () => 'abort' });
      assert.equal(abandoned.error, 'transfer_failed', `attempt ${attempt}`);
      for (let wait = 0; wait < 50 && observe(drop.id) !== 'submitted'; wait += 1) await sleep(20);
      stillClaimable(drop, `attempt ${attempt}`);
    }

    // The last attempt in the budget still works — the bound refuses the attempt
    // *after* it, not the one that reaches it.
    const lastGood = await claim(drop.id);
    assert.equal(lastGood.ok, true, `the budgeted attempt must succeed: ${JSON.stringify(lastGood)}`);
    assert.deepEqual(
      lastGood.files.map((file) => file.bytes),
      FILES.map((file) => Buffer.from(file.bytes)),
    );
  });

  it('refuses a further begin once the attempt budget is spent, without destroying the payload', async () => {
    const drop = await submitted();
    const budget = broker.config.maxTransferAttempts;

    for (let attempt = 0; attempt < budget; attempt += 1) {
      const abandoned = await hostile(drop.id, { afterFrames: () => 'abort' });
      assert.equal(abandoned.error, 'transfer_failed', `attempt ${attempt}`);
      for (let wait = 0; wait < 50 && observe(drop.id) !== 'submitted'; wait += 1) await sleep(20);
    }

    const refused = await claim(drop.id);
    assert.equal(refused.ok, false, JSON.stringify(refused));
    assert.equal(refused.error, 'transfer_failed');
    assert.equal(refused.reason, 'attempt_budget_spent');

    // Not destroyed: a receiver that crashed eight times is a broken receiver, not a
    // reason to throw away the user's files. The drop lapses on its own TTL, and an
    // operator can still see it.
    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'submitted');
    assert.equal(snapshot.hasPlaintext, true);
    assert.ok(
      logLines.some((line) => line.includes('attempt_budget_spent')),
      'and the refusal is diagnosable locally',
    );
  });

  // ── expiry and shutdown under a live transfer ───────────────────────────

  it('destroys a transferring drop when its TTL lapses, and the commit fails', async () => {
    const drop = await submitted();
    const result = await hostile(drop.id, {
      afterFrames: async () => {
        core.sweep(Date.now() + TTL_SECONDS * 1000 + 1);
        await sleep(50);
      },
    });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(observe(drop.id), 'gone', 'expiry reaches a leased record like any other');
    assert.equal(broker.broker.fileBudget().reservedBytes, 0, 'and gives the reservation back');
  });

  it('destroys a transferring drop on shutdown', async () => {
    const instance = await testBroker();
    try {
      const drop = await createFileDrop(instance, { ttlSeconds: TTL_SECONDS });
      assert.equal(await drop.send(await drop.seal(FILES)), 'received');

      const result = await hostileFileClaim(instance.controlSocketPath, drop.id, {
        afterFrames: async () => {
          instance.broker.destroyAll();
          await sleep(50);
        },
      });

      assert.equal(result.ok, false, JSON.stringify(result));
      assert.equal(instance.testSnapshot(drop.id), null);
      assert.equal(instance.broker.fileBudget().reservedBytes, 0);
    } finally {
      await instance.stop();
    }
  });

  // ── what the other seams say about a transferring drop ──────────────────

  it('keeps every other seam answering as it does for a submitted drop', async () => {
    const drop = await submitted();
    await hostile(drop.id, {
      afterFrames: async () => {
        const waited = await broker.control({ op: 'await', handoff_id: drop.id, wait_ms: 50 });
        assert.deepEqual(
          waited,
          { ok: true, handoff_id: drop.id, status: 'submitted' },
          'a transfer in flight is still news of a submission, not a new status',
        );

        assert.deepEqual(
          await broker.control({ op: 'claim', handoff_id: drop.id }),
          { ok: false, error: 'unavailable' },
          'and the text claim seam still refuses a container',
        );

        assert.equal(
          await fetchMetadata({ capability: drop.capability, origin: broker.baseUrl }),
          null,
          'the form stays dead: a transfer in flight does not reopen it',
        );
        // The MVP's compatibility rule: an identical browser retry keeps its
        // receipt, mid-transfer like anywhere else. A mobile client that lost the
        // response must not be told its upload failed while it is being collected.
        assert.equal(await drop.send(drop.envelope), 'received', 'the winning envelope');
        assert.equal(await drop.send(await drop.seal(FILES)), 'unavailable', 'a fresh envelope');
        assert.equal(broker.broker.submitBodyCeiling(drop.capability), broker.config.maxBodyBytes);
      },
    });
    assert.equal(observe(drop.id), 'claimed');
  });

  it('refuses a begin for anything that is not a submitted file drop', async () => {
    const pendingFiles = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const text = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });

    for (const [note, handoffId] of [
      ['a pending file drop', pendingFiles.id],
      ['a text drop', text.handoff_id],
      ['a handoff that never existed', 'abcdefghijklmnopqrstuv'],
    ]) {
      const result = await claim(handoffId);
      assert.equal(result.ok, false, note);
      assert.equal(result.error, 'unavailable', note);
    }
    assert.equal(broker.testSnapshot(pendingFiles.id).state, 'pending', 'and nothing moved');
    assert.equal(broker.testSnapshot(text.handoff_id).state, 'pending');
  });

  it('refuses a malformed begin without moving anything', async () => {
    const drop = await submitted();
    for (const request of [
      { op: 'begin_file_claim' },
      { op: 'begin_file_claim', handoff_id: 42 },
      { op: 'begin_file_claim', handoff_id: null },
    ]) {
      assert.deepEqual(await controlRequest(broker.controlSocketPath, request), {
        ok: false,
        error: 'invalid_request',
      });
    }
    for (const request of [
      { op: 'commit_file_claim' },
      { op: 'commit_file_claim', handoff_id: drop.id },
      { op: 'commit_file_claim', handoff_id: drop.id, transfer_id: 'x' },
    ]) {
      assert.deepEqual(await controlRequest(broker.controlSocketPath, request), {
        ok: false,
        error: 'invalid_request',
      });
    }
    stillClaimable(drop, 'a malformed begin or commit');
    await completesLater(drop);
  });

  // ── the things a 42 MiB limit makes non-negotiable ──────────────────────

  it('hands the streamer views into the container rather than copies of it', async () => {
    // Copying here would mean a second 42 MiB allocation per claim, on top of the
    // one the live-file budget already accounts for. The views are the reason the
    // budget's number means what it says.
    const drop = await submitted();
    const begun = await core.beginFileClaim(drop.id, { owner: {} });
    try {
      assert.equal(begun.ok, true, JSON.stringify(begun));
      assert.equal(begun.files.length, 2);
      assert.equal(
        begun.files[0].bytes.buffer,
        begun.files[1].bytes.buffer,
        'every file is a window onto the one container',
      );
      assert.ok(
        begun.files[0].bytes.buffer.byteLength > begun.total_bytes,
        'and that container is larger than the payload, because it has a header and a manifest',
      );
    } finally {
      core.abandonFileClaim(drop.id, begun.transfer_id, 'test');
    }
    stillClaimable(drop, 'an abandoned in-process lease');
  });

  it('streams a multi-megabyte payload byte-exactly, backpressure and all', async () => {
    // Large enough to cross the socket's write buffer many times over, so the
    // drain path and the frame boundaries are really exercised — and small enough
    // that the suite is not sealing 42 MiB of HPKE to prove it.
    const first = new Uint8Array(3 * 1024 * 1024);
    for (let index = 0; index < first.length; index += 1) first[index] = index % 251;
    const second = new Uint8Array(1024 * 1024).fill(0xa7);
    const drop = await submitted([
      { name: 'large-a.bin', type: 'application/octet-stream', bytes: first },
      { name: 'large-b.bin', type: 'application/octet-stream', bytes: second },
    ]);

    const result = await claim(drop.id);
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.bytes, first.length + second.length);
    assert.equal(result.files[0].sha256, sha256Hex(first));
    assert.equal(result.files[1].sha256, sha256Hex(second));
    assert.deepEqual(result.files[0].bytes, Buffer.from(first));
  });

  it('streams every byte to a per-chunk consumer that retains nothing', async () => {
    // The shape slice 4 needs, and the one a whole-file buffer would quietly break:
    // `collectBytes: false` keeps no payload anywhere, and `onChunk` still sees every
    // byte. A receiver whose streaming path delivered nothing while its digests came
    // out right would be handed a `claimed` verdict for files it never got.
    const big = new Uint8Array(2 * 1024 * 1024);
    for (let index = 0; index < big.length; index += 1) big[index] = (index * 7) % 251;
    const drop = await submitted([
      { name: 'streamed.bin', type: '', bytes: big },
      { name: 'small.txt', type: 'text/plain', bytes: utf8('and one small one') },
    ]);

    const digests = [createHash('sha256'), createHash('sha256')];
    const counts = [0, 0];
    const chunks = [0, 0];
    const result = await claim(drop.id, {
      collectBytes: false,
      onChunk: (chunk, { index }) => {
        digests[index].update(chunk);
        counts[index] += chunk.length;
        chunks[index] += 1;
      },
    });

    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(counts, [big.length, 'and one small one'.length], 'every byte reached the sink');
    assert.equal(digests[0].digest('hex'), sha256Hex(big));
    assert.equal(digests[1].digest('hex'), sha256Hex(utf8('and one small one')));
    assert.ok(chunks[0] > 1, `a 2 MiB file must arrive in pieces, not one buffer (${chunks[0]})`);
    for (const file of result.files) {
      assert.ok(!('bytes' in file), 'and nothing was retained after the callback');
    }
  });

  it('rejects every malformed private descriptor before reading a frame or sending an ACK', async () => {
    const digest = 'a'.repeat(64);
    const malformed = [
      { size: 65_537, sha256: digest },
      { size: -1, sha256: digest },
      { size: true, sha256: digest },
      { size: 1.5, sha256: digest },
      { size: '1', sha256: digest },
      { size: 1 },
      { sha256: digest },
      { size: 1, sha256: digest, extra: true },
      { size: 1, sha256: 'A'.repeat(64) },
      { size: 1, sha256: 'g'.repeat(64) },
      { size: 1, sha256: 'a'.repeat(63) },
    ];

    for (const privateText of malformed) {
      let bytesAfterBegin = 0;
      const server = createServer((socket) => {
        socket.once('data', () => {
          socket.on('data', (chunk) => { bytesAfterBegin += chunk.length; });
          socket.write(`${JSON.stringify({
            ok: true,
            transfer_id: 'AAAAAAAAAAAAAAAAAAAAAA',
            total_bytes: 1,
            private_text: privateText,
            files: [],
          })}\n`);
        });
      });
      const socketPath = join(await mkdtemp(join(tmpdir(), 'handoff-bad-private-')), 'control.sock');
      await new Promise((resolve) => server.listen(socketPath, resolve));
      try {
        const result = await receiveFileClaim(socketPath, 'abcdefghijklmnopqrstuv', { timeoutMs: 500 });
        assert.deepEqual(
          { ok: result.ok, reason: result.reason, phase: result.phase },
          { ok: false, reason: 'malformed_metadata', phase: 'begin' },
        );
        await sleep(5);
        assert.equal(bytesAfterBegin, 0, `no frame read/ACK for ${JSON.stringify(privateText)}`);
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
    }
  });

  it('refuses a frame whose length disagrees with the advertised size', async () => {
    // Unreachable against this broker, which writes `file.size` as the frame length.
    // It is checked because this client is the reference receiver for a documented
    // wire format: against a broker that mis-frames, reading the framed length would
    // mis-attribute bytes to the next file and surface as a `size_mismatch` pointing
    // at the receiver. The Python receiver refuses on the same terms.
    const server = createServer((socket) => {
      socket.once('data', () => {
        socket.write(
          `${JSON.stringify({
            ok: true,
            handoff_id: 'abcdefghijklmnopqrstuv',
            transfer_id: 'AAAAAAAAAAAAAAAAAAAAAA',
            lease_expires_at: Date.now() + 60_000,
            total_bytes: 8,
            files: [{ name: 'lie.bin', size: 8, type: '' }],
          })}\n`,
        );
        const header = Buffer.allocUnsafe(4);
        header.writeUInt32BE(4, 0); // says 4, the manifest said 8
        socket.write(Buffer.concat([header, Buffer.alloc(4, 1)]));
      });
    });
    const socketPath = join(await mkdtemp(join(tmpdir(), 'handoff-misframe-')), 'control.sock');
    await new Promise((resolve) => server.listen(socketPath, resolve));

    try {
      const result = await receiveFileClaim(socketPath, 'abcdefghijklmnopqrstuv', {
        timeoutMs: 2_000,
      });
      assert.equal(result.ok, false, JSON.stringify(result));
      assert.equal(result.error, 'transfer_failed');
      assert.equal(result.reason, 'frame_length_mismatch');
      assert.equal(result.index, 0, 'and it says which frame');
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it('keeps the hostile hooks out of the production receiver', async () => {
    // A `mutateCommit` that can rewrite the digests is a forge-a-commit primitive.
    // It exists (test/helpers/hostile-receiver.js drives every refusal test in this
    // file) but must not be reachable through the module slice 4 imports.
    const source = await readFile(new URL('../src/file-claim-client.js', import.meta.url), 'utf8');
    for (const hook of [
      'mutateCommit',
      'commitTimes',
      'afterFrames',
      'afterCommit',
      'stopReadingAfterBytes',
      'truncateAfterBytes',
      'pipelineCommit',
      'commitAfterMetadata',
      'mutateAck',
      'ackFrames',
      'extraAckBeforeCommit',
      'afterFrameRead',
    ]) {
      assert.ok(!source.includes(`${hook} `), `${hook} must not be a production option`);
    }

    // And passing one is inert rather than honoured: an unknown option cannot
    // become a way to rewrite an ACK.
    const drop = await submitted();
    const result = await claim(drop.id, {
      mutateCommit: () => ({ op: 'commit_file_claim', digests: ['0'.repeat(64)] }),
    });
    assert.equal(result.ok, true, 'the honest commit went out regardless');
    assert.equal(observe(drop.id), 'claimed');
  });

  it('keeps the metadata line inside the response ceiling a client must buffer', async () => {
    // The one line `begin_file_claim` writes carries the same names the manifest
    // ceiling already bounds, so it cannot approach `max_response_bytes` — which is
    // why this op has no `max_response_bytes` field of its own. Symbolic, because
    // the point is the arithmetic rather than one sample.
    const worstLine =
      MAX_MANIFEST_BYTES + Buffer.byteLength(JSON.stringify({
        ok: true,
        handoff_id: 'x'.repeat(22),
        transfer_id: 'x'.repeat(22),
        lease_expires_at: Number.MAX_SAFE_INTEGER,
        total_bytes: Number.MAX_SAFE_INTEGER,
        files: [],
      })) + 1;
    assert.ok(
      worstLine < CONTRACT.transport.max_response_bytes,
      `a maximal metadata line is ${worstLine} bytes`,
    );
  });

  it('never puts a filename or a digest in a log line', async () => {
    const drop = await submitted();
    // Every refusal path that logs: a bad frame ack, an ack out of order, an early
    // commit, and a commit whose digests do not match. Each one has a number or a
    // reason in its line and nothing else.
    await hostile(drop.id, { mutateAck: (ack) => ({ ...ack, sha256: '0'.repeat(64) }) });
    await hostile(drop.id, { mutateAck: (ack) => (ack.index === 0 ? { ...ack, index: 1 } : ack) });
    await hostile(drop.id, {
      ackFrames: false,
      commitAfterMetadata: (metadata) => ({
        transfer_id: metadata.transfer_id,
        received_bytes: metadata.total_bytes,
        digests: FILES.map((file) => sha256Hex(file.bytes)),
      }),
    });
    await hostile(drop.id, { mutateCommit: (commit) => ({ ...commit, digests: ['0'.repeat(64)] }) });
    await claim(drop.id);

    for (const line of logLines) {
      for (const file of FILES) {
        assert.ok(!line.includes(file.name), `a filename leaked into a log line: ${line}`);
        assert.ok(!line.includes(sha256Hex(file.bytes)), `a digest leaked into a log line: ${line}`);
      }
      assert.ok(!line.includes(drop.capability), `the capability leaked: ${line}`);
    }
    for (const reason of [
      'frame_ack_mismatch',
      'frame_ack_out_of_order',
      'commit_out_of_turn',
      'digest_mismatch',
    ]) {
      assert.ok(
        logLines.some((line) => line.includes(reason)),
        `${reason} must still be diagnosable locally`,
      );
    }
  });
});
