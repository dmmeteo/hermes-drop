// The transport consequences of a 42 MiB limit.
//
// Slice 2 gave the broker a payload kind; that widened one number on the public
// submit path from 128 KiB to 56 MiB, and every property that used to be safe
// because the number was small has to be re-established at the new size:
//
//   - at most ONE widened body per pending file drop is ever buffered, admitted
//     before the first byte is read and given back however the request ends —
//     because `broker.submit`'s de-duplication only engages *after* the whole
//     body is already in memory, so it cannot bound buffering at all;
//   - the allowance for reading past the ceiling purely to answer politely is
//     additive, not a multiple of a ceiling that grew 448x;
//   - a maximal drop is actually completable on an ordinary upstream, which the
//     15-second default request deadline makes impossible, so the deadline is
//     extended for exactly the request that needs it and for nothing else;
//   - a request that runs out of time answers with the *uniform* unavailable
//     rather than Node's 408, so the public contract survives the new size;
//   - the widened ceiling collapses back to the text ceiling the instant the drop
//     stops being pending, for every way it can stop.
//
// These are transport properties, so they are tested over real HTTP against a
// real broker, with bodies dribbled through `node:http` rather than `fetch` so a
// test can control the timing of a partial upload.
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { fetchMetadata, sealEnvelope } from '../src/client/handoff-client.js';
import { DEFAULTS } from '../src/config.js';
import {
  CONTAINER_HEADER_BYTES,
  DEFAULT_FILE_LIMITS,
  MAX_MANIFEST_BYTES,
  fileContainerCeiling,
} from '../src/file-container.js';
import { AEAD_TAG_BYTES } from '../src/hpke-suite.js';
import {
  claimFileDrop,
  createFileDrop,
  splitHandoffUrl,
  startTestBroker,
} from './helpers/harness.js';

const TTL_SECONDS = 120;
const utf8 = (text) => new TextEncoder().encode(text);
const SAMPLE_FILES = [{ name: 'note.txt', type: 'text/plain', bytes: utf8('a small file') }];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function testBroker(overrides = {}) {
  return startTestBroker({ sweepIntervalMs: 3_600_000, ...overrides });
}

/**
 * POSTs a body in `chunks` pieces, `gapMs` apart, over a raw socket — the shape
 * of a real phone upload, and the only way to observe a deadline that is supposed
 * to fire mid-body.
 */
function dribble({ origin, path, capability, body, chunks = 4, gapMs = 120 }) {
  const url = new URL(`${origin}${path}`);
  const payload = Buffer.from(body);
  const size = Math.ceil(payload.length / chunks);

  return new Promise((resolve) => {
    const clientRequest = httpRequest(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
          'x-handoff-capability': capability,
          'content-type': 'application/json',
          'content-length': payload.length,
        },
      },
      (response) => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          text += chunk;
        });
        response.on('end', () => resolve({ status: response.statusCode, body: text }));
      },
    );
    clientRequest.on('error', (error) => resolve({ status: null, body: '', error: error.code }));

    (async () => {
      for (let offset = 0; offset < payload.length; offset += size) {
        if (clientRequest.destroyed || clientRequest.writableEnded) return;
        clientRequest.write(payload.subarray(offset, offset + size));
        await sleep(gapMs);
      }
      if (!clientRequest.destroyed) clientRequest.end();
    })();
  });
}

describe('one widened body per file drop', () => {
  let broker;
  let logLines;

  beforeEach(async () => {
    logLines = [];
    const capture = (level) => (message) => logLines.push(`${level} ${message}`);
    broker = await testBroker({
      logger: { info: capture('info'), warn: capture('warn'), error: capture('error') },
    });
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('admits exactly one concurrent submission and refuses the rest uniformly', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelopes = await Promise.all(
      ['a', 'b', 'c', 'd', 'e', 'f'].map((tag) =>
        drop.seal([{ name: `${tag}.txt`, type: '', bytes: utf8(tag.repeat(64)) }]),
      ),
    );

    const responses = await Promise.all(
      envelopes.map((envelope) =>
        fetch(`${broker.baseUrl}/api/submit`, {
          method: 'POST',
          headers: {
            'x-handoff-capability': drop.capability,
            'content-type': 'application/json',
          },
          body: JSON.stringify(envelope),
        }).then(async (response) => ({ status: response.status, body: await response.text() })),
      ),
    );

    const admitted = responses.filter((response) => response.status === 200);
    assert.equal(admitted.length, 1, 'exactly one body may be buffered at a time');
    for (const refused of responses.filter((response) => response.status !== 200)) {
      assert.equal(refused.status, 404, 'a busy drop is refused, not queued');
      assert.equal(refused.body, '{"status":"unavailable"}', 'and refused uniformly');
    }
    assert.equal(broker.testSnapshot(drop.id).state, 'submitted');
    assert.equal(broker.testSnapshot(drop.id).bodySlotBusy, false, 'the slot is given back');
  });

  it('gives the slot back after a completed submission, refusal and all', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });

    // A refused submission (a malformed envelope) must not strand the slot.
    assert.equal(await drop.send({ nonsense: true }), 'unavailable');
    assert.equal(broker.testSnapshot(drop.id).bodySlotBusy, false);

    // ...and the drop is still submittable.
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');
  });

  it('gives the slot back when the client aborts mid-body', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.seal(SAMPLE_FILES);
    const body = Buffer.from(JSON.stringify(envelope));

    // Declare a full body, send half, then destroy the socket.
    await new Promise((resolve) => {
      const url = new URL(`${broker.baseUrl}/api/submit`);
      const clientRequest = httpRequest({
        hostname: url.hostname,
        port: url.port,
        path: '/api/submit',
        method: 'POST',
        headers: {
          'x-handoff-capability': drop.capability,
          'content-type': 'application/json',
          'content-length': body.length,
        },
      });
      clientRequest.on('error', resolve);
      clientRequest.write(body.subarray(0, Math.floor(body.length / 2)));
      setTimeout(() => {
        clientRequest.destroy();
        resolve();
      }, 120);
    });

    // The abort has to reach the server before the slot can be observed free.
    for (let attempt = 0; attempt < 50; attempt += 1) {
      if (broker.testSnapshot(drop.id).bodySlotBusy === false) break;
      await sleep(20);
    }
    assert.equal(
      broker.testSnapshot(drop.id).bodySlotBusy,
      false,
      'an abandoned upload must not lock the drop out for the rest of its TTL',
    );
    assert.equal(await drop.send(envelope), 'received', 'and the drop is still submittable');
  });

  it('never gates a text drop, however many submissions arrive at once', async () => {
    // The text ceiling was always small enough to buffer freely, and the seam-3
    // concurrency behaviour is load-bearing: the losers must reach the broker and
    // be told `unavailable` by it, not be turned away by an admission gate.
    const created = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    const capability = splitHandoffUrl(created.url).capability;
    const metadata = await fetchMetadata({ capability, origin: broker.baseUrl });
    const envelopes = await Promise.all(
      ['a', 'b', 'c', 'd', 'e', 'f'].map((text) =>
        sealEnvelope({ capability, metadata, plaintext: text }),
      ),
    );

    const statuses = await Promise.all(
      envelopes.map((envelope) =>
        fetch(`${broker.baseUrl}/api/submit`, {
          method: 'POST',
          headers: { 'x-handoff-capability': capability, 'content-type': 'application/json' },
          body: JSON.stringify(envelope),
        }).then((response) => response.status),
      ),
    );
    assert.equal(statuses.filter((status) => status === 200).length, 1);
    assert.equal(broker.testSnapshot(created.handoff_id).bodySlotBusy, false, 'never taken');
  });

  it('logs a refused admission locally, by reason and without the capability', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const first = await drop.seal(SAMPLE_FILES);
    const second = await drop.seal([{ name: 'b.txt', type: '', bytes: utf8('second') }]);

    await Promise.all([drop.send(first), drop.send(second)]);
    assert.ok(
      logLines.some((line) => /submit_slot_busy/.test(line)),
      'the refusal is diagnosable locally',
    );
    for (const line of logLines) {
      assert.ok(!line.includes(drop.capability), `capability leaked into a log line: ${line}`);
    }
  });
});

describe('the request-body overrun allowance', () => {
  let broker;

  beforeEach(async () => {
    broker = await testBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('is additive, so it does not scale with a 42 MiB ceiling', async () => {
    const config = broker.config;
    // Additive means the politeness budget is a constant, not `ceiling * 8`: at
    // the file ceiling the old multiplier admitted a ~470 MB single-request drain.
    assert.ok(config.bodyOverrunAllowanceBytes > 0);
    assert.ok(
      config.bodyOverrunAllowanceBytes <= 4 * 1024 * 1024,
      'the whole point is that it stays small next to a 56 MiB ceiling',
    );
    const fileDropCeiling = broker.broker.submitBodyCeiling(
      (await createFileDrop(broker, { ttlSeconds: TTL_SECONDS })).capability,
    );
    assert.ok(
      fileDropCeiling + config.bodyOverrunAllowanceBytes < 2 * fileDropCeiling,
      'the drain a single request can buy must be a fraction of the ceiling, not a multiple',
    );
  });

  it('still answers an over-limit text body politely rather than resetting it', async () => {
    // The behaviour seam 3 pins: a body past the ceiling but inside the allowance
    // is drained and answered with the uniform contract.
    const created = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    const capability = splitHandoffUrl(created.url).capability;
    const response = await fetch(`${broker.baseUrl}/api/submit`, {
      method: 'POST',
      headers: { 'x-handoff-capability': capability, 'content-type': 'application/json' },
      body: JSON.stringify({ v: 1, ct: 'A'.repeat(400_000) }),
    });
    assert.equal(response.status, 404);
    assert.equal(await response.text(), '{"status":"unavailable"}');
  });

  it('cuts off a body absurdly past the ceiling', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    const capability = splitHandoffUrl(created.url).capability;
    const beyond =
      broker.config.maxBodyBytes + broker.config.bodyOverrunAllowanceBytes + 512 * 1024;

    // Either a reset or the uniform body is acceptable here — this is the one case
    // the uniform contract cannot be honoured, and it is honoured as far as it can
    // be. What must NOT happen is the whole body being read.
    const outcome = await fetch(`${broker.baseUrl}/api/submit`, {
      method: 'POST',
      headers: { 'x-handoff-capability': capability, 'content-type': 'application/json' },
      body: 'A'.repeat(beyond),
    }).then(
      async (response) => ({ status: response.status, body: await response.text() }),
      (error) => ({ status: null, error: String(error) }),
    );
    assert.ok(outcome.status === 404 || outcome.status === null, JSON.stringify(outcome));
    assert.equal(broker.testSnapshot(created.handoff_id).state, 'pending');
  });
});

describe('the file-submit deadline', () => {
  let broker;

  beforeEach(async () => {
    // A tiny default deadline and a generous file one, so the difference between
    // them is observable in a test rather than in a 30-second wall clock.
    broker = await testBroker({ requestTimeoutMs: 400, fileSubmitTimeoutMs: 8_000 });
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('ships a default long enough for a maximal drop on an ordinary upstream', () => {
    // The shipped default has to carry the largest body the broker advertises at a
    // modest sustained upstream, or the advertised 42 MiB is a promise the
    // transport cannot keep — the acceptance criterion at
    // docs/FILE_TRANSFER_MVP.md:230 is a *completable* 42 MiB drop.
    const worstBodyBytes =
      Math.ceil(
        ((CONTAINER_HEADER_BYTES +
          MAX_MANIFEST_BYTES +
          DEFAULT_FILE_LIMITS.maxTotalBytes +
          AEAD_TAG_BYTES) *
          4) /
          3,
      ) + 4;
    const bytesPerSecondAt1Mbit = 125_000;
    assert.ok(
      DEFAULTS.fileSubmitTimeoutMs >= (worstBodyBytes / bytesPerSecondAt1Mbit) * 1000,
      `${DEFAULTS.fileSubmitTimeoutMs}ms must clear ${worstBodyBytes} bytes at 1 Mbit/s`,
    );
    assert.ok(
      DEFAULTS.fileSubmitTimeoutMs > DEFAULTS.requestTimeoutMs,
      'and it is an extension of the default deadline, not a replacement for it',
    );
  });

  it('lets a file submission take longer than the default deadline', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.seal(SAMPLE_FILES);

    // Eight chunks 150ms apart is ~1.2s of upload: comfortably past the 400ms
    // default deadline and comfortably inside the 8s file deadline.
    const response = await dribble({
      origin: broker.baseUrl,
      path: '/api/submit',
      capability: drop.capability,
      body: JSON.stringify(envelope),
      chunks: 8,
      gapMs: 150,
    });

    assert.equal(response.status, 200, JSON.stringify(response));
    assert.equal(broker.testSnapshot(drop.id).state, 'submitted');
  });

  it('still holds a text submission to the default deadline', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    const capability = splitHandoffUrl(created.url).capability;
    const metadata = await fetchMetadata({ capability, origin: broker.baseUrl });
    const envelope = await sealEnvelope({ capability, metadata, plaintext: 'a secret' });

    const response = await dribble({
      origin: broker.baseUrl,
      path: '/api/submit',
      capability,
      body: JSON.stringify(envelope),
      chunks: 8,
      gapMs: 150,
    });

    // The uniform contract, not Node's 408: a request that ran out of time must be
    // indistinguishable from every other refusal as far as Node permits.
    assert.equal(response.status, 404, JSON.stringify(response));
    assert.equal(response.body, '{"status":"unavailable"}');
    assert.equal(broker.testSnapshot(created.handoff_id).state, 'pending', 'nothing consumed');
  });

  it('answers a timed-out file submission with the same uniform body', async () => {
    const slow = await testBroker({ requestTimeoutMs: 300, fileSubmitTimeoutMs: 600 });
    try {
      const drop = await createFileDrop(slow, { ttlSeconds: TTL_SECONDS });
      const envelope = await drop.seal(SAMPLE_FILES);
      const response = await dribble({
        origin: slow.baseUrl,
        path: '/api/submit',
        capability: drop.capability,
        body: JSON.stringify(envelope),
        chunks: 10,
        gapMs: 150,
      });

      assert.equal(response.status, 404, JSON.stringify(response));
      assert.equal(response.body, '{"status":"unavailable"}');
      assert.equal(slow.testSnapshot(drop.id).state, 'pending');
      assert.equal(slow.testSnapshot(drop.id).bodySlotBusy, false, 'and the slot is released');
    } finally {
      await slow.stop();
    }
  });
});

describe('the advertised body ceiling holds a maximal container', () => {
  let broker;

  beforeEach(async () => {
    broker = await testBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  // Symbolic, not allocated: the worst case is 42 MiB of file bytes plus the
  // manifest ceiling, and computing it costs nothing. This pins the one number in
  // the slice that has no other guard — an extra envelope field, a longer suite
  // id or a rounding change in the base64 arithmetic would silently turn every
  // maximal drop into a generic unavailable, discovered by users only after a
  // ~16-second seal and a full upload.
  it('fits the largest container the limits can produce, envelope scaffolding included', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const ceiling = broker.broker.submitBodyCeiling(drop.capability);

    const worstContainerBytes = fileContainerCeiling(DEFAULT_FILE_LIMITS);
    assert.equal(
      worstContainerBytes,
      CONTAINER_HEADER_BYTES + MAX_MANIFEST_BYTES + DEFAULT_FILE_LIMITS.maxTotalBytes,
    );
    const worstCtChars = Math.ceil(((worstContainerBytes + AEAD_TAG_BYTES) * 4) / 3);

    // The real envelope, from the real sealer, with its real field names — the ct
    // is stripped out so only the scaffolding is measured.
    const sample = await drop.seal(SAMPLE_FILES);
    const scaffoldingBytes = Buffer.byteLength(JSON.stringify({ ...sample, ct: '' }));

    const worstBodyBytes = worstCtChars + scaffoldingBytes;
    assert.ok(
      worstBodyBytes <= ceiling,
      `a maximal body is ${worstBodyBytes} bytes but the ceiling is ${ceiling}`,
    );
  });

  it('collapses back to the text ceiling for anything that is not a live file drop', async () => {
    const core = broker.broker;
    const textCeiling = broker.config.maxBodyBytes;

    // Garbage and never-existed capabilities.
    for (const capability of ['', 'not-base64url!!', 'z'.repeat(21), 'z'.repeat(22)]) {
      assert.equal(
        core.submitBodyCeiling(capability),
        textCeiling,
        `capability ${JSON.stringify(capability)} must buy no extra buffer`,
      );
    }

    // A live pending text drop.
    const text = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    assert.equal(core.submitBodyCeiling(splitHandoffUrl(text.url).capability), textCeiling);

    // A file drop, at every state after pending.
    const submitted = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.ok(core.submitBodyCeiling(submitted.capability) > textCeiling, 'widened while pending');
    assert.equal(await submitted.send(await submitted.seal(SAMPLE_FILES)), 'received');
    assert.equal(
      core.submitBodyCeiling(submitted.capability),
      textCeiling,
      'a submitted drop can never need a widened body again',
    );

    assert.equal((await claimFileDrop(broker, submitted.id)).ok, true);
    assert.equal(core.submitBodyCeiling(submitted.capability), textCeiling, 'claimed');

    const expired = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    core.sweep(Date.now() + TTL_SECONDS * 1000 + 1);
    assert.equal(core.submitBodyCeiling(expired.capability), textCeiling, 'expired');
  });
});
