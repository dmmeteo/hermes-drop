// Slice U1 of docs/UNIVERSAL_DROP_DELIVERY_PLAN.md — one link, two lanes.
//
// Every drop before this slice had its payload kind chosen by whoever asked for
// it. A universal drop does not: it is minted as `pending(choice)`, advertises
// both lanes from one metadata response, and the *sender* picks text or files in
// the browser at submit time. Three things follow, and they are what this file
// pins:
//
//   DECLARE   the broker has to know which lane a body is before it buffers up to
//             56 MiB of it, so one submission carries a small non-secret
//             declaration in a request header — the same convention the capability
//             already travels by. It says text-versus-files and nothing else: no
//             name, no size, no MIME hint, no digest.
//   BIND      the declaration is bound to the envelope version it implies (text→v1,
//             files→v2). A mismatch in either direction is the uniform refusal and
//             consumes nothing, because `info` is rebuilt from the declared lane's
//             version and a relabelled ciphertext cannot open.
//   RESERVE   a universal link does *not* reserve 42 MiB at creation — that would
//             make four idle text links exhaust the process budget. The reservation
//             is taken by the `files` declaration before the body is read, and it
//             converts into the record's own live reservation in the same
//             synchronous step that fixes the payload kind. Every other ending
//             gives it back.
//
// The one-winner property is the old one at a new width: a link that can be
// submitted to two different ways still accepts exactly one submission, and the
// loser of a text/files race gets the same `unavailable` as any second submission.
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { afterEach, beforeEach, describe, it } from 'node:test';

import {
  fetchMetadata,
  sealEnvelope,
  sendSecret,
  submitEnvelope,
} from '../src/client/handoff-client.js';
import { DEFAULT_FILE_LIMITS, fileContainerCeiling } from '../src/file-container.js';
import { AEAD_TAG_BYTES, ENVELOPE_VERSION } from '../src/hpke-suite.js';
import {
  claimFileDrop,
  createFileDrop,
  createUniversalDrop,
  splitHandoffUrl,
  startTestBroker,
} from './helpers/harness.js';

const TTL_SECONDS = 120;
const utf8 = (text) => new TextEncoder().encode(text);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** The header the declaration rides in, spelled as it appears on the wire. */
const DECLARATION_HEADER = 'x-handoff-payload';

/** A distinctive name and body, so a leak into a log or a snapshot is visible. */
const FILE_NAME = 'universal-secrets.env';
const FILE_BODY = 'PGPASSWORD=example-not-a-real-secret\n';
const SAMPLE_FILES = [{ name: FILE_NAME, type: 'text/plain', bytes: utf8(FILE_BODY) }];

const DROP_RESERVATION_BYTES = fileContainerCeiling(DEFAULT_FILE_LIMITS);

function testBroker(overrides = {}) {
  return startTestBroker({ sweepIntervalMs: 3_600_000, ...overrides });
}

/**
 * POSTs a body in pieces, `gapMs` apart, over a raw socket, and calls `whileSending`
 * once the first piece is out — the only way to observe what the broker reserved
 * *before* the body finished arriving.
 */
function dribble({ origin, capability, declaration, body, chunks = 4, gapMs = 60, whileSending }) {
  const url = new URL(`${origin}/api/submit`);
  const payload = Buffer.from(body);
  const size = Math.ceil(payload.length / chunks);
  const headers = {
    'x-handoff-capability': capability,
    'content-type': 'application/json',
    'content-length': payload.length,
  };
  if (declaration !== undefined && declaration !== null) headers[DECLARATION_HEADER] = declaration;

  return new Promise((resolve) => {
    const clientRequest = httpRequest(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers,
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
        if (offset === 0 && whileSending) await whileSending({ clientRequest });
        await sleep(gapMs);
      }
      if (!clientRequest.destroyed) clientRequest.end();
    })();
  });
}

/** Polls until `predicate` holds, so a mid-request observation is not a sleep race. */
async function until(predicate, { attempts = 200, everyMs = 10 } = {}) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (predicate()) return true;
    await sleep(everyMs);
  }
  return false;
}

describe('universal drops: one link that advertises both lanes', () => {
  let broker;

  beforeEach(async () => {
    broker = await testBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('mints a pending(choice) link over the same control seam', async () => {
    const created = await broker.control({
      op: 'create',
      payload_kind: 'universal',
      ttl_seconds: TTL_SECONDS,
    });

    assert.equal(created.ok, true, JSON.stringify(created));
    assert.equal(created.payload_kind, 'universal');
    // One response carries both capabilities and both sets of limits: the requester
    // does not choose a lane, so it may not be told about only one of them.
    assert.equal(created.max_plaintext_bytes, 65536);
    assert.equal(created.max_files, DEFAULT_FILE_LIMITS.maxFiles);
    assert.equal(created.max_file_bytes, DEFAULT_FILE_LIMITS.maxFileBytes);
    assert.equal(created.max_total_bytes, DEFAULT_FILE_LIMITS.maxTotalBytes);
    assert.match(created.url, /^http:\/\/127\.0\.0\.1:\d+\/#[A-Za-z0-9_-]{22}$/);
    assert.equal(broker.testSnapshot(created.handoff_id).state, 'pending');
  });

  // The pre-flight check the MVP requires: a plugin that cannot claim a universal
  // link safely must be able to fail *before* it posts one. An older broker refuses
  // `payload_kind: "universal"` with `invalid_request`, so the list is what a newer
  // plugin reads to know it is talking to a broker that can mint one.
  it('advertises the universal kind so an older plugin can fail before posting', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    assert.deepEqual(created.payload_kinds, ['text', 'files', 'universal']);
    assert.equal(created.protocol_version, 2, 'the universal kind is additive');
  });

  it('does not reserve file bytes at creation, however many links are live', async () => {
    const core = broker.broker;
    for (let index = 0; index < 8; index += 1) {
      const created = await broker.control({
        op: 'create',
        payload_kind: 'universal',
        ttl_seconds: TTL_SECONDS,
      });
      assert.equal(created.ok, true, `universal link ${index} must be mintable`);
    }
    assert.equal(
      core.fileBudget().reservedBytes,
      0,
      'eight text-capable links must not have reserved a byte of the file budget',
    );
    // ...and the whole file budget is still there for the drops that really hold
    // bytes, which is the property pre-reserving would have destroyed.
    for (let index = 0; index < 4; index += 1) {
      assert.equal((await createFileDrop(broker, { ttlSeconds: TTL_SECONDS })).created.ok, true);
    }
    assert.equal(core.fileBudget().reservedBytes, 4 * DROP_RESERVATION_BYTES);
  });

  it('publishes one metadata response the page can choose from', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });

    assert.equal(drop.metadata.payload_kind, 'universal');
    assert.deepEqual(drop.metadata.accepts, ['text', 'files']);
    // The version an *undeclared* submission must use, and the pair a declared one
    // chooses between. Both are stated: a page that had to infer either would be
    // guessing at the one thing the AEAD binds.
    assert.equal(drop.metadata.v, ENVELOPE_VERSION);
    assert.deepEqual(drop.metadata.envelope_versions, { text: 1, files: 2 });
    assert.equal(drop.metadata.payload_declaration, DECLARATION_HEADER);
    // Both lanes' limits, from the broker, because a browser check is a courtesy.
    assert.equal(drop.metadata.max_plaintext_bytes, 65536);
    assert.equal(drop.metadata.max_files, DEFAULT_FILE_LIMITS.maxFiles);
    assert.equal(drop.metadata.max_file_bytes, DEFAULT_FILE_LIMITS.maxFileBytes);
    assert.equal(drop.metadata.max_total_bytes, DEFAULT_FILE_LIMITS.maxTotalBytes);
    assert.equal(drop.metadata.hid, drop.id);
    assert.ok(Number.isInteger(drop.metadata.now));
  });

  it('lets a requester narrow the file lane of a universal link', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS, maxFiles: 2 });
    assert.equal(drop.created.max_files, 2);
    assert.equal(drop.metadata.max_files, 2);
    // ...and still cannot raise it.
    const raised = await broker.control({
      op: 'create',
      payload_kind: 'universal',
      max_files: 50,
      ttl_seconds: TTL_SECONDS,
    });
    assert.equal(raised.max_files, DEFAULT_FILE_LIMITS.maxFiles);
  });

  it('leaves an explicitly typed drop exactly as it was', async () => {
    const text = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    assert.equal(text.payload_kind, 'text');
    assert.equal(text.max_plaintext_bytes, 65536);
    for (const key of ['max_files', 'max_file_bytes', 'max_total_bytes', 'accepts']) {
      assert.ok(!(key in text), `${key} is meaningless on an explicitly typed text drop`);
    }

    const files = await broker.control({
      op: 'create',
      payload_kind: 'files',
      ttl_seconds: TTL_SECONDS,
    });
    assert.equal(files.payload_kind, 'files');
    assert.ok(!('max_plaintext_bytes' in files));
    assert.equal(
      broker.broker.fileBudget().reservedBytes,
      DROP_RESERVATION_BYTES,
      'an explicitly typed files drop still reserves at creation, as it always did',
    );
  });
});

describe('universal drops: the pre-body payload declaration', () => {
  let broker;

  beforeEach(async () => {
    broker = await testBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('is one header, spelled the same on both sides of the wire', async () => {
    const server = await import('../src/public-server.js');
    const client = await import('../src/client/handoff-client.js');
    assert.equal(server.PAYLOAD_DECLARATION_HEADER, DECLARATION_HEADER);
    assert.equal(client.PAYLOAD_DECLARATION_HEADER.toLowerCase(), DECLARATION_HEADER);
    assert.deepEqual(server.PAYLOAD_DECLARATIONS, ['text', 'files']);
  });

  it('widens the body ceiling for the files lane and for nothing else', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    // Base64 of a maximal container plus its AEAD tag, plus the envelope JSON around
    // it — computed here rather than read from the broker, so the two must agree.
    const widened = Math.ceil(((DROP_RESERVATION_BYTES + AEAD_TAG_BYTES) * 4) / 3) + 4 + 512;

    assert.equal(core.submitBodyCeiling(drop.capability), broker.config.maxBodyBytes, 'undeclared');
    assert.equal(
      core.submitBodyCeiling(drop.capability, { declaration: 'text' }),
      broker.config.maxBodyBytes,
      'a text declaration buys no buffer at all',
    );
    assert.equal(core.submitBodyCeiling(drop.capability, { declaration: 'files' }), widened);
  });

  it('reserves the file budget before the body is buffered', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealFiles(SAMPLE_FILES);

    let observed = null;
    const response = await dribble({
      origin: broker.baseUrl,
      capability: drop.capability,
      declaration: 'files',
      body: JSON.stringify(envelope),
      chunks: 5,
      gapMs: 80,
      whileSending: async () => {
        await until(() => core.fileBudget().reservedBytes > 0);
        observed = {
          budget: core.fileBudget(),
          snapshot: broker.testSnapshot(drop.id),
        };
      },
    });

    assert.ok(observed, 'the upload must be observable while it is still arriving');
    assert.equal(
      observed.snapshot.state,
      'pending',
      'the reservation has to exist before the payload does',
    );
    assert.equal(observed.budget.reservedBytes, DROP_RESERVATION_BYTES);
    assert.equal(observed.snapshot.reservedBytes, DROP_RESERVATION_BYTES);
    assert.ok(observed.snapshot.submitLease, 'and it is held as a lease, not as a payload');
    assert.equal(observed.snapshot.bodySlotBusy, true, 'one widened body at a time, as before');

    assert.equal(response.status, 200, JSON.stringify(response));
    // Converted, in the same step that fixed the kind: the same bytes, now owned by
    // the record rather than by the request.
    const after = broker.testSnapshot(drop.id);
    assert.equal(after.state, 'submitted');
    assert.equal(after.payloadKind, 'files');
    assert.equal(after.reservedBytes, DROP_RESERVATION_BYTES);
    assert.equal(after.submitLease, null, "the lease is the record's reservation now");
    assert.equal(after.bodySlotBusy, false, 'and the request gave its slot back');
    assert.equal(core.fileBudget().reservedBytes, DROP_RESERVATION_BYTES);
  });

  it('reserves nothing for a text submission on the same link', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealText('a small secret');

    let observed = null;
    const response = await dribble({
      origin: broker.baseUrl,
      capability: drop.capability,
      declaration: 'text',
      body: JSON.stringify(envelope),
      chunks: 4,
      gapMs: 60,
      whileSending: async () => {
        observed = {
          budget: core.fileBudget(),
          snapshot: broker.testSnapshot(drop.id),
        };
      },
    });

    assert.equal(observed.budget.reservedBytes, 0, 'a text lane reserves nothing');
    assert.equal(observed.snapshot.bodySlotBusy, false, 'and is not gated, as text never was');
    assert.equal(response.status, 200);
    assert.equal(broker.testSnapshot(drop.id).payloadKind, 'text');
    assert.equal(core.fileBudget().reservedBytes, 0);
  });

  it('holds an undeclared submission to the text lane, for the compatibility window', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const text = await drop.sealText('sent by a client from before the declaration');

    assert.equal(await drop.send(text, { declaration: null }), 'received');
    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'submitted');
    assert.equal(snapshot.payloadKind, 'text');
  });

  it('refuses an undeclared container without consuming the drop', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const files = await drop.sealFiles(SAMPLE_FILES);

    assert.equal(await drop.send(files, { declaration: null }), 'unavailable');
    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'pending', 'silence is read as text, so v2 is a mismatch');
    assert.equal(snapshot.aeadFailures, 0, 'and it costs nothing from the AEAD budget');
    assert.equal(core.fileBudget().reservedBytes, 0);
    // Still the sender's link: the refusal took nothing away.
    assert.equal(await drop.send(files), 'received');
  });

  it('refuses a declaration that contradicts the sealed envelope, both ways', async () => {
    const core = broker.broker;
    for (const [declaration, seal] of [
      ['text', (drop) => drop.sealFiles(SAMPLE_FILES)],
      ['files', (drop) => drop.sealText('a secret declared as files')],
    ]) {
      const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
      const envelope = await seal(drop);

      assert.equal(await drop.send(envelope, { declaration }), 'unavailable');
      const snapshot = broker.testSnapshot(drop.id);
      assert.equal(snapshot.state, 'pending', `declaration ${declaration} must consume nothing`);
      assert.equal(snapshot.aeadFailures, 0, 'the version is refused before any crypto');
      assert.equal(snapshot.containerFailures, 0);
      assert.equal(snapshot.bodySlotBusy, false);
      assert.equal(core.fileBudget().reservedBytes, 0, 'and any lease is given back');

      // ...and the honest submission still works afterwards.
      assert.equal(await drop.send(envelope), 'received');
      // The honest submission of a container reserves; of a secret, it does not.
      const reserved = declaration === 'text' ? DROP_RESERVATION_BYTES : 0;
      assert.equal(core.fileBudget().reservedBytes, reserved);
      await broker.control({ op: 'claim', handoff_id: drop.id }).catch(() => {});
      core.testSetExpiry(drop.id, Date.now() - 1);
      core.sweep();
    }
  });

  it('refuses a declaration it does not speak, uniformly and without minting a buffer', async () => {
    const core = broker.broker;
    // Casing, whitespace, a third word, and the comma-joined pair `node:http`
    // produces from a repeated header: none of them is one of the two words.
    const nonsense = ['binary', 'FILES', 'Text', '', 'text files', 'files,files', ' files'];
    for (const declaration of nonsense) {
      const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
      const envelope = await drop.sealText('a secret with a nonsense declaration');

      assert.equal(
        await drop.send(envelope, { declaration }),
        'unavailable',
        `declaration ${JSON.stringify(declaration)} must be refused`,
      );
      assert.equal(broker.testSnapshot(drop.id).state, 'pending');
      assert.equal(core.fileBudget().reservedBytes, 0);
      assert.equal(
        core.submitBodyCeiling(drop.capability, { declaration }),
        broker.config.maxBodyBytes,
        'an unspeakable declaration never widens the ceiling',
      );
    }
  });

  it('refuses a declaration that contradicts an explicitly typed drop', async () => {
    const text = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    const textCapability = splitHandoffUrl(text.url).capability;
    const textMetadata = await fetchMetadata({ capability: textCapability, origin: broker.baseUrl });
    const secret = await sealEnvelope({
      capability: textCapability,
      metadata: textMetadata,
      plaintext: 'a text secret',
    });

    const post = (capability, declaration, envelope) =>
      fetch(`${broker.baseUrl}/api/submit`, {
        method: 'POST',
        headers: {
          'x-handoff-capability': capability,
          'content-type': 'application/json',
          [DECLARATION_HEADER]: declaration,
        },
        body: JSON.stringify(envelope),
      }).then((response) => response.status);

    assert.equal(await post(textCapability, 'files', secret), 404, 'a text drop has no file lane');
    assert.equal(broker.testSnapshot(text.handoff_id).state, 'pending', 'and nothing was consumed');
    assert.equal(broker.broker.fileBudget().reservedBytes, 0, 'least of all a reservation');

    const files = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const container = await files.seal(SAMPLE_FILES);
    assert.equal(await post(files.capability, 'text', container), 404);
    assert.equal(broker.testSnapshot(files.id).state, 'pending');

    // The matching declaration, and silence, both still work on a typed drop.
    assert.equal(await post(files.capability, 'files', container), 200);
    assert.equal(await post(textCapability, 'text', secret), 200);
  });
});

describe('universal drops: exactly one submission wins', () => {
  let broker;

  beforeEach(async () => {
    broker = await testBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('takes one text submission and then refuses the file lane', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const secret = 'AKIA-EXAMPLE-NOT-A-REAL-KEY';

    assert.equal(await drop.send(await drop.sealText(secret)), 'received');
    assert.equal(broker.testSnapshot(drop.id).payloadKind, 'text', 'the kind is now immutable');
    assert.equal(await drop.send(await drop.sealFiles(SAMPLE_FILES)), 'unavailable');

    // ...and it claims over the text seam, which is what makes the kind usable.
    const claimed = await broker.control({ op: 'claim', handoff_id: drop.id });
    assert.equal(claimed.ok, true, JSON.stringify(claimed));
    assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), secret);
    assert.equal(broker.testSnapshot(drop.id).state, 'claimed');
  });

  it('takes one file submission and then refuses the text lane', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });

    assert.equal(await drop.send(await drop.sealFiles(SAMPLE_FILES)), 'received');
    assert.equal(broker.testSnapshot(drop.id).payloadKind, 'files');
    assert.equal(await drop.send(await drop.sealText('too late')), 'unavailable');
    // A text claim cannot reach a container, exactly as on a typed files drop.
    assert.deepEqual(await broker.control({ op: 'claim', handoff_id: drop.id }), {
      ok: false,
      error: 'unavailable',
    });

    const claimed = await claimFileDrop(broker, drop.id);
    assert.equal(claimed.ok, true, JSON.stringify(claimed));
    assert.equal(claimed.files.length, 1);
    assert.equal(claimed.files[0].name, FILE_NAME);
    assert.equal(claimed.files[0].bytes.toString('utf8'), FILE_BODY);
    assert.equal(broker.testSnapshot(drop.id).state, 'claimed');
    assert.equal(broker.broker.fileBudget().reservedBytes, 0, 'and the claim released it');
  });

  it('has exactly one winner when both lanes are submitted at once', async () => {
    const core = broker.broker;
    for (let round = 0; round < 4; round += 1) {
      const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
      const [text, files] = await Promise.all([
        drop.sealText(`racing secret ${round}`),
        drop.sealFiles(SAMPLE_FILES),
      ]);

      const [textOutcome, filesOutcome] = await Promise.all([drop.send(text), drop.send(files)]);
      const winners = [textOutcome, filesOutcome].filter((outcome) => outcome === 'received');
      assert.equal(winners.length, 1, `round ${round}: exactly one lane may win`);

      const snapshot = broker.testSnapshot(drop.id);
      assert.equal(snapshot.state, 'submitted');
      assert.equal(snapshot.payloadKind, textOutcome === 'received' ? 'text' : 'files');
      assert.equal(
        core.fileBudget().reservedBytes,
        textOutcome === 'received' ? 0 : DROP_RESERVATION_BYTES,
        'the budget agrees with whichever lane won',
      );
      assert.equal(snapshot.bodySlotBusy, false);

      core.testSetExpiry(drop.id, Date.now() - 1);
      core.sweep();
      assert.equal(core.fileBudget().reservedBytes, 0);
    }
  });

  it('admits one widened body at a time, and one reservation with it', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelopes = await Promise.all(
      ['a', 'b', 'c', 'd'].map((tag) =>
        drop.sealFiles([{ name: `${tag}.txt`, type: '', bytes: utf8(tag.repeat(64)) }]),
      ),
    );

    const outcomes = await Promise.all(envelopes.map((envelope) => drop.send(envelope)));
    assert.equal(outcomes.filter((outcome) => outcome === 'received').length, 1);
    assert.equal(
      core.fileBudget().reservedBytes,
      DROP_RESERVATION_BYTES,
      'four concurrent file bodies may never hold four reservations against one drop',
    );
    assert.equal(core.fileBudget().reservations, 1);
    assert.equal(broker.testSnapshot(drop.id).bodySlotBusy, false);
  });

  it('answers an exact retry that preserves its declaration, and nothing else', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealFiles(SAMPLE_FILES);

    assert.equal(await drop.send(envelope), 'received');
    // The same sealed bytes and the same declaration: the mobile-retry case, and it
    // is answered idempotently rather than as a second submission.
    assert.equal(await drop.send(envelope), 'received');
    // The same bytes with the other declaration is not that retry. It cannot open
    // as v1, so it is the uniform refusal — and it still delivers nothing twice.
    assert.equal(await drop.send(envelope, { declaration: 'text' }), 'unavailable');
    assert.equal(await drop.send(envelope, { declaration: null }), 'unavailable');
    assert.equal(await drop.send(envelope), 'received', 'and the receipt survives all of it');

    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'submitted');
    assert.equal(snapshot.fileCount, 1);
    assert.equal(broker.broker.fileBudget().reservedBytes, DROP_RESERVATION_BYTES);
  });

  it('returns the original receipt for a maximal-file HTTP retry without another reservation', async () => {
    const maxBroker = await testBroker({ fileSubmitTimeoutMs: 60_000 });
    try {
      const core = maxBroker.broker;
      const drop = await createUniversalDrop(maxBroker, { ttlSeconds: TTL_SECONDS });
      const envelope = await drop.sealFiles([
        { name: 'max.bin', type: '', bytes: new Uint8Array(DEFAULT_FILE_LIMITS.maxTotalBytes) },
      ]);
      assert.equal(await drop.send(envelope), 'received');
      const before = core.fileBudget();
      assert.equal(await drop.send(envelope), 'received');
      assert.deepEqual(core.fileBudget(), before, 'retry must reuse the live payload reservation');
    } finally {
      await maxBroker.stop();
    }
  });

  it('admits only one concurrent widened retry body and keeps accounting unchanged', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealFiles(SAMPLE_FILES);
    assert.equal(await drop.send(envelope), 'received');
    const first = core.acquireSubmitSlot(drop.capability, { declaration: 'files' });
    const second = core.acquireSubmitSlot(drop.capability, { declaration: 'files' });
    assert.equal(first.ok, true);
    assert.equal(first.widened, true);
    assert.equal(second.ok, false);
    assert.equal(core.fileBudget().reservations, 1);
    assert.equal(core.fileBudget().submitLeases, 0);
    first.release();
    assert.equal(core.fileBudget().reservedBytes, DROP_RESERVATION_BYTES);
  });

  it('binds exact retry identity to every envelope field and the declaration', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealFiles(SAMPLE_FILES);
    assert.equal(await drop.send(envelope), 'received');
    const flip = (value) => `${value.slice(0, -1)}${value.endsWith('A') ? 'B' : 'A'}`;
    const mutations = {
      v: { ...envelope, v: 1 },
      hid: { ...envelope, hid: flip(envelope.hid) },
      pkfp: { ...envelope, pkfp: flip(envelope.pkfp) },
      enc: { ...envelope, enc: flip(envelope.enc) },
      ct: { ...envelope, ct: flip(envelope.ct) },
    };
    for (const [field, mutated] of Object.entries(mutations)) {
      assert.equal(await drop.send(mutated), 'unavailable', `${field} mutation is not exact`);
    }
    assert.equal(await drop.send(envelope, { declaration: 'text' }), 'unavailable');
    assert.equal(await drop.send(envelope, { declaration: null }), 'unavailable');
    assert.equal(await drop.send(envelope), 'received');
  });

  it('answers a text retry the same way, declaration included', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealText('one secret, sent twice');

    assert.equal(await drop.send(envelope), 'received');
    assert.equal(await drop.send(envelope), 'received');
    assert.equal(await drop.send(envelope, { declaration: null }), 'received', 'silence is text');
    assert.equal(await drop.send(envelope, { declaration: 'files' }), 'unavailable');
    assert.equal(broker.broker.fileBudget().reservedBytes, 0);
  });
});

describe('universal drops: the file submit lease always comes back', () => {
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

  it('gives it back when the envelope is refused', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });

    // A forged envelope: right shape, wrong ciphertext. It costs the AEAD budget
    // and must cost nothing else.
    const honest = await drop.sealFiles(SAMPLE_FILES);
    const forged = { ...honest, ct: honest.ct.slice(0, -4) + 'AAAA' };
    assert.equal(await drop.send(forged), 'unavailable');
    assert.equal(core.fileBudget().reservedBytes, 0, 'a failed AEAD holds no reservation');
    assert.equal(broker.testSnapshot(drop.id).state, 'pending');

    // A malformed body, which never reaches the crypto at all.
    assert.equal(await drop.send({ nonsense: true }, { declaration: 'files' }), 'unavailable');
    assert.equal(core.fileBudget().reservedBytes, 0);

    // A decryptable payload that is not a container.
    const notAContainer = await drop.sealFiles(SAMPLE_FILES);
    const plain = await import('../src/client/handoff-client.js');
    const junk = await plain.sealBytesEnvelope({
      capability: drop.capability,
      metadata: drop.metadata,
      bytes: utf8('this is not an HDROP2 container'),
      version: 2,
    });
    assert.equal(await drop.send(junk), 'unavailable');
    assert.equal(core.fileBudget().reservedBytes, 0, 'a refused container holds no reservation');
    assert.equal(broker.testSnapshot(drop.id).containerFailures, 1);

    // ...and the link still works.
    assert.equal(await drop.send(notAContainer), 'received');
    assert.equal(core.fileBudget().reservedBytes, DROP_RESERVATION_BYTES);
  });

  it('gives it back when the client abandons the upload mid-body', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealFiles(SAMPLE_FILES);

    await dribble({
      origin: broker.baseUrl,
      capability: drop.capability,
      declaration: 'files',
      body: JSON.stringify(envelope),
      chunks: 6,
      gapMs: 40,
      whileSending: async ({ clientRequest }) => {
        await until(() => core.fileBudget().reservedBytes > 0);
        clientRequest.destroy();
      },
    });

    assert.ok(
      await until(() => core.fileBudget().reservedBytes === 0),
      'an abandoned upload must not hold a quarter of the process budget for a whole TTL',
    );
    assert.equal(broker.testSnapshot(drop.id).bodySlotBusy, false);
    assert.equal(broker.testSnapshot(drop.id).submitLease, null);
    assert.equal(await drop.send(envelope), 'received', 'and the drop is still submittable');
  });

  it('gives it back when the request deadline fires mid-body', async () => {
    // Short deadlines, so a dribbled body cannot finish inside them. The file lane
    // extends the deadline to `fileSubmitTimeoutMs` and this proves the extension is
    // still a deadline: when it fires, the reservation goes back.
    const short = await testBroker({ requestTimeoutMs: 200, fileSubmitTimeoutMs: 400 });
    try {
      const core = short.broker;
      const drop = await createUniversalDrop(short, { ttlSeconds: TTL_SECONDS });
      const envelope = await drop.sealFiles(SAMPLE_FILES);

      const response = await dribble({
        origin: short.baseUrl,
        capability: drop.capability,
        declaration: 'files',
        body: JSON.stringify(envelope),
        chunks: 12,
        gapMs: 120,
      });

      assert.equal(response.status ?? 404, 404, 'a timed-out submission is refused uniformly');
      // A deadline that fires answers the uniform body before it stops reading; the
      // one case it cannot honour is a socket that dies first, which arrives here as
      // no body at all rather than as a different one.
      if (response.body !== '') assert.equal(response.body, '{"status":"unavailable"}');
      assert.ok(
        await until(() => core.fileBudget().reservedBytes === 0),
        'a deadline that fires mid-upload must not strand the reservation',
      );
      const snapshot = short.testSnapshot(drop.id);
      assert.equal(snapshot.state, 'pending', 'and nothing was consumed');
      assert.equal(snapshot.submitLease, null);
      assert.equal(snapshot.bodySlotBusy, false);
      // ...and a submission that fits inside the deadline still lands.
      assert.equal(await drop.send(envelope), 'received');
    } finally {
      await short.stop();
    }
  });

  // The interleaving the two lanes make possible: a file body is admitted and
  // holding its reservation when the *text* lane wins. Only the lane that actually
  // won may take the reservation over — a text record that inherited 42 MiB of file
  // budget would hold it for the rest of its TTL, for a payload it does not have and
  // an upload that is already being refused.
  it('does not let a text winner inherit an in-flight file lease', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });

    const slot = core.acquireSubmitSlot(drop.capability, { declaration: 'files' });
    assert.equal(slot.ok, true);
    assert.equal(core.fileBudget().leasedBytes, DROP_RESERVATION_BYTES);

    // The text lane is not gated, so it can win while that body is still unread.
    assert.equal(await drop.send(await drop.sealText('the text lane won')), 'received');
    assert.equal(broker.testSnapshot(drop.id).payloadKind, 'text');

    slot.release();
    assert.equal(
      core.fileBudget().reservedBytes,
      0,
      'the reservation belongs to the upload that was refused, not to the secret that landed',
    );
    assert.equal(broker.testSnapshot(drop.id).reservedBytes, 0);
    assert.equal(broker.testSnapshot(drop.id).submitLease, null);

    // ...and the budget is genuinely free again: four full file drops still fit.
    for (let index = 0; index < 4; index += 1) {
      assert.equal((await createFileDrop(broker, { ttlSeconds: TTL_SECONDS })).created.ok, true);
    }
    assert.equal(core.fileBudget().availableBytes, 0);
  });

  it('reports an in-flight lease separately from the reservations it holds', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const typed = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });

    assert.deepEqual(
      {
        reservations: core.fileBudget().reservations,
        submitLeases: core.fileBudget().submitLeases,
        leasedBytes: core.fileBudget().leasedBytes,
      },
      { reservations: 1, submitLeases: 0, leasedBytes: 0 },
      'a typed files drop reserves at creation and holds no lease',
    );

    const slot = core.acquireSubmitSlot(drop.capability, { declaration: 'files' });
    const held = core.fileBudget();
    assert.equal(held.reservations, 2, 'two drops hold bytes');
    assert.equal(held.submitLeases, 1, 'one of them provisionally, for an unread body');
    assert.equal(held.leasedBytes, DROP_RESERVATION_BYTES);
    assert.equal(held.reservedBytes, 2 * DROP_RESERVATION_BYTES);

    slot.release();
    assert.equal(core.fileBudget().submitLeases, 0);
    assert.equal(core.fileBudget().leasedBytes, 0);
    assert.equal(
      core.fileBudget().reservedBytes,
      DROP_RESERVATION_BYTES,
      "the typed drop's own reservation is untouched",
    );

    // A won submission converts rather than releases: the bytes stay, the lease goes.
    assert.equal(await drop.send(await drop.sealFiles(SAMPLE_FILES)), 'received');
    const converted = core.fileBudget();
    assert.equal(converted.submitLeases, 0, 'nothing is provisional once a lane has won');
    assert.equal(converted.leasedBytes, 0);
    assert.equal(converted.reservedBytes, 2 * DROP_RESERVATION_BYTES);
    assert.equal(typed.created.ok, true);
  });

  it('holds a text submission to the text ceiling over the wire, not just in arithmetic', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealText('a secret');
    // A body past the text ceiling, declared as text: the widened ceiling belongs to
    // the file lane and a text declaration may not reach it.
    const oversized = JSON.stringify({
      ...envelope,
      padding: 'x'.repeat(broker.config.maxBodyBytes + 1024),
    });

    const response = await fetch(`${broker.baseUrl}/api/submit`, {
      method: 'POST',
      headers: {
        'x-handoff-capability': drop.capability,
        'content-type': 'application/json',
        [DECLARATION_HEADER]: 'text',
      },
      body: oversized,
    });
    assert.equal(response.status, 404);
    assert.equal(await response.text(), '{"status":"unavailable"}');
    assert.equal(broker.testSnapshot(drop.id).state, 'pending', 'nothing was consumed');
    assert.equal(broker.broker.fileBudget().reservedBytes, 0, 'and nothing was reserved');
    assert.equal(await drop.send(envelope), 'received');
  });

  it('gives it back when the drop expires under an upload', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealFiles(SAMPLE_FILES);

    const response = await dribble({
      origin: broker.baseUrl,
      capability: drop.capability,
      declaration: 'files',
      body: JSON.stringify(envelope),
      chunks: 6,
      gapMs: 40,
      whileSending: async () => {
        await until(() => core.fileBudget().reservedBytes > 0);
        core.testSetExpiry(drop.id, Date.now() - 1);
        core.sweep();
      },
    });

    assert.equal(core.fileBudget().reservedBytes, 0, 'expiry released the lease');
    assert.equal(response.status ?? 404, 404, 'and the upload is refused uniformly');
    assert.equal(broker.testSnapshot(drop.id), null, 'the record is gone');
    assert.equal(core.fileBudget().reservedBytes, 0, 'and nothing double-released');
  });

  it('gives it back on shutdown, and refuses to go negative', async () => {
    const core = broker.broker;
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });

    const slot = core.acquireSubmitSlot(drop.capability, { declaration: 'files' });
    assert.equal(slot.ok, true);
    assert.equal(slot.widened, true);
    assert.equal(core.fileBudget().reservedBytes, DROP_RESERVATION_BYTES);

    core.destroyAll();
    assert.equal(core.fileBudget().reservedBytes, 0, 'shutdown releases every reservation');
    slot.release();
    assert.equal(core.fileBudget().reservedBytes, 0, 'and a late release is not a second one');

    // Repeated releases are the same no-op, on a live drop too.
    const second = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const held = core.acquireSubmitSlot(second.capability, { declaration: 'files' });
    held.release();
    held.release();
    assert.equal(core.fileBudget().reservedBytes, 0);
    assert.equal(broker.testSnapshot(second.id).bodySlotBusy, false);
  });

  it('refuses the file lane uniformly when the process budget is full', async () => {
    const core = broker.broker;
    const drops = [];
    for (let index = 0; index < 4; index += 1) {
      drops.push(await createFileDrop(broker, { ttlSeconds: TTL_SECONDS }));
    }
    assert.equal(core.fileBudget().availableBytes, 0, 'the shipped budget holds four drops');

    const universal = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(universal.created.ok, true, 'a universal link is still mintable');
    assert.equal(
      await universal.send(await universal.sealFiles(SAMPLE_FILES)),
      'unavailable',
      'but its file lane cannot be admitted while the budget is full',
    );
    assert.equal(broker.testSnapshot(universal.id).state, 'pending', 'nothing was consumed');
    assert.ok(
      logLines.some((line) => /live_file_budget/.test(line)),
      'and the refusal is diagnosable locally',
    );

    // The text lane is unaffected: it never shared that budget.
    assert.equal(await universal.send(await universal.sealText('a secret')), 'received');

    // Free one file drop and the file lane opens again for the next link.
    core.testSetExpiry(drops[0].id, Date.now() - 1);
    core.sweep();
    const next = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await next.send(await next.sealFiles(SAMPLE_FILES)), 'received');
  });

  it('keeps names, bytes, digests and capabilities out of every log line', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.sealFiles(SAMPLE_FILES);
    assert.equal(await drop.send(envelope), 'received');
    assert.equal((await claimFileDrop(broker, drop.id)).ok, true);

    for (const line of logLines) {
      assert.ok(!line.includes(FILE_NAME), `a filename leaked into a log line: ${line}`);
      assert.ok(!line.includes('PGPASSWORD'), `file bytes leaked into a log line: ${line}`);
      assert.ok(!line.includes(drop.capability), `the capability leaked: ${line}`);
      assert.ok(!/[0-9a-f]{64}/.test(line), `a digest leaked into a log line: ${line}`);
    }
    // ...and the record itself keeps a count and a byte total, never a name.
    const snapshot = broker.testSnapshot(drop.id);
    assert.ok(!snapshot.serialized.includes(FILE_NAME));
    assert.ok(!snapshot.serialized.includes('PGPASSWORD'));
  });
});

describe('universal drops: the browser client contract', () => {
  let broker;

  beforeEach(async () => {
    broker = await testBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('sends a text secret into a universal link through the whole client flow', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const secret = 'a secret typed into the universal form';

    assert.deepEqual(
      await sendSecret({ capability: drop.capability, plaintext: secret, origin: broker.baseUrl }),
      { status: 'sent' },
    );
    const claimed = await broker.control({ op: 'claim', handoff_id: drop.id });
    assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), secret);
  });

  it('still refuses an oversized text secret against the advertised cap', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const outcome = await sendSecret({
      capability: drop.capability,
      plaintext: 'x'.repeat(broker.config.maxPlaintextBytes + 1),
      origin: broker.baseUrl,
    });
    assert.deepEqual(outcome, { status: 'too_large', limit: broker.config.maxPlaintextBytes });
    assert.equal(broker.testSnapshot(drop.id).state, 'pending');
  });

  it('derives the declaration from the sealed envelope and repeats it on retry', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const container = await drop.sealFiles(SAMPLE_FILES);
    const secret = await drop.sealText('a secret');

    // Whatever casing the client chooses, the header a server reads is the same
    // one, so the test looks it up the way `node:http` would.
    const declarationOf = (headers) =>
      headers[Object.keys(headers).find((key) => key.toLowerCase() === DECLARATION_HEADER)];

    const seen = [];
    const fetchImpl = async (url, options) => {
      seen.push({ declaration: declarationOf(options.headers), body: options.body });
      // Transient the first time, so the retry is the same bytes and the same
      // declaration rather than a fresh seal.
      return seen.length === 1
        ? { ok: false, status: 503 }
        : { ok: true, status: 200, json: async () => ({ status: 'received' }) };
    };

    assert.equal(
      await submitEnvelope({
        capability: drop.capability,
        envelope: container,
        fetchImpl,
        retryDelayMs: 0,
      }),
      'received',
    );
    assert.equal(seen.length, 2, 'one transient failure, one retry');
    assert.deepEqual(
      seen.map((attempt) => attempt.declaration),
      ['files', 'files'],
      'a container declares files, twice',
    );
    assert.equal(seen[0].body, seen[1].body, 'and the retry is the exact same sealed bytes');

    seen.length = 0;
    await submitEnvelope({
      capability: drop.capability,
      envelope: secret,
      fetchImpl: async (url, options) => {
        seen.push({ declaration: declarationOf(options.headers) });
        return { ok: true, status: 200 };
      },
    });
    assert.deepEqual(seen.map((attempt) => attempt.declaration), ['text']);
  });

  it('refuses universal metadata that does not advertise the pair it can seal', async () => {
    const drop = await createUniversalDrop(broker, { ttlSeconds: TTL_SECONDS });
    const cases = [
      { envelope_versions: { text: 1, files: 3 } },
      { envelope_versions: { text: 2, files: 2 } },
      { envelope_versions: undefined },
      { v: 2 },
      { payload_declaration: 'x-something-else' },
      { accepts: ['text'] },
    ];

    for (const patch of cases) {
      const metadata = { ...drop.metadata, ...patch };
      const outcome = await fetchMetadata({
        capability: drop.capability,
        origin: broker.baseUrl,
        fetchImpl: async () => ({ ok: true, json: async () => metadata }),
      });
      assert.equal(outcome, null, `metadata patched with ${JSON.stringify(patch)} must be refused`);
    }

    // The real thing is accepted, so the guard is not simply always-null.
    assert.ok(await fetchMetadata({ capability: drop.capability, origin: broker.baseUrl }));
  });
});
