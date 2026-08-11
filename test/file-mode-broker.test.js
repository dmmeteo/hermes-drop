// Slice 2 of docs/FILE_TRANSFER_MVP.md — the broker's file mode.
//
// What is pinned here is everything the broker must do before a file drop can
// exist at all: it mints one, it advertises the count and byte limits as
// *authorized metadata* rather than trusting the browser for them, it accepts an
// HPKE envelope bound to version 2 and no other version, it validates the whole
// HDROP2 container after the AEAD succeeds and before the record ever reaches
// `submitted`, and it does none of that to a text drop.
//
// The version binding is the point of the file: `docs/FILE_TRANSFER_MVP.md`
// records that envelope v2 is a *required integration*, not something the codec
// delivers on its own. So the checks below are deliberately cross-wired — a v1
// envelope offered to a file drop, a v2 envelope offered to a text drop, and a
// container sealed with the wrong version in `info` — because each of those is a
// different layer failing, and only the last of them may cost the AEAD budget.
//
// Nothing here asserts on file bytes or filenames beyond proving they never
// escape: the broker retains a count and a byte total and nothing else.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { afterEach, beforeEach, describe, it } from 'node:test';

import { fetchMetadata, sealEnvelope, sendSecret } from '../src/client/handoff-client.js';
import { DEFAULTS, loadConfig } from '../src/config.js';
import {
  FILE_ENVELOPE_VERSION,
  encodeFileContainer,
  fileContainerCeiling,
} from '../src/file-container.js';
import { ENVELOPE_VERSION } from '../src/hpke-suite.js';
import {
  createFileDrop,
  sealFileEnvelope,
  splitHandoffUrl,
  startTestBroker,
} from './helpers/harness.js';

const MIB = 1024 * 1024;
const TTL_SECONDS = 120;

const utf8 = (text) => new TextEncoder().encode(text);

/** A distinctive filename and body, so a leak into a log or a snapshot is visible. */
const FILE_NAME = 'client-secrets.env';
const FILE_BODY = 'PGPASSWORD=example-not-a-real-secret\n';
const SAMPLE_FILES = [{ name: FILE_NAME, type: 'text/plain', bytes: utf8(FILE_BODY) }];

function testBroker(overrides = {}) {
  return startTestBroker({ sweepIntervalMs: 3_600_000, ...overrides });
}

describe('file mode: configuration', () => {
  it('ships the MVP defaults as its own config keys, separate from the text cap', () => {
    const config = loadConfig({}, {});
    assert.equal(config.maxFiles, 5);
    assert.equal(config.maxFileBytes, 42 * MIB);
    assert.equal(config.maxFileTotalBytes, 42 * MIB);
    // Four fully reserved drops, where a reservation is the whole container
    // ceiling — 42 MiB of file bytes plus the header and manifest ceiling the
    // broker will really be holding alongside them.
    assert.equal(config.maxLiveFileBytes, 4 * fileContainerCeiling(config.fileLimits));
    assert.equal(config.maxLiveFileBytes, 4 * (42 * MIB + 6447));
    assert.equal(config.maxPlaintextBytes, 65536, 'the secret cap is untouched by file mode');
    assert.equal(DEFAULTS.maxFileTotalBytes, 42 * MIB);
  });

  it('reads every file key from the environment', () => {
    const config = loadConfig(
      {},
      {
        HANDOFF_MAX_FILES: '2',
        HANDOFF_MAX_FILE_BYTES: String(MIB),
        HANDOFF_MAX_FILE_TOTAL_BYTES: String(2 * MIB),
        HANDOFF_MAX_LIVE_FILE_BYTES: String(8 * MIB),
      },
    );
    assert.equal(config.maxFiles, 2);
    assert.equal(config.maxFileBytes, MIB);
    assert.equal(config.maxFileTotalBytes, 2 * MIB);
    assert.equal(config.maxLiveFileBytes, 8 * MIB);
  });

  it('lets an operator narrow every file limit', () => {
    const config = loadConfig({ maxFiles: 1, maxFileBytes: 1024, maxFileTotalBytes: 1024 });
    assert.equal(config.maxFiles, 1);
    assert.equal(config.fileLimits.maxTotalBytes, 1024);
  });

  it('refuses an attempt to raise any of them past the reviewed default', () => {
    for (const overrides of [
      { maxFiles: 6 },
      { maxFileBytes: 43 * MIB },
      { maxFileTotalBytes: 43 * MIB },
      { maxLiveFileBytes: 169 * MIB },
    ]) {
      assert.throws(
        () => loadConfig(overrides),
        /may only be lowered|limits_too_high/,
        `${JSON.stringify(overrides)} must be refused at startup`,
      );
    }
  });

  it('refuses an incoherent pair rather than resolving it silently', () => {
    // A per-file cap above the total cap cannot describe anything.
    assert.throws(() => loadConfig({ maxFileBytes: 8 * MIB, maxFileTotalBytes: 4 * MIB }));
    // A live budget under one drop's reservation means no file drop can ever be
    // created — a deployment that is broken at startup, not at submit time.
    assert.throws(() => loadConfig({ maxLiveFileBytes: 4 * MIB, maxFileTotalBytes: 8 * MIB }));
    assert.throws(() => loadConfig({ maxFiles: 0 }));
    assert.throws(() => loadConfig({ maxFileTotalBytes: 0 }));
  });

  it('names the offending environment key when it refuses', () => {
    assert.throws(
      () => loadConfig({}, { HANDOFF_MAX_FILES: '9' }),
      /HANDOFF_MAX_FILES|HANDOFF_MAX_FILE/,
    );
  });

  // Every byte constant the README prints is a value an operator will paste into
  // an env file, and `loadConfig` refuses anything above the default — so a README
  // number that is merely *wrong* is a startup crash for whoever trusts it. The
  // table is therefore held against the loader rather than proof-read.
  it('loads every default the README prints, unchanged', async () => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
    const rows = [...readme.matchAll(/^\| `(HANDOFF_[A-Z_]+)` \| `(\d+)`/gm)];
    const printed = Object.fromEntries(rows.map((row) => [row[1], row[2]]));

    const FILE_KEYS = {
      HANDOFF_MAX_FILES: 'maxFiles',
      HANDOFF_MAX_FILE_BYTES: 'maxFileBytes',
      HANDOFF_MAX_FILE_TOTAL_BYTES: 'maxFileTotalBytes',
      HANDOFF_MAX_LIVE_FILE_BYTES: 'maxLiveFileBytes',
    };
    for (const [envKey, configKey] of Object.entries(FILE_KEYS)) {
      assert.ok(printed[envKey], `${envKey} must appear in the README with its byte default`);
      assert.equal(
        Number(printed[envKey]),
        DEFAULTS[configKey],
        `the README default for ${envKey} is not the shipped one`,
      );
      // And it really loads: a printed number above the default is a hard throw.
      const config = loadConfig({}, { [envKey]: printed[envKey] });
      assert.equal(config[configKey], DEFAULTS[configKey]);
    }
  });
});

describe('file mode: minting and advertised limits', () => {
  let broker;

  beforeEach(async () => {
    broker = await testBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('mints a file-kind handoff over the same control seam', async () => {
    const created = await broker.control({
      op: 'create',
      payload_kind: 'files',
      ttl_seconds: TTL_SECONDS,
    });

    assert.equal(created.ok, true, JSON.stringify(created));
    assert.equal(created.payload_kind, 'files');
    assert.equal(created.max_files, 5);
    assert.equal(created.max_file_bytes, 42 * MIB);
    assert.equal(created.max_total_bytes, 42 * MIB);
    assert.match(created.url, /^http:\/\/127\.0\.0\.1:\d+\/#[A-Za-z0-9_-]{22}$/);
    assert.ok(
      !('max_plaintext_bytes' in created),
      'the secret cap says nothing about a file drop and must not be quoted at one',
    );
  });

  it('advertises which payload kinds this broker speaks, so a plugin need not guess', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    assert.deepEqual(created.payload_kinds, ['text', 'files']);
    assert.equal(created.protocol_version, 2, 'file mode is additive; the protocol did not move');
  });

  it('keeps a text drop exactly as it was', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    assert.equal(created.ok, true);
    assert.equal(created.payload_kind, 'text');
    assert.equal(created.max_plaintext_bytes, 65536);
    for (const key of ['max_files', 'max_file_bytes', 'max_total_bytes']) {
      assert.ok(!(key in created), `${key} is meaningless on a text drop`);
    }
  });

  it('refuses an unsupported payload kind without minting anything', async () => {
    for (const payload_kind of ['file', 'FILES', 'binary', '', 42, null, '__proto__']) {
      const response = await broker.control({ op: 'create', payload_kind });
      assert.deepEqual(
        response,
        { ok: false, error: 'invalid_request' },
        `payload_kind ${JSON.stringify(payload_kind)} must be refused`,
      );
      assert.ok(!('url' in response), 'a refused kind must not burn a handoff');
    }
  });

  it('lets a requester narrow the file count and never raise it', async () => {
    const narrowed = await broker.control({
      op: 'create',
      payload_kind: 'files',
      max_files: 2,
      ttl_seconds: TTL_SECONDS,
    });
    assert.equal(narrowed.max_files, 2);

    const raised = await broker.control({
      op: 'create',
      payload_kind: 'files',
      max_files: 50,
      ttl_seconds: TTL_SECONDS,
    });
    assert.equal(raised.max_files, 5, 'a request may only narrow the operator limit');
  });

  it('refuses a file count on a text drop instead of ignoring it', async () => {
    const response = await broker.control({ op: 'create', max_files: 3 });
    assert.deepEqual(response, { ok: false, error: 'invalid_request' });
  });

  it('refuses an unusable file count without minting anything', async () => {
    for (const max_files of [0, -1, 2.5, '2', null]) {
      const response = await broker.control({ op: 'create', payload_kind: 'files', max_files });
      assert.deepEqual(
        response,
        { ok: false, error: 'invalid_request' },
        `max_files ${JSON.stringify(max_files)} must be refused`,
      );
    }
  });

  it('publishes the kind and the limits as authorized page metadata', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });

    assert.equal(drop.metadata.payload_kind, 'files');
    assert.equal(drop.metadata.v, FILE_ENVELOPE_VERSION);
    assert.equal(drop.metadata.max_files, 5);
    assert.equal(drop.metadata.max_total_bytes, 42 * MIB);
    assert.equal(drop.metadata.max_file_bytes, 42 * MIB);
    assert.equal(drop.metadata.hid, drop.id);
    assert.ok(Number.isInteger(drop.metadata.now));
    assert.ok(
      !('max_plaintext_bytes' in drop.metadata),
      'a file page sizes itself from the file limits, not from the secret cap',
    );
  });

  it('keeps text metadata on version 1 with the cap it always had', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    const capability = splitHandoffUrl(created.url).capability;
    const metadata = await fetchMetadata({ capability, origin: broker.baseUrl });

    assert.equal(metadata.v, ENVELOPE_VERSION);
    assert.equal(metadata.payload_kind, 'text');
    assert.equal(metadata.max_plaintext_bytes, 65536);
    for (const key of ['max_files', 'max_file_bytes', 'max_total_bytes']) {
      assert.ok(!(key in metadata), `${key} must not appear on a text drop`);
    }
  });

  it('stops the text send flow at a file drop rather than sealing into it', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.deepEqual(
      await sendSecret({
        capability: drop.capability,
        plaintext: 'a secret typed into the wrong page',
        origin: broker.baseUrl,
      }),
      { status: 'unavailable' },
    );
    assert.equal(broker.testSnapshot(drop.id).state, 'pending', 'and nothing was consumed');
  });
});

describe('file mode: envelope version binding', () => {
  let broker;

  beforeEach(async () => {
    broker = await testBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('accepts an envelope v2 carrying a valid container', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await drop.seal(SAMPLE_FILES);

    assert.equal(envelope.v, FILE_ENVELOPE_VERSION);
    assert.equal(await drop.send(envelope), 'received');

    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'submitted');
    assert.equal(snapshot.hasPlaintext, true);
    assert.equal(snapshot.hasPrivateKey, false, 'the key dies the moment the AEAD succeeds');
    assert.equal(snapshot.payloadKind, 'files');
    assert.equal(snapshot.fileCount, 1);
    assert.equal(snapshot.fileTotalBytes, FILE_BODY.length);
  });

  it('refuses a version 1 envelope offered to a file drop, before any crypto', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const wrongVersion = await sealFileEnvelope({
      capability: drop.capability,
      metadata: drop.metadata,
      files: SAMPLE_FILES,
    });

    assert.equal(await drop.send({ ...wrongVersion, v: ENVELOPE_VERSION }), 'unavailable');
    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'pending', 'a shape refusal consumes nothing');
    assert.equal(snapshot.aeadFailures, 0, 'and costs nothing from the AEAD budget');
    assert.equal(snapshot.containerFailures, 0, 'nor from the container budget');
  });

  it('refuses a version 2 envelope offered to a text drop, before any crypto', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    const capability = splitHandoffUrl(created.url).capability;
    const metadata = await fetchMetadata({ capability, origin: broker.baseUrl });
    const envelope = await sealEnvelope({ capability, metadata, plaintext: 'still a secret' });

    const response = await fetch(`${broker.baseUrl}/api/submit`, {
      method: 'POST',
      headers: { 'x-handoff-capability': capability, 'content-type': 'application/json' },
      body: JSON.stringify({ ...envelope, v: FILE_ENVELOPE_VERSION }),
    });
    assert.equal(response.ok, false);
    assert.equal(broker.testSnapshot(created.handoff_id).aeadFailures, 0);
    assert.equal(broker.testSnapshot(created.handoff_id).state, 'pending');
  });

  it('binds the version cryptographically, not just in the JSON field', async () => {
    // A container sealed with version 1 in `info` and relabelled `v: 2`. The shape
    // check passes; the AEAD cannot, because both sides derive `info` themselves.
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const container = await encodeFileContainer(SAMPLE_FILES);
    const { sealBytesEnvelope } = await import('../src/client/handoff-client.js');
    const misbound = await sealBytesEnvelope({
      capability: drop.capability,
      metadata: drop.metadata,
      bytes: container,
      version: ENVELOPE_VERSION,
    });

    assert.equal(await drop.send({ ...misbound, v: FILE_ENVELOPE_VERSION }), 'unavailable');
    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'pending', 'a forgery must not consume the drop');
    assert.equal(snapshot.aeadFailures, 1, 'this one is a real AEAD failure and is charged');

    // The honestly bound envelope still works.
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');
  });

  it('refuses every malformed envelope shape without consuming the drop', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const good = await drop.seal(SAMPLE_FILES);

    const mutations = {
      'version 0': { ...good, v: 0 },
      'version 3': { ...good, v: 3 },
      'version as a string': { ...good, v: '2' },
      'unlisted suite': { ...good, suite: 'DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM' },
      'foreign handoff id': { ...good, hid: 'B'.repeat(22) },
      'empty ciphertext': { ...good, ct: '' },
      'missing field': { v: good.v, suite: good.suite, hid: good.hid },
    };
    for (const [name, envelope] of Object.entries(mutations)) {
      assert.equal(await drop.send(envelope), 'unavailable', `${name} must be refused`);
    }
    assert.equal(broker.testSnapshot(drop.id).state, 'pending');
    assert.equal(broker.testSnapshot(drop.id).aeadFailures, 0);
    assert.equal(await drop.send(good), 'received');
  });

  it('sizes its ciphertext ceiling from the container ceiling, not the secret cap', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const good = await drop.seal(SAMPLE_FILES);

    // Comfortably past the 64 KiB text cap and comfortably under the file
    // ceiling: a file drop must not inherit the secret cap's refusal.
    const roomy = await drop.seal([
      { name: 'blob.bin', type: '', bytes: new Uint8Array(200_000).fill(7) },
    ]);
    assert.ok(roomy.ct.length > 65536);
    assert.ok(good.ct.length < roomy.ct.length, 'both are under the same file ceiling');
    assert.equal(await drop.send(roomy), 'received');
    assert.equal(broker.testSnapshot(drop.id).fileTotalBytes, 200_000);
  });

  it('widens the request-body ceiling for a file drop and for nothing else', async () => {
    // The default body ceiling is 128 KiB, sized for a 64 KiB secret. A container
    // has to be able to arrive anyway, and a text drop must not inherit the room.
    const config = broker.config;
    assert.equal(config.maxBodyBytes, 131072);

    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const big = await drop.seal([
      { name: 'blob.bin', type: '', bytes: new Uint8Array(300_000).fill(3) },
    ]);
    const body = JSON.stringify(big);
    assert.ok(body.length > config.maxBodyBytes, 'the body really is past the text ceiling');
    assert.equal(await drop.send(big), 'received');
    assert.equal(broker.testSnapshot(drop.id).fileTotalBytes, 300_000);

    // The same body offered to a text drop is dropped before any crypto, exactly
    // as it was before file mode existed.
    const text = await broker.control({ op: 'create', ttl_seconds: TTL_SECONDS });
    const response = await fetch(`${broker.baseUrl}/api/submit`, {
      method: 'POST',
      headers: {
        'x-handoff-capability': splitHandoffUrl(text.url).capability,
        'content-type': 'application/json',
      },
      body,
    });
    assert.equal(response.status, 404);
    assert.equal(broker.testSnapshot(text.handoff_id).state, 'pending');
  });

  it('refuses a ciphertext past the container ceiling before any crypto work', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const good = await drop.seal(SAMPLE_FILES);
    const ceiling = fileContainerCeiling();
    const oversize = 'A'.repeat(Math.ceil(((ceiling + 16) * 4) / 3) + 64);

    assert.equal(await drop.send({ ...good, ct: oversize }), 'unavailable');
    assert.equal(broker.testSnapshot(drop.id).state, 'pending');
    assert.equal(broker.testSnapshot(drop.id).aeadFailures, 0);
  });
});

describe('file mode: container validation stands between submitted and the payload', () => {
  let broker;
  let logLines;

  beforeEach(async () => {
    logLines = [];
    const capture = (level) => (message) => logLines.push(`${level} ${message}`);
    // Narrowed per-drop caps, so a test that mints one drop per malformed case
    // is not refused by the live-file budget partway through. Narrowing is the
    // supported direction, and it changes nothing about the validation itself.
    broker = await testBroker({
      maxFileBytes: 65536,
      maxFileTotalBytes: 65536,
      logger: { info: capture('info'), warn: capture('warn'), error: capture('error') },
    });
  });

  afterEach(async () => {
    await broker.stop();
  });

  /** Seals arbitrary bytes as a genuine v2 envelope: the AEAD will succeed. */
  async function sealBytes(drop, bytes) {
    const { sealBytesEnvelope } = await import('../src/client/handoff-client.js');
    return sealBytesEnvelope({
      capability: drop.capability,
      metadata: drop.metadata,
      bytes,
      version: FILE_ENVELOPE_VERSION,
    });
  }

  it('refuses a decryptable payload that is not a container, and stays pending', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelope = await sealBytes(drop, utf8('this is just a secret, not a container'));

    assert.equal(await drop.send(envelope), 'unavailable');
    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'pending', 'validation failure never reaches submitted');
    assert.equal(snapshot.hasPlaintext, false, 'and never retains the payload');
    assert.equal(snapshot.aeadFailures, 0, 'the AEAD succeeded; this is not an AEAD failure');
    assert.equal(snapshot.containerFailures, 1);
  });

  it('refuses each way a container can be malformed', async () => {
    const valid = await encodeFileContainer(SAMPLE_FILES);
    const cases = {
      'shorter than a header': new Uint8Array(4),
      'bad magic': (() => {
        const bytes = valid.slice();
        bytes[0] = 0x48 ^ 0xff;
        return bytes;
      })(),
      'truncated manifest': valid.subarray(0, 12),
      'truncated payload': valid.subarray(0, valid.length - 1),
      'flipped payload byte': (() => {
        const bytes = valid.slice();
        bytes[bytes.length - 1] ^= 0xff;
        return bytes;
      })(),
      'trailing byte': (() => {
        const bytes = new Uint8Array(valid.length + 1);
        bytes.set(valid, 0);
        return bytes;
      })(),
    };

    for (const [name, bytes] of Object.entries(cases)) {
      const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
      assert.equal(await drop.send(await sealBytes(drop, bytes)), 'unavailable', name);
      assert.equal(broker.testSnapshot(drop.id).state, 'pending', name);
      assert.equal(broker.testSnapshot(drop.id).containerFailures, 1, name);
    }
  });

  it('refuses an empty payload before decrypting it, as the text path always has', async () => {
    // A zero-byte plaintext seals to a bare AEAD tag, and the ciphertext floor
    // catches it before any key is used — so it never reaches the container check
    // and costs nothing from either failure budget.
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await drop.send(await sealBytes(drop, new Uint8Array(0))), 'unavailable');

    const snapshot = broker.testSnapshot(drop.id);
    assert.equal(snapshot.state, 'pending');
    assert.equal(snapshot.aeadFailures, 0);
    assert.equal(snapshot.containerFailures, 0);
  });

  it('enforces the drop`s own narrowed file count against the container', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS, maxFiles: 1 });
    assert.equal(drop.metadata.max_files, 1);

    // Encoded against the *default* limits, so the container itself is honest —
    // it is only over the limit this particular drop advertised.
    const twoFiles = await encodeFileContainer([
      { name: 'a.txt', type: 'text/plain', bytes: utf8('a') },
      { name: 'b.txt', type: 'text/plain', bytes: utf8('b') },
    ]);
    assert.equal(await drop.send(await sealBytes(drop, twoFiles)), 'unavailable');
    assert.equal(broker.testSnapshot(drop.id).state, 'pending');
    assert.equal(broker.testSnapshot(drop.id).containerFailures, 1);

    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');
  });

  it('destroys the drop after a bounded number of container failures', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const junk = utf8('not a container');
    // Read from the config rather than hard-coded, or a moved default would make
    // this pass vacuously.
    const budget = broker.config.maxAeadFailures;

    for (let attempt = 0; attempt < budget; attempt += 1) {
      assert.equal(await drop.send(await sealBytes(drop, junk)), 'unavailable', `attempt ${attempt}`);
    }
    assert.equal(broker.testSnapshot(drop.id), null, 'destroyed, exactly like the AEAD budget');
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'unavailable');
  });

  it('keeps filenames out of the record, the snapshot and every log line', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');

    const snapshot = broker.testSnapshot(drop.id);
    assert.ok(!snapshot.serialized.includes(FILE_NAME), 'the record retains no filename');
    assert.ok(!snapshot.serialized.includes(FILE_BODY), 'and no file bytes');
    assert.ok(!snapshot.serialized.includes('text/plain'), 'and no MIME hint');
    assert.ok(logLines.length > 0);
    for (const line of logLines) {
      assert.ok(!line.includes(FILE_NAME), `filename leaked into a log line: ${line}`);
      assert.ok(!line.includes(FILE_BODY.trim()), `file bytes leaked into a log line: ${line}`);
      assert.ok(!line.includes(drop.capability), `capability leaked into a log line: ${line}`);
    }
  });
});

describe('file mode: the text claim path stays text-only', () => {
  let broker;

  beforeEach(async () => {
    broker = await testBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  it('refuses to hand a container down the newline-delimited claim seam', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');

    assert.deepEqual(await broker.control({ op: 'claim', handoff_id: drop.id }), {
      ok: false,
      error: 'unavailable',
    });
    assert.equal(
      broker.testSnapshot(drop.id).state,
      'submitted',
      'a refusal is not a claim: the payload waits for the slice 3 transfer',
    );
    assert.equal(broker.testSnapshot(drop.id).hasPlaintext, true);
  });

  it('still reports the submission over `await`, which carries no payload', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');

    const awaited = await broker.control({ op: 'await', handoff_id: drop.id, wait_ms: 0 });
    assert.deepEqual(awaited, { ok: true, handoff_id: drop.id, status: 'submitted' });
  });

  it('kills the page the instant the container lands', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    assert.equal(await drop.send(await drop.seal(SAMPLE_FILES)), 'received');

    assert.equal(await fetchMetadata({ capability: drop.capability, origin: broker.baseUrl }), null);
  });

  it('answers an identical retry with the same receipt, and a different one with unavailable', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const winner = await drop.seal(SAMPLE_FILES);
    const other = await drop.seal([{ name: 'other.txt', type: '', bytes: utf8('different') }]);

    assert.equal(await drop.send(winner), 'received');
    assert.equal(await drop.send(winner), 'received', 'the retry is idempotent');
    assert.equal(await drop.send(other), 'unavailable');
    assert.equal(broker.testSnapshot(drop.id).fileCount, 1);
    assert.equal(broker.testSnapshot(drop.id).fileTotalBytes, FILE_BODY.length);
  });

  it('lets exactly one of many concurrent containers win', async () => {
    const drop = await createFileDrop(broker, { ttlSeconds: TTL_SECONDS });
    const envelopes = await Promise.all(
      ['a', 'b', 'c', 'd', 'e'].map((tag) =>
        drop.seal([{ name: `${tag}.txt`, type: '', bytes: utf8(tag.repeat(16)) }]),
      ),
    );

    const outcomes = await Promise.all(envelopes.map((envelope) => drop.send(envelope)));
    assert.equal(outcomes.filter((outcome) => outcome === 'received').length, 1);
    assert.equal(broker.testSnapshot(drop.id).state, 'submitted');
    assert.equal(broker.testSnapshot(drop.id).fileTotalBytes, 16);
  });
});
