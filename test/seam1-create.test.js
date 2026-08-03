// Seam 1 — Local admin CLI creates a handoff and prints a URL.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { decodeBase64Url, splitHandoffUrl, startTestBroker } from './helpers/harness.js';

const execFileAsync = promisify(execFile);
const ADMIN_CLI = fileURLToPath(new URL('../bin/handoff-admin.mjs', import.meta.url));

describe('seam 1: create a handoff over the local control path', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  it('returns a handoff url that carries the capability in the fragment only', async () => {
    const created = await broker.control({ op: 'create' });

    assert.equal(created.ok, true);
    assert.match(created.url, /^http:\/\/127\.0\.0\.1:\d+\/#[A-Za-z0-9_-]{22}$/);

    const { target, capability } = splitHandoffUrl(created.url);
    assert.equal(target, `${broker.baseUrl}/`);
    assert.ok(capability, 'capability must be present in the fragment');
    assert.doesNotMatch(target, /[?&=]/, 'request target must carry no query parameters');
    assert.ok(!target.includes(capability), 'capability must not appear in path or query');
  });

  it('mints exactly 128 bits of CSPRNG capability entropy per handoff', async () => {
    const seen = new Set();
    for (let i = 0; i < 16; i += 1) {
      const { capability } = splitHandoffUrl((await broker.control({ op: 'create' })).url);
      assert.equal(decodeBase64Url(capability).length, 16, 'capability must decode to 16 bytes');
      assert.equal(capability.length, 22, 'unpadded base64url of 16 bytes is 22 characters');
      seen.add(capability);
    }
    assert.equal(seen.size, 16, 'capabilities must never repeat');
  });

  it('reports a non-secret handoff id and an absolute expiry defaulting to 30 minutes', async () => {
    const before = Date.now();
    const created = await broker.control({ op: 'create' });
    const after = Date.now();

    assert.match(created.handoff_id, /^[A-Za-z0-9_-]{22}$/);
    assert.equal(created.ttl_seconds, 1800);
    assert.ok(created.expires_at >= before + 1_800_000);
    assert.ok(created.expires_at <= after + 1_800_000);
    assert.equal(created.max_plaintext_bytes, 65536);
    assert.ok(!('capability' in created), 'control response must not echo the capability field');
    assert.ok(!('private_key' in created), 'control response must not expose key material');
  });

  it('honours a deployment-supplied ttl and refuses an absurd one', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: 30 });
    assert.equal(created.ttl_seconds, 30);

    const rejected = await broker.control({ op: 'create', ttl_seconds: 99_999 });
    assert.equal(rejected.ok, false);
    assert.equal(rejected.error, 'invalid_request');
  });

  it('retains no capability value in broker state, only its hash', async () => {
    const created = await broker.control({ op: 'create' });
    const { capability } = splitHandoffUrl(created.url);

    const snapshot = broker.testSnapshot(created.handoff_id);
    assert.equal(snapshot.state, 'pending');
    assert.equal(snapshot.hasPrivateKey, true);
    assert.equal(snapshot.hasPlaintext, false);
    assert.equal(snapshot.capabilityHashHex.length, 64);
    assert.ok(
      !snapshot.serialized.includes(capability),
      'the capability itself must never be retained in broker state',
    );
  });

  it('prints exactly one handoff url to stdout from the admin cli', async () => {
    const { stdout, stderr } = await execFileAsync(process.execPath, [ADMIN_CLI, 'create'], {
      env: { ...process.env, HANDOFF_CONTROL_SOCKET: broker.controlSocketPath },
    });

    const lines = stdout.trim().split('\n');
    assert.equal(lines.length, 1);
    assert.match(lines[0], /^http:\/\/127\.0\.0\.1:\d+\/#[A-Za-z0-9_-]{22}$/);
    assert.doesNotMatch(stderr, /error/i);
  });
});
