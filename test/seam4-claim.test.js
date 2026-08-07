// Seam 4 — the local admin CLI claims the handoff, emits the plaintext to stdout
// exactly once, and every later claim fails safely.
//
// The CLI is driven as a real child process, so what is asserted is what an
// operator would actually see on stdout/stderr and in the exit code.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { sendSecret } from '../src/client/handoff-client.js';
import { splitHandoffUrl, startTestBroker } from './helpers/harness.js';

const ADMIN_CLI = fileURLToPath(new URL('../bin/handoff-admin.mjs', import.meta.url));
// The response-size numbers are the shared fixture's, never restated here: this
// seam is where they have to hold against a real payload.
const CONTRACT = JSON.parse(
  await readFile(new URL('../contract/control-protocol.json', import.meta.url), 'utf8'),
);
const SECRET = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI\nline two\ttab\tand ünïcode ✓';
// Big enough that its claim response clears the contract's minimum ceiling, so a
// refusal can be provoked with a ceiling the broker will actually accept. The
// small SECRET above cannot: its whole response is ~160 bytes, well under the
// floor, and every ceiling that would refuse it is a caller mistake instead.
const BIG_SECRET = `${SECRET}\n${'kty=OKP;crv=Ed25519;d='.repeat(80)}`;

describe('seam 4: claiming the payload from the local control path', () => {
  let broker;
  let logLines;

  beforeEach(async () => {
    logLines = [];
    const capture = (level) => (message) => logLines.push(`${level} ${message}`);
    broker = await startTestBroker({
      logger: { info: capture('info'), warn: capture('warn'), error: capture('error') },
    });
  });

  afterEach(async () => {
    await broker.stop();
  });

  function admin(args) {
    return new Promise((resolve) => {
      execFile(
        process.execPath,
        [ADMIN_CLI, ...args],
        {
          encoding: 'buffer',
          env: { ...process.env, HANDOFF_CONTROL_SOCKET: broker.controlSocketPath },
        },
        (error, stdout, stderr) => {
          resolve({
            code: error?.code ?? 0,
            stdout,
            stderr: stderr.toString('utf8'),
          });
        },
      );
    });
  }

  async function createHandoff(options) {
    const created = await broker.control({ op: 'create', ...options });
    return { ...created, capability: splitHandoffUrl(created.url).capability };
  }

  async function submit(handoff, plaintext = SECRET) {
    const result = await sendSecret({
      capability: handoff.capability,
      plaintext,
      origin: broker.baseUrl,
    });
    assert.equal(result.status, 'sent');
  }

  it('emits the exact submitted bytes to stdout and nothing else', async () => {
    const handoff = await createHandoff();
    await submit(handoff);

    const claimed = await admin(['claim', handoff.handoff_id]);
    assert.equal(claimed.code, 0);
    assert.equal(claimed.stdout.toString('utf8'), SECRET, 'byte-exact payload on stdout');
    assert.equal(claimed.stderr, '', 'no diagnostics on a successful claim');
  });

  it('fails safely on the second claim, with no partial output', async () => {
    const handoff = await createHandoff();
    await submit(handoff);

    const first = await admin(['claim', handoff.handoff_id]);
    const second = await admin(['claim', handoff.handoff_id]);

    assert.equal(first.code, 0);
    assert.equal(second.code, 1);
    assert.equal(second.stdout.length, 0, 'a refused claim writes nothing to stdout');
    assert.match(second.stderr, /unavailable/);
    const snapshot = broker.testSnapshot(handoff.handoff_id);
    assert.equal(snapshot.state, 'claimed', 'a payload-free receipt survives until the TTL');
    assert.equal(snapshot.hasPlaintext, false);
    assert.equal(snapshot.hasPrivateKey, false);
  });

  it('gives the same refusal for consumed, never-submitted and unknown handoffs', async () => {
    const consumed = await createHandoff();
    await submit(consumed);
    await admin(['claim', consumed.handoff_id]);

    const pending = await createHandoff();

    const outcomes = await Promise.all([
      admin(['claim', consumed.handoff_id]),
      admin(['claim', pending.handoff_id]),
      admin(['claim', 'AAAAAAAAAAAAAAAAAAAAAA']),
      admin(['claim', 'not-a-handoff-id']),
    ]);

    for (const outcome of outcomes) {
      assert.equal(outcome.code, 1);
      assert.equal(outcome.stdout.length, 0);
      assert.equal(outcome.stderr, 'claim unavailable: unavailable\n');
    }
    assert.equal(broker.testSnapshot(pending.handoff_id).state, 'pending', 'not consumed');
  });

  it('waits for a pending handoff and then claims it once', async () => {
    const handoff = await createHandoff();

    const claiming = admin(['claim', handoff.handoff_id, '--wait', '5']);
    // The browser submits while the operator is already waiting.
    await new Promise((resolve) => setTimeout(resolve, 120));
    await submit(handoff);

    const claimed = await claiming;
    assert.equal(claimed.code, 0);
    assert.equal(claimed.stdout.toString('utf8'), SECRET);
    assert.equal(broker.testSnapshot(handoff.handoff_id).hasPlaintext, false);
  });

  it('stops waiting when the handoff expires unclaimed', async () => {
    const handoff = await createHandoff({ ttl_seconds: 1 });

    const claimed = await admin(['claim', handoff.handoff_id, '--wait', '5']);
    assert.equal(claimed.code, 1);
    assert.equal(claimed.stdout.length, 0);
    assert.match(claimed.stderr, /unavailable/);
    assert.equal(broker.testSnapshot(handoff.handoff_id), null, 'expiry destroyed it');
  });

  it('exposes no claim path on the public HTTP surface', async () => {
    const handoff = await createHandoff();
    await submit(handoff);

    for (const path of ['/api/claim', '/claim', '/api/handoffs', '/admin']) {
      for (const method of ['GET', 'POST']) {
        const response = await fetch(`${broker.baseUrl}${path}`, {
          method,
          headers: { 'x-handoff-capability': handoff.capability },
        });
        const body = await response.text();
        assert.equal(response.status, 404, `${method} ${path}`);
        assert.ok(!body.includes(SECRET), `${method} ${path} must not return plaintext`);
        assert.ok(!body.includes(handoff.handoff_id));
      }
    }

    // Still claimable afterwards: none of those probes consumed anything.
    const claimed = await admin(['claim', handoff.handoff_id]);
    assert.equal(claimed.stdout.toString('utf8'), SECRET);
  });

  it('keeps the control socket private to the broker owner', async () => {
    const info = await stat(broker.controlSocketPath);
    assert.equal(info.mode & 0o777, 0o600);
  });

  it('creates its socket directory as 0700, so the socket is never exposed', async () => {
    const base = await mkdtemp(join(tmpdir(), 'handoff-socketdir-'));
    const socketDir = join(base, 'nested', 'run');
    const instance = await startTestBroker({ controlSocketPath: join(socketDir, 'control.sock') });
    try {
      assert.equal((await stat(socketDir)).mode & 0o777, 0o700, 'socket directory must be 0700');
      assert.equal((await stat(join(socketDir, 'control.sock'))).mode & 0o777, 0o600);
    } finally {
      await instance.stop();
      await rm(base, { recursive: true, force: true });
    }
  });

  it('tightens a pre-existing permissive socket directory before listening', async () => {
    const base = await mkdtemp(join(tmpdir(), 'handoff-socketdir-'));
    const socketDir = join(base, 'run');
    await mkdir(socketDir, { recursive: true });
    await chmod(socketDir, 0o755);

    const instance = await startTestBroker({ controlSocketPath: join(socketDir, 'control.sock') });
    try {
      assert.equal((await stat(socketDir)).mode & 0o777, 0o700);
    } finally {
      await instance.stop();
      await rm(base, { recursive: true, force: true });
    }
  });

  // ── the response-size capability ─────────────────────────────────────────
  //
  // `claim` retires the record before its response is written, so a response the
  // caller cannot read is a secret nobody gets — the one lossy window a local
  // socket still had. A caller that reads a bounded line says so in the request,
  // and the broker sizes the answer *before* consuming anything.
  describe('a claim that advertises a reader ceiling', () => {
    /** The exact bytes a successful claim would put on the wire, newline included. */
    function claimLineBytes(handoffId, plaintext) {
      const body = {
        ok: true,
        handoff_id: handoffId,
        plaintext_b64: Buffer.from(plaintext, 'utf8').toString('base64'),
      };
      return Buffer.byteLength(`${JSON.stringify(body)}\n`, 'utf8');
    }

    it('refuses, names both numbers, and consumes nothing', async () => {
      const handoff = await createHandoff();
      await submit(handoff, BIG_SECRET);
      const needed = claimLineBytes(handoff.handoff_id, BIG_SECRET);

      const refused = await broker.control({
        op: 'claim',
        handoff_id: handoff.handoff_id,
        max_response_bytes: needed - 1,
      });

      assert.deepEqual(refused, {
        ok: false,
        error: 'response_too_large',
        required_bytes: needed,
        max_response_bytes: needed - 1,
      });

      const snapshot = broker.testSnapshot(handoff.handoff_id);
      assert.equal(snapshot.state, 'submitted', 'a refused claim is not a claim');
      assert.equal(snapshot.hasPlaintext, true, 'the payload is still there to be claimed');

      // And it really is still claimable: the whole point is that the refusal
      // cost nothing.
      const claimed = await admin(['claim', handoff.handoff_id]);
      assert.equal(claimed.code, 0, claimed.stderr);
      assert.equal(claimed.stdout.toString('utf8'), BIG_SECRET);
    });

    it('sizes the answer exactly: one byte of headroom is enough', async () => {
      const handoff = await createHandoff();
      await submit(handoff, BIG_SECRET);
      const needed = claimLineBytes(handoff.handoff_id, BIG_SECRET);

      const claimed = await broker.control({
        op: 'claim',
        handoff_id: handoff.handoff_id,
        max_response_bytes: needed,
      });

      assert.equal(claimed.ok, true, JSON.stringify(claimed));
      assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), BIG_SECRET);
      assert.equal(
        Buffer.byteLength(`${JSON.stringify(claimed)}\n`, 'utf8'),
        needed,
        'required_bytes must be the real line length, not an estimate',
      );
      assert.equal(broker.testSnapshot(handoff.handoff_id).state, 'claimed', 'one shot, spent');
    });

    it('stays one-shot: an advertised ceiling does not buy a second claim', async () => {
      const handoff = await createHandoff();
      await submit(handoff, BIG_SECRET);
      const needed = claimLineBytes(handoff.handoff_id, BIG_SECRET);

      const first = await broker.control({
        op: 'claim',
        handoff_id: handoff.handoff_id,
        max_response_bytes: needed,
      });
      const second = await broker.control({
        op: 'claim',
        handoff_id: handoff.handoff_id,
        max_response_bytes: needed,
      });

      assert.equal(first.ok, true);
      assert.deepEqual(second, { ok: false, error: 'unavailable' });
    });

    it('refuses an unusable ceiling as a caller mistake, still consuming nothing', async () => {
      const handoff = await createHandoff();
      await submit(handoff);

      const belowMinimum = CONTRACT.transport.min_response_bytes - 1;
      for (const max_response_bytes of [0, -1, 1.5, '65536', null, {}, Number.NaN, belowMinimum]) {
        const response = await broker.control({
          op: 'claim',
          handoff_id: handoff.handoff_id,
          max_response_bytes,
        });
        assert.deepEqual(
          response,
          { ok: false, error: 'invalid_request' },
          `ceiling ${JSON.stringify(max_response_bytes)} is a caller mistake`,
        );
        assert.equal(broker.testSnapshot(handoff.handoff_id).hasPlaintext, true, 'not consumed');
      }
    });

    it('leaves an unbounded reader exactly as it was', async () => {
      // The admin CLI buffers the whole line in memory and advertises nothing;
      // omitting the field must therefore mean "no ceiling", not "the default".
      const handoff = await createHandoff();
      await submit(handoff);

      const claimed = await broker.control({ op: 'claim', handoff_id: handoff.handoff_id });
      assert.equal(claimed.ok, true);
      assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), SECRET);
    });

    it('fits its refusal inside the smallest ceiling it accepts', async () => {
      // Otherwise the contract would be incoherent: a client small enough to be
      // refused would be answered with a line it cannot read either, and would
      // report a transport fault for a configuration mistake. The minimum is what
      // makes "every conforming client can receive the refusal" checkable.
      const minimum = CONTRACT.transport.min_response_bytes;
      const handoff = await createHandoff();
      await submit(handoff, BIG_SECRET);

      const refused = await broker.control({
        op: 'claim',
        handoff_id: handoff.handoff_id,
        max_response_bytes: minimum,
      });

      assert.equal(refused.error, 'response_too_large', JSON.stringify(refused));
      assert.ok(
        Buffer.byteLength(`${JSON.stringify(refused)}\n`, 'utf8') <= minimum,
        'the refusal must fit in the ceiling that produced it',
      );
      assert.equal(broker.testSnapshot(handoff.handoff_id).hasPlaintext, true, 'not consumed');

      // The contract's claim is about *every* non-payload answer `claim` can
      // give, not just this one — that is what "a conforming client can always
      // read the answer it gets" means, so all three are measured.
      const others = [
        await broker.control({ op: 'claim', handoff_id: 'AAAAAAAAAAAAAAAAAAAAAA' }),
        await broker.control({ op: 'claim', handoff_id: 42 }),
      ];
      for (const answer of [refused, ...others]) {
        assert.ok(
          Buffer.byteLength(`${JSON.stringify(answer)}\n`, 'utf8') <= minimum,
          `${answer.error} must fit inside the minimum ceiling`,
        );
      }
      assert.deepEqual(
        others.map((answer) => answer.error),
        ['unavailable', 'invalid_request'],
      );
    });

    it('says nothing about the payload in a refusal beyond its size', async () => {
      const handoff = await createHandoff();
      await submit(handoff, BIG_SECRET);

      const refused = await broker.control({
        op: 'claim',
        handoff_id: handoff.handoff_id,
        max_response_bytes: CONTRACT.transport.min_response_bytes,
      });

      const serialized = JSON.stringify(refused);
      assert.equal(refused.error, 'response_too_large');
      assert.ok(!serialized.includes(SECRET.slice(0, 16)), 'no plaintext in a refusal');
      assert.ok(!serialized.includes(handoff.capability), 'no capability in a refusal');
      for (const line of logLines) {
        assert.ok(!line.includes(SECRET), `plaintext leaked into a log line: ${line}`);
      }
    });
  });

  it('never writes plaintext or capability into the broker log', async () => {
    const handoff = await createHandoff();
    await submit(handoff);
    await admin(['claim', handoff.handoff_id]);

    assert.ok(logLines.some((line) => line.includes(handoff.handoff_id)));
    for (const line of logLines) {
      assert.ok(!line.includes(SECRET), `plaintext leaked into a log line: ${line}`);
      assert.ok(!line.includes(handoff.capability), `capability leaked into a log line: ${line}`);
      assert.ok(!/ssh-ed25519|AAAAC3/.test(line));
    }
  });
});
