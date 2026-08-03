// Seam 6 — the submission event.
//
// A local subscriber blocks on the broker until the browser submits, so nothing
// polls: not the operator, not Hermes, not the broker. What comes back is a
// status and a handoff id and nothing else — this is the seam whose output ends
// up interpolated into a Hermes wake message and therefore into durable session
// history, so it must be provably payload-free.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { sendSecret } from '../src/client/handoff-client.js';
import { splitHandoffUrl, startTestBroker } from './helpers/harness.js';

const ADMIN = fileURLToPath(new URL('../bin/handoff-admin.mjs', import.meta.url));
const SECRET = 'GRAFANA_ADMIN_PASSWORD=example-not-a-real-secret';

function admin(socketPath, args) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [ADMIN, ...args],
      { encoding: 'utf8', env: { ...process.env, HANDOFF_CONTROL_SOCKET: socketPath } },
      (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr }),
    );
  });
}

describe('seam 6: blocking on the submission event', () => {
  let broker;

  beforeEach(async () => {
    broker = await startTestBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  async function createHandoff(options) {
    const created = await broker.control({ op: 'create', ...options });
    return { ...created, capability: splitHandoffUrl(created.url).capability };
  }

  describe('the control op', () => {
    it('stays blocked until the browser submits, then reports it', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });

      let settled = false;
      const waiting = broker
        .control({ op: 'await', handoff_id: handoff.handoff_id, wait_ms: 10_000 })
        .then((response) => {
          settled = true;
          return response;
        });

      await new Promise((resolve) => setTimeout(resolve, 250));
      assert.equal(settled, false, 'nothing has been submitted, so nothing may resolve');

      const sent = await sendSecret({
        capability: handoff.capability,
        plaintext: SECRET,
        origin: broker.baseUrl,
      });
      assert.equal(sent.status, 'sent');

      const response = await waiting;
      assert.deepEqual(response, {
        ok: true,
        handoff_id: handoff.handoff_id,
        status: 'submitted',
      });
    });

    it('carries no payload, capability or key material', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });
      await sendSecret({
        capability: handoff.capability,
        plaintext: SECRET,
        origin: broker.baseUrl,
      });

      const response = await broker.control({
        op: 'await',
        handoff_id: handoff.handoff_id,
        wait_ms: 1000,
      });
      const serialized = JSON.stringify(response);
      assert.ok(!serialized.includes(SECRET), 'no plaintext');
      assert.ok(!serialized.includes(handoff.capability), 'no capability');
      assert.ok(!/plaintext|_b64|pk|enc|ct/.test(Object.keys(response).join(' ')));
    });

    it('answers immediately when the payload is already waiting', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });
      await sendSecret({
        capability: handoff.capability,
        plaintext: SECRET,
        origin: broker.baseUrl,
      });

      const started = Date.now();
      const response = await broker.control({
        op: 'await',
        handoff_id: handoff.handoff_id,
        wait_ms: 10_000,
      });
      assert.equal(response.status, 'submitted');
      assert.ok(Date.now() - started < 1000, 'a late subscriber must not wait for the timeout');
    });

    it('leaves the payload for the claim, and can be subscribed to twice', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });
      const both = Promise.all([
        broker.control({ op: 'await', handoff_id: handoff.handoff_id, wait_ms: 10_000 }),
        broker.control({ op: 'await', handoff_id: handoff.handoff_id, wait_ms: 10_000 }),
      ]);
      await sendSecret({
        capability: handoff.capability,
        plaintext: SECRET,
        origin: broker.baseUrl,
      });
      for (const response of await both) assert.equal(response.status, 'submitted');

      const claimed = await broker.control({ op: 'claim', handoff_id: handoff.handoff_id });
      assert.equal(claimed.ok, true, 'awaiting must not consume the handoff');
      assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), SECRET);
    });

    it('gives the same generic unavailable for unknown, claimed and expired', async () => {
      const unknown = await broker.control({
        op: 'await',
        handoff_id: 'AAAAAAAAAAAAAAAAAAAAAA',
        wait_ms: 200,
      });
      assert.deepEqual(unknown, { ok: false, error: 'unavailable' });

      const handoff = await createHandoff({ ttl_seconds: 30 });
      await sendSecret({
        capability: handoff.capability,
        plaintext: SECRET,
        origin: broker.baseUrl,
      });
      await broker.control({ op: 'claim', handoff_id: handoff.handoff_id });
      const claimed = await broker.control({
        op: 'await',
        handoff_id: handoff.handoff_id,
        wait_ms: 200,
      });
      assert.deepEqual(claimed, { ok: false, error: 'unavailable' });

      const shortLived = await createHandoff({ ttl_seconds: 0.4 });
      const expired = await broker.control({
        op: 'await',
        handoff_id: shortLived.handoff_id,
        wait_ms: 10_000,
      });
      assert.deepEqual(expired, { ok: false, error: 'unavailable' }, 'never waits past the TTL');
    });

    it('gives up at the requested deadline instead of hanging', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });
      const started = Date.now();
      const response = await broker.control({
        op: 'await',
        handoff_id: handoff.handoff_id,
        wait_ms: 400,
      });
      assert.deepEqual(response, { ok: false, error: 'unavailable' });
      assert.ok(Date.now() - started >= 350, 'it really waited');
      assert.equal(broker.testSnapshot(handoff.handoff_id).state, 'pending', 'and destroyed nothing');
    });

    it('forgets a subscription that timed out, instead of retaining it for the TTL', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });
      assert.equal(broker.testSnapshot(handoff.handoff_id).waiters, 0, 'nothing attached yet');

      for (let i = 0; i < 5; i += 1) {
        await broker.control({ op: 'await', handoff_id: handoff.handoff_id, wait_ms: 40 });
      }
      assert.equal(
        broker.testSnapshot(handoff.handoff_id).waiters,
        0,
        'a resolved waiter must not stay attached — the count is read as truth',
      );

      // And detaching them has not broken the notification path.
      const waiting = broker.control({
        op: 'await',
        handoff_id: handoff.handoff_id,
        wait_ms: 10_000,
      });
      await sendSecret({
        capability: handoff.capability,
        plaintext: SECRET,
        origin: broker.baseUrl,
      });
      assert.equal((await waiting).status, 'submitted');
    });

    it('does not hold shutdown open until the last subscription would have expired', async () => {
      const own = await startTestBroker();
      const created = await own.control({ op: 'create', ttl_seconds: 25 });

      // A subscriber parked for the whole TTL, exactly like the backgrounded
      // process Hermes leaves behind.
      const parked = own.control({
        op: 'await',
        handoff_id: created.handoff_id,
        wait_ms: 25_000,
      });
      await new Promise((resolve) => setTimeout(resolve, 100));

      const started = Date.now();
      await own.stop();
      const elapsed = Date.now() - started;
      assert.ok(elapsed < 2000, `shutdown must not wait out the TTL (took ${elapsed}ms)`);

      // And the parked subscriber is answered rather than dropped: shutdown
      // destroys the handoff, so "unavailable" is the truthful answer.
      assert.deepEqual(await parked, { ok: false, error: 'unavailable' });
    });

    it('refuses a malformed subscription', async () => {
      const handoff = await createHandoff();
      for (const request of [
        { op: 'await' },
        { op: 'await', handoff_id: 42 },
        { op: 'await', handoff_id: handoff.handoff_id, wait_ms: -1 },
        { op: 'await', handoff_id: handoff.handoff_id, wait_ms: 'soon' },
      ]) {
        assert.deepEqual(await broker.control(request), {
          ok: false,
          error: 'invalid_request',
        });
      }
    });
  });

  describe('create argument validation', () => {
    it('treats a malformed --ttl as the caller mistake it is, not a broker fault', async () => {
      for (const args of [['create', '--ttl'], ['create', '--ttl', 'abc'], ['create', '--ttl', '-5']]) {
        const result = await admin(broker.controlSocketPath, args);
        assert.equal(result.code, 2, args.join(' '));
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /usage/);
        assert.ok(!/invalid_request/.test(result.stderr), 'the broker was never asked');
      }
    });

    it('still refuses a well-formed but out-of-policy ttl at the broker', async () => {
      const result = await admin(broker.controlSocketPath, ['create', '--ttl', '99999']);
      assert.equal(result.code, 1, 'a policy refusal is the broker speaking, so it stays exit 1');
      assert.match(result.stderr, /invalid_request/);
    });
  });

  describe('the admin CLI', () => {
    it('exits 0 with one non-secret line when the browser submits', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });
      const waiting = admin(broker.controlSocketPath, [
        'await',
        handoff.handoff_id,
        '--timeout',
        '20',
      ]);

      await new Promise((resolve) => setTimeout(resolve, 250));
      await sendSecret({
        capability: handoff.capability,
        plaintext: SECRET,
        origin: broker.baseUrl,
      });

      const result = await waiting;
      assert.equal(result.code, 0);
      assert.equal(result.stdout, `handoff ${handoff.handoff_id} submitted\n`);
      const everything = result.stdout + result.stderr;
      assert.ok(!everything.includes(SECRET), 'the wake signal carries no plaintext');
      assert.ok(!everything.includes(handoff.capability), 'nor the capability');
    });

    it('exits 3 with nothing on stdout when the link lapses', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });
      const result = await admin(broker.controlSocketPath, [
        'await',
        handoff.handoff_id,
        '--timeout',
        '0.5',
      ]);
      assert.equal(result.code, 3, 'a distinct code, so a lapse is not read as a broker fault');
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /unavailable/);
    });

    it('rejects bad usage with the usage exit code', async () => {
      for (const args of [
        ['await'],
        ['await', 'someid', '--timeout'],
        ['await', 'someid', '--timeout', 'soon'],
        ['await', 'someid', '--timeout', '-1'],
        // 0 conventionally reads as "no limit"; here it used to slip through as
        // an instant timeout and report a live handoff as lapsed.
        ['await', 'someid', '--timeout', '0'],
      ]) {
        const result = await admin(broker.controlSocketPath, args);
        assert.equal(result.code, 2, args.join(' '));
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /usage/);
      }
    });

    it('never reports a live handoff as lapsed because of a zero timeout', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });
      const result = await admin(broker.controlSocketPath, [
        'await',
        handoff.handoff_id,
        '--timeout',
        '0',
      ]);
      assert.equal(result.code, 2, 'a caller mistake, not a verdict on the handoff');
      assert.ok(!/unavailable/.test(result.stderr), 'and it must not claim the link lapsed');
      assert.equal(broker.testSnapshot(handoff.handoff_id).state, 'pending');
    });

    it('exits 1, distinct from 3, when the broker cannot be reached at all', async () => {
      const handoff = await createHandoff({ ttl_seconds: 30 });
      const result = await admin('/tmp/handoff-no-such-broker.sock', [
        'await',
        handoff.handoff_id,
        '--timeout',
        '5',
      ]);
      // 3 means "the broker answered: that link is gone". 1 means "no answer" —
      // a restarted broker mid-wait looks like this, and the payload's fate is
      // unknown. Both are non-zero, so neither may lead to a claim.
      assert.equal(result.code, 1);
      assert.equal(result.stdout, '', 'nothing that could be mistaken for a receipt');
      assert.match(result.stderr, /error/);
      assert.ok(!/submitted/.test(result.stderr));
    });
  });
});
