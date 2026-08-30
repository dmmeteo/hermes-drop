// The Hermes integration contract.
//
// Two things have to hold for the browser submit to continue the originating
// chat task safely:
//
//   1. The wake text Hermes injects into that session — which is built from the
//      awaited command line and its output, and which lands in `state.db` —
//      must carry no payload, no capability and no ciphertext.
//   2. The drop must cost the channel exactly one message, edited in place
//      through three fixed states — waiting (masked link + `<t:UNIX:R>`),
//      received, expired. The two quiet states carry no URL, capability,
//      timestamp or id, and the substantive answer follows separately.
//
// `formatCompletionNotification` below is a verbatim reproduction of Hermes'
// own completion template at
// tools/process_registry.py:2290-2295 (commit dd241cf0cd), so this file fails
// if the text Hermes would actually inject ever carries something it should
// not. It reproduces the template; it does not run Hermes.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { sendSecret } from '../src/client/handoff-client.js';
import { expiredNotice, receivedNotice, waitingNotice } from '../src/notice.js';
import { splitHandoffUrl, startTestBroker } from './helpers/harness.js';

const ADMIN = fileURLToPath(new URL('../bin/handoff-admin.mjs', import.meta.url));
const SECRET = [
  'PGPASSWORD=example-not-a-real-secret',
  'SSH_KEY=-----BEGIN OPENSSH PRIVATE KEY-----',
].join('\n');

function runAdmin(socketPath, args) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [ADMIN, ...args],
      { encoding: 'utf8', env: { ...process.env, HANDOFF_CONTROL_SOCKET: socketPath } },
      (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr }),
    );
  });
}

/**
 * Mirror of `format_process_notification`'s completion branch,
 * tools/process_registry.py:2273-2295 (commit dd241cf0cd) — every arm of it,
 * not just exit-0/else, because the `killed` and SIGTERM arms are exactly what
 * an orphaned or reaped `docker exec` produces.
 */
function formatCompletionNotification({
  sessionId,
  command,
  exitCode,
  output,
  completionReason = 'exited',
  terminationSource = '',
}) {
  const signal = [-15, 143, '-15', '143'].includes(exitCode) ? ', SIGTERM' : '';
  let status;
  if (completionReason === 'killed') status = `terminated by ${terminationSource || 'Hermes'}`;
  else if (completionReason === 'lost') {
    status = 'marked lost because the process backend disappeared';
  } else if (completionReason === 'failed_start') status = 'failed to start';
  else if (exitCode === 0) status = 'completed normally';
  else status = 'exited';

  return (
    `[IMPORTANT: Background process ${sessionId} ${status} ` +
    `(exit code ${exitCode}${signal}).\nCommand: ${command}\nOutput:\n${output}]`
  );
}

/**
 * The one property every wake must have, whatever killed the process.
 *
 * The shape check needs care since the capability went to 128 bits: at 22
 * base64url characters a capability is now *the same shape as a handoff id*,
 * and the wake text is supposed to carry the id. So the known-public id is
 * removed first, and what remains must contain no high-entropy token at all.
 * That makes the shape check a weaker signal than it was against the old
 * 43-character capability — the exact-string check above is what carries the
 * weight now, and it is the one that would catch a real leak.
 */
function assertPayloadFree(wakeText, { secret, capability, handoffId }) {
  assert.ok(!wakeText.includes(secret), 'no plaintext in the injected turn');
  for (const line of secret.split('\n')) assert.ok(!wakeText.includes(line));
  if (capability) assert.ok(!wakeText.includes(capability), 'no capability');
  // Exact canaries carry the security assertion. A generic 22-character shape
  // is not a sound proxy here: ordinary command paths and option names can have
  // that length and caused false positives in worktrees with descriptive names.
}

describe('the Hermes integration contract', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  describe('the one message, edited through three states', () => {
    const handoffId = 'abcdefghijklmnopqrstuv';
    const url = 'https://drop.example.test/#0123456789abcdefghij_-';
    const expiresAt = 1_800_000_000_000;

    it('offers exactly the three states, and nothing else', async () => {
      const module = await import('../src/notice.js');
      assert.deepEqual(Object.keys(module).sort(), [
        'expiredNotice',
        'receivedNotice',
        'waitingNotice',
      ]);
    });

    it('publishes the link as a masked Markdown link, so Discord makes no embed', () => {
      const notice = waitingNotice({ handoffId, url, expiresAt });
      assert.match(notice, /\[[^\]]+\]\(https:\/\/drop\.example\.test\/#[^)]+\)/, 'masked link');
      assert.ok(notice.includes(url), 'and it is the real url inside it');
      assert.ok(!notice.includes(`drop:${handoffId}`), 'transport metadata stays out of the UI');
    });

    it('delegates the countdown to Discord with a relative timestamp', () => {
      const notice = waitingNotice({ handoffId, url, expiresAt });
      assert.ok(
        notice.includes(`<t:${Math.floor(expiresAt / 1000)}:R>`),
        'a <t:UNIX:R> stamp Discord re-renders client-side',
      );
      // Rendering the duration into the text would go stale and invite the
      // per-minute edits this design exists to avoid.
      assert.ok(!/minute|hour|\d+\s*m\b/i.test(notice), 'no baked-in duration to drift');
    });

    it('reduces to a quiet received state with nothing left in it', () => {
      const notice = receivedNotice();
      assert.equal(notice, '✓ **Private input received**');
      assert.ok(!/https?:\/\//.test(notice), 'no url');
      assert.ok(!notice.includes('#'), 'no fragment, where the capability rides');
      assert.ok(!notice.includes('<t:'), 'no timestamp');
      assert.ok(!notice.includes(handoffId), 'no id: there is nothing left to look up');
    });

    it('reduces to a quiet expired state with nothing left in it', () => {
      const notice = expiredNotice();
      assert.equal(notice, '✕ **Private input link expired**');
      assert.ok(!/https?:\/\//.test(notice));
      assert.ok(!notice.includes('#'));
      assert.ok(!notice.includes('<t:'));
    });

    it('never carries a capability-shaped token outside the link itself', () => {
      const notice = waitingNotice({ handoffId, url, expiresAt });
      const rest = notice.split(url).join('').split(handoffId).join('');
      assert.ok(!/[A-Za-z0-9_-]{22}/.test(rest));
      for (const quiet of [receivedNotice(), expiredNotice()]) {
        assert.ok(!/[A-Za-z0-9_-]{22}/.test(quiet));
      }
    });
  });

  describe('the admin CLI', () => {
    it('prints the ready-to-post waiting notice with --notice', async () => {
      const result = await runAdmin(broker.controlSocketPath, [
        'create',
        '--ttl',
        '1800',
        '--notice',
      ]);
      assert.equal(result.code, 0);
      const handoffId = result.stderr.match(/handoff (\S+) expires/)[1];
      assert.ok(!result.stdout.includes(`drop:${handoffId}`), 'transport metadata stays hidden');
      assert.match(result.stdout, /\]\(https?:\/\/\S+#[A-Za-z0-9_-]{22}\)/, 'a masked link');
      assert.match(result.stdout, /<t:\d{10}:R>/, 'and a relative timestamp');
    });

    it('renders the two quiet states so Hermes never has to paraphrase them', async () => {
      const received = await runAdmin(broker.controlSocketPath, ['notice', 'received']);
      assert.equal(received.code, 0);
      assert.equal(received.stdout, '✓ **Private input received**\n');

      const expired = await runAdmin(broker.controlSocketPath, ['notice', 'expired']);
      assert.equal(expired.code, 0);
      assert.equal(expired.stdout, '✕ **Private input link expired**\n');
    });

    it('refuses any state it does not define', async () => {
      for (const args of [['notice'], ['notice', 'waiting'], ['notice', 'processing']]) {
        const result = await runAdmin(broker.controlSocketPath, args);
        assert.equal(result.code, 2, args.join(' '));
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /usage/);
      }
    });
  });

  describe('the wake text Hermes would inject', () => {
    it('is payload-free, and arrives on the event rather than on a poll', async () => {
      const created = await broker.control({ op: 'create', ttl_seconds: 30 });
      const { capability } = splitHandoffUrl(created.url);
      const handoffId = created.handoff_id;

      // Exactly what the integration contract tells Hermes to background.
      const command = `node ${ADMIN} await ${handoffId} --timeout 20`;
      const child = spawn(process.execPath, [ADMIN, 'await', handoffId, '--timeout', '20'], {
        env: { ...process.env, HANDOFF_CONTROL_SOCKET: broker.controlSocketPath },
      });
      let output = '';
      child.stdout.on('data', (chunk) => {
        output += chunk;
      });
      child.stderr.on('data', (chunk) => {
        output += chunk;
      });
      const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)));

      await new Promise((resolve) => setTimeout(resolve, 200));

      const submittedAt = Date.now();
      const sent = await sendSecret({ capability, plaintext: SECRET, origin: broker.baseUrl });
      assert.equal(sent.status, 'sent');

      const exitCode = await exited;
      const latencyMs = Date.now() - submittedAt;
      assert.equal(exitCode, 0, 'the subscription resolves on the submission');
      assert.ok(latencyMs < 2000, `woken by the event, not a poll (${latencyMs}ms)`);

      const wakeText = formatCompletionNotification({
        sessionId: 'proc_test',
        command,
        exitCode,
        output,
      });

      assertPayloadFree(wakeText, { secret: SECRET, capability, handoffId });
      assert.ok(wakeText.includes(handoffId), 'but Hermes learns which handoff woke it');
      assert.ok(wakeText.includes('submitted'));
      assert.ok(wakeText.length < 400, `the wake text stays tiny (${wakeText.length} chars)`);

      // And the payload is still there for the claim the woken turn performs.
      const claimed = await broker.control({ op: 'claim', handoff_id: handoffId });
      assert.equal(Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'), SECRET);
    });

    it('still wakes the session when the link lapses instead of hanging', async () => {
      const created = await broker.control({ op: 'create', ttl_seconds: 30 });
      const handoffId = created.handoff_id;
      const child = spawn(process.execPath, [ADMIN, 'await', handoffId, '--timeout', '0.5'], {
        env: { ...process.env, HANDOFF_CONTROL_SOCKET: broker.controlSocketPath },
      });
      let output = '';
      child.stdout.on('data', (chunk) => {
        output += chunk;
      });
      child.stderr.on('data', (chunk) => {
        output += chunk;
      });
      const exitCode = await new Promise((resolve) => child.on('exit', resolve));

      // notify_on_complete fires on exit, not on success, so a lapse is still a
      // turn — Hermes can tell the user rather than leaving them at a dead form.
      assert.equal(exitCode, 3);
      const wakeText = formatCompletionNotification({
        sessionId: 'proc_test',
        command: `await ${handoffId}`,
        exitCode,
        output,
      });
      assert.match(wakeText, /exit code 3/);
      assert.match(wakeText, /unavailable/);
      assertPayloadFree(wakeText, { secret: SECRET, handoffId });
      assert.ok(!/submitted/.test(wakeText), 'nothing here may read as "go ahead and claim"');
    });

    it('stays payload-free when the awaited process is killed mid-wait', async () => {
      const created = await broker.control({ op: 'create', ttl_seconds: 30 });
      const { capability } = splitHandoffUrl(created.url);
      const handoffId = created.handoff_id;

      const command = `node ${ADMIN} await ${handoffId} --timeout 1800`;
      const child = spawn(process.execPath, [ADMIN, 'await', handoffId, '--timeout', '1800'], {
        env: { ...process.env, HANDOFF_CONTROL_SOCKET: broker.controlSocketPath },
      });
      let output = '';
      child.stdout.on('data', (chunk) => {
        output += chunk;
      });
      child.stderr.on('data', (chunk) => {
        output += chunk;
      });
      const exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve(signal)));

      await new Promise((resolve) => setTimeout(resolve, 200));
      child.kill('SIGTERM');
      assert.equal(await exited, 'SIGTERM');

      // A reaped or orphaned background process lands on Hermes' `killed` arm
      // with exit -15, which is the scenario the report flags as open. It must
      // still be safe to inject and must not read as a delivery.
      const wakeText = formatCompletionNotification({
        sessionId: 'proc_test',
        command,
        exitCode: -15,
        output,
        completionReason: 'killed',
        terminationSource: 'Hermes',
      });
      assert.match(wakeText, /terminated by Hermes \(exit code -15, SIGTERM\)/);
      assertPayloadFree(wakeText, { secret: SECRET, capability, handoffId });
      assert.ok(!/submitted/.test(wakeText), 'a killed subscription is not a delivery');
      assert.ok(wakeText.includes(handoffId));

      // The payload was never at risk: nothing was submitted, so the handoff is
      // still pending and a fresh subscription would still work.
      assert.equal(broker.testSnapshot(handoffId).state, 'pending');
    });

    it('stays payload-free on the lost-backend and failed-start arms', () => {
      const handoffId = 'abcdefghijklmnopqrstuv';
      for (const [completionReason, expected] of [
        ['lost', /marked lost because the process backend disappeared/],
        ['failed_start', /failed to start/],
      ]) {
        const wakeText = formatCompletionNotification({
          sessionId: 'proc_test',
          command: `docker exec handoff-broker node bin/handoff-admin.mjs await ${handoffId} --timeout 1800`,
          exitCode: -1,
          output: '',
          completionReason,
        });
        assert.match(wakeText, expected);
        assertPayloadFree(wakeText, { secret: SECRET, handoffId });
        assert.ok(!/submitted/.test(wakeText));
      }
    });

    it('stays payload-free, and refuses to read as a delivery, when the broker vanishes', async () => {
      const created = await broker.control({ op: 'create', ttl_seconds: 30 });
      const { capability } = splitHandoffUrl(created.url);
      const handoffId = created.handoff_id;

      // Exactly what a broker container restart mid-wait looks like from here.
      const command = `node ${ADMIN} await ${handoffId} --timeout 20`;
      const child = spawn(process.execPath, [ADMIN, 'await', handoffId, '--timeout', '20'], {
        env: { ...process.env, HANDOFF_CONTROL_SOCKET: '/tmp/handoff-gone.sock' },
      });
      let output = '';
      child.stdout.on('data', (chunk) => {
        output += chunk;
      });
      child.stderr.on('data', (chunk) => {
        output += chunk;
      });
      const exitCode = await new Promise((resolve) => child.on('exit', resolve));

      assert.equal(exitCode, 1, 'transport failure, distinct from the broker saying unavailable');
      const wakeText = formatCompletionNotification({
        sessionId: 'proc_test',
        command,
        exitCode,
        output,
      });
      assert.match(wakeText, /exit code 1/);
      assertPayloadFree(wakeText, { secret: SECRET, capability, handoffId });
      assert.ok(
        !/submitted/.test(wakeText),
        'a non-zero exit must never contain the word the success path uses',
      );
    });
  });
});
