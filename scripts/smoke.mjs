#!/usr/bin/env node
// Local end-to-end runtime smoke.
//
// Boots the real entrypoint as a child process, creates a handoff with the real
// admin CLI, encrypts and submits through the real browser-facing client module,
// claims once, and proves the second claim fails. Nothing it prints contains
// plaintext, the capability, or ciphertext — only lengths and digests.
import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { sendSecret } from '../src/client/handoff-client.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SECRET = [
  'DB_PASSWORD=' + randomBytes(18).toString('base64url'),
  'API_TOKEN=' + randomBytes(24).toString('base64url'),
  'PRIVATE_KEY_BODY=' + randomBytes(48).toString('base64'),
].join('\n');
const SECRET2 = 'SMTP_PASSWORD=' + randomBytes(21).toString('base64url');

const steps = [];
let failed = false;

function check(name, condition, detail = '') {
  steps.push({ name, ok: Boolean(condition), detail });
  if (!condition) failed = true;
  process.stdout.write(`${condition ? 'ok  ' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}\n`);
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex').slice(0, 16);
}

function admin(socketPath, args) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [join(ROOT, 'bin/handoff-admin.mjs'), ...args],
      { encoding: 'buffer', env: { ...process.env, HANDOFF_CONTROL_SOCKET: socketPath } },
      (error, stdout, stderr) =>
        resolve({ code: error?.code ?? 0, stdout, stderr: stderr.toString('utf8') }),
    );
  });
}

async function waitForSocket(socketPath, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      await stat(socketPath);
      return true;
    } catch {
      if (Date.now() > deadline) return false;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
}

const dir = await mkdtemp(join(tmpdir(), 'handoff-smoke-'));
const socketPath = join(dir, 'control.sock');
const brokerLog = [];

const broker = spawn(process.execPath, [join(ROOT, 'src/main.js')], {
  cwd: ROOT,
  env: {
    ...process.env,
    HANDOFF_PORT: '0',
    HANDOFF_HOST: '127.0.0.1',
    HANDOFF_CONTROL_SOCKET: socketPath,
    HANDOFF_BASE_URL: '',
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
broker.stdout.on('data', (chunk) => brokerLog.push(chunk.toString('utf8')));
broker.stderr.on('data', (chunk) => brokerLog.push(chunk.toString('utf8')));

try {
  check('broker process starts and opens its control socket', await waitForSocket(socketPath));

  // 1. Admin CLI creates the handoff.
  const created = await admin(socketPath, ['create', '--ttl', '120']);
  const url = created.stdout.toString('utf8').trim();
  const handoffId = created.stderr.match(/handoff (\S+) expires/)?.[1];
  const [target, capability] = url.split('#');
  check('admin cli prints one handoff url', created.code === 0 && /^http:\/\/127\.0\.0\.1:\d+\/$/.test(target), target);
  check(
    'capability rides in the fragment with 128 bits of entropy',
    capability?.length === 22 && Buffer.from(capability, 'base64url').length === 16,
  );
  check('handoff id is reported for the operator', Boolean(handoffId), handoffId);

  // 2. The browser loads the page and its self-hosted assets.
  const origin = target.replace(/\/$/, '');
  const page = await fetch(target);
  const html = await page.text();
  check('page loads over the plain request target', page.status === 200);
  check(
    'page is the accepted Variant A form, branded Hermes Drop',
    html.includes('Send to Hermes') &&
      html.includes('Send privately to Hermes') &&
      html.includes('<title>Hermes Drop</title>'),
  );
  check('page carries a strict self-only CSP', /default-src 'none'/.test(page.headers.get('content-security-policy') ?? ''));
  check('page carries no-referrer', page.headers.get('referrer-policy') === 'no-referrer');
  for (const asset of ['/assets/app.js', '/assets/app.css']) {
    const response = await fetch(`${origin}${asset}`);
    check(`asset ${asset} is self-hosted`, response.status === 200);
  }

  // 3. Encrypt and submit through the actual browser-facing client logic.
  const wire = [];
  const recordingFetch = async (input, init) => {
    const response = await fetch(input, init);
    const body = await response.text();
    wire.push({ url: String(input), requestBody: String(init?.body ?? ''), responseBody: body });
    return new Response(body, { status: response.status, headers: response.headers });
  };

  const sent = await sendSecret({ capability, plaintext: SECRET, fetchImpl: recordingFetch, origin });
  check('client sealed and submitted the envelope', sent.status === 'sent');
  check(
    'no plaintext in any request or response body',
    wire.every((call) => !call.requestBody.includes(SECRET) && !call.responseBody.includes(SECRET)),
  );
  check(
    'no capability in any request target',
    wire.every((call) => !call.url.includes(capability)),
  );
  const envelope = JSON.parse(wire.at(-1).requestBody);
  check(
    'envelope is one HPKE ciphertext with a 65-byte enc and no nonce field',
    Buffer.from(envelope.enc, 'base64url').length === 65 && !('nonce' in envelope),
    `ct=${Buffer.from(envelope.ct, 'base64url').length} bytes`,
  );

  // 4. A second submission is refused.
  const secondSend = await sendSecret({ capability, plaintext: 'second attempt', origin });
  check('second submission is refused', secondSend.status === 'unavailable');

  // 5. Claim once.
  const claim = await admin(socketPath, ['claim', handoffId]);
  check(
    'claim emits the exact submitted bytes to stdout',
    claim.code === 0 && claim.stdout.toString('utf8') === SECRET,
    `${Buffer.byteLength(SECRET)} bytes, sha256:${digest(SECRET)}`,
  );

  // 6. And exactly once.
  const secondClaim = await admin(socketPath, ['claim', handoffId]);
  check(
    'second claim fails safely with nothing on stdout',
    secondClaim.code === 1 && secondClaim.stdout.length === 0 && /unavailable/.test(secondClaim.stderr),
  );

  // 7. The metadata endpoint is closed too.
  const afterClaim = await fetch(`${origin}/api/metadata`, {
    method: 'POST',
    headers: { 'x-handoff-capability': capability },
  });
  check(
    'the consumed capability now gets the generic unavailable contract',
    afterClaim.status === 404 && (await afterClaim.text()) === '{"status":"unavailable"}',
  );

  // 8. The whole Hermes-shaped flow on a second handoff: post the waiting
  //    notice, background the subscription the way terminal(background=true,
  //    notify_on_complete=true) would, let the browser submit, and check that
  //    the wake Hermes injects into the originating session says enough to
  //    continue and nothing more.
  const opened = await admin(socketPath, ['create', '--ttl', '120', '--notice']);
  const notice = opened.stdout.toString('utf8');
  const secondId = opened.stderr.match(/handoff (\S+) expires/)?.[1];
  // The link is masked Markdown now, so pull it out of the parentheses rather
  // than off whitespace — `\S+` would swallow the closing bracket.
  const secondUrl = notice.match(/\]\((http:\/\/[^)]+)\)/)?.[1];
  const secondCapability = secondUrl?.split('#')[1];
  check(
    'the waiting state is friendly, masked, and uses a Discord relative timestamp',
    Boolean(secondUrl) &&
      notice.includes('🔒 **Private input requested**') &&
      !notice.includes(`drop:${secondId}`) &&
      new RegExp(`\\]\\(${secondUrl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\)`).test(notice) &&
      /^Expires <t:\d{10}:R>\.$/m.test(notice) &&
      !/minute|hour/i.test(notice),
  );

  const awaiting = spawn(
    process.execPath,
    [join(ROOT, 'bin/handoff-admin.mjs'), 'await', secondId, '--timeout', '60'],
    { env: { ...process.env, HANDOFF_CONTROL_SOCKET: socketPath }, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let awaitOutput = '';
  awaiting.stdout.on('data', (chunk) => {
    awaitOutput += chunk.toString('utf8');
  });
  awaiting.stderr.on('data', (chunk) => {
    awaitOutput += chunk.toString('utf8');
  });
  const awaitExit = new Promise((resolve) => awaiting.once('exit', resolve));
  await new Promise((resolve) => setTimeout(resolve, 200));
  check('the subscription is still blocked before anyone submits', awaitOutput === '');

  const submittedAt = Date.now();
  const secondSent = await sendSecret({
    capability: secondCapability,
    plaintext: SECRET2,
    origin: target.replace(/\/$/, ''),
  });
  const awaitCode = await awaitExit;
  const wakeLatencyMs = Date.now() - submittedAt;
  check('the browser submits the second payload', secondSent.status === 'sent');
  check(
    'the subscription wakes on the event, not on a poll',
    awaitCode === 0 && wakeLatencyMs < 2000,
    `${wakeLatencyMs}ms after submit`,
  );

  // Verbatim reproduction of Hermes' completion template
  // (tools/process_registry.py:2290-2295) over the real command and output.
  const wakeText =
    `[IMPORTANT: Background process proc_smoke completed normally (exit code ${awaitCode}).\n` +
    `Command: handoff-admin await ${secondId} --timeout 60\nOutput:\n${awaitOutput}]`;
  // A 128-bit capability is the same 22-character shape as a handoff id, so the
  // shape check only means anything with the id — which the wake is meant to
  // name — removed first. The exact-value check is what carries the weight.
  const wakeMinusPublicIds = wakeText.split(secondId).join('');
  check(
    'the injected wake text is payload-free and names the handoff',
    !wakeText.includes(SECRET2) &&
      !wakeText.includes(secondCapability) &&
      !/[A-Za-z0-9_-]{22}/.test(wakeMinusPublicIds) &&
      wakeText.includes(secondId) &&
      wakeText.includes('submitted'),
    `${wakeText.length} chars`,
  );

  // The wake edits that same message in place. Both quiet states are fixed
  // strings this CLI renders, and neither can carry the link forward.
  const received = await admin(socketPath, ['notice', 'received']).then((r) =>
    r.stdout.toString('utf8'),
  );
  const expired = await admin(socketPath, ['notice', 'expired']).then((r) =>
    r.stdout.toString('utf8'),
  );
  check(
    'the received state is quiet and carries nothing forward',
    received === '✓ **Private input received**\n' &&
      !/https?:\/\/|#|<t:/.test(received) &&
      !received.includes(secondId),
  );
  check(
    'the expired state is quiet and carries nothing forward',
    expired === '✕ **Private input link expired**\n' && !/https?:\/\/|#|<t:/.test(expired),
  );
  check(
    'no state outside the contract can be rendered',
    (await admin(socketPath, ['notice', 'processing'])).code === 2,
  );

  const wokenClaim = await admin(socketPath, ['claim', secondId]);
  check(
    'the woken turn can claim the payload exactly once',
    wokenClaim.code === 0 && wokenClaim.stdout.toString('utf8') === SECRET2,
    `${Buffer.byteLength(SECRET2)} bytes, sha256:${digest(SECRET2)}`,
  );

  // 9. Nothing sensitive reached the broker's own log.
  const log = brokerLog.join('');
  check(
    'broker log contains no plaintext, capability or ciphertext',
    !log.includes(SECRET) &&
      !log.includes(SECRET2) &&
      !log.includes(capability) &&
      !log.includes(secondCapability) &&
      !log.includes(envelope.ct),
    `${log.split('\n').filter(Boolean).length} log lines`,
  );
} finally {
  broker.kill('SIGTERM');
  await new Promise((resolve) => broker.once('exit', resolve));
  await rm(dir, { recursive: true, force: true });
}

process.stdout.write(
  `\n${steps.filter((step) => step.ok).length}/${steps.length} smoke checks passed\n`,
);
process.exit(failed ? 1 : 0);
