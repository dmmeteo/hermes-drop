// The control protocol as a *shared* contract.
//
// Two consumers speak this protocol: the local admin CLI in this repo and the
// Hermes-side plugin that will live outside it. `contract/control-protocol.json`
// is the single source of truth both read, so the tests below hold it against
// the server's real behaviour rather than against its documentation:
//
//   - the accepted ops in the contract are exactly the ops the switch in
//     src/control-server.js accepts, and an op the contract does not name is
//     refused;
//   - `create` can answer with all three notice strings in ONE response, so the
//     Hermes side never round-trips for a constant. There is deliberately **no**
//     `notice` op: `receivedNotice`/`expiredNotice` are byte-identical across
//     platforms, and fetching a constant over a socket buys nothing;
//   - the CLI exit codes the contract publishes are the codes the CLI really
//     exits with, because the whole Hermes-side rule is "0 means claim, any
//     non-zero means do not".
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { expiredNotice, receivedNotice, waitingNotice } from '../src/notice.js';
import { startTestBroker } from './helpers/harness.js';

const ADMIN = fileURLToPath(new URL('../bin/handoff-admin.mjs', import.meta.url));
const read = (name) => readFile(new URL(`../${name}`, import.meta.url), 'utf8');

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

describe('the control protocol contract', () => {
  let broker;
  let contract;

  before(async () => {
    broker = await startTestBroker();
    contract = JSON.parse(await read('contract/control-protocol.json'));
  });

  after(async () => {
    await broker.stop();
  });

  describe('the shared fixture', () => {
    it('names exactly the ops the server accepts', async () => {
      const source = await read('src/control-server.js');
      const accepted = [...source.matchAll(/^\s*case '([a-z_]+)':/gm)].map((match) => match[1]);

      assert.deepEqual(Object.keys(contract.ops).sort(), [...accepted].sort());
    });

    it('does not name a `notice` op, and the server has none', async () => {
      assert.ok(!('notice' in contract.ops), 'the notice op is cut, not pending');

      const response = await broker.control({ op: 'notice', state: 'received' });
      assert.deepEqual(response, { ok: false, error: 'invalid_request' });
    });

    it('refuses any op the contract does not name', async () => {
      for (const op of ['metadata', 'submit', 'sweep', 'destroy', '', 'CREATE']) {
        assert.ok(!(op in contract.ops));
        assert.deepEqual(await broker.control({ op }), { ok: false, error: 'invalid_request' });
      }
    });

    it('pins the transport facts a foreign client has to match', async () => {
      const source = await read('src/control-server.js');
      const maxLine = Number(source.match(/MAX_CONTROL_LINE_BYTES = (\d+)/)[1]);

      assert.equal(contract.transport.framing, 'newline-delimited-json');
      assert.equal(contract.transport.max_request_bytes, maxLine);
      assert.equal(contract.transport.socket_mode, '0600');
      assert.equal(contract.transport.socket_dir_mode, '0700');
    });

    it('lists exactly the notice platforms the renderer registry supports', () => {
      const sample = { handoffId: 'abcdefghijklmnopqrstuv', url: 'https://x.test/#c', expiresAt: 0 };
      for (const platform of contract.notice_platforms) {
        assert.equal(typeof waitingNotice({ ...sample, platform }), 'string', platform);
      }
      assert.throws(() => waitingNotice({ ...sample, platform: 'slack' }), /unsupported/);
      assert.ok(!contract.notice_platforms.includes('slack'));
    });

    it('publishes the same two error bodies the broker actually uses', async () => {
      assert.deepEqual([...contract.errors].sort(), ['invalid_request', 'unavailable']);

      const invalid = await broker.control({ op: 'await' });
      assert.equal(invalid.error, 'invalid_request');
      const unavailable = await broker.control({ op: 'claim', handoff_id: 'nope' });
      assert.equal(unavailable.error, 'unavailable');
    });
  });

  describe('`create` with a notice platform', () => {
    it('answers with all three notice strings in one response', async () => {
      const created = await broker.control({
        op: 'create',
        ttl_seconds: 60,
        notice_platform: 'telegram',
      });

      assert.equal(created.ok, true);
      assert.equal(
        created.notice,
        waitingNotice({
          handoffId: created.handoff_id,
          url: created.url,
          expiresAt: created.expires_at,
          platform: 'telegram',
        }),
        'the waiting notice is rendered for the platform asked for',
      );
      assert.equal(created.notice_received, receivedNotice());
      assert.equal(created.notice_expired, expiredNotice());
      // Review H1: this used to assert `<a href=`. Both verified platforms emit
      // Markdown now, because both adapters run `format_message` before posting
      // and MarkdownV2 displays an HTML tag rather than honouring it. What still
      // distinguishes telegram from discord is the deadline form, so that is what
      // is pinned here.
      assert.match(created.notice, /\]\(\S+#[A-Za-z0-9_-]{22}\)/, 'a masked Markdown link');
      assert.ok(!created.notice.includes('<'), 'no HTML tag, and nothing that could become one');
      assert.ok(!created.notice.includes('<t:'), 'no Discord stamp: telegram re-renders nothing');
      assert.match(created.notice, /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} UTC/, 'absolute deadline');
    });

    it('renders `plain` too, so an unverified platform is still served', async () => {
      const created = await broker.control({
        op: 'create',
        ttl_seconds: 60,
        notice_platform: 'plain',
      });
      assert.equal(created.ok, true);
      assert.ok(created.notice.split('\n').includes(created.url), 'bare url on its own line');
      assert.equal(created.notice_received, receivedNotice());
    });

    it('accepts every platform the contract lists, and only those', async () => {
      // The server keeps its own accepted-platform list (notice.js's export
      // surface is pinned to the three states), so this is the check that keeps
      // the two lists from drifting apart.
      for (const notice_platform of contract.notice_platforms) {
        const created = await broker.control({ op: 'create', ttl_seconds: 60, notice_platform });
        assert.equal(created.ok, true, notice_platform);
        assert.equal(typeof created.notice, 'string', notice_platform);
      }
    });

    it('leaves the response untouched when no platform is asked for', async () => {
      const created = await broker.control({ op: 'create', ttl_seconds: 60 });
      assert.equal(created.ok, true);
      for (const key of ['notice', 'notice_received', 'notice_expired']) {
        assert.ok(!(key in created), `${key} is opt-in`);
      }
    });

    it('refuses an unknown platform without minting anything', async () => {
      for (const notice_platform of ['slack', 'discord ', 'PLAIN', 42, null, '__proto__']) {
        const response = await broker.control({ op: 'create', notice_platform });
        assert.deepEqual(
          response,
          { ok: false, error: 'invalid_request' },
          `platform ${JSON.stringify(notice_platform)} is refused, not rendered`,
        );
        assert.ok(!('handoff_id' in response), 'and no handoff is burned on the way out');
      }
    });

    it('keeps the capability out of every field except `url` and `notice`', async () => {
      const created = await broker.control({
        op: 'create',
        ttl_seconds: 60,
        notice_platform: 'plain',
      });
      const capability = created.url.slice(created.url.indexOf('#') + 1);
      assert.match(capability, /^[A-Za-z0-9_-]{22}$/);

      for (const [key, value] of Object.entries(created)) {
        if (key === 'url' || key === 'notice') continue;
        assert.ok(!String(value).includes(capability), `${key} must not carry the capability`);
      }
    });
  });

  describe('the admin CLI exit codes the contract publishes', () => {
    it('exits 0 on a create, including with --platform plain', async () => {
      assert.match(contract.cli.exit_codes['0'], /submitted|success/i);

      const plain = await runAdmin(broker.controlSocketPath, ['create', '--notice', '--platform', 'plain']);
      assert.equal(plain.code, 0, plain.stderr);
      const handoffId = plain.stderr.match(/handoff (\S+) expires/)[1];
      assert.ok(plain.stdout.includes(`drop:${handoffId}`));
      assert.ok(!plain.stdout.includes('**'), 'plain carries no markdown');
      assert.ok(!/[<>]/.test(plain.stdout), 'and no HTML');
    });

    it('exits 2 on usage — including a platform it does not render', async () => {
      assert.match(contract.cli.exit_codes['2'], /usage/i);
      for (const args of [
        ['create', '--platform', 'slack'],
        ['create', '--platform'],
        ['create', '--notice', '--platform', 'Discord'],
      ]) {
        const result = await runAdmin(broker.controlSocketPath, args);
        assert.equal(result.code, 2, args.join(' '));
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /usage/);
      }
    });

    it('still accepts the platforms it always accepted', async () => {
      for (const platform of ['discord', 'telegram']) {
        const result = await runAdmin(broker.controlSocketPath, [
          'create',
          '--notice',
          '--platform',
          platform,
        ]);
        assert.equal(result.code, 0, result.stderr);
      }
    });

    it('documents the platform flag in its own usage text', async () => {
      const usage = await runAdmin(broker.controlSocketPath, ['bogus']);
      assert.equal(usage.code, 2);
      assert.match(usage.stderr, /--platform <discord\|telegram\|plain>/);
    });

    it('exits 3 when the broker answers unavailable', async () => {
      assert.match(contract.cli.exit_codes['3'], /unavailable/i);
      const result = await runAdmin(broker.controlSocketPath, [
        'await',
        'abcdefghijklmnopqrstuv',
        '--timeout',
        '1',
      ]);
      assert.equal(result.code, 3, result.stderr);
    });

    it('exits 1 when the control socket is unreachable', async () => {
      assert.match(contract.cli.exit_codes['1'], /transport/i);
      const result = await runAdmin('/tmp/handoff-not-here.sock', [
        'await',
        'abcdefghijklmnopqrstuv',
        '--timeout',
        '1',
      ]);
      assert.equal(result.code, 1, result.stderr);
    });
  });
});
