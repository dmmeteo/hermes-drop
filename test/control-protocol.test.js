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

import { PAYLOAD_KINDS } from '../src/broker.js';
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

    // The request ceiling counts the whole line *including* its newline, same as
    // the response one (`transport.size_convention`). Pinned against the real
    // server because it is a boundary a client cannot discover safely: a line one
    // byte over is answered, not dropped, so a client that measured it the other
    // way would see a working request refused and have nothing to go on.
    it('applies its request ceiling to the line including the newline', async () => {
      const limit = contract.transport.max_request_bytes;
      // A syntactically valid request, padded with an ignored field to an exact
      // wire length. `handoff_id` is unknown, so the answer at the limit is the
      // uniform `unavailable` — a statement about the handoff, which is only
      // reachable if the line was read at all.
      const lineOf = (bytes) => {
        const skeleton = { op: 'await', handoff_id: 'abcdefghijklmnopqrstuv', pad: '' };
        const padding = bytes - 1 - Buffer.byteLength(JSON.stringify(skeleton));
        return { ...skeleton, pad: 'p'.repeat(padding) };
      };

      const atLimit = lineOf(limit);
      assert.equal(Buffer.byteLength(`${JSON.stringify(atLimit)}\n`), limit);
      assert.deepEqual(await broker.control(atLimit), { ok: false, error: 'unavailable' });

      const overLimit = lineOf(limit + 1);
      assert.equal(Buffer.byteLength(`${JSON.stringify(overLimit)}\n`), limit + 1);
      assert.deepEqual(await broker.control(overLimit), { ok: false, error: 'invalid_request' });
    });

    it('lists exactly the notice platforms the renderer registry supports', () => {
      const sample = { handoffId: 'abcdefghijklmnopqrstuv', url: 'https://x.test/#c', expiresAt: 0 };
      for (const platform of contract.notice_platforms) {
        assert.equal(typeof waitingNotice({ ...sample, platform }), 'string', platform);
      }
      assert.throws(() => waitingNotice({ ...sample, platform: 'slack' }), /unsupported/);
      assert.ok(!contract.notice_platforms.includes('slack'));
    });

    it('publishes the same error bodies the broker actually uses, and no others', async () => {
      assert.deepEqual(
        [...contract.errors].sort(),
        ['invalid_request', 'response_too_large', 'transfer_failed', 'unavailable'],
      );

      const invalid = await broker.control({ op: 'await' });
      assert.equal(invalid.error, 'invalid_request');
      const unavailable = await broker.control({ op: 'claim', handoff_id: 'nope' });
      assert.equal(unavailable.error, 'unavailable');
      // `response_too_large` needs a live payload to be about, so it is proved
      // against the broker in test/seam4-claim.test.js, and `transfer_failed`
      // needs a live transfer, so it is proved in test/file-claim-transfer.test.js.
      // What is pinned here is that the fixture names them and that every published
      // error has a note.
      for (const error of contract.errors) {
        assert.equal(typeof contract.error_notes[error], 'string', `${error} needs a note`);
      }
    });

    // The response-size capability. A claim response is the one line that can be
    // arbitrarily large, and the broker retires the record before writing it — so
    // a reader that cannot buffer the line is a destroyed secret. The contract is
    // what lets a foreign client say how much it can read *before* anything is
    // consumed.
    it('publishes a response-size ceiling a bounded reader can hold itself to', () => {
      assert.equal(typeof contract.transport.max_response_bytes, 'number');
      assert.ok(
        contract.transport.max_response_bytes > contract.transport.max_request_bytes,
        'a response carries a payload; a request never does',
      );

      const field = contract.ops.claim.request.max_response_bytes;
      assert.equal(field.type, 'number');
      assert.equal(field.optional, true, 'a caller that reads an unbounded line sends nothing');
      assert.match(field.note, /before/i, 'the point is that the refusal precedes consumption');
      assert.match(field.note, /newline/i, 'the unit has to be unambiguous to be checkable');
    });

    // A ceiling below the refusal itself would be self-defeating: the caller
    // would be answered with a line it cannot read either, and would report a
    // transport fault for what is really a configuration mistake.
    it('pins a minimum ceiling every conforming client can receive a refusal in', async () => {
      const source = await read('src/control-server.js');
      const serverMin = Number(source.match(/MIN_RESPONSE_BYTES = (\d+)/)[1]);

      assert.equal(contract.transport.min_response_bytes, serverMin);
      assert.ok(
        contract.transport.min_response_bytes < contract.transport.max_response_bytes,
        'the floor is below the ceiling',
      );

      const below = await broker.control({
        op: 'claim',
        handoff_id: 'abcdefghijklmnopqrstuv',
        max_response_bytes: serverMin - 1,
      });
      assert.deepEqual(below, { ok: false, error: 'invalid_request' });
    });

    // The payload-kind capability is the exact analogue of notice_platforms: a
    // list in the fixture that a foreign client reads to decide what it may ask
    // for, held here against the broker's own list so the two cannot drift. The
    // MVP designates it as the plugin's pre-flight check — a plugin must refuse
    // file creation *before* posting a link if the broker lacks file support
    // (docs/FILE_TRANSFER_MVP.md, Compatibility).
    it('lists exactly the payload kinds the broker can mint', async () => {
      assert.deepEqual(contract.payload_kinds, [...PAYLOAD_KINDS]);
      assert.equal(typeof contract.payload_kinds_note, 'string');

      for (const payload_kind of contract.payload_kinds) {
        const created = await broker.control({ op: 'create', ttl_seconds: 60, payload_kind });
        assert.equal(created.ok, true, payload_kind);
        assert.equal(created.payload_kind, payload_kind);
      }
      const unlisted = await broker.control({ op: 'create', payload_kind: 'archive' });
      assert.deepEqual(unlisted, { ok: false, error: 'invalid_request' });
    });

    it('echoes the capability on every create, so no probe op is needed', async () => {
      const created = await broker.control({ op: 'create', ttl_seconds: 60 });
      assert.deepEqual(created.payload_kinds, contract.payload_kinds);
      assert.equal(
        contract.ops.create.response.payload_kinds,
        'array of the payload kinds this broker can mint; absent means ["text"]',
      );
    });

    // Every documented kind-specific response key is present on the kind that owns
    // it and absent on the other. A key that quietly appeared on both — or on
    // neither — would leave the fixture describing a response nobody sends.
    it('sends exactly the kind-specific response fields it documents', async () => {
      const TEXT_CAPS = ['max_plaintext_bytes'];
      const FILE_CAPS = ['max_files', 'max_file_bytes', 'max_total_bytes'];
      for (const key of [...TEXT_CAPS, ...FILE_CAPS]) {
        assert.match(
          contract.ops.create.response[key],
          /only/,
          `${key} must document which kinds it belongs to`,
        );
      }

      const text = await broker.control({ op: 'create', ttl_seconds: 60 });
      const files = await broker.control({
        op: 'create',
        ttl_seconds: 60,
        payload_kind: 'files',
      });
      // A universal drop quotes *both* sets, because its requester chose neither
      // lane and may not be told about only one of them. That is the one case where
      // "kind-specific" means two kinds, so it is asserted rather than left to the
      // reader of the two exclusions below.
      const universal = await broker.control({
        op: 'create',
        ttl_seconds: 60,
        payload_kind: 'universal',
      });
      for (const key of TEXT_CAPS) {
        assert.ok(key in text, `${key} must be present on a text drop`);
        assert.ok(!(key in files), `${key} must be absent on a files drop`);
        assert.ok(key in universal, `${key} must be present on a universal drop`);
      }
      for (const key of FILE_CAPS) {
        assert.ok(key in files, `${key} must be present on a files drop`);
        assert.ok(!(key in text), `${key} must be absent on a text drop`);
        assert.ok(key in universal, `${key} must be present on a universal drop`);
      }
    });

    // The universal drop's contract has two halves in two places: `create` mints the
    // link over this socket, and the sender's choice arrives on the browser-facing
    // submit endpoint. A foreign client that implements one half from this fixture
    // and guesses the other would guess at the one thing the AEAD binds, so both are
    // published here and both are held against the running broker.
    it('publishes the universal drop and the declaration that chooses its lane', async () => {
      const { PAYLOAD_DECLARATIONS, PAYLOAD_DECLARATION_HEADER } = await import(
        '../src/public-server.js'
      );
      const universal = contract.universal_drop;

      assert.ok(contract.payload_kinds.includes(universal.payload_kind));
      assert.match(universal.pending_choice, /exactly one/i, 'one link still takes one submission');
      assert.equal(universal.declaration.header, PAYLOAD_DECLARATION_HEADER);
      assert.deepEqual(universal.declaration.values, [...PAYLOAD_DECLARATIONS]);
      assert.deepEqual(universal.declaration.envelope_versions, { text: 1, files: 2 });
      assert.match(universal.declaration.binding, /unavailable/, 'a mismatch is the uniform body');
      assert.match(universal.declaration.compatibility_window, /omits the header/);
      assert.match(universal.declaration.reservation, /before the body is buffered/);

      // ...and the broker really advertises all three facts to the page, so nothing
      // in the paragraphs above has to be known in advance by whoever renders it.
      const created = await broker.control({
        op: 'create',
        ttl_seconds: 60,
        payload_kind: 'universal',
      });
      const capability = created.url.slice(created.url.indexOf('#') + 1);
      const response = await fetch(`${broker.baseUrl}/api/metadata`, {
        method: 'POST',
        headers: { 'x-handoff-capability': capability },
      });
      const metadata = await response.json();
      assert.equal(metadata.payload_kind, universal.payload_kind);
      assert.deepEqual(metadata.accepts, universal.declaration.values);
      assert.deepEqual(metadata.envelope_versions, universal.declaration.envelope_versions);
      assert.equal(metadata.payload_declaration, universal.declaration.header);
    });

    it('documents the create request fields the server really validates', async () => {
      const field = contract.ops.create.request.payload_kind;
      assert.deepEqual(field.enum, [...PAYLOAD_KINDS]);
      assert.equal(field.optional, true, 'a client that sends nothing gets a text drop');
      assert.match(field.note, /unavailable/, 'a full live-file budget refuses uniformly');

      const count = contract.ops.create.request.max_files;
      assert.equal(count.optional, true);
      assert.match(count.note, /narrow/i, 'it may only narrow the operator limit');

      // ...and the server refuses it on a text drop rather than ignoring it, which
      // is the half of the note a reader cannot verify from the fixture alone.
      assert.deepEqual(await broker.control({ op: 'create', max_files: 2 }), {
        ok: false,
        error: 'invalid_request',
      });
    });

    it('says that a files drop cannot be claimed over this seam', async () => {
      assert.match(contract.ops.claim.summary, /files|text drops only/i);

      const files = await broker.control({ op: 'create', ttl_seconds: 60, payload_kind: 'files' });
      assert.deepEqual(await broker.control({ op: 'claim', handoff_id: files.handoff_id }), {
        ok: false,
        error: 'unavailable',
      });
    });

    // Both halves of this repo ship together, but a Hermes-side plugin does not:
    // it is installed once and upgraded on its own schedule. So the one thing a
    // foreign client cannot be asked to infer is which protocol it is talking to.
    // The framed transfer is the second capability this fixture has to carry
    // without a version bump, and the reasoning is the same as `payload_kinds`':
    // a text-only client sends none of it and reads none of it, so ordering it
    // against a version would make every such client widen a check for something
    // it will never use. What a *file* client needs is a yes-or-no answer before
    // it posts a link, which is what `file_claim_protocol` is.
    it('advertises the framed file claim as a capability rather than a version', async () => {
      assert.equal(contract.version, 2, 'the framed transfer is additive to version 2');
      assert.match(contract.version_notes.file_claim, /additive/i);
      assert.equal(typeof contract.file_claim.protocol, 'number');

      const created = await broker.control({ op: 'create', ttl_seconds: 60 });
      assert.equal(created.file_claim_protocol, contract.file_claim.protocol);
      assert.equal(created.protocol_version, 2, 'and the protocol version is untouched by it');
      assert.match(
        contract.ops.create.response.file_claim_protocol,
        /absent means/,
        'absence has to mean something specific, because a slice-2 broker sends nothing',
      );
    });

    it('documents the framing precisely enough for a foreign client to implement', async () => {
      const source = await read('src/control-server.js');
      const frameHeader = Number(source.match(/FRAME_HEADER_BYTES = (\d+)/)[1]);
      const protocol = Number(source.match(/FILE_CLAIM_PROTOCOL = (\d+)/)[1]);

      assert.equal(protocol, contract.file_claim.protocol);
      assert.equal(frameHeader, 4, 'a uint32 length prefix, as the conversation describes');
      const framing = contract.file_claim.conversation.join(' ');
      assert.match(framing, /uint32 big-endian/, 'the width and the byte order are both stated');
      assert.match(framing, /zero-length frame/, 'and an empty file is a legitimate frame');
      // The two halves a client could get wrong silently: what it must compute, and
      // what the broker will not tell it.
      assert.match(contract.file_claim.digests_are_not_echoed, /computes/);
      assert.match(contract.file_claim.commit_is_the_only_retirement, /until/);
      assert.match(contract.transport.exchange_note, /begin_file_claim/);
    });

    // The turn-taking rule is a wire requirement, not an implementation detail: a
    // third implementation reading only this fixture has to know that a commit sent
    // early is refused, or it will write one and lose a payload learning why.
    it('states that the conversation is turn-taking, and enforces it structurally', async () => {
      assert.match(contract.file_claim.turn_taking, /invalid_request/);
      assert.match(
        contract.file_claim.turn_taking,
        /size-independent/i,
        'the reason for the structure is the property it buys',
      );
      assert.match(
        contract.ops.commit_file_claim.errors.invalid_request,
        /outstanding/i,
        'the op that refuses an early commit has to document the refusal',
      );
      // The ack is the mechanism, so a third implementation must find it in the ops.
      const ack = contract.ops.ack_frame;
      assert.equal(ack.request.op, 'ack_frame');
      for (const field of ['transfer_id', 'index', 'size', 'sha256']) {
        assert.equal(ack.request[field].optional, false, `${field} binds the ack to a frame`);
      }
      assert.match(ack.request.sha256.note, /over the bytes that frame actually delivered/i);
      assert.match(ack.request.index.note, /outstanding/i, 'acks are strictly in order');
      assert.equal(
        ack.response.next_index,
        'number: the frame the broker has just written and is now waiting on, or null when that was the last one — at which point the only op left is commit_file_claim',
      );
    });

    // The finding this replaced: the old rule was inferred from whether the broker was
    // still writing, which is a fact about the socket send buffer. It held for a 42 MiB
    // drop and silently did not hold for a 16 KiB one. The fixture has to say why the
    // ack exists, or a third implementation will "optimise" it away.
    it('explains why receipt cannot be inferred from write completions', async () => {
      const receipt = contract.file_claim.receipt;
      assert.match(receipt, /send buffer/i);
      assert.match(receipt, /kernel/i);
      assert.match(receipt, /16 bytes and at 42 MiB|every payload size/i);
      // ...and keeps the irreducible limit stated rather than quietly dropped.
      assert.match(receipt, /already knows the plaintext/i);
      assert.match(contract.file_claim.digests_are_not_echoed, /irreducible/i);
    });

    // A receiver has to be able to say something the socket did not. Keeping that
    // vocabulary *out* of `errors` is the point: `errors` is what comes off the wire,
    // and a client verdict is not.
    it('names the verdicts a receiver produces, separately from the broker\'s errors', async () => {
      assert.deepEqual(contract.file_claim.client_verdicts, ['transfer_indeterminate']);
      for (const verdict of contract.file_claim.client_verdicts) {
        assert.ok(!contract.errors.includes(verdict), `${verdict} is not a broker error`);
      }
      const note = contract.file_claim.client_verdicts_note;
      // The three prohibitions are the whole safe reading, and a consumer that gets
      // any of them wrong either publishes unverified files or discards received ones.
      assert.match(note, /do not publish/i);
      assert.match(note, /do not retry/i);
      assert.match(note, /(do not|nothing as) (record|spent)/i);
      assert.match(
        contract.file_claim.lease_lost_mid_conversation,
        /indeterminate/i,
        'and the close that produces it has to point at it',
      );
    });

    // A client that treats this like `unavailable` marks a drop spent that is still
    // sitting there — which is the exact loss the two-phase protocol exists to
    // prevent. So the fixture has to say what it means, and the server has to mean
    // it, and both are checked here rather than only in the transfer suite.
    it('publishes `transfer_failed` as a refusal that consumed nothing', async () => {
      assert.ok(contract.errors.includes('transfer_failed'));
      assert.match(contract.error_notes.transfer_failed, /nothing was consumed/i);
      // ...and scopes that promise to refusals the broker actually spoke, or it would
      // contradict the indeterminate verdict above.
      assert.match(contract.error_notes.transfer_failed, /scoped to refusals the broker/i);

      const files = await broker.control({ op: 'create', ttl_seconds: 60, payload_kind: 'files' });
      // No payload yet, so there is nothing for a transfer to fail *about*: a
      // pending drop is `unavailable` here, not `transfer_failed`.
      assert.deepEqual(
        await broker.control({ op: 'begin_file_claim', handoff_id: files.handoff_id }),
        { ok: false, error: 'unavailable' },
        'the two errors are not interchangeable',
      );
      for (const op of ['begin_file_claim', 'commit_file_claim']) {
        assert.deepEqual(await broker.control({ op }), { ok: false, error: 'invalid_request' });
      }
    });

    it('states its protocol version on the wire, in the response every drop starts with', async () => {
      const created = await broker.control({ op: 'create', ttl_seconds: 60 });
      assert.equal(created.ok, true);
      assert.equal(created.protocol_version, contract.version);
      assert.equal(contract.ops.create.response.protocol_version, 'number: the protocol this broker speaks; absent means 1');
      assert.match(
        contract.version_notes.lossless_claim,
        /2/,
        'the note has to say which version made the claim boundary lossless',
      );
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
