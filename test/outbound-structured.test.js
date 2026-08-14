// The structured outbound drop, end to end over the real seams: the control op that
// mints one, the notice it hands back, and what neither of them may carry.
//
// The store below it is deliberately untouched by all of this — an outbound record
// still holds ciphertext, an IV and a code verifier and knows nothing about JSON
// (test/outbound-drop.test.js pins that). What this file is about is the *seam*: the
// one place a model-composed object is turned into a payload, where the refusal has
// to be atomic and the reason has to be a code.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { after, before, describe, it } from 'node:test';

import {
  FIELD_TYPES,
  GENERATE_KINDS,
  MAX_FIELDS,
  MAX_LABEL_CHARS,
  MAX_NOTE_LINES,
  MAX_PAYLOAD_BYTES,
  MAX_TITLE_CHARS,
  MAX_VALUE_BYTES,
  OUTBOUND_PAYLOAD_VERSION,
  REFUSAL_REASONS,
  buildOutboundPayload,
  parseOutboundPayload,
} from '../src/outbound-payload.js';
import { outboundNotice } from '../src/outbound-notice.js';
import { createOutboundDrop, startTestBroker } from './helpers/harness.js';

const CANON = {
  v: 1,
  title: 'OpenRouter access',
  fields: [
    { label: 'Login', type: 'text', value: 'ops@example.test' },
    { label: 'Password', type: 'secret', value: 'example-not-a-real-secret' },
    { label: 'API key', type: 'secret', value: 'sk-example-not-a-real-key' },
    { label: 'Console', type: 'url', value: 'https://openrouter.test/keys' },
    { label: 'Note', type: 'note', value: 'Rotate within 30 days.' },
  ],
};

describe('structured outbound drops: the control seam', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  it('mints one from a structured payload and reveals it as the same JSON', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });
    assert.equal(drop.created.ok, true);
    assert.equal(drop.created.payload_format, 'structured');
    assert.equal(drop.created.field_count, 5);

    const revealed = await drop.reveal();
    assert.equal(revealed.status, 'revealed');

    const parsed = parseOutboundPayload(revealed.plaintext);
    assert.equal(parsed.ok, true, `the page must be able to read it back: ${parsed.reason}`);
    assert.deepEqual(
      parsed.payload.fields.map((field) => [field.label, field.type, field.value]),
      CANON.fields.map((field) => [field.label, field.type, field.value]),
    );
    assert.equal(parsed.payload.title, CANON.title);
  });

  it('refuses a malformed payload atomically — no drop, no code, no link', async () => {
    const before = broker.testOutboundSnapshot;
    for (const [payload, reason] of [
      [{ v: 1, fields: [] }, 'no_fields'],
      [{ v: 2, fields: [{ label: 'Key', value: 'x' }] }, 'bad_version'],
      [{ v: 1, fields: [{ label: 'Key', value: 'x', extra: 1 }] }, 'unknown_key'],
      [{ v: 1, fields: [{ label: 'Key', type: 'html', value: 'x' }] }, 'bad_type'],
      [{ v: 1, fields: [{ label: '', value: 'x' }] }, 'bad_label'],
      [{ v: 1, fields: [{ label: 'Site', type: 'url', value: 'javascript:alert(1)' }] }, 'bad_url'],
      // Every field inside its own bounds; the canonical whole over the ceiling.
      // Sized to still fit the 4096-byte control request line, so what refuses it
      // is the payload ceiling rather than the transport's.
      [
        {
          v: 1,
          fields: Array.from({ length: 4 }, (_u, i) => ({
            label: `Field ${i + 1}`,
            value: 'v'.repeat(MAX_VALUE_BYTES - 60),
          })),
        },
        'payload_too_large',
      ],
    ]) {
      const answer = await broker.control({
        op: 'create_outbound_drop',
        payload_format: 'structured',
        plaintext_b64: Buffer.from(JSON.stringify(payload), 'utf8').toString('base64'),
      });
      assert.deepEqual(
        answer,
        { ok: false, error: 'invalid_request', reason },
        `payload ${reason}`,
      );
      assert.ok(!('drop_id' in answer), 'nothing is minted on the way out');
      assert.ok(!('url' in answer), 'and no link is handed back');
      assert.ok(!('code' in answer), 'and no code');
    }
    assert.equal(before, broker.testOutboundSnapshot, 'the store was never reached');
  });

  it('tells "not JSON" apart from "JSON of the wrong shape", and sizes before parsing', async () => {
    // Both are `invalid_request`, and the `reason` is the only thing a caller has to
    // act on — so a body that is not JSON at all, a body that is not UTF-8, and a
    // body that is valid JSON of the wrong shape must not all read the same.
    const send = (bytes) =>
      broker.control({
        op: 'create_outbound_drop',
        payload_format: 'structured',
        plaintext_b64: Buffer.from(bytes).toString('base64'),
      });

    for (const text of ['not json', '{', '{"v":1,', 'null']) {
      assert.deepEqual(
        await send(Buffer.from(text, 'utf8')),
        { ok: false, error: 'invalid_request', reason: 'not_json' },
        JSON.stringify(text),
      );
    }
    // Bytes that are not UTF-8 at all: one refusal rather than two for one mistake,
    // and never a payload with U+FFFD silently substituted into a credential.
    assert.deepEqual(await send(Buffer.from([0xff, 0xfe, 0x00, 0x80])), {
      ok: false,
      error: 'invalid_request',
      reason: 'not_json',
    });
    // Valid JSON, wrong shape.
    assert.deepEqual(await send(Buffer.from('[1,2,3]', 'utf8')), {
      ok: false,
      error: 'invalid_request',
      reason: 'not_an_object',
    });
    // Over the ceiling: refused on size, before anything is parsed.
    assert.deepEqual(await send(Buffer.alloc(MAX_PAYLOAD_BYTES + 1, 0x7b)), {
      ok: false,
      error: 'invalid_request',
      reason: 'payload_too_large',
    });
  });

  it('refuses a payload_format it does not know, and never guesses at one', async () => {
    for (const payload_format of ['json', 'STRUCTURED', '', 42, null, {}, '__proto__']) {
      assert.deepEqual(
        await broker.control({
          op: 'create_outbound_drop',
          payload_format,
          plaintext_b64: Buffer.from('{}', 'utf8').toString('base64'),
        }),
        { ok: false, error: 'invalid_request' },
        `format ${JSON.stringify(payload_format)}`,
      );
    }
  });

  it('leaves an undeclared payload opaque, so nothing that worked before now refuses', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: 'correct horse battery staple' });
    assert.equal(drop.created.ok, true);
    assert.equal(drop.created.payload_format, 'opaque');
    assert.ok(!('field_count' in drop.created), 'an opaque payload has no field count');
    const revealed = await drop.reveal();
    assert.equal(revealed.plaintext, 'correct horse battery staple');
  });

  it('generates a value the caller never held, and hands back no trace of it', async () => {
    const created = await broker.control({
      op: 'create_outbound_drop',
      payload_format: 'structured',
      plaintext_b64: Buffer.from(
        JSON.stringify({
          v: 1,
          fields: [
            { label: 'Login', type: 'text', value: 'ops@example.test' },
            { label: 'Password', type: 'secret', generate: { kind: 'password', length: 24 } },
          ],
        }),
        'utf8',
      ).toString('base64'),
    });
    assert.equal(created.ok, true);
    assert.equal(created.field_count, 2);

    // The response carries a link, a code and metadata — never the value it just
    // generated, which would put the secret back in the caller's hands and from
    // there into a model turn.
    const serialized = JSON.stringify(created);
    assert.ok(!/"value"/.test(serialized), serialized);
    assert.ok(!/"password"/i.test(serialized.replace(/"code_length"|"max_code_attempts"/g, '')));

    const drop = await createOutboundDrop(broker, {
      payload: {
        v: 1,
        fields: [{ label: 'Password', type: 'secret', generate: { kind: 'password', length: 24 } }],
      },
    });
    const parsed = parseOutboundPayload((await drop.reveal()).plaintext);
    assert.equal(parsed.ok, true);
    assert.match(parsed.payload.fields[0].value, /^[A-Za-z0-9]{24}$/);
  });

  it('re-canonicalises, so the bytes stored are the schema\'s rather than the caller\'s', async () => {
    // Key order and an absent type both come back normalised, which is what makes
    // the payload the page reads a function of the schema and not of whoever typed
    // the request.
    const drop = await createOutboundDrop(broker, {
      payload: { fields: [{ value: 'abc', label: 'Token' }], v: 1 },
    });
    const revealed = await drop.reveal();
    assert.equal(revealed.plaintext, '{"v":1,"fields":[{"label":"Token","type":"secret","value":"abc"}]}');
  });
});

describe('structured outbound drops: the notice that carries the link and the code', () => {
  let broker;
  let contract;

  before(async () => {
    broker = await startTestBroker();
    contract = JSON.parse(
      await readFile(new URL('../contract/control-protocol.json', import.meta.url), 'utf8'),
    );
  });

  after(async () => {
    await broker.stop();
  });

  it('renders every platform the contract lists, and only those', () => {
    const sample = {
      dropId: 'abcdefghijklmnopqrstuv',
      url: 'https://x.test/#r.aaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      code: '007',
      expiresAt: 1_800_000_000_000,
      fieldCount: 3,
    };
    for (const platform of contract.notice_platforms) {
      assert.equal(typeof outboundNotice({ ...sample, platform }), 'string', platform);
    }
    assert.throws(() => outboundNotice({ ...sample, platform: 'slack' }), /unsupported/);
    assert.throws(() => outboundNotice({ ...sample, platform: '__proto__' }), /unsupported/);
  });

  it('answers with the notice in the same response that mints the drop', async () => {
    const created = await broker.control({
      op: 'create_outbound_drop',
      payload_format: 'structured',
      notice_platform: 'telegram',
      plaintext_b64: Buffer.from(JSON.stringify(CANON), 'utf8').toString('base64'),
    });

    assert.equal(created.ok, true);
    assert.equal(
      created.notice,
      outboundNotice({
        dropId: created.drop_id,
        url: created.url,
        code: created.code,
        expiresAt: created.expires_at,
        fieldCount: 5,
        platform: 'telegram',
      }),
      'the notice is rendered for the platform asked for, in one round trip',
    );
  });

  it('says the four things a person has to be told, in the message itself', async () => {
    for (const platform of ['discord', 'telegram', 'plain']) {
      const created = await broker.control({
        op: 'create_outbound_drop',
        payload_format: 'structured',
        notice_platform: platform,
        plaintext_b64: Buffer.from(JSON.stringify(CANON), 'utf8').toString('base64'),
      });
      const notice = created.notice;

      assert.ok(notice.includes(created.url), `${platform}: the link`);
      assert.ok(notice.includes(created.code), `${platform}: the code`);
      assert.match(notice, /reveal it once/i, `${platform}: one reveal only`);
      assert.match(notice, /cannot be opened again/i, `${platform}: and what that means`);
      assert.match(notice, /not posted here/i, `${platform}: why it is not in the chat`);
      assert.match(notice, /5 labelled values/, `${platform}: what is in it, derived not quoted`);
      // The deadline, in the form the platform can actually render.
      if (platform === 'discord') assert.match(notice, /<t:\d+:R>/);
      else assert.match(notice, /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2} UTC/);
      assert.ok(!notice.includes('<') || platform === 'discord', `${platform}: no HTML`);
    }
  });

  it('never quotes a label, a title or a value into the chat message', async () => {
    // The one property that keeps a Markdown message safe from a model-composed
    // string: nothing of the payload but its field *count* is in the text. A title
    // of `x](https://evil.test) [click` would otherwise forge a link.
    const created = await broker.control({
      op: 'create_outbound_drop',
      payload_format: 'structured',
      notice_platform: 'telegram',
      plaintext_b64: Buffer.from(
        JSON.stringify({
          v: 1,
          title: 'x](https://evil.test) [click here',
          fields: [
            { label: 'Inject me](https://evil.test)', type: 'secret', value: 'example-xyzzy' },
          ],
        }),
        'utf8',
      ).toString('base64'),
    });

    assert.equal(created.ok, true);
    for (const forbidden of ['evil.test', 'Inject me', 'click here', 'xyzzy']) {
      assert.ok(!created.notice.includes(forbidden), `${forbidden} must not reach the chat`);
    }
    // Exactly one Markdown link, and it is the drop's own.
    assert.deepEqual(
      [...created.notice.matchAll(/\]\(([^)]*)\)/g)].map((match) => match[1]),
      [created.url],
    );
  });

  it('refuses an unknown notice platform without minting anything', async () => {
    for (const notice_platform of ['slack', 'PLAIN', 'telegram ', 42, null, '__proto__']) {
      const answer = await broker.control({
        op: 'create_outbound_drop',
        notice_platform,
        plaintext_b64: Buffer.from('x', 'utf8').toString('base64'),
      });
      assert.deepEqual(
        answer,
        { ok: false, error: 'invalid_request' },
        `platform ${JSON.stringify(notice_platform)}`,
      );
    }
  });

  it('leaves the response untouched when no platform is asked for', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });
    assert.ok(!('notice' in drop.created), 'the notice is opt-in, like the inbound one');
  });

  it('keeps the capability and the code out of every field except `url` and `notice`', async () => {
    const created = await broker.control({
      op: 'create_outbound_drop',
      payload_format: 'structured',
      notice_platform: 'plain',
      plaintext_b64: Buffer.from(JSON.stringify(CANON), 'utf8').toString('base64'),
    });
    const fragment = created.url.slice(created.url.indexOf('#') + 1);

    for (const [key, value] of Object.entries(created)) {
      if (key === 'url' || key === 'notice') continue;
      assert.ok(!String(value).includes(fragment), `${key} must not carry the fragment`);
    }
    // The decryption key is in the fragment and the fragment is in the URL. That is
    // the design — but it must be in nothing else, the notice included beyond its
    // one link.
    assert.equal(created.notice.split(fragment).length - 1, 1, 'the fragment appears once');
  });
});

describe('structured outbound drops: the shared contract fixture', () => {
  let broker;
  let contract;

  before(async () => {
    broker = await startTestBroker();
    contract = JSON.parse(
      await readFile(new URL('../contract/control-protocol.json', import.meta.url), 'utf8'),
    );
  });

  after(async () => {
    await broker.stop();
  });

  it('publishes the bounds the schema really enforces, so a foreign client can check them', () => {
    const bounds = contract.outbound_payload.bounds;
    assert.equal(contract.outbound_payload.version, OUTBOUND_PAYLOAD_VERSION);
    assert.equal(bounds.max_fields, MAX_FIELDS);
    assert.equal(bounds.max_label_chars, MAX_LABEL_CHARS);
    assert.equal(bounds.max_title_chars, MAX_TITLE_CHARS);
    assert.equal(bounds.max_value_bytes, MAX_VALUE_BYTES);
    assert.equal(bounds.max_payload_bytes, MAX_PAYLOAD_BYTES);
    assert.equal(bounds.max_note_lines, MAX_NOTE_LINES);
  });

  it('publishes exactly the types and the generator kinds the schema accepts', () => {
    assert.deepEqual(Object.keys(contract.outbound_payload.types).sort(), [...FIELD_TYPES].sort());
    // The sensitive one has to be identifiable from the fixture alone, because a
    // foreign renderer decides what to mask from this and nothing else.
    assert.match(contract.outbound_payload.types.secret, /masked/i);
    assert.match(contract.outbound_payload.default_type, /secret/);
    for (const kind of GENERATE_KINDS) {
      assert.ok(contract.outbound_payload.generate.includes(kind), kind);
    }
  });

  it('publishes every reason code the schema can answer with, and no others', () => {
    // A `reason` is the one field of a refusal a caller may branch on, so the list a
    // foreign client reads has to be the list this broker can actually produce.
    assert.deepEqual(
      [...contract.outbound_payload.reasons].sort(),
      [...REFUSAL_REASONS].sort(),
      'the fixture and the validator must name the same reasons',
    );

    // ...and the set is closed at the point of use, not just declared: `refuse`
    // throws on an undeclared code, so driving every refusal path proves the two
    // agree rather than merely that a constant was copied.
    const bad = [
      null,
      'string',
      { fields: [] },
      { v: 1, fields: [] },
      { v: 1, fields: [{}] },
      { v: 1, fields: [{ label: 'A', value: 'x', extra: 1 }] },
      { v: 1, fields: [{ label: 'A', type: 'nope', value: 'x' }] },
      { v: 1, fields: [{ label: 'L'.repeat(999), value: 'x' }] },
      { v: 1, fields: [{ label: 'A', value: 'v'.repeat(9999) }] },
      { v: 1, fields: [{ label: 'A', type: 'url', value: 'nope' }] },
      { v: 1, title: '  ', fields: [{ label: 'A', value: 'x' }] },
      { v: 1, title: 'T'.repeat(999), fields: [{ label: 'A', value: 'x' }] },
      { v: 1, fields: [{ label: 'A', value: 'x' }, { label: 'a', value: 'y' }] },
      { v: 1, fields: Array.from({ length: 99 }, (_u, i) => ({ label: `F${i}`, value: 'x' })) },
      { v: 1, fields: [{ label: 'A', generate: { kind: 'nope', length: 9 } }] },
    ];
    for (const input of bad) {
      const result = buildOutboundPayload(input);
      assert.equal(result.ok, false, JSON.stringify(input)?.slice(0, 80));
      assert.ok(REFUSAL_REASONS.includes(result.reason), result.reason);
    }
    assert.equal(parseOutboundPayload('{').reason, 'not_json');
  });

  it('states the two properties a reader cannot verify from prose', async () => {
    assert.match(contract.outbound_payload.atomicity, /valid or it is nothing/i);
    assert.match(contract.outbound_payload.rendering, /textContent/);
    assert.match(contract.ops.create_outbound_drop.errors.reason, /CODE and never prose/);
    assert.match(
      contract.ops.create_outbound_drop.request.payload_format.note,
      /BEFORE minting/,
      'the refusal has to be documented as pre-mint, because there is no destroy op',
    );

    // ...and the enum the fixture publishes is the enum the server enforces.
    const formats = contract.ops.create_outbound_drop.request.payload_format.enum;
    for (const payload_format of formats) {
      const answer = await broker.control({
        op: 'create_outbound_drop',
        payload_format,
        plaintext_b64: Buffer.from(
          payload_format === 'structured' ? JSON.stringify(CANON) : 'opaque bytes',
          'utf8',
        ).toString('base64'),
      });
      assert.equal(answer.ok, true, payload_format);
      assert.equal(answer.payload_format, payload_format);
    }
    assert.deepEqual(
      contract.ops.create_outbound_drop.request.notice_platform.enum,
      contract.notice_platforms,
      'the outbound notice renders the same platforms the inbound one does',
    );
  });
});

describe('structured outbound drops: what reaches a log line', () => {
  it('logs the drop id, the format and the field count, and never a label or a value', async () => {
    const lines = [];
    const record = (line) => lines.push(String(line));
    const broker = await startTestBroker({
      logger: { info: record, warn: record, error: record },
    });

    try {
      const created = await broker.control({
        op: 'create_outbound_drop',
        payload_format: 'structured',
        notice_platform: 'plain',
        plaintext_b64: Buffer.from(
          JSON.stringify({
            v: 1,
            title: 'Title xyzzy',
            fields: [{ label: 'Label xyzzy', type: 'secret', value: 'value-xyzzy' }],
          }),
          'utf8',
        ).toString('base64'),
      });
      assert.equal(created.ok, true);

      // ...and a refusal, which is the path most likely to want to explain itself
      // by quoting what it refused.
      await broker.control({
        op: 'create_outbound_drop',
        payload_format: 'structured',
        plaintext_b64: Buffer.from(
          JSON.stringify({ v: 1, fields: [{ label: 'xyzzy ', value: 'value-xyzzy' }] }),
          'utf8',
        ).toString('base64'),
      });

      const joined = lines.join('\n');
      assert.ok(lines.length > 0, 'something was logged, or this proves nothing');
      assert.ok(!joined.includes('xyzzy'), joined);
      assert.ok(!joined.includes(created.code), 'and never the code');
      assert.ok(!joined.includes(created.url.slice(created.url.indexOf('#') + 1)));
    } finally {
      await broker.stop();
    }
  });
});
