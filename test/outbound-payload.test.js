// The structured outbound payload: the schema the reveal page renders and the
// bounds the broker refuses outside of (docs/OUTBOUND_SECRET_DROP_MVP.md, and the
// recovered UX canon — a revealed payload is JSON, the page renders however many
// fields it holds, each with a label, a Copy button and a mask for the sensitive
// ones).
//
// Everything here is about *refusing*. The schema is the one place a model-supplied
// object crosses into a page that will render it, so the interesting assertions are
// not "a good payload validates" but "each way of being bad is refused, whole, with
// a reason that carries none of the payload back".
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  FIELD_TYPES,
  MAX_FIELDS,
  MAX_LABEL_CHARS,
  MAX_PAYLOAD_BYTES,
  MAX_TITLE_CHARS,
  MAX_VALUE_BYTES,
  OUTBOUND_PAYLOAD_VERSION,
  SENSITIVE_FIELD_TYPES,
  buildOutboundPayload,
  canonicalizeOutboundPayload,
  isSensitiveFieldType,
  parseOutboundPayload,
  validateOutboundPayload,
} from '../src/outbound-payload.js';

const field = (over = {}) => ({ label: 'Password', type: 'secret', value: 'hunter2', ...over });
const payload = (over = {}) => ({ v: OUTBOUND_PAYLOAD_VERSION, fields: [field()], ...over });

/** Every refusal is the same shape, and the reason is a code rather than prose. */
function refusal(input, reason) {
  const result = validateOutboundPayload(input);
  assert.equal(result.ok, false, `expected a refusal for ${JSON.stringify(input)?.slice(0, 120)}`);
  assert.equal(result.reason, reason);
  assert.ok(!('payload' in result), 'a refusal hands back nothing to render');
  return result;
}

describe('the structured outbound payload: what it accepts', () => {
  it('accepts the canon example — login, password, API key, URL and note', () => {
    const result = validateOutboundPayload({
      v: 1,
      title: 'OpenRouter access',
      fields: [
        { label: 'Login', type: 'text', value: 'ops@example.test' },
        { label: 'Password', type: 'secret', value: 'example-not-a-real-secret' },
        { label: 'API key', type: 'secret', value: 'sk-example-not-a-real-key' },
        { label: 'Console', type: 'url', value: 'https://openrouter.test/keys' },
        { label: 'Note', type: 'note', value: 'Rotate this within 30 days.\nAsk ops first.' },
      ],
    });

    assert.equal(result.ok, true);
    assert.equal(result.payload.fields.length, 5);
    assert.deepEqual(
      result.payload.fields.map((entry) => entry.type),
      ['text', 'secret', 'secret', 'url', 'note'],
    );
    assert.equal(result.payload.title, 'OpenRouter access');
  });

  it('renders a single field as happily as five, which is what "however many" means', () => {
    for (const count of [1, 2, MAX_FIELDS]) {
      const fields = Array.from({ length: count }, (_unused, index) =>
        field({ label: `Field ${index + 1}` }),
      );
      const result = validateOutboundPayload(payload({ fields }));
      assert.equal(result.ok, true, `${count} fields`);
      assert.equal(result.payload.fields.length, count);
    }
  });

  it('treats a missing type as sensitive, so an unlabelled field masks rather than shows', () => {
    const result = validateOutboundPayload(payload({ fields: [{ label: 'Token', value: 'abc' }] }));
    assert.equal(result.ok, true);
    assert.equal(result.payload.fields[0].type, 'secret');
    assert.equal(isSensitiveFieldType(result.payload.fields[0].type), true);
  });

  it('keeps the sensitive set inside the type set, and non-secret types displayable', () => {
    for (const type of SENSITIVE_FIELD_TYPES) assert.ok(FIELD_TYPES.includes(type));
    assert.deepEqual([...SENSITIVE_FIELD_TYPES], ['secret']);
    for (const type of FIELD_TYPES) {
      assert.equal(isSensitiveFieldType(type), type === 'secret', type);
    }
    // An unknown type is sensitive too. A future type this bundle does not know
    // must mask rather than display, because the one that shows a secret in the
    // clear is the mistake that cannot be taken back.
    assert.equal(isSensitiveFieldType('something-new'), true);
    assert.equal(isSensitiveFieldType(undefined), true);
  });

  it('accepts labels and values outside ASCII, because the users are not', () => {
    const result = validateOutboundPayload(
      payload({ fields: [{ label: 'Логін', type: 'text', value: 'оператор' }] }),
    );
    assert.equal(result.ok, true);
    assert.equal(result.payload.fields[0].label, 'Логін');
  });

  it('accepts the documented bounds exactly, and refuses one past each of them', () => {
    const label = 'L'.repeat(MAX_LABEL_CHARS);
    assert.equal(validateOutboundPayload(payload({ fields: [field({ label })] })).ok, true);
    refusal(payload({ fields: [field({ label: `${label}L` })] }), 'label_too_long');

    const value = 'v'.repeat(MAX_VALUE_BYTES);
    assert.equal(validateOutboundPayload(payload({ fields: [field({ value })] })).ok, true);
    refusal(payload({ fields: [field({ value: `${value}v` })] }), 'value_too_long');

    const title = 'T'.repeat(MAX_TITLE_CHARS);
    assert.equal(validateOutboundPayload(payload({ title })).ok, true);
    refusal(payload({ title: `${title}T` }), 'title_too_long');
  });
});

describe('the structured outbound payload: what it refuses', () => {
  it('refuses anything that is not an object with the version it knows', () => {
    for (const input of [null, undefined, 'a string', 42, true, [], () => {}]) {
      refusal(input, 'not_an_object');
    }
    refusal({ fields: [field()] }, 'bad_version');
    for (const v of [0, 2, '1', 1.5, true, null]) refusal(payload({ v }), 'bad_version');
  });

  it('refuses a field list that is empty, overlong or not a list', () => {
    refusal(payload({ fields: [] }), 'no_fields');
    for (const fields of [null, undefined, 'Password', {}, 3]) {
      refusal(payload({ fields }), 'no_fields');
    }
    refusal(
      payload({ fields: Array.from({ length: MAX_FIELDS + 1 }, (_u, i) => field({ label: `F${i}` })) }),
      'too_many_fields',
    );
  });

  it('refuses a key it does not know, at the root and inside a field', () => {
    refusal(payload({ extra: 'surprise' }), 'unknown_key');
    refusal(payload({ fields: [{ ...field(), sensitive: true }] }), 'unknown_key');
    // Including the ones a prototype would otherwise answer for.
    refusal(payload({ fields: [{ ...field(), constructor: 'x' }] }), 'unknown_key');
  });

  it('refuses a type outside the closed set rather than guessing at it', () => {
    for (const type of ['password', 'SECRET', 'html', '', 1, null, {}]) {
      refusal(payload({ fields: [field({ type })] }), 'bad_type');
    }
  });

  it('refuses a label that is empty, blank, padded or has no letter or digit in it', () => {
    for (const label of ['', ' ', '   ', ' Password', 'Password ', '\tPassword']) {
      refusal(payload({ fields: [field({ label })] }), 'bad_label');
    }
    refusal(payload({ fields: [field({ label: '***' })] }), 'bad_label');
    for (const label of [null, undefined, 7, {}, []]) {
      refusal(payload({ fields: [field({ label })] }), 'bad_label');
    }
  });

  it('allows an ordinary space in a label, and refuses every other kind', () => {
    // "API key" is the canon example, so a plain space is the point. Every other
    // whitespace character is refused: two labels that render identically and sort
    // differently are two labels a user cannot tell apart.
    assert.equal(
      validateOutboundPayload(payload({ fields: [field({ label: 'API key' })] })).ok,
      true,
    );
    for (const label of ['Pass\u00a0word', 'Pass\u2009word', 'Pass\tword', 'Pass  word']) {
      refusal(payload({ fields: [field({ label })] }), 'bad_label');
    }
  });

  it('refuses control characters and bidi overrides in a label', () => {
    // A label is rendered next to a value the user is about to trust, so a
    // right-to-left override that makes "Note" read as "Password" is not a
    // cosmetic problem.
    for (const label of [
      'Pass\u202eword',
      'Pass\u200bword',
      'Pass\u200fword',
      'Pass\nword',
      'Pass\u2028word',
    ]) {
      refusal(payload({ fields: [field({ label })] }), 'bad_label');
    }
  });

  it('refuses two fields that would render under the same label', () => {
    refusal(
      payload({ fields: [field({ label: 'Password' }), field({ label: 'password' })] }),
      'duplicate_label',
    );
  });

  it('refuses a value that is empty, non-string, or carries a control character', () => {
    for (const value of ['', null, undefined, 42, {}, []]) {
      refusal(payload({ fields: [field({ value })] }), 'bad_value');
    }
    // A plain space is legal in a value — a passphrase is four words — but a padded
    // one is not, and no other whitespace character is: two credentials that render
    // identically and authenticate differently is the failure a user cannot see.
    assert.equal(
      validateOutboundPayload(
        payload({ fields: [field({ value: 'correct horse battery staple' })] }),
      ).ok,
      true,
    );
    for (const value of ['a\u00a0b', 'a\u202eb', 'a\rb', 'a\tb', ' a', 'a ']) {
      refusal(payload({ fields: [field({ value })] }), 'bad_value');
    }
  });

  it('allows newlines in a note and nowhere else, and bounds how many', () => {
    const note = (value) => payload({ fields: [{ label: 'Note', type: 'note', value }] });
    assert.equal(validateOutboundPayload(note('one\ntwo\nthree')).ok, true);
    refusal(note('x\n'.repeat(9)), 'bad_value');
    for (const type of ['text', 'secret', 'url']) {
      refusal(payload({ fields: [field({ type, value: 'a\nb' })] }), 'bad_value');
    }
  });

  it('refuses a url field that is not an absolute http(s) URL', () => {
    const url = (value) => payload({ fields: [{ label: 'Console', type: 'url', value }] });
    assert.equal(validateOutboundPayload(url('https://example.test/a?b=c')).ok, true);
    assert.equal(validateOutboundPayload(url('http://example.test')).ok, true);
    for (const value of [
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      'file:///etc/passwd',
      'vbscript:msgbox',
      '//example.test',
      'example.test',
      'https://',
      'JAVASCRIPT:alert(1)',
    ]) {
      refusal(url(value), 'bad_url');
    }
  });

  it('refuses a payload whose canonical form is over the wire ceiling', () => {
    // Each field is inside its own bounds; the whole is not. Bounding the parts
    // and not the sum is how a request line that cannot be sent gets minted.
    const fields = Array.from({ length: MAX_FIELDS }, (_u, index) => ({
      label: `Field ${index + 1}`,
      type: 'secret',
      value: 'v'.repeat(MAX_VALUE_BYTES),
    }));
    refusal({ v: 1, fields }, 'payload_too_large');
  });
});

describe('the structured outbound payload: the canonical form', () => {
  it('serialises deterministically, in a fixed key order, with no incidental keys', () => {
    const first = canonicalizeOutboundPayload(
      validateOutboundPayload({
        v: 1,
        title: 'Two ways round',
        fields: [
          { value: 'ops@example.test', label: 'Login', type: 'text' },
          { type: 'secret', label: 'Password', value: 'example-not-a-real-secret' },
        ],
      }).payload,
    );
    const second = canonicalizeOutboundPayload(
      validateOutboundPayload({
        title: 'Two ways round',
        fields: [
          { label: 'Login', type: 'text', value: 'ops@example.test' },
          { label: 'Password', type: 'secret', value: 'example-not-a-real-secret' },
        ],
        v: 1,
      }).payload,
    );

    assert.equal(first, second, 'key order in the input cannot change the bytes stored');
    assert.equal(
      first,
      '{"v":1,"title":"Two ways round","fields":[' +
        '{"label":"Login","type":"text","value":"ops@example.test"},' +
        '{"label":"Password","type":"secret","value":"example-not-a-real-secret"}]}',
    );
  });

  it('omits a title that was never given rather than emitting an empty one', () => {
    const canonical = canonicalizeOutboundPayload(validateOutboundPayload(payload()).payload);
    assert.ok(!canonical.includes('title'));
    assert.equal(canonical, '{"v":1,"fields":[{"label":"Password","type":"secret","value":"hunter2"}]}');
  });

  it('round-trips through the parser the page uses', () => {
    const canonical = canonicalizeOutboundPayload(
      validateOutboundPayload(payload({ title: 'Round trip' })).payload,
    );
    const parsed = parseOutboundPayload(canonical);
    assert.equal(parsed.ok, true);
    assert.deepEqual(parsed.payload, validateOutboundPayload(payload({ title: 'Round trip' })).payload);
  });

  it('refuses text that is not JSON, or is JSON of the wrong shape, without throwing', () => {
    for (const text of ['', 'not json', '{', '[]', 'null', '"a string"', '{"v":1}']) {
      const parsed = parseOutboundPayload(text);
      assert.equal(parsed.ok, false, JSON.stringify(text));
      assert.equal(typeof parsed.reason, 'string');
    }
    assert.equal(parseOutboundPayload('not json').reason, 'not_json');
  });

  it('refuses oversized text before it parses it, so a huge line costs no parse', () => {
    const parsed = parseOutboundPayload(`{"v":1,"pad":"${'p'.repeat(MAX_PAYLOAD_BYTES)}"}`);
    assert.equal(parsed.ok, false);
    assert.equal(parsed.reason, 'payload_too_large');
  });

  it('never echoes a value or a label in the reason it refuses with', () => {
    // The reason travels back to a caller whose results reach a model's context and
    // durable state, so it has to be a code from a closed set and nothing else.
    const secret = 'example-not-a-real-secret-xyzzy';
    for (const input of [
      payload({ fields: [field({ value: `${secret} ` })] }),
      payload({ fields: [field({ label: `${secret}‮`, value: secret })] }),
      payload({ fields: [field({ type: secret, value: secret })] }),
    ]) {
      const result = validateOutboundPayload(input);
      assert.equal(result.ok, false);
      assert.ok(!JSON.stringify(result).includes('xyzzy'), JSON.stringify(result));
      assert.ok(/^[a-z_]+$/.test(result.reason), result.reason);
    }
  });
});

describe('the structured outbound payload: values the broker generates', () => {
  it('fills a generated field so the requester never held the value', () => {
    const built = buildOutboundPayload({
      v: 1,
      fields: [
        { label: 'Login', type: 'text', value: 'ops@example.test' },
        { label: 'Password', type: 'secret', generate: { kind: 'password', length: 24 } },
      ],
    });

    assert.equal(built.ok, true);
    const [, generated] = built.payload.fields;
    assert.equal(generated.value.length, 24);
    assert.match(generated.value, /^[A-Za-z0-9]+$/);
    assert.ok(!('generate' in generated), 'the request is replaced by its result');

    // Two builds of the same request must not produce the same secret.
    const again = buildOutboundPayload({
      v: 1,
      fields: [{ label: 'Password', type: 'secret', generate: { kind: 'password', length: 24 } }],
    });
    assert.notEqual(again.payload.fields[0].value, built.payload.fields[1].value);
  });

  it('generates every documented kind at its documented width', () => {
    for (const [kind, pattern] of [
      ['password', /^[A-Za-z0-9]{32}$/],
      ['hex', /^[0-9a-f]{32}$/],
      ['base64url', /^[A-Za-z0-9_-]{32}$/],
    ]) {
      const built = buildOutboundPayload({
        v: 1,
        fields: [{ label: 'Key', type: 'secret', generate: { kind, length: 32 } }],
      });
      assert.equal(built.ok, true, kind);
      assert.match(built.payload.fields[0].value, pattern, kind);
    }
  });

  it('refuses a generated field that also carries a value, or neither', () => {
    const build = (over) =>
      buildOutboundPayload({ v: 1, fields: [{ label: 'Key', type: 'secret', ...over }] });
    assert.equal(build({ value: 'a', generate: { kind: 'hex', length: 16 } }).reason, 'bad_value');
    assert.equal(build({}).reason, 'bad_value');
  });

  it('refuses to generate anything but a secret, an unknown kind, or a silly width', () => {
    const build = (over) => buildOutboundPayload({ v: 1, fields: [{ label: 'Key', ...over }] });
    assert.equal(
      build({ type: 'text', generate: { kind: 'hex', length: 16 } }).reason,
      'bad_generate',
    );
    for (const kind of ['uuid', '', null, 42]) {
      assert.equal(build({ type: 'secret', generate: { kind, length: 16 } }).reason, 'bad_generate');
    }
    for (const length of [0, 7, 65, 16.5, '16', true, null, undefined]) {
      assert.equal(
        build({ type: 'secret', generate: { kind: 'hex', length } }).reason,
        'bad_generate',
        `length ${JSON.stringify(length)}`,
      );
    }
    assert.equal(build({ type: 'secret', generate: 'hex' }).reason, 'bad_generate');
    assert.equal(
      build({ type: 'secret', generate: { kind: 'hex', length: 16, extra: 1 } }).reason,
      'unknown_key',
    );
  });

  it('validates the built payload as a whole, so a generated field cannot burst the ceiling', () => {
    const fields = Array.from({ length: MAX_FIELDS }, (_u, index) => ({
      label: `Key ${index + 1}`,
      type: 'secret',
      generate: { kind: 'base64url', length: 64 },
    }));
    fields.push({ label: 'Overflow', type: 'secret', value: 'v'.repeat(MAX_VALUE_BYTES) });
    const built = buildOutboundPayload({ v: 1, fields });
    assert.equal(built.ok, false);
    assert.equal(built.reason, 'too_many_fields');
  });

  it('is the plain validator when nothing asks to be generated', () => {
    const input = payload({ title: 'No generation here' });
    assert.deepEqual(buildOutboundPayload(input), validateOutboundPayload(input));
  });
});
