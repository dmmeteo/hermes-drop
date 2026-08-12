// Outbound secret drops (docs/OUTBOUND_SECRET_DROP_MVP.md), slice U1: the
// broker/control contract Hermes mints one with, and the public code-gated claim
// lifecycle a browser walks.
//
// The direction is the opposite of every other suite in this repo. There the
// browser holds a secret and the broker receives it; here Hermes holds one and the
// broker hands it to exactly one browser, once, behind a 3-digit code.
//
// Everything is asserted at the seams the two parties actually reach — the 0600
// control socket and the public HTTP endpoints — never at a private helper, so a
// refactor that kept the tests green kept the contract too.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { after, before, describe, it } from 'node:test';

import {
  OUTBOUND_ALG,
  OUTBOUND_CODE_DIGITS,
  OUTBOUND_MAX_CODE_ATTEMPTS,
  OUTBOUND_PROTOCOL,
  parseOutboundFragment,
} from '../src/outbound-drop.js';
import { DEFAULTS, loadConfig } from '../src/config.js';
import { createOutboundDrop, startTestBroker } from './helpers/harness.js';

/** The secret under test. Never printed, and never asserted on except once. */
const SECRET = 'correct horse battery staple';

const toBase64 = (value) => Buffer.from(value, 'utf8').toString('base64');

describe('outbound drops: the control contract that mints one', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  const create = (request = {}) =>
    broker.control({ op: 'create_outbound_drop', plaintext_b64: toBase64(SECRET), ...request });

  it('mints a link whose fragment carries the capability and the decryption key', async () => {
    const created = await create();

    assert.equal(created.ok, true);
    assert.match(created.drop_id, /^[A-Za-z0-9_-]{22}$/);
    assert.equal(created.outbound_protocol, OUTBOUND_PROTOCOL);

    // The whole point of the fragment: a browser gets the key, and a server — this
    // one, an unfurler, a proxy, an access log — never does.
    const [target, fragment] = created.url.split('#');
    assert.equal(target, `${broker.baseUrl}/`);
    const parsed = parseOutboundFragment(fragment);
    assert.ok(parsed, 'the fragment must parse with the client the page will use');
    assert.match(parsed.capability, /^[A-Za-z0-9_-]{22}$/);
    assert.match(parsed.key, /^[A-Za-z0-9_-]{43}$/, 'a 32-byte AES key, base64url');
  });

  it('answers with the approved defaults: 3 digits, 3 attempts, the configured TTL', async () => {
    const created = await create();

    assert.match(created.code, /^[0-9]{3}$/);
    assert.equal(created.code_length, OUTBOUND_CODE_DIGITS);
    assert.equal(OUTBOUND_CODE_DIGITS, 3);
    assert.equal(created.max_code_attempts, OUTBOUND_MAX_CODE_ATTEMPTS);
    assert.equal(OUTBOUND_MAX_CODE_ATTEMPTS, 3);
    // Thirty minutes for this deployment, from the outbound dial rather than the
    // inbound one — the two agree numerically today and are still separate decisions.
    assert.equal(created.ttl_seconds, 1800);
    assert.ok(created.expires_at > Date.now() + 1_790_000);
    assert.ok(created.expires_at <= Date.now() + 1_800_000);
    assert.equal(typeof created.ack_window_ms, 'number');
  });

  it('keeps the key out of every field but `url`, and the secret out of all of them', async () => {
    const created = await create();
    const { capability, key } = parseOutboundFragment(created.url.split('#')[1]);

    for (const [field, value] of Object.entries(created)) {
      if (field === 'url') continue;
      assert.ok(!String(value).includes(key), `${field} must not carry the decryption key`);
      assert.ok(!String(value).includes(capability), `${field} must not carry the capability`);
    }
    // The response is what Hermes posts from, so the one thing it must never carry
    // is the secret itself.
    assert.ok(!JSON.stringify(created).includes(SECRET));
  });

  it('stores ciphertext only: no plaintext, no key, no raw code on the record', async () => {
    const created = await create();
    const snapshot = broker.testOutboundSnapshot(created.drop_id);

    assert.equal(snapshot.state, 'available');
    assert.equal(snapshot.hasCiphertext, true);
    assert.equal(snapshot.hasKey, false, 'the broker hands the key away and keeps none');
    assert.equal(snapshot.attemptsRemaining, OUTBOUND_MAX_CODE_ATTEMPTS);

    const { key } = parseOutboundFragment(created.url.split('#')[1]);
    for (const secret of [SECRET, key]) {
      assert.ok(
        !snapshot.serialized.includes(secret),
        'a serialized record must carry neither the secret nor the key',
      );
    }

    // The code is checked as a *value*, not as a substring. Three digits turn up by
    // chance inside 64 characters of capability hash and two epoch timestamps about
    // one run in six, so a substring assertion here is a coin toss dressed as a
    // security check — it failed exactly that often before this was rewritten. What is
    // actually claimed is that no field of the record is the code and that the
    // verifier is not printable, and both of those are checkable.
    const record = JSON.parse(snapshot.serialized);
    assert.ok(!('code' in record), 'there is no code field to redact in the first place');
    for (const [field, value] of Object.entries(record)) {
      assert.notEqual(String(value), created.code, `${field} must not be the code`);
    }
    assert.equal(record.verifier, '[redacted]');
    assert.equal(record.verifierKey, '[redacted]');
    assert.ok(!snapshot.serialized.includes(`"${created.code}"`), 'nor the code as a JSON string');
  });

  it('refuses a malformed request without minting anything', async () => {
    const refusals = {
      noPayload: { plaintext_b64: undefined },
      empty: { plaintext_b64: '' },
      notBase64: { plaintext_b64: 'not base64!!' },
      nonCanonical: { plaintext_b64: `${toBase64(SECRET)}=` },
      notAString: { plaintext_b64: 42 },
      tooLarge: { plaintext_b64: Buffer.alloc(4096, 0x61).toString('base64') },
      ttlZero: { ttl_seconds: 0 },
      ttlNegative: { ttl_seconds: -1 },
      ttlPastMax: { ttl_seconds: 999_999 },
      ttlNotANumber: { ttl_seconds: 'ten' },
    };

    for (const [name, request] of Object.entries(refusals)) {
      const response = await create(request);
      assert.deepEqual(response, { ok: false, error: 'invalid_request' }, name);
      assert.ok(!('drop_id' in response), `${name} must mint nothing on the way out`);
    }
  });

  // A drop that lapses before the message carrying its link renders is worse than a
  // refusal: the user meets the uniform 404, which is byte-identical to the one a
  // secret somebody *else* took produces, and no seam on either side can tell them
  // apart. The floor is on the effective lifetime, not on the sign of the float.
  it('refuses a TTL too short to be a lifetime rather than minting a dead drop', async () => {
    for (const ttl_seconds of [1e-9, 0.001, 0.4, 0.999]) {
      const response = await create({ ttl_seconds });
      assert.deepEqual(response, { ok: false, error: 'invalid_request' }, String(ttl_seconds));
    }

    const minimum = await create({ ttl_seconds: 1 });
    assert.equal(minimum.ok, true, 'one second is the floor, not the first refusal');
    assert.ok(minimum.expires_at > Date.now(), 'and what it mints has a future deadline');
  });

  // Every other numeric field on this socket is type-checked rather than coerced
  // (`max_files`, `lease_ms`, `index`, `size`, `received_bytes`), and the fixture says
  // `"type": "number"`. A boolean that quietly becomes a one-second drop is the same
  // user-visible failure as the case above, reached from a foreign client's type slip.
  it('type-checks ttl_seconds instead of coercing it', async () => {
    for (const ttl_seconds of [true, false, '1800', '  1800  ', '', [], [1800], {}, null]) {
      const response = await create({ ttl_seconds });
      assert.deepEqual(
        response,
        { ok: false, error: 'invalid_request' },
        `${JSON.stringify(ttl_seconds)} must be refused, not coerced`,
      );
    }
  });

  it('bounds a requested TTL by the outbound ceiling, not by the inbound one', async () => {
    const narrow = await startTestBroker({ outboundTtlSeconds: 600, maxOutboundTtlSeconds: 900 });
    try {
      const ask = (ttl_seconds) =>
        narrow.control({ op: 'create_outbound_drop', plaintext_b64: toBase64(SECRET), ttl_seconds });

      // Well inside the broker-wide maximum (3600) and past the outbound one.
      assert.deepEqual(await ask(1800), { ok: false, error: 'invalid_request' });
      assert.deepEqual(await ask(3600), { ok: false, error: 'invalid_request' });
      // At the ceiling: accepted, so the bound is the ceiling and not the default.
      const atCeiling = await ask(900);
      assert.equal(atCeiling.ok, true);
      assert.equal(atCeiling.ttl_seconds, 900);
      // An exceptional request above the *default* is still legal, which is why the
      // ceiling is a separate dial rather than the default doing double duty.
      assert.equal((await ask(750)).ttl_seconds, 750);
      // ...and the inbound dial is untouched: the same broker still mints a
      // half-hour inbound drop, because the two exposures are different decisions.
      assert.equal((await narrow.control({ op: 'create', ttl_seconds: 1800 })).ok, true);
    } finally {
      await narrow.stop();
    }
  });
});

// Volatile between two responses and therefore excluded from a fingerprint; the
// same set seam 5 excludes, for the same reason.
const VOLATILE_HEADERS = new Set(['date', 'connection', 'keep-alive']);

function fingerprint(response, body) {
  const headers = [...response.headers.entries()]
    .filter(([name]) => !VOLATILE_HEADERS.has(name))
    .sort(([a], [b]) => a.localeCompare(b));
  return `${response.status}\n${JSON.stringify(headers)}\n${body}`;
}

describe('outbound drops: the public metadata seam', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  async function call(path, capability, body) {
    const response = await fetch(`${broker.baseUrl}${path}`, {
      method: 'POST',
      headers: {
        ...(capability === null ? {} : { 'x-handoff-capability': capability }),
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body,
    });
    return fingerprint(response, await response.text());
  }

  it('publishes what a page needs to render the gate, and nothing that opens it', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    const metadata = await drop.metadata();

    assert.equal(metadata.did, drop.id);
    assert.equal(metadata.alg, OUTBOUND_ALG);
    assert.equal(metadata.code_length, OUTBOUND_CODE_DIGITS);
    assert.equal(metadata.attempts_remaining, OUTBOUND_MAX_CODE_ATTEMPTS);
    assert.equal(metadata.expires_at, drop.created.expires_at);
    // The broker's own clock, so a countdown does not depend on the device's.
    assert.ok(metadata.now >= drop.created.expires_at - 1_800_000);

    // Not the payload, not the key, not the code, and not a verifier of the code.
    const serialized = JSON.stringify(metadata);
    for (const field of ['ct', 'iv', 'verifier', 'code', 'plaintext']) {
      assert.ok(!(field in metadata), `${field} must not be in metadata`);
    }
    assert.ok(!serialized.includes(drop.code), 'metadata must not carry the code');
    assert.ok(!serialized.includes(drop.key), 'metadata must not carry the key');
    assert.ok(!serialized.includes(SECRET));
  });

  it('answers one identical unavailable for unknown, malformed, expired and gone', async () => {
    // A genuinely minted drop whose deadline is then moved into the past. It has to be
    // minted, and asserted so: a refused create would leave `capability` null and turn
    // this whole comparison into the "absent header" case wearing the word "expired".
    const expired = await createOutboundDrop(broker, { plaintext: SECRET });
    assert.match(expired.capability, /^[A-Za-z0-9_-]{22}$/, 'the expired case must be a real drop');
    broker.testSetOutboundExpiry(expired.id, Date.now() - 1);
    const live = await createOutboundDrop(broker, { plaintext: SECRET });

    const capabilities = {
      expired: expired.capability,
      unknown: 'z'.repeat(22),
      tooShort: 'z'.repeat(21),
      tooLong: 'z'.repeat(23),
      badCharset: `${'z'.repeat(20)}+/`,
      empty: '',
      absent: null,
      // An *inbound* capability is not an outbound one, and this endpoint must not
      // say which of the two it failed to find.
      inbound: (await broker.control({ op: 'create' })).url.split('#')[1],
    };

    const results = {};
    for (const [name, capability] of Object.entries(capabilities)) {
      results[name] = await call('/api/reveal/metadata', capability);
    }

    const reference = results.expired;
    assert.ok(reference.startsWith('404\n'), 'the unavailable contract is a 404 with no detail');
    assert.ok(reference.endsWith('{"status":"unavailable"}'));
    for (const [name, value] of Object.entries(results)) {
      assert.equal(value, reference, `${name} must be indistinguishable from expired`);
    }
    // ...and the live drop is still live, so nothing above touched it.
    assert.equal(broker.testOutboundSnapshot(live.id).state, 'available');
  });

  it('never claims, reserves or spends an attempt on GET or HEAD', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });

    // Everything a scanner, an unfurler or an antivirus does to a link.
    for (const path of ['/', `/#r.${drop.capability}.${drop.key}`, '/api/reveal/metadata', '/api/reveal/claim', '/api/reveal/ack']) {
      for (const method of ['GET', 'HEAD']) {
        const response = await fetch(`${broker.baseUrl}${path}`, {
          method,
          headers: { 'x-handoff-capability': drop.capability },
        });
        // The page answers 200; every /api/* target answers the uniform refusal
        // whatever the method, so probing one the wrong way discloses nothing.
        assert.ok(response.status === 200 || response.status === 404, `${method} ${path}`);
        await response.text();
      }
    }

    const snapshot = broker.testOutboundSnapshot(drop.id);
    assert.equal(snapshot.state, 'available', 'a preview must not reserve the drop');
    assert.equal(snapshot.attemptsRemaining, OUTBOUND_MAX_CODE_ATTEMPTS);
    assert.equal(snapshot.hasCiphertext, true);
    // ...and the drop is still claimable afterwards, which is the property that
    // matters to the user rather than the states above.
    const claimed = await drop.claim({ claimId: 'a'.repeat(22) });
    assert.equal(claimed.status, 'revealed');
  });
});

describe('outbound drops: the code gate', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  /** A code that is definitely not this drop's, in the right shape. */
  const wrongCode = (code) => String((Number(code) + 1) % 1000).padStart(3, '0');

  it('spends one attempt per wrong code and says how many are left', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });

    const first = await drop.claim({ code: wrongCode(drop.code) });
    assert.deepEqual(first, { status: 'code_incorrect', attempts_remaining: 2 });
    const second = await drop.claim({ code: wrongCode(drop.code) });
    assert.deepEqual(second, { status: 'code_incorrect', attempts_remaining: 1 });

    // Nothing was handed out and nothing was reserved on the way.
    const snapshot = broker.testOutboundSnapshot(drop.id);
    assert.equal(snapshot.state, 'available');
    assert.equal(snapshot.attemptsRemaining, 1);
    assert.equal(snapshot.claimed, false);

    // ...and the right code still works with one attempt left.
    const revealed = await drop.reveal();
    assert.equal(revealed.status, 'revealed');
    assert.equal(revealed.plaintext, SECRET);
  });

  it('destroys the payload on the third wrong code, and says nothing more', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });

    for (const attempts_remaining of [2, 1]) {
      assert.deepEqual(await drop.claim({ code: wrongCode(drop.code) }), {
        status: 'code_incorrect',
        attempts_remaining,
      });
    }
    // The third refusal is the uniform one: the drop is over, and a caller learns
    // exactly what it would learn about a link that never existed.
    assert.deepEqual(await drop.claim({ code: wrongCode(drop.code) }), { status: 'unavailable' });

    assert.equal(broker.testOutboundSnapshot(drop.id), null, 'the record is gone, not merely locked');
    // And the *correct* code buys nothing afterwards. This is the trade the MVP
    // states: denial of delivery over online brute force.
    assert.deepEqual(await drop.claim(), { status: 'unavailable' });
    assert.equal((await drop.metadata()), null);
  });

  it('publishes the wrong-code refusal as 403 with the remaining count and nothing else', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });

    const response = await fetch(`${broker.baseUrl}/api/reveal/claim`, {
      method: 'POST',
      headers: { 'x-handoff-capability': drop.capability, 'content-type': 'application/json' },
      body: JSON.stringify({ code: wrongCode(drop.code), claim_id: 'b'.repeat(22) }),
    });
    assert.equal(response.status, 403);
    const body = await response.text();
    assert.deepEqual(JSON.parse(body), { status: 'code_incorrect', attempts_remaining: 2 });
    assert.ok(!body.includes(drop.code), 'a refusal must not carry the code it refused');
  });

  it('charges no attempt for a malformed code, a malformed claim id or a malformed body', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });

    const bodies = [
      { code: '12', claim_id: 'c'.repeat(22) },
      { code: '1234', claim_id: 'c'.repeat(22) },
      { code: 'abc', claim_id: 'c'.repeat(22) },
      { code: 12, claim_id: 'c'.repeat(22) },
      { code: ' 12', claim_id: 'c'.repeat(22) },
      { code: drop.code, claim_id: 'short' },
      { code: drop.code, claim_id: 42 },
      { code: drop.code },
      {},
    ];
    for (const body of bodies) {
      const response = await fetch(`${broker.baseUrl}/api/reveal/claim`, {
        method: 'POST',
        headers: { 'x-handoff-capability': drop.capability, 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      assert.equal(response.status, 404, JSON.stringify(body));
      assert.equal(await response.text(), '{"status":"unavailable"}');
    }
    for (const body of ['', 'not json', 'null', '[]', 'x'.repeat(4096)]) {
      const response = await fetch(`${broker.baseUrl}/api/reveal/claim`, {
        method: 'POST',
        headers: { 'x-handoff-capability': drop.capability, 'content-type': 'application/json' },
        body,
      });
      assert.equal(response.status, 404, body.slice(0, 12));
      assert.equal(await response.text(), '{"status":"unavailable"}');
    }

    // A shape mistake is the client's, and the user's three attempts are not the
    // place to charge it: all of the above cost nothing.
    assert.equal(broker.testOutboundSnapshot(drop.id).attemptsRemaining, 3);
    assert.equal((await drop.metadata()).attempts_remaining, 3);
  });
});

describe('outbound drops: one browser, and one retry of that browser', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  it('hands the secret to a browser that knows the code, and only through the fragment key', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });

    const claimed = await drop.claim({ claimId: 'd'.repeat(22) });
    assert.equal(claimed.status, 'revealed');
    assert.equal(claimed.did, drop.id);
    // The one equality check this suite is allowed: the bytes the browser opens are
    // the bytes Hermes handed in.
    assert.equal(await drop.open(claimed), SECRET);

    // The ciphertext alone is not the secret: without the fragment key it is bytes.
    assert.ok(!claimed.ct.includes(Buffer.from(SECRET, 'utf8').toString('base64url')));
    // The first base64url character always maps to real ciphertext bits (unlike the
    // last, which can carry unused ones), and it is flipped to a *different* value
    // rather than to a fixed one — writing 'A' over a ciphertext that already starts
    // with 'A' is not a tamper, and this assertion passed by luck 1 run in ~64.
    const tampered = `${claimed.ct[0] === 'A' ? 'B' : 'A'}${claimed.ct.slice(1)}`;
    assert.notEqual(tampered, claimed.ct, 'the tamper has to actually change a byte');
    await assert.rejects(
      () => drop.open({ ...claimed, ct: tampered }),
      'a tampered ciphertext must fail the AEAD rather than decrypt to something',
    );
  });

  it('binds the payload to its own drop id, not merely to its key', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    const claimed = await drop.claim();

    // The right key and the *wrong* drop id: still an AEAD failure, because the drop
    // id is in the additional authenticated data. Asserting this with the right key
    // is the whole point — a cross-drop test would have failed on the key alone and
    // would have passed with no binding at all.
    await assert.rejects(
      () => drop.open({ ...claimed, did: 'z'.repeat(22) }),
      'the payload must be bound to the drop it was sealed for',
    );
    // ...and one drop's key does not open another's ciphertext either.
    const other = await createOutboundDrop(broker, { plaintext: 'a different secret' });
    await assert.rejects(() => other.open(claimed));
  });

  it('reserves for exactly one claimant, however many arrive with the right code', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });

    const claimants = await Promise.all(
      Array.from({ length: 6 }, (_, index) =>
        drop.claim({ claimId: String(index).repeat(22).slice(0, 22) }),
      ),
    );
    const revealed = claimants.filter((claimed) => claimed.status === 'revealed');
    assert.equal(revealed.length, 1, 'exactly one browser may reveal a drop');
    for (const loser of claimants.filter((claimed) => claimed.status !== 'revealed')) {
      // The losers are told the uniform thing, not "someone else has it".
      assert.deepEqual(loser, { status: 'unavailable' });
    }
    // A loser's arrival must not have cost the winner an attempt either.
    assert.equal(broker.testOutboundSnapshot(drop.id).attemptsRemaining, 3);
  });

  it('answers the same claim id with the same bytes, and a different one with nothing', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    const claimId = 'e'.repeat(22);

    const first = await drop.claim({ claimId });
    const retry = await drop.claim({ claimId });
    assert.deepEqual(retry, first, 'a retry is the same delivery, not a second one');
    assert.equal(await drop.open(retry), SECRET);

    // A second browser, with the correct code, inside the window: still nothing.
    assert.deepEqual(await drop.claim({ claimId: 'f'.repeat(22) }), { status: 'unavailable' });
    // ...and the same claim id with the *wrong* code is refused without a hint and
    // without spending an attempt, because the budget bounds guessing at an
    // available drop and this one is already reserved.
    assert.deepEqual(
      await drop.claim({ claimId, code: String((Number(drop.code) + 1) % 1000).padStart(3, '0') }),
      { status: 'unavailable' },
    );
    // The retry still works after all of that.
    assert.deepEqual(await drop.claim({ claimId }), first);
  });

  it('refuses a reserved drop at the metadata seam too, without disclosing why', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    assert.ok(await drop.metadata());

    await drop.claim({ claimId: 'g'.repeat(22) });
    assert.equal(await drop.metadata(), null, 'a reserved drop is unavailable to a fresh page');
  });
});

describe('outbound drops: destruction', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  it('destroys the payload on acknowledgement, and answers nothing afterwards', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });

    const revealed = await drop.reveal({ claimId: 'h'.repeat(22) });
    assert.equal(revealed.status, 'revealed');
    assert.equal(revealed.plaintext, SECRET);
    assert.equal(revealed.acknowledged, 'acknowledged');

    assert.equal(broker.testOutboundSnapshot(drop.id), null, 'the ack destroys the record');
    // Every seam afterwards, including the claimant's own retry: the drop is over.
    assert.deepEqual(await drop.claim({ claimId: 'h'.repeat(22) }), { status: 'unavailable' });
    assert.equal(await drop.ack({ claimId: 'h'.repeat(22) }), 'unavailable');
    assert.equal(await drop.metadata(), null);
  });

  it('refuses an acknowledgement from anyone but the claimant', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    const claimId = 'i'.repeat(22);
    await drop.claim({ claimId });

    assert.equal(await drop.ack({ claimId: 'j'.repeat(22) }), 'unavailable');
    // ...and the real claimant is untouched by the attempt.
    assert.equal(broker.testOutboundSnapshot(drop.id).state, 'reserved');
    assert.equal(await drop.ack({ claimId }), 'acknowledged');
  });

  it('destroys the payload when the claim window lapses unacknowledged', async () => {
    const short = await startTestBroker({ outboundAckWindowMs: 300 });
    try {
      const drop = await createOutboundDrop(short, { plaintext: SECRET });
      const claimed = await drop.claim({ claimId: 'k'.repeat(22) });
      assert.equal(claimed.status, 'revealed');
      assert.ok(claimed.claim_expires_at <= Date.now() + 300);

      await new Promise((resolve) => setTimeout(resolve, 700));
      assert.equal(
        short.testOutboundSnapshot(drop.id),
        null,
        'a browser that reveals and vanishes must not leave the payload resident',
      );
      assert.deepEqual(await drop.claim({ claimId: 'k'.repeat(22) }), { status: 'unavailable' });
    } finally {
      await short.stop();
    }
  });

  it('destroys an unclaimed drop when its own TTL lapses', async () => {
    // The deadline is moved rather than minted short: a sub-second TTL is refused by
    // design now (see the lifetime floor), and this drives the same `live()` and the
    // same sweeper a real lapse does.
    const swept = await createOutboundDrop(broker, { plaintext: SECRET });
    assert.equal(broker.testOutboundSnapshot(swept.id).state, 'available');
    broker.testSetOutboundExpiry(swept.id, Date.now() - 1);

    await new Promise((resolve) => setTimeout(resolve, 1400));
    assert.equal(
      broker.testOutboundSnapshot(swept.id),
      null,
      'the sweeper must drop the record without anyone touching it',
    );

    // ...and lazily too, on the next touch, so a parked sweeper cannot extend a life.
    const touched = await createOutboundDrop(broker, { plaintext: SECRET });
    broker.testSetOutboundExpiry(touched.id, Date.now() - 1);
    assert.equal(await touched.metadata(), null);
    assert.equal(broker.testOutboundSnapshot(touched.id), null);
    assert.deepEqual(await touched.claim({ claimId: 'o'.repeat(22) }), { status: 'unavailable' });
  });

  it('destroys every outbound payload on shutdown, like every other state', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    broker.broker.destroyAll();
    assert.equal(broker.testOutboundSnapshot(drop.id), null);
  });
});

// The fixture both languages read. The Hermes side is a separate codebase upgraded
// on its own schedule, so what it can implement without guessing has to be *in* the
// fixture and has to be held against the running broker — the same argument the
// universal declaration is published under, and the same reason: a foreign client
// that guesses at a lifecycle loses a payload learning it was wrong.
describe('outbound drops: the shared contract fixture', () => {
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

  it('advertises the outbound capability on every create, inbound ones included', async () => {
    assert.equal(contract.outbound_drop.protocol, OUTBOUND_PROTOCOL);
    assert.match(
      contract.outbound_drop.advertised_as,
      /absen(ce|t) means/i,
      'absence has to mean something specific, because a broker without it sends nothing',
    );

    const inbound = await broker.control({ op: 'create', ttl_seconds: 60 });
    assert.equal(inbound.outbound_protocol, OUTBOUND_PROTOCOL);
    const outbound = await createOutboundDrop(broker, { plaintext: SECRET });
    assert.equal(outbound.created.outbound_protocol, OUTBOUND_PROTOCOL);
    // ...and it is a capability, not a version bump: the protocol version is
    // untouched, exactly as the framed file claim left it.
    assert.equal(inbound.protocol_version, contract.version);
    assert.equal(outbound.created.protocol_version, contract.version);
  });

  it('documents the numbers the broker really enforces', async () => {
    const code = contract.outbound_drop.code;
    assert.equal(code.digits, OUTBOUND_CODE_DIGITS);
    assert.equal(code.max_attempts, OUTBOUND_MAX_CODE_ATTEMPTS);
    assert.match(code.note, /never appears in the URL/i, 'where the code must not be is the point');
    assert.match(code.attempts_note, /denial of delivery/i, 'the trade has to be stated');
    assert.match(contract.outbound_drop.stored, /[Cc]iphertext only/);
    assert.match(contract.outbound_drop.stored, /drops the key/i);

    const created = await createOutboundDrop(broker, { plaintext: SECRET });
    assert.equal(created.created.code_length, code.digits);
    assert.equal(created.created.max_code_attempts, code.max_attempts);
    assert.equal(created.code.length, code.digits);
  });

  it('names the public endpoints, the statuses and the capability header it really uses', async () => {
    const surface = contract.outbound_drop.public;
    assert.equal(surface.capability_header, 'x-handoff-capability');
    assert.deepEqual(
      [...surface.statuses].sort(),
      ['acknowledged', 'code_incorrect', 'revealed', 'unavailable'],
    );
    // A public body is not a control-protocol error, and conflating the two would put
    // `code_incorrect` in a vocabulary foreign clients read off the socket.
    for (const status of surface.statuses) {
      if (status === 'unavailable') continue;
      assert.ok(!contract.errors.includes(status), `${status} is not a socket error`);
    }
    assert.match(surface.statuses_note, /NOT entries/i);
    assert.match(surface.safe_previews, /GET or HEAD/);
    assert.match(surface.decryption, /additional authenticated data/i);
    assert.match(contract.outbound_drop.one_browser, /synchronously/);
    assert.match(contract.outbound_drop.same_claim_retry, /not a second delivery/i);
    assert.match(contract.outbound_drop.destruction, /whichever comes first/);
    assert.match(contract.outbound_drop.fragment, /never send/);

    // ...and each documented endpoint answers as documented, at the path published.
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    const paths = Object.keys(surface.endpoints).map((entry) => entry.split(' ')[1]);
    assert.deepEqual(paths, ['/api/reveal/metadata', '/api/reveal/claim', '/api/reveal/ack']);
    for (const entry of Object.keys(surface.endpoints)) {
      assert.ok(entry.startsWith('POST '), `${entry} must be POST — a preview must not claim`);
    }
    assert.ok(await drop.metadata());
    const claimed = await drop.claim({ claimId: 'l'.repeat(22) });
    assert.equal(claimed.status, 'revealed');
    assert.equal(await drop.ack({ claimId: 'l'.repeat(22) }), 'acknowledged');
  });

  it('states the request fields the op really validates', async () => {
    const request = contract.ops.create_outbound_drop.request;
    assert.equal(request.op, 'create_outbound_drop');
    assert.equal(request.plaintext_b64.optional, false);
    assert.match(request.plaintext_b64.note, /canonical base64/i);
    assert.match(request.plaintext_b64.note, /2048/, 'the ceiling is a number a client can check');
    assert.equal(request.ttl_seconds.optional, true);
    assert.match(request.ttl_seconds.note, /1800/, 'the fixture has to quote the real default');
    assert.match(
      request.ttl_seconds.note,
      /HANDOFF_MAX_OUTBOUND_TTL_SECONDS/,
      'and the outbound ceiling it is bounded by, which is not the inbound one',
    );

    // The two halves a client cannot verify from prose: that the ceiling is real, and
    // that the default is the one documented.
    const atCeiling = Buffer.alloc(2048, 0x61).toString('base64');
    const accepted = await broker.control({ op: 'create_outbound_drop', plaintext_b64: atCeiling });
    assert.equal(accepted.ok, true, 'the documented ceiling must be accepted');
    const over = Buffer.alloc(2049, 0x61).toString('base64');
    assert.deepEqual(await broker.control({ op: 'create_outbound_drop', plaintext_b64: over }), {
      ok: false,
      error: 'invalid_request',
    });
    assert.equal(accepted.ttl_seconds, 1800);
  });

  it('keeps the outbound id space out of every inbound op', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });

    // An outbound drop is not a handoff. Nothing above may claim, await or transfer
    // one, and each refusal is the uniform body rather than a hint that the id names
    // something of another kind.
    for (const op of ['await', 'claim', 'begin_file_claim']) {
      assert.deepEqual(await broker.control({ op, handoff_id: drop.id }), {
        ok: false,
        error: 'unavailable',
      });
    }
    // ...and the drop is untouched by all of it.
    assert.equal(broker.testOutboundSnapshot(drop.id).state, 'available');
  });
});

describe('outbound drops: what reaches a log line', () => {
  it('logs the drop id and the reason, and never the secret, the key, the capability or a code', async () => {
    const lines = [];
    const record = (line) => lines.push(String(line));
    const local = await startTestBroker({
      logger: { info: record, warn: record, error: record },
      outboundAckWindowMs: 200,
    });

    try {
      // Every path that logs: create, a wrong code, a spent budget, a reveal, an ack,
      // a lapsed ack window and an expiry.
      const drop = await createOutboundDrop(local, { plaintext: SECRET });
      const wrong = String((Number(drop.code) + 1) % 1000).padStart(3, '0');
      await drop.claim({ code: wrong });
      await drop.reveal({ claimId: 'm'.repeat(22) });

      const spent = await createOutboundDrop(local, { plaintext: SECRET });
      const spentWrong = String((Number(spent.code) + 1) % 1000).padStart(3, '0');
      for (let attempt = 0; attempt < 3; attempt += 1) await spent.claim({ code: spentWrong });

      const abandoned = await createOutboundDrop(local, { plaintext: SECRET });
      await abandoned.claim({ claimId: 'n'.repeat(22) });
      const lapsing = await createOutboundDrop(local, { plaintext: SECRET });
      local.testSetOutboundExpiry(lapsing.id, Date.now() - 1);
      await new Promise((resolve) => setTimeout(resolve, 1400));

      assert.ok(lines.length >= 8, 'the paths under test must actually have logged');
      for (const line of lines) {
        assert.ok(!line.includes(SECRET), 'no plaintext in a log line');
        for (const drops of [drop, spent, abandoned, lapsing]) {
          assert.ok(!line.includes(drops.key), 'no decryption key in a log line');
          assert.ok(!line.includes(drops.capability), 'no capability in a log line');
        }
        // No code field at all, rather than "no code that happens to be this one":
        // a three-digit number is too easy to match by accident to be checked as a
        // value, so what is pinned is that nothing logs one under any name.
        assert.ok(!/\bcode=/.test(line), `a code must never be a log field: ${line}`);
        assert.ok(!/claim_id=|verifier/.test(line), 'nor a claim id or a verifier');
      }
      // ...and what an operator does get is the id and the reason, which is what makes
      // a destroyed drop diagnosable without making it disclosable.
      assert.ok(lines.some((line) => line.includes(drop.id) && line.includes('reason=acknowledged')));
      assert.ok(lines.some((line) => line.includes('reason=code_attempts_spent')));
      assert.ok(lines.some((line) => line.includes('reason=ack_timeout')));
      assert.ok(lines.some((line) => line.includes('reason=expired')));
    } finally {
      await local.stop();
    }
  });
});

// The operator's seam is startup. Every comparable knob in this repository is pinned
// the same way (test/file-mode-broker.test.js does it for the file caps): a lowered
// value is accepted, a raise is refused, an incoherent pair is refused, and each env
// key round-trips — because the argument for a bound lives in a comment, and a comment
// does not fail when a later refactor inverts the comparison it explains.
describe('outbound drops: the operator dials', () => {
  const env = (values) => loadConfig({}, values);

  it('defaults to a 30-minute drop under its own configurable ceiling', () => {
    const config = env({});
    assert.equal(config.outboundTtlSeconds, 1800, 'the deployment canon is thirty minutes');
    assert.equal(config.maxOutboundTtlSeconds, 3600);
    assert.equal(config.maxOutboundPlaintextBytes, 2048);
    assert.equal(config.outboundAckWindowMs, 60_000);
    // The outbound ceiling is its own dial rather than the inbound one, which is the
    // whole point: an operator can shorten outbound exposure without shortening the
    // window a user has to compose an inbound secret.
    assert.notEqual(config.maxOutboundTtlSeconds, config.maxTtlSeconds - 1);
    assert.ok(config.maxOutboundTtlSeconds <= config.maxTtlSeconds);
  });

  it('round-trips every outbound env key', () => {
    const config = env({
      HANDOFF_OUTBOUND_TTL_SECONDS: '900',
      HANDOFF_MAX_OUTBOUND_TTL_SECONDS: '1200',
      HANDOFF_MAX_OUTBOUND_PLAINTEXT_BYTES: '512',
      HANDOFF_OUTBOUND_ACK_WINDOW_MS: '30000',
    });
    assert.equal(config.outboundTtlSeconds, 900);
    assert.equal(config.maxOutboundTtlSeconds, 1200);
    assert.equal(config.maxOutboundPlaintextBytes, 512);
    assert.equal(config.outboundAckWindowMs, 30_000);
  });

  it('lets the outbound ceiling be narrowed but never raised past the broker maximum', () => {
    assert.equal(
      env({ HANDOFF_MAX_OUTBOUND_TTL_SECONDS: '900', HANDOFF_OUTBOUND_TTL_SECONDS: '600' })
        .maxOutboundTtlSeconds,
      900,
    );
    assert.throws(
      () => env({ HANDOFF_MAX_OUTBOUND_TTL_SECONDS: '3601' }),
      /HANDOFF_MAX_OUTBOUND_TTL_SECONDS/,
      'an outbound ceiling above the broker-wide maximum is not a ceiling',
    );
    // A ceiling under the default it is supposed to bound is incoherent, and refusing
    // it at startup is the only place it can be refused usefully: at runtime every
    // create would be an unexplained invalid_request.
    assert.throws(
      () => env({ HANDOFF_MAX_OUTBOUND_TTL_SECONDS: '600' }),
      /HANDOFF_OUTBOUND_TTL_SECONDS/,
      'the default has to fit inside its own ceiling',
    );
    // ...and an exceptional TTL between the default and the ceiling is legal, which is
    // the reason the ceiling is a separate dial and not the default itself.
    const config = env({ HANDOFF_OUTBOUND_TTL_SECONDS: '600', HANDOFF_MAX_OUTBOUND_TTL_SECONDS: '2400' });
    assert.ok(config.maxOutboundTtlSeconds > config.outboundTtlSeconds);
  });

  // R1. `HANDOFF_MAX_TTL_SECONDS` has no upper bound of its own — it is validated only
  // as the thing the inbound TTL must fit inside — so bounding the outbound ceiling by
  // it alone means an operator who raises the inbound maximum for an inbound reason
  // silently raises how long an outbound secret and its 3-digit code stay readable in a
  // chat conversation. That is the exposure the outbound ceiling exists to bound
  // independently, and the README promises in bold that it cannot happen.
  it('keeps the outbound ceiling narrow-only even when the inbound maximum is raised', async () => {
    assert.throws(
      () => env({ HANDOFF_MAX_TTL_SECONDS: '86400', HANDOFF_MAX_OUTBOUND_TTL_SECONDS: '86400' }),
      /HANDOFF_MAX_OUTBOUND_TTL_SECONDS/,
      'a day-long outbound ceiling is a raise, whatever the inbound maximum allows',
    );

    // A raised inbound maximum on its own leaves the outbound ceiling where it was.
    const config = env({ HANDOFF_MAX_TTL_SECONDS: '86400' });
    assert.equal(config.maxTtlSeconds, 86_400);
    assert.equal(config.maxOutboundTtlSeconds, 3600, 'the two dials move independently');

    // ...and the broker really refuses such a drop, which is the half of the rule a
    // config assertion cannot prove.
    const wide = await startTestBroker({ maxTtlSeconds: 86_400 });
    try {
      const outbound = await wide.control({
        op: 'create_outbound_drop',
        plaintext_b64: toBase64(SECRET),
        ttl_seconds: 7200,
      });
      assert.deepEqual(outbound, { ok: false, error: 'invalid_request' });
      // The inbound drop of the same length is fine on the same broker: that is the
      // separation, stated as behaviour rather than as configuration.
      assert.equal((await wide.control({ op: 'create', ttl_seconds: 7200 })).ok, true);
    } finally {
      await wide.stop();
    }
  });

  it('refuses an outbound TTL that is zero, negative or shorter than a second', () => {
    for (const value of ['0', '-1', '0.5', '0.001']) {
      assert.throws(() => env({ HANDOFF_OUTBOUND_TTL_SECONDS: value }), /HANDOFF_OUTBOUND_TTL_SECONDS/, value);
    }
    // One second is the floor, and it takes an ack window that fits inside it — which
    // is the pair rule below, exercised here from the other side.
    const config = env({ HANDOFF_OUTBOUND_TTL_SECONDS: '1', HANDOFF_OUTBOUND_ACK_WINDOW_MS: '1000' });
    assert.equal(config.outboundTtlSeconds, 1);
  });

  it('lets the plaintext ceiling be lowered and refuses a raise', () => {
    assert.equal(env({ HANDOFF_MAX_OUTBOUND_PLAINTEXT_BYTES: '64' }).maxOutboundPlaintextBytes, 64);
    for (const value of ['0', '2049', '4096']) {
      assert.throws(
        () => env({ HANDOFF_MAX_OUTBOUND_PLAINTEXT_BYTES: value }),
        /HANDOFF_MAX_OUTBOUND_PLAINTEXT_BYTES/,
        value,
      );
    }
  });

  // The same discipline test/file-mode-broker.test.js applies to the file caps: an
  // operator pastes these numbers out of the README into an env file, and three of the
  // four are narrow-only — so a README number that is merely *wrong* is a startup
  // crash for whoever trusted it. The table is held against the loader, not proof-read.
  it('prints the shipped outbound defaults in the README, and loads them back', async () => {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
    const rows = [...readme.matchAll(/^\| `(HANDOFF_[A-Z_]+)` \| `(\d+)`/gm)];
    const printed = Object.fromEntries(rows.map((row) => [row[1], row[2]]));

    const OUTBOUND_KEYS = {
      HANDOFF_OUTBOUND_TTL_SECONDS: 'outboundTtlSeconds',
      HANDOFF_MAX_OUTBOUND_TTL_SECONDS: 'maxOutboundTtlSeconds',
      HANDOFF_MAX_OUTBOUND_PLAINTEXT_BYTES: 'maxOutboundPlaintextBytes',
      HANDOFF_OUTBOUND_ACK_WINDOW_MS: 'outboundAckWindowMs',
    };
    for (const [envKey, configKey] of Object.entries(OUTBOUND_KEYS)) {
      assert.ok(printed[envKey], `${envKey} must appear in the README with its default`);
      assert.equal(
        Number(printed[envKey]),
        DEFAULTS[configKey],
        `the README default for ${envKey} is not the shipped one`,
      );
      assert.equal(env({ [envKey]: printed[envKey] })[configKey], DEFAULTS[configKey]);
    }

    // The startup refusal an operator actually hits has to be findable in the README,
    // because under `restart: unless-stopped` it is a crash loop until they find it.
    assert.match(readme, /lowering the outbound TTL under 60 s/i);
  });

  it('refuses an ack window that is zero or outlives its own drop', () => {
    assert.throws(() => env({ HANDOFF_OUTBOUND_ACK_WINDOW_MS: '0' }), /HANDOFF_OUTBOUND_ACK_WINDOW_MS/);
    // The refusal an operator actually hits: shortening the outbound TTL under the
    // 60-second ack window without shortening the window too.
    assert.throws(
      () => env({ HANDOFF_OUTBOUND_TTL_SECONDS: '30' }),
      /HANDOFF_OUTBOUND_ACK_WINDOW_MS/,
      'the message has to name the key that is now too large',
    );
    const config = env({ HANDOFF_OUTBOUND_TTL_SECONDS: '30', HANDOFF_OUTBOUND_ACK_WINDOW_MS: '15000' });
    assert.equal(config.outboundAckWindowMs, 15_000);
  });
});

describe('outbound drops: the review findings', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  const post = async (path, capability, body) => {
    try {
      const response = await fetch(`${broker.baseUrl}${path}`, {
        method: 'POST',
        headers: { 'x-handoff-capability': capability, 'content-type': 'application/json' },
        body,
      });
      return `${response.status} ${await response.text()}`;
    } catch (error) {
      // A body far past the ceiling is cut off rather than drained, which the client
      // sees as a reset. That is the one case where the uniform body cannot be
      // honoured, and it is the point of the bound.
      return `cut off: ${error.cause?.code ?? error.message}`;
    }
  };

  // L3. The claim id authorizes destruction, so the comparison must be constant-time
  // like the code's — and it must not *throw* on a length it did not expect, which is
  // exactly what a naive `timingSafeEqual` does. A crash here would be a 500 on a seam
  // whose entire contract is one uniform refusal.
  it('compares the claim id safely, whatever length is presented', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    const claimId = 'p'.repeat(22);
    assert.equal((await drop.claim({ claimId })).status, 'revealed');

    for (const wrong of ['q'.repeat(22), '', 'short', 'x'.repeat(40), 'p'.repeat(21), 'p'.repeat(23)]) {
      assert.equal(
        await post('/api/reveal/ack', drop.capability, JSON.stringify({ claim_id: wrong })),
        '404 {"status":"unavailable"}',
        `ack with ${wrong.length} characters must be the uniform refusal, not an error`,
      );
    }
    // Nothing above destroyed the payload or unseated the real claimant.
    assert.equal(broker.testOutboundSnapshot(drop.id).state, 'reserved');
    assert.equal(await drop.ack({ claimId }), 'acknowledged');
  });

  // L6. The page renders its pre-claim countdown from this number, so publishing the
  // configured window rather than the honourable one tells the user they have time the
  // broker will not give them.
  it('publishes the ack window the drop can actually honour', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    assert.equal((await drop.metadata()).ack_window_ms, 60_000, 'a fresh drop can honour it all');

    broker.testSetOutboundExpiry(drop.id, Date.now() + 5_000);
    const near = await drop.metadata();
    assert.ok(near.ack_window_ms > 0, 'a live drop still has some window');
    assert.ok(
      near.ack_window_ms <= 5_000,
      `a drop with 5s of life must not advertise ${near.ack_window_ms}ms of ack window`,
    );

    // ...and the window it then grants agrees with what was advertised, clamped to the
    // drop's own expiry rather than to the configured number.
    const claimed = await drop.claim({ claimId: 's'.repeat(22) });
    assert.equal(claimed.status, 'revealed');
    assert.ok(claimed.claim_expires_at <= drop.created.expires_at);
    assert.ok(claimed.claim_expires_at <= Date.now() + 5_000);
  });

  // L4. The capability is deliberately resolved *after* the body is read, so that
  // "this capability is valid" is not observable from whether a body was drained. The
  // fix is therefore the drain bound, not the order: an unauthenticated caller may
  // cost this endpoint a few kilobytes, not a megabyte.
  it('bounds what an unauthenticated reveal body can make the broker read', async () => {
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    const junk = 'z'.repeat(22);

    // Small over-limit bodies keep the polite uniform refusal, so nothing about the
    // ordinary malformed case changes.
    for (const bytes of [1024, 2048]) {
      assert.equal(
        await post('/api/reveal/claim', junk, 'x'.repeat(bytes)),
        '404 {"status":"unavailable"}',
        `${bytes} bytes must still be answered politely`,
      );
    }
    // A 64 KiB body — 128x the ceiling — must not be read to the end just to be
    // refused, and neither must a megabyte.
    for (const bytes of [64 * 1024, 1024 * 1024]) {
      const result = await post('/api/reveal/claim', junk, 'x'.repeat(bytes));
      assert.notEqual(
        result,
        '404 {"status":"unavailable"}',
        `${bytes} bytes must be cut off rather than drained`,
      );
    }
    // The endpoint is unharmed by all of it, and no attempt was spent.
    assert.equal(broker.testOutboundSnapshot(drop.id).attemptsRemaining, 3);
    assert.equal((await drop.claim({ claimId: 't'.repeat(22) })).status, 'revealed');
  });

  // L1. The module states the invariant without qualification — the buffer the secret
  // arrived in is wiped in the same call — so it has to hold on the paths that never
  // reach the encryption, which are exactly the paths a caller retries after.
  it('wipes the plaintext buffer on every refusal, not only on success', async () => {
    const refusals = {
      oversized: { plaintext: Buffer.alloc(4096, 0x61) },
      ttlTooShort: { plaintext: Buffer.from(SECRET, 'utf8'), ttlSeconds: 0.2 },
      ttlTooLong: { plaintext: Buffer.from(SECRET, 'utf8'), ttlSeconds: 999_999 },
      ttlNotFinite: { plaintext: Buffer.from(SECRET, 'utf8'), ttlSeconds: Number.NaN },
      // R3. A `BigInt` or a `Symbol` cannot be multiplied — `ttlSeconds * 1000` *throws*
      // — so a validation that does the arithmetic before the type check leaves the
      // buffer un-wiped on the way out, which is the hole the wipe invariant closed.
      // Unreachable through the control socket (JSON carries neither, and the seam
      // type-checks first) and reachable by any in-process caller, including this one.
      ttlBigInt: { plaintext: Buffer.from(SECRET, 'utf8'), ttlSeconds: 10n },
      ttlSymbol: { plaintext: Buffer.from(SECRET, 'utf8'), ttlSeconds: Symbol('ttl') },
      ttlObject: { plaintext: Buffer.from(SECRET, 'utf8'), ttlSeconds: { valueOf: () => 60 } },
      ttlString: { plaintext: Buffer.from(SECRET, 'utf8'), ttlSeconds: '60' },
    };

    for (const [name, request] of Object.entries(refusals)) {
      const buffer = request.plaintext;
      // The refusal must be a refusal, not a throw: a caller that meets an exception
      // here has no idea whether the drop was minted, and the buffer is the evidence.
      let response;
      await assert.doesNotReject(async () => {
        response = await broker.broker.createOutboundDrop(request);
      }, `${name} must be refused rather than thrown at`);
      assert.deepEqual(response, { ok: false, error: 'invalid_request' }, name);
      assert.ok(buffer.every((byte) => byte === 0), `${name} left the secret in memory`);
    }

    // ...and on the success path, which is the one the `finally` already covered.
    const accepted = Buffer.from(SECRET, 'utf8');
    const created = await broker.broker.createOutboundDrop({ plaintext: accepted });
    assert.equal(created.ok, true);
    assert.ok(accepted.every((byte) => byte === 0));
  });

  // L2. `create_outbound_drop` is the first op that carries plaintext *into* this
  // socket, which changes what a parse-error message can contain: V8 embeds a ~10
  // character window of the offending input in `JSON.parse` messages.
  it('logs a malformed control line by class, never by content', async () => {
    const lines = [];
    const record = (line) => lines.push(String(line));
    const local = await startTestBroker({ logger: { info: record, warn: record, error: record } });

    try {
      const b64 = toBase64(SECRET);
      // The shape a serializer bug or a partial write produces: a line that stops
      // being JSON exactly where the secret starts.
      const malformed = `{"op":"create_outbound_drop","plaintext_b64":${b64}\n`;
      const answer = await new Promise((resolve, reject) => {
        const socket = connect(local.controlSocketPath, () => socket.write(malformed));
        let buffer = '';
        socket.on('data', (chunk) => {
          buffer += chunk;
        });
        socket.on('end', () => resolve(buffer.trim()));
        socket.on('error', reject);
      });
      assert.deepEqual(JSON.parse(answer), { ok: false, error: 'invalid_request' });

      assert.ok(lines.some((line) => /rejected/.test(line)), 'the refusal is still logged');
      for (const line of lines) {
        assert.ok(!line.includes(b64.slice(0, 8)), `a log line carried the secret: ${line}`);
        assert.ok(!line.includes(SECRET));
      }
    } finally {
      await local.stop();
    }
  });
});

// The fixture is the only authoritative written description of the outbound lifecycle
// a foreign client reads, so where it overstated what the code does, the correction
// gets a test. A promise in a contract is a feature nobody implemented.
describe('outbound drops: the contract tells the truth', () => {
  let broker;
  let outbound;

  before(async () => {
    broker = await startTestBroker();
    outbound = JSON.parse(
      await readFile(new URL('../contract/control-protocol.json', import.meta.url), 'utf8'),
    ).outbound_drop;
  });

  after(async () => {
    await broker.stop();
  });

  it('scopes the same-claim retry to a dropped response, and names the reload loss', async () => {
    assert.match(outbound.same_claim_retry, /dropped response/i);
    assert.ok(
      !/reload/i.test(outbound.same_claim_retry),
      'the reload case belongs to the paragraph that denies it, not the one that promises',
    );

    const loss = outbound.same_claim_retry_does_not_survive_a_reload;
    assert.equal(typeof loss, 'string', 'the loss mode has to be documented, not implied');
    assert.match(loss, /fresh/i, 'a reloaded page draws a new claim id');
    assert.match(loss, /uniform body/, 'and meets the same refusal as a dead drop');
    assert.match(loss, /one-shot|no re-request/i, 'with nothing to re-request');

    // ...and that is really what happens. A page that lost its claim id is a second
    // claimant, and the broker cannot tell the two apart — which is the point.
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    await drop.claim({ claimId: 'u'.repeat(22) });
    assert.equal(await drop.metadata(), null, 'the reloaded page cannot render the gate');
    assert.deepEqual(await drop.claim({ claimId: 'v'.repeat(22) }), { status: 'unavailable' });
  });

  it('describes the claim id as the token that authorizes destruction', () => {
    assert.match(outbound.claim_id, /destroy/i, 'what it authorizes has to be stated');
    assert.match(outbound.claim_id, /never put it in a URL/i);
    assert.match(outbound.claim_id, /constant time/i);
    assert.match(outbound.claim_id, /CSPRNG/);
  });

  it('publishes the liveness disclosure it accepts instead of implying there is none', async () => {
    const note = outbound.public.liveness_disclosure;
    assert.equal(typeof note, 'string');
    assert.match(note, /not rate-limited/i);
    assert.match(note, /countdown/i, 'and why it is accepted rather than closed');

    // The behaviour the note describes: metadata flips the instant a reservation is
    // taken. Pinned so the note cannot become false in either direction.
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    assert.ok(await drop.metadata());
    await drop.claim({ claimId: 'w'.repeat(22) });
    assert.equal(await drop.metadata(), null);
  });

  // R2. The deletion-guarantee list is what a reader checks when deciding what
  // "destroyed" is worth, and it used to say a payload is never destroyed by expiry
  // alone — contradicting its own state diagram three paragraphs above, and the
  // behaviour a test in this file pins. Both cases have to be in it.
  it('states both destruction paths in SECURITY.md, not only the reserved one', async () => {
    const security = await readFile(new URL('../SECURITY.md', import.meta.url), 'utf8');
    const section = security.slice(
      security.indexOf('## Outbound drop lifecycle and deletion guarantees'),
      security.indexOf('## Known limitations tracked rather than fixed'),
    );
    assert.ok(section.length > 0, 'the outbound section has to exist to be checked');

    const guarantees = section.slice(
      section.indexOf('### What deletion guarantees'),
      section.indexOf('### What it does not guarantee'),
    );
    assert.match(guarantees, /reserved/i, 'the reserved path: ack or window, whichever is first');
    assert.match(guarantees, /unclaimed/i, 'and the unclaimed one, which the TTL destroys');
    assert.match(guarantees, /TTL/);
    assert.ok(
      !/never at the TTL alone/i.test(guarantees),
      'the old wording denied the very path the diagram and the tests both state',
    );

    // ...and the behaviour it now describes is the behaviour under test: an unclaimed
    // drop really is destroyed by expiry with nobody touching it (see the destruction
    // suite), which is what makes the corrected sentence the true one.
    const drop = await createOutboundDrop(broker, { plaintext: SECRET });
    broker.testSetOutboundExpiry(drop.id, Date.now() - 1);
    broker.broker.sweep();
    assert.equal(broker.testOutboundSnapshot(drop.id), null);
  });

  it('says the published ack window is the one the drop can honour', () => {
    const metadata = outbound.public.endpoints['POST /api/reveal/metadata'];
    assert.match(metadata, /clamped/i);
    assert.match(metadata, /remaining life|own remaining/i);
  });

  it('states the TTL floor, the type check and the outbound ceiling', () => {
    const contractRoot = outbound;
    assert.ok(contractRoot, 'the outbound block exists');
    // The floor and the type rule are the two things a foreign client cannot discover
    // safely: it would learn them by posting a link for a drop that was already dead.
    const note = JSON.parse(
      readFileSync(new URL('../contract/control-protocol.json', import.meta.url), 'utf8'),
    ).ops.create_outbound_drop.request.ttl_seconds.note;
    assert.match(note, /1000 ms|1 second|at least 1000/i);
    assert.match(note, /Type-checked, not coerced/);
    assert.match(note, /HANDOFF_MAX_OUTBOUND_TTL_SECONDS/);
    assert.match(note, /NOT by the inbound maximum/i);
  });
});
