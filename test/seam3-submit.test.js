// Seam 3 — the browser POSTs an HPKE envelope; plaintext appears in neither the
// request body, the response body, nor the logs.
//
// Everything here drives src/client/handoff-client.js, i.e. the same module the
// page bundle ships, against a live broker over real HTTP.
import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, it } from 'node:test';

import {
  fetchMetadata,
  sealEnvelope,
  sendSecret,
  submitEnvelope,
} from '../src/client/handoff-client.js';
import { decodeBase64Url, splitHandoffUrl, startTestBroker } from './helpers/harness.js';

const SECRET = 'correct horse battery staple\nAWS_SECRET_ACCESS_KEY=example-not-a-real-key';

/** Records every request/response pair so the test can prove what crossed the wire. */
function recordingFetch(captures) {
  return async (url, options) => {
    const response = await fetch(url, options);
    const text = await response.text();
    captures.push({
      url: String(url),
      method: options?.method,
      headers: options?.headers ?? {},
      requestBody: options?.body ?? null,
      status: response.status,
      responseBody: text,
    });
    return new Response(text, { status: response.status, headers: response.headers });
  };
}

describe('seam 3: HPKE envelope submission', () => {
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

  async function createHandoff(options) {
    const created = await broker.control({ op: 'create', ...options });
    return { ...created, capability: splitHandoffUrl(created.url).capability };
  }

  it('accepts one envelope from the real client logic and keeps plaintext off the wire', async () => {
    const handoff = await createHandoff();
    const captures = [];

    const result = await sendSecret({
      capability: handoff.capability,
      plaintext: SECRET,
      fetchImpl: recordingFetch(captures),
      origin: broker.baseUrl,
    });
    assert.deepEqual(result, { status: 'sent' });

    const [metadataCall, submitCall] = captures;
    assert.equal(metadataCall.url, `${broker.baseUrl}/api/metadata`);
    assert.equal(submitCall.url, `${broker.baseUrl}/api/submit`);
    assert.equal(submitCall.status, 200);
    assert.deepEqual(JSON.parse(submitCall.responseBody), { status: 'received' });

    for (const call of captures) {
      assert.ok(!call.url.includes(handoff.capability), 'capability must stay out of the URL');
      assert.ok(!String(call.requestBody ?? '').includes(SECRET), 'no plaintext in request body');
      assert.ok(!call.responseBody.includes(SECRET), 'no plaintext in response body');
      // The capability travels as a header and nowhere else.
      if (call.requestBody) assert.ok(!String(call.requestBody).includes(handoff.capability));
    }

    const envelope = JSON.parse(submitCall.requestBody);
    assert.deepEqual(Object.keys(envelope).sort(), ['ct', 'enc', 'hid', 'pkfp', 'suite', 'v']);
    assert.equal(envelope.v, 1);
    assert.equal(envelope.hid, handoff.handoff_id);
    assert.equal(decodeBase64Url(envelope.enc).length, 65);
    assert.equal(decodeBase64Url(envelope.pkfp).length, 16);
    assert.equal(
      decodeBase64Url(envelope.ct).length,
      Buffer.byteLength(SECRET, 'utf8') + 16,
      'single Seal over the whole payload plus one AEAD tag',
    );
    assert.ok(!('nonce' in envelope), 'there must be no client-chosen nonce field');

    const snapshot = broker.testSnapshot(handoff.handoff_id);
    assert.equal(snapshot.state, 'submitted');
    assert.equal(snapshot.hasPlaintext, true);
    assert.equal(snapshot.hasPrivateKey, false, 'the handoff key dies once the AEAD succeeds');
    assert.ok(!snapshot.serialized.includes(SECRET));

    assert.ok(logLines.length > 0, 'the flow should log something');
    for (const line of logLines) {
      assert.ok(!line.includes(SECRET), `plaintext leaked into a log line: ${line}`);
      assert.ok(!line.includes(handoff.capability), `capability leaked into a log line: ${line}`);
    }
  });

  it('refuses a second submission with a different envelope', async () => {
    const handoff = await createHandoff();
    assert.equal(
      (await sendSecret({ ...clientArgs(handoff, broker), plaintext: 'first' })).status,
      'sent',
    );
    assert.equal(
      (await sendSecret({ ...clientArgs(handoff, broker), plaintext: 'second' })).status,
      'unavailable',
    );
    assert.equal(broker.testSnapshot(handoff.handoff_id).state, 'submitted');
  });

  it('treats a replay of the winning envelope as the same single delivery', async () => {
    const handoff = await createHandoff();
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });
    const envelope = await sealEnvelope({
      capability: handoff.capability,
      metadata,
      plaintext: SECRET,
    });

    const first = await submitEnvelope({ ...clientArgs(handoff, broker), envelope });
    const replay = await submitEnvelope({ ...clientArgs(handoff, broker), envelope });
    assert.equal(first, 'received');
    assert.equal(replay, 'received', 'an identical retry gets the same receipt');

    const snapshot = broker.testSnapshot(handoff.handoff_id);
    assert.equal(snapshot.state, 'submitted');
    assert.equal(snapshot.plaintextBytes, Buffer.byteLength(SECRET, 'utf8'), 'delivered once');
  });

  it('lets only one of many concurrent submissions win', async () => {
    const handoff = await createHandoff();
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });
    const envelopes = await Promise.all(
      ['a', 'b', 'c', 'd', 'e'].map((text) =>
        sealEnvelope({ capability: handoff.capability, metadata, plaintext: text }),
      ),
    );

    const results = await Promise.all(
      envelopes.map((envelope) => submitEnvelope({ ...clientArgs(handoff, broker), envelope })),
    );
    assert.equal(
      results.filter((status) => status === 'received').length,
      1,
      'exactly one submission may be accepted',
    );
    assert.ok(
      results.every((status) => status === 'received' || status === 'unavailable'),
      'the losers get the generic unavailable status',
    );
  });

  it('still returns the same receipt for an identical retry after the claim', async () => {
    const handoff = await createHandoff();
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });
    const envelope = await sealEnvelope({
      capability: handoff.capability,
      metadata,
      plaintext: SECRET,
    });
    assert.equal(await submitEnvelope({ ...clientArgs(handoff, broker), envelope }), 'received');

    const claimed = await broker.control({ op: 'claim', handoff_id: handoff.handoff_id });
    assert.equal(claimed.ok, true);

    // A retry that lost its response still sees success for the TTL remainder.
    assert.equal(await submitEnvelope({ ...clientArgs(handoff, broker), envelope }), 'received');
    assert.equal(await submitEnvelope({ ...clientArgs(handoff, broker), envelope }), 'received');

    // But the payload is delivered exactly once.
    const secondClaim = await broker.control({ op: 'claim', handoff_id: handoff.handoff_id });
    assert.equal(secondClaim.ok, false);
    assert.ok(!('plaintext_b64' in secondClaim));

    // And a different envelope gets the generic unavailable response.
    const different = await sealEnvelope({
      capability: handoff.capability,
      metadata,
      plaintext: 'a different payload',
    });
    assert.equal(
      await submitEnvelope({ ...clientArgs(handoff, broker), envelope: different }),
      'unavailable',
    );

    const snapshot = broker.testSnapshot(handoff.handoff_id);
    assert.equal(snapshot.state, 'claimed');
    assert.equal(snapshot.hasPlaintext, false, 'the receipt keeps no payload');
    assert.equal(snapshot.hasPrivateKey, false);
    assert.ok(!snapshot.serialized.includes(SECRET));
  });

  it('kills the capability the instant a submit is accepted', async () => {
    const handoff = await createHandoff();
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });
    const envelope = await sealEnvelope({
      capability: handoff.capability,
      metadata,
      plaintext: SECRET,
    });
    assert.equal(await submitEnvelope({ ...clientArgs(handoff, broker), envelope }), 'received');

    // No TTL sweep, no claim, no delay: the capability is spent already.
    const reopened = await fetch(`${broker.baseUrl}/api/metadata`, {
      method: 'POST',
      headers: { 'x-handoff-capability': handoff.capability },
    });
    assert.equal(reopened.status, 404, 'reloading the page cannot resurrect the form');
    assert.equal(await reopened.text(), '{"status":"unavailable"}');
    assert.equal(
      await fetchMetadata({ capability: handoff.capability, origin: broker.baseUrl }),
      null,
    );

    // The one exception stays: the identical envelope's receipt is idempotent.
    assert.equal(await submitEnvelope({ ...clientArgs(handoff, broker), envelope }), 'received');
    assert.equal(broker.testSnapshot(handoff.handoff_id).state, 'submitted');
  });

  it('stops honouring that receipt once the ttl lapses', async () => {
    const handoff = await createHandoff({ ttl_seconds: 1 });
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });
    const envelope = await sealEnvelope({
      capability: handoff.capability,
      metadata,
      plaintext: SECRET,
    });
    assert.equal(await submitEnvelope({ ...clientArgs(handoff, broker), envelope }), 'received');
    await broker.control({ op: 'claim', handoff_id: handoff.handoff_id });

    await new Promise((resolve) => setTimeout(resolve, 1300));
    assert.equal(await submitEnvelope({ ...clientArgs(handoff, broker), envelope }), 'unavailable');
    assert.equal(broker.testSnapshot(handoff.handoff_id), null, 'the receipt expires with the TTL');
  });

  it('shares one outcome between concurrent identical duplicates', async () => {
    const handoff = await createHandoff();
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });
    const envelope = await sealEnvelope({
      capability: handoff.capability,
      metadata,
      plaintext: SECRET,
    });

    const results = await Promise.all(
      Array.from({ length: 6 }, () => submitEnvelope({ ...clientArgs(handoff, broker), envelope })),
    );
    assert.deepEqual(
      results,
      new Array(6).fill('received'),
      'every identical duplicate shares the winning receipt',
    );

    const snapshot = broker.testSnapshot(handoff.handoff_id);
    assert.equal(snapshot.state, 'submitted');
    assert.equal(snapshot.plaintextBytes, Buffer.byteLength(SECRET, 'utf8'), 'delivered once');

    const claimed = await broker.control({ op: 'claim', handoff_id: handoff.handoff_id });
    assert.equal(
      Buffer.from(claimed.plaintext_b64, 'base64').toString('utf8'),
      SECRET,
      'and delivered intact',
    );
  });

  it('rejects an envelope whose info binds a different capability', async () => {
    const victim = await createHandoff();
    const attacker = await createHandoff();
    const victimMetadata = await fetchMetadata({
      capability: victim.capability,
      origin: broker.baseUrl,
    });

    // Correct handoff id and correct recipient key — so `hid` and `pkfp` both pass
    // the broker's shape checks — but `info` is bound to another capability.
    const forged = await sealEnvelope({
      capability: attacker.capability,
      metadata: victimMetadata,
      plaintext: SECRET,
    });
    const honest = await sealEnvelope({
      capability: victim.capability,
      metadata: victimMetadata,
      plaintext: SECRET,
    });
    assert.equal(forged.hid, victim.handoff_id);
    assert.equal(forged.pkfp, honest.pkfp, 'the forgery targets the right public key');
    assert.notEqual(forged.ct, honest.ct);

    assert.equal(
      await submitEnvelope({ ...clientArgs(victim, broker), envelope: forged }),
      'unavailable',
    );
    const snapshot = broker.testSnapshot(victim.handoff_id);
    assert.equal(snapshot.state, 'pending', 'a forgery must not consume the handoff');
    assert.equal(snapshot.aeadFailures, 1, 'it must fail at the AEAD, not at a shape check');

    // The genuine envelope still works.
    assert.equal(
      await submitEnvelope({ ...clientArgs(victim, broker), envelope: honest }),
      'received',
    );
  });

  it('cannot be replayed into a different handoff', async () => {
    const victim = await createHandoff();
    const other = await createHandoff();

    const metadata = await fetchMetadata({ capability: victim.capability, origin: broker.baseUrl });
    const envelope = await sealEnvelope({
      capability: victim.capability,
      metadata,
      plaintext: SECRET,
    });

    // Same envelope bytes, presented for the other handoff's capability.
    assert.equal(await submitEnvelope({ ...clientArgs(other, broker), envelope }), 'unavailable');
    assert.equal(broker.testSnapshot(other.handoff_id).state, 'pending');
  });

  it('does not consume the handoff when the AEAD fails, but destroys it after a bounded number', async () => {
    const handoff = await createHandoff();
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });
    const good = await sealEnvelope({
      capability: handoff.capability,
      metadata,
      plaintext: SECRET,
    });

    const tampered = { ...good, ct: flipLastByte(good.ct) };
    assert.equal(
      await submitEnvelope({ ...clientArgs(handoff, broker), envelope: tampered }),
      'unavailable',
    );
    assert.equal(broker.testSnapshot(handoff.handoff_id).state, 'pending', 'not consumed');
    assert.equal(broker.testSnapshot(handoff.handoff_id).aeadFailures, 1);

    // A genuine envelope still works after a corrupted one.
    assert.equal(
      await submitEnvelope({ ...clientArgs(handoff, broker), envelope: good }),
      'received',
    );

    const second = await createHandoff();
    const secondMetadata = await fetchMetadata({
      capability: second.capability,
      origin: broker.baseUrl,
    });
    const secondGood = await sealEnvelope({
      capability: second.capability,
      metadata: secondMetadata,
      plaintext: SECRET,
    });
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await submitEnvelope({
        ...clientArgs(second, broker),
        envelope: { ...secondGood, ct: flipLastByte(secondGood.ct) },
      });
    }
    assert.equal(broker.testSnapshot(second.handoff_id), null, 'destroyed after 3 AEAD failures');
    assert.equal(
      await submitEnvelope({ ...clientArgs(second, broker), envelope: secondGood }),
      'unavailable',
    );
  });

  it('rejects malformed envelopes without consuming the handoff', async () => {
    const handoff = await createHandoff();
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });
    const good = await sealEnvelope({
      capability: handoff.capability,
      metadata,
      plaintext: SECRET,
    });

    const mutations = {
      'unknown version': { ...good, v: 2 },
      'unlisted suite': { ...good, suite: 'DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM' },
      'foreign handoff id': { ...good, hid: 'B'.repeat(22) },
      'short enc': { ...good, enc: good.enc.slice(0, 40) },
      'wrong public key fingerprint': { ...good, pkfp: 'A'.repeat(22) },
      'padded base64': { ...good, ct: `${good.ct}==` },
      'empty ciphertext': { ...good, ct: '' },
      'missing field': { v: good.v, suite: good.suite, hid: good.hid },
      'not an object': 'nope',
    };

    for (const [name, envelope] of Object.entries(mutations)) {
      assert.equal(
        await submitEnvelope({ ...clientArgs(handoff, broker), envelope }),
        'unavailable',
        `${name} must be refused`,
      );
    }
    assert.equal(broker.testSnapshot(handoff.handoff_id).state, 'pending');
    assert.equal(
      await submitEnvelope({ ...clientArgs(handoff, broker), envelope: good }),
      'received',
    );
  });

  it('enforces the payload ceiling on both sides', async () => {
    const handoff = await createHandoff();
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });

    // Client-side courtesy check.
    const oversize = 'x'.repeat(metadata.max_plaintext_bytes + 1);
    assert.deepEqual(await sendSecret({ ...clientArgs(handoff, broker), plaintext: oversize }), {
      status: 'too_large',
      limit: metadata.max_plaintext_bytes,
    });
    assert.equal(broker.testSnapshot(handoff.handoff_id).state, 'pending');

    // Server-side authority: seal the oversized payload anyway and submit it.
    const envelope = await sealEnvelope({
      capability: handoff.capability,
      metadata,
      plaintext: oversize,
    });
    assert.equal(
      await submitEnvelope({ ...clientArgs(handoff, broker), envelope }),
      'unavailable',
    );
    assert.equal(broker.testSnapshot(handoff.handoff_id).state, 'pending');

    // And a body far past the ceiling is dropped before any crypto work.
    const response = await fetch(`${broker.baseUrl}/api/submit`, {
      method: 'POST',
      headers: {
        'x-handoff-capability': handoff.capability,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ ...envelope, ct: 'A'.repeat(400_000) }),
    });
    assert.equal(response.status, 404);
  });

  // Regression guard. @hpke/core re-derives pk_R when `open` is given a bare
  // private CryptoKey, and its non-extractable fallback canonicalizes the y
  // coordinate — so roughly half of all generated keys used to fail the AEAD.
  // Anything below 20/20 here means the broker stopped passing the whole key pair.
  it('succeeds for every generated key pair, not just half of them', async () => {
    const attempts = 20;
    const outcomes = [];
    for (let i = 0; i < attempts; i += 1) {
      const handoff = await createHandoff();
      outcomes.push(
        (await sendSecret({ ...clientArgs(handoff, broker), plaintext: `round ${i}` })).status,
      );
    }
    assert.deepEqual(
      outcomes,
      new Array(attempts).fill('sent'),
      'every handoff must complete regardless of the public key point parity',
    );
  });

  it('accepts a payload right at the ceiling', async () => {
    const handoff = await createHandoff();
    const metadata = await fetchMetadata({
      capability: handoff.capability,
      origin: broker.baseUrl,
    });
    const atLimit = 'y'.repeat(metadata.max_plaintext_bytes);

    assert.deepEqual(await sendSecret({ ...clientArgs(handoff, broker), plaintext: atLimit }), {
      status: 'sent',
    });
    assert.equal(
      broker.testSnapshot(handoff.handoff_id).plaintextBytes,
      metadata.max_plaintext_bytes,
    );
  });
});

describe('seam 3: transport failures on the browser side', () => {
  let broker;

  beforeEach(async () => {
    broker = await startTestBroker();
  });

  afterEach(async () => {
    await broker.stop();
  });

  async function liveHandoff() {
    const created = await broker.control({ op: 'create' });
    const capability = splitHandoffUrl(created.url).capability;
    const metadata = await fetchMetadata({ capability, origin: broker.baseUrl });
    const envelope = await sealEnvelope({ capability, metadata, plaintext: SECRET });
    return { ...created, capability, metadata, envelope };
  }

  /** Fails the first `failures` submit attempts, then behaves normally. */
  function flakyFetch(failures, { status } = {}) {
    const attempts = [];
    const impl = async (url, options) => {
      if (String(url).endsWith('/api/submit')) {
        attempts.push(String(options?.body ?? ''));
        if (attempts.length <= failures) {
          if (status) return new Response('upstream down', { status });
          throw new TypeError('fetch failed');
        }
      }
      return fetch(url, options);
    };
    impl.attempts = attempts;
    return impl;
  }

  it('retries the exact same sealed envelope once after a transient failure', async () => {
    const handoff = await liveHandoff();
    const fetchImpl = flakyFetch(1);

    const status = await submitEnvelope({
      capability: handoff.capability,
      envelope: handoff.envelope,
      origin: broker.baseUrl,
      fetchImpl,
    });

    assert.equal(status, 'received');
    assert.equal(fetchImpl.attempts.length, 2, 'exactly one retry');
    assert.equal(fetchImpl.attempts[0], fetchImpl.attempts[1], 'the same bytes are resent');
    assert.equal(
      broker.testSnapshot(handoff.handoff_id).plaintextBytes,
      Buffer.byteLength(SECRET, 'utf8'),
      'one delivery, not two',
    );
  });

  it('retries a 503 the same way', async () => {
    const handoff = await liveHandoff();
    const fetchImpl = flakyFetch(1, { status: 503 });

    assert.equal(
      await submitEnvelope({
        capability: handoff.capability,
        envelope: handoff.envelope,
        origin: broker.baseUrl,
        fetchImpl,
      }),
      'received',
    );
    assert.equal(fetchImpl.attempts.length, 2);
  });

  it('reports an unreachable broker instead of a definitive refusal', async () => {
    const handoff = await liveHandoff();
    const fetchImpl = flakyFetch(5);

    assert.equal(
      await submitEnvelope({
        capability: handoff.capability,
        envelope: handoff.envelope,
        origin: broker.baseUrl,
        fetchImpl,
      }),
      'unreachable',
      'a transport failure must be distinguishable from unavailable',
    );
    assert.equal(fetchImpl.attempts.length, 2, 'one retry, then it gives up');
    assert.equal(
      broker.testSnapshot(handoff.handoff_id).state,
      'pending',
      'nothing was consumed, so the same envelope can still be resent',
    );
  });

  it('never retries a definitive unavailable', async () => {
    const handoff = await liveHandoff();
    // Consume it first, so the broker answers 404 for a different envelope.
    await submitEnvelope({
      capability: handoff.capability,
      envelope: handoff.envelope,
      origin: broker.baseUrl,
    });
    const different = await sealEnvelope({
      capability: handoff.capability,
      metadata: handoff.metadata,
      plaintext: 'something else',
    });

    const fetchImpl = flakyFetch(0);
    assert.equal(
      await submitEnvelope({
        capability: handoff.capability,
        envelope: different,
        origin: broker.baseUrl,
        fetchImpl,
      }),
      'unavailable',
    );
    assert.equal(fetchImpl.attempts.length, 1, 'a 404 is final');
  });

  it('surfaces an unreachable broker from the whole send flow', async () => {
    const created = await broker.control({ op: 'create' });
    const capability = splitHandoffUrl(created.url).capability;
    const dead = async () => {
      throw new TypeError('fetch failed');
    };

    assert.deepEqual(
      await sendSecret({ capability, plaintext: SECRET, origin: broker.baseUrl, fetchImpl: dead }),
      { status: 'unreachable' },
    );
    assert.equal(broker.testSnapshot(created.handoff_id).state, 'pending');
  });
});

function clientArgs(handoff, broker) {
  return { capability: handoff.capability, origin: broker.baseUrl };
}

function flipLastByte(base64url) {
  const bytes = decodeBase64Url(base64url);
  bytes[bytes.length - 1] ^= 0xff;
  return Buffer.from(bytes).toString('base64url');
}
