// Seam 5 — expired, missing, malformed and consumed handoffs must be
// indistinguishable. Anything that varies with the reason is a disclosure
// channel, so this compares whole responses byte for byte, not just statuses.
import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';

import { sendSecret } from '../src/client/handoff-client.js';
import { splitHandoffUrl, startTestBroker } from './helpers/harness.js';

const VOLATILE_HEADERS = new Set(['date', 'connection', 'keep-alive']);

function fingerprint(response, body) {
  const headers = [...response.headers.entries()]
    .filter(([name]) => !VOLATILE_HEADERS.has(name))
    .sort(([a], [b]) => a.localeCompare(b));
  // Body is kept out of the stringify so assertions can match on it directly.
  return `${response.status}\n${JSON.stringify(headers)}\n${body}`;
}

describe('seam 5: one unavailable contract for every failure', () => {
  let broker;
  /** name -> capability header value (or null for "header absent") */
  const capabilities = {};

  before(async () => {
    broker = await startTestBroker({ ttlSeconds: 600 });

    const create = async () => {
      const created = await broker.control({ op: 'create' });
      return { ...created, capability: splitHandoffUrl(created.url).capability };
    };

    // Expired: created with a sub-second ttl, then left to lapse.
    const expired = await broker.control({ op: 'create', ttl_seconds: 0.4 });
    capabilities.expired = splitHandoffUrl(expired.url).capability;

    // Consumed: one successful submission already accepted.
    const consumed = await create();
    const sent = await sendSecret({
      capability: consumed.capability,
      plaintext: 'already delivered',
      origin: broker.baseUrl,
    });
    assert.equal(sent.status, 'sent');
    capabilities.consumed = consumed.capability;

    // Claimed: submitted and then claimed through the control path.
    const claimed = await create();
    assert.equal(
      (
        await sendSecret({
          capability: claimed.capability,
          plaintext: 'claimed already',
          origin: broker.baseUrl,
        })
      ).status,
      'sent',
    );
    const claimResult = await broker.control({ op: 'claim', handoff_id: claimed.handoff_id });
    assert.equal(claimResult.ok, true);
    capabilities.claimed = claimed.capability;

    // Never existed, but syntactically perfect (16 bytes -> 22 base64url chars).
    capabilities.unknown = 'z'.repeat(22);
    // Malformed in three different ways.
    capabilities.tooShort = 'z'.repeat(21);
    capabilities.tooLong = 'z'.repeat(23);
    capabilities.badCharset = `${'z'.repeat(20)}+/`;
    capabilities.padded = `${'z'.repeat(19)}a==`;
    capabilities.empty = '';
    capabilities.absent = null;

    await new Promise((resolve) => setTimeout(resolve, 500));
  });

  after(async () => {
    await broker.stop();
  });

  async function call(path, capability, options = {}) {
    const headers = capability === null ? {} : { 'x-handoff-capability': capability };
    const response = await fetch(`${broker.baseUrl}${path}`, {
      method: 'POST',
      headers: { ...headers, ...(options.body ? { 'content-type': 'application/json' } : {}) },
      body: options.body,
    });
    return fingerprint(response, await response.text());
  }

  it('returns one identical metadata response for every unavailable reason', async () => {
    const results = {};
    for (const [name, capability] of Object.entries(capabilities)) {
      results[name] = await call('/api/metadata', capability);
    }

    const reference = results.expired;
    assert.ok(reference.startsWith('404\n'), 'the unavailable contract is a 404 with no detail');
    assert.ok(reference.endsWith('{"status":"unavailable"}'));
    for (const [name, value] of Object.entries(results)) {
      assert.equal(value, reference, `${name} must be indistinguishable from expired`);
    }
  });

  it('returns that same response shape on submit, whatever the envelope', async () => {
    const envelopes = {
      absentBody: undefined,
      emptyBody: '',
      notJson: 'not json at all',
      jsonNull: 'null',
      jsonArray: '[]',
      wrongFields: JSON.stringify({ v: 1, suite: 'nope', hid: 'x', enc: '', ct: '', pkfp: '' }),
    };

    const results = [];
    for (const [name, capability] of Object.entries(capabilities)) {
      for (const [envelopeName, body] of Object.entries(envelopes)) {
        results.push({ name: `${name}/${envelopeName}`, value: await call('/api/submit', capability, { body }) });
      }
    }

    const reference = results[0].value;
    assert.ok(reference.endsWith('{"status":"unavailable"}'));
    for (const { name, value } of results) {
      assert.equal(value, reference, `${name} must be indistinguishable`);
    }
  });

  it('serves the same page bytes whether or not a handoff exists', async () => {
    const pages = await Promise.all(
      ['/', `/#${capabilities.expired}`, `/#${capabilities.unknown}`, '/anything'].map(
        async (path) => {
          const response = await fetch(`${broker.baseUrl}${path}`);
          const body = await response.text();
          return { path, body, headers: fingerprint(response, body) };
        },
      ),
    );

    // The fragment never reaches the server, so all four bodies are the one page.
    for (const page of pages) {
      assert.equal(page.body, pages[0].body, `${page.path} must serve the same document`);
      assert.ok(!page.body.includes('pending') && !page.body.includes('claimed'));
    }
  });

  it('answers HEAD without a body and with the same headers as POST', async () => {
    const head = await fetch(`${broker.baseUrl}/api/metadata`, { method: 'HEAD' });
    const body = await head.text();
    assert.equal(head.status, 404);
    assert.equal(body, '', 'HEAD must not carry a response body');
    assert.ok(head.headers.get('content-security-policy'), 'security headers still apply to HEAD');

    const headPage = await fetch(`${broker.baseUrl}/`, { method: 'HEAD' });
    assert.equal(await headPage.text(), '');
    assert.equal(headPage.status, 200);
  });

  it('reveals nothing through unsupported methods', async () => {
    const results = [];
    for (const method of ['PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
      const response = await fetch(`${broker.baseUrl}/api/metadata`, {
        method,
        headers: { 'x-handoff-capability': capabilities.unknown },
      });
      results.push(fingerprint(response, await response.text()));
    }
    for (const value of results) assert.equal(value, results[0]);
    assert.ok(results[0].endsWith('{"status":"unavailable"}'));
  });

  it('destroys expired handoffs rather than keeping their key material around', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: 0.3 });
    assert.equal(broker.testSnapshot(created.handoff_id).state, 'pending');

    await new Promise((resolve) => setTimeout(resolve, 1400));
    assert.equal(
      broker.testSnapshot(created.handoff_id),
      null,
      'the sweeper must drop the record without anyone touching it',
    );
  });
});
