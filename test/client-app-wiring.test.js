// Page wiring. src/client/app.js is the only module the browser runs that the
// seam tests do not touch, so it is exercised here against a minimal fake DOM and
// a live broker: real HTTP, real HPKE, fake elements.
//
// This is not a substitute for opening the page in a browser engine — it proves
// the element ids, the state transitions and the send path line up, nothing about
// rendering.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { after, before, describe, it } from 'node:test';

import { splitHandoffUrl, startTestBroker } from './helpers/harness.js';

const ELEMENT_IDS = ['app', 'form', 'success', 'unavailable', 'secret', 'send', 'note', 'ttl'];

function fakeDom() {
  const elements = new Map();
  for (const id of ELEMENT_IDS) {
    elements.set(id, {
      id,
      hidden: false,
      value: '',
      textContent: '',
      disabled: false,
      readOnly: false,
      dataset: {},
      focused: false,
      attributes: new Map(),
      handlers: new Map(),
      focus() {
        this.focused = true;
      },
      setAttribute(name, value) {
        this.attributes.set(name, value);
      },
      addEventListener(type, handler) {
        this.handlers.set(type, handler);
      },
    });
  }
  const documentHandlers = new Map();
  return {
    elements,
    documentHandlers,
    document: {
      hidden: false,
      getElementById: (id) => elements.get(id) ?? null,
      addEventListener(type, handler) {
        documentHandlers.set(type, handler);
      },
    },
  };
}

/** Loads app.js afresh with the given fragment, since it runs on import. */
async function loadApp({ hash, origin }) {
  const dom = fakeDom();
  const timers = [];
  const intervals = new Map();
  let nextIntervalId = 1;
  globalThis.document = dom.document;
  globalThis.window = {
    location: { hash, origin },
    setTimeout: (fn, ms) => {
      timers.push({ fn, ms });
      return timers.length;
    },
    setInterval: (fn, ms) => {
      const id = nextIntervalId;
      nextIntervalId += 1;
      intervals.set(id, { fn, ms });
      return id;
    },
    clearInterval: (id) => intervals.delete(id),
  };

  // Cache-bust so each scenario gets a fresh module instance.
  await import(`../src/client/app.js?scenario=${encodeURIComponent(hash)}${Math.random()}`);
  // Let start()'s metadata fetch settle.
  await new Promise((resolve) => setTimeout(resolve, 150));
  return {
    ...dom,
    timers,
    intervals,
    /** Fires every armed interval once, the way a live tab would each second. */
    tick() {
      for (const { fn } of [...intervals.values()]) fn();
    },
  };
}

describe('the page script wiring', () => {
  let broker;

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
    delete globalThis.document;
    delete globalThis.window;
  });

  it('references only element ids that exist in index.html', async () => {
    const html = await readFile(new URL('../src/public/index.html', import.meta.url), 'utf8');
    for (const id of ELEMENT_IDS) {
      assert.match(html, new RegExp(`id="${id}"`), `index.html must define #${id}`);
    }
  });

  it('shows the unavailable screen when the fragment is missing or malformed', async () => {
    for (const hash of ['', '#', '#not-a-capability', `#${'z'.repeat(21)}`]) {
      const dom = await loadApp({ hash, origin: broker.baseUrl });
      assert.equal(dom.elements.get('unavailable').hidden, false, `hash ${JSON.stringify(hash)}`);
      assert.equal(dom.elements.get('form').hidden, true);
      assert.equal(dom.elements.get('app').dataset.state, 'unavailable');
    }
  });

  it('shows the unavailable screen for a consumed handoff', async () => {
    const created = await broker.control({ op: 'create' });
    const { capability } = splitHandoffUrl(created.url);
    const { sendSecret } = await import('../src/client/handoff-client.js');
    await sendSecret({ capability, plaintext: 'already used', origin: broker.baseUrl });

    const dom = await loadApp({ hash: `#${capability}`, origin: broker.baseUrl });
    assert.equal(dom.elements.get('unavailable').hidden, false);
  });

  it('renders the form, sends once, and lands on the receipt', async () => {
    const created = await broker.control({ op: 'create' });
    const { capability } = splitHandoffUrl(created.url);
    const dom = await loadApp({ hash: `#${capability}`, origin: broker.baseUrl });

    const form = dom.elements.get('form');
    const textarea = dom.elements.get('secret');
    const send = dom.elements.get('send');

    assert.equal(form.hidden, false, 'a live capability renders the form');
    assert.equal(dom.elements.get('app').dataset.state, 'form');
    assert.match(dom.elements.get('ttl').textContent, /^(29|30):\d{2}$/, 'a live m:ss countdown');
    assert.equal(textarea.focused, true);
    assert.ok(
      [...dom.intervals.values()].some((interval) => interval.ms === 1000),
      'the page arms a one-second countdown ticker',
    );

    // Empty send is a no-op.
    await send.handlers.get('click')();
    assert.equal(form.hidden, false);
    assert.equal(broker.testSnapshot(created.handoff_id).state, 'pending');

    textarea.value = 'PGADMIN_DEFAULT_PASSWORD=example-not-a-real-secret';
    await textarea.handlers.get('input')();
    assert.equal(dom.elements.get('note').textContent, 'One secure send · no edits');

    await send.handlers.get('click')();
    assert.equal(dom.elements.get('success').hidden, false, 'success screen after send');
    assert.equal(form.hidden, true);
    assert.equal(send.disabled, true, 'the send button cannot be pressed twice');
    assert.equal(textarea.value, '', 'the visible copy is cleared once sealed');

    const snapshot = broker.testSnapshot(created.handoff_id);
    assert.equal(snapshot.state, 'submitted');
    assert.equal(snapshot.hasPrivateKey, false);
  });

  it('keeps the pasted text when the broker is unreachable, then resends the same envelope', async () => {
    const created = await broker.control({ op: 'create' });
    const { capability } = splitHandoffUrl(created.url);
    const dom = await loadApp({ hash: `#${capability}`, origin: broker.baseUrl });

    const textarea = dom.elements.get('secret');
    const send = dom.elements.get('send');
    const note = dom.elements.get('note');
    const plaintext = 'REDIS_PASSWORD=example-not-a-real-secret';
    textarea.value = plaintext;

    const realFetch = globalThis.fetch;
    const submissions = [];
    globalThis.fetch = async (url, options) => {
      if (String(url).endsWith('/api/submit')) {
        submissions.push(String(options.body));
        throw new TypeError('fetch failed');
      }
      return realFetch(url, options);
    };

    try {
      await send.handlers.get('click')();

      // Nothing definitive came back, so the payload must still be here.
      assert.equal(dom.elements.get('form').hidden, false, 'stays on the form');
      assert.equal(dom.elements.get('unavailable').hidden, true, 'a timeout is not a refusal');
      assert.equal(textarea.value, plaintext, 'the pasted text must not be lost');
      assert.equal(send.disabled, false, 'the operator can try again');
      assert.match(note.textContent, /again/i, 'and is told so');
      assert.equal(submissions.length, 2, 'the client already retried the same bytes once');
      assert.equal(submissions[0], submissions[1]);
      assert.equal(broker.testSnapshot(created.handoff_id).state, 'pending');

      // Network back: pressing Send must resend the sealed envelope, not re-seal.
      globalThis.fetch = async (url, options) => {
        if (String(url).endsWith('/api/submit')) submissions.push(String(options.body));
        return realFetch(url, options);
      };
      await send.handlers.get('click')();

      assert.equal(submissions.length, 3);
      assert.equal(
        JSON.parse(submissions[2]).ct,
        JSON.parse(submissions[0]).ct,
        'the same sealed ciphertext is resent',
      );
      assert.equal(dom.elements.get('success').hidden, false, 'receipt at last');
      assert.equal(textarea.value, '', 'cleared only once the receipt is definitive');

      const snapshot = broker.testSnapshot(created.handoff_id);
      assert.equal(snapshot.state, 'submitted');
      assert.equal(
        snapshot.plaintextBytes,
        Buffer.byteLength(plaintext, 'utf8'),
        'delivered exactly once',
      );
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('counts the remaining time down and refreshes when the tab comes back', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: 120 });
    const { capability } = splitHandoffUrl(created.url);
    const dom = await loadApp({ hash: `#${capability}`, origin: broker.baseUrl });

    const ttl = dom.elements.get('ttl');
    assert.match(ttl.textContent, /^[12]:\d{2}$/, 'starts near two minutes');
    assert.match(
      ttl.attributes.get('aria-label'),
      /^[12] minutes? left$/,
      'the unannounced digits get a readable whole-minute label',
    );
    const first = ttl.textContent;

    await new Promise((resolve) => setTimeout(resolve, 1100));
    dom.tick();
    assert.notEqual(ttl.textContent, first, 'the label moves with real elapsed time');
    assert.match(ttl.textContent, /^[01]:\d{2}$/);

    // A throttled background tab can miss ticks, so returning must resync
    // rather than trust the timer.
    const beforeResync = ttl.textContent;
    ttl.textContent = 'stale';
    const onVisibility = dom.documentHandlers.get('visibilitychange');
    assert.ok(onVisibility, 'the page listens for visibilitychange');
    onVisibility();
    assert.equal(ttl.textContent, beforeResync, 'resynced from the deadline, not the timer');
  });

  it('closes the form when the countdown reaches zero', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: 1 });
    const { capability } = splitHandoffUrl(created.url);
    const dom = await loadApp({ hash: `#${capability}`, origin: broker.baseUrl });
    assert.equal(dom.elements.get('form').hidden, false, 'live at load');

    await new Promise((resolve) => setTimeout(resolve, 1100));
    dom.tick();

    assert.equal(dom.elements.get('unavailable').hidden, false, 'expired in the browser too');
    assert.equal(dom.elements.get('form').hidden, true);
    assert.equal(dom.elements.get('ttl').textContent, '0:00');
  });

  it('stops the countdown once the receipt is shown, so it cannot overwrite it', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: 1 });
    const { capability } = splitHandoffUrl(created.url);
    const dom = await loadApp({ hash: `#${capability}`, origin: broker.baseUrl });

    dom.elements.get('secret').value = 'STAGING_TOKEN=example-not-a-real-secret';
    await dom.elements.get('send').handlers.get('click')();
    assert.equal(dom.elements.get('success').hidden, false);

    await new Promise((resolve) => setTimeout(resolve, 1100));
    dom.tick();
    assert.equal(dom.elements.get('success').hidden, false, 'the receipt survives the expiry');
    assert.equal(dom.elements.get('unavailable').hidden, true);
  });

  // The interval is only one of the two ways a stale countdown can fire. The
  // visibilitychange listener is registered once and never removed, so it
  // outlives the ticker — and telling someone who *did* deliver a credential
  // that the link failed is an invitation to resend it into the chat channel,
  // which is the one outcome this system exists to prevent.
  it('cannot repaint the receipt when the tab returns after expiry', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: 1 });
    const { capability } = splitHandoffUrl(created.url);
    const dom = await loadApp({ hash: `#${capability}`, origin: broker.baseUrl });

    dom.elements.get('secret').value = 'DEPLOY_KEY=example-not-a-real-secret';
    await dom.elements.get('send').handlers.get('click')();
    assert.equal(dom.elements.get('success').hidden, false, 'delivered');

    await new Promise((resolve) => setTimeout(resolve, 1100));
    dom.tick();
    dom.documentHandlers.get('visibilitychange')();

    assert.equal(dom.elements.get('success').hidden, false, 'the receipt is still the answer');
    assert.equal(dom.elements.get('unavailable').hidden, true, 'a delivered secret is not a failure');
    assert.equal(dom.elements.get('app').dataset.state, 'success');
  });

  it('cannot repaint the unavailable screen when the tab returns after expiry', async () => {
    const created = await broker.control({ op: 'create', ttl_seconds: 1 });
    const { capability } = splitHandoffUrl(created.url);
    const dom = await loadApp({ hash: `#${capability}`, origin: broker.baseUrl });

    await new Promise((resolve) => setTimeout(resolve, 1100));
    dom.tick();
    assert.equal(dom.elements.get('unavailable').hidden, false, 'expired');

    dom.elements.get('ttl').textContent = 'untouched';
    dom.documentHandlers.get('visibilitychange')();

    assert.equal(dom.elements.get('unavailable').hidden, false);
    assert.equal(dom.elements.get('form').hidden, true, 'and the form does not come back');
    assert.equal(
      dom.elements.get('ttl').textContent,
      'untouched',
      'a detached countdown writes nothing at all',
    );
  });

  it('warns instead of sending when the payload exceeds the ceiling', async () => {
    const created = await broker.control({ op: 'create' });
    const { capability } = splitHandoffUrl(created.url);
    const dom = await loadApp({ hash: `#${capability}`, origin: broker.baseUrl });

    dom.elements.get('secret').value = 'x'.repeat(65537);
    await dom.elements.get('secret').handlers.get('input')();
    assert.match(dom.elements.get('note').textContent, /Too large/);

    await dom.elements.get('send').handlers.get('click')();
    assert.equal(dom.elements.get('form').hidden, false, 'still on the form');
    assert.equal(broker.testSnapshot(created.handoff_id).state, 'pending');
  });
});
