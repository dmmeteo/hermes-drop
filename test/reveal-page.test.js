// The reveal page, driven the way a browser drives it: the real src/client/app.js,
// against a real broker over real HTTP, through a fake document.
//
// The companion of test/client-app-wiring.test.js for the other direction. Same
// caveat, restated because it matters more here — this proves the element ids, the
// state machine, the gate and what reaches each node. It proves nothing about
// *visual* rendering, and it is not a browser engine.
//
// What it is really for is the two properties the page cannot be trusted on by
// inspection: that a payload string only ever becomes a text node, and that a
// preview or a reload cannot spend a drop.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { after, before, beforeEach, describe, it } from 'node:test';

import { isSensitiveFieldType } from '../src/outbound-payload.js';
import { HIDE_LABEL, MASK, SHOW_LABEL } from '../src/client/reveal-view.js';
import { createOutboundDrop, startTestBroker } from './helpers/harness.js';

const ELEMENT_IDS = [
  'app', 'form', 'success', 'unavailable', 'secret', 'send', 'note', 'ttl',
  'file-panel', 'files', 'drop-zone', 'file-list', 'file-total',
  'reveal', 'revealed', 'reveal-code', 'reveal-open', 'reveal-note', 'reveal-ttl',
  'revealed-fields', 'revealed-note', 'revealed-title',
];

const CANON = {
  v: 1,
  title: 'OpenRouter access',
  fields: [
    { label: 'Login', type: 'text', value: 'ops@example.test' },
    { label: 'Password', type: 'secret', value: 'example-not-a-real-secret' },
    { label: 'Console', type: 'url', value: 'https://openrouter.test/keys' },
    { label: 'Note', type: 'note', value: 'Rotate within 30 days.\nAsk ops first.' },
  ],
};

function element(id = '') {
  return {
    id, hidden: false, value: '', textContent: '', disabled: false, readOnly: false,
    type: '', className: '', dataset: {}, focused: false, files: [], children: [],
    attributes: new Map(), handlers: new Map(),
    classList: { add() {}, remove() {} },
    focus() { this.focused = true; },
    setAttribute(name, value) { this.attributes.set(name, value); },
    addEventListener(type, handler) { this.handlers.set(type, handler); },
    append(...children) { this.children.push(...children); },
  };
}

function fakeDom() {
  const elements = new Map(ELEMENT_IDS.map((id) => [id, element(id)]));
  const documentHandlers = new Map();
  const created = [];
  return {
    elements,
    documentHandlers,
    created,
    document: {
      hidden: false,
      getElementById: (id) => elements.get(id) ?? null,
      createElement: (tag) => { const node = element(); node.tag = tag; created.push(node); return node; },
      addEventListener(type, handler) { documentHandlers.set(type, handler); },
    },
  };
}

/** Loads app.js afresh with the given fragment, since it runs on import. */
async function loadApp({ hash, origin }) {
  const dom = fakeDom();
  const intervals = new Map();
  let nextIntervalId = 1;
  globalThis.document = dom.document;
  globalThis.window = {
    location: { hash, origin },
    setTimeout: (fn) => fn,
    setInterval: (fn, ms) => {
      const id = nextIntervalId;
      nextIntervalId += 1;
      intervals.set(id, { fn, ms });
      return id;
    },
    clearInterval: (id) => intervals.delete(id),
  };

  await import(`../src/client/app.js?reveal=${encodeURIComponent(hash)}${Math.random()}`);
  await new Promise((resolve) => setTimeout(resolve, 300));

  const $ = (id) => dom.elements.get(id);
  return {
    ...dom,
    intervals,
    $,
    state: () => $('app').dataset.state,
    tick() { for (const { fn } of [...intervals.values()]) fn(); },
    /** Types a code and presses Reveal, the way a person does. */
    async reveal(code) {
      $('reveal-code').value = code;
      await $('reveal-open').handlers.get('click')();
    },
    /** The rendered rows, flattened into what a reader would see. */
    rows() {
      return $('revealed-fields').children.map((row) => {
        const [head, value, actions] = row.children;
        const buttons = actions.children;
        return {
          label: head.children[0].textContent,
          shown: value.textContent,
          className: value.className,
          toggle: buttons.length === 2 ? buttons[0] : null,
          copy: buttons[buttons.length - 1],
        };
      });
    },
  };
}

/** Replaces `navigator` for one test. It is a configurable getter, not writable. */
function withClipboard(implementation) {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  Object.defineProperty(globalThis, 'navigator', {
    value: implementation,
    configurable: true,
    enumerable: true,
  });
  return () => Object.defineProperty(globalThis, 'navigator', original);
}

describe('the reveal page', () => {
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

  it('tells the user what a Hermes Drop is, before asking for a code', async () => {
    // The four things the MVP requires the page to be clear about. Asserted against
    // the shipped markup rather than against a copy of it, so a rewrite that drops
    // one of them fails here.
    const html = await readFile(new URL('../src/public/index.html', import.meta.url), 'utf8');
    const gate = html.slice(html.indexOf('<section id="reveal"'), html.indexOf('<section id="revealed"'));

    assert.match(gate, /encrypted/i, 'that it is encrypted');
    assert.match(gate, /reveal it once/i, 'that there is one reveal');
    assert.match(gate, /cannot be opened again/i, 'and what that means afterwards');
    assert.match(gate, /expires/i, 'that it expires on its own');
    assert.match(gate, /id="reveal-ttl"/, 'with a live countdown to show when');
    assert.match(gate, /3-digit code/, 'what to type');
    assert.ok(/never send/i.test(gate) || /#/.test(gate), 'and why the key is safe in the link');
  });

  it('opens the gate for a live drop and counts its lifetime down', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON, ttlSeconds: 120 });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });

    assert.equal(dom.state(), 'reveal');
    assert.equal(dom.$('reveal').hidden, false);
    assert.equal(dom.$('form').hidden, true, 'never the inbound form');
    assert.equal(dom.$('revealed').hidden, true);
    assert.equal(dom.$('reveal-code').focused, true);
    assert.match(dom.$('reveal-ttl').textContent, /^[12]:\d{2}$/, 'a live m:ss countdown');
    assert.match(dom.$('reveal-note').textContent, /3 tries/, 'and how many tries are left');
    assert.ok([...dom.intervals.values()].some((interval) => interval.ms === 1000));

    // Loading the page is not a claim: the drop is untouched, which is what makes it
    // safe for an unfurler, a scanner or an antivirus to have fetched it first.
    assert.equal(broker.testOutboundSnapshot(drop.id).state, 'available');
    assert.equal(broker.testOutboundSnapshot(drop.id).attemptsRemaining, 3);
  });

  it('renders one labelled row per field, with a Copy button on each', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
    await dom.reveal(drop.code);

    assert.equal(dom.state(), 'revealed');
    assert.equal(dom.$('reveal').hidden, true, 'the gate is done');
    assert.equal(dom.$('revealed-title').textContent, 'OpenRouter access', 'the payload heading');

    const rows = dom.rows();
    assert.equal(rows.length, 4, 'however many fields the payload held');
    assert.deepEqual(rows.map((row) => row.label), ['Login', 'Password', 'Console', 'Note']);
    for (const row of rows) {
      assert.ok(row.copy, `${row.label} has a Copy button`);
      assert.equal(row.copy.textContent, 'Copy');
      assert.equal(row.copy.attributes.get('aria-label'), `Copy ${row.label}`);
    }
  });

  it('masks the sensitive fields and shows the rest, and toggles only the masked ones', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
    await dom.reveal(drop.code);

    const byLabel = Object.fromEntries(dom.rows().map((row) => [row.label, row]));

    // Non-sensitive fields display normally, and get no toggle at all: a Show button
    // beside a login teaches the user that Show buttons do nothing.
    for (const field of CANON.fields.filter((entry) => !isSensitiveFieldType(entry.type))) {
      const row = byLabel[field.label];
      assert.equal(row.shown, field.value, `${field.label} displays normally`);
      assert.equal(row.className, 'field-value', `${field.label} is not masked`);
      assert.equal(row.toggle, null, `${field.label} needs no reveal control`);
    }
    assert.equal(byLabel.Login.shown, 'ops@example.test');
    assert.equal(byLabel.Console.shown, 'https://openrouter.test/keys');
    assert.equal(byLabel.Note.shown, 'Rotate within 30 days.\nAsk ops first.');

    // The secret is masked, at a width that does not report its length.
    const password = byLabel.Password;
    assert.equal(password.shown, MASK);
    assert.match(password.className, /masked/);
    assert.notEqual(MASK.length, 'example-not-a-real-secret'.length, 'the mask is fixed width');
    assert.equal(password.toggle.textContent, SHOW_LABEL);
    assert.equal(password.toggle.attributes.get('aria-pressed'), 'false');

    // Show, then hide, and the row is back where it started.
    password.toggle.handlers.get('click')();
    const revealedRow = dom.rows().find((row) => row.label === 'Password');
    assert.equal(revealedRow.shown, 'example-not-a-real-secret');
    assert.equal(revealedRow.className, 'field-value');
    assert.equal(revealedRow.toggle.textContent, HIDE_LABEL);
    assert.equal(revealedRow.toggle.attributes.get('aria-pressed'), 'true');

    password.toggle.handlers.get('click')();
    const hiddenAgain = dom.rows().find((row) => row.label === 'Password');
    assert.equal(hiddenAgain.shown, MASK);
    assert.equal(hiddenAgain.toggle.textContent, SHOW_LABEL);
  });

  it('copies the real value even while it is masked, and says so', async () => {
    const copied = [];
    const restore = withClipboard({ clipboard: { writeText: async (value) => { copied.push(value); } } });
    try {
      const drop = await createOutboundDrop(broker, { payload: CANON });
      const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
      await dom.reveal(drop.code);

      const password = dom.rows().find((row) => row.label === 'Password');
      assert.equal(password.shown, MASK, 'still masked');
      await password.copy.handlers.get('click')();

      // The whole point of the mask: a password can be pasted without ever being
      // displayed on a screen someone else can see.
      assert.deepEqual(copied, ['example-not-a-real-secret']);
      assert.match(dom.$('revealed-note').textContent, /Copied Password/);
      assert.equal(dom.rows().find((row) => row.label === 'Password').shown, MASK, 'and stays masked');
    } finally {
      restore();
    }
  });

  it('tells the user what to do instead when the clipboard refuses', async () => {
    const restore = withClipboard({ clipboard: { writeText: async () => { throw new Error('denied'); } } });
    try {
      const drop = await createOutboundDrop(broker, { payload: CANON });
      const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
      await dom.reveal(drop.code);

      await dom.rows()[1].copy.handlers.get('click')();
      assert.match(dom.$('revealed-note').textContent, /Could not copy Password/);
      assert.match(dom.$('revealed-note').textContent, /reveal it and select it/);
    } finally {
      restore();
    }
  });

  it('never builds a node from markup, so a payload cannot become one', async () => {
    // The schema refuses most of this, but the page's defence must not depend on
    // that: every value here is schema-legal and every one of them would be markup
    // if the page interpolated instead of assigning textContent.
    const drop = await createOutboundDrop(broker, {
      payload: {
        v: 1,
        title: 'Escaping',
        fields: [
          { label: 'Tag', type: 'text', value: '<img src=x onerror=alert(1)>' },
          { label: 'Script', type: 'secret', value: '</p><script>alert(1)</script>' },
          { label: 'Entity', type: 'text', value: '&lt;b&gt;&amp;#39;' },
        ],
      },
    });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
    await dom.reveal(drop.code);

    const rows = dom.rows();
    assert.equal(rows[0].shown, '<img src=x onerror=alert(1)>', 'characters, not an element');
    assert.equal(rows[2].shown, '&lt;b&gt;&amp;#39;', 'and not re-decoded either');
    rows[1].toggle.handlers.get('click')();
    assert.equal(dom.rows()[1].shown, '</p><script>alert(1)</script>');

    // Nothing was ever written as markup, and no attribute took a payload string.
    for (const node of dom.created) {
      assert.ok(!('innerHTML' in node), 'the fake node has no innerHTML to have been set');
      for (const [name, value] of node.attributes) {
        assert.ok(
          !/^(href|src|style|on)/i.test(name),
          `no payload-bearing attribute: ${name}=${value}`,
        );
      }
    }
    // A `url` field renders as text, never as a link, so there is no href anywhere.
    assert.ok(!dom.created.some((node) => node.tag === 'a'), 'no anchor is ever built');
  });

  it('spends one attempt per wrong code, says how many are left, and stays on the gate', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
    const wrong = String((Number(drop.code) + 1) % 1000).padStart(3, '0');

    await dom.reveal(wrong);
    assert.equal(dom.state(), 'reveal', 'still on the gate');
    assert.match(dom.$('reveal-note').textContent, /not right/);
    assert.match(dom.$('reveal-note').textContent, /2 tries/);
    assert.equal(dom.$('reveal-code').value, '', 'the wrong code is cleared to be retyped');
    assert.equal(dom.$('reveal-open').disabled, false, 'and the button comes back');
    assert.equal(broker.testOutboundSnapshot(drop.id).attemptsRemaining, 2);

    // ...and the right code still works afterwards.
    await dom.reveal(drop.code);
    assert.equal(dom.state(), 'revealed');
  });

  it('refuses a mistyped length without spending an attempt', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });

    for (const typed of ['', '1', '12', '1234', 'abc', '12a']) {
      await dom.reveal(typed);
      assert.equal(dom.state(), 'reveal', `${JSON.stringify(typed)} stays on the gate`);
      assert.match(dom.$('reveal-note').textContent, /3-digit code/);
      assert.equal(broker.testOutboundSnapshot(drop.id).attemptsRemaining, 3, 'no attempt spent');
    }
  });

  it('closes the drop after three wrong codes and shows the uniform screen', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
    const wrong = String((Number(drop.code) + 1) % 1000).padStart(3, '0');

    await dom.reveal(wrong);
    await dom.reveal(wrong);
    await dom.reveal(wrong);

    assert.equal(dom.state(), 'unavailable', 'the budget is the rate limit');
    assert.equal(dom.$('revealed').hidden, true);
    assert.equal(broker.testOutboundSnapshot(drop.id), null, 'and the payload is gone');
  });

  it('shows the uniform screen for a fragment that is missing, malformed or spent', async () => {
    for (const hash of ['#r.short.short', '#r..', `#r.${'z'.repeat(22)}.${'z'.repeat(43)}`]) {
      const dom = await loadApp({ hash, origin: broker.baseUrl });
      assert.equal(dom.$('unavailable').hidden, false, `hash ${hash}`);
      assert.equal(dom.$('reveal').hidden, true);
      assert.equal(dom.$('form').hidden, true, 'and an outbound-shaped link never shows the form');
    }

    // A drop already revealed by another browser is the same screen: the page never
    // learns whether a secret was taken or the link merely lapsed.
    const spent = await createOutboundDrop(broker, { payload: CANON });
    await spent.reveal();
    const dom = await loadApp({ hash: `#${spent.fragment}`, origin: broker.baseUrl });
    assert.equal(dom.$('unavailable').hidden, false);
  });

  it('retries the same claim id when the reveal request fails mid-flight', async () => {
    // The one property that keeps a dropped response from costing the user the
    // secret: a retry is the *same* claimant, so the broker replays the same
    // ciphertext instead of refusing a second one.
    const drop = await createOutboundDrop(broker, { payload: CANON });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });

    const realFetch = globalThis.fetch;
    const claims = [];
    globalThis.fetch = async (url, options) => {
      if (String(url).endsWith('/api/reveal/claim')) {
        claims.push(JSON.parse(String(options.body)));
        throw new TypeError('fetch failed');
      }
      return realFetch(url, options);
    };
    try {
      await dom.reveal(drop.code);
      assert.equal(dom.state(), 'reveal', 'a transport failure is not a refusal');
      assert.match(dom.$('reveal-note').textContent, /try again/i);
      assert.equal(dom.$('reveal-open').disabled, false);
      assert.equal(claims.length, 1);
      assert.equal(broker.testOutboundSnapshot(drop.id).state, 'available', 'nothing was claimed');

      globalThis.fetch = async (url, options) => {
        if (String(url).endsWith('/api/reveal/claim')) claims.push(JSON.parse(String(options.body)));
        return realFetch(url, options);
      };
      await dom.reveal(drop.code);
      assert.equal(dom.state(), 'revealed', 'and the retry lands');
      assert.equal(claims[1].claim_id, claims[0].claim_id, 'as the same claimant, not a second');
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('acknowledges only after a successful decryption, and destroys the drop by doing so', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });

    const realFetch = globalThis.fetch;
    const order = [];
    globalThis.fetch = async (url, options) => {
      const path = String(url).replace(broker.baseUrl, '');
      if (path.startsWith('/api/reveal/')) order.push(path);
      return realFetch(url, options);
    };
    try {
      await dom.reveal(drop.code);
    } finally {
      globalThis.fetch = realFetch;
    }

    // The metadata POST already happened at load, before this stub went in. What is
    // pinned here is the order of the two that matter: the ack is sent *after* the
    // claim and after the local decryption, never before — an ack that arrived first
    // would destroy a payload this page had not yet read.
    assert.deepEqual(order, ['/api/reveal/claim', '/api/reveal/ack']);
    assert.equal(dom.state(), 'revealed');
    assert.equal(broker.testOutboundSnapshot(drop.id), null, 'the payload is destroyed');
    assert.match(dom.$('revealed-note').textContent, /now closed/i);
  });

  it('renders an opaque payload as one masked field rather than refusing it', async () => {
    // A drop minted before the structured format existed, or by a broker speaking a
    // schema this bundle does not know. The secret is already open in the page and
    // the drop is already spent, so refusing to draw it would throw away a value
    // that was delivered correctly.
    const drop = await createOutboundDrop(broker, { plaintext: 'correct horse battery staple' });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
    await dom.reveal(drop.code);

    const rows = dom.rows();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].label, 'Private value');
    assert.equal(rows[0].shown, MASK, 'and it is masked, because unknown means sensitive');
    rows[0].toggle.handlers.get('click')();
    assert.equal(dom.rows()[0].shown, 'correct horse battery staple');
  });

  it('closes the gate when the countdown reaches zero, without claiming anything', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON, ttlSeconds: 1 });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
    assert.equal(dom.$('reveal').hidden, false, 'live at load');

    await new Promise((resolve) => setTimeout(resolve, 1100));
    dom.tick();

    assert.equal(dom.state(), 'unavailable', 'expired in the browser too');
    assert.equal(dom.$('reveal').hidden, true);
    assert.equal(dom.$('reveal-ttl').textContent, '0:00');
  });

  it('cannot repaint the revealed screen when the tab returns after expiry', async () => {
    // Telling someone who *has* the credential that the link failed is an invitation
    // to ask for it again in the chat, which is the outcome this system exists to
    // prevent. Same argument as the inbound receipt.
    const drop = await createOutboundDrop(broker, { payload: CANON, ttlSeconds: 1 });
    const dom = await loadApp({ hash: `#${drop.fragment}`, origin: broker.baseUrl });
    await dom.reveal(drop.code);
    assert.equal(dom.state(), 'revealed');

    await new Promise((resolve) => setTimeout(resolve, 1100));
    dom.tick();
    dom.documentHandlers.get('visibilitychange')();

    assert.equal(dom.state(), 'revealed', 'the values are still the answer');
    assert.equal(dom.$('unavailable').hidden, true);
    assert.equal(dom.rows().length, 4, 'and they are still on screen');
  });
});

describe('the reveal page: what a preview can do to it', () => {
  let broker;

  beforeEach(() => {
    delete globalThis.document;
    delete globalThis.window;
  });

  before(async () => {
    broker = await startTestBroker();
  });

  after(async () => {
    await broker.stop();
  });

  it('serves the same page to GET and HEAD without touching the drop', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });

    for (const method of ['GET', 'HEAD', 'GET', 'HEAD']) {
      const response = await fetch(`${broker.baseUrl}/`, { method });
      assert.equal(response.status, 200, method);
      await response.arrayBuffer();
    }
    // Four scanner fetches later the drop is exactly as it was: available, three
    // attempts, payload intact. This is what the code gate buys.
    const snapshot = broker.testOutboundSnapshot(drop.id);
    assert.equal(snapshot.state, 'available');
    assert.equal(snapshot.attemptsRemaining, 3);
    assert.equal(snapshot.hasCiphertext, true);

    // ...and it is still revealable afterwards.
    assert.equal((await drop.reveal()).status, 'revealed');
  });

  it('ships a page and a bundle that load nothing from anywhere else', async () => {
    // No third-party assets and no analytics, checked on the built artefacts rather
    // than on the sources they came from.
    const html = await readFile(new URL('../src/public/index.html', import.meta.url), 'utf8');
    const bundle = await readFile(new URL('../src/public/assets/app.js', import.meta.url), 'utf8');

    for (const [name, text] of [['index.html', html], ['app.js', bundle]]) {
      assert.ok(!/https?:\/\/(?!127\.0\.0\.1|localhost)[a-z]/i.test(text.replace(/https?:\/\/\S*example\S*/gi, '')), `${name} names no external host`);
      assert.ok(!/googletagmanager|google-analytics|sentry|segment|hotjar|plausible/i.test(text), `${name} loads no analytics`);
    }
    for (const attribute of ['src="/assets/app.js"', 'href="/assets/app.css"']) {
      assert.ok(html.includes(attribute), `${attribute} is served from this origin`);
    }
  });

  it('answers every response with the security headers the page relies on', async () => {
    const response = await fetch(`${broker.baseUrl}/`, { method: 'GET' });
    await response.arrayBuffer();

    const csp = response.headers.get('content-security-policy');
    // `default-src 'none'` is what makes the "nothing from anywhere else" claim
    // enforced rather than merely true of today's markup.
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /connect-src 'self'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });

  it('never answers a reveal endpoint to a GET or a HEAD', async () => {
    const drop = await createOutboundDrop(broker, { payload: CANON });

    for (const path of ['/api/reveal/metadata', '/api/reveal/claim', '/api/reveal/ack']) {
      for (const method of ['GET', 'HEAD']) {
        const response = await fetch(`${broker.baseUrl}${path}`, { method });
        await response.arrayBuffer();
        assert.equal(response.status, 404, `${method} ${path}`);
      }
    }
    assert.equal(broker.testOutboundSnapshot(drop.id).state, 'available');
  });
});
