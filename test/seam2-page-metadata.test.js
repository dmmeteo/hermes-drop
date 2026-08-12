// Seam 2 — Browser GET loads the minimal responsive form, and handoff metadata
// arrives without the capability ever entering the HTTP request target.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { decodeBase64Url, splitHandoffUrl, startTestBroker } from './helpers/harness.js';

const execFileAsync = promisify(execFile);
const REPO_ROOT = fileURLToPath(new URL('..', import.meta.url));

describe('seam 2: page delivery and capability-authorized metadata', () => {
  let broker;
  let page;

  before(async () => {
    // The browser bundle is a build artifact; build it before asserting on it.
    await execFileAsync(process.execPath, ['scripts/build-client.mjs'], { cwd: REPO_ROOT });
    broker = await startTestBroker();
    page = await fetch(`${broker.baseUrl}/`);
  });

  after(async () => {
    await broker.stop();
  });

  describe('the page itself', () => {
    let html;

    before(async () => {
      html = await page.text();
    });

    it('serves one html document with no query or capability in the request target', () => {
      assert.equal(page.status, 200);
      assert.match(page.headers.get('content-type'), /^text\/html; charset=utf-8$/);
    });

    it('reuses the accepted Variant A direction', () => {
      assert.match(html, /Send to Hermes/);
      assert.match(html, /Private drop/);
    });

    it('carries the Hermes Drop user-facing branding', () => {
      assert.match(html, /<title>Hermes Drop<\/title>/, 'product name');
      assert.match(html, /<h1>Send privately to Hermes<\/h1>/, 'public heading');
      assert.match(html, />Send to Hermes</, 'the send action keeps its wording');
      assert.ok(!html.includes('Hermes is ready.'), 'the old heading is gone');
      assert.match(html, /<h1>This link is unavailable<\/h1>/, 'unavailable heading');
      assert.match(html, /Ask Hermes for a new link/, 'unavailable guidance');
      // The internal domain term must not surface anywhere a user can read it.
      assert.ok(
        !/handoff/i.test(html),
        'the word "handoff" must not appear in the public document',
      );
      // Branding must not have smuggled chrome back in.
      assert.ok(!/<img|<svg|<header|<nav/.test(html), 'still no logo or header chrome');
      assert.equal(html.match(/<h1/g).length, 3, 'one heading per screen, nothing added');
    });

    it('drops the prototype variant switcher and the losing variants', () => {
      for (const marker of [
        'THROWAWAY PROTOTYPE',
        'prototype-flag',
        'Prototype variants',
        'variantName',
        'formB',
        'formC',
        'Requested by Hermes',
        'Encrypt &amp; send once',
        'phone',
        'Private reply',
      ]) {
        assert.ok(!html.includes(marker), `runtime page must not contain "${marker}"`);
      }
    });

    it('is one always-visible composer with textarea, file picker and one send button', () => {
      assert.equal(html.match(/<textarea/g).length, 1);
      assert.equal(html.match(/<button/g).length, 1);
      assert.doesNotMatch(html, /id="(?:text|files)-mode"/);
      assert.match(html, /id="files"/);
      assert.match(html, /id="send"/);
      assert.ok(!/<img|<svg|<header|<nav/.test(html), 'no logo or header chrome');
    });

    it('has one multi-file picker and Send spans the width', async () => {
      assert.equal((html.match(/<input/g) || []).length, 1);
      assert.match(html, /<input[^>]+type="file"[^>]+multiple/);

      const css = await (await fetch(`${broker.baseUrl}/assets/app.css`)).text();
      const primary = css.match(/\.primary\s*\{[^}]*\}/)[0];
      assert.match(primary, /width:\s*100%/, 'the Send button spans the full bottom width');
      assert.ok(!/min-width/.test(primary), 'a spanning button needs no min-width');

      const actions = css.match(/\.actions\s*\{[^}]*\}/)[0];
      assert.ok(
        !/justify-content:\s*space-between/.test(actions),
        'the note no longer sits beside the button',
      );
    });

    it('shows a live countdown placeholder rather than a static duration', () => {
      const ttl = html.match(/<[a-z]+ id="ttl"[^>]*>([^<]*)</)[1];
      assert.ok(!/minute/i.test(ttl), 'the copy must not hard-code "10 minutes"');
      assert.ok(!/minute/i.test(html), 'nor anywhere else in the document');
      assert.match(html, /id="ttl"[^>]*role="timer"/, 'the countdown is announced as a timer');
    });

    it('keeps textarea contents out of form restore, spellcheck and autocorrect', () => {
      const textarea = html.match(/<textarea[^>]*>/)[0];
      assert.match(textarea, /autocomplete="off"/);
      assert.match(textarea, /spellcheck="false"/);
      assert.match(textarea, /autocapitalize="off"/);
      assert.match(textarea, /autocorrect="off"/);
    });

    it('has no inline script or style, so a strict CSP needs no unsafe-inline', () => {
      assert.ok(!/<style[^>]*>[^<]/.test(html), 'no inline <style> body');
      assert.ok(!/<script(?![^>]*\ssrc=)/.test(html), 'no inline <script> body');
      assert.ok(!/\son\w+=/.test(html), 'no inline event handlers');
    });

    it('is responsive and follows the system light/dark theme', async () => {
      assert.match(html, /<meta name="viewport" content="width=device-width/);
      const css = await (await fetch(`${broker.baseUrl}/assets/app.css`)).text();
      assert.match(css, /@media\s*\(prefers-color-scheme:\s*dark\)/);
      assert.match(css, /@media\s*\(max-width/);
      assert.match(css, /color-scheme:\s*light dark/);
    });
  });

  describe('security headers', () => {
    it('sends a strict self-only CSP and no-referrer', () => {
      const csp = page.headers.get('content-security-policy');
      assert.ok(csp, 'CSP header is required');
      assert.match(csp, /default-src 'none'/);
      assert.match(csp, /script-src 'self'/);
      assert.match(csp, /style-src 'self'/);
      assert.match(csp, /connect-src 'self'/);
      assert.match(csp, /frame-ancestors 'none'/);
      assert.match(csp, /base-uri 'none'/);
      assert.match(csp, /form-action 'none'/);
      assert.ok(!csp.includes('unsafe-inline'), 'CSP must not allow inline code');
      assert.ok(!csp.includes('unsafe-eval'), 'CSP must not allow eval');
      assert.ok(!/https?:\/\//.test(csp), 'CSP must name no third-party origin');

      assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
      assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(page.headers.get('x-frame-options'), 'DENY');
      assert.equal(page.headers.get('cache-control'), 'no-store');
      assert.match(page.headers.get('permissions-policy'), /geolocation=\(\)/);
    });

    it('sends no cookies and advertises no server software', () => {
      assert.equal(page.headers.get('set-cookie'), null);
      assert.equal(page.headers.get('server'), null);
    });
  });

  describe('the self-hosted browser bundle', () => {
    let bundle;

    before(async () => {
      bundle = await readFile(new URL('../src/public/assets/app.js', import.meta.url), 'utf8');
    });

    it('is served from this origin as javascript', async () => {
      const response = await fetch(`${broker.baseUrl}/assets/app.js`);
      assert.equal(response.status, 200);
      assert.match(response.headers.get('content-type'), /^text\/javascript/);
      assert.equal(response.headers.get('cache-control'), 'no-store');
    });

    it('embeds the pinned hpke implementation instead of a cdn', () => {
      assert.ok(!/\bfrom\s*["'][^."'][^"']*["']/.test(bundle), 'no bare module imports remain');
      assert.ok(!/cdn|unpkg|jsdelivr|esm\.sh|googleapis/i.test(bundle), 'no third-party origin');
      assert.match(bundle, /ECDH/);
      assert.match(bundle, /AES-GCM/);
    });

    it('never puts the capability in a url', () => {
      assert.ok(!/[?&]cap/.test(bundle), 'capability must not be assembled into a query string');
      assert.match(bundle, /X-Handoff-Capability/i);
    });
  });

  describe('POST /api/metadata', () => {
    it('returns the non-secret handoff metadata for a live capability', async () => {
      const created = await broker.control({ op: 'create' });
      const { capability } = splitHandoffUrl(created.url);

      const before = Date.now();
      const response = await fetch(`${broker.baseUrl}/api/metadata`, {
        method: 'POST',
        headers: { 'x-handoff-capability': capability },
      });
      const after = Date.now();
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('cache-control'), 'no-store');

      const body = await response.json();
      assert.equal(body.hid, created.handoff_id);
      assert.equal(body.v, 1);
      assert.equal(body.suite, 'DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM');
      assert.equal(decodeBase64Url(body.pk).length, 65, 'uncompressed P-256 point');
      assert.equal(decodeBase64Url(body.pk)[0], 0x04, 'must not be a compressed point');
      assert.equal(body.max_plaintext_bytes, 65536);
      assert.equal(body.expires_at, created.expires_at);

      // The page must be able to compute "time left" without trusting the
      // device clock, so the broker states its own clock alongside the expiry.
      assert.ok(Number.isInteger(body.now), 'metadata must carry the broker clock');
      assert.ok(body.now >= before && body.now <= after, 'and it must be this response`s clock');
      assert.ok(
        !('created_at' in body),
        'remaining duration needs an expiry and a time base, not a creation stamp',
      );

      const serialized = JSON.stringify(body);
      assert.ok(!serialized.includes(capability), 'metadata must not echo the capability');
      assert.ok(!('sk' in body) && !('private_key' in body));
    });

    it('mints a distinct recipient key per handoff', async () => {
      const keys = new Set();
      const fingerprintable = [];
      for (let i = 0; i < 12; i += 1) {
        const created = await broker.control({ op: 'create' });
        const { capability } = splitHandoffUrl(created.url);
        const body = await (
          await fetch(`${broker.baseUrl}/api/metadata`, {
            method: 'POST',
            headers: { 'x-handoff-capability': capability },
          })
        ).json();
        assert.equal(decodeBase64Url(body.pk).length, 65);
        keys.add(body.pk);
        fingerprintable.push(body.hid);
      }
      assert.equal(keys.size, 12, 'a handoff must never reuse another handoff public key');
      assert.equal(new Set(fingerprintable).size, 12);
    });

    it('ignores a capability presented in the query string', async () => {
      const created = await broker.control({ op: 'create' });
      const { capability } = splitHandoffUrl(created.url);

      const response = await fetch(
        `${broker.baseUrl}/api/metadata?capability=${encodeURIComponent(capability)}`,
        { method: 'POST' },
      );
      assert.equal(response.status, 404);
      assert.equal(await response.text(), '{"status":"unavailable"}');
    });

    it('refuses methods other than POST', async () => {
      const created = await broker.control({ op: 'create' });
      const { capability } = splitHandoffUrl(created.url);
      const response = await fetch(`${broker.baseUrl}/api/metadata`, {
        headers: { 'x-handoff-capability': capability },
      });
      assert.equal(response.status, 404);
      assert.equal(await response.text(), '{"status":"unavailable"}');
    });

    it('discloses nothing on an unknown path', async () => {
      const response = await fetch(`${broker.baseUrl}/handoffs`);
      assert.equal(response.status, 404);
      const body = await response.text();
      assert.ok(!body.includes('handoff_id'));
      assert.ok(!/pending|submitted|claimed/.test(body));
    });
  });
});
