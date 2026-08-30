// The renderer registry behind the one chat message.
//
// Rendering is the broker's job, not the caller's: the notice wording for every
// platform lives in this repo, so a platform Hermes cannot render richly still
// gets a notice from here rather than model prose.
//
// Three properties are load-bearing:
//
//   - `plain` exists, carries no markup of any kind, and puts the URL on a line
//     of its own, because that is the only shape that survives a platform whose
//     formatting we have not verified end to end.
//   - an *unknown* platform still throws. A silent fallback to `plain` would
//     make an unsupported platform something a caller discovers by not noticing,
//     and §7.3 requires the refusal to be loud.
//   - the two quiet states are byte-identical on every platform, which is what
//     lets the Hermes side treat them as constants instead of asking for them.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { expiredNotice, receivedNotice, waitingNotice } from '../src/notice.js';

const handoffId = 'abcdefghijklmnopqrstuv';
const url = 'https://drop.example.test/#0123456789abcdefghij_-';
const expiresAt = 1_800_000_000_000;


describe('the notice renderer registry', () => {
  it('renders a `plain` waiting notice with no markup at all', () => {
    const notice = waitingNotice({ handoffId, url, expiresAt, platform: 'plain' });

    for (const markup of ['**', '](', '<a ', '<b>', '<code>', '<t:', '`']) {
      assert.ok(!notice.includes(markup), `plain carries no ${markup}`);
    }
    assert.ok(!/[<>]/.test(notice), 'and no angle brackets at all, so nothing can be an HTML tag');
  });

  it('puts the bare URL on a line of its own, so no unfurler has to be trusted', () => {
    const lines = waitingNotice({ handoffId, url, expiresAt, platform: 'plain' }).split('\n');
    assert.ok(
      lines.includes(url),
      `the url must be a whole line by itself; got ${JSON.stringify(lines)}`,
    );
    assert.equal(lines.filter((line) => line.includes(url)).length, 1, 'named exactly once');
  });

  it('renders one compact relative expiry line outside Discord', () => {
    const notice = waitingNotice({ handoffId, url, expiresAt, platform: 'plain' });
    assert.match(notice.split('\n').at(-1), /^Expires in \d+ min\.$/);
    assert.ok(!notice.includes('<t:'), 'no Discord relative stamp outside Discord');
  });

  it('keeps transport metadata out of the notice', () => {
    const notice = waitingNotice({ handoffId, url, expiresAt, platform: 'plain' });
    assert.ok(!notice.includes(`drop:${handoffId}`));
  });

  it('carries no capability-shaped token outside the link itself', () => {
    const notice = waitingNotice({ handoffId, url, expiresAt, platform: 'plain' });
    const rest = notice.split(url).join('').split(handoffId).join('');
    assert.ok(!/[A-Za-z0-9_-]{22}/.test(rest));
  });

  it('renders discord as a masked Markdown link with a relative stamp', () => {
    const discord = waitingNotice({ handoffId, url, expiresAt, platform: 'discord' });
    assert.equal(discord, waitingNotice({ handoffId, url, expiresAt }), 'discord is the default');
    assert.ok(discord.includes(`<t:${Math.floor(expiresAt / 1000)}:R>`));
    assert.match(discord, /\[[^\]]+\]\(https:\/\/drop\.example\.test\/#[^)]+\)/);
  });

  // Review H1. The `telegram` renderer used to emit `<b>` and `<a href>`, which
  // was correct for the superseded raw-Bot-API design. The delivered design posts
  // through `TelegramAdapter.send`, which runs `format_message` and posts with
  // `parse_mode=MARKDOWN_V2` — so HTML was escaped and *displayed*, putting the
  // whole capability URL in plain view. Markdown is the only shape that renders.
  //
  // This asserts the shape; the behaviour is asserted where it can be, against
  // the real adapter, in
  // integrations/hermes-drop/tests/test_notice_adapter_seam.py.
  it('renders telegram as Markdown, never HTML, so MarkdownV2 can carry it', () => {
    const telegram = waitingNotice({ handoffId, url, expiresAt, platform: 'telegram' });

    assert.match(
      telegram,
      /\[open the secure form\]\(https:\/\/drop\.example\.test\/#[^)]+\)/,
      'a masked Markdown link, so the capability is a link target and not text',
    );
    assert.ok(!/[<>]/.test(telegram), 'no angle bracket can become a literal tag');
    assert.ok(telegram.includes('🔒 **Private input requested**'),
      'the lock and Markdown title survive until MarkdownV2 conversion');
    assert.match(telegram.split('\n').at(-1), /^Expires in \d+ min\.$/);
    assert.ok(!telegram.includes('<t:'), 'and no Discord stamp, which would be literal here');
  });

  it('keeps a non-round expiry compact too', () => {
    const ragged = Date.UTC(2027, 0, 15, 8, 0, 0, 542);
    for (const platform of ['telegram', 'plain']) {
      const notice = waitingNotice({ handoffId, url, expiresAt: ragged, platform });
      assert.match(notice.split('\n').at(-1), /^Expires in \d+ min\.$/);
      assert.ok(!notice.includes('.542'), `${platform}: milliseconds are not a deadline`);
    }
  });

  it('fails closed on a platform it does not render', () => {
    for (const platform of ['slack', 'matrix', 'whatsapp', 'PLAIN', 'Discord', '', 'plain ']) {
      assert.throws(
        () => waitingNotice({ handoffId, url, expiresAt, platform }),
        /unsupported notice platform/,
        `unknown platform ${JSON.stringify(platform)} must throw, never fall back`,
      );
    }
  });

  it('never lets a caller reach a renderer by prototype lookup', () => {
    for (const platform of ['toString', 'constructor', '__proto__', 'hasOwnProperty']) {
      assert.throws(
        () => waitingNotice({ handoffId, url, expiresAt, platform }),
        /unsupported notice platform/,
        `${platform} is not a renderer`,
      );
    }
  });

  it('renders the two quiet states byte-identically on every platform', () => {
    // They take no platform at all — that is the point. Asserting it here means
    // a future platform argument cannot quietly start varying them, because the
    // Hermes side treats both as constants (§S1: no `notice` control op).
    assert.equal(receivedNotice.length, 0, 'receivedNotice takes no arguments');
    assert.equal(expiredNotice.length, 0, 'expiredNotice takes no arguments');

    for (const platform of ['discord', 'telegram', 'plain']) {
      assert.equal(receivedNotice(platform), '✓ **Private input received**');
      assert.equal(expiredNotice(platform), '✕ **Private input link expired**');
    }
  });
});
