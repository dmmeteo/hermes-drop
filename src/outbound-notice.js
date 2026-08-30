// The one chat message an *outbound* drop costs: a link, a code, a deadline, and
// what "one reveal" means (docs/OUTBOUND_SECRET_DROP_MVP.md, "Approved UX").
//
// Its own module rather than a fourth renderer in src/notice.js, because that
// module's export surface is pinned to its three inbound states
// (test/hermes-wake-contract.test.js) — and because these two messages say opposite
// things. An inbound notice asks for a secret and is *edited* through three states as
// the drop resolves. An outbound notice hands one over and is never edited at all:
// there is no submission to report, and the only event after it is a reveal the
// broker deliberately cannot attribute to a conversation. One post, no follow-up.
//
// EVERY RENDERER HERE EMITS STANDARD MARKDOWN, for the transport reason spelled out
// at length in src/notice.js: both verified adapters run `format_message` over the
// string, Telegram posts MarkdownV2, and an HTML tag would be escaped and *displayed*
// — capability and all (review H1).
//
// NOTHING MODEL-SUPPLIED REACHES THIS TEXT, and that is the load-bearing rule of the
// module rather than an accident of what it happens to render. The payload's `title`
// and its field labels are strings a model composed, and this message is Markdown
// going to a platform that renders links: a "title" of
// `x](https://evil.test) [click here` forges a link in the conversation, and escaping
// it correctly for MarkdownV2 *and* for whatever the adapter's own `format_message`
// then does to it is exactly the double-translation that review H1 was. So nothing
// from the payload reaches the notice. Labels and titles render on the *page*, where
// they are `textContent` and cannot be markup at all (src/client/reveal-view.js).
//
// The code goes in the same message as the link, which the MVP approves and which its
// own security note is honest about: the code is a human-presence and anti-preview
// gate, not a second factor, precisely because the two travel together. What it buys
// is that an unfurler, a scanner or an antivirus fetching the URL cannot consume the
// drop. It is emitted as a backticked span so that it survives MarkdownV2 as a
// protected code span, is unambiguous about its leading zeros, and is tappable to
// copy on both verified platforms.

/** "12 min" — a compact snapshot for clients without relative timestamps. */
function relativeMinutes(expiresAt) {
  return `${Math.max(1, Math.ceil((expiresAt - Date.now()) / 60_000))} min`;
}

const RENDERERS = Object.assign(Object.create(null), {
  discord({ dropId, url, code, expiresAt, fieldCount }) {
    return [
      '🔑 **Private drop from Hermes**',
      `[Open private drop](${url})`,
      `**Access code:** \`${code}\``,
      '',
      `Expires <t:${Math.floor(expiresAt / 1000)}:R>.`,
    ].join('\n');
  },

  // Discord's shape with an absolute UTC deadline: Telegram has no client-rendered
  // relative stamp, so a `<t:UNIX:R>` would show up literally.
  telegram({ dropId, url, code, expiresAt, fieldCount }) {
    return [
      '🔑 **Private drop from Hermes**',
      `[Open private drop](${url})`,
      `**Access code:** \`${code}\``,
      '',
      `Expires in ${relativeMinutes(expiresAt)}.`,
    ].join('\n');
  },

  // No markup of any kind, the URL alone on its own line so no client has to parse a
  // link out of prose, and an absolute deadline because nothing here re-renders a
  // relative one. A *deliberate* choice by the caller, never a default.
  plain({ dropId, url, code, expiresAt, fieldCount }) {
    return [
      '🔑 Private drop from Hermes',
      'Open private drop:',
      url,
      `Access code: ${code}`,
      '',
      `Expires in ${relativeMinutes(expiresAt)}.`,
    ].join('\n');
  },
});

/**
 * Renders the outbound notice for one platform.
 *
 * Fails closed on an unknown platform, exactly as `waitingNotice` does: a fallback to
 * `plain` would turn "this platform was never verified" into something a caller
 * discovers by not noticing. `Object.create(null)` under the registry so that
 * `__proto__`, `toString` and friends cannot resolve to something callable — a
 * caller-supplied platform string reaches this lookup directly.
 */
export function outboundNotice({ dropId, url, code, expiresAt, fieldCount, platform = 'plain' }) {
  const render = typeof platform === 'string' ? RENDERERS[platform] : undefined;
  if (!render) throw new Error(`unsupported notice platform: ${platform}`);
  return render({ dropId, url, code, expiresAt, fieldCount });
}
