// The one chat message a drop costs, and the three states it is edited through.
//
// Variant A: Hermes posts `waitingNotice` with `send_message(action="send")`,
// keeps the `message_id` that comes back, and then *edits that same message* —
// to `receivedNotice()` when the browser submits, or `expiredNotice()` when the
// link lapses. The message is never deleted and never joined by a status
// sibling; the substantive answer to the payload is a separate ordinary reply.
//
// The send and the edit both go through the **origin adapter** —
// `adapter.send(...)` and `adapter.edit_message(..., finalize=True)` on the
// adapter that owns the originating conversation (`drop/messenger.py`). There is
// no raw REST call and no bot credential resolution anywhere in the delivered
// design: the earlier plan to `PATCH /channels/{id}/messages/{id}` with the
// active profile's token (research 09) is **superseded** by §2/§7.1, and dropping
// it is the plan's largest security win — no token is read, so none can leak.
//
// EVERY RENDERER HERE EMITS STANDARD MARKDOWN, and that is a transport
// requirement rather than a style choice. Both verified adapters run
// `format_message(content)` over the string before posting it:
//
//   - Telegram posts with `parse_mode=ParseMode.MARKDOWN_V2` and translates a
//     standard Markdown link into a MarkdownV2 one, `**bold**` into `*bold*`,
//     and a backticked span into a protected code span
//     (`plugins/platforms/telegram/adapter.py:7480-7650`, the send at `:4450`).
//     HTML has no meaning there: `<b>` is escaped to a literal `<b>` and
//     *displayed*, which is how the pre-fix HTML notice put the whole capability
//     URL in plain view (review H1). Nothing selects a parse mode from the
//     `metadata` dict the messenger builds, so Markdown is the only shape that
//     renders.
//   - Discord's `format_message` is a table-to-bullets pass and otherwise a
//     passthrough (`plugins/platforms/discord/adapter.py:5197-5205`).
//
// The renderer × real-`format_message` seam is pinned by
// integrations/hermes-drop/tests/test_notice_adapter_seam.py, which formats a
// notice minted by this module through both real adapters and asserts the
// capability never reaches the visible layer. Nothing in the JS suite can check
// that — it is a cross-language property.
//
// Two properties are load-bearing and are pinned by
// test/hermes-wake-contract.test.js:
//
//   - The link is a *masked Markdown link*, on both verified platforms. Discord
//     builds no embed for one, and the capability lives in the `#fragment`,
//     which no unfurler would fetch anyway — a fragment is never sent to the
//     server. Telegram may still build a preview for the *base* URL (the plugin
//     cannot suppress it: `_link_preview_kwargs` is adapter-wide config, not a
//     per-message `metadata` key), and that preview carries no fragment.
//   - Discord's deadline is a *relative timestamp*, `<t:UNIX:R>`. Discord
//     re-renders "in 29 minutes" client-side, so the countdown costs zero API
//     calls. A duration baked into the text would go stale within a minute and
//     invite exactly the per-minute edit loop this design rules out. Telegram
//     re-renders nothing, so it gets an absolute UTC deadline instead.
//
// The received and expired states are deliberately bare: no URL, no capability,
// no timestamp, not even the handoff id — by then there is nothing left to look
// up, and a quiet line is the whole point. The `drop:<id>` tag on the waiting
// state stays as an audit affordance and a fallback if the message id is lost.

/** Whichever the wake reports, this is the only content that replaces the link. */
export function receivedNotice() {
  return '✓ **Private input received**';
}

/** Any non-zero `await` exit: the link must stop advertising itself. */
export function expiredNotice() {
  return '✕ **Private input link expired**';
}

/** `2027-01-15T08:00:00 UTC` — the only deadline form no client has to re-render.
 *
 * The milliseconds are matched as a *pattern*, not as the literal `.000Z`: a real
 * `expires_at` is `Date.now() + ttl`, so it lands on `.000` roughly one time in a
 * thousand. Matching the literal left every other deadline reading
 * `2026-08-03T14:55:55.542Z` — sub-second precision nobody asked for, and a `Z`
 * where the word UTC was promised. Caught by the renderer × adapter seam test,
 * whose expiry comes from the broker rather than from a round fixture.
 */
function absoluteUtc(expiresAt) {
  return new Date(expiresAt).toISOString().replace(/\.\d{3}Z$/, ' UTC');
}

// One renderer per platform, and a platform is supported exactly when it has an
// entry here. `Object.create(null)` rather than a literal so `__proto__`,
// `toString` and friends cannot resolve to something callable — a caller-supplied
// platform string reaches this lookup directly.
const RENDERERS = Object.assign(Object.create(null), {
  discord({ handoffId, url, expiresAt }) {
    return [
      `🔐 **Private input** — [open the secure form](${url}) and paste it there, ` +
        'not in this channel.',
      `One send, and the link dies the moment it is used. Expires <t:${Math.floor(
        expiresAt / 1000,
      )}:R>.`,
      `\`drop:${handoffId}\``,
    ].join('\n');
  },

  // Markdown, not HTML — see the header. The shape is Discord's, with one
  // deliberate difference: an absolute UTC deadline, because Telegram has no
  // client-rendered relative stamp and a `<t:UNIX:R>` would show up literally.
  telegram({ handoffId, url, expiresAt }) {
    return [
      `🔐 **Private input** — [open the secure form](${url}) and paste it there, ` +
        'not in this chat.',
      `One send, and the link dies the moment it is used. Expires at ${absoluteUtc(expiresAt)}.`,
      `\`drop:${handoffId}\``,
    ].join('\n');
  },

  // The fallback shape for every platform whose formatting is not verified end to
  // end: no markup of any kind, the URL alone on its own line so no client has to
  // parse a link out of prose, and an absolute deadline because nothing here
  // re-renders a relative one. `plain` is a *deliberate* choice by the caller, not
  // a default — an unknown platform still throws below.
  plain({ handoffId, url, expiresAt }) {
    return [
      '🔐 Private input — open the secure form below and paste it there, not in this chat:',
      url,
      `One send, and the link dies the moment it is used. Expires at ${absoluteUtc(expiresAt)}.`,
      `drop:${handoffId}`,
    ].join('\n');
  },
});

// The module deliberately exports only the three state renderers — the platform
// list is *not* exported, because test/hermes-wake-contract.test.js pins this
// module's public surface to exactly those three states. Callers that need to
// know which platforms exist read `contract/control-protocol.json`, which
// test/control-protocol.test.js holds against this registry.
export function waitingNotice({ handoffId, url, expiresAt, platform = 'discord' }) {
  const render = typeof platform === 'string' ? RENDERERS[platform] : undefined;
  // Fail closed. A fallback to `plain` would turn "this platform was never
  // verified" into something a caller discovers by not noticing.
  if (!render) throw new Error(`unsupported notice platform: ${platform}`);
  return render({ handoffId, url, expiresAt });
}
