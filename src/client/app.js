// DOM wiring for the accepted Variant A page. All crypto and transport lives in
// handoff-client.js; this file only moves between the three screens.
import { PAYLOAD_KIND_TEXT } from '../file-container.js';
import { createDeadline, formatRemaining } from './countdown.js';
import {
  fetchMetadata,
  plaintextByteLength,
  readCapability,
  sealEnvelope,
  submitEnvelope,
} from './handoff-client.js';

const screens = {
  form: document.getElementById('form'),
  success: document.getElementById('success'),
  unavailable: document.getElementById('unavailable'),
};
const textarea = document.getElementById('secret');
const sendButton = document.getElementById('send');
const note = document.getElementById('note');
const ttlNote = document.getElementById('ttl');

function show(name) {
  // Leaving the form is final: a receipt or a refusal must never be repainted
  // by a countdown that fires afterwards.
  if (name !== 'form') stopCountdown();
  for (const [key, section] of Object.entries(screens)) section.hidden = key !== name;
  document.getElementById('app').dataset.state = name;
}

// The countdown owns the form screen only.
let deadline = null;
let ticker = null;

/**
 * Detaching the deadline — not just clearing the interval — is what makes
 * leaving the form final. The `visibilitychange` listener registered in
 * `start()` is an anonymous closure that cannot be removed and outlives the
 * ticker, so clearing the interval alone still let a returning tab repaint a
 * delivered receipt as "this link is unavailable". Telling someone who *did*
 * hand over a credential that it failed invites them to resend it into the
 * chat channel, which is exactly what this system exists to prevent. With the
 * deadline gone, `renderRemaining` is a no-op from whichever path calls it.
 */
function stopCountdown() {
  deadline = null;
  if (ticker === null) return;
  window.clearInterval(ticker);
  ticker = null;
}

function renderRemaining() {
  if (!deadline) return;
  const remaining = deadline.remaining();
  ttlNote.textContent = formatRemaining(remaining);
  // `role="timer"` is not a live region, so the ticking digits are never
  // announced. A whole-minute label is something assistive technology can read
  // on demand without a per-second announcement nobody wants.
  const minutes = Math.ceil(remaining / 60000);
  ttlNote.setAttribute(
    'aria-label',
    remaining <= 0 ? 'expired' : `${minutes} minute${minutes === 1 ? '' : 's'} left`,
  );
  // The broker expired it too; stop offering a Send that cannot succeed.
  if (remaining <= 0) show('unavailable');
}

const capability = readCapability(window.location.hash);
// Pinned explicitly rather than left relative: same requests in the browser, and
// it keeps this module drivable outside one.
const origin = window.location.origin;
let metadata = null;

async function start() {
  if (!capability) return show('unavailable');

  const askedAt = performance.now();
  metadata = await fetchMetadata({ capability, origin });
  if (!metadata) return show('unavailable');

  // This page is a text page: one textarea, one Send, one UTF-8 secret sealed
  // under envelope v1. A file drop advertises `payload_kind: "files"` and, with
  // it, no `max_plaintext_bytes` at all — which is the field both size guards
  // below read. Rendering the form anyway would leave them comparing against
  // `undefined`, i.e. never firing, so an arbitrarily large secret would be
  // sealed and posted into a body ceiling widened for containers, to be refused
  // on the version mismatch at the far end. Refusing the link is the honest
  // answer until the picker lands (docs/FILE_TRANSFER_MVP.md, slice 6), and it
  // keeps `metadata` null so no later handler can act on it.
  if (metadata.payload_kind !== PAYLOAD_KIND_TEXT) {
    metadata = null;
    return show('unavailable');
  }

  // Anchored on the broker's clock, not the device's — see countdown.js. The
  // whole round trip is charged against the remaining span: that over-charges
  // by the request leg, which is the safe direction.
  deadline = createDeadline({
    expiresAt: metadata.expires_at,
    now: metadata.now,
    elapsedSinceAnswerMs: performance.now() - askedAt,
  });
  // Already dead on arrival: this paints 0:00, shows the unavailable screen and
  // detaches the deadline, which is the single signal that the countdown is over.
  renderRemaining();
  if (!deadline) return;

  show('form');
  textarea.focus();

  ticker = window.setInterval(renderRemaining, 1000);
  // A hidden tab has its timers throttled to as little as one tick a minute, so
  // coming back has to resync from the deadline rather than trust the ticker.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) renderRemaining();
  });
}

// Survives a transient transport failure: pressing Send again resends these exact
// bytes rather than sealing a second, different envelope the broker would refuse.
let pendingEnvelope = null;

sendButton.addEventListener('click', async () => {
  if (!metadata || sendButton.disabled) return;

  const plaintext = textarea.value;
  if (!pendingEnvelope && plaintext.length === 0) {
    textarea.focus();
    return;
  }
  if (!pendingEnvelope && plaintextByteLength(plaintext) > metadata.max_plaintext_bytes) {
    note.textContent = `Too large — keep it under ${metadata.max_plaintext_bytes} bytes`;
    return;
  }

  sendButton.disabled = true;
  sendButton.textContent = 'Sending…';
  textarea.readOnly = true;

  try {
    pendingEnvelope = pendingEnvelope ?? (await sealEnvelope({ capability, metadata, plaintext }));
    const outcome = await submitEnvelope({ capability, envelope: pendingEnvelope, origin });

    if (outcome === 'received') {
      // Only a definitive receipt clears the visible copy.
      pendingEnvelope = null;
      textarea.value = '';
      show('success');
      return;
    }

    if (outcome === 'unreachable') {
      // Nothing definitive came back, so keep the text and the sealed envelope.
      note.textContent = 'Could not reach Hermes — press Send to try again';
      sendButton.disabled = false;
      sendButton.textContent = 'Send to Hermes';
      return;
    }

    show('unavailable');
  } catch {
    show('unavailable');
  }
});

textarea.addEventListener('input', () => {
  if (!metadata) return;
  const size = plaintextByteLength(textarea.value);
  note.textContent =
    size > metadata.max_plaintext_bytes
      ? `Too large — keep it under ${metadata.max_plaintext_bytes} bytes`
      : 'One secure send · no edits';
});

start();
