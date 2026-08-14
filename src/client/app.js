import { DEFAULT_FILE_LIMITS, FILE_ENVELOPE_VERSION, PAYLOAD_KIND_TEXT, PAYLOAD_KIND_UNIVERSAL, encodeFileContainer } from '../file-container.js';
import { parseOutboundFragment } from '../outbound-envelope.js';
import { isSensitiveFieldType, parseOutboundPayload } from '../outbound-payload.js';
import { createDeadline, formatRemaining } from './countdown.js';
import { fetchMetadata, plaintextByteLength, readCapability, sealBytesEnvelope, sealEnvelope, submitEnvelope } from './handoff-client.js';
import { fetchOutboundMetadata, newClaimId, revealSecret } from './reveal-client.js';
import { renderRevealedFields, writeToClipboard } from './reveal-view.js';

const $ = (id) => document.getElementById(id);
// Built by filtering rather than as a literal, because one page serves both
// directions and a section is only in the document once its slice has shipped. A
// missing id is a screen this build cannot show, not a crash on load.
const screens = Object.fromEntries(
  ['form', 'success', 'unavailable', 'reveal', 'revealed']
    .map((name) => [name, $(name)])
    .filter(([, element]) => element !== null),
);
const textarea = $('secret');
const sendButton = $('send');
const note = $('note');
const ttlNote = $('ttl');
const filePanel = $('file-panel');
const fileInput = $('files');
const dropZone = $('drop-zone');
const fileList = $('file-list');
const fileTotal = $('file-total');
let selectedFiles = [];
let metadata = null;
let deadline = null;
let ticker = null;
let pending = null; // exact sealed envelope + declaration, retained for retry
const capability = readCapability(window.location.hash);
const origin = window.location.origin;

// Which screens keep a live countdown: the two that are still waiting on a person.
// Everything else is terminal, and a terminal screen that let a ticker keep running
// could be repainted into `unavailable` after the work already succeeded.
const COUNTING_SCREENS = new Set(['form', 'reveal']);
function show(name) {
  if (!COUNTING_SCREENS.has(name)) stopCountdown();
  for (const [key, section] of Object.entries(screens)) section.hidden = key !== name;
  $('app').dataset.state = name;
}
function stopCountdown() { deadline = null; if (ticker !== null) window.clearInterval(ticker); ticker = null; }
// Which element the countdown writes into. The inbound form and the reveal gate each
// have their own, and only one of the two is ever live in a page.
let ttlTarget = ttlNote;
function renderRemaining() {
  if (!deadline || !ttlTarget) return;
  const remaining = deadline.remaining();
  ttlTarget.textContent = formatRemaining(remaining);
  const minutes = Math.ceil(remaining / 60000);
  ttlTarget.setAttribute('aria-label', remaining <= 0 ? 'expired' : `${minutes} minute${minutes === 1 ? '' : 's'} left`);
  if (remaining <= 0) show('unavailable');
}
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}
function limits() {
  return { maxFiles: metadata?.max_files ?? DEFAULT_FILE_LIMITS.maxFiles, maxFileBytes: metadata?.max_file_bytes ?? DEFAULT_FILE_LIMITS.maxFileBytes, maxTotalBytes: metadata?.max_total_bytes ?? DEFAULT_FILE_LIMITS.maxTotalBytes };
}
function renderFiles() {
  if (!fileList || !fileTotal) return;
  fileList.textContent = '';
  selectedFiles.forEach((file, index) => {
    const li = document.createElement('li');
    const name = document.createElement('span'); name.className = 'name'; name.textContent = file.name;
    const size = document.createElement('span'); size.className = 'meta'; size.textContent = formatBytes(file.size);
    const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = 'Remove'; remove.setAttribute('aria-label', `Remove ${file.name}`);
    remove.addEventListener('click', () => { selectedFiles.splice(index, 1); renderFiles(); });
    li.append(name, size, remove); fileList.append(li);
  });
  const total = selectedFiles.reduce((sum, file) => sum + file.size, 0);
  fileTotal.textContent = `${selectedFiles.length} file${selectedFiles.length === 1 ? '' : 's'} · ${formatBytes(total)}`;
}
function addFiles(files) {
  if (pending) return;
  const candidate = [...selectedFiles, ...files];
  const cap = limits();
  if (candidate.length > cap.maxFiles) { note.textContent = `Choose at most ${cap.maxFiles} files`; return; }
  if (candidate.some((f) => f.size > cap.maxFileBytes)) { note.textContent = `Each file must be at most ${formatBytes(cap.maxFileBytes)}`; return; }
  const total = candidate.reduce((sum, f) => sum + f.size, 0);
  if (total > cap.maxTotalBytes) { note.textContent = `Files must total at most ${formatBytes(cap.maxTotalBytes)}`; return; }
  selectedFiles = candidate; renderFiles(); note.textContent = 'Files ready · one secure send';
}
function wireInbound() {
  fileInput?.addEventListener('change', () => { addFiles([...fileInput.files]); fileInput.value = ''; });
  if (dropZone) for (const type of ['dragenter', 'dragover']) dropZone.addEventListener(type, (event) => { event.preventDefault(); dropZone.classList.add('drag'); });
  if (dropZone) for (const type of ['dragleave', 'drop']) dropZone.addEventListener(type, (event) => { event.preventDefault(); dropZone.classList.remove('drag'); if (type === 'drop') addFiles([...event.dataTransfer.files]); });
  sendButton.addEventListener('click', send);
  textarea.addEventListener('input', () => { if (!metadata) return; const size = plaintextByteLength(textarea.value); note.textContent = size > metadata.max_plaintext_bytes ? `Too large — keep it under ${metadata.max_plaintext_bytes} bytes` : 'One secure send · no edits'; });
}

async function start() {
  if (!capability) return show('unavailable');
  const askedAt = performance.now();
  metadata = await fetchMetadata({ capability, origin });
  if (!metadata || (metadata.payload_kind !== PAYLOAD_KIND_TEXT && metadata.payload_kind !== PAYLOAD_KIND_UNIVERSAL)) return show('unavailable');
  deadline = createDeadline({ expiresAt: metadata.expires_at, now: metadata.now, elapsedSinceAnswerMs: performance.now() - askedAt });
  renderRemaining(); if (!deadline) return;
  show('form'); textarea.focus(); ticker = window.setInterval(renderRemaining, 1000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) renderRemaining(); });
}

async function send() {
  if (!metadata || sendButton.disabled) return;
  if (!pending && textarea.value.length === 0 && selectedFiles.length === 0) { textarea.focus(); return; }
  if (!pending && plaintextByteLength(textarea.value) > metadata.max_plaintext_bytes) { note.textContent = `Too large — keep it under ${metadata.max_plaintext_bytes} bytes`; return; }
  sendButton.disabled = true; sendButton.textContent = 'Sending…'; textarea.readOnly = true; if (fileInput) fileInput.disabled = true;
  try {
    if (!pending) {
      if (selectedFiles.length === 0) pending = { declaration: 'text', envelope: await sealEnvelope({ capability, metadata, plaintext: textarea.value }) };
      else {
        const files = await Promise.all(selectedFiles.map(async (file) => ({ name: file.name, type: file.type, bytes: new Uint8Array(await file.arrayBuffer()) })));
        const container = await encodeFileContainer(files, { limits: limits(), ...(textarea.value.length === 0 ? {} : { text: textarea.value }) });
        try { pending = { declaration: 'files', envelope: await sealBytesEnvelope({ capability, metadata, bytes: container, version: FILE_ENVELOPE_VERSION }) }; }
        finally { container.fill(0); for (const file of files) file.bytes.fill(0); }
      }
    }
    const outcome = await submitEnvelope({ capability, envelope: pending.envelope, declaration: pending.declaration, origin });
    if (outcome === 'received') { pending = null; textarea.value = ''; selectedFiles = []; renderFiles(); show('success'); return; }
    if (outcome === 'unreachable') { note.textContent = 'Could not reach Hermes — press Send to try again'; sendButton.disabled = false; sendButton.textContent = 'Send to Hermes'; return; }
    show('unavailable');
  } catch { show('unavailable'); }
}

// ── the outbound direction: Hermes → the user ─────────────────────────────────
//
// The gate, then one reveal. Everything the MVP calls load-bearing lives in the few
// rules below rather than in the shape of the code:
//
//   - the code is typed by a person and travels only on the claim, which is the one
//     state-changing request. Loading this page performs a POST for metadata and
//     nothing else, so a preview, a scanner or an antivirus cannot consume the drop;
//   - ONE claim id per page, drawn once here and reused for every retry. A fresh one
//     would be a second claimant and would be refused however correct its code —
//     which is exactly what makes "one browser" true;
//   - the acknowledgement that destroys the payload is sent by `revealSecret` only
//     after a successful *local* decryption. A transport failure therefore leaves the
//     drop reserved to this claim id and retryable for the ack window, so a dropped
//     response does not cost the user the secret;
//   - the decryption key never leaves this function. It came out of the fragment, it
//     is handed to `revealSecret`, and it is used by `crypto.subtle` in this process.
async function startReveal({ capability, key }) {
  const codeInput = $('reveal-code');
  const openButton = $('reveal-open');
  const revealNote = $('reveal-note');
  const fieldList = $('revealed-fields');
  const revealedNote = $('revealed-note');
  const revealedTitle = $('revealed-title');
  ttlTarget = $('reveal-ttl');

  const askedAt = performance.now();
  const meta = await fetchOutboundMetadata({ capability, origin });
  // One answer for expired, already revealed, reserved by another browser, out of
  // attempts and never existed. The page is not entitled to know which, and saying
  // so would tell a link-holder whether a secret was taken.
  if (!meta) return show('unavailable');

  deadline = createDeadline({ expiresAt: meta.expires_at, now: meta.now, elapsedSinceAnswerMs: performance.now() - askedAt });
  renderRemaining();
  if (!deadline) return;

  const tries = (remaining) => `${remaining} tr${remaining === 1 ? 'y' : 'ies'} · one reveal`;
  revealNote.textContent = tries(meta.attempts_remaining);
  show('reveal');
  codeInput.focus();
  ticker = window.setInterval(renderRemaining, 1000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) renderRemaining(); });

  // Drawn once for this page, not once per request. See the header above.
  const claimId = newClaimId();

  async function open() {
    if (openButton.disabled) return;
    const code = codeInput.value.trim();
    // Checked here so a mistyped length costs a keystroke rather than one of three
    // attempts; the broker checks it again and refuses uniformly.
    if (!/^[0-9]+$/.test(code) || code.length !== meta.code_length) {
      revealNote.textContent = `Enter the ${meta.code_length}-digit code from the message`;
      codeInput.focus();
      return;
    }

    openButton.disabled = true;
    openButton.textContent = 'Revealing…';
    codeInput.readOnly = true;
    const retry = (message) => {
      revealNote.textContent = message;
      openButton.disabled = false;
      openButton.textContent = 'Reveal once';
      codeInput.readOnly = false;
      codeInput.focus();
    };

    let outcome;
    try {
      outcome = await revealSecret({ capability, key, code, claimId, origin });
    } catch {
      // Nothing definitive came back. The claim may or may not have been reserved to
      // this id, and either way the *same* id may present the *same* code again
      // inside the ack window — so this is retryable and must not spend the reveal.
      return retry('Could not reach the drop — press Reveal to try again');
    }

    if (outcome.status === 'code_incorrect') {
      const remaining = outcome.attempts_remaining;
      codeInput.value = '';
      return retry(
        remaining > 0
          ? `That code is not right — ${tries(remaining)}`
          : 'That code is not right',
      );
    }
    if (outcome.status === 'invalid_code') return retry(`Enter the ${meta.code_length}-digit code`);
    if (outcome.status === 'undecryptable') {
      // The claim is still reserved to this id and nothing was acknowledged, so a
      // retry is legal — but a wrong key or a substituted ciphertext will fail the
      // same way every time, and the honest thing is to say the link is damaged
      // rather than to blame the code.
      return retry('This link could not open the value — it may be damaged');
    }
    if (outcome.status !== 'revealed') return show('unavailable');

    renderRevealed(outcome.plaintext, outcome.acknowledged);
  }

  function renderRevealed(plaintext, acknowledged) {
    const parsed = parseOutboundPayload(plaintext);
    // An opaque payload, or one from a broker speaking a schema this bundle does not
    // know: rendered as a single masked field rather than refused. The secret is
    // already open in this page and the drop is already spent, so refusing to draw it
    // would destroy a value that was delivered correctly.
    const payload = parsed.ok
      ? parsed.payload
      : { fields: [{ label: 'Private value', type: 'secret', value: plaintext }] };
    if (payload.title) revealedTitle.textContent = payload.title;

    renderRevealedFields({
      document,
      list: fieldList,
      payload,
      isSensitive: isSensitiveFieldType,
      copy: writeToClipboard,
      report: (message) => { revealedNote.textContent = message; },
    });
    show('revealed');
    // A failed acknowledgement is worth saying and never worth calling a failure: the
    // user has the value, and the broker destroys the payload at the end of the ack
    // window regardless.
    revealedNote.textContent =
      acknowledged === 'acknowledged'
        ? 'Copy what you need — this drop is now closed.'
        : 'Copy what you need now. This drop closes on its own within the minute.';
    codeInput.value = '';
  }

  openButton.addEventListener('click', open);
  codeInput.addEventListener('keydown', (event) => { if (event.key === 'Enter') open(); });
}

// Which direction this link is, decided from the fragment alone — the server is never
// sent it, so the page cannot ask. An outbound fragment is `r.<capability>.<key>`; an
// inbound one is a bare capability (src/outbound-envelope.js).
const outboundFragment = parseOutboundFragment(window.location.hash);
if (outboundFragment) {
  startReveal(outboundFragment);
} else {
  wireInbound();
  start();
}
