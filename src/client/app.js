import { DEFAULT_FILE_LIMITS, FILE_ENVELOPE_VERSION, PAYLOAD_KIND_TEXT, PAYLOAD_KIND_UNIVERSAL, encodeFileContainer } from '../file-container.js';
import { createDeadline, formatRemaining } from './countdown.js';
import { fetchMetadata, plaintextByteLength, readCapability, sealBytesEnvelope, sealEnvelope, submitEnvelope } from './handoff-client.js';

const $ = (id) => document.getElementById(id);
const screens = { form: $('form'), success: $('success'), unavailable: $('unavailable') };
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

function show(name) {
  if (name !== 'form') stopCountdown();
  for (const [key, section] of Object.entries(screens)) section.hidden = key !== name;
  $('app').dataset.state = name;
}
function stopCountdown() { deadline = null; if (ticker !== null) window.clearInterval(ticker); ticker = null; }
function renderRemaining() {
  if (!deadline) return;
  const remaining = deadline.remaining();
  ttlNote.textContent = formatRemaining(remaining);
  const minutes = Math.ceil(remaining / 60000);
  ttlNote.setAttribute('aria-label', remaining <= 0 ? 'expired' : `${minutes} minute${minutes === 1 ? '' : 's'} left`);
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
fileInput?.addEventListener('change', () => { addFiles([...fileInput.files]); fileInput.value = ''; });
if (dropZone) for (const type of ['dragenter', 'dragover']) dropZone.addEventListener(type, (event) => { event.preventDefault(); dropZone.classList.add('drag'); });
if (dropZone) for (const type of ['dragleave', 'drop']) dropZone.addEventListener(type, (event) => { event.preventDefault(); dropZone.classList.remove('drag'); if (type === 'drop') addFiles([...event.dataTransfer.files]); });

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

sendButton.addEventListener('click', async () => {
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
});
textarea.addEventListener('input', () => { if (!metadata) return; const size = plaintextByteLength(textarea.value); note.textContent = size > metadata.max_plaintext_bytes ? `Too large — keep it under ${metadata.max_plaintext_bytes} bytes` : 'One secure send · no edits'; });
start();
