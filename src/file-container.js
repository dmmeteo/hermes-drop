// HDROP2 — the encrypted file container (docs/FILE_TRANSFER_MVP.md, slice 1).
//
//   magic: "HDROP2" (6 bytes)
//   manifest_length: uint32 big-endian
//   manifest: UTF-8 JSON
//   file bytes: concatenated in manifest order
//
// Why a hand-rolled container rather than an archive format: this codec runs on
// attacker-supplied bytes the moment an AEAD open succeeds, so its whole job is
// to be small enough to read in one sitting. There is no parser to confuse, no
// decompressor to bomb, no per-entry metadata that can disagree with itself, and
// no new browser dependency. Everything it accepts is length-framed up front and
// verified by SHA-256 before a caller sees a single byte.
//
// Isomorphic, exactly like base64url.js and hpke-suite.js: WebCrypto and the
// TextEncoder/TextDecoder pair only, so the browser bundle and the broker run
// the same validation code. A container the page can build is a container the
// broker can check, byte for byte.
//
// The whole container is sealed once by the existing HPKE suite, so nothing here
// is a confidentiality boundary — it is an *integrity and shape* boundary, and
// it fails closed. Every refusal is a `FileContainerError` carrying a short
// stable code and nothing else: names, MIME hints and payload bytes never reach
// a message, because these errors are logged locally while the public seams keep
// answering their single uniform `unavailable`.

/** ASCII magic. Distinct from the v1 text envelope, which has no container. */
export const CONTAINER_MAGIC = 'HDROP2';

/** uint32 big-endian manifest length. */
export const MANIFEST_LENGTH_BYTES = 4;

/** magic(6) + manifest_length(4) — everything before the manifest itself. */
export const CONTAINER_HEADER_BYTES = 10;

/**
 * Envelope version that will carry a container. v1 stays exactly what it is:
 * one UTF-8 secret, no container, no manifest.
 *
 * Declared here, *not yet bound anywhere*: `src/hpke-suite.js` still builds
 * `info` with `ENVELOPE_VERSION = 1` and `src/broker.js` still refuses any
 * `envelope.v !== 1`. Threading this version through `buildInfo` on both sides
 * and widening the broker's check to an allowlist is required integration work
 * for the broker slice — until it lands, nothing separates a v2 ciphertext from
 * a v1 one cryptographically, because nothing produces one.
 */
export const FILE_ENVELOPE_VERSION = 2;

export const PAYLOAD_KIND_TEXT = 'text';
export const PAYLOAD_KIND_FILES = 'files';

/**
 * The kind of a drop that has not been told which of the two it is yet: one link
 * whose sender chooses text or files in the browser at submit time
 * (docs/UNIVERSAL_DROP_DELIVERY_PLAN.md).
 *
 * It lives here with the other two because this module is the payload vocabulary
 * both sides import, but it is a *lifecycle* kind and nothing else: no container
 * manifest ever carries it, `decodeFileContainer` refuses it like any other
 * unknown `kind`, and a record stops being universal the moment one submission
 * wins.
 */
export const PAYLOAD_KIND_UNIVERSAL = 'universal';

/** Display names are capped in UTF-8 bytes, per the MVP's filename rules. */
export const MAX_FILE_NAME_BYTES = 255;

/** The MIME hint is untrusted display text; the same cap keeps it bounded. */
export const MAX_FILE_TYPE_BYTES = 255;

/** What a sanitized name collapses to when nothing usable survives. */
export const FALLBACK_FILE_NAME = 'unnamed';

/** 42 MiB, the MVP's total and per-file plaintext cap. */
const MIB = 1024 * 1024;

/**
 * The MVP ceiling. Operators may lower every one of these and may raise none of
 * them (`resolveFileLimits`), so this object is simultaneously the default and
 * the maximum — which is what lets `MAX_MANIFEST_BYTES` below be a constant
 * rather than something a caller can widen.
 */
export const DEFAULT_FILE_LIMITS = Object.freeze({
  maxFiles: 5,
  maxFileBytes: 42 * MIB,
  maxTotalBytes: 42 * MIB,
});

/**
 * Worst case for one manifest entry, derived rather than guessed:
 *
 *   name    255 bytes, doubled to 510 because JSON escapes `"` and names may
 *           be nothing but quotes (backslashes cannot survive sanitization —
 *           they are separators);
 *   type    255 bytes, doubled to 510 for the same reason;
 *   sha256  64 bytes, fixed;
 *   size + offset  16 digits each, the widest a safe integer prints;
 *   keys, quotes, colons and braces  56 bytes.
 *
 * That is 1172; 1280 leaves room without pretending to be exact. The test suite
 * measures a genuinely maximal five-file manifest against the ceiling rather
 * than trusting this arithmetic.
 */
const MANIFEST_ENTRY_CEILING_BYTES = 1280;

/** `{"kind":"files","files":[]}` is 27 bytes; 32 covers it with slack. */
const MANIFEST_ENVELOPE_BYTES = 32;

/** The largest manifest `maxFiles` entries can produce, separators included. */
export function worstCaseManifestBytes(maxFiles) {
  return MANIFEST_ENVELOPE_BYTES + maxFiles * (MANIFEST_ENTRY_CEILING_BYTES + 1);
}

/**
 * Hard ceiling on the declared manifest length, checked before a single
 * manifest byte is decoded. Derived from the maximum file count rather than
 * picked: a looser number would widen the pre-parse work an attacker can buy
 * with a hostile length field, and would let a raised `maxFiles` fail late — at
 * submit time, depending on how long the user's filenames happened to be —
 * instead of at startup.
 */
export const MAX_MANIFEST_BYTES = worstCaseManifestBytes(DEFAULT_FILE_LIMITS.maxFiles);

/** Lowercase hex, fixed width — the only digest spelling the manifest accepts. */
const SHA256_HEX = /^[0-9a-f]{64}$/;

/**
 * Unicode Cc (C0/C1 controls, including NUL) and Cf (format characters). Cf is
 * stripped as well as Cc because the bidirectional overrides live there, and
 * `invoice‮gpj.exe` renders as `invoice exe.jpg` in almost every list a
 * human will read this name in. The cost is that a name is a label, not a
 * faithful copy: an emoji joined by U+200D loses its joiner. That trade is made
 * deliberately in favour of the name meaning what it looks like.
 */
const FORMAT_AND_CONTROL = /[\p{Cc}\p{Cf}]/gu;

/** Printable ASCII only for the MIME hint. Anything else is treated as absent. */
const PRINTABLE_ASCII = /^[\x20-\x7e]*$/;

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true });
const MAGIC_BYTES = encoder.encode(CONTAINER_MAGIC);

/**
 * A refusal with a stable machine-readable code and no payload-derived text.
 * Codes are for local logs and tests; no seam may forward one to the browser,
 * which learns only that a handoff is unavailable.
 */
export class FileContainerError extends Error {
  constructor(code) {
    super(code);
    this.name = 'FileContainerError';
    this.code = code;
  }
}

function refuse(code) {
  throw new FileContainerError(code);
}

function utf8Length(value) {
  return encoder.encode(value).length;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Exact own-key match: an unknown or missing key is a malformed manifest, not
 *  a field to ignore. This is also what stops `__proto__` smuggling — it lands
 *  as an own key here and fails the comparison. */
function hasExactKeys(value, keys) {
  if (!isPlainObject(value)) return false;
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

/** `-0` is excluded so a byte count has exactly one spelling in the manifest. */
function isByteCount(value, max) {
  return Number.isSafeInteger(value) && !Object.is(value, -0) && value >= 0 && value <= max;
}

/** Truncates on a code-point boundary, so a cut name is never invalid UTF-8. */
function truncateToBytes(value, maxBytes) {
  if (utf8Length(value) <= maxBytes) return value;
  let out = '';
  let used = 0;
  for (const codePoint of value) {
    const size = utf8Length(codePoint);
    if (used + size > maxBytes) break;
    out += codePoint;
    used += size;
  }
  return out;
}

/**
 * Applies trim, basename and drive-prefix stripping until nothing changes.
 *
 * Iterating is the point rather than an optimisation: each rule can uncover
 * work for another. A directory strip on `D:\ E:report.pdf` leaves ` E:…`, so
 * the drive rule only sees a prefix after the next trim; `C:D:x` hides a second
 * drive letter behind the first. Applying each rule once — in any order — makes
 * the sanitizer non-idempotent, and a non-idempotent sanitizer is a real defect
 * here, because `decodeFileContainer` refuses any manifest name that is not
 * already canonical: the encoder would produce containers its own decoder
 * rejects, after AEAD success, identically on every retry.
 *
 * It terminates because every step only ever shortens the string.
 */
function collapseToBasename(value) {
  let previous;
  do {
    previous = value;
    value = value.trim();
    const lastSeparator = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'));
    // Whatever a separator hides — traversal, a nested path, a UNC root — is
    // discarded with the part of the string it lived in.
    if (lastSeparator >= 0) value = value.slice(lastSeparator + 1);
    // `C:report.pdf` is drive-relative on Windows, not a filename.
    value = value.replace(/^[A-Za-z]:/, '');
  } while (value !== previous);
  return value;
}

/**
 * Browser filename -> display label. Never a path: the claim side generates its
 * own storage names, so nothing here is trusted to be joined onto a directory.
 * The rules are the MVP's: NFC, basename only, no separators, no drive prefix,
 * no controls, trimmed, capped, and `unnamed` when nothing is left.
 *
 * The result is a fixed point — `sanitizeFileName(sanitizeFileName(x))` is
 * always `sanitizeFileName(x)` — and the test suite proves that over every
 * combination of the characters these rules interact through.
 */
export function sanitizeFileName(raw) {
  if (typeof raw !== 'string') return FALLBACK_FILE_NAME;

  // Invisibles come out first: a format character sitting between a base letter
  // and its combining mark blocks composition, so normalizing before the strip
  // would leave a name that normalizes further on the next pass.
  let value = raw.replace(FORMAT_AND_CONTROL, '').normalize('NFC');
  value = collapseToBasename(value);
  // Truncation is safe to do last: the string holds no separators by now, so a
  // cut cannot uncover one, and trimming the tail cannot uncover a prefix.
  value = truncateToBytes(value, MAX_FILE_NAME_BYTES).trimEnd();

  // `.` and `..` survive basename extraction and would be a lie in any list
  // that shows them; they are not names.
  if (value === '' || value === '.' || value === '..') return FALLBACK_FILE_NAME;
  return value;
}

/**
 * The MIME hint is a display convenience the browser guessed. Nothing sniffs,
 * dispatches or executes on it, so anything unusable becomes the empty string
 * rather than a refusal — and unlike a name, a type is never repaired. A hint
 * with an embedded control character has nothing worth salvaging, and dropping
 * it beats displaying a cleaned-up version of something that arrived malformed.
 */
export function sanitizeFileType(raw) {
  if (typeof raw !== 'string') return '';
  const value = raw.trim();
  if (!PRINTABLE_ASCII.test(value)) return '';
  if (utf8Length(value) > MAX_FILE_TYPE_BYTES) return '';
  return value;
}

/**
 * Validates operator-supplied limits into a frozen triple. Bad values refuse
 * rather than fall back to a default: a misconfigured cap must be visible at
 * startup, not silently generous at submit time.
 */
export function resolveFileLimits(overrides = {}) {
  if (!isPlainObject(overrides)) refuse('bad_limits');
  const limits = { ...DEFAULT_FILE_LIMITS, ...overrides };
  // An unknown key is a typo in an operator's configuration, and a typo that is
  // ignored is a cap that silently stayed at the default.
  if (Object.keys(limits).length !== Object.keys(DEFAULT_FILE_LIMITS).length) {
    refuse('bad_limits');
  }

  // A zero byte cap would admit only empty files.
  if (!Number.isSafeInteger(limits.maxFiles) || limits.maxFiles < 1) refuse('bad_limits');
  if (!isByteCount(limits.maxFileBytes, Number.MAX_SAFE_INTEGER) || limits.maxFileBytes < 1) {
    refuse('bad_limits');
  }
  if (!isByteCount(limits.maxTotalBytes, Number.MAX_SAFE_INTEGER) || limits.maxTotalBytes < 1) {
    refuse('bad_limits');
  }

  // Narrow only, and checked before the coherence rule below so that an attempt
  // to *raise* a cap is reported as exactly that. The MVP says operators may
  // lower these; raising one is not a configuration this codec supports,
  // because the manifest ceiling, the broker's live-memory budget and the
  // browser's advertised limits are all derived from the defaults. A raise has
  // to be a deliberate change to DEFAULT_FILE_LIMITS, reviewed with them.
  for (const key of Object.keys(DEFAULT_FILE_LIMITS)) {
    if (limits[key] > DEFAULT_FILE_LIMITS[key]) refuse('limits_too_high');
  }

  // A per-file cap above the total cap cannot describe anything: the total is
  // authoritative, so the pair would only mislead whoever reads the config.
  if (limits.maxFileBytes > limits.maxTotalBytes) refuse('bad_limits');

  // Belt and braces for the day DEFAULT_FILE_LIMITS moves: the pre-parse
  // manifest ceiling has to be able to hold an honest manifest for this many
  // files, or every maximal drop would fail at submit time.
  if (worstCaseManifestBytes(limits.maxFiles) > MAX_MANIFEST_BYTES) refuse('bad_limits');

  return Object.freeze(limits);
}

/**
 * A requester may ask for fewer files than the operator allows and never more.
 * A value that is not a usable count is ignored, because the caller is a model
 * tool argument: the safe reading of nonsense is "no narrowing requested".
 */
export function narrowFileLimits(limits, request = {}) {
  const base = resolveFileLimits(limits);
  const asked = isPlainObject(request) ? request.maxFiles : undefined;
  if (!Number.isSafeInteger(asked) || asked < 1) return base;
  return Object.freeze({ ...base, maxFiles: Math.min(base.maxFiles, asked) });
}

/**
 * The largest container these limits can produce. Transports size their buffers
 * and their own ceilings from this rather than guessing.
 */
export function fileContainerCeiling(limits = DEFAULT_FILE_LIMITS) {
  const resolved = resolveFileLimits(limits);
  return CONTAINER_HEADER_BYTES + MAX_MANIFEST_BYTES + resolved.maxTotalBytes;
}

/**
 * `crypto.subtle` does not exist outside a secure context, and this project can
 * be reached over plain HTTP. That failure has to arrive as a refusal like any
 * other rather than as a bare TypeError, so the module's one error type stays
 * the only thing a caller has to catch.
 */
async function sha256Hex(bytes) {
  let digest;
  try {
    digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  } catch {
    refuse('digest_unavailable');
  }
  let out = '';
  for (const byte of digest) out += byte.toString(16).padStart(2, '0');
  return out;
}

/**
 * Builds one container from `[{ name, type, bytes }]`, in the order given.
 * Names and MIME hints are sanitized here, so the manifest only ever carries
 * canonical values — which is exactly what `decodeFileContainer` re-checks.
 */
export async function encodeFileContainer(files, { limits = DEFAULT_FILE_LIMITS } = {}) {
  const resolved = resolveFileLimits(limits);
  if (!Array.isArray(files)) refuse('input_shape');
  for (const file of files) {
    if (!isPlainObject(file) || !(file.bytes instanceof Uint8Array)) refuse('input_shape');
  }

  // Empty files are allowed; an empty submission is not.
  if (files.length === 0 || files.length > resolved.maxFiles) refuse('file_count');

  let total = 0;
  for (const file of files) {
    if (file.bytes.length > resolved.maxFileBytes) refuse('file_size');
    total += file.bytes.length;
  }
  if (total > resolved.maxTotalBytes) refuse('total_size');

  let offset = 0;
  const entries = [];
  for (const file of files) {
    // Key order is fixed so the same inputs always produce the same bytes: the
    // container is what the test vectors pin, and a reordered manifest would be
    // a different container for identical files.
    entries.push({
      name: sanitizeFileName(file.name),
      size: file.bytes.length,
      offset,
      sha256: await sha256Hex(file.bytes),
      type: sanitizeFileType(file.type),
    });
    offset += file.bytes.length;
  }

  const manifest = encoder.encode(JSON.stringify({ kind: PAYLOAD_KIND_FILES, files: entries }));
  if (manifest.length > MAX_MANIFEST_BYTES) refuse('manifest_length_out_of_range');

  const container = new Uint8Array(CONTAINER_HEADER_BYTES + manifest.length + total);
  container.set(MAGIC_BYTES, 0);
  new DataView(container.buffer, container.byteOffset, container.byteLength).setUint32(
    MAGIC_BYTES.length,
    manifest.length,
    false,
  );
  container.set(manifest, CONTAINER_HEADER_BYTES);

  let cursor = CONTAINER_HEADER_BYTES + manifest.length;
  for (const file of files) {
    container.set(file.bytes, cursor);
    cursor += file.bytes.length;
  }
  return container;
}

function readManifest(bytes, limits) {
  if (bytes.length > fileContainerCeiling(limits)) refuse('container_too_large');
  if (bytes.length < CONTAINER_HEADER_BYTES) refuse('container_too_small');
  for (let index = 0; index < MAGIC_BYTES.length; index += 1) {
    if (bytes[index] !== MAGIC_BYTES[index]) refuse('bad_magic');
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const manifestLength = view.getUint32(MAGIC_BYTES.length, false);
  // Checked against the fixed ceiling *before* the buffer, so a hostile length
  // is refused without reference to how much was actually sent.
  if (manifestLength > MAX_MANIFEST_BYTES) refuse('manifest_length_out_of_range');
  const payloadStart = CONTAINER_HEADER_BYTES + manifestLength;
  if (payloadStart > bytes.length) refuse('manifest_truncated');

  let text;
  try {
    text = strictDecoder.decode(bytes.subarray(CONTAINER_HEADER_BYTES, payloadStart));
  } catch {
    refuse('manifest_not_utf8');
  }

  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch {
    refuse('manifest_not_json');
  }
  return { manifest, payloadStart };
}

function validateManifest(manifest, payloadLength, limits) {
  if (!hasExactKeys(manifest, ['kind', 'files'])) refuse('manifest_shape');
  if (manifest.kind !== PAYLOAD_KIND_FILES) refuse('manifest_shape');
  if (!Array.isArray(manifest.files)) refuse('manifest_shape');
  if (manifest.files.length === 0 || manifest.files.length > limits.maxFiles) refuse('file_count');

  let running = 0;
  const entries = [];
  for (const file of manifest.files) {
    if (!hasExactKeys(file, ['name', 'size', 'offset', 'sha256', 'type'])) refuse('manifest_shape');
    if (typeof file.name !== 'string') refuse('manifest_shape');
    if (typeof file.type !== 'string') refuse('manifest_shape');
    if (typeof file.sha256 !== 'string') refuse('manifest_shape');

    // Canonical only: the manifest must already carry what sanitization would
    // produce. Accepting a name and cleaning it up here would mean the bytes
    // that were hashed and the label that gets displayed disagree.
    if (sanitizeFileName(file.name) !== file.name) refuse('file_name');
    if (sanitizeFileType(file.type) !== file.type) refuse('file_type');
    if (!SHA256_HEX.test(file.sha256)) refuse('digest_format');
    if (!isByteCount(file.size, limits.maxFileBytes)) refuse('file_size');
    // Contiguous, ordered and non-overlapping is one check: each file starts
    // exactly where the previous one ended.
    if (!isByteCount(file.offset, limits.maxTotalBytes) || file.offset !== running) {
      refuse('offsets');
    }

    running += file.size;
    if (running > limits.maxTotalBytes) refuse('total_size');
    entries.push(file);
  }

  // ...and the files together consume the payload exactly, so no byte is
  // unaccounted for and none is claimed twice.
  if (running !== payloadLength) refuse('offsets');
  return entries;
}

/**
 * Parses and fully verifies one container. Resolves only when the magic, the
 * manifest shape, every name, every size, every offset and every SHA-256 agree
 * with the bytes actually present; otherwise it throws a `FileContainerError`.
 *
 * Ownership, which the caller must read before holding the result:
 *
 *   1. `file.bytes` are **views into `container`**, never copies. A 42 MiB
 *      payload is not duplicated to be read.
 *   2. The container therefore stays alive as long as any single view does, and
 *      so do the bytes of every *other* file in it — including ones already
 *      written out. A caller that wants one small file to outlive the drop must
 *      copy it (`new Uint8Array(file.bytes)`) and drop the container.
 *   3. Zeroizing is the container owner's job and it reaches everything:
 *      `container.fill(0)` empties every view handed out here. That matches the
 *      broker's existing pattern (`src/broker.js` wipes `record.plaintext` on
 *      retire and destroy) but it means a consumer that keeps `files` past the
 *      wipe holds zeroes, not data — copy first, or keep the container.
 *   4. The digests are verified **at this moment and no later**. A view is only
 *      as good as its buffer: anything that writes to `container` afterwards
 *      invalidates the guarantee silently. This is why the claim side must
 *      re-verify size and SHA-256 while it writes each file out, rather than
 *      treating that as a redundant second check.
 */
export async function decodeFileContainer(container, { limits = DEFAULT_FILE_LIMITS } = {}) {
  const resolved = resolveFileLimits(limits);
  if (!(container instanceof Uint8Array)) refuse('not_bytes');

  const { manifest, payloadStart } = readManifest(container, resolved);
  const entries = validateManifest(manifest, container.length - payloadStart, resolved);

  const files = [];
  for (const file of entries) {
    const start = payloadStart + file.offset;
    const bytes = container.subarray(start, start + file.size);
    // Verified before the caller can see the bytes, for every file — a claim
    // must not succeed on a payload that was altered in transit or in memory.
    if ((await sha256Hex(bytes)) !== file.sha256) refuse('hash_mismatch');
    files.push({
      name: file.name,
      type: file.type,
      size: file.size,
      offset: file.offset,
      sha256: file.sha256,
      bytes,
    });
  }

  return { kind: PAYLOAD_KIND_FILES, files, totalBytes: container.length - payloadStart };
}
