// The HDROP2 encrypted-file container — slice 1 of docs/FILE_TRANSFER_MVP.md.
//
// This codec is the whole reason a file drop needs no archive parser: it is a
// magic string, a length-framed JSON manifest and concatenated bytes, validated
// strictly enough that a malformed container is a refusal rather than a parser
// bug. The tests below are the contract for that strictness, and they run
// against the same module the browser bundle and the broker will both import.
//
// Nothing here prints file bytes or crafted names into assertion output beyond
// the equality checks a round trip needs.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';

import {
  CONTAINER_HEADER_BYTES,
  CONTAINER_MAGIC,
  DEFAULT_FILE_LIMITS,
  FALLBACK_FILE_NAME,
  FILE_ENVELOPE_VERSION,
  FileContainerError,
  MANIFEST_LENGTH_BYTES,
  MAX_FILE_NAME_BYTES,
  MAX_FILE_TYPE_BYTES,
  MAX_MANIFEST_BYTES,
  MAX_PRIVATE_TEXT_BYTES,
  PAYLOAD_KIND_FILES,
  decodeFileContainer,
  encodeFileContainer,
  fileContainerCeiling,
  narrowFileLimits,
  resolveFileLimits,
  sanitizeFileName,
  sanitizeFileType,
  worstCaseManifestBytes,
} from '../src/file-container.js';
import {
  FILE_A,
  FILE_B,
  FILE_C,
  MANIFEST_JSON,
  VECTOR,
  frameContainer,
  vectorContainerBytes,
  vectorInputs,
} from './fixtures/file-container-vectors.js';

const encoder = new TextEncoder();
const utf8 = (text) => encoder.encode(text);
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const utf8Length = (text) => utf8(text).length;

/** Small limits so an over-limit test never allocates a real 42 MiB payload. */
const TINY_LIMITS = resolveFileLimits({ maxFiles: 3, maxFileBytes: 8, maxTotalBytes: 16 });

async function decodeFailure(container, options) {
  try {
    await decodeFileContainer(container, options);
  } catch (error) {
    assert.ok(error instanceof FileContainerError, 'must be a FileContainerError');
    return error;
  }
  throw new assert.AssertionError({ message: 'decode resolved but should have refused' });
}

function resolveLimitsFailure(overrides) {
  try {
    resolveFileLimits(overrides);
  } catch (error) {
    assert.ok(error instanceof FileContainerError, 'must be a FileContainerError');
    return error;
  }
  throw new assert.AssertionError({ message: 'resolveFileLimits accepted limits it must refuse' });
}

async function encodeFailure(files, options) {
  try {
    await encodeFileContainer(files, options);
  } catch (error) {
    assert.ok(error instanceof FileContainerError, 'must be a FileContainerError');
    return error;
  }
  throw new assert.AssertionError({ message: 'encode resolved but should have refused' });
}

/**
 * Every character that participates in a sanitization rule: both separators, a
 * drive letter and a second one, whitespace an operator can type, the three
 * invisible classes (C0 control, bidi format, non-breaking space), a combining
 * mark that only composes once the invisible next to it is gone, and an astral
 * code point that must never be cut in half.
 */
const ADVERSARIAL_CHARS = [
  'a',
  '.',
  '/',
  '\\',
  ':',
  'C',
  'D',
  ' ',
  '\t',
  '\u00a0', // non-breaking space: whitespace to trim, not a control
  '\u202e', // right-to-left override (Cf)
  '\u200e', // left-to-right mark (Cf)
  'e',
  '\u0301', // combining acute — composes with `e` once a Cf between them goes
  '\u{1f642}',
];

/** Every string of `length` characters over the alphabet above. */
function adversarialNames(length) {
  let names = [''];
  for (let index = 0; index < length; index += 1) {
    names = names.flatMap((prefix) => ADVERSARIAL_CHARS.map((char) => prefix + char));
  }
  return names;
}

/** A manifest built from parts, so a test can break exactly one field. */
function manifestFor(entries) {
  return JSON.stringify({ kind: 'files', files: entries });
}

function entry(overrides = {}) {
  return {
    name: 'a.txt',
    size: 2,
    offset: 0,
    sha256: sha256Hex(utf8('hi')),
    type: 'text/plain',
    ...overrides,
  };
}

describe('HDROP2 framing', () => {
  it('pins the container constants the format is named for', () => {
    assert.equal(CONTAINER_MAGIC, 'HDROP2');
    assert.equal(utf8Length(CONTAINER_MAGIC), 6);
    assert.equal(MANIFEST_LENGTH_BYTES, 4);
    assert.equal(CONTAINER_HEADER_BYTES, 10);
    assert.equal(FILE_ENVELOPE_VERSION, 2, 'envelope v2 carries the container');
    assert.equal(PAYLOAD_KIND_FILES, 'files');
  });

  it('encodes the pinned vector byte for byte', async () => {
    const container = await encodeFileContainer(vectorInputs());

    assert.equal(container.length, VECTOR.containerLength);
    assert.equal(hex(container.subarray(0, CONTAINER_HEADER_BYTES)), VECTOR.headerHex);
    assert.deepEqual(container, vectorContainerBytes());
    assert.equal(sha256Hex(container), VECTOR.containerSha256);
  });

  it('emits the manifest text the contract specifies, key order included', async () => {
    const container = await encodeFileContainer(vectorInputs());
    const view = new DataView(container.buffer, container.byteOffset, container.byteLength);
    const manifestLength = view.getUint32(6, false);

    assert.equal(manifestLength, VECTOR.manifestLength);
    const manifest = new TextDecoder('utf-8', { fatal: true }).decode(
      container.subarray(CONTAINER_HEADER_BYTES, CONTAINER_HEADER_BYTES + manifestLength),
    );
    assert.equal(manifest, MANIFEST_JSON);
  });

  it('is deterministic: the same inputs produce the same bytes', async () => {
    const first = await encodeFileContainer(vectorInputs());
    const second = await encodeFileContainer(vectorInputs());
    assert.deepEqual(first, second);
  });

  it('round-trips through decode with every manifest field intact', async () => {
    const decoded = await decodeFileContainer(await encodeFileContainer(vectorInputs()));

    assert.equal(decoded.kind, PAYLOAD_KIND_FILES);
    assert.equal(decoded.totalBytes, 28);
    assert.equal(decoded.files.length, 3);
    for (const [index, file] of decoded.files.entries()) {
      const expected = VECTOR.files[index];
      assert.equal(file.name, expected.name);
      assert.equal(file.type, expected.type);
      assert.equal(file.size, expected.size);
      assert.equal(file.sha256, expected.sha256);
      assert.equal(file.bytes.length, expected.size);
      assert.equal(sha256Hex(file.bytes), expected.sha256);
    }
    assert.deepEqual(
      decoded.files.map((file) => file.offset),
      [0, 16, 28],
    );
  });

  it('decodes a container built outside the codec', async () => {
    const decoded = await decodeFileContainer(vectorContainerBytes());
    assert.deepEqual(
      decoded.files.map((file) => file.name),
      [FILE_A.name, FILE_B.name, FILE_C.name],
    );
    assert.equal(new TextDecoder().decode(decoded.files[1].bytes), FILE_B.text);
  });

  it('keeps offsets contiguous, ordered and exactly consuming the payload', async () => {
    const inputs = [
      { name: 'one', type: '', bytes: utf8('aaaa') },
      { name: 'two', type: '', bytes: new Uint8Array(0) },
      { name: 'three', type: '', bytes: utf8('bb') },
    ];
    const decoded = await decodeFileContainer(await encodeFileContainer(inputs));

    let running = 0;
    for (const file of decoded.files) {
      assert.equal(file.offset, running);
      running += file.size;
    }
    assert.equal(running, decoded.totalBytes);
  });

  it('allows duplicate display names, because storage names are generated later', async () => {
    const inputs = [
      { name: 'report.pdf', type: '', bytes: utf8('one') },
      { name: 'report.pdf', type: '', bytes: utf8('two') },
    ];
    const decoded = await decodeFileContainer(await encodeFileContainer(inputs));
    assert.deepEqual(
      decoded.files.map((file) => file.name),
      ['report.pdf', 'report.pdf'],
    );
  });

  it('keeps the legacy file-only pinned vector unchanged', async () => {
    assert.deepEqual(await encodeFileContainer(vectorInputs()), vectorContainerBytes());
  });

  it('round-trips Unicode private text with binary and empty files', async () => {
    const text = 'пароль 🔐 e\u0301';
    const decoded = await decodeFileContainer(await encodeFileContainer([
      { name: 'binary.bin', type: 'application/octet-stream', bytes: Uint8Array.from([0, 255, 128]) },
      { name: 'empty', type: '', bytes: new Uint8Array() },
    ], { text }));
    assert.equal(decoded.text, text);
    assert.deepEqual(decoded.files.map((file) => [...file.bytes]), [[0, 255, 128], []]);
    assert.equal(decoded.totalBytes, 3);
  });

  it('rejects private text above 65536 UTF-8 bytes', async () => {
    const error = await encodeFailure([{ name: 'x', type: '', bytes: new Uint8Array() }], {
      text: 'é'.repeat(MAX_PRIVATE_TEXT_BYTES / 2 + 1),
    });
    assert.equal(error.code, 'text_size');
  });
});

/** Curated sanitization cases: `[label, browser name, canonical display name]`. */
const NAME_CASES = [
  ['strips POSIX directory components', 'etc/passwd', 'passwd'],
  ['strips traversal segments', '../../../etc/shadow', 'shadow'],
  ['strips Windows directory components', 'C:\\Users\\me\\report.pdf', 'report.pdf'],
  ['strips a bare Windows drive prefix', 'C:report.pdf', 'report.pdf'],
  // A drive prefix is only a prefix once whitespace, controls and the
  // directory part are gone, so the rule has to survive anything hiding in
  // front of it. Each of these used to leave a `X:` in the manifest.
  ['strips a drive prefix hidden behind whitespace', ' C:notes.txt', 'notes.txt'],
  ['strips a drive prefix hidden behind a control character', '\tA:x', 'x'],
  ['strips a drive prefix hidden behind a bidi override', '\u202eC:x', 'x'],
  ['strips repeated drive prefixes', 'C:D:report.pdf', 'report.pdf'],
  ['strips a drive prefix a directory strip uncovered', 'D:\\ E:report.pdf', 'report.pdf'],
  ['replaces a name that is only a directory and a drive letter', 'D:\\ a:', FALLBACK_FILE_NAME],
  ['strips a NUL byte', 'inv\u0000oice.pdf', 'invoice.pdf'],
  ['strips C0 control characters', 'note\u0007\u001b.txt', 'note.txt'],
  ['strips bidi overrides that spoof an extension', 'invoice\u202egpj.exe', 'invoicegpj.exe'],
  ['trims surrounding whitespace', '  spaced.txt \t', 'spaced.txt'],
  ['normalizes to NFC', 'cafe\u0301.txt', 'caf\u00e9.txt'],
  ['replaces an empty result', '', FALLBACK_FILE_NAME],
  ['replaces a whitespace-only result', '   ', FALLBACK_FILE_NAME],
  ['replaces a path that leaves nothing behind', 'a/b/', FALLBACK_FILE_NAME],
  ['replaces a bare dot', '.', FALLBACK_FILE_NAME],
  ['replaces a bare double dot', '..', FALLBACK_FILE_NAME],
  ['replaces a non-string', 42, FALLBACK_FILE_NAME],
  ['replaces a missing name', undefined, FALLBACK_FILE_NAME],
  ['keeps a leading dot', '.env.example', '.env.example'],
  ['keeps inner spaces', 'quarterly report.pdf', 'quarterly report.pdf'],
];

describe('filename normalization and sanitization', () => {
  for (const [label, input, expected] of NAME_CASES) {
    it(label, () => assert.equal(sanitizeFileName(input), expected));
  }

  it('is idempotent across the curated table', () => {
    for (const [, input] of NAME_CASES) {
      const once = sanitizeFileName(input);
      assert.equal(sanitizeFileName(once), once);
    }
  });

  /**
   * The curated table only proves the cases someone thought of. Sanitization is
   * a *fixed point* — `sanitize(sanitize(x)) === sanitize(x)` for every input —
   * and that is what the encoder/decoder contract rests on, because the decoder
   * refuses any manifest name that is not already canonical. Every character
   * below is one that interacts with another rule: separators, a drive letter,
   * the three kinds of invisible (control, format, non-breaking space), a
   * combining mark and an astral code point.
   */
  it('reaches a fixed point for every combination of the characters that interact', () => {
    let unstable = 0;
    for (const name of adversarialNames(3)) {
      const once = sanitizeFileName(name);
      if (sanitizeFileName(once) !== once) unstable += 1;
    }
    assert.equal(unstable, 0, 'sanitizing a sanitized name must change nothing');
  });

  it('caps display names at 255 UTF-8 bytes without splitting a code point', () => {
    const wide = sanitizeFileName('\u00e4'.repeat(200) + '.txt');
    assert.ok(utf8Length(wide) <= MAX_FILE_NAME_BYTES);
    assert.equal(utf8Length(wide), 254, 'stops on the last code point that fits');

    const astral = sanitizeFileName('\u{1f642}'.repeat(70) + '.txt');
    assert.ok(utf8Length(astral) <= MAX_FILE_NAME_BYTES);
    assert.equal([...astral].length, 63, 'whole code points only');
    assert.ok(!astral.includes('\ufffd'), 'never a replacement character');
  });

  it('measures the cap in bytes, not characters', () => {
    const ascii = sanitizeFileName('a'.repeat(300));
    assert.equal(ascii.length, MAX_FILE_NAME_BYTES);
  });

  it('sanitizes on the way into the manifest', async () => {
    const container = await encodeFileContainer([
      { name: '../../etc/pa\u0000sswd', type: '', bytes: utf8('x') },
    ]);
    const decoded = await decodeFileContainer(container);
    assert.equal(decoded.files[0].name, 'passwd');
  });
});

describe('encode → decode round trip', () => {
  /**
   * The invariant the two halves of this module owe each other: anything the
   * encoder emits, the decoder accepts. It is easy to break from the *encoder*
   * side — the decoder demands canonical names, so any name the sanitizer does
   * not fully canonicalize in one pass becomes a container that fails closed
   * after AEAD success, permanently, because the spec's retry replays identical
   * bytes. A single curated example does not cover that; the corpus does.
   */
  async function roundTrip(names) {
    const drifted = [];
    for (let index = 0; index < names.length; index += DEFAULT_FILE_LIMITS.maxFiles) {
      const batch = names.slice(index, index + DEFAULT_FILE_LIMITS.maxFiles);
      const container = await encodeFileContainer(
        batch.map((name, position) => ({ name, type: '', bytes: utf8(String(position)) })),
      );

      let decoded;
      try {
        decoded = await decodeFileContainer(container);
      } catch (error) {
        // The crafted name is deliberately not reported: the code is enough to
        // locate it, and a failure message must not carry a filename.
        drifted.push(`refused:${error.code}@${index}`);
        continue;
      }
      for (const [position, file] of decoded.files.entries()) {
        const expected = sanitizeFileName(batch[position]);
        if (file.name !== expected) drifted.push(`name@${index + position}`);
      }
    }
    return drifted;
  }

  it('accepts back every container built from the curated names', async () => {
    assert.deepEqual(await roundTrip(NAME_CASES.map(([, input]) => input)), []);
  });

  it('accepts back every container built from the adversarial corpus', async () => {
    assert.deepEqual(await roundTrip(adversarialNames(3)), []);
  });
});

describe('decoded views and the ownership they hand the caller', () => {
  async function decodeVector() {
    const container = await encodeFileContainer(vectorInputs());
    return { container, decoded: await decodeFileContainer(container) };
  }

  it('aliases the container instead of copying it', async () => {
    const { container, decoded } = await decodeVector();
    assert.equal(decoded.files[0].bytes.buffer, container.buffer);
    assert.ok(decoded.files[0].bytes.byteOffset > 0);
  });

  it('hands zeroization of the whole payload to whoever owns the container', async () => {
    const { container, decoded } = await decodeVector();
    container.fill(0);
    assert.ok(
      decoded.files.every((file) => file.bytes.every((byte) => byte === 0)),
      'wiping the container must wipe every decoded view with it',
    );
  });

  it('retains the whole container for as long as any single file is held', async () => {
    const { container, decoded } = await decodeVector();
    const smallest = decoded.files[1];
    assert.equal(smallest.bytes.buffer.byteLength, container.buffer.byteLength);
  });

  it('verifies the digest at decode time only, so later writes are not covered', async () => {
    const { container, decoded } = await decodeVector();
    const file = decoded.files[1];
    const verified = file.sha256;
    container[container.length - 1] ^= 0x01; // the last byte of that same file

    assert.equal(file.sha256, verified, 'the manifest digest does not follow the bytes');
    assert.notEqual(sha256Hex(file.bytes), verified, 'the view now disagrees with its digest');
    // Which is exactly why the claim side must re-verify while it writes.
  });
});

describe('the MIME hint', () => {
  it('passes a plain ASCII type through', () => {
    assert.equal(sanitizeFileType('application/json'), 'application/json');
  });

  it('treats anything unusable as absent rather than refusing', () => {
    assert.equal(sanitizeFileType(''), '');
    assert.equal(sanitizeFileType(undefined), '');
    assert.equal(sanitizeFileType(42), '');
    assert.equal(sanitizeFileType('text/pl\u0000ain'), '');
    assert.equal(sanitizeFileType('t'.repeat(300)), '');
    assert.equal(sanitizeFileType('  text/plain  '), 'text/plain');
  });
});

describe('limits', () => {
  it('pins the MVP defaults', () => {
    assert.deepEqual(DEFAULT_FILE_LIMITS, {
      maxFiles: 5,
      maxFileBytes: 44040192,
      maxTotalBytes: 44040192,
    });
    assert.equal(DEFAULT_FILE_LIMITS.maxTotalBytes, 42 * 1024 * 1024);
  });

  it('refuses an empty submission', async () => {
    assert.equal((await encodeFailure([])).code, 'file_count');
    assert.equal((await decodeFailure(frameContainer(manifestFor([])))).code, 'file_count');
  });

  it('refuses more files than the limit allows', async () => {
    const many = Array.from({ length: 4 }, (_, index) => ({
      name: `f${index}`,
      type: '',
      bytes: utf8('x'),
    }));
    assert.equal((await encodeFailure(many, { limits: TINY_LIMITS })).code, 'file_count');

    const container = await encodeFileContainer(many);
    assert.equal((await decodeFailure(container, { limits: TINY_LIMITS })).code, 'file_count');
  });

  it('refuses a single file over the per-file cap', async () => {
    const big = [{ name: 'big.bin', type: '', bytes: new Uint8Array(9) }];
    assert.equal((await encodeFailure(big, { limits: TINY_LIMITS })).code, 'file_size');

    const container = await encodeFileContainer(big);
    assert.equal((await decodeFailure(container, { limits: TINY_LIMITS })).code, 'file_size');
  });

  it('refuses a total over the cap even when each file fits', async () => {
    const spread = [
      { name: 'a', type: '', bytes: new Uint8Array(8) },
      { name: 'b', type: '', bytes: new Uint8Array(8) },
      { name: 'c', type: '', bytes: new Uint8Array(8) },
    ];
    assert.equal((await encodeFailure(spread, { limits: TINY_LIMITS })).code, 'total_size');

    const container = await encodeFileContainer(spread);
    assert.equal((await decodeFailure(container, { limits: TINY_LIMITS })).code, 'total_size');
  });

  it('accepts exactly the limit', async () => {
    const atLimit = [
      { name: 'a', type: '', bytes: new Uint8Array(8) },
      { name: 'b', type: '', bytes: new Uint8Array(8) },
    ];
    const decoded = await decodeFileContainer(
      await encodeFileContainer(atLimit, { limits: TINY_LIMITS }),
      { limits: TINY_LIMITS },
    );
    assert.equal(decoded.totalBytes, 16);
  });

  it('validates operator overrides instead of trusting them', () => {
    assert.equal(resolveFileLimits({ maxFiles: 1 }).maxFiles, 1);
    assert.equal(resolveFileLimits().maxTotalBytes, DEFAULT_FILE_LIMITS.maxTotalBytes);
    for (const bad of [{ maxFiles: 0 }, { maxFiles: 1.5 }, { maxFileBytes: -1 }, { maxTotalBytes: '4' }]) {
      assert.throws(() => resolveFileLimits(bad), FileContainerError);
    }
    assert.ok(Object.isFrozen(resolveFileLimits()));
  });

  it('lets an operator lower a limit and never raise one', () => {
    assert.equal(resolveFileLimits({ maxFiles: 2 }).maxFiles, 2);
    assert.equal(resolveFileLimits({ maxTotalBytes: 1024, maxFileBytes: 1024 }).maxTotalBytes, 1024);

    for (const raised of [
      { maxFiles: DEFAULT_FILE_LIMITS.maxFiles + 1 },
      { maxFiles: 1000 },
      { maxFileBytes: DEFAULT_FILE_LIMITS.maxFileBytes + 1 },
      { maxTotalBytes: DEFAULT_FILE_LIMITS.maxTotalBytes + 1 },
      { maxTotalBytes: Number.MAX_SAFE_INTEGER },
    ]) {
      assert.equal(resolveLimitsFailure(raised).code, 'limits_too_high');
    }
  });

  it('refuses a byte cap of zero, which would admit only empty files', () => {
    assert.equal(resolveLimitsFailure({ maxFileBytes: 0 }).code, 'bad_limits');
    assert.equal(resolveLimitsFailure({ maxTotalBytes: 0 }).code, 'bad_limits');
  });

  it('refuses a per-file cap above the total cap, which cannot mean anything', () => {
    assert.equal(
      resolveLimitsFailure({ maxTotalBytes: 1024 }).code,
      'bad_limits',
      'the per-file default would exceed the lowered total',
    );
    assert.equal(resolveFileLimits({ maxTotalBytes: 1024, maxFileBytes: 512 }).maxFileBytes, 512);
  });

  it('refuses an unknown limit key rather than ignoring a typo', () => {
    assert.equal(resolveLimitsFailure({ maxFileCount: 2 }).code, 'bad_limits');
  });

  it('keeps the worst-case manifest inside the manifest ceiling', () => {
    assert.equal(MAX_MANIFEST_BYTES, worstCaseManifestBytes(DEFAULT_FILE_LIMITS.maxFiles));
    assert.ok(worstCaseManifestBytes(DEFAULT_FILE_LIMITS.maxFiles) <= MAX_MANIFEST_BYTES);
  });

  it('really does fit a maximal manifest, measured rather than asserted', async () => {
    // Every field at its cap, and `"` chosen because JSON escaping doubles it —
    // this is the largest manifest five files can produce.
    const worst = Array.from({ length: DEFAULT_FILE_LIMITS.maxFiles }, () => ({
      name: '"'.repeat(MAX_FILE_NAME_BYTES),
      type: '"'.repeat(MAX_FILE_TYPE_BYTES),
      bytes: utf8('x'),
    }));
    const container = await encodeFileContainer(worst);
    const manifestLength = new DataView(
      container.buffer,
      container.byteOffset,
      container.byteLength,
    ).getUint32(6, false);

    assert.ok(
      manifestLength <= MAX_MANIFEST_BYTES,
      `maximal manifest is ${manifestLength} bytes, ceiling is ${MAX_MANIFEST_BYTES}`,
    );
    const decoded = await decodeFileContainer(container);
    assert.equal(decoded.files[0].name.length, MAX_FILE_NAME_BYTES);
  });

  it('lets a caller narrow the file count but never raise it', () => {
    const base = resolveFileLimits();
    assert.equal(narrowFileLimits(base, { maxFiles: 2 }).maxFiles, 2);
    assert.equal(narrowFileLimits(base, { maxFiles: 50 }).maxFiles, base.maxFiles);
    for (const ignored of [{}, { maxFiles: 0 }, { maxFiles: -1 }, { maxFiles: 'two' }, undefined]) {
      assert.equal(narrowFileLimits(base, ignored).maxFiles, base.maxFiles);
    }
    assert.equal(narrowFileLimits(base, { maxFiles: 2 }).maxTotalBytes, base.maxTotalBytes);
  });

  it('publishes the ceiling a transport can size a buffer from', () => {
    const limits = resolveFileLimits();
    assert.equal(
      fileContainerCeiling(limits),
      CONTAINER_HEADER_BYTES + MAX_MANIFEST_BYTES + limits.maxTotalBytes,
    );
  });

  it('refuses a container larger than the ceiling before parsing it', async () => {
    const oversized = new Uint8Array(fileContainerCeiling(TINY_LIMITS) + 1);
    oversized.set(utf8(CONTAINER_MAGIC), 0);
    assert.equal((await decodeFailure(oversized, { limits: TINY_LIMITS })).code, 'container_too_large');
  });
});

describe('malformed containers', () => {
  const payload = utf8('hi');
  const good = () => entry();

  /** A declared manifest length that no buffer of this size could hold. */
  function withDeclaredLength(length, totalBytes) {
    const out = new Uint8Array(Math.max(totalBytes, CONTAINER_HEADER_BYTES));
    out.set(utf8(CONTAINER_MAGIC), 0);
    new DataView(out.buffer).setUint32(6, length, false);
    return out;
  }

  const cases = [
    ['an empty buffer', () => new Uint8Array(0), 'container_too_small'],
    ['a header-length runt', () => new Uint8Array(CONTAINER_HEADER_BYTES - 1), 'container_too_small'],
    ['the v1 magic', () => frameContainer(manifestFor([good()]), payload, 'HDROP1'), 'bad_magic'],
    ['a lowercased magic', () => frameContainer(manifestFor([good()]), payload, 'hdrop2'), 'bad_magic'],
    ['a manifest length past the buffer', () => withDeclaredLength(4096, 64), 'manifest_truncated'],
    ['an absurd manifest length', () => withDeclaredLength(0xffffffff, 64), 'manifest_length_out_of_range'],
    ['a manifest that is not JSON', () => frameContainer('not json', payload), 'manifest_not_json'],
    ['a manifest that is a JSON array', () => frameContainer('[]', payload), 'manifest_shape'],
    ['a manifest that is JSON null', () => frameContainer('null', payload), 'manifest_shape'],
    [
      'the wrong payload kind',
      () => frameContainer(JSON.stringify({ kind: 'text', files: [good()] }), payload),
      'manifest_shape',
    ],
    [
      'an unknown top-level key',
      () => frameContainer(JSON.stringify({ kind: 'files', files: [good()], extra: 1 }), payload),
      'manifest_shape',
    ],
    [
      'a prototype-polluting key',
      () =>
        frameContainer(
          `{"kind":"files","__proto__":{"x":1},"files":[${JSON.stringify(good())}]}`,
          payload,
        ),
      'manifest_shape',
    ],
    [
      'files that is not an array',
      () => frameContainer(JSON.stringify({ kind: 'files', files: {} }), payload),
      'manifest_shape',
    ],
    ['an unknown per-file key', () => frameContainer(manifestFor([{ ...good(), extra: 1 }]), payload), 'manifest_shape'],
    [
      'a missing per-file key',
      () => {
        const { type, ...rest } = good();
        return frameContainer(manifestFor([rest]), payload);
      },
      'manifest_shape',
    ],
    ['a non-string name', () => frameContainer(manifestFor([{ ...good(), name: 7 }]), payload), 'manifest_shape'],
    ['a non-string type', () => frameContainer(manifestFor([{ ...good(), type: null }]), payload), 'manifest_shape'],
    ['a path in the manifest name', () => frameContainer(manifestFor([{ ...good(), name: '../a.txt' }]), payload), 'file_name'],
    ['an empty manifest name', () => frameContainer(manifestFor([{ ...good(), name: '' }]), payload), 'file_name'],
    [
      'a control character in the manifest name',
      () => frameContainer(manifestFor([{ ...good(), name: 'a\u0000.txt' }]), payload),
      'file_name',
    ],
    [
      'a control character in the type',
      () => frameContainer(manifestFor([{ ...good(), type: 'text/pl\u0007ain' }]), payload),
      'file_type',
    ],
    ['a fractional size', () => frameContainer(manifestFor([{ ...good(), size: 1.5 }]), payload), 'file_size'],
    ['a negative size', () => frameContainer(manifestFor([{ ...good(), size: -2 }]), payload), 'file_size'],
    ['a stringly-typed size', () => frameContainer(manifestFor([{ ...good(), size: '2' }]), payload), 'file_size'],
    ['a fractional offset', () => frameContainer(manifestFor([{ ...good(), offset: 0.5 }]), payload), 'offsets'],
    ['a negative offset', () => frameContainer(manifestFor([{ ...good(), offset: -1 }]), payload), 'offsets'],
    [
      'a gap between files',
      () =>
        frameContainer(
          manifestFor([
            entry({ name: 'a', size: 1, offset: 0, sha256: sha256Hex(utf8('h')) }),
            entry({ name: 'b', size: 1, offset: 2, sha256: sha256Hex(utf8('i')) }),
          ]),
          utf8('hxi'),
        ),
      'offsets',
    ],
    [
      'overlapping files',
      () =>
        frameContainer(
          manifestFor([
            entry({ name: 'a', size: 2, offset: 0 }),
            entry({ name: 'b', size: 2, offset: 1 }),
          ]),
          utf8('hi!'),
        ),
      'offsets',
    ],
    [
      'files out of order',
      () =>
        frameContainer(
          manifestFor([
            entry({ name: 'a', size: 1, offset: 1, sha256: sha256Hex(utf8('i')) }),
            entry({ name: 'b', size: 1, offset: 0, sha256: sha256Hex(utf8('h')) }),
          ]),
          utf8('hi'),
        ),
      'offsets',
    ],
    ['trailing payload bytes', () => frameContainer(manifestFor([good()]), utf8('hi!')), 'offsets'],
    ['a truncated payload', () => frameContainer(manifestFor([good()]), utf8('h')), 'offsets'],
    [
      'an uppercase digest',
      () => frameContainer(manifestFor([{ ...good(), sha256: sha256Hex(payload).toUpperCase() }]), payload),
      'digest_format',
    ],
    ['a short digest', () => frameContainer(manifestFor([{ ...good(), sha256: 'abc' }]), payload), 'digest_format'],
    [
      'a non-hex digest',
      () => frameContainer(manifestFor([{ ...good(), sha256: 'z'.repeat(64) }]), payload),
      'digest_format',
    ],
    [
      'a digest that does not match the bytes',
      () => frameContainer(manifestFor([{ ...good(), sha256: '0'.repeat(64) }]), payload),
      'hash_mismatch',
    ],
  ];

  for (const [label, build, code] of cases) {
    it(`refuses ${label}`, async () => {
      assert.equal((await decodeFailure(build())).code, code);
    });
  }

  it('refuses a manifest that is not valid UTF-8', async () => {
    const container = frameContainer(manifestFor([good()]), payload);
    container[CONTAINER_HEADER_BYTES + 2] = 0xff;
    assert.equal((await decodeFailure(container)).code, 'manifest_not_utf8');
  });

  it('refuses a manifest larger than the manifest ceiling', async () => {
    const filler = 'n'.repeat(MAX_MANIFEST_BYTES);
    const container = frameContainer(manifestFor([{ ...good(), name: filler }]), payload);
    assert.equal((await decodeFailure(container)).code, 'manifest_length_out_of_range');
  });

  it('refuses a header with nothing behind it', async () => {
    const header = new Uint8Array(CONTAINER_HEADER_BYTES);
    header.set(utf8(CONTAINER_MAGIC), 0);
    assert.equal((await decodeFailure(header)).code, 'manifest_not_json');
  });

  it('refuses input that is not a byte array', async () => {
    for (const bad of [null, undefined, 'HDROP2', 42, {}]) {
      assert.equal((await decodeFailure(bad)).code, 'not_bytes');
    }
  });

  it('refuses encoder input that is not a list of {name, type, bytes}', async () => {
    assert.equal((await encodeFailure(null)).code, 'input_shape');
    assert.equal((await encodeFailure([{ name: 'a', type: '', bytes: 'not bytes' }])).code, 'input_shape');
    assert.equal((await encodeFailure(['a.txt'])).code, 'input_shape');
  });
});

describe('buffer boundaries', () => {
  /** The container as a window into a larger buffer, which is what a framed
   *  transport hands over: every read must respect `byteOffset`. */
  async function embedded(padding) {
    const container = await encodeFileContainer(vectorInputs());
    const backing = new Uint8Array(padding + container.length + padding).fill(0xaa);
    backing.set(container, padding);
    return backing.subarray(padding, padding + container.length);
  }

  it('decodes a view that does not start at byte zero', async () => {
    const decoded = await decodeFileContainer(await embedded(7));
    assert.deepEqual(
      decoded.files.map((file) => file.name),
      [FILE_A.name, FILE_B.name, FILE_C.name],
    );
    assert.equal(new TextDecoder().decode(decoded.files[0].bytes), FILE_A.text);
  });

  it('reads the manifest length from the view, not from the backing buffer', async () => {
    const view = await embedded(7);
    view[view.length - 1] ^= 0x01; // still inside the view: a real digest failure
    assert.equal((await decodeFailure(view)).code, 'hash_mismatch');
  });

  it('never reads past the end of the view', async () => {
    const container = await encodeFileContainer(vectorInputs());
    const backing = new Uint8Array(container.length + 16);
    backing.set(container, 0);
    // The trailing bytes belong to the buffer, not the container: a decoder
    // that used `buffer.byteLength` would see them as payload.
    assert.equal((await decodeFailure(backing)).code, 'offsets');
  });

  it('decodes under a narrowed limit exactly as under the operator limit', async () => {
    const narrowed = narrowFileLimits(resolveFileLimits(), { maxFiles: 3 });
    const container = await encodeFileContainer(vectorInputs());
    assert.equal((await decodeFileContainer(container, { limits: narrowed })).files.length, 3);

    const tighter = narrowFileLimits(resolveFileLimits(), { maxFiles: 2 });
    assert.equal((await decodeFailure(container, { limits: tighter })).code, 'file_count');
  });
});

describe('integrity verification', () => {
  it('detects a single flipped payload byte', async () => {
    const container = await encodeFileContainer(vectorInputs());
    container[container.length - 1] ^= 0x01;
    assert.equal((await decodeFailure(container)).code, 'hash_mismatch');
  });

  it('detects bytes moved between two same-sized files', async () => {
    const container = await encodeFileContainer([
      { name: 'a', type: '', bytes: utf8('AAAA') },
      { name: 'b', type: '', bytes: utf8('BBBB') },
    ]);
    const payloadStart = container.length - 8;
    container.set(utf8('BBBBAAAA'), payloadStart);
    assert.equal((await decodeFailure(container)).code, 'hash_mismatch');
  });

  it('verifies every file, not just the first', async () => {
    const container = await encodeFileContainer([
      { name: 'a', type: '', bytes: utf8('AAAA') },
      { name: 'b', type: '', bytes: utf8('BBBB') },
    ]);
    container[container.length - 1] ^= 0x01;
    assert.equal((await decodeFailure(container)).code, 'hash_mismatch');
  });
});

describe('failure hygiene', () => {
  it('never puts a filename, a MIME hint or payload bytes in the error', async () => {
    const secretName = 'client-onboarding-2026.pdf';
    const container = frameContainer(
      manifestFor([entry({ name: secretName, type: 'application/pdf', sha256: '0'.repeat(64) })]),
      utf8('hi'),
    );
    const error = await decodeFailure(container);
    const rendered = `${error.message} ${error.stack?.split('\n')[0] ?? ''} ${String(error)}`;

    assert.equal(error.code, 'hash_mismatch');
    assert.ok(!rendered.includes(secretName));
    assert.ok(!rendered.includes('application/pdf'));
    assert.ok(!rendered.includes('hi'));
  });

  it('refuses with a container error when WebCrypto is missing', async () => {
    // An insecure context has no `crypto.subtle`, which this project supports
    // reaching (and refuses to encrypt in). The module's contract is that every
    // refusal is a FileContainerError, so a bare TypeError would be a hole the
    // seams have to catch around.
    const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true });
    try {
      const files = [{ name: 'a.txt', type: '', bytes: utf8('x') }];
      assert.equal((await encodeFailure(files)).code, 'digest_unavailable');
      assert.equal((await decodeFailure(vectorContainerBytes())).code, 'digest_unavailable');
    } finally {
      Object.defineProperty(globalThis, 'crypto', original);
    }
  });

  it('reports a stable machine-readable code, not free text', async () => {
    const error = await decodeFailure(new Uint8Array(0));
    assert.equal(error.name, 'FileContainerError');
    assert.equal(error.message, error.code);
  });
});

describe('module hygiene', () => {
  it('stays isomorphic: no node: imports, so the page bundle can ship it', async () => {
    const source = await readFile(new URL('../src/file-container.js', import.meta.url), 'utf8');
    assert.ok(!/from\s+'node:/.test(source), 'must not import node built-ins');
    assert.ok(!/require\(/.test(source), 'must stay ESM');
    assert.ok(!/\bBuffer\b/.test(source), 'Buffer does not exist in the browser');
  });

  it('adds no compression or archive dependency', async () => {
    const source = await readFile(new URL('../src/file-container.js', import.meta.url), 'utf8');
    // Comments stripped first: this checks what the module *does*, and prose
    // about ceilings is allowed to use the same words as an API.
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.ok(!/\b(zip|gzip|deflate|inflate|CompressionStream|DecompressionStream)\b/i.test(code));
    // The codec imports nothing at all, which is the strong form of "adds no
    // dependency" — and it is what keeps the module droppable into the page
    // bundle. Asserting the project's whole dependency list here instead would
    // fail on any unrelated addition, which is somebody else's test.
    assert.ok(!/^\s*import\s/m.test(source), 'the codec must stay self-contained');

    const manifest = JSON.parse(
      await readFile(new URL('../package.json', import.meta.url), 'utf8'),
    );
    const archival = /(zip|tar|gz|brotli|compress|archive|unpack)/i;
    for (const dependency of Object.keys(manifest.dependencies ?? {})) {
      assert.ok(!archival.test(dependency), `unexpected archive dependency: ${dependency}`);
    }
  });
});
