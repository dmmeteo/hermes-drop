// Deterministic HDROP2 container vectors.
//
// Provenance, stated precisely because these are the codec's acceptance
// criteria: every byte below was derived *outside* the module under test.
// The three per-file digests come from GNU coreutils `sha256sum` over files
// written with `printf`; the manifest text is hand-written to the layout in
// `docs/FILE_TRANSFER_MVP.md`; `containerSha256`, `manifestLength` and
// `containerLength` come from a standalone Python 3 script that concatenated
// `magic || uint32be(len) || manifest || payload` and hashed the result
// (derived 2026-08-11). If `src/file-container.js` ever disagrees with these,
// the codec changed — not the vector.
//
// Contents are inert ASCII on purpose: a fixture that has to be readable in a
// diff must not carry anything that looks like a credential.

const encoder = new TextEncoder();

/** File A — 16 bytes, `printf '{"key":"value"}\n'`. */
export const FILE_A = Object.freeze({
  name: 'config.json',
  type: 'application/json',
  text: '{"key":"value"}\n',
  size: 16,
  sha256: 'cbdea9ab8317fcd1e3b3a8626c735b7dfb3a929eb927b02aeab7e7f67a511d8a',
});

/** File B — 12 bytes, `printf 'hermes drop\n'`. */
export const FILE_B = Object.freeze({
  name: 'notes.txt',
  type: 'text/plain',
  text: 'hermes drop\n',
  size: 12,
  sha256: '71f194662db5806c621c6d4499b1f76bb811ff44ac5ef48296bad3a8b6e991b8',
});

/** File C — the empty file, which the MVP allows. Its digest is the well-known
 *  SHA-256 of the empty string. */
export const FILE_C = Object.freeze({
  name: 'empty.bin',
  type: '',
  text: '',
  size: 0,
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
});

/**
 * The exact manifest JSON the encoder must emit: no whitespace, files in
 * selection order, and the key order `name, size, offset, sha256, type`.
 * Pinned as text because "deterministic" is the property being tested.
 */
export const MANIFEST_JSON =
  '{"kind":"files","files":[' +
  `{"name":"${FILE_A.name}","size":16,"offset":0,"sha256":"${FILE_A.sha256}",` +
  `"type":"${FILE_A.type}"},` +
  `{"name":"${FILE_B.name}","size":12,"offset":16,"sha256":"${FILE_B.sha256}",` +
  `"type":"${FILE_B.type}"},` +
  `{"name":"${FILE_C.name}","size":0,"offset":28,"sha256":"${FILE_C.sha256}","type":""}` +
  ']}';

export const VECTOR = Object.freeze({
  label: 'HDROP2 — three files (json, text, empty)',
  files: Object.freeze([FILE_A, FILE_B, FILE_C]),
  manifestJson: MANIFEST_JSON,
  manifestLength: 439,
  containerLength: 477,
  /** `magic(6) || uint32be(439)` */
  headerHex: '4844524f5032000001b7',
  containerSha256: '2e740321d998cc653cbe2e05235540cdb7a9066a0343b0eafd2580920a2bb4c9',
  payloadText: FILE_A.text + FILE_B.text + FILE_C.text,
});

/** The vector's input shape, ready for `encodeFileContainer`. */
export function vectorInputs() {
  return VECTOR.files.map((file) => ({
    name: file.name,
    type: file.type,
    bytes: encoder.encode(file.text),
  }));
}

/** Rebuilds the vector container from the pinned parts, without the codec. */
export function vectorContainerBytes() {
  const manifest = encoder.encode(MANIFEST_JSON);
  const payload = encoder.encode(VECTOR.payloadText);
  const out = new Uint8Array(6 + 4 + manifest.length + payload.length);
  out.set(encoder.encode('HDROP2'), 0);
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(6, manifest.length, false);
  out.set(manifest, 10);
  out.set(payload, 10 + manifest.length);
  return out;
}

/**
 * Builds a container around an arbitrary manifest string and payload, so the
 * malformed-container tests can craft inputs no honest encoder would produce.
 */
export function frameContainer(manifestText, payload = new Uint8Array(0), magic = 'HDROP2') {
  const manifest = encoder.encode(manifestText);
  const magicBytes = encoder.encode(magic);
  const out = new Uint8Array(magicBytes.length + 4 + manifest.length + payload.length);
  out.set(magicBytes, 0);
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(
    magicBytes.length,
    manifest.length,
    false,
  );
  out.set(manifest, magicBytes.length + 4);
  out.set(payload, magicBytes.length + 4 + manifest.length);
  return out;
}
