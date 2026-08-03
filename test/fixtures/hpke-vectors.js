// HPKE Base-mode test vectors, verbatim.
//
// Provenance, stated precisely because the acceptance criteria depend on it:
//
//   `RFC_9180_A_3_1` is RFC 9180 Appendix A.3.1 — mode 0, DHKEM(P-256,
//   HKDF-SHA256), HKDF-SHA256, AES-128-GCM. Copied from
//   https://www.rfc-editor.org/rfc/rfc9180.txt (accessed 2026-08-01) and
//   byte-compared against the same record in the CFRG reference
//   `test-vectors.json`. It validates the KEM and KDF halves of our suite
//   against a *published RFC* vector.
//
//   `CFRG_P256_AES256GCM` is mode 0, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256,
//   AES-256-GCM — this prototype's exact suite. RFC 9180's appendix does NOT
//   publish a vector for this combination, so this record comes from
//   https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json
//   (accessed 2026-08-01), the CFRG reference file that RFC 9180's appendix was
//   generated from. Same source, not the same standing: it is a reference
//   implementation vector, not an RFC-published one, and must not be described
//   as the latter.
//
// `aad` is non-empty in these vectors because that is what the reference file
// specifies. The application itself always uses empty aad and binds context
// through `info` (RFC 9180 §8.1); these records test the library, not the
// application's parameter choices.

export const RFC_9180_A_3_1 = Object.freeze({
  label: 'RFC 9180 Appendix A.3.1 — DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM',
  mode: 0,
  kem_id: 16,
  kdf_id: 1,
  aead_id: 1,
  info: '4f6465206f6e2061204772656369616e2055726e',
  ikmE: '4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e',
  pkRm:
    '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a' +
    '826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
  skRm: 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2',
  enc:
    '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325a' +
    'c98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
  shared_secret: 'c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8',
  key: '868c066ef58aae6dc589b6cfdd18f97e',
  base_nonce: '4e0bc5018beba4bf004cca59',
  encryption: {
    aad: '436f756e742d30',
    pt: '4265617574792069732074727574682c20747275746820626561757479',
    ct: '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434',
  },
});

export const CFRG_P256_AES256GCM = Object.freeze({
  label: 'CFRG reference — DHKEM(P-256,HKDF-SHA256)/HKDF-SHA256/AES-256-GCM (this suite)',
  mode: 0,
  kem_id: 16,
  kdf_id: 1,
  aead_id: 2,
  info: '4f6465206f6e2061204772656369616e2055726e',
  ikmE: 'a90d3417c3da9cb6c6ae19b4b5dd6cc9529a4cc24efb7ae0ace1f31887a8cd6c',
  pkRm:
    '04abc7e49a4c6b3566d77d0304addc6ed0e98512ffccf505e6a8e3eb25c68513' +
    '6f853148544876de76c0f2ef99cdc3a05ccf5ded7860c7c021238f9e2073d2356c',
  skRm: '317f915db7bc629c48fe765587897e01e282d3e8445f79f27f65d031a88082b2',
  enc:
    '04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f0' +
    '3e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0',
  shared_secret: '48893fecd82f7c3456af6a42d8f56325d21e08c10fa81299986aaff54cde7b49',
  key: 'ee16802a936d5f544771131900ee6973d0551de9e852ece2ef34bf0d5f9e1d1d',
  base_nonce: '9bc50980832a7b4b58c40161',
  encryption: {
    aad: '436f756e742d30',
    pt: '4265617574792069732074727574682c20747275746820626561757479',
    ct: '58c61a45059d0c5704560e9d88b564a8b63f1364b8d1fcb3c4c6ddc1d291742465e902cd216f8908da49f8f96f',
  },
});

export function hexToBytes(hex) {
  return Uint8Array.from(hex.match(/../g).map((byte) => parseInt(byte, 16)));
}

export function bytesToHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}
