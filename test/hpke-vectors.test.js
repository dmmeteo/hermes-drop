// Library interoperability and `info` binding.
//
// The accepted crypto model makes this an acceptance criterion, not a nicety:
// @hpke/core states it has not been formally audited, so the substitute for
// "trust the library" is reproducing published vectors in both directions.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { describe, it } from 'node:test';

import {
  CAPABILITY_LENGTH,
  ENVELOPE_VERSION,
  HANDOFF_ID_LENGTH,
  INFO_LABEL,
  SUITE_CODE_POINTS,
  buildInfo,
  capabilityHash,
  createSuite,
  utf8,
} from '../src/hpke-suite.js';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import {
  CFRG_P256_AES256GCM,
  RFC_9180_A_3_1,
  bytesToHex,
  hexToBytes,
} from './fixtures/hpke-vectors.js';

const vectorSuites = [
  {
    vector: RFC_9180_A_3_1,
    build: () =>
      new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      }),
  },
  // The production suite, exercised through exactly the factory the broker and
  // the browser both use.
  { vector: CFRG_P256_AES256GCM, build: createSuite },
];

describe('HPKE Base single-shot interoperability', () => {
  for (const { vector, build } of vectorSuites) {
    describe(vector.label, () => {
      it('reproduces the vector ciphertext byte for byte (encrypt direction)', async () => {
        const suite = build();
        const recipientPublicKey = await suite.kem.deserializePublicKey(hexToBytes(vector.pkRm));

        // `ekm` pins the ephemeral KEM key material so the vector is
        // reproducible. It exists for test vectors only and is never used by the
        // application.
        const { enc, ct } = await suite.seal(
          { recipientPublicKey, info: hexToBytes(vector.info), ekm: hexToBytes(vector.ikmE) },
          hexToBytes(vector.encryption.pt),
          hexToBytes(vector.encryption.aad),
        );

        assert.equal(bytesToHex(new Uint8Array(enc)), vector.enc);
        assert.equal(bytesToHex(new Uint8Array(ct)), vector.encryption.ct);
      });

      it('opens the vector ciphertext (decrypt direction)', async () => {
        const suite = build();
        const recipientKey = await suite.kem.deserializePrivateKey(hexToBytes(vector.skRm));

        const plaintext = await suite.open(
          { recipientKey, enc: hexToBytes(vector.enc), info: hexToBytes(vector.info) },
          hexToBytes(vector.encryption.ct),
          hexToBytes(vector.encryption.aad),
        );

        assert.equal(bytesToHex(new Uint8Array(plaintext)), vector.encryption.pt);
      });

      it('fails the AEAD when info differs by one byte', async () => {
        const suite = build();
        const recipientKey = await suite.kem.deserializePrivateKey(hexToBytes(vector.skRm));
        const info = hexToBytes(vector.info);
        info[0] ^= 0x01;

        await assert.rejects(() =>
          suite.open(
            { recipientKey, enc: hexToBytes(vector.enc), info },
            hexToBytes(vector.encryption.ct),
            hexToBytes(vector.encryption.aad),
          ),
        );
      });

      it('uses the enc and tag sizes the RFC specifies for this suite', () => {
        assert.equal(hexToBytes(vector.enc).length, 65, 'Nenc = 65 for DHKEM(P-256)');
        assert.equal(
          hexToBytes(vector.encryption.ct).length - hexToBytes(vector.encryption.pt).length,
          16,
          'AES-GCM tag is 128 bits',
        );
      });
    });
  }

  it('pins the suite code points registered in RFC 9180 §7', () => {
    assert.deepEqual(SUITE_CODE_POINTS, { kem: 0x0010, kdf: 0x0001, aead: 0x0002 });
    assert.equal(SUITE_CODE_POINTS.kem, RFC_9180_A_3_1.kem_id);
    assert.equal(SUITE_CODE_POINTS.kdf, RFC_9180_A_3_1.kdf_id);
    assert.equal(SUITE_CODE_POINTS.aead, CFRG_P256_AES256GCM.aead_id);
  });

  it('never passes ekm from application code', async () => {
    for (const file of ['../src/client/handoff-client.js', '../src/broker.js']) {
      const source = await readFile(new URL(file, import.meta.url), 'utf8');
      assert.ok(!/\bekm\b/.test(source), `${file} must not pin ephemeral key material`);
    }
  });
});

describe('the info binding', () => {
  const handoffId = 'A'.repeat(HANDOFF_ID_LENGTH);

  it('lays out label, version, suite, handoff id and capability hash', async () => {
    const capHash = await capabilityHash('c'.repeat(CAPABILITY_LENGTH));
    const info = buildInfo({ handoffId, capabilityHash: capHash });

    const label = utf8(INFO_LABEL);
    assert.equal(info.length, label.length + 1 + 1 + 6 + HANDOFF_ID_LENGTH + 32);
    assert.deepEqual(info.subarray(0, label.length), label);
    assert.equal(info[label.length], 0x00, 'domain separator');
    assert.equal(info[label.length + 1], ENVELOPE_VERSION);

    const suiteBytes = info.subarray(label.length + 2, label.length + 8);
    assert.deepEqual([...suiteBytes], [0x00, 0x10, 0x00, 0x01, 0x00, 0x02]);
    assert.deepEqual(
      info.subarray(label.length + 8, label.length + 8 + HANDOFF_ID_LENGTH),
      utf8(handoffId),
    );
    assert.deepEqual(info.subarray(label.length + 8 + HANDOFF_ID_LENGTH), capHash);
  });

  it('binds the capability by hash, not by value', async () => {
    const capability = 'c'.repeat(CAPABILITY_LENGTH);
    const info = buildInfo({ handoffId, capabilityHash: await capabilityHash(capability) });
    assert.ok(!Buffer.from(info).toString('latin1').includes(capability));
  });

  it('changes when the version, handoff id or capability changes', async () => {
    const base = buildInfo({ handoffId, capabilityHash: await capabilityHash('a') });
    const otherVersion = buildInfo({
      handoffId,
      capabilityHash: await capabilityHash('a'),
      version: 2,
    });
    const otherHandoff = buildInfo({
      handoffId: 'B'.repeat(HANDOFF_ID_LENGTH),
      capabilityHash: await capabilityHash('a'),
    });
    const otherCapability = buildInfo({ handoffId, capabilityHash: await capabilityHash('b') });

    for (const other of [otherVersion, otherHandoff, otherCapability]) {
      assert.notDeepEqual(base, other);
    }
  });

  it('rejects a handoff id that is not fixed width', async () => {
    const capHash = await capabilityHash('a');
    assert.throws(() => buildInfo({ handoffId: 'short', capabilityHash: capHash }), TypeError);
    assert.throws(
      () => buildInfo({ handoffId, capabilityHash: new Uint8Array(16) }),
      TypeError,
    );
  });
});
