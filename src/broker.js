// In-memory handoff broker.
//
// Invariants this module owns:
//   - the capability itself is never stored, only SHA-256(capability);
//   - the per-handoff P-256 private key is non-extractable and lives only here;
//   - state transitions pending -> submitted -> claimed happen synchronously, so
//     exactly one submit and exactly one claim can win in a single Node process;
//   - a claimed handoff keeps a payload-free receipt until its TTL, so an
//     identical retry is answered idempotently instead of looking unavailable;
//   - missing, malformed, expired and consumed handoffs are indistinguishable
//     *by response content*: every failure is the same
//     `{ ok: false, error: 'unavailable' }`. This is a content invariant, not a
//     timing one — `waitForSubmission` blocks for a live pending handoff and
//     returns at once for every other state, so it deliberately leaks liveness
//     by timing. That is acceptable only because it is reachable solely through
//     the 0600 admin socket, by a caller already trusted with the plaintext,
//     and because handoff ids are public by design;
//   - nothing here logs, returns or serializes plaintext except `claim()`, whose
//     bytes go straight to the local admin CLI's stdout.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { base64UrlToBytes, bytesToBase64Url, isBase64Url } from './base64url.js';
import {
  AEAD_TAG_BYTES,
  CAPABILITY_BYTES,
  CAPABILITY_LENGTH,
  EMPTY_AAD,
  ENC_BYTES,
  ENVELOPE_VERSION,
  HANDOFF_ID_LENGTH,
  SUITE_ID,
  buildInfo,
  createSuite,
  publicKeyFingerprint,
} from './hpke-suite.js';

const UNAVAILABLE = Object.freeze({ ok: false, error: 'unavailable' });
const RECEIPT = Object.freeze({ ok: true, status: 'received' });
const INVALID_REQUEST = Object.freeze({ ok: false, error: 'invalid_request' });

function zeroize(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

// Synchronous SHA-256, byte-identical to the WebCrypto digest the browser uses in
// hpke-suite.js. Being synchronous is what lets the single-use gates below run
// without an await between check and mutation.
function sha256Sync(value) {
  return new Uint8Array(createHash('sha256').update(value).digest());
}

function sha256HexSync(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function createBroker(config, logger = console) {
  const suite = createSuite();
  /** capabilityHashHex -> record */
  const byCapabilityHash = new Map();
  /** handoffId -> record */
  const byHandoffId = new Map();
  let baseUrl = config.baseUrl;

  /** Wakes anyone blocked in `waitForSubmission`, exactly once per waiter. */
  function notify(record, outcome) {
    const waiters = record.waiters;
    record.waiters = [];
    for (const waiter of waiters) waiter(outcome);
  }

  /**
   * After a successful claim the payload and key material are gone, but the
   * record stays until its TTL so an identical retry still gets its receipt
   * instead of a misleading unavailable. What remains holds no secret: an
   * envelope digest, a capability hash and timestamps.
   */
  function retire(record) {
    // `claim` detaches the payload first, so this cannot wipe the bytes in flight
    // to the operator.
    zeroize(record.plaintext);
    record.plaintext = null;
    record.keyPair = null;
    record.publicKeyBytes = null;
    record.state = 'claimed';
    notify(record, 'unavailable');
    logger.info?.(`handoff claimed hid=${record.handoffId} retained=receipt-only`);
  }

  function destroy(record, reason) {
    zeroize(record.plaintext);
    record.plaintext = null;
    record.keyPair = null;
    record.publicKeyBytes = null;
    record.state = 'destroyed';
    byCapabilityHash.delete(record.capabilityHashHex);
    byHandoffId.delete(record.handoffId);
    notify(record, 'unavailable');
    logger.info?.(`handoff destroyed hid=${record.handoffId} reason=${reason}`);
  }

  function live(record, now) {
    if (!record) return null;
    if (now >= record.expiresAt) {
      destroy(record, 'expired');
      return null;
    }
    return record;
  }

  /**
   * Resolves a presented capability to a live record. The presented value is
   * hashed first, so the lookup never compares secret bytes; the constant-time
   * comparison below guards the retained hash itself. Synchronous by design.
   */
  function resolve(capability, now = Date.now()) {
    if (!isBase64Url(capability, CAPABILITY_LENGTH)) return null;
    const hash = sha256Sync(capability);
    const record = byCapabilityHash.get(toHex(hash));
    if (!record) return null;
    if (!timingSafeEqual(Buffer.from(hash), Buffer.from(record.capabilityHash))) return null;
    return live(record, now);
  }

  /**
   * Validates and opens one envelope for a `pending` record. Exactly one call per
   * record can be in flight, which is what makes the pending -> submitted
   * transition below a single-use gate.
   */
  async function acceptEnvelope(record, envelope, envelopeKeyHex) {
    if (envelope.hid !== record.handoffId) return UNAVAILABLE;

    const enc = safeDecode(envelope.enc, ENC_BYTES);
    const ct = safeDecode(envelope.ct);
    const pkfp = safeDecode(envelope.pkfp, 16);
    if (!enc || !ct || !pkfp) return UNAVAILABLE;
    if (ct.length < AEAD_TAG_BYTES + 1) return UNAVAILABLE;
    if (ct.length > config.maxPlaintextBytes + AEAD_TAG_BYTES) return UNAVAILABLE;

    const expectedFingerprint = await publicKeyFingerprint(record.publicKeyBytes);
    if (!timingSafeEqual(Buffer.from(pkfp), Buffer.from(expectedFingerprint))) {
      return UNAVAILABLE;
    }

    const info = buildInfo({
      handoffId: record.handoffId,
      capabilityHash: record.capabilityHash,
    });

    let plaintext;
    try {
      plaintext = new Uint8Array(
        // The full key pair is handed over on purpose: given only a private
        // CryptoKey, @hpke/core re-derives pk_R for the KEM context, and its
        // non-extractable fallback path canonicalizes the y coordinate, so it
        // recovers the wrong point for roughly half of all keys.
        await suite.open({ recipientKey: record.keyPair, enc, info }, ct, EMPTY_AAD),
      );
    } catch {
      // AEAD failure does not consume the handoff, but a bounded number of them
      // destroys it so the endpoint cannot become a retry oracle. A forged `info`
      // — right handoff id and right public key, wrong capability — lands here.
      record.aeadFailures += 1;
      logger.warn?.(`handoff aead failure hid=${record.handoffId} count=${record.aeadFailures}`);
      if (record.aeadFailures >= config.maxAeadFailures) destroy(record, 'aead_failures');
      return UNAVAILABLE;
    }

    if (plaintext.length > config.maxPlaintextBytes) {
      zeroize(plaintext);
      return UNAVAILABLE;
    }

    // Synchronous single-use gate: no await between check and mutation.
    if (record.state !== 'pending') {
      zeroize(plaintext);
      return UNAVAILABLE;
    }
    record.plaintext = plaintext;
    record.envelopeKeyHex = envelopeKeyHex;
    record.state = 'submitted';
    record.keyPair = null; // AEAD succeeded: the handoff key is done
    record.publicKeyBytes = null;
    logger.info?.(`handoff submitted hid=${record.handoffId} bytes=${plaintext.length}`);
    notify(record, 'submitted');
    return RECEIPT;
  }

  return {
    get baseUrl() {
      return baseUrl;
    },

    setBaseUrl(url) {
      baseUrl = url.replace(/\/+$/, '');
    },

    /** Seam 1: mint a handoff and return its one-time URL. */
    async create({ ttlSeconds = config.ttlSeconds } = {}) {
      if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > config.maxTtlSeconds) {
        return INVALID_REQUEST;
      }
      if (!baseUrl) throw new Error('broker baseUrl is not resolved yet');

      const handoffId = bytesToBase64Url(randomBytes(16));
      const capability = bytesToBase64Url(randomBytes(CAPABILITY_BYTES));
      const hash = sha256Sync(capability);

      const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        false, // non-extractable private key; the public half stays exportable
        ['deriveBits'],
      );
      const publicKeyBytes = new Uint8Array(
        await crypto.subtle.exportKey('raw', keyPair.publicKey),
      );

      const now = Date.now();
      const record = {
        handoffId,
        capabilityHash: hash,
        capabilityHashHex: toHex(hash),
        keyPair,
        publicKeyBytes,
        state: 'pending',
        createdAt: now,
        expiresAt: now + Math.round(ttlSeconds * 1000),
        aeadFailures: 0,
        envelopeKeyHex: null,
        plaintext: null,
        inFlight: null,
        waiters: [],
      };

      byCapabilityHash.set(record.capabilityHashHex, record);
      byHandoffId.set(handoffId, record);
      logger.info?.(`handoff created hid=${handoffId} ttl=${ttlSeconds}s`);

      return {
        ok: true,
        handoff_id: handoffId,
        url: `${baseUrl}/#${capability}`,
        expires_at: record.expiresAt,
        ttl_seconds: ttlSeconds,
        max_plaintext_bytes: config.maxPlaintextBytes,
      };
    },

    /** Seam 2: non-secret metadata for a live capability. */
    metadata(capability) {
      const now = Date.now();
      const record = resolve(capability, now);
      if (!record || record.state !== 'pending') return UNAVAILABLE;
      return {
        ok: true,
        v: ENVELOPE_VERSION,
        hid: record.handoffId,
        suite: SUITE_ID,
        pk: bytesToBase64Url(record.publicKeyBytes),
        max_plaintext_bytes: config.maxPlaintextBytes,
        expires_at: record.expiresAt,
        // The broker's own clock, so the page can render a countdown without
        // trusting the device's. Creation time is deliberately not published:
        // the page needs time *left*, and that is expiry minus a time base.
        now,
      };
    },

    /** Seam 3: accept exactly one HPKE envelope. */
    async submit(capability, envelope) {
      // Everything from here to registering the attempt is synchronous, so two
      // concurrent duplicates cannot both start decrypting.
      const record = resolve(capability);
      if (!record) return UNAVAILABLE;

      // Idempotency key over the envelope bytes, per the accepted crypto model.
      const envelopeKeyHex = isEnvelopeShapeValid(envelope, config)
        ? sha256HexSync(`${envelope.enc}.${envelope.ct}`)
        : null;

      // Idempotent replay of the winning envelope (mobile retry, double tap, lost
      // response): the same receipt for the rest of the TTL, whether the payload is
      // still waiting or has already been claimed. Never a second delivery.
      if (record.state !== 'pending') {
        if (envelopeKeyHex && record.envelopeKeyHex === envelopeKeyHex) return RECEIPT;
        return UNAVAILABLE;
      }
      if (!envelopeKeyHex) return UNAVAILABLE;

      if (record.inFlight) {
        // A duplicate that arrives mid-flight waits for the winner's outcome; a
        // different envelope is refused as usual.
        return record.inFlight.envelopeKeyHex === envelopeKeyHex
          ? record.inFlight.promise
          : UNAVAILABLE;
      }

      const attempt = acceptEnvelope(record, envelope, envelopeKeyHex);
      record.inFlight = { envelopeKeyHex, promise: attempt };
      try {
        return await attempt;
      } finally {
        if (record.inFlight?.promise === attempt) record.inFlight = null;
      }
    },

    /**
     * Lets a local operator block until the browser submits, instead of polling.
     * Resolves 'unavailable' if the handoff expires, is destroyed or the wait
     * elapses — the caller cannot tell those apart, same as every other seam.
     */
    waitForSubmission(handoffId, timeoutMs) {
      const record = live(byHandoffId.get(handoffId), Date.now());
      if (!record) return Promise.resolve('unavailable');
      if (record.state === 'submitted') return Promise.resolve('submitted');
      // Already claimed: waiting cannot make it claimable again.
      if (record.state !== 'pending') return Promise.resolve('unavailable');

      // Never wait past the handoff's own expiry: it cannot become claimable then.
      const budget = Math.max(0, Math.min(timeoutMs, record.expiresAt - Date.now() + 50));
      return new Promise((resolve) => {
        let settled = false;
        const settle = (outcome) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          // Detach on the way out. `notify` empties the list for the paths it
          // owns, but a waiter that simply ran out of time would otherwise stay
          // attached for the rest of the TTL — leaking a closure per timed-out
          // subscription and making the waiter count report subscribers that
          // have long since been answered.
          const index = record.waiters.indexOf(settle);
          if (index >= 0) record.waiters.splice(index, 1);
          resolve(outcome);
        };
        const timer = setTimeout(() => settle('unavailable'), budget);
        record.waiters.push(settle);
      });
    },

    /**
     * Seam 4: hand the plaintext to the local admin caller exactly once, then
     * retire the handoff to a payload-free receipt. Fully synchronous after the
     * lookup, so a second concurrent claim cannot observe `submitted`.
     */
    claim(handoffId) {
      const record = live(byHandoffId.get(handoffId), Date.now());
      if (!record || record.state !== 'submitted' || !record.plaintext) return UNAVAILABLE;

      const plaintext = record.plaintext;
      record.plaintext = null; // detached before retiring, so it is not zeroized
      retire(record);
      return { ok: true, handoff_id: handoffId, plaintext };
    },

    /** Expiry sweeper: drops key material and payloads as soon as a TTL lapses. */
    sweep(now = Date.now()) {
      for (const record of [...byHandoffId.values()]) {
        if (now >= record.expiresAt) destroy(record, 'expired');
      }
    },

    destroyAll() {
      for (const record of [...byHandoffId.values()]) destroy(record, 'shutdown');
    },

    /** Test-only introspection. Returns no plaintext and no key material. */
    testSnapshot(handoffId) {
      const record = byHandoffId.get(handoffId);
      if (!record) return null;
      return {
        state: record.state,
        hasPrivateKey: record.keyPair !== null,
        hasPlaintext: record.plaintext !== null,
        plaintextBytes: record.plaintext ? record.plaintext.length : 0,
        capabilityHashHex: record.capabilityHashHex,
        aeadFailures: record.aeadFailures,
        expiresAt: record.expiresAt,
        waiters: record.waiters.length,
        serialized: JSON.stringify(record, (key, value) => {
          if (key === 'plaintext') return value ? '[redacted]' : null;
          if (value instanceof Uint8Array) return toHex(value);
          if (key === 'keyPair') return value ? '[CryptoKeyPair]' : null;
          if (key === 'waiters') return value.length;
          if (key === 'inFlight') return value ? 'in-flight' : null;
          return value;
        }),
      };
    },
  };
}

function isEnvelopeShapeValid(envelope, config) {
  if (!envelope || typeof envelope !== 'object') return false;
  if (envelope.v !== ENVELOPE_VERSION) return false;
  if (envelope.suite !== SUITE_ID) return false;
  if (!isBase64Url(envelope.hid, HANDOFF_ID_LENGTH)) return false;
  if (!isBase64Url(envelope.enc)) return false;
  if (!isBase64Url(envelope.ct)) return false;
  if (!isBase64Url(envelope.pkfp)) return false;
  // Reject oversized ciphertext before any crypto work.
  const ceiling = Math.ceil(((config.maxPlaintextBytes + AEAD_TAG_BYTES) * 4) / 3) + 4;
  if (envelope.ct.length > ceiling) return false;
  return true;
}

function safeDecode(value, expectedBytes) {
  try {
    const bytes = base64UrlToBytes(value);
    if (expectedBytes !== undefined && bytes.length !== expectedBytes) return null;
    return bytes;
  } catch {
    return null;
  }
}
