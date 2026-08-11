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
//     bytes go straight to the local admin CLI's stdout;
//   - `claim()` never consumes a payload it cannot hand over: a caller that
//     declares how much it can receive is refused *before* the retirement, so a
//     reader too small for the answer costs a refusal rather than the secret.
//
// Payload kinds (docs/FILE_TRANSFER_MVP.md, slice 2). A handoff is minted as
// `text` — one UTF-8 secret under `maxPlaintextBytes`, envelope v1, unchanged in
// every respect — or as `files`, which carries one HDROP2 container under the
// file limits and envelope v2. The kind is fixed at creation and decides three
// things that must never be decided by the submitter: which envelope version the
// broker will rebuild `info` with, which ceiling the ciphertext is measured
// against, and whether the decrypted bytes must parse as a container before the
// record may reach `submitted`.
//
// The live-file byte budget, in one place because every release has to agree
// with it:
//
//   RESERVE  `create` takes one reservation, synchronously, before its first
//            await. Refused when it does not fit, with the same uniform
//            `unavailable` as everything else.
//   HOLD     `submit` does not release. From submit onward the broker really is
//            holding those bytes, so releasing there would let the process
//            exceed the budget it enforced at create.
//   RELEASE  exactly once, at the record's first terminal event — the retirement
//            a claim performs, or `destroy` for expiry, a spent failure budget
//            and shutdown. A claimed receipt holds no payload and no reservation.
//
// The reservation is the largest plaintext the drop could ever hold — the whole
// container ceiling, header and manifest included — never the actual size, which
// is unknown until submit. Bounding the worst case is the entire point, so the
// reservation has to *be* the worst case rather than most of it.
//
// What the budget does NOT cover, stated because the number invites the opposite
// reading: it bounds *resident payload* bytes only. One submission in flight costs
// several times its payload transiently — a buffered base64 body, that body as a
// JS string, the ciphertext string `JSON.parse` produces, the decoded ciphertext
// and the plaintext — and none of that is charged here. It is bounded instead by
// admitting at most one widened body per drop (`acquireSubmitSlot`), which caps
// concurrent submission-path allocation at one in-flight upload per live file
// drop. Removing that gate would make this budget's guarantee false, not merely
// loose: the de-duplication in `submit` engages only after a body is already whole
// in memory, so nothing else on the path limits buffering.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { base64UrlToBytes, bytesToBase64Url, isBase64Url } from './base64url.js';
import {
  FILE_ENVELOPE_VERSION,
  FileContainerError,
  PAYLOAD_KIND_FILES,
  PAYLOAD_KIND_TEXT,
  decodeFileContainer,
  fileContainerCeiling,
  narrowFileLimits,
} from './file-container.js';
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

/** The payload kinds this broker speaks, advertised on `create`. */
export const PAYLOAD_KINDS = Object.freeze([PAYLOAD_KIND_TEXT, PAYLOAD_KIND_FILES]);

/**
 * Everything in one submit body that is not the base64 ciphertext: the version,
 * the suite id, the handoff id, the fingerprint and the JSON around them. ~200
 * bytes in practice; 512 is slack for a field growing later, and it only ever
 * makes the transport ceiling on a *file* drop slightly generous.
 */
const ENVELOPE_JSON_OVERHEAD_BYTES = 512;

/** Base64url of `bytes`, unpadded, rounded up — the wire length of a ciphertext. */
function base64Length(bytes) {
  return Math.ceil((bytes * 4) / 3) + 4;
}

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

  /** The operator's validated per-drop file caps; narrow-only, checked at startup. */
  const fileLimits = config.fileLimits;
  /** Sum of every live reservation. Only `reserveFileBytes`/`release` may move it. */
  let reservedFileBytes = 0;

  /**
   * Takes one reservation, or refuses. Synchronous on purpose: `create` calls it
   * before its first await, which is what makes the budget hold under concurrent
   * creations instead of being a check two callers can both pass.
   */
  function reserveFileBytes(bytes) {
    if (reservedFileBytes + bytes > config.maxLiveFileBytes) return false;
    reservedFileBytes += bytes;
    return true;
  }

  /** Idempotent by construction: the record's own reservation is zeroed as it is given back. */
  function releaseReservation(record) {
    if (!record?.reservedBytes) return;
    reservedFileBytes -= record.reservedBytes;
    record.reservedBytes = 0;
  }

  /**
   * The two numbers a drop's payload kind fixes, resolved once at creation
   * rather than on every submit: the largest plaintext it can carry, and the
   * envelope version its `info` must be built with. Both are read from the
   * record afterwards, never from the envelope.
   */
  function payloadShapeFor(payloadKind, limits) {
    if (payloadKind !== PAYLOAD_KIND_FILES) {
      return { maxPayloadBytes: config.maxPlaintextBytes, envelopeVersion: ENVELOPE_VERSION };
    }
    return {
      maxPayloadBytes: fileContainerCeiling(limits),
      envelopeVersion: FILE_ENVELOPE_VERSION,
    };
  }

  /**
   * The record a widened submit body would be read for, or `null` for everything
   * else — unknown, malformed, expired, a text drop, or a file drop that has
   * already been submitted to or claimed. `null` is what collapses the ceiling
   * back to `maxBodyBytes`, so a caller without a live pending file capability
   * learns nothing and buys no extra buffer.
   */
  function widenableRecord(capability) {
    const record = resolve(capability);
    if (!record || record.state !== 'pending' || record.payloadKind !== PAYLOAD_KIND_FILES) {
      return null;
    }
    return record;
  }

  function bodyCeilingFor(record) {
    if (record === null) return config.maxBodyBytes;
    return base64Length(record.maxPayloadBytes + AEAD_TAG_BYTES) + ENVELOPE_JSON_OVERHEAD_BYTES;
  }

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
    // The receipt that survives holds no bytes, so it holds no reservation.
    releaseReservation(record);
    notify(record, 'unavailable');
    logger.info?.(`handoff claimed hid=${record.handoffId} retained=receipt-only`);
  }

  function destroy(record, reason) {
    zeroize(record.plaintext);
    record.plaintext = null;
    record.keyPair = null;
    record.publicKeyBytes = null;
    record.state = 'destroyed';
    releaseReservation(record);
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

    const maxPayloadBytes = record.maxPayloadBytes;
    const enc = safeDecode(envelope.enc, ENC_BYTES);
    const ct = safeDecode(envelope.ct);
    const pkfp = safeDecode(envelope.pkfp, 16);
    if (!enc || !ct || !pkfp) return UNAVAILABLE;
    if (ct.length < AEAD_TAG_BYTES + 1) return UNAVAILABLE;
    if (ct.length > maxPayloadBytes + AEAD_TAG_BYTES) return UNAVAILABLE;

    const expectedFingerprint = await publicKeyFingerprint(record.publicKeyBytes);
    if (!timingSafeEqual(Buffer.from(pkfp), Buffer.from(expectedFingerprint))) {
      return UNAVAILABLE;
    }

    // The version goes into `info`, so it is bound by the AEAD rather than merely
    // declared: a v1 ciphertext relabelled `v: 2` cannot be opened as a container,
    // and a v2 container cannot be replayed at a text drop.
    const info = buildInfo({
      handoffId: record.handoffId,
      capabilityHash: record.capabilityHash,
      version: record.envelopeVersion,
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

    if (plaintext.length > maxPayloadBytes) {
      zeroize(plaintext);
      return UNAVAILABLE;
    }

    // A file drop's payload has to *be* a container before the record may reach
    // `submitted`: the whole point of validating here is that no other seam ever
    // meets an unvalidated one. What the broker keeps out of the result is as
    // deliberate as what it checks — a count and a byte total, never a filename,
    // a MIME hint or a digest, because none of those may reach a log or a public
    // status message and the claim side re-derives them from the container it is
    // handed anyway (see the ownership note in src/file-container.js).
    let fileCount = 0;
    let fileTotalBytes = 0;
    if (record.payloadKind === PAYLOAD_KIND_FILES) {
      try {
        const decoded = await decodeFileContainer(plaintext, { limits: record.fileLimits });
        fileCount = decoded.files.length;
        fileTotalBytes = decoded.totalBytes;
      } catch (error) {
        if (!(error instanceof FileContainerError)) throw error;
        zeroize(plaintext);
        // Not an AEAD failure: this sender proved it holds the capability, so it
        // is a broken client rather than a guesser, and it is charged to its own
        // counter. It is charged to *something*, though — validating a container
        // is a SHA-256 over every byte of it, and an authenticated caller must not
        // be able to buy that arbitrarily often against one drop.
        record.containerFailures += 1;
        logger.warn?.(
          `handoff container rejected hid=${record.handoffId} code=${error.code} ` +
            `count=${record.containerFailures}`,
        );
        if (record.containerFailures >= config.maxAeadFailures) destroy(record, 'container_failures');
        return UNAVAILABLE;
      }
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
    record.fileCount = fileCount;
    record.fileTotalBytes = fileTotalBytes;
    logger.info?.(
      `handoff submitted hid=${record.handoffId} kind=${record.payloadKind} ` +
        `bytes=${plaintext.length}` +
        (record.payloadKind === PAYLOAD_KIND_FILES ? ` files=${fileCount}` : ''),
    );
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

    /**
     * Seam 1: mint a handoff and return its one-time URL.
     *
     * `payloadKind` is fixed here and never revisited: it decides the envelope
     * version, the ciphertext ceiling and whether a container is required. A
     * `files` drop also reserves its advertised maximum against the process-wide
     * budget *before the first await*, so two concurrent creations cannot both
     * pass a check only one of them fits through.
     */
    async create({ ttlSeconds = config.ttlSeconds, payloadKind = PAYLOAD_KIND_TEXT, maxFiles } = {}) {
      if (!PAYLOAD_KINDS.includes(payloadKind)) return INVALID_REQUEST;
      if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > config.maxTtlSeconds) {
        return INVALID_REQUEST;
      }
      if (!baseUrl) throw new Error('broker baseUrl is not resolved yet');

      const isFiles = payloadKind === PAYLOAD_KIND_FILES;
      // A requester may narrow the file count and never raise it; nonsense is
      // read as "no narrowing asked for", which is what the codec's own resolver
      // does with a model tool's argument.
      const limits = isFiles ? narrowFileLimits(fileLimits, { maxFiles }) : null;
      const { maxPayloadBytes, envelopeVersion } = payloadShapeFor(payloadKind, limits);
      // The reservation is the ceiling the broker will actually enforce on this
      // drop's plaintext, so the two can never disagree.
      const reservedBytes = isFiles ? maxPayloadBytes : 0;
      if (isFiles && !reserveFileBytes(reservedBytes)) {
        // Not a caller mistake and not a statement about any one handoff, so it
        // gets the same uniform refusal as everything else. Nothing is minted.
        logger.warn?.(
          `handoff create refused reason=live_file_budget wanted=${reservedBytes} ` +
            `reserved=${reservedFileBytes} limit=${config.maxLiveFileBytes}`,
        );
        return UNAVAILABLE;
      }

      let record;
      try {
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
        record = {
          handoffId,
          capabilityHash: hash,
          capabilityHashHex: toHex(hash),
          keyPair,
          publicKeyBytes,
          payloadKind,
          fileLimits: limits,
          maxPayloadBytes,
          envelopeVersion,
          reservedBytes,
          bodySlotBusy: false,
          fileCount: 0,
          fileTotalBytes: 0,
          state: 'pending',
          createdAt: now,
          expiresAt: now + Math.round(ttlSeconds * 1000),
          aeadFailures: 0,
          containerFailures: 0,
          envelopeKeyHex: null,
          plaintext: null,
          inFlight: null,
          waiters: [],
        };

        byCapabilityHash.set(record.capabilityHashHex, record);
        byHandoffId.set(handoffId, record);
        logger.info?.(`handoff created hid=${handoffId} kind=${payloadKind} ttl=${ttlSeconds}s`);

        const created = {
          ok: true,
          handoff_id: handoffId,
          url: `${baseUrl}/#${capability}`,
          expires_at: record.expiresAt,
          ttl_seconds: ttlSeconds,
          payload_kind: payloadKind,
        };
        if (!isFiles) return { ...created, max_plaintext_bytes: config.maxPlaintextBytes };
        return {
          ...created,
          max_files: limits.maxFiles,
          max_file_bytes: limits.maxFileBytes,
          max_total_bytes: limits.maxTotalBytes,
        };
      } catch (error) {
        // Key generation is the only thing here that can fail, and a reservation
        // for a drop that never existed would never be released by anything.
        // Released here only if the record never made it into the indexes; once
        // it is there, `destroy` owns the release like it does for every drop.
        if (!record || !byHandoffId.has(record.handoffId)) reservedFileBytes -= reservedBytes;
        throw error;
      }
    },

    /**
     * Seam 2: non-secret metadata for a live capability.
     *
     * The limits published here are the authority the page checks against. They
     * are stated by the broker rather than assumed by the browser precisely
     * because a browser check is a courtesy: the same numbers are enforced again
     * on the way in, and the container is validated against this drop's own
     * narrowed limits, not the defaults.
     */
    metadata(capability) {
      const now = Date.now();
      const record = resolve(capability, now);
      if (!record || record.state !== 'pending') return UNAVAILABLE;
      const common = {
        ok: true,
        v: record.envelopeVersion,
        hid: record.handoffId,
        suite: SUITE_ID,
        pk: bytesToBase64Url(record.publicKeyBytes),
        payload_kind: record.payloadKind,
        expires_at: record.expiresAt,
        // The broker's own clock, so the page can render a countdown without
        // trusting the device's. Creation time is deliberately not published:
        // the page needs time *left*, and that is expiry minus a time base.
        now,
      };
      if (record.payloadKind !== PAYLOAD_KIND_FILES) {
        return { ...common, max_plaintext_bytes: config.maxPlaintextBytes };
      }
      return {
        ...common,
        max_files: record.fileLimits.maxFiles,
        max_total_bytes: record.fileLimits.maxTotalBytes,
        max_file_bytes: record.fileLimits.maxFileBytes,
      };
    },

    /**
     * The request-body ceiling for one submission, chosen by the drop the
     * capability actually names. A text drop keeps `maxBodyBytes` exactly; only a
     * live pending file drop widens it, and only to the size its own advertised
     * limits can produce. Anything unknown, expired, spent or ill-formed gets the
     * text ceiling, so a caller without a valid capability learns nothing and
     * buys no extra buffer — and a file drop's ceiling collapses back to the text
     * one the instant it stops being pending, which is what closes the widened
     * window for a drop that has already been submitted to.
     *
     * Pure: it admits nothing and takes nothing. `acquireSubmitSlot` is what a
     * request goes through; this is what tests and operators can ask.
     */
    submitBodyCeiling(capability) {
      return bodyCeilingFor(widenableRecord(capability));
    },

    /**
     * Admits one submission body for buffering and says how large it may be.
     *
     * This is the gate that makes the live-file budget's guarantee true. A widened
     * ceiling is 56 MiB, and one body of that size costs several times its own
     * length in transient allocation before `submit` ever sees it — so the *count*
     * of bodies in flight against one drop has to be bounded, and it cannot be
     * bounded by `submit`'s de-duplication, which only engages once a body is
     * already whole in memory. At most one widened body per pending file drop is
     * admitted; the rest are refused with the uniform `unavailable`.
     *
     * Synchronous from the check to the mutation, with no await between them, so
     * two concurrent uploads cannot both be admitted — the same single-use gate
     * pattern as the pending -> submitted transition.
     *
     * A text drop is not gated at all: its ceiling was always small enough to
     * buffer freely, and the concurrent-submit behaviour at that size is
     * established behaviour that the seams pin.
     *
     * `release` must be called however the request ends — completed, refused,
     * timed out, errored or aborted mid-body — or the drop is locked out of its
     * own submission for the rest of its TTL. It is idempotent.
     */
    acquireSubmitSlot(capability) {
      // Resolved once, so the record the ceiling was computed from is the record
      // the slot is taken on — no second lookup that could disagree with the first.
      const record = widenableRecord(capability);
      const ceiling = bodyCeilingFor(record);
      if (record === null) {
        return { ok: true, ceiling, widened: false, release: () => {} };
      }
      if (record.bodySlotBusy) {
        logger.warn?.(`handoff submit refused hid=${record.handoffId} reason=submit_slot_busy`);
        return { ok: false, ceiling, widened: true, release: () => {} };
      }
      record.bodySlotBusy = true;
      let released = false;
      return {
        ok: true,
        ceiling,
        widened: true,
        release: () => {
          if (released) return;
          released = true;
          record.bodySlotBusy = false;
        },
      };
    },

    /** Seam 3: accept exactly one HPKE envelope. */
    async submit(capability, envelope) {
      // Everything from here to registering the attempt is synchronous, so two
      // concurrent duplicates cannot both start decrypting.
      const record = resolve(capability);
      if (!record) return UNAVAILABLE;

      // Idempotency key over the envelope bytes, per the accepted crypto model.
      const envelopeKeyHex = isEnvelopeShapeValid(envelope, record)
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
     *
     * `maxPayloadBytes` is the caller's own capacity, translated from the
     * response-line ceiling it advertised (`src/control-server.js`). It is
     * checked here, inside the same synchronous gate as the retirement, rather
     * than by a peek-then-claim pair at that seam: both are correct today, and
     * only this one is still correct the day an `await` appears between them.
     * A payload over the ceiling is refused with the record untouched — still
     * `submitted`, still one-shot, still there for a reader that can hold it.
     */
    claim(handoffId, { maxPayloadBytes = Infinity } = {}) {
      const record = live(byHandoffId.get(handoffId), Date.now());
      if (!record || record.state !== 'submitted' || !record.plaintext) return UNAVAILABLE;
      // A container is not a secret to be base64'd into one newline-delimited
      // line, and the text claim path has no way to say so — so it says nothing,
      // the way it says nothing about everything else. The payload stays
      // `submitted` and one-shot, waiting for the framed transfer of slice 3.
      if (record.payloadKind === PAYLOAD_KIND_FILES) return UNAVAILABLE;

      if (record.plaintext.length > maxPayloadBytes) {
        logger.info?.(
          `handoff claim refused hid=${handoffId} reason=response_too_large ` +
            `bytes=${record.plaintext.length} caller_capacity=${maxPayloadBytes}`,
        );
        // The size and nothing else. The caller needs it to say what went wrong;
        // it is the same number already logged at submit.
        return { ok: false, error: 'response_too_large', payload_bytes: record.plaintext.length };
      }

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

    /**
     * The live-file budget, as numbers. Not test-only and not secret: it is a
     * count and three byte totals, with nothing in it derived from a payload, a
     * filename or a capability, so it is equally safe to log or expose to an
     * operator. `reservations` is counted from the records themselves rather than
     * from the counter, so the two can be held against each other.
     */
    fileBudget() {
      let reservations = 0;
      let reservedBytesFromRecords = 0;
      for (const record of byHandoffId.values()) {
        if (record.reservedBytes > 0) {
          reservations += 1;
          reservedBytesFromRecords += record.reservedBytes;
        }
      }
      return {
        limitBytes: config.maxLiveFileBytes,
        reservedBytes: reservedFileBytes,
        // The same total, summed over the live records instead of accumulated.
        // `availableBytes` is `limit - reserved` by construction and so can never
        // disagree with the counter; this can, which is what makes it worth
        // reporting — a missed release, a double release of unequal amounts or a
        // reservation that drifted from the ceiling all show up here and nowhere
        // else.
        reservedBytesFromRecords,
        availableBytes: config.maxLiveFileBytes - reservedFileBytes,
        reservations,
        reservationBytes: config.fileReservationBytes,
      };
    },

    /**
     * Test-only stand-in for the file claim that slice 3 will build: it performs
     * exactly the retirement a real claim performs — payload zeroized, receipt
     * kept, reservation released — and hands back a count and a byte total
     * instead of bytes. It exists so the release-on-claim edge is provable now,
     * and it is deliberately incapable of moving a payload anywhere.
     *
     * Slice 3 replaces it with `begin_file_claim` → transfer → `commit_file_claim`
     * over the control socket. Nothing outside tests may call it in the meantime.
     */
    testClaimFileDrop(handoffId) {
      const record = live(byHandoffId.get(handoffId), Date.now());
      if (!record || record.state !== 'submitted' || !record.plaintext) return UNAVAILABLE;
      if (record.payloadKind !== PAYLOAD_KIND_FILES) return UNAVAILABLE;
      const files = record.fileCount;
      const bytes = record.fileTotalBytes;
      retire(record);
      return { ok: true, handoff_id: handoffId, files, bytes };
    },

    /** Test-only introspection. Returns no plaintext and no key material. */
    testSnapshot(handoffId) {
      const record = byHandoffId.get(handoffId);
      if (!record) return null;
      return {
        state: record.state,
        payloadKind: record.payloadKind,
        hasPrivateKey: record.keyPair !== null,
        hasPlaintext: record.plaintext !== null,
        plaintextBytes: record.plaintext ? record.plaintext.length : 0,
        capabilityHashHex: record.capabilityHashHex,
        aeadFailures: record.aeadFailures,
        containerFailures: record.containerFailures,
        // A count and a byte total: the only two things the broker retains about
        // a container, and neither of them is a name.
        fileCount: record.fileCount,
        fileTotalBytes: record.fileTotalBytes,
        reservedBytes: record.reservedBytes,
        bodySlotBusy: record.bodySlotBusy,
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

/**
 * Shape only, and always against the version and ceiling the *record's own*
 * payload kind requires — never against whatever the envelope claims. A text
 * drop therefore still refuses `v: 2` here, before any crypto and without
 * spending a byte of the AEAD budget, exactly as it always did.
 */
function isEnvelopeShapeValid(envelope, { envelopeVersion, maxPayloadBytes }) {
  if (!envelope || typeof envelope !== 'object') return false;
  if (envelope.v !== envelopeVersion) return false;
  if (envelope.suite !== SUITE_ID) return false;
  if (!isBase64Url(envelope.hid, HANDOFF_ID_LENGTH)) return false;
  if (!isBase64Url(envelope.enc)) return false;
  if (!isBase64Url(envelope.ct)) return false;
  if (!isBase64Url(envelope.pkfp)) return false;
  // Reject oversized ciphertext before any crypto work.
  if (envelope.ct.length > base64Length(maxPayloadBytes + AEAD_TAG_BYTES)) return false;
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
