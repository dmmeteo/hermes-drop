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
//     bytes go straight to the local admin CLI's stdout, and `beginFileClaim()`,
//     which hands container views to the local streamer;
//   - `claim()` never consumes a payload it cannot hand over: a caller that
//     declares how much it can receive is refused *before* the retirement, so a
//     reader too small for the answer costs a refusal rather than the secret.
//
// The transfer lease (docs/FILE_TRANSFER_MVP.md, slice 3). A `files` payload is
// too large to hand over in one answer, so its claim is two operations with a
// stream between them, and the state machine grows the substate that makes that
// lossless:
//
//   submitted --beginFileClaim--> transferring --commitFileClaim--> claimed
//                                      |
//                                      +-- disconnect, lease timeout, failed
//                                          commit --> submitted
//
// Three rules make it lossless rather than merely two-phase:
//
//   ONE      at most one lease per handoff, taken and released inside a
//            synchronous gate, so concurrent receivers cannot both stream.
//   OWNED    the lease belongs to an `owner` token the caller supplies — the
//            control server passes its per-connection session object, so the
//            lease is the connection and there is nothing to forge. Knowing a
//            transfer id buys nothing.
//   COMMIT   the retirement happens in `commitFileClaim` and nowhere else, only
//            after the receiver has acknowledged every frame with a digest that
//            matches the manifest. Frames go out one at a time and each one has to be
//            acked before the next is written, so "the receiver has the bytes" does
//            not depend on the socket send buffer — see `ackFileClaimFrame`. Every
//            other outcome is a refusal that leaves the payload `submitted` and
//            one-shot.
//
// A lease holds its live-file reservation for its whole duration, which is why
// the lease has a bounded deadline: an abandoned transfer must not be able to
// hold a quarter of the process budget until the TTL lapses.
//
// Payload kinds (docs/FILE_TRANSFER_MVP.md, slice 2). A handoff is minted as
// `text` — one UTF-8 secret under `maxPlaintextBytes`, envelope v1, unchanged in
// every respect — or as `files`, which carries one HDROP2 container under the
// file limits and envelope v2. The kind decides three things that must never be
// decided freely by the submitter: which envelope version the broker will rebuild
// `info` with, which ceiling the ciphertext is measured against, and whether the
// decrypted bytes must parse as a container before the record may reach
// `submitted`.
//
// The universal drop (docs/UNIVERSAL_DROP_DELIVERY_PLAN.md, U1). A third kind is
// minted without that choice made — `pending(choice)` — because the sender, not
// the requester, decides in the browser:
//
//   pending(choice)
//     ├─ accepted v1 text  → submitted(text)
//     └─ accepted v2 files → submitted(files)
//
// Two rules keep that from handing the submitter the three decisions above:
//
//   DECLARE  one submission says which lane it is *before* its body is read, in a
//            non-secret request header next to the capability. The broker resolves
//            that declaration to a kind once, and every ceiling, version and
//            validation rule for that request comes from the resolution — never
//            from the envelope's own `v`, which is a claim, not an authority.
//   BIND     the resolved kind's version goes into `info`, so a declaration and a
//            ciphertext that disagree cannot open. A mismatch is refused before any
//            crypto, and neither the drop nor the AEAD budget pays for it.
//
// A universal record's kind is fixed by the winning submission, in the same
// synchronous step that stores the payload, and is immutable afterwards: from
// `submitted` onward it is indistinguishable from a drop minted that way, which is
// what lets `claim`, `beginFileClaim` and every other seam stay as they were. A
// competing submission of the other kind then reads as a declaration that
// contradicts a fixed kind, i.e. the same uniform `unavailable` as any second
// submission.
//
// The live-file byte budget, in one place because every release has to agree
// with it:
//
//   RESERVE  a drop minted as `files` takes one reservation in `create`,
//            synchronously, before its first await. Refused when it does not fit,
//            with the same uniform `unavailable` as everything else.
//   LEASE    a *universal* drop reserves nothing at creation — it may never carry
//            a file at all, and four idle text-capable links must not exhaust the
//            budget. Its reservation is taken by the `files` declaration in
//            `acquireSubmitSlot`, before a byte of the body is buffered, and it
//            converts into the reservation above in the same synchronous step that
//            fixes the kind. Every other ending — refusal, abort, deadline, expiry,
//            shutdown — gives it back.
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
  PAYLOAD_KIND_UNIVERSAL,
  decodeFileContainer,
  fileContainerCeiling,
  narrowFileLimits,
} from './file-container.js';
import { createOutboundDrops } from './outbound-drop.js';
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

/**
 * The refusal that means *nothing was consumed*. A caller may rely on that: the
 * payload is still `submitted`, still one-shot, and still claimable by the next
 * transfer. It is deliberately not `unavailable`, which a client is entitled to
 * read as "this drop is over" — recording a busy lease or a mismatched digest as a
 * spent drop would manufacture the loss the refusal just prevented.
 */
function transferFailed(reason) {
  return { ok: false, error: 'transfer_failed', reason };
}

/**
 * The least remaining TTL worth granting a lease for.
 *
 * Not an operator dial: it is a statement about what a transfer needs to be
 * *committable*, not about deployment. Below a second the frames of a maximal drop
 * cannot land, and even a small drop is a coin flip — and the cost of losing the
 * flip is the whole transfer plus the payload, because the record is destroyed at
 * expiry while the receiver is mid-stream. Refusing before any byte moves is
 * strictly better than that for every party.
 */
const MIN_TRANSFER_LEASE_MS = 1000;

/** The payload kinds this broker can mint, advertised on `create`. */
export const PAYLOAD_KINDS = Object.freeze([
  PAYLOAD_KIND_TEXT,
  PAYLOAD_KIND_FILES,
  PAYLOAD_KIND_UNIVERSAL,
]);

/**
 * The lanes one submission can declare, and the only two a universal link accepts.
 * `universal` is deliberately not among them: it is what a *link* is before a
 * sender chooses, never something a submission may claim to be.
 */
export const PAYLOAD_DECLARATIONS = Object.freeze([PAYLOAD_KIND_TEXT, PAYLOAD_KIND_FILES]);

/**
 * The request header the declaration rides in, following the capability's own
 * convention (`x-handoff-capability`) rather than inventing a second one.
 *
 * It is spelled here, next to the rules that interpret it, because the broker is
 * what *advertises* it in a universal link's metadata: a page is told the header
 * name rather than having to know it. The transport seam re-exports this
 * (src/public-server.js) and the browser bundle states the same header in its own
 * canonical casing (src/client/handoff-client.js), the way it already does for the
 * capability. All three are held together by test/universal-drop.test.js.
 *
 * What it carries is the whole reason it is safe: one of two fixed words, chosen by
 * the sender, revealing text-versus-files to a broker that is about to receive the
 * payload anyway. No name, size, MIME hint, count or digest is in it, and nothing
 * secret can be: it is written before the body it describes.
 */
export const PAYLOAD_DECLARATION_HEADER = 'x-handoff-payload';

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

  /**
   * Outbound drops (docs/OUTBOUND_SECRET_DROP_MVP.md) live in their own store, with
   * their own records, ids, capabilities and lifecycle — nothing above is reused,
   * because an outbound drop holds ciphertext the broker cannot read and never holds
   * the key material or the state machine a handoff does. What is shared is exactly
   * the two things an operator and a shutdown must not have to know about twice:
   * `sweep` and `destroyAll` reach both stores, so a lapsed outbound payload is
   * destroyed by the same timer that destroys a lapsed handoff and a shutdown
   * destroys both.
   */
  const outbound = createOutboundDrops(config, logger);

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
   * The two numbers a payload kind fixes: the largest plaintext it can carry, and
   * the envelope version its `info` must be built with. Resolved at creation for a
   * drop minted `text` or `files`, and once per submission for a universal one —
   * from the declared lane, never from the envelope.
   *
   * `universal` has neither number, on purpose: a record that answered here with a
   * default would be a record whose ceiling a submitter could pick by silence.
   */
  function payloadShapeFor(payloadKind, limits) {
    if (payloadKind === PAYLOAD_KIND_FILES) {
      return {
        maxPayloadBytes: fileContainerCeiling(limits),
        envelopeVersion: FILE_ENVELOPE_VERSION,
      };
    }
    if (payloadKind === PAYLOAD_KIND_TEXT) {
      return { maxPayloadBytes: config.maxPlaintextBytes, envelopeVersion: ENVELOPE_VERSION };
    }
    return { maxPayloadBytes: null, envelopeVersion: null };
  }

  /**
   * The live *pending* record a capability names, or `null` for everything else —
   * unknown, malformed, expired, submitted or claimed. `null` is what collapses
   * every ceiling below back to `maxBodyBytes`, so a caller without a live pending
   * capability learns nothing and buys no extra buffer.
   */
  function pendingRecord(capability) {
    const record = resolve(capability);
    if (!record || record.state !== 'pending') return null;
    return record;
  }

  /** A live record that may legitimately need the widened file retry ceiling. */
  function fileSubmitRecord(capability, declaration) {
    const record = resolve(capability);
    if (!record) return null;
    if (record.state === 'pending') return record;
    if (
      record.state === 'submitted' &&
      record.payloadKind === PAYLOAD_KIND_FILES &&
      declaration === PAYLOAD_KIND_FILES
    ) return record;
    return null;
  }

  /** Canonical full retry identity, including the resolved declaration. */
  function envelopeIdentity(envelope, declaration) {
    return sha256HexSync(
      JSON.stringify([
        envelope.v,
        envelope.hid,
        envelope.pkfp,
        envelope.enc,
        envelope.ct,
        declaration,
      ]),
    );
  }

  /**
   * The lane one submission is being made as, or `null` for a refusal.
   *
   * Three cases, and the middle one is the whole point of the slice:
   *
   *   - a drop minted `text` or `files` has its lane already. A declaration that
   *     agrees is accepted, silence is accepted, and a declaration that
   *     *contradicts* it is refused — never ignored, because a sender that declared
   *     one lane and had the other applied would have been misheard about the only
   *     thing it was asked;
   *   - a universal drop takes the declaration. `text` and `files` are the two
   *     lanes; anything else is a refusal;
   *   - a universal drop with no declaration reads as `text`. That is the
   *     documented compatibility window for a client from before the declaration,
   *     and it is safe in the one direction that matters: silence buys the small
   *     ceiling, no reservation and envelope v1, so an undeclared container is a
   *     version mismatch rather than an admission.
   *
   * The lane of a *universal* link is read from `mintedKind`, not from the kind its
   * winning submission fixed, so silence means the same thing for the whole life of
   * that link: an undeclared retry of a container is refused after the container
   * won exactly as it was before. A rule whose meaning changed with the record's
   * state would be one nobody could audit from the header alone.
   */
  function resolveSubmitKind(record, declaration) {
    if (declaration !== undefined && declaration !== null) {
      if (!PAYLOAD_DECLARATIONS.includes(declaration)) return null;
    }
    if (record.mintedKind === PAYLOAD_KIND_UNIVERSAL) {
      return declaration ?? PAYLOAD_KIND_TEXT;
    }
    if (declaration && declaration !== record.payloadKind) return null;
    return record.payloadKind;
  }

  /** The widened body ceiling for one file submission against this record's limits. */
  function fileBodyCeiling(record) {
    const ceiling = fileContainerCeiling(record.fileLimits);
    return base64Length(ceiling + AEAD_TAG_BYTES) + ENVELOPE_JSON_OVERHEAD_BYTES;
  }

  /**
   * Reserves the file budget for one submission that has not been read yet, or
   * refuses. Synchronous like `reserveFileBytes` and for the same reason.
   *
   * A drop minted `files` already reserved at creation, so its lease holds nothing
   * and releases nothing — the reservation there belongs to the record from the
   * moment it exists. Only a universal drop's file lane borrows.
   */
  function takeFileSubmitLease(record) {
    // One lease per record, structurally. `bodySlotBusy` already admits one file
    // body at a time and is the refusal a caller sees; this is what makes a second
    // lease impossible rather than merely unreachable.
    if (record.submitLease) return null;
    if (record.reservedBytes > 0) return { bytes: 0, held: false };
    const bytes = fileContainerCeiling(record.fileLimits);
    if (!reserveFileBytes(bytes)) return null;
    const lease = { bytes, held: true };
    record.submitLease = lease;
    record.reservedBytes = bytes;
    return lease;
  }

  /**
   * Gives one submit lease back. Idempotent, and it cannot release a lease that is
   * no longer the record's — a converted lease (the submission won) or one a
   * `destroy` already took back both land here and do nothing.
   */
  function releaseFileSubmitLease(record, lease) {
    if (!lease?.held || record.submitLease !== lease) return;
    record.submitLease = null;
    releaseReservation(record);
  }

  /**
   * Ends a transfer lease, whatever ended it, and puts the record back where it
   * was. The only place `transferring` is left, and idempotent by construction:
   * the lease is detached before anything else happens, so a timeout that fires
   * while a commit is already running finds nothing to release.
   *
   * `reason` is a fixed vocabulary and never carries a name, a digest or a
   * capability, because it is logged.
   *
   * `notifyHolder` is the difference between the two kinds of ending. A lease that
   * the holder itself ended — a commit, a refused commit, an explicit abandon — is
   * released quietly, because the holder is mid-answer and telling it to drop its
   * connection would take the answer with it. A lease ended *under* the holder —
   * the deadline, an expiry, a shutdown — has to reach it, or it would keep
   * streaming views into a record that no longer owns those bytes.
   */
  function clearLease(record, reason, notifyHolder = false) {
    const lease = record?.transfer;
    if (!lease) return null;
    record.transfer = null;
    clearTimeout(lease.timer);
    if (record.state === 'transferring') record.state = 'submitted';
    logger.info?.(
      `handoff transfer ended hid=${record.handoffId} reason=${reason} ` +
        `acked=${lease.ackedBytes}/${lease.totalBytes}`,
    );
    if (notifyHolder) {
      try {
        lease.onLeaseLost?.(reason);
      } catch (error) {
        // A throwing callback is the holder's problem and must not take the
        // release — or the destroy that is probably calling it — down with it.
        logger.warn?.(`handoff transfer notify failed hid=${record.handoffId}: ${error.message}`);
      }
    }
    return lease;
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
    // A commit clears its own lease before retiring, so this only ever fires for
    // a lease nothing is holding any more. It is here so that "claimed" cannot
    // coexist with a live transfer under any future caller either.
    clearLease(record, 'claimed');
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
    // ORDER IS LOAD-BEARING — do not move the wipe above this line.
    //
    // A lease holder is streaming *views into* `record.plaintext` (see
    // `beginFileClaim`), and `socket.write` holds a reference to the view rather
    // than a copy of it. Releasing the lease first tells the holder to stop and
    // destroys its connection, which discards whatever is still queued; zeroizing
    // first would instead turn queued frames into zeros on the wire. Even that fails
    // safe — the receiver's digests would not match and the commit would be refused
    // — but it would spend a whole transfer to arrive there, and a partially drained
    // frame can still be zeroized mid-flight regardless, which is why the digest
    // check is the backstop and this ordering is the intent.
    clearLease(record, 'handoff_destroyed', true);
    zeroize(record.plaintext);
    record.plaintext = null;
    record.keyPair = null;
    record.publicKeyBytes = null;
    record.state = 'destroyed';
    releaseReservation(record);
    // A submit lease is a reservation too, and the release above took it back. The
    // request that holds it is told nothing — it will find its body refused like any
    // other submission to a record that is gone — so the pointer is dropped here to
    // keep "holds a lease" and "holds bytes" from disagreeing for a destroyed record.
    record.submitLease = null;
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
  async function acceptEnvelope(record, envelope, envelopeKeyHex, submission) {
    if (envelope.hid !== record.handoffId) return UNAVAILABLE;

    const { kind, maxPayloadBytes, envelopeVersion } = submission;
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
      version: envelopeVersion,
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
    if (kind === PAYLOAD_KIND_FILES) {
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
    if (kind === PAYLOAD_KIND_FILES) {
      if (record.reservedBytes === 0) {
        // No pre-body lease was taken, so this is an in-process caller that went
        // straight to `submit` rather than through `acquireSubmitSlot`. The budget
        // still has to hold, so the reservation happens here — late, but inside the
        // same gate and still before the record holds a single payload byte.
        if (!reserveFileBytes(maxPayloadBytes)) {
          zeroize(plaintext);
          logger.warn?.(
            `handoff submit refused hid=${record.handoffId} reason=live_file_budget ` +
              `wanted=${maxPayloadBytes} limit=${config.maxLiveFileBytes}`,
          );
          return UNAVAILABLE;
        }
        record.reservedBytes = maxPayloadBytes;
      }
      // The lease converts here and only here: from this line the reserved bytes are
      // the record's own, released by the retirement or by `destroy` like every other
      // drop's, and whichever request held the lease has nothing left to give back.
      record.submitLease = null;
    }
    // A *text* winner deliberately converts nothing. The two lanes race, so a file
    // body can be admitted and holding its reservation when the secret lands — and
    // that reservation belongs to the upload that is now being refused, not to the
    // record. Taking it over here would leave a text drop holding 42 MiB of file
    // budget for the rest of its TTL, for a payload it does not have; leaving it
    // alone lets the refused request's `release` give it straight back.

    // The choice is made, and it is made once. Everything downstream — the claim
    // seam, the transfer lease, the ceiling a retry is measured against — reads the
    // kind from the record, so a universal drop stops being universal right here.
    record.payloadKind = kind;
    record.maxPayloadBytes = maxPayloadBytes;
    record.envelopeVersion = envelopeVersion;
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
     * `payloadKind` decides the envelope version, the ciphertext ceiling and
     * whether a container is required. `text` and `files` fix all three here and
     * never revisit them; `universal` mints the link without the choice made and
     * resolves them once per submission from the sender's declaration.
     *
     * A `files` drop reserves its advertised maximum against the process-wide
     * budget *before the first await*, so two concurrent creations cannot both pass
     * a check only one of them fits through. A universal drop reserves nothing: it
     * may never carry a file at all, and pre-reserving would let four idle
     * text-capable links exhaust a budget for bytes nobody sent.
     */
    async create({ ttlSeconds = config.ttlSeconds, payloadKind = PAYLOAD_KIND_TEXT, maxFiles } = {}) {
      if (!PAYLOAD_KINDS.includes(payloadKind)) return INVALID_REQUEST;
      if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > config.maxTtlSeconds) {
        return INVALID_REQUEST;
      }
      if (!baseUrl) throw new Error('broker baseUrl is not resolved yet');

      const isFiles = payloadKind === PAYLOAD_KIND_FILES;
      const isUniversal = payloadKind === PAYLOAD_KIND_UNIVERSAL;
      // A requester may narrow the file count and never raise it; nonsense is
      // read as "no narrowing asked for", which is what the codec's own resolver
      // does with a model tool's argument. A universal link carries the file limits
      // too: they are half of what its metadata advertises, and the ceiling its file
      // lane is measured against.
      const limits = isFiles || isUniversal ? narrowFileLimits(fileLimits, { maxFiles }) : null;
      const { maxPayloadBytes, envelopeVersion } = payloadShapeFor(payloadKind, limits);
      // The reservation is the ceiling the broker will actually enforce on this
      // drop's plaintext, so the two can never disagree. A universal drop has no
      // such ceiling yet, and reserves when its file lane is declared.
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
          /**
           * The kind this drop was *minted* as, which `payloadKind` stops being the
           * moment a universal drop's submission fixes one. Retained because how a
           * link reads an absent declaration is a fact about the link, not about
           * whether it has been submitted to yet.
           */
          mintedKind: payloadKind,
          fileLimits: limits,
          maxPayloadBytes,
          envelopeVersion,
          reservedBytes,
          /**
           * The provisional reservation one in-flight file submission holds, or
           * null. Only a universal drop ever has one, and it stops being
           * provisional — without moving a byte of the counter — the moment that
           * submission wins.
           */
          submitLease: null,
          bodySlotBusy: false,
          /** The one live transfer lease, or null. See `clearLease` above. */
          transfer: null,
          /** Leases granted without a commit. Bounded by `maxTransferAttempts`. */
          transferAttempts: 0,
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
        const fileCaps = isFiles || isUniversal
          ? {
              max_files: limits.maxFiles,
              max_file_bytes: limits.maxFileBytes,
              max_total_bytes: limits.maxTotalBytes,
            }
          : {};
        // A universal link quotes both caps, because the requester chose neither
        // lane and may not be told about only one of them. A typed drop quotes only
        // its own: the secret cap says nothing about a container, and the file caps
        // say nothing about a secret.
        if (isFiles) return { ...created, ...fileCaps };
        return { ...created, max_plaintext_bytes: config.maxPlaintextBytes, ...fileCaps };
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
        // The version a submission must seal with when it declares nothing. For a
        // typed drop that is the drop's only version; for a universal one it is the
        // text lane, which is exactly what silence resolves to.
        v: record.envelopeVersion ?? ENVELOPE_VERSION,
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
      if (record.payloadKind === PAYLOAD_KIND_TEXT) {
        return { ...common, max_plaintext_bytes: config.maxPlaintextBytes };
      }
      const fileCaps = {
        max_files: record.fileLimits.maxFiles,
        max_total_bytes: record.fileLimits.maxTotalBytes,
        max_file_bytes: record.fileLimits.maxFileBytes,
      };
      if (record.payloadKind === PAYLOAD_KIND_FILES) return { ...common, ...fileCaps };

      // A universal link: one response, both lanes, and the three facts a page
      // cannot be asked to infer — which lanes it may choose between, which version
      // each lane must be sealed with, and the header the choice travels in. A page
      // that guessed any of them would be guessing at what the AEAD binds.
      return {
        ...common,
        accepts: [...PAYLOAD_DECLARATIONS],
        envelope_versions: { text: ENVELOPE_VERSION, files: FILE_ENVELOPE_VERSION },
        payload_declaration: PAYLOAD_DECLARATION_HEADER,
        max_plaintext_bytes: config.maxPlaintextBytes,
        ...fileCaps,
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
    submitBodyCeiling(capability, { declaration } = {}) {
      const record = pendingRecord(capability);
      if (record === null) return config.maxBodyBytes;
      // A declaration this record cannot honour gets the text ceiling rather than a
      // refusal: this function is pure and has no refusal channel. The refusal is
      // `acquireSubmitSlot`'s, which is what a request actually goes through.
      if (resolveSubmitKind(record, declaration) !== PAYLOAD_KIND_FILES) {
        return config.maxBodyBytes;
      }
      return fileBodyCeiling(record);
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
    acquireSubmitSlot(capability, { declaration } = {}) {
      // Resolved once, so the record the ceiling was computed from is the record
      // the slot is taken on — no second lookup that could disagree with the first.
      const record = fileSubmitRecord(capability, declaration);
      const textCeiling = config.maxBodyBytes;
      if (record === null) {
        return { ok: true, ceiling: textCeiling, widened: false, release: () => {} };
      }

      // The lane, before a byte is read. A declaration this drop cannot honour is
      // refused here rather than at the far end of a 56 MiB upload — and refused
      // with the uniform `unavailable`, having consumed nothing.
      const kind = resolveSubmitKind(record, declaration);
      if (kind === null) {
        logger.warn?.(
          `handoff submit refused hid=${record.handoffId} reason=payload_declaration_refused`,
        );
        return { ok: false, ceiling: textCeiling, widened: false, release: () => {} };
      }
      if (kind !== PAYLOAD_KIND_FILES) {
        // The text lane, gated by nothing, exactly as text always was: its ceiling
        // was always small enough to buffer freely and the seam-3 concurrency
        // behaviour depends on the losers reaching the broker.
        return { ok: true, ceiling: textCeiling, widened: false, release: () => {} };
      }

      const ceiling = fileBodyCeiling(record);
      if (record.bodySlotBusy) {
        logger.warn?.(`handoff submit refused hid=${record.handoffId} reason=submit_slot_busy`);
        return { ok: false, ceiling, widened: true, release: () => {} };
      }
      // Checked after the busy gate, so a refused admission never reserves and then
      // gives back. A universal drop borrows here; a drop minted `files` reserved at
      // creation and its lease holds nothing.
      // A submitted file record already owns its payload reservation. Its exact
      // retry needs only this bounded body slot, never a second reservation.
      const lease =
        record.state === 'submitted'
          ? { bytes: 0, held: false }
          : takeFileSubmitLease(record);
      if (lease === null) {
        logger.warn?.(
          `handoff submit refused hid=${record.handoffId} reason=live_file_budget ` +
            `wanted=${fileContainerCeiling(record.fileLimits)} reserved=${reservedFileBytes} ` +
            `limit=${config.maxLiveFileBytes}`,
        );
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
          // A no-op once the submission won and the lease became the record's own
          // reservation, and a no-op again if a destroy took it back first.
          releaseFileSubmitLease(record, lease);
        },
      };
    },

    /**
     * Seam 3: accept exactly one HPKE envelope.
     *
     * `declaration` is the sender's pre-body choice of lane, and it decides the
     * version `info` is rebuilt with and the ceiling the ciphertext is measured
     * against. It is resolved against the record's own kind first, so it can only
     * ever *choose* where a universal drop left a choice — never override a kind
     * that is already fixed. A declaration that contradicts one is the uniform
     * refusal, before any crypto and without touching the AEAD budget.
     */
    async submit(capability, envelope, { declaration } = {}) {
      // Everything from here to registering the attempt is synchronous, so two
      // concurrent duplicates cannot both start decrypting.
      const record = resolve(capability);
      if (!record) return UNAVAILABLE;

      const kind = resolveSubmitKind(record, declaration);
      if (kind === null) return UNAVAILABLE;
      const shape = payloadShapeFor(kind, record.fileLimits);
      const submission = { kind, ...shape };

      // Idempotency key over the envelope bytes, per the accepted crypto model.
      // Measured against the *declared* lane's version and ceiling, which is what
      // makes an exact retry have to carry its declaration too: the same bytes with
      // the other declaration are not a shape this drop can be submitted to, so
      // they are refused rather than answered with a receipt.
      const envelopeKeyHex = isEnvelopeShapeValid(envelope, shape)
        ? envelopeIdentity(envelope, kind)
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

      const attempt = acceptEnvelope(record, envelope, envelopeKeyHex, submission);
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
      // `transferring` answers `submitted` because that is what it is: a payload
      // that arrived and has not been consumed. The substate is an internal fact
      // about who is currently reading it, and a subscriber whose whole question
      // is "has the browser sent it yet" must not be given a third answer to
      // handle — least of all one that could be mistaken for a terminal state.
      if (record.state === 'submitted' || record.state === 'transferring') {
        return Promise.resolve('submitted');
      }
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

    /**
     * Seam 1, outbound: mint an encrypted outbound drop and return its link, its
     * code and nothing else (docs/OUTBOUND_SECRET_DROP_MVP.md).
     *
     * `plaintext` is a buffer this call consumes and wipes. The store encrypts it
     * before storing anything and keeps neither the key nor the code — see the
     * module header in src/outbound-drop.js for what that buys and what it does not.
     */
    createOutboundDrop({ plaintext, ttlSeconds } = {}) {
      if (!baseUrl) throw new Error('broker baseUrl is not resolved yet');
      return outbound.create({
        plaintext,
        ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
        baseUrl,
      });
    },

    /**
     * Seam 2, outbound: non-secret status for a live outbound capability. Holds
     * nothing open and consumes nothing — a page may fetch it as often as it likes.
     */
    outboundMetadata(capability) {
      return outbound.metadata(capability);
    },

    /**
     * Seam 3, outbound: the code gate and the one claimant reservation. The only
     * operation that can hand out ciphertext, and the only one that spends an attempt.
     */
    claimOutboundDrop(capability, options) {
      return outbound.claim(capability, options);
    },

    /** Seam 4, outbound: the acknowledgement that destroys the payload. */
    acknowledgeOutboundDrop(capability, options) {
      return outbound.acknowledge(capability, options);
    },

    /** Expiry sweeper: drops key material and payloads as soon as a TTL lapses. */
    sweep(now = Date.now()) {
      for (const record of [...byHandoffId.values()]) {
        if (now >= record.expiresAt) destroy(record, 'expired');
      }
      // Both directions on one timer. An outbound drop has a second deadline the
      // sweeper has to reach — the bounded ack window — and the store enforces it
      // here as well as lazily, for the same reason a TTL is enforced twice.
      outbound.sweep(now);
    },

    destroyAll() {
      for (const record of [...byHandoffId.values()]) destroy(record, 'shutdown');
      outbound.destroyAll();
    },

    /** Test-only introspection for an outbound drop. No ciphertext, key or code. */
    testOutboundSnapshot(dropId) {
      return outbound.testSnapshot(dropId);
    },

    /** Test-only: move an outbound drop's deadline, like `testSetExpiry` does inbound. */
    testSetOutboundExpiry(dropId, expiresAt) {
      return outbound.testSetExpiry(dropId, expiresAt);
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
      let submitLeases = 0;
      let leasedBytes = 0;
      for (const record of byHandoffId.values()) {
        if (record.reservedBytes > 0) {
          reservations += 1;
          reservedBytesFromRecords += record.reservedBytes;
        }
        if (record.submitLease?.held) {
          submitLeases += 1;
          leasedBytes += record.submitLease.bytes;
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
        // How much of `reservedBytes` is still an unread body's rather than a
        // payload the broker is really holding — a subset of the reservations above,
        // not an addition to them. It is the one thing the totals cannot show on
        // their own, and it is what tells an operator whether the budget is full of
        // drops or full of uploads that never arrived.
        submitLeases,
        leasedBytes,
        reservationBytes: config.fileReservationBytes,
      };
    },

    /**
     * Seam 4b, phase 1: take the one transfer lease on a submitted `files` drop
     * and hand the streamer what it needs to write.
     *
     * It consumes nothing. What comes back is a manifest and a set of **views into
     * the container** — never copies, so a 42 MiB claim costs no second 42 MiB,
     * which is what makes the live-file budget's number mean what it says. The
     * views are only as good as the record that owns them: `clearLease` tells the
     * holder the instant that stops being true (expiry, shutdown, timeout).
     *
     * Digests are deliberately *not* returned. The receiver computes them over the
     * bytes it actually received and `commitFileClaim` checks them, so the commit
     * is evidence of receipt rather than an echo of this response.
     *
     * `owner` is whatever token the caller can prove it holds later — the control
     * server passes its per-connection session object, which is why the lease
     * cannot be committed from a second connection.
     */
    async beginFileClaim(handoffId, { owner, leaseMs, onLeaseLost } = {}) {
      const record = live(byHandoffId.get(handoffId), Date.now());
      if (!record || !record.plaintext) return UNAVAILABLE;
      if (record.payloadKind !== PAYLOAD_KIND_FILES) return UNAVAILABLE;
      // The busy lease is answered *before* the state check, and that order is the
      // whole difference between the two refusals. `transferring` is not
      // `submitted`, so checking the state first would tell a second receiver
      // `unavailable` — which it is entitled to read as "this drop is over" — about
      // a payload that is merely being read by someone else right now.
      if (record.transfer || record.state === 'transferring') {
        return transferFailed('transfer_in_progress');
      }
      if (record.state !== 'submitted') return UNAVAILABLE;

      // Every granted lease costs a full digest pass over the container below, and
      // `abandonFileClaim` gives the drop back for free — so the number of passes
      // one drop can be made to spend has to be bounded, exactly as the submit path
      // bounds container validation with `containerFailures`. Unlike that path this
      // one does *not* destroy the drop when the budget is spent: a receiver that
      // crashed eight times is a broken receiver, not a reason to throw away the
      // user's files. The payload stays and lapses on its own TTL.
      if (record.transferAttempts >= config.maxTransferAttempts) {
        logger.warn?.(
          `handoff transfer refused hid=${handoffId} reason=attempt_budget_spent ` +
            `attempts=${record.transferAttempts}/${config.maxTransferAttempts}`,
        );
        return transferFailed('attempt_budget_spent');
      }

      // Narrow-only, and nonsense reads as "no narrowing asked for" — the same
      // reading `narrowFileLimits` gives a model tool's argument. The control
      // server refuses an ill-typed `lease_ms` before it gets here; this is what
      // holds for an in-process caller.
      const asked = Number.isSafeInteger(leaseMs) && leaseMs > 0 ? leaseMs : Infinity;
      // ...and clamped to the handoff's own remaining time, because
      // `lease_expires_at` is published as the deadline the frames and the commit
      // must both land before. A deadline past the record's expiry is one this
      // broker cannot honour: it would stream up to 42 MiB and then destroy the
      // payload under a receiver that did everything right.
      const remainingMs = record.expiresAt - Date.now();
      // Below the floor there is no point starting: an honest refusal now costs the
      // caller a round trip, where a lease costs it a full transfer that could never
      // have been committed. Nothing is consumed and nothing is destroyed — the drop
      // simply lapses on its own clock, so this is `transfer_failed` and not
      // `unavailable`.
      if (remainingMs < MIN_TRANSFER_LEASE_MS) {
        logger.info?.(
          `handoff transfer refused hid=${handoffId} reason=handoff_expiring ` +
            `remaining_ms=${Math.max(0, remainingMs)}`,
        );
        return transferFailed('handoff_expiring');
      }
      const effectiveLeaseMs = Math.min(config.fileClaimLeaseMs, asked, remainingMs);

      // The manifest is re-derived from the container on every transfer rather
      // than cached at submit, which costs one SHA-256 pass and buys two things:
      // the record retains no filename and no digest between submit and claim, and
      // the digests the commit is checked against were verified against these
      // bytes moments ago rather than against whatever they were at submit time
      // (see the ownership note in src/file-container.js).
      let decoded;
      try {
        decoded = await decodeFileContainer(record.plaintext, { limits: record.fileLimits });
      } catch (error) {
        if (!(error instanceof FileContainerError)) throw error;
        // Unreachable through any ordinary path: `submit` refused anything that
        // was not already a valid container. Reaching it means the bytes changed
        // under us — a destroy that raced this decode, most plausibly — so the
        // record is left exactly as it is and the caller is told nothing.
        logger.warn?.(`handoff transfer container rejected hid=${handoffId} code=${error.code}`);
        return UNAVAILABLE;
      }

      // Synchronous single-use gate: nothing may await between here and the
      // mutation, or two receivers could both leave the decode believing they won.
      //
      // In the *same order* as the pre-await gate above, and for the same reason —
      // which matters more here, not less. The window this gate closes is the whole
      // digest pass, so two connections arriving together both land in it, and
      // answering the loser `unavailable` would tell it a payload it can see is
      // gone. Checking the state first would do exactly that.
      if (!record.plaintext) return UNAVAILABLE;
      if (record.transfer || record.state === 'transferring') {
        return transferFailed('transfer_in_progress');
      }
      if (record.state !== 'submitted') return UNAVAILABLE;

      const transferId = bytesToBase64Url(randomBytes(16));
      // The deadline is fixed *here*, against a clock read after the manifest pass,
      // and clamped again to the record's own expiry. Adding `effectiveLeaseMs` to
      // this later clock without re-clamping would put the deadline past the handoff
      // by however long the pass took — which for a maximal container is tens of
      // milliseconds, and is exactly the overshoot the clamp exists to remove.
      const leaseExpiresAt = Math.min(Date.now() + effectiveLeaseMs, record.expiresAt);
      const lease = {
        transferId,
        owner,
        onLeaseLost,
        totalBytes: decoded.totalBytes + (decoded.textBytes?.length ?? 0),
        expectedDigests: [
          ...(decoded.textBytes ? [sha256HexSync(decoded.textBytes)] : []),
          ...decoded.files.map((file) => file.sha256),
        ],
        expectedSizes: [
          ...(decoded.textBytes ? [decoded.textBytes.length] : []),
          ...decoded.files.map((file) => file.size),
        ],
        hasPrivateText: decoded.textBytes !== undefined,
        /** The frame the receiver must ack next; `files.length` means all are in. */
        nextFrame: 0,
        /** Bytes the receiver proved it hashed, one validated ack at a time. */
        ackedBytes: 0,
        expiresAt: leaseExpiresAt,
        timer: setTimeout(() => {
          // Guarded against the release that already happened: a commit clears the
          // lease first, so a timer that fires just behind one finds nothing.
          if (record.transfer?.transferId !== transferId) return;
          clearLease(record, 'lease_timeout', true);
        }, Math.max(1, leaseExpiresAt - Date.now())),
      };
      lease.timer.unref();
      record.transfer = lease;
      record.state = 'transferring';
      // Counted here, at the point a lease is actually granted, so refusals above
      // cost nothing and only real digest passes are charged.
      record.transferAttempts += 1;
      logger.info?.(
        `handoff transfer began hid=${handoffId} files=${decoded.files.length} ` +
          `bytes=${decoded.totalBytes} lease_ms=${leaseExpiresAt - Date.now()} ` +
          `attempt=${record.transferAttempts}/${config.maxTransferAttempts}`,
      );

      return {
        ok: true,
        handoff_id: handoffId,
        transfer_id: transferId,
        lease_expires_at: lease.expiresAt,
        total_bytes: decoded.totalBytes + (decoded.textBytes?.length ?? 0),
        ...(decoded.textBytes === undefined ? {} : {
          private_text: { size: decoded.textBytes.length, sha256: sha256HexSync(decoded.textBytes) },
          private_text_bytes: decoded.textBytes,
        }),
        files: decoded.files.map((file) => ({
          name: file.name,
          type: file.type,
          size: file.size,
          bytes: file.bytes,
        })),
      };
    },

    /**
     * Validates one frame acknowledgement and advances the transfer.
     *
     * This is the transfer's progress authority, and it replaced a byte counter fed
     * by socket write completions. That counter was not evidence of receipt and the
     * difference mattered: a write completes when the *kernel* takes the bytes, so
     * for any payload smaller than the socket send buffer every frame "completed"
     * before the receiver had read one, and an early commit was accepted below that
     * size and refused above it. A rule that depends on a tunable buffer size is
     * absent exactly where drops are most common.
     *
     * An ack cannot be produced by a kernel. To answer, a receiver has to have read
     * the frame and hashed it, and the digest is checked against the manifest — which
     * the broker holds and the receiver was never given. What remains forgeable is a
     * caller that already knows the plaintext, and no exchange over this socket can
     * fix that (see `file_claim.receipt` in the contract). What it does buy,
     * uniformly at 16 bytes and at 42 MiB, is that an ordinary or buggy receiver
     * cannot retire a payload it never read.
     *
     * Strictly in order, and synchronous: `next_index` is the only frame that can be
     * acked, so a duplicate or a skipped ack is a refusal rather than something to
     * reconcile.
     */
    ackFileClaimFrame(handoffId, transferId, { owner, index, size, digest } = {}) {
      const record = live(byHandoffId.get(handoffId), Date.now());
      if (!record || !record.plaintext) return UNAVAILABLE;
      if (record.state !== 'transferring' || !record.transfer) {
        // The lease lapsed or was released under the caller. The payload survived it,
        // which is what `transfer_failed` promises.
        return record.state === 'submitted' ? transferFailed('lease_expired') : UNAVAILABLE;
      }

      const lease = record.transfer;
      if (lease.transferId !== transferId) return transferFailed('transfer_id_mismatch');
      if (lease.owner !== owner) return transferFailed('lease_not_yours');
      if (lease.nextFrame >= lease.expectedSizes.length) return INVALID_REQUEST;
      if (index !== lease.nextFrame) {
        logger.warn?.(
          `handoff transfer refused hid=${handoffId} reason=frame_ack_out_of_order ` +
            `acked=${index} expected=${lease.nextFrame}`,
        );
        clearLease(record, 'frame_ack_out_of_order');
        return transferFailed('frame_ack_out_of_order');
      }
      // Size and digest together. Nothing about *which* of them differed is logged:
      // one is a length and the other is a statement about content.
      if (size !== lease.expectedSizes[index] || digest !== lease.expectedDigests[index]) {
        logger.warn?.(
          `handoff transfer refused hid=${handoffId} reason=frame_ack_mismatch frame=${index}`,
        );
        clearLease(record, 'frame_ack_mismatch');
        return transferFailed('frame_ack_mismatch');
      }

      lease.ackedBytes += size;
      lease.nextFrame += 1;
      const done = lease.nextFrame >= lease.expectedSizes.length;
      // No frame bytes come back here. The streamer already holds the views this
      // transfer's `beginFileClaim` handed it and indexes them by `next_index`, so the
      // record keeps no second reference to the payload and — the part that matters —
      // no filename between submit and claim.
      return { ok: true, index, next_index: done ? null : lease.nextFrame };
    },

    /**
     * Seam 4b, phase 2: the ACK, and the only thing in the protocol that retires a
     * `files` payload.
     *
     * Four conditions, in the order that costs the caller least to get right:
     * the lease is live and theirs, the broker really flushed every advertised
     * byte, the receiver counted the same number, and the digests it computed over
     * those bytes are the manifest's. Only then — synchronously, with no await
     * between the last check and the retirement — is the payload consumed.
     *
     * Everything else is `transfer_failed` with the record back to `submitted`,
     * which is the whole point of the two phases.
     */
    commitFileClaim(handoffId, transferId, { owner, receivedBytes, digests } = {}) {
      const record = live(byHandoffId.get(handoffId), Date.now());
      // Gone, or already claimed: there is nothing to commit and nothing to keep,
      // so this is the uniform refusal rather than a statement about a transfer.
      if (!record || !record.plaintext) return UNAVAILABLE;
      if (record.state === 'submitted' && !record.transfer) {
        // The lease lapsed or was released under the caller; the payload survived
        // it, which is exactly what `transfer_failed` promises.
        return transferFailed('lease_expired');
      }
      if (record.state !== 'transferring' || !record.transfer) return UNAVAILABLE;

      const lease = record.transfer;
      if (lease.transferId !== transferId) return transferFailed('transfer_id_mismatch');
      if (lease.owner !== owner) return transferFailed('lease_not_yours');
      // Every frame acked, which is the size-independent form of "the receiver has it".
      // Unreachable over the wire — the connection will not accept a commit while a
      // frame is outstanding — and checked here because this is the function that
      // retires the payload, and it must not depend on a caller's phase discipline.
      if (lease.nextFrame !== lease.expectedSizes.length) {
        logger.warn?.(
          `handoff transfer refused hid=${handoffId} reason=frames_not_acked ` +
            `acked=${lease.nextFrame}/${lease.expectedSizes.length}`,
        );
        clearLease(record, 'frames_not_acked');
        return transferFailed('frames_not_acked');
      }
      if (lease.ackedBytes !== lease.totalBytes) {
        logger.warn?.(
          `handoff transfer refused hid=${handoffId} reason=incomplete_transfer ` +
            `acked=${lease.ackedBytes}/${lease.totalBytes}`,
        );
        clearLease(record, 'incomplete_transfer');
        return transferFailed('incomplete_transfer');
      }
      if (receivedBytes !== lease.totalBytes) {
        logger.warn?.(
          `handoff transfer refused hid=${handoffId} reason=size_mismatch ` +
            `claimed=${receivedBytes} transferred=${lease.totalBytes}`,
        );
        clearLease(record, 'size_mismatch');
        return transferFailed('size_mismatch');
      }
      if (!digestsMatch(digests, lease.expectedDigests)) {
        // The count and the order are part of the match, not conditions before it:
        // a receiver that returns the right digests in the wrong order did not
        // receive the files this manifest describes. Nothing about which digest
        // differed is logged — that is a statement about content.
        logger.warn?.(`handoff transfer refused hid=${handoffId} reason=digest_mismatch`);
        clearLease(record, 'digest_mismatch');
        return transferFailed('digest_mismatch');
      }

      const files = lease.expectedDigests.length - (lease.hasPrivateText ? 1 : 0);
      const bytes = lease.totalBytes;
      clearLease(record, 'committed');
      retire(record);
      return { ok: true, handoff_id: handoffId, status: 'claimed', files, bytes };
    },

    /**
     * Gives a lease back without committing it — the disconnect path, and what an
     * in-process caller uses when it decides not to finish. Idempotent, and it
     * cannot end a lease that is not the one named.
     */
    abandonFileClaim(handoffId, transferId, reason = 'abandoned') {
      const record = byHandoffId.get(handoffId);
      if (record?.transfer?.transferId !== transferId) return false;
      clearLease(record, reason);
      return true;
    },

    /**
     * Test-only: move a live record's deadline. The counterpart to `sweep(now)`,
     * which already lets a test choose *when* expiry happens; this lets it choose a
     * deadline instead, which is the only way to exercise "too little TTL left to
     * start a transfer" without a real sleep racing the setup.
     */
    testSetExpiry(handoffId, expiresAt) {
      const record = byHandoffId.get(handoffId);
      if (!record) return false;
      record.expiresAt = expiresAt;
      return true;
    },

    /** Non-secret local routing metadata for the universal Hermes dispatcher. */
    payloadKind(handoffId) {
      const record = live(byHandoffId.get(handoffId), Date.now());
      return record && (record.state === 'submitted' || record.state === 'transferring')
        ? record.payloadKind
        : null;
    },

    /** Test-only introspection. Returns no plaintext and no key material. */
    testSnapshot(handoffId) {
      const record = byHandoffId.get(handoffId);
      if (!record) return null;
      return {
        state: record.state,
        payloadKind: record.payloadKind,
        mintedKind: record.mintedKind,
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
        // Whether the reservation above is still an in-flight submission's, as a
        // byte count and nothing else — the lease object itself is two numbers, but
        // reporting it as a shape a test can print keeps it symmetrical with
        // `transfer` below.
        submitLease: record.submitLease ? { bytes: record.submitLease.bytes } : null,
        bodySlotBusy: record.bodySlotBusy,
        // The live transfer lease as four numbers and an id. Deliberately not the
        // lease object: that one holds the manifest's digests and a callback into
        // whoever is streaming, and neither belongs in something a test prints.
        transfer: record.transfer
          ? {
              transferId: record.transfer.transferId,
              expiresAt: record.transfer.expiresAt,
              ackedBytes: record.transfer.ackedBytes,
              nextFrame: record.transfer.nextFrame,
              totalBytes: record.transfer.totalBytes,
              files: record.transfer.expectedDigests.length,
            }
          : null,
        transferAttempts: record.transferAttempts,
        expiresAt: record.expiresAt,
        waiters: record.waiters.length,
        serialized: JSON.stringify(record, (key, value) => {
          if (key === 'plaintext') return value ? '[redacted]' : null;
          if (key === 'submitLease') return value ? `[lease ${value.bytes}]` : null;
          // Same reasoning as above, and it matters more here: this string is what
          // the invariant tests grep for leaked payloads.
          if (key === 'transfer') return value ? `[lease ${value.transferId}]` : null;
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
 * Shape only, and always against the version and ceiling of the lane this
 * submission was *resolved* to — the record's fixed kind, or the declaration that
 * chose one on a universal link — never against whatever the envelope claims. A
 * text drop therefore still refuses `v: 2` here, before any crypto and without
 * spending a byte of the AEAD budget, exactly as it always did, and a container
 * declared as text is refused on the same line.
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

/** Lowercase hex, fixed width — the same single digest spelling the manifest accepts. */
const SHA256_HEX = /^[0-9a-f]{64}$/;

/**
 * Does what the receiver computed match the container, in count, order and value?
 *
 * All three at once and with no early distinction between them: a client that
 * returns the right digests in the wrong order did not receive the files this
 * manifest describes, and a client that returns four digests for five files has
 * not received the drop either. The comparison is not constant-time because
 * nothing here is a secret being guessed — these are the digests of bytes the
 * caller was just handed, over a socket only a caller trusted with the plaintext
 * can reach.
 */
function digestsMatch(digests, expected) {
  if (!Array.isArray(digests) || digests.length !== expected.length) return false;
  return expected.every(
    (digest, index) =>
      typeof digests[index] === 'string' &&
      SHA256_HEX.test(digests[index]) &&
      digests[index] === digest,
  );
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
