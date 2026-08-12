// Outbound secret drops (docs/OUTBOUND_SECRET_DROP_MVP.md): Hermes → the user.
//
// Every other store in this repo runs the other way. There a browser holds a
// secret, the broker receives one envelope it cannot forge, and a local caller
// claims the plaintext over the 0600 socket. Here the local caller *starts* with
// the plaintext and the browser is the one that has to be handed it, exactly once,
// behind a code a person types. That reversal changes what the broker must not
// keep, so this store is separate from the handoff records rather than a fourth
// payload kind on them:
//
//   NO PLAINTEXT   the secret is encrypted before it is stored and the buffer it
//                  arrived in is wiped in the same call. The record holds
//                  ciphertext, an IV and nothing that can open them.
//   NO KEY         the AES key is generated per drop, handed back inside the URL
//                  *fragment* — which browsers never send — and dropped. A
//                  compromise of this process's memory after `create` yields
//                  ciphertext, not a secret. This is the one place in the project
//                  where the broker does not hold the decryption key, and it is
//                  free: nothing here ever needs to read the payload.
//   NO CODE        what is stored is HMAC-SHA256 over the code under a per-record
//                  random key, compared in constant time. It is a verifier, not a
//                  hint: nothing in a log, a snapshot or a serialized record can be
//                  read as the code the user was told.
//   NO SNIPPET     nothing on this path logs its input. This is the first op that
//                  carries plaintext *into* the control socket, so a parse error's
//                  message — which V8 fills with a window of the offending line — is
//                  never logged (src/control-server.js).
//
// The code is a human-presence and anti-preview gate, not a second factor — the
// link and the code travel in the same conversation (MVP, "Security meaning of the
// code"). Three digits is 1000 possibilities, so the *only* thing standing between
// a link-holder and the payload is the attempt budget, and the budget is therefore
// the rate limit rather than something layered on top of one: three wrong codes
// destroy the payload. That deliberately prefers denial of delivery over allowing
// online brute force, and it is why a wrong code is answered distinguishably at all
// — the user has to be able to see that they mistyped, and they get three tries to
// do it in.
//
// The claim lifecycle, and there are no other states:
//
//   available --correct code, one claim id--> reserved --ack--> destroyed
//      |                                        |
//      |  three wrong codes                     |  ack window lapses
//      +-------------+--------------------------+
//                    v
//                destroyed   (also: TTL lapse from either state, shutdown)
//
// `reserved` is what makes "one browser" true. The reservation is taken
// synchronously, in the same step that verifies the code, so two browsers racing
// the same correct code cannot both leave it believing they won — and the loser
// gets the uniform unavailable, because from its side the drop is over. What the
// winner gets is a bounded retry: the same claim id replayed inside the window is
// answered with the same ciphertext, so a *dropped response* and a re-sent request
// do not cost the user the secret, while a different claim id is refused however
// correct its code. The payload dies at the ack or at the window's end, whichever
// comes first, so a browser that never answers cannot leave a secret resident for
// the whole TTL.
//
// What that retry does NOT survive, stated here because the opposite is the natural
// assumption: a page *reload*. A reloaded page draws a fresh claim id, and the
// reserved one is gone with the page — so metadata answers the uniform body, the new
// id is refused however correct its code, and the payload lapses at the window. A
// reload between the code and the copy therefore costs the secret, and there is no
// re-request path because a drop is one-shot. That is the accepted cost of
// one-browser reservation in this slice; the remedy belongs to the browser slice
// (persist the claim id in the page session before claiming, and let metadata answer
// a reserved drop to a caller presenting that drop's own id).
import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

import { bytesToBase64Url, isBase64Url } from './base64url.js';
import { CAPABILITY_BYTES, CAPABILITY_LENGTH } from './hpke-suite.js';
import {
  CLAIM_ID_LENGTH,
  OUTBOUND_ALG,
  OUTBOUND_CODE_DIGITS,
  OUTBOUND_IV_BYTES,
  OUTBOUND_KEY_BYTES,
  formatOutboundFragment,
  isOutboundCode,
  outboundAad,
} from './outbound-envelope.js';

// Re-exported so a server-side consumer has one import for the whole outbound
// contract, rather than having to know which half of it is isomorphic.
export {
  CLAIM_ID_LENGTH,
  OUTBOUND_ALG,
  OUTBOUND_CODE_DIGITS,
  OUTBOUND_FRAGMENT_SCHEME,
  formatOutboundFragment,
  isOutboundCode,
  parseOutboundFragment,
} from './outbound-envelope.js';

const UNAVAILABLE = Object.freeze({ ok: false, error: 'unavailable' });
const INVALID_REQUEST = Object.freeze({ ok: false, error: 'invalid_request' });

/**
 * The outbound revision this broker speaks, advertised on `create` responses the
 * way `file_claim_protocol` is, and for the same reason: a plugin upgraded on its
 * own schedule needs a yes-or-no answer *before* it posts a link and a code into a
 * conversation, not a version ordering it has to reason about.
 */
export const OUTBOUND_PROTOCOL = 1;

/**
 * The attempt budget (MVP, "Approved defaults"): three incorrect codes and the
 * payload is gone. Deliberately not an operator dial — it is *the* bound on online
 * guessing at three digits, and lowering the cost of a wrong guess is not a
 * deployment decision.
 */
export const OUTBOUND_MAX_CODE_ATTEMPTS = 3;

/**
 * The shortest outbound drop this broker will mint.
 *
 * A floor on the *effective lifetime*, not a sign check on a float, because the
 * failure it prevents is silent: a drop minted with a degenerate TTL — a unit slip, a
 * millisecond value where seconds were meant, a computed `remaining / 1e9` — is
 * answered `ok`, and the caller then posts a link and a code for a payload that is
 * already gone. What the user meets is the uniform refusal, which is
 * byte-identical to the one a *stolen* secret produces, and no seam on either side
 * can tell them which happened. Refusing the create is the only place that
 * ambiguity can be prevented rather than explained.
 *
 * One second is the smallest interval that is still a lifetime rather than a race
 * with the message that carries the link.
 */
export const MIN_OUTBOUND_TTL_SECONDS = 1;
const MIN_OUTBOUND_TTL_MS = MIN_OUTBOUND_TTL_SECONDS * 1000;

function zeroize(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

function sha256Sync(value) {
  return new Uint8Array(createHash('sha256').update(value).digest());
}

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

/**
 * A uniform-random code of exactly `OUTBOUND_CODE_DIGITS` digits, leading zeros
 * included. `randomInt` is rejection-sampled, so 000 and 999 are exactly as likely
 * as anything between them — a modulo of a random byte would not be.
 */
function generateCode() {
  return String(randomInt(0, 10 ** OUTBOUND_CODE_DIGITS)).padStart(OUTBOUND_CODE_DIGITS, '0');
}

/**
 * The stored form of the code: HMAC-SHA256 under a per-record random key.
 *
 * Keyed rather than plain-hashed because 1000 candidates is a table anyone can
 * build in a millisecond: an unkeyed digest in a log line, a heap dump or a crash
 * report would *be* the code. What the key buys is bounded and worth stating
 * exactly — it defends against a verifier that has escaped the record (a serialized
 * snapshot, a log, an operator's dump), not against an attacker who already has the
 * whole record, since the key is next to it. Nothing can defend against that at
 * three digits, which is why the attempt budget and not the verifier is what
 * bounds guessing.
 */
function codeVerifier(verifierKey, code) {
  return new Uint8Array(createHmac('sha256', verifierKey).update(code, 'utf8').digest());
}

export function createOutboundDrops(config, logger = console) {
  /** capabilityHashHex -> record */
  const byCapabilityHash = new Map();
  /** dropId -> record */
  const byDropId = new Map();

  function destroy(record, reason) {
    if (record.claimTimer) clearTimeout(record.claimTimer);
    record.claimTimer = null;
    zeroize(record.ciphertext);
    zeroize(record.iv);
    zeroize(record.verifier);
    zeroize(record.verifierKey);
    record.ciphertext = null;
    record.state = 'destroyed';
    byCapabilityHash.delete(record.capabilityHashHex);
    byDropId.delete(record.dropId);
    logger.info?.(`outbound drop destroyed did=${record.dropId} reason=${reason}`);
  }

  /**
   * The record if it is still live, or null after destroying whatever lapsed.
   *
   * Two deadlines, enforced lazily here as well as by the sweeper, so a parked
   * sweeper cannot extend either: the drop's own TTL, and — once a claimant has
   * reserved it — the bounded ack window. Both mean the payload is gone, which is
   * why they land in the same place rather than one of them merely refusing.
   */
  function live(record, now) {
    if (!record) return null;
    if (now >= record.expiresAt) {
      destroy(record, 'expired');
      return null;
    }
    if (record.state === 'reserved' && now >= record.claimExpiresAt) {
      destroy(record, 'ack_timeout');
      return null;
    }
    return record;
  }

  /**
   * Resolves a presented capability to a live record. The presented value is hashed
   * first, so the lookup never compares secret bytes; the constant-time comparison
   * guards the retained hash itself. Synchronous, which is what lets the claim gate
   * below run with no await between its check and its mutation.
   */
  function resolve(capability, now) {
    if (!isBase64Url(capability, CAPABILITY_LENGTH)) return null;
    const hash = sha256Sync(capability);
    const record = byCapabilityHash.get(toHex(hash));
    if (!record) return null;
    if (!timingSafeEqual(Buffer.from(hash), Buffer.from(record.capabilityHash))) return null;
    return live(record, now);
  }

  function codeMatches(record, code) {
    const presented = codeVerifier(record.verifierKey, code);
    return timingSafeEqual(Buffer.from(presented), Buffer.from(record.verifier));
  }

  /**
   * Compares a presented claim id against the reservation's, in constant time.
   *
   * Constant-time because of what the claim id *authorizes*, which is more than its
   * "not a credential" description suggests: it replays the ciphertext inside the
   * window, and it is the only thing `acknowledge` checks before destroying the
   * payload. A plain `!==` next to a `timingSafeEqual` on the code invites the reading
   * that one of the two matters and the other does not.
   *
   * The length is checked first and separately, and that is not an optimisation:
   * `timingSafeEqual` *throws* on unequal lengths, and a throw here would turn a seam
   * whose whole contract is one uniform refusal into a caller-triggered error. Length
   * is not a secret — every claim id this broker accepts is exactly
   * `CLAIM_ID_LENGTH` characters — so leaking it costs nothing.
   */
  function claimIdMatches(record, claimId) {
    if (typeof claimId !== 'string' || !isBase64Url(claimId, CLAIM_ID_LENGTH)) return false;
    if (record.claimId === null || record.claimId.length !== claimId.length) return false;
    return timingSafeEqual(Buffer.from(record.claimId, 'utf8'), Buffer.from(claimId, 'utf8'));
  }

  /**
   * What a reserved claimant is handed: the sealed payload and the deadline it has to
   * acknowledge by. Identical on the first claim and on every retry of it — the same
   * ciphertext, the same IV and the same deadline — because a retry that re-sealed or
   * extended anything would be a second delivery wearing the first one's name.
   */
  function revealed(record) {
    return {
      ok: true,
      did: record.dropId,
      alg: OUTBOUND_ALG,
      iv: bytesToBase64Url(record.iv),
      ct: bytesToBase64Url(record.ciphertext),
      claim_expires_at: record.claimExpiresAt,
    };
  }

  return {
    /**
     * Mints one outbound drop: encrypt, store the ciphertext, hand back the link,
     * the code and nothing else.
     *
     * `plaintext` is a buffer the caller owns and this call wipes — the control seam
     * decoded it out of a request line and has no further use for it. What survives
     * that wipe is documented rather than claimed away: the base64 the secret
     * arrived as is an immutable JS string on this process's heap until it is
     * collected, exactly like the one `claim` produces in the other direction
     * (SECURITY.md, "The claim path makes copies that cannot be zeroed").
     */
    async create({ plaintext, ttlSeconds = config.outboundTtlSeconds, baseUrl }) {
      if (!(plaintext instanceof Uint8Array) || plaintext.length === 0) return INVALID_REQUEST;

      // ONE wipe for every exit, and a `finally` rather than a line per branch.
      //
      // The invariant this module states without qualification — the buffer the secret
      // arrived in is wiped in the same call — used to be held by a `zeroize` on each
      // refusal path plus one around the encryption. That is a thread every future
      // branch has to remember to pick up, and it broke once already: adding the
      // lifetime floor put `ttlSeconds * 1000` *above* the type check, and multiplying a
      // BigInt or a Symbol throws — so the buffer survived un-wiped on a path nobody had
      // thought about. A `finally` cannot be forgotten by the next branch, and it covers
      // the success path and a throwing AEAD too. The control seam wipes again on its
      // way out; a second fill of at most 2 KiB is free.
      try {
        if (plaintext.length > config.maxOutboundPlaintextBytes) return INVALID_REQUEST;
        // Typed before it is measured, so this function cannot be reached with a value
        // the arithmetic below could not touch. `typeof` is not redundant next to
        // `Number.isFinite`: that answers `false` for a BigInt rather than throwing, but
        // the multiplication producing `ttlMs` would already have thrown.
        if (typeof ttlSeconds !== 'number' || !Number.isFinite(ttlSeconds)) {
          return INVALID_REQUEST;
        }
        // The lifetime, bounded at both ends. The floor is on the effective
        // milliseconds — `Math.round` collapses anything under half a millisecond to
        // zero, which would mint a drop that `live()` destroys on first touch — and the
        // ceiling is the *outbound* one, because an outbound link and its code sit in a
        // conversation and that exposure is not the inbound drop's.
        const ttlMs = Math.round(ttlSeconds * 1000);
        if (ttlMs < MIN_OUTBOUND_TTL_MS || ttlSeconds > config.maxOutboundTtlSeconds) {
          return INVALID_REQUEST;
        }
        if (!baseUrl) throw new Error('broker baseUrl is not resolved yet');

        const dropId = bytesToBase64Url(randomBytes(16));
        const capability = bytesToBase64Url(randomBytes(CAPABILITY_BYTES));
        const capabilityHash = sha256Sync(capability);
        const keyBytes = randomBytes(OUTBOUND_KEY_BYTES);
        const iv = randomBytes(OUTBOUND_IV_BYTES);
        const code = generateCode();
        const verifierKey = randomBytes(32);

        // Non-extractable: the key object cannot be read back out of WebCrypto, so the
        // raw bytes below are the only copy and they are wiped a few lines on.
        const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
          'encrypt',
        ]);
        const ciphertext = new Uint8Array(
          await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: outboundAad(dropId) },
            key,
            plaintext,
          ),
        );

        const now = Date.now();
        const record = {
          dropId,
          capabilityHash,
          capabilityHashHex: toHex(capabilityHash),
          ciphertext,
          iv,
          /** HMAC-SHA256(verifierKey, code). The code itself is never stored. */
          verifier: codeVerifier(verifierKey, code),
          verifierKey,
          attemptsRemaining: OUTBOUND_MAX_CODE_ATTEMPTS,
          state: 'available',
          /** The one claimant, once one has been reserved. */
          claimId: null,
          claimExpiresAt: 0,
          claimTimer: null,
          createdAt: now,
          expiresAt: now + ttlMs,
        };
        byCapabilityHash.set(record.capabilityHashHex, record);
        byDropId.set(dropId, record);

        const url = `${baseUrl}/#${formatOutboundFragment({
          capability,
          key: bytesToBase64Url(keyBytes),
        })}`;
        // The key exists in this process only as the characters now inside `url`, and
        // that string is the caller's. Nothing keyed to this record can open it any
        // more, which is the property the whole module is arranged around.
        zeroize(keyBytes);
        logger.info?.(`outbound drop created did=${dropId} ttl=${ttlSeconds}s`);

        return {
          ok: true,
          drop_id: dropId,
          url,
          code,
          code_length: OUTBOUND_CODE_DIGITS,
          max_code_attempts: OUTBOUND_MAX_CODE_ATTEMPTS,
          // The window this drop can honour, clamped like the claim will clamp it.
          ack_window_ms: Math.min(config.outboundAckWindowMs, record.expiresAt - now),
          expires_at: record.expiresAt,
          ttl_seconds: ttlSeconds,
        };
      } finally {
        zeroize(plaintext);
      }
    },

    /**
     * Non-secret status for the gate. Available drops only: a drop already reserved
     * by a claimant is `unavailable` here, because the only party entitled to hear
     * anything more about it is the one holding its claim id, and it hears it at the
     * claim seam.
     *
     * Nothing here opens anything. No ciphertext, no IV, no verifier — a page is told
     * how long is left and how many attempts remain, which is exactly what it needs
     * to render the gate and no more.
     */
    metadata(capability) {
      const now = Date.now();
      const record = resolve(capability, now);
      if (!record || record.state !== 'available') return UNAVAILABLE;
      return {
        ok: true,
        did: record.dropId,
        alg: OUTBOUND_ALG,
        code_length: OUTBOUND_CODE_DIGITS,
        attempts_remaining: record.attemptsRemaining,
        expires_at: record.expiresAt,
        // The window this drop can actually honour, not the configured one. A claim
        // clamps its deadline to the record's own expiry, so a drop near the end of its
        // life grants less than the full window — and this number is what a page renders
        // its pre-claim countdown from, so advertising the unclamped one would promise
        // the user time the broker will take back mid-copy.
        ack_window_ms: Math.min(config.outboundAckWindowMs, record.expiresAt - now),
        // The broker's own clock, so the page can render a countdown without
        // trusting the device's — the same reason the inbound metadata publishes it.
        now,
      };
    },

    /**
     * The code gate and the claimant reservation, in one synchronous step.
     *
     * The order of the checks is the contract. A reserved drop is answered from its
     * claim id alone and never spends an attempt, so a competing browser cannot drain
     * the budget of a drop that is already being revealed; an `available` drop spends
     * an attempt on a wrong code and nothing else does; and the reservation is taken
     * with no await between the verification and the mutation, so two browsers
     * arriving with the same correct code cannot both leave here believing they won.
     *
     * A malformed code or claim id is the uniform refusal and costs no attempt: it is
     * a shape mistake, not a guess, and spending the user's budget on their own
     * client's bug would be the wrong trade.
     */
    claim(capability, { code, claimId } = {}) {
      const now = Date.now();
      const record = resolve(capability, now);
      if (!record) return UNAVAILABLE;
      if (!isOutboundCode(code)) return UNAVAILABLE;
      if (typeof claimId !== 'string' || !isBase64Url(claimId, CLAIM_ID_LENGTH)) {
        return UNAVAILABLE;
      }

      if (record.state === 'reserved') {
        // The bounded same-claim retry, and nothing else. A second claimant is
        // refused here however correct its code — that is what "one browser" means —
        // and it is refused with the uniform body, so it cannot tell a drop someone
        // else is revealing from one that is already over.
        if (!claimIdMatches(record, claimId)) return UNAVAILABLE;
        if (!codeMatches(record, code)) return UNAVAILABLE;
        logger.info?.(`outbound drop re-served did=${record.dropId} reason=same_claim_retry`);
        return revealed(record);
      }

      if (!codeMatches(record, code)) {
        record.attemptsRemaining -= 1;
        logger.warn?.(
          `outbound drop code refused did=${record.dropId} ` +
            `remaining=${record.attemptsRemaining}/${OUTBOUND_MAX_CODE_ATTEMPTS}`,
        );
        if (record.attemptsRemaining <= 0) {
          // The budget is the rate limit, and this is what makes it one: the payload
          // is destroyed rather than left for a fourth guess. Denial of delivery over
          // online brute force, as the MVP states.
          destroy(record, 'code_attempts_spent');
          return UNAVAILABLE;
        }
        // The one public refusal that is not uniform, and it is deliberate: a user
        // who mistyped has to be able to see that they did, and three attempts are
        // worthless if they cannot tell a wrong code from a dead link. It is
        // reachable only with a live capability, which the holder of the link
        // already has.
        return { ok: false, error: 'code_incorrect', attempts_remaining: record.attemptsRemaining };
      }

      // Synchronous reservation gate: nothing may await between the check above and
      // these mutations.
      record.state = 'reserved';
      record.claimId = claimId;
      // Clamped inside the drop's own expiry, so the window can never publish a
      // deadline past the payload's own life.
      record.claimExpiresAt = Math.min(now + config.outboundAckWindowMs, record.expiresAt);
      record.claimTimer = setTimeout(
        () => {
          // The payload dies at the window's end whether or not anyone acknowledged
          // it, which is what stops a browser that revealed and vanished from leaving
          // a decryptable secret resident for the rest of the TTL.
          if (record.state === 'reserved') destroy(record, 'ack_timeout');
        },
        Math.max(1, record.claimExpiresAt - now),
      );
      record.claimTimer.unref();
      logger.info?.(`outbound drop reserved did=${record.dropId} window_ms=${record.claimExpiresAt - now}`);
      return revealed(record);
    },

    /**
     * The acknowledgement: the claimant has the plaintext, so the broker destroys its
     * copy. One-shot by construction — the record is gone afterwards, so a repeated
     * ack is the uniform unavailable, which is the truth.
     */
    acknowledge(capability, { claimId } = {}) {
      const record = resolve(capability, Date.now());
      if (!record || record.state !== 'reserved') return UNAVAILABLE;
      if (!claimIdMatches(record, claimId)) return UNAVAILABLE;
      destroy(record, 'acknowledged');
      return { ok: true, status: 'acknowledged' };
    },

    /** Expiry sweeper: drops payloads as soon as a TTL or an ack window lapses. */
    sweep(now = Date.now()) {
      for (const record of [...byDropId.values()]) live(record, now);
    },

    destroyAll() {
      for (const record of [...byDropId.values()]) destroy(record, 'shutdown');
    },

    /**
     * Test-only: move a live drop's deadline, like the inbound store's `testSetExpiry`.
     *
     * It exists because the lifetime floor (`MIN_OUTBOUND_TTL_SECONDS`) deliberately
     * makes the old way of driving expiry impossible: a test can no longer mint a drop
     * that dies on its own in 300 ms, because minting one is the defect that floor
     * closes. Choosing the deadline is the honest replacement for choosing a
     * degenerate TTL, and it drives the real `live()` and the real sweeper.
     */
    testSetExpiry(dropId, expiresAt) {
      const record = byDropId.get(dropId);
      if (!record) return false;
      record.expiresAt = expiresAt;
      return true;
    },

    /** Test-only introspection. Returns no ciphertext, no key material and no code. */
    testSnapshot(dropId) {
      const record = byDropId.get(dropId);
      if (!record) return null;
      return {
        state: record.state,
        attemptsRemaining: record.attemptsRemaining,
        hasCiphertext: record.ciphertext !== null,
        // Stated as a fact a test can assert rather than as an absence a reader has
        // to notice: this store never holds the key that opens its own payload.
        hasKey: false,
        claimed: record.claimId !== null,
        claimExpiresAt: record.claimExpiresAt,
        expiresAt: record.expiresAt,
        serialized: JSON.stringify(record, (key, value) => {
          if (key === 'ciphertext') return value ? '[ciphertext]' : null;
          if (key === 'verifier' || key === 'verifierKey') return '[redacted]';
          if (key === 'claimTimer') return value ? '[timer]' : null;
          if (value instanceof Uint8Array) return toHex(value);
          return value;
        }),
      };
    },
  };
}
