// Browser-facing reveal client: the exact code the page runs to open an outbound
// drop (docs/OUTBOUND_SECRET_DROP_MVP.md). Kept free of DOM references, like its
// inbound counterpart in src/client/handoff-client.js, so tests and the smoke run
// can drive the real client logic from Node.
//
// Rules encoded here:
//   - the capability travels in a request header, never in a path or query, and the
//     decryption key travels in neither: it comes out of the fragment and is used
//     only by `crypto.subtle` in this process;
//   - the code is sent only on the claim, which is the one state-changing request. A
//     GET, a HEAD or a metadata fetch never carries it and never claims;
//   - one claimant is one claim id, drawn here and reused for every retry of the
//     same reveal. A fresh id would be a second claimant and would be refused;
//   - the payload is decrypted locally, and the acknowledgement that destroys it on
//     the broker is sent only *after* a successful decryption — an ack before that
//     would destroy a payload this page could not read.
import { base64UrlToBytes, bytesToBase64Url } from '../base64url.js';
import {
  CLAIM_ID_LENGTH,
  OUTBOUND_ALG,
  OUTBOUND_IV_BYTES,
  OUTBOUND_KEY_BYTES,
  isOutboundCode,
  outboundAad,
} from '../outbound-envelope.js';

export const CAPABILITY_HEADER = 'X-Handoff-Capability';
export const REVEAL_METADATA_PATH = '/api/reveal/metadata';
export const REVEAL_CLAIM_PATH = '/api/reveal/claim';
export const REVEAL_ACK_PATH = '/api/reveal/ack';

/**
 * A fresh claim id: 16 CSPRNG bytes from the browser. Drawn once per reveal attempt
 * by the *user*, not per request — every retry of one reveal presents the same id,
 * which is what makes a retry a retry instead of a second browser.
 *
 * It lives in this page's memory and nowhere else: it must not reach a URL, a log, an
 * analytics event or durable storage, because inside the ack window it is what
 * replays the ciphertext and what authorizes the destruction. The consequence, which
 * the reveal UI has to decide about rather than inherit: a reload loses it, and with
 * it the only claim that drop will answer.
 */
export function newClaimId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

const request = (path, { capability, body, fetchImpl, origin }) =>
  fetchImpl(`${origin}${path}`, {
    method: 'POST',
    headers: {
      [CAPABILITY_HEADER]: capability,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  });

/**
 * Non-secret status for the gate: how long is left, how many attempts remain, and
 * which algorithm the payload will arrive under. Null for every unavailable reason,
 * exactly as the inbound metadata fetch is — the page never learns which one.
 */
export async function fetchOutboundMetadata({ capability, fetchImpl = fetch, origin = '' }) {
  const response = await request(REVEAL_METADATA_PATH, { capability, fetchImpl, origin });
  if (!response.ok) return null;

  const metadata = await response.json();
  // An algorithm this bundle cannot open is a broker it must not put a code into:
  // the user would spend an attempt to reach a payload the page could not read.
  if (metadata.alg !== OUTBOUND_ALG) return null;
  if (typeof metadata.did !== 'string') return null;
  return metadata;
}

/**
 * Submits one code and, if it is right, receives the ciphertext.
 *
 * Three outcomes and no fourth: `revealed` with the sealed payload, `code_incorrect`
 * with the attempts that remain, or `unavailable` — which covers expired, already
 * revealed, reserved by another browser, out of attempts and never existed, because
 * none of those is a distinction a public caller is entitled to.
 */
export async function claimOutboundDrop({
  capability,
  code,
  claimId,
  fetchImpl = fetch,
  origin = '',
}) {
  // Checked here so a mistyped length costs a keystroke rather than one of three
  // attempts. The broker checks it again, and refuses uniformly.
  if (!isOutboundCode(code)) return { status: 'invalid_code' };
  if (typeof claimId !== 'string' || claimId.length !== CLAIM_ID_LENGTH) {
    return { status: 'unavailable' };
  }

  const response = await request(REVEAL_CLAIM_PATH, {
    capability,
    body: { code, claim_id: claimId },
    fetchImpl,
    origin,
  });
  let answer = null;
  try {
    answer = await response.json();
  } catch {
    return { status: 'unavailable' };
  }
  if (answer?.status === 'revealed' || answer?.status === 'code_incorrect') return answer;
  return { status: 'unavailable' };
}

/**
 * Opens the sealed payload locally. Throws if the AEAD fails, which is the only
 * honest outcome: a wrong key, a substituted ciphertext or a drop id that does not
 * match what the payload was sealed against are indistinguishable from here, and
 * none of them may be turned into a displayable string.
 */
export async function decryptOutboundPayload({ key, dropId, iv, ct }) {
  const keyBytes = base64UrlToBytes(key);
  if (keyBytes.length !== OUTBOUND_KEY_BYTES) throw new Error('bad key length');
  const ivBytes = base64UrlToBytes(iv);
  if (ivBytes.length !== OUTBOUND_IV_BYTES) throw new Error('bad iv length');

  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);
  keyBytes.fill(0);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes, additionalData: outboundAad(dropId) },
      cryptoKey,
      base64UrlToBytes(ct),
    ),
  );
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Tells the broker the reveal landed, which is what destroys the payload. Sent only
 * after a successful local decryption: until then the bounded retry window is the
 * user's only protection against a dropped response, and an early ack would spend it.
 */
export async function acknowledgeOutboundDrop({
  capability,
  claimId,
  fetchImpl = fetch,
  origin = '',
}) {
  const response = await request(REVEAL_ACK_PATH, {
    capability,
    body: { claim_id: claimId },
    fetchImpl,
    origin,
  });
  if (!response.ok) return 'unavailable';
  const answer = await response.json().catch(() => null);
  return answer?.status === 'acknowledged' ? 'acknowledged' : 'unavailable';
}

/**
 * The whole browser-side reveal: claim, decrypt, acknowledge.
 *
 * The ack is deliberately not fatal. By the time it is sent the user already has the
 * secret on screen, so a failed ack is a payload that will be destroyed by the
 * bounded window instead of by this request — worth reporting, never worth telling
 * the user their reveal failed.
 */
export async function revealSecret({
  capability,
  key,
  code,
  claimId = newClaimId(),
  fetchImpl = fetch,
  origin = '',
}) {
  const claimed = await claimOutboundDrop({ capability, code, claimId, fetchImpl, origin });
  if (claimed.status !== 'revealed') return { ...claimed, claim_id: claimId };

  let plaintext;
  try {
    plaintext = await decryptOutboundPayload({
      key,
      dropId: claimed.did,
      iv: claimed.iv,
      ct: claimed.ct,
    });
  } catch {
    // The claim is still reserved to this claim id, so the same reveal may be
    // retried inside the window; nothing is acknowledged and nothing is destroyed.
    return { status: 'undecryptable', claim_id: claimId };
  }

  const acknowledged = await acknowledgeOutboundDrop({ capability, claimId, fetchImpl, origin });
  return { status: 'revealed', plaintext, claim_id: claimId, acknowledged };
}
