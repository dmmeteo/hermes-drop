// The outbound drop's wire format: the fragment, the AEAD binding and the code
// shape (docs/OUTBOUND_SECRET_DROP_MVP.md).
//
// Isomorphic, like src/hpke-suite.js and for the same reason: the broker seals the
// payload and the browser opens it, so both have to construct the *same* AAD from
// the same code, or a correct claimant would meet an AEAD failure. Nothing here
// imports Node, and nothing here is a secret — it is a format, a label and two
// widths.
import { isBase64Url } from './base64url.js';
import { CAPABILITY_LENGTH } from './hpke-suite.js';

/** AES-256-GCM: the one AEAD `crypto.subtle` has everywhere this page runs. */
export const OUTBOUND_ALG = 'A256GCM';

/** 32-byte key, 12-byte IV — the sizes the algorithm above fixes. */
export const OUTBOUND_KEY_BYTES = 32;
export const OUTBOUND_IV_BYTES = 12;

/** Base64url width of the key, so a fragment can be checked without decoding it. */
export const OUTBOUND_KEY_LENGTH = 43;

/**
 * Code length (MVP, "Approved defaults"): three decimal digits, and not an operator
 * dial. A 2-digit code is deliberately not the default and configurable lengths are
 * a deferred decision, so the number lives in the format both sides implement.
 */
export const OUTBOUND_CODE_DIGITS = 3;

/**
 * Length of a claim id: 16 CSPRNG bytes the *browser* draws, base64url.
 *
 * A non-guessable reservation token. Its job is to say "the same claimant as
 * before" — so a retry is a retry and a second browser is a second browser — and it
 * is deliberately *not* described as non-secret, because for the life of the ack
 * window it carries two powers: it replays the ciphertext, and it is the only thing
 * the acknowledgement checks before the payload is destroyed.
 *
 * So it must be drawn from a CSPRNG, kept inside the page's own session, and never
 * put in a URL, a query string, a log line, an analytics event, a `postMessage` or
 * durable storage. Anyone holding the link *and* this value can destroy the drop
 * before the user reads it. The broker compares it in constant time and refuses a
 * wrong length uniformly rather than throwing (`claimIdMatches` in
 * src/outbound-drop.js).
 */
export const CLAIM_ID_LENGTH = 22;

/**
 * The fragment scheme marker. One link format serves both directions of Hermes
 * Drop, so a page has to be able to tell which one it is holding before it fetches
 * anything — and it cannot ask the server, because the server is never sent the
 * fragment. `r` is for reveal.
 */
export const OUTBOUND_FRAGMENT_SCHEME = 'r';

/** The code shape as a string: fixed width, decimal, leading zeros kept. */
const CODE_PATTERN = new RegExp(`^[0-9]{${OUTBOUND_CODE_DIGITS}}$`);

export function isOutboundCode(value) {
  return typeof value === 'string' && CODE_PATTERN.test(value);
}

/** `r.<capability>.<key>` — the whole fragment, and the only place the key exists. */
export function formatOutboundFragment({ capability, key }) {
  return `${OUTBOUND_FRAGMENT_SCHEME}.${capability}.${key}`;
}

/**
 * Reads an outbound fragment. Anything malformed — including an inbound,
 * capability-only fragment — is `null`, which is what lets one page hold both
 * directions apart without asking a server which one it has.
 */
export function parseOutboundFragment(hash) {
  if (typeof hash !== 'string') return null;
  const value = hash.startsWith('#') ? hash.slice(1) : hash;
  const parts = value.split('.');
  if (parts.length !== 3) return null;
  const [scheme, capability, key] = parts;
  if (scheme !== OUTBOUND_FRAGMENT_SCHEME) return null;
  if (!isBase64Url(capability, CAPABILITY_LENGTH)) return null;
  if (!isBase64Url(key, OUTBOUND_KEY_LENGTH)) return null;
  return { capability, key };
}

/**
 * Additional authenticated data for the payload: the drop this ciphertext belongs
 * to. Ciphertext handed out for one drop therefore cannot be opened as another's
 * even by a holder of both keys, so a broker that mixed two records up would fail
 * closed rather than reveal the wrong secret — and a page that was served someone
 * else's ciphertext gets an AEAD failure rather than a plausible string.
 */
const AAD_LABEL = 'hermes-drop/outbound/v1';

export function outboundAad(dropId) {
  return new TextEncoder().encode(`${AAD_LABEL}.${dropId}`);
}
