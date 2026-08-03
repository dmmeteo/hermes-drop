// Browser-facing handoff client: the exact code the page runs to fetch metadata,
// seal one HPKE envelope and submit it once. Kept free of DOM references so the
// runtime smoke test can drive the real client logic from Node.
//
// Rules encoded here:
//   - the capability travels in a request header, never in a path or query;
//   - plaintext is sealed before it reaches any request body;
//   - `info` is rebuilt locally from the capability and handoff id, so a stolen
//     envelope cannot be replayed into another handoff;
//   - only the one allowlisted suite is accepted from metadata.
import { base64UrlToBytes, bytesToBase64Url, isBase64Url } from '../base64url.js';
import {
  CAPABILITY_LENGTH,
  EMPTY_AAD,
  ENVELOPE_VERSION,
  PUBLIC_KEY_BYTES,
  SUITE_ID,
  buildInfo,
  capabilityHash,
  createSuite,
  publicKeyFingerprint,
  utf8,
} from '../hpke-suite.js';

export const CAPABILITY_HEADER = 'X-Handoff-Capability';
export const METADATA_PATH = '/api/metadata';
export const SUBMIT_PATH = '/api/submit';

/** Reads the capability out of a `#fragment`. Anything malformed is treated as absent. */
export function readCapability(hash) {
  if (typeof hash !== 'string') return null;
  const value = hash.startsWith('#') ? hash.slice(1) : hash;
  return isBase64Url(value, CAPABILITY_LENGTH) ? value : null;
}

export async function fetchMetadata({ capability, fetchImpl = fetch, origin = '' }) {
  const response = await fetchImpl(`${origin}${METADATA_PATH}`, {
    method: 'POST',
    headers: { [CAPABILITY_HEADER]: capability },
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  });
  if (!response.ok) return null;

  const metadata = await response.json();
  if (metadata.v !== ENVELOPE_VERSION || metadata.suite !== SUITE_ID) return null;
  if (!isBase64Url(metadata.hid) || !isBase64Url(metadata.pk)) return null;
  if (base64UrlToBytes(metadata.pk).length !== PUBLIC_KEY_BYTES) return null;
  return metadata;
}

/**
 * One RFC 9180 single-shot SealBase over the whole payload. No caller-chosen
 * nonce exists in this construction, and `aad` stays empty (RFC 9180 §8.1).
 */
export async function sealEnvelope({ capability, metadata, plaintext }) {
  const suite = createSuite();
  const publicKeyBytes = base64UrlToBytes(metadata.pk);
  const recipientPublicKey = await suite.kem.deserializePublicKey(publicKeyBytes);
  const info = buildInfo({
    handoffId: metadata.hid,
    capabilityHash: await capabilityHash(capability),
  });

  const pt = utf8(plaintext);
  try {
    const { ct, enc } = await suite.seal({ recipientPublicKey, info }, pt, EMPTY_AAD);
    return {
      v: ENVELOPE_VERSION,
      suite: SUITE_ID,
      hid: metadata.hid,
      enc: bytesToBase64Url(new Uint8Array(enc)),
      ct: bytesToBase64Url(new Uint8Array(ct)),
      pkfp: bytesToBase64Url(await publicKeyFingerprint(publicKeyBytes)),
    };
  } finally {
    pt.fill(0);
  }
}

/** Transient at the transport layer: worth resending the identical envelope for. */
function isTransient(status) {
  return status === 502 || status === 503 || status === 504 || status === 429;
}

/**
 * Submits one already-sealed envelope, retrying the *same bytes* once if the
 * transport fails. Retrying is safe because the broker answers an identical
 * envelope idempotently, and re-sealing is deliberately not an option: a fresh
 * Seal would be a different envelope and would be refused if the first attempt
 * actually landed.
 *
 * Returns 'received' (definitive success), 'unavailable' (definitive refusal) or
 * 'unreachable' (no answer — the caller must keep the plaintext and may resend
 * these exact bytes).
 */
export async function submitEnvelope({
  capability,
  envelope,
  fetchImpl = fetch,
  origin = '',
  retries = 1,
  retryDelayMs = 250,
}) {
  const body = JSON.stringify(envelope);

  for (let attempt = 0; ; attempt += 1) {
    let response;
    try {
      response = await fetchImpl(`${origin}${SUBMIT_PATH}`, {
        method: 'POST',
        headers: {
          [CAPABILITY_HEADER]: capability,
          'content-type': 'application/json',
        },
        body,
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
      });
    } catch {
      response = null; // network-level failure
    }

    if (response?.ok) return 'received';
    if (response && !isTransient(response.status)) return 'unavailable';
    if (attempt >= retries) return 'unreachable';
    if (retryDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }
}

/** Measures the payload the way the broker will: UTF-8 bytes, not characters. */
export function plaintextByteLength(plaintext) {
  return utf8(plaintext).length;
}

/**
 * The whole browser-side flow. Returns a coarse status only; the caller never
 * learns why a handoff was unavailable, matching the server's single contract.
 */
export async function sendSecret({ capability, plaintext, fetchImpl = fetch, origin = '' }) {
  if (!capability) return { status: 'unavailable' };

  let metadata;
  try {
    metadata = await fetchMetadata({ capability, fetchImpl, origin });
  } catch {
    return { status: 'unreachable' };
  }
  if (!metadata) return { status: 'unavailable' };

  if (plaintextByteLength(plaintext) > metadata.max_plaintext_bytes) {
    return { status: 'too_large', limit: metadata.max_plaintext_bytes };
  }

  const envelope = await sealEnvelope({ capability, metadata, plaintext });
  const outcome = await submitEnvelope({ capability, envelope, fetchImpl, origin });
  if (outcome === 'received') return { status: 'sent' };
  return { status: outcome === 'unreachable' ? 'unreachable' : 'unavailable' };
}
