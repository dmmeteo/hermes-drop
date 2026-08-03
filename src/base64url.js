// Unpadded base64url, isomorphic (browser + Node) — uses only btoa/atob so the
// same module can be bundled for the browser and imported by the broker.

const BASE64URL = /^[A-Za-z0-9_-]*$/;

export function bytesToBase64Url(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let i = 0; i < view.length; i += 1) binary += String.fromCharCode(view[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Strict decoder: rejects padding, whitespace and non-base64url characters. */
export function base64UrlToBytes(value) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) {
    throw new TypeError('not unpadded base64url');
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function isBase64Url(value, expectedLength) {
  if (typeof value !== 'string' || !BASE64URL.test(value) || value.length === 0) return false;
  return expectedLength === undefined || value.length === expectedLength;
}
