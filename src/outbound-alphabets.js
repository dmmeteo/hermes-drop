// The alphabets the broker generates outbound secrets over.
//
// Its own module so that src/outbound-payload.js — which is bundled into the browser
// page — states its generator kinds in one place while the *characters* stay a
// single table both halves read. There is nothing secret here; it is three strings
// and the reason each is the string it is.
//
// `password` is deliberately alphanumeric and nothing more. Not for entropy — 62
// characters at the 8-character floor is already past what a 3-digit code gate
// bounds, and at the 24-character default it is far past anything online — but for
// *transport*: an outbound secret is read off a page by a person and pasted into a
// shell, a YAML file, a `.env`, or a form. Punctuation in that path is where a
// credential acquires a backslash, gets shell-expanded, breaks an unquoted YAML
// value, or is silently truncated at a `#`. A longer alphanumeric string is strictly
// better than a shorter one with `$` in it, and length is the dial the caller has.
//
// Nothing is excluded for looking similar (no dropping `l`, `1`, `I`, `O`, `0`): the
// value is copied with a button, never transcribed by eye, so ambiguity costs
// nothing and removing characters costs entropy.
export const OUTBOUND_PAYLOAD_ALPHABETS = Object.freeze({
  password: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  hex: '0123456789abcdef',
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
});
