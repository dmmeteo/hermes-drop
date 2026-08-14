// The structured outbound payload: what a revealed drop actually contains, and the
// bounds outside which nothing is minted at all.
//
// An outbound drop hands a *person* a credential, and a credential is almost never
// one string: it is a login and a password, or a key and the console it belongs to,
// or a token and a note about rotating it. So the payload is JSON with a list of
// labelled fields and the reveal page renders however many it finds — one, or five,
// or eight (src/client/reveal-view.js).
//
// That makes this module the boundary where an object composed by a *model* crosses
// into a page a user is about to trust, and every rule below exists because of that
// sentence rather than because JSON needs a schema:
//
//   CLOSED SETS      the version, the field types and the generator kinds are
//                    enumerations. A value outside one is refused, never coerced and
//                    never carried through as "some other kind of field" — the page
//                    would then have to decide what to do with it, and the safe
//                    decision is the one made here.
//   SENSITIVE BY     a field with no type, or a type this bundle does not know, is
//   DEFAULT          sensitive. Showing a secret in the clear is the mistake that
//                    cannot be taken back, so the default has to be the mask.
//   NO CONTROL       labels and values are checked for control characters, format
//   CHARACTERS       characters and line/paragraph separators. Not because they
//                    would break the rendering — the page writes `textContent`, so
//                    they cannot — but because a right-to-left override inside a
//                    label makes "Note" render as "Password" next to a value the
//                    user is about to paste somewhere. The page can render text
//                    safely; it cannot render *honestly* if the text lies about its
//                    own direction.
//   BOUNDED SUM      each label, each value, the field count *and the canonical
//                    whole* are bounded. Bounding only the parts is how a payload
//                    every field of which is legal gets minted and then cannot be
//                    sent, because the control request line it has to fit inside is
//                    4096 bytes (src/control-server.js).
//   ATOMIC REFUSAL   a payload is valid or it is nothing. There is no partial
//                    acceptance, no dropped field and no truncated value: a drop
//                    that silently delivered four of five credentials would be
//                    worse than one that refused, because the user cannot tell.
//   REASONS ARE      a refusal comes back as a code from a closed set and never as
//   CODES            prose containing the input. The reason travels to a caller
//                    whose results reach a model's context and from there durable
//                    session state (integrations/hermes-drop/drop/vault.py), so a
//                    reason quoting the offending value would put the secret in the
//                    one place this whole project exists to keep it out of.
//
// Isomorphic, like src/outbound-envelope.js and for the same reason: the broker
// validates on the way in and the page validates on the way out. Nothing here
// imports Node — `crypto.getRandomValues` is the one platform call, and it is
// present in both.
import { OUTBOUND_PAYLOAD_ALPHABETS } from './outbound-alphabets.js';

/** The payload revision. A change to the shape raises this rather than reusing it. */
export const OUTBOUND_PAYLOAD_VERSION = 1;

/**
 * How many fields one drop may carry.
 *
 * Eight is comfortably more than any real credential — login, password, key, URL,
 * note is five — and it is what keeps the canonical whole inside
 * `MAX_PAYLOAD_BYTES` for values of a useful size rather than only for tiny ones.
 */
export const MAX_FIELDS = 8;

/** Label width, in code points. Long enough for "Recovery phrase"; not a sentence. */
export const MAX_LABEL_CHARS = 40;

/** Optional heading width, in code points. */
export const MAX_TITLE_CHARS = 60;

/** Per-value ceiling, in UTF-8 *bytes* — the unit the wire and the AEAD count in. */
export const MAX_VALUE_BYTES = 512;

/**
 * The canonical payload ceiling, in UTF-8 bytes.
 *
 * Sized against the control protocol rather than against taste: the whole
 * `create_outbound_drop` request line is bounded at 4096 bytes and the payload
 * travels inside it as base64 (×4/3), so 1536 bytes of payload is 2048 bytes of
 * base64 and leaves the rest of the line to its own fields with room to spare. It is
 * also inside `MAX_OUTBOUND_PLAINTEXT_BYTES` (2048), which the store enforces
 * independently — two ceilings, and the smaller one is the one a caller meets.
 */
export const MAX_PAYLOAD_BYTES = 1536;

/** How many lines a `note` may hold. A note, not a document. */
export const MAX_NOTE_LINES = 8;

/**
 * The closed type set.
 *
 *   text    — shown normally. A login, an account id, a username.
 *   secret  — masked until the user asks. A password, a token, a key.
 *   url     — shown normally, as *text*. See `isSafeUrlValue` for why not a link.
 *   note    — shown normally, and the one type that may hold newlines.
 */
export const FIELD_TYPES = Object.freeze(['text', 'secret', 'url', 'note']);

/** The types the page masks by default. Everything not in here displays normally. */
export const SENSITIVE_FIELD_TYPES = Object.freeze(['secret']);

/** The type a field with none gets: the masked one. */
export const DEFAULT_FIELD_TYPE = 'secret';

/** The closed generator set (`generate.kind`). */
export const GENERATE_KINDS = Object.freeze(['password', 'hex', 'base64url']);

/** Generated width, in output characters. */
export const MIN_GENERATE_LENGTH = 8;
export const MAX_GENERATE_LENGTH = 64;

/**
 * Every code a refusal can carry, as a closed set.
 *
 * Exported and enumerated rather than left implicit in the branches that produce
 * them, because a `reason` crosses two language boundaries: the broker answers one on
 * the control socket, the plugin turns it into something a model can act on, and the
 * shared fixture (`contract/control-protocol.json` → `outbound_payload.reasons`)
 * publishes the list a foreign client may branch on. A code that exists in the code
 * and not in that list is a client's `default:` branch; one in the list and not in the
 * code is a client handling something that cannot happen. `assertReason` below keeps
 * them the same set.
 */
export const REFUSAL_REASONS = Object.freeze([
  'bad_generate',
  'bad_label',
  'bad_title',
  'bad_type',
  'bad_url',
  'bad_value',
  'bad_version',
  'duplicate_label',
  'label_too_long',
  'no_fields',
  'not_an_object',
  'not_json',
  'payload_too_large',
  'title_too_long',
  'too_many_fields',
  'unknown_key',
  'value_too_long',
]);

const ROOT_KEYS = new Set(['v', 'title', 'fields']);
const FIELD_KEYS = new Set(['label', 'type', 'value', 'generate']);
const GENERATE_KEYS = new Set(['kind', 'length']);

/**
 * Characters no label or value may contain: every Unicode "other" category (control,
 * format, surrogate, private-use, unassigned) plus the line and paragraph
 * separators. `\p{Cf}` is the load-bearing half — it is where the bidi overrides
 * live, and a label that can reverse its own rendering is a label that can lie.
 */
const FORBIDDEN_CHARS = /[\p{C}\p{Zl}\p{Zp}]/u;

/** …and the same set with `\n` carved out, for the one type that may hold lines. */
const FORBIDDEN_CHARS_EXCEPT_LF = /[\p{Zl}\p{Zp}]|(?!\n)[\p{C}]/u;

/**
 * Whitespace that is not a plain U+0020 space — and, for a `note`, not a newline
 * either.
 *
 * An ordinary space is allowed inside a label ("API key") and inside a value (a
 * passphrase is four words). What is refused is every *other* whitespace character:
 * a non-breaking space, a thin space, a tab, a zero-width joiner. Those are the ones
 * that make two credentials look identical and authenticate differently, and a user
 * reading a page has no way to see which they were handed.
 *
 * Leading and trailing whitespace is refused separately (`!== trim()`), rather than
 * trimmed, because a trailing space in a credential is a login failure whose cause is
 * invisible — and silently repairing the producer's mistake means the next one is
 * repaired too, in a case where it changes the value's meaning.
 */
const EXOTIC_WHITESPACE = /[^\S ]/u;
const EXOTIC_WHITESPACE_IN_NOTE = /[^\S \n]/u;

/** Two spaces in a row: a label rendered from it is not the label that was meant. */
const DOUBLE_SPACE = /  /u;

/** A label has to *say* something: at least one letter or digit. */
const HAS_LETTER_OR_DIGIT = /[\p{L}\p{N}]/u;

const utf8Length = (value) => new TextEncoder().encode(value).length;

function refuse(reason) {
  // A reason outside the published set would reach a caller that has no branch for
  // it, so it is a defect here rather than something to forward. Throwing is safe
  // because it is unreachable except by editing this module: every call site passes
  // a literal or a value from one of the two problem helpers.
  if (!REFUSAL_REASONS.includes(reason)) throw new Error(`undeclared refusal reason: ${reason}`);
  return { ok: false, reason };
}

/** True when the page must mask this type. Unknown and absent are both sensitive. */
export function isSensitiveFieldType(type) {
  if (typeof type !== 'string') return true;
  if (!FIELD_TYPES.includes(type)) return true;
  return SENSITIVE_FIELD_TYPES.includes(type);
}

/**
 * An absolute `http`/`https` URL, and nothing else.
 *
 * The scheme allowlist is checked on the *parsed* protocol rather than on the raw
 * string, so `JAVASCRIPT:` and a scheme reached through case or whitespace tricks
 * are refused by the same line. A hostname is required, which is what rejects
 * `https://` and `file:///…`.
 *
 * Worth stating what this does **not** license: the reveal page renders a `url` as
 * text with a Copy button, never as an anchor. A validated scheme keeps a
 * `javascript:` URI out, but it cannot make a link to an attacker's host safe to
 * *offer* — and a clickable link inside a page the user has been told is their
 * secure drop borrows that page's credibility for whatever it points at. The
 * validation is here so a malformed URL is caught at the seam rather than rendered;
 * the decision not to make it clickable is the page's, and it is deliberate.
 */
export function isSafeUrlValue(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
  return parsed.hostname.length > 0;
}

/**
 * The rules a heading has to satisfy: single line, no exotic whitespace, no
 * padding, and at least one letter or digit so it says something. Shared by
 * `label` and `title`, which differ only in their ceiling and in the code they
 * refuse under.
 */
function headingProblem(value, maxChars) {
  if (typeof value !== 'string' || value.length === 0) return 'bad';
  if ([...value].length > maxChars) return 'too_long';
  if (FORBIDDEN_CHARS.test(value)) return 'bad';
  if (EXOTIC_WHITESPACE.test(value)) return 'bad';
  if (DOUBLE_SPACE.test(value)) return 'bad';
  if (value !== value.trim()) return 'bad';
  if (!HAS_LETTER_OR_DIGIT.test(value)) return 'bad';
  return null;
}

function validateLabel(label) {
  const problem = headingProblem(label, MAX_LABEL_CHARS);
  if (problem === 'too_long') return 'label_too_long';
  return problem ? 'bad_label' : null;
}

function validateTitle(title) {
  const problem = headingProblem(title, MAX_TITLE_CHARS);
  if (problem === 'too_long') return 'title_too_long';
  return problem ? 'bad_title' : null;
}

function validateValue(value, type) {
  if (typeof value !== 'string' || value.length === 0) return 'bad_value';
  if (utf8Length(value) > MAX_VALUE_BYTES) return 'value_too_long';
  if (value !== value.trim()) return 'bad_value';

  if (type === 'note') {
    if (FORBIDDEN_CHARS_EXCEPT_LF.test(value)) return 'bad_value';
    if (EXOTIC_WHITESPACE_IN_NOTE.test(value)) return 'bad_value';
    if (value.split('\n').length > MAX_NOTE_LINES) return 'bad_value';
    return null;
  }

  if (FORBIDDEN_CHARS.test(value)) return 'bad_value';
  if (EXOTIC_WHITESPACE.test(value)) return 'bad_value';
  // A URL with a space in it is not a URL; checked before the parse so the code
  // that comes back names the field's own rule rather than the parser's.
  if (type === 'url' && value.includes(' ')) return 'bad_url';
  if (type === 'url' && !isSafeUrlValue(value)) return 'bad_url';
  return null;
}

/** Rejects a key the schema does not name, including anything off the prototype. */
function unknownKey(object, allowed) {
  for (const key of Object.keys(object)) {
    if (!allowed.has(key)) return true;
  }
  return false;
}

/**
 * Validates one field. `generate` is *rejected* here — this is the validator the
 * page and the store both run, and by the time a payload reaches either, every
 * generated value has already been materialised (`buildOutboundPayload`). Leaving
 * `generate` acceptable would mean a page could be handed a field with no value.
 */
function validateField(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return refuse('bad_label');
  if (unknownKey(input, FIELD_KEYS)) return refuse('unknown_key');
  if ('generate' in input) return refuse('bad_value');

  const labelError = validateLabel(input.label);
  if (labelError) return refuse(labelError);

  const type = input.type === undefined ? DEFAULT_FIELD_TYPE : input.type;
  if (typeof type !== 'string' || !FIELD_TYPES.includes(type)) return refuse('bad_type');

  const valueError = validateValue(input.value, type);
  if (valueError) return refuse(valueError);

  return { ok: true, field: { label: input.label, type, value: input.value } };
}

/**
 * The whole check, in the order a reader should think about it: shape, then version,
 * then the field list, then each field, then the sum.
 *
 * `{ ok: true, payload }` hands back a *new* object holding only the keys the schema
 * names, in the order `canonicalizeOutboundPayload` emits them. Nothing from the
 * input object survives by reference, so a getter, a prototype trick or an extra key
 * on the caller's object cannot reach the store or the page.
 */
export function validateOutboundPayload(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return refuse('not_an_object');
  if (unknownKey(input, ROOT_KEYS)) return refuse('unknown_key');
  // `!== VERSION` rather than a range check: a version this bundle does not
  // implement is not a payload it may guess at.
  if (input.v !== OUTBOUND_PAYLOAD_VERSION) return refuse('bad_version');

  let title;
  if (input.title !== undefined) {
    const titleError = validateTitle(input.title);
    if (titleError) return refuse(titleError);
    title = input.title;
  }

  if (!Array.isArray(input.fields) || input.fields.length === 0) return refuse('no_fields');
  if (input.fields.length > MAX_FIELDS) return refuse('too_many_fields');

  const fields = [];
  const seen = new Set();
  for (const candidate of input.fields) {
    const checked = validateField(candidate);
    if (!checked.ok) return checked;
    // Case-insensitively unique, because two fields rendering under the same
    // heading is a user pasting the wrong one of them.
    const key = checked.field.label.toLowerCase();
    if (seen.has(key)) return refuse('duplicate_label');
    seen.add(key);
    fields.push(checked.field);
  }

  const payload = title === undefined ? { v: OUTBOUND_PAYLOAD_VERSION, fields } : { v: OUTBOUND_PAYLOAD_VERSION, title, fields };
  // The sum, checked last and on the canonical bytes rather than on an estimate:
  // the ceiling that matters is the one the wire applies.
  if (utf8Length(canonicalizeOutboundPayload(payload)) > MAX_PAYLOAD_BYTES) {
    return refuse('payload_too_large');
  }
  return { ok: true, payload };
}

/**
 * The bytes a drop stores: a fixed key order, no whitespace, no incidental keys.
 *
 * Deterministic because the payload is sealed under an AEAD and handed to exactly
 * one browser: two encodings of "the same payload" would be two different
 * ciphertexts, which is not wrong but is untestable. Built by hand rather than by
 * `JSON.stringify(payload)` so the order is stated here rather than inherited from
 * whatever order the validator happened to assign.
 */
export function canonicalizeOutboundPayload(payload) {
  const fields = payload.fields.map(
    (field) =>
      `{"label":${JSON.stringify(field.label)},"type":${JSON.stringify(field.type)},` +
      `"value":${JSON.stringify(field.value)}}`,
  );
  const title = payload.title === undefined ? '' : `"title":${JSON.stringify(payload.title)},`;
  return `{"v":${payload.v},${title}"fields":[${fields.join(',')}]}`;
}

/**
 * Reads a revealed payload back. The page's entry point, and the only one that ever
 * sees text of unknown provenance.
 *
 * The length check is *before* the parse and that ordering is the point: a page that
 * parsed first would do the work on whatever it was handed, and a broker of a
 * version this bundle does not know is exactly the case where the text may not be
 * what the schema says. It never throws — a malformed payload is a rendering
 * decision, not an exception.
 */
export function parseOutboundPayload(text) {
  if (typeof text !== 'string') return refuse('not_json');
  if (utf8Length(text) > MAX_PAYLOAD_BYTES) return refuse('payload_too_large');
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return refuse('not_json');
  }
  return validateOutboundPayload(parsed);
}

/**
 * A CSPRNG string of `length` characters over `alphabet`, rejection-sampled.
 *
 * Rejection sampling rather than `byte % alphabet.length`: a modulo over 256 is
 * biased for every alphabet whose size does not divide it, and "slightly biased
 * password" is not a thing worth shipping when the fix is a loop.
 */
function randomString(alphabet, length) {
  const limit = 256 - (256 % alphabet.length);
  const out = [];
  const buffer = new Uint8Array(length * 2);
  while (out.length < length) {
    crypto.getRandomValues(buffer);
    for (const byte of buffer) {
      if (out.length === length) break;
      if (byte >= limit) continue;
      out.push(alphabet[byte % alphabet.length]);
    }
  }
  buffer.fill(0);
  return out.join('');
}

function materializeGenerated(field) {
  const request = field.generate;
  if (!request || typeof request !== 'object' || Array.isArray(request)) return refuse('bad_generate');
  if (unknownKey(request, GENERATE_KEYS)) return refuse('unknown_key');
  // Generation produces a credential, so a generated field is a `secret` and may
  // not claim to be anything else. One fewer combination to reason about, and the
  // combination it removes is "a generated password rendered in the clear".
  if (field.type !== undefined && field.type !== 'secret') return refuse('bad_generate');
  if (typeof request.kind !== 'string' || !GENERATE_KINDS.includes(request.kind)) {
    return refuse('bad_generate');
  }
  if (
    typeof request.length !== 'number' ||
    !Number.isInteger(request.length) ||
    request.length < MIN_GENERATE_LENGTH ||
    request.length > MAX_GENERATE_LENGTH
  ) {
    return refuse('bad_generate');
  }
  return {
    ok: true,
    field: {
      label: field.label,
      type: 'secret',
      value: randomString(OUTBOUND_PAYLOAD_ALPHABETS[request.kind], request.length),
    },
  };
}

/**
 * Validation *plus* generation: the broker's entry point for a structured payload.
 *
 * A field may carry a `value` or a `generate` request and never both. A generated
 * value is drawn here, on the broker, which is the whole point of the mechanism:
 * for the "give me a new password" case the requester never holds the secret at all,
 * so it cannot appear in a tool argument, a model turn or a durable transcript. The
 * value's life starts inside this call and ends when the drop is claimed.
 *
 * The generated fields are materialised first and the *whole* payload is then run
 * through `validateOutboundPayload`, so a generated value is bound by exactly the
 * same label rules, per-value ceiling and canonical sum as one that was handed in.
 * There is no path by which generation can produce a payload the validator would
 * have refused.
 */
export function buildOutboundPayload(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return refuse('not_an_object');
  if (!Array.isArray(input.fields)) return validateOutboundPayload(input);
  if (!input.fields.some((field) => field && typeof field === 'object' && 'generate' in field)) {
    return validateOutboundPayload(input);
  }

  const fields = [];
  for (const candidate of input.fields) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      return refuse('bad_label');
    }
    if (unknownKey(candidate, FIELD_KEYS)) return refuse('unknown_key');
    const hasValue = candidate.value !== undefined;
    const hasGenerate = candidate.generate !== undefined;
    // Exactly one. Both is an ambiguity ("which did you mean?") and neither is a
    // field with nothing in it; refusing beats picking.
    if (hasValue === hasGenerate) return refuse('bad_value');
    if (!hasGenerate) {
      fields.push(candidate);
      continue;
    }
    const labelError = validateLabel(candidate.label);
    if (labelError) return refuse(labelError);
    const materialized = materializeGenerated(candidate);
    if (!materialized.ok) return materialized;
    fields.push(materialized.field);
  }

  return validateOutboundPayload({ ...input, fields });
}
