"""The structured outbound payload, from this side of the socket.

The producer half of ``src/outbound-payload.js``. The broker validates
independently and is the authority — a payload this module builds and the broker
refuses is a defect *here*, and the operator hears about it — so what this module
is for is not enforcement but the two things enforcement cannot do:

1. **Refuse before a drop exists.** The broker's refusal is already atomic (no
   drop, no link, no code), but by then a round trip has been spent and the
   refusal has to be turned back into something a model can act on. Checking the
   same bounds here means the *usual* mistake — a label with a newline in it, a
   value over the ceiling, a ninth field — is answered with the rule it broke and
   the field it broke it on, without touching the broker at all.

2. **Normalise what is safe to normalise, and nothing else.** A label and a title
   are display strings: leading and trailing whitespace is stripped and internal
   runs are collapsed to single spaces, because a model that emitted ``"API  key"``
   meant ``"API key"`` and refusing that is pedantry with no safety behind it.

   A **value is never modified**. Not trimmed, not collapsed, not normalised. A
   password with a trailing space is a different password, and silently repairing
   it would deliver a credential that does not authenticate and give nobody a way
   to find out why. So a padded value is *refused* and the model is told which
   field, which is the one outcome that leads to the right value being sent.

Two implementations of one schema is a drift risk, and it is taken deliberately
rather than by omission: the alternative is this side sending an unvalidated blob
and learning the bounds only from the broker, which puts the error message a round
trip and a language away from the model that has to act on it. The bounds
themselves live in ``contract/control-protocol.json`` →  ``outbound_payload``, the
same shared fixture the control protocol uses, and ``tests/test_outbound_payload.py``
pins every constant below against it *and* runs the real broker over the real
socket to prove the two agree on live payloads rather than only on numbers.

**Nothing here logs.** Every value that passes through this module is a secret,
and every refusal names a rule and a field index — never a label, never a value.
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

#: contract/control-protocol.json -> outbound_payload.version
PAYLOAD_VERSION = 1

#: contract/control-protocol.json -> outbound_payload.bounds
MAX_FIELDS = 8
MAX_LABEL_CHARS = 40
MAX_TITLE_CHARS = 60
MAX_VALUE_BYTES = 512
MAX_PAYLOAD_BYTES = 1536
MAX_NOTE_LINES = 8

#: contract/control-protocol.json -> outbound_payload.types
FIELD_TYPES: Tuple[str, ...] = ("text", "secret", "url", "note")

#: The types a renderer masks. Everything else displays normally.
SENSITIVE_FIELD_TYPES: Tuple[str, ...] = ("secret",)

#: A field with no type gets this one — the masked one. Showing a secret in the
#: clear is the mistake that cannot be taken back, so the default fails closed.
DEFAULT_FIELD_TYPE = "secret"

#: contract/control-protocol.json -> outbound_payload.generate
GENERATE_KINDS: Tuple[str, ...] = ("password", "hex", "base64url")
MIN_GENERATE_LENGTH = 8
MAX_GENERATE_LENGTH = 64

#: What a bare ``generate: {}`` means. A password rather than hex, because the
#: value is going to be pasted into a login form far more often than into a config
#: file, and 24 characters of alphanumeric is past anything a code-gated one-shot
#: link needs to resist.
DEFAULT_GENERATE_KIND = "password"
DEFAULT_GENERATE_LENGTH = 24

#: contract/control-protocol.json -> outbound_payload.reasons. The closed set the
#: broker can answer with, mirrored so this side can name the same rule without a
#: round trip. Pinned against the fixture by the tests.
REFUSAL_REASONS = frozenset(
    {
        "bad_generate",
        "bad_label",
        "bad_title",
        "bad_type",
        "bad_url",
        "bad_value",
        "bad_version",
        "duplicate_label",
        "label_too_long",
        "no_fields",
        "not_an_object",
        "not_json",
        "payload_too_large",
        "title_too_long",
        "too_many_fields",
        "unknown_key",
        "value_too_long",
    }
)

#: One sentence per rule, for a model that has to fix it. Locally authored, so it
#: is safe to put in a tool result (``drop/safe_errors.py``) — and deliberately
#: about the RULE rather than about the value that broke it.
REASON_HELP: Dict[str, str] = {
    "no_fields": f"send between 1 and {MAX_FIELDS} labelled values",
    "too_many_fields": f"send at most {MAX_FIELDS} labelled values",
    "bad_label": (
        "each label must be a short single-line heading with at least one letter or "
        "digit, no tabs or newlines and no padding"
    ),
    "label_too_long": f"each label must be at most {MAX_LABEL_CHARS} characters",
    "duplicate_label": "two values cannot share a label",
    "bad_title": "the title must be a short single-line heading",
    "title_too_long": f"the title must be at most {MAX_TITLE_CHARS} characters",
    "bad_type": f"type must be one of {', '.join(FIELD_TYPES)}",
    "bad_value": (
        "each value must be a non-empty single-line string with no leading or trailing "
        "whitespace, and exactly one of value or generate must be given"
    ),
    "value_too_long": f"each value must be at most {MAX_VALUE_BYTES} bytes",
    "bad_url": "a url value must be an absolute http:// or https:// address",
    "bad_generate": (
        f"generate takes kind ({', '.join(GENERATE_KINDS)}) and length "
        f"({MIN_GENERATE_LENGTH}..{MAX_GENERATE_LENGTH}), and only on a secret"
    ),
    "payload_too_large": (
        f"all the values together must be at most {MAX_PAYLOAD_BYTES} bytes — send fewer "
        "or shorter ones"
    ),
    "unknown_key": "a value takes only label, type, and one of value or generate",
    "not_an_object": "send a list of labelled values",
}

_ROOT_KEYS = frozenset({"v", "title", "fields"})
_FIELD_KEYS = frozenset({"label", "type", "value", "generate"})
_GENERATE_KEYS = frozenset({"kind", "length"})

#: Every Unicode "other" category — control, format, surrogate, private-use,
#: unassigned — plus the line and paragraph separators. ``Cf`` is the load-bearing
#: half: it is where the bidi overrides live, and a label that can reverse its own
#: rendering can make ``Note`` read as ``Password`` beside a value the user is about
#: to paste somewhere. Python's ``re`` has no ``\\p{C}``, so the categories are
#: tested through ``unicodedata`` instead of through a character class.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})

#: Whitespace that is not a plain U+0020 space. Refused everywhere: a non-breaking
#: space in a credential makes two values that look identical authenticate
#: differently, and the user cannot see which they were handed.
_EXOTIC_WHITESPACE = re.compile(r"[^\S ]")
_EXOTIC_WHITESPACE_IN_NOTE = re.compile(r"[^\S \n]")
_WHITESPACE_RUN = re.compile(r"\s+")
_HAS_LETTER_OR_DIGIT = re.compile(r"[^\W_]", re.UNICODE)
_ABSOLUTE_HTTP_URL = re.compile(r"^https?://[^\s/?#]+")


class PayloadRefused(Exception):
    """A payload that must not be sent. Carries a reason code and a field index.

    An exception rather than a result tuple because every caller's response to it
    is identical — refuse the whole request, mint nothing — and the reason has to
    survive a dozen nested checks without each of them threading it upward.
    """

    def __init__(self, reason: str, *, field_index: Optional[int] = None) -> None:
        assert reason in REFUSAL_REASONS, f"undeclared refusal reason: {reason}"
        super().__init__(reason)
        self.reason = reason
        self.field_index = field_index

    @property
    def detail(self) -> str:
        """A sentence for a model, naming the rule and the field — never a value.

        This string reaches the model's context and from there durable session
        state, so it says *field 2* and *value_too_long* and stops. A label would
        be harmless and a value would not, and the line between them is not worth
        depending on: neither is here.
        """
        where = "" if self.field_index is None else f"value {self.field_index + 1}: "
        help_text = REASON_HELP.get(self.reason, "")
        return f"{where}{self.reason}" + (f" — {help_text}" if help_text else "")


def is_sensitive_field_type(field_type: Any) -> bool:
    """True when a renderer must mask this type. Unknown and absent are sensitive."""
    if not isinstance(field_type, str):
        return True
    if field_type not in FIELD_TYPES:
        return True
    return field_type in SENSITIVE_FIELD_TYPES


def _has_forbidden_character(text: str) -> bool:
    return any(unicodedata.category(char) in _FORBIDDEN_CATEGORIES for char in text)


def _normalise_heading(raw: Any, *, max_chars: int, bad: str, too_long: str) -> str:
    """A label or a title: collapsed, stripped, then checked.

    Normalising *before* the length check on purpose — ``"API  key"`` is 8
    characters and ``"API key"`` is 7, and the bound should apply to what will
    actually be rendered.
    """
    if not isinstance(raw, str):
        raise PayloadRefused(bad)
    if _has_forbidden_character(raw):
        raise PayloadRefused(bad)
    if _EXOTIC_WHITESPACE.search(raw):
        raise PayloadRefused(bad)
    collapsed = _WHITESPACE_RUN.sub(" ", raw).strip()
    if not collapsed:
        raise PayloadRefused(bad)
    if len(collapsed) > max_chars:
        raise PayloadRefused(too_long)
    if not _HAS_LETTER_OR_DIGIT.search(collapsed):
        raise PayloadRefused(bad)
    return collapsed


def _check_value(raw: Any, field_type: str, index: int) -> str:
    """A value, checked and returned unchanged. Never normalised — see the header."""
    if not isinstance(raw, str) or not raw:
        raise PayloadRefused("bad_value", field_index=index)
    if len(raw.encode("utf-8")) > MAX_VALUE_BYTES:
        raise PayloadRefused("value_too_long", field_index=index)
    if raw != raw.strip():
        raise PayloadRefused("bad_value", field_index=index)

    if field_type == "note":
        if any(
            unicodedata.category(char) in _FORBIDDEN_CATEGORIES
            for char in raw
            if char != "\n"
        ):
            raise PayloadRefused("bad_value", field_index=index)
        if _EXOTIC_WHITESPACE_IN_NOTE.search(raw):
            raise PayloadRefused("bad_value", field_index=index)
        if len(raw.split("\n")) > MAX_NOTE_LINES:
            raise PayloadRefused("bad_value", field_index=index)
        return raw

    if _has_forbidden_character(raw):
        raise PayloadRefused("bad_value", field_index=index)
    if _EXOTIC_WHITESPACE.search(raw):
        raise PayloadRefused("bad_value", field_index=index)
    if field_type == "url" and not _ABSOLUTE_HTTP_URL.match(raw):
        raise PayloadRefused("bad_url", field_index=index)
    return raw


def _check_generate(raw: Any, field_type: Optional[str], index: int) -> Dict[str, Any]:
    """A generation request, defaulted and bounded.

    The value is drawn by the **broker**, not here, and that is the whole point of
    the mechanism: for the "give me a new password" case the requester never holds
    the secret, so it cannot appear in a tool argument, a model turn or a durable
    transcript. What this function produces is the *request*.
    """
    if not isinstance(raw, Mapping):
        raise PayloadRefused("bad_generate", field_index=index)
    if set(raw) - _GENERATE_KEYS:
        raise PayloadRefused("unknown_key", field_index=index)
    # A generated value is a credential, so a generated field is a `secret` and may
    # not claim to be anything else. One fewer combination to reason about, and the
    # one it removes is "a generated password rendered in the clear".
    if field_type is not None and field_type != "secret":
        raise PayloadRefused("bad_generate", field_index=index)

    kind = raw.get("kind", DEFAULT_GENERATE_KIND)
    if not isinstance(kind, str) or kind not in GENERATE_KINDS:
        raise PayloadRefused("bad_generate", field_index=index)

    length = raw.get("length", DEFAULT_GENERATE_LENGTH)
    # ``bool`` is an ``int`` subclass; ``True`` would otherwise become length 1.
    if isinstance(length, bool) or not isinstance(length, int):
        raise PayloadRefused("bad_generate", field_index=index)
    if not (MIN_GENERATE_LENGTH <= length <= MAX_GENERATE_LENGTH):
        raise PayloadRefused("bad_generate", field_index=index)
    return {"kind": kind, "length": length}


def _check_field(raw: Any, index: int) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise PayloadRefused("bad_label", field_index=index)
    if set(raw) - _FIELD_KEYS:
        raise PayloadRefused("unknown_key", field_index=index)

    try:
        label = _normalise_heading(
            raw.get("label"), max_chars=MAX_LABEL_CHARS, bad="bad_label", too_long="label_too_long"
        )
    except PayloadRefused as refusal:
        raise PayloadRefused(refusal.reason, field_index=index) from None

    declared_type = raw.get("type")
    if declared_type is not None and (
        not isinstance(declared_type, str) or declared_type not in FIELD_TYPES
    ):
        raise PayloadRefused("bad_type", field_index=index)

    has_value = raw.get("value") is not None
    has_generate = raw.get("generate") is not None
    # Exactly one. Both is an ambiguity and neither is a field with nothing in it;
    # refusing beats picking, because picking wrong sends the wrong credential.
    if has_value == has_generate:
        raise PayloadRefused("bad_value", field_index=index)

    if has_generate:
        return {
            "label": label,
            "type": "secret",
            "generate": _check_generate(raw.get("generate"), declared_type, index),
        }

    field_type = declared_type or DEFAULT_FIELD_TYPE
    return {
        "label": label,
        "type": field_type,
        "value": _check_value(raw.get("value"), field_type, index),
    }


def build_outbound_payload(
    fields: Any, *, title: Any = None
) -> Tuple[str, List[str], int]:
    """Build the wire payload. Returns ``(json, labels, generated_count)``.

    ``labels`` comes back so a caller can put them in a receipt — they are
    model-supplied and non-secret, and they are what lets a model say "I sent you
    the login and the password" without holding either. ``generated_count`` is
    there so the same receipt can say a value was generated rather than sent.

    Raises :class:`PayloadRefused`, which is the only failure mode: the payload is
    valid whole or it is nothing. There is no partial acceptance, no dropped field
    and no truncated value — a drop that silently delivered four of five
    credentials would be worse than one that refused, because the user cannot tell.
    """
    if not isinstance(fields, Sequence) or isinstance(fields, (str, bytes)):
        raise PayloadRefused("not_an_object")
    if not fields:
        raise PayloadRefused("no_fields")
    if len(fields) > MAX_FIELDS:
        raise PayloadRefused("too_many_fields")

    checked: List[Dict[str, Any]] = []
    labels: List[str] = []
    seen = set()
    for index, raw in enumerate(fields):
        field = _check_field(raw, index)
        # Case-insensitively unique: two fields under one heading is a user
        # copying the wrong one of them.
        key = field["label"].casefold()
        if key in seen:
            raise PayloadRefused("duplicate_label", field_index=index)
        seen.add(key)
        checked.append(field)
        labels.append(field["label"])

    payload: Dict[str, Any] = {"v": PAYLOAD_VERSION}
    if title is not None:
        payload["title"] = _normalise_heading(
            title, max_chars=MAX_TITLE_CHARS, bad="bad_title", too_long="title_too_long"
        )
    payload["fields"] = checked

    # ``ensure_ascii=False`` so a Cyrillic label costs its own bytes rather than six
    # per character, and the separators so the size checked here is the size sent.
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    # The sum, and it is checked on the encoded bytes rather than estimated: the
    # ceiling that matters is the one the wire applies. Bounding only the parts is
    # how a payload every field of which is legal gets built and then cannot be sent.
    #
    # A generation request is *smaller* on the wire than the value it will become,
    # so this is measured against the payload as it would be if every generated
    # field were already filled in — otherwise a caller could pass the check here
    # and be refused by the broker after generation.
    if len(_worst_case(payload).encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise PayloadRefused("payload_too_large")

    generated = sum(1 for field in checked if "generate" in field)
    return encoded, labels, generated


def _worst_case(payload: Mapping[str, Any]) -> str:
    """The payload as it will be once the broker has filled in every generated field.

    Only the *size* matters, so the placeholder is a run of ``x`` of the requested
    length rather than anything random. This exists because the request
    ``{"kind":"base64url","length":64}`` is longer on the wire than the 64
    characters it becomes for some kinds and shorter for others, and the ceiling has
    to be checked against whichever is larger — the broker validates the filled-in
    payload, and a caller that passed a check here and failed there would have
    learned the bound a round trip away from the model that has to act on it.
    """
    filled = dict(payload)
    filled["fields"] = [
        {"label": field["label"], "type": field["type"], "value": "x" * field["generate"]["length"]}
        if "generate" in field
        else field
        for field in payload["fields"]
    ]
    return json.dumps(filled, ensure_ascii=False, separators=(",", ":"))


__all__ = [
    "DEFAULT_FIELD_TYPE",
    "DEFAULT_GENERATE_KIND",
    "DEFAULT_GENERATE_LENGTH",
    "FIELD_TYPES",
    "GENERATE_KINDS",
    "MAX_FIELDS",
    "MAX_GENERATE_LENGTH",
    "MAX_LABEL_CHARS",
    "MAX_NOTE_LINES",
    "MAX_PAYLOAD_BYTES",
    "MAX_TITLE_CHARS",
    "MAX_VALUE_BYTES",
    "MIN_GENERATE_LENGTH",
    "PAYLOAD_VERSION",
    "REASON_HELP",
    "REFUSAL_REASONS",
    "SENSITIVE_FIELD_TYPES",
    "PayloadRefused",
    "build_outbound_payload",
    "is_sensitive_field_type",
]
