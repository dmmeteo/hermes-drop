"""The structured payload, from this side — and the two languages agreeing on it.

Two implementations of one schema is a drift risk taken deliberately
(``drop/outbound_payload.py`` says why), so this file is where the risk is paid for.
It has three layers, and the third is the one that matters:

1. Every bound is pinned against ``contract/control-protocol.json``, the shared
   fixture both languages read. A constant that drifts fails here.
2. Every rule is exercised locally, so the usual model mistake is answered without a
   round trip and with the rule it broke named.
3. **The real Node broker is booted and asked.** Numbers agreeing proves nothing about
   behaviour, so every payload this side accepts is sent over a real AF_UNIX socket to
   the real validator, and every payload this side refuses is sent too — because the
   dangerous drift is not "we both refuse it" but "we accept it and they don't", and
   its mirror, "we refuse what they would have taken".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import load_plugin_package

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def payload_module():
    return load_plugin_package().drop.outbound_payload


@pytest.fixture(scope="module")
def contract():
    return json.loads((REPO_ROOT / "contract" / "control-protocol.json").read_text("utf-8"))


def canon_fields():
    return [
        {"label": "Login", "type": "text", "value": "ops@example.test"},
        {"label": "Password", "type": "secret", "value": "example-not-a-real-secret"},
        {"label": "API key", "type": "secret", "value": "sk-example-not-a-real-key"},
        {"label": "Console", "type": "url", "value": "https://openrouter.test/keys"},
        {"label": "Note", "type": "note", "value": "Rotate within 30 days."},
    ]


# ── 1. the numbers, against the shared fixture ─────────────────────────────


def test_every_bound_matches_the_shared_fixture(payload_module, contract) -> None:
    bounds = contract["outbound_payload"]["bounds"]
    assert payload_module.PAYLOAD_VERSION == contract["outbound_payload"]["version"]
    assert payload_module.MAX_FIELDS == bounds["max_fields"]
    assert payload_module.MAX_LABEL_CHARS == bounds["max_label_chars"]
    assert payload_module.MAX_TITLE_CHARS == bounds["max_title_chars"]
    assert payload_module.MAX_VALUE_BYTES == bounds["max_value_bytes"]
    assert payload_module.MAX_PAYLOAD_BYTES == bounds["max_payload_bytes"]
    assert payload_module.MAX_NOTE_LINES == bounds["max_note_lines"]


def test_the_types_and_the_generator_kinds_match_the_fixture(payload_module, contract) -> None:
    assert set(payload_module.FIELD_TYPES) == set(contract["outbound_payload"]["types"])
    assert "masked" in contract["outbound_payload"]["types"]["secret"].lower()
    for kind in payload_module.GENERATE_KINDS:
        assert kind in contract["outbound_payload"]["generate"]


def test_the_reason_codes_match_the_fixture(payload_module, contract) -> None:
    """The vocabulary a caller may branch on, in one list rather than two."""
    assert payload_module.REFUSAL_REASONS == set(contract["outbound_payload"]["reasons"])


def test_an_unknown_type_is_sensitive_and_so_is_a_missing_one(payload_module) -> None:
    # Fail closed: a renderer that does not recognise a type must mask, because
    # showing a secret in the clear is the mistake that cannot be taken back.
    assert payload_module.is_sensitive_field_type("secret") is True
    assert payload_module.is_sensitive_field_type("text") is False
    assert payload_module.is_sensitive_field_type("something-new") is True
    assert payload_module.is_sensitive_field_type(None) is True
    assert payload_module.DEFAULT_FIELD_TYPE == "secret"


# ── 2. the rules, locally ──────────────────────────────────────────────────


def test_the_canon_example_builds(payload_module) -> None:
    encoded, labels, generated = payload_module.build_outbound_payload(
        canon_fields(), title="OpenRouter access"
    )
    assert labels == ["Login", "Password", "API key", "Console", "Note"]
    assert generated == 0
    payload = json.loads(encoded)
    assert payload["v"] == 1
    assert payload["title"] == "OpenRouter access"
    assert [field["type"] for field in payload["fields"]] == [
        "text",
        "secret",
        "secret",
        "url",
        "note",
    ]


def test_a_missing_type_becomes_secret(payload_module) -> None:
    encoded, _labels, _generated = payload_module.build_outbound_payload(
        [{"label": "Token", "value": "abc"}]
    )
    assert json.loads(encoded)["fields"][0]["type"] == "secret"


def test_a_label_is_normalised_and_a_value_is_never_touched(payload_module) -> None:
    """The one asymmetry in the module, and the reason for it."""
    encoded, labels, _generated = payload_module.build_outbound_payload(
        [{"label": "  API   key  ", "type": "text", "value": "kept as sent"}],
        title="  Two   words  ",
    )
    payload = json.loads(encoded)
    # A label is a display string: collapsed and stripped, because a model that
    # wrote "API  key" meant "API key".
    assert labels == ["API key"]
    assert payload["title"] == "Two words"
    # A value is a credential: byte for byte what was sent, spaces included.
    assert payload["fields"][0]["value"] == "kept as sent"


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ([], "no_fields"),
        ("not a list", "not_an_object"),
        ([{"label": "A", "value": "x"}] * 9, "too_many_fields"),
        ([{"label": "", "value": "x"}], "bad_label"),
        ([{"label": "***", "value": "x"}], "bad_label"),
        ([{"label": "A\nB", "value": "x"}], "bad_label"),
        ([{"label": "A‮B", "value": "x"}], "bad_label"),
        ([{"label": "A B", "value": "x"}], "bad_label"),
        ([{"label": "L" * 41, "value": "x"}], "label_too_long"),
        ([{"label": "A", "type": "html", "value": "x"}], "bad_type"),
        ([{"label": "A", "value": ""}], "bad_value"),
        ([{"label": "A", "value": " padded"}], "bad_value"),
        ([{"label": "A", "value": "padded "}], "bad_value"),
        ([{"label": "A", "value": "tab\there"}], "bad_value"),
        ([{"label": "A", "value": "nbsp here"}], "bad_value"),
        ([{"label": "A", "value": "v" * 513}], "value_too_long"),
        ([{"label": "A", "type": "url", "value": "javascript:alert(1)"}], "bad_url"),
        ([{"label": "A", "type": "url", "value": "example.test"}], "bad_url"),
        ([{"label": "A", "type": "url", "value": "https://"}], "bad_url"),
        ([{"label": "A", "type": "note", "value": "x\n" * 9}], "bad_value"),
        ([{"label": "A", "value": "x", "extra": 1}], "unknown_key"),
        ([{"label": "A"}], "bad_value"),
        ([{"label": "A", "value": "x", "generate": {}}], "bad_value"),
        ([{"label": "A", "value": "x"}, {"label": "a", "value": "y"}], "duplicate_label"),
        ([{"label": "A", "type": "text", "generate": {}}], "bad_generate"),
        ([{"label": "A", "generate": {"kind": "uuid"}}], "bad_generate"),
        ([{"label": "A", "generate": {"length": 7}}], "bad_generate"),
        ([{"label": "A", "generate": {"length": 65}}], "bad_generate"),
        ([{"label": "A", "generate": {"length": True}}], "bad_generate"),
        ([{"label": "A", "generate": {"kind": "hex", "length": 16, "x": 1}}], "unknown_key"),
        ([{"label": "A", "generate": "hex"}], "bad_generate"),
        ([{"label": f"F{i}", "value": "v" * 460} for i in range(4)], "payload_too_large"),
    ],
)
def test_each_rule_refuses_with_its_own_reason(payload_module, fields, reason) -> None:
    with pytest.raises(payload_module.PayloadRefused) as caught:
        payload_module.build_outbound_payload(fields)
    assert caught.value.reason == reason


@pytest.mark.parametrize(
    ("title", "reason"),
    [("", "bad_title"), ("   ", "bad_title"), ("T" * 61, "title_too_long"), (42, "bad_title")],
)
def test_a_bad_title_refuses_the_whole_payload(payload_module, title, reason) -> None:
    with pytest.raises(payload_module.PayloadRefused) as caught:
        payload_module.build_outbound_payload([{"label": "A", "value": "x"}], title=title)
    assert caught.value.reason == reason


def test_a_refusal_names_the_field_and_the_rule_and_never_the_value(payload_module) -> None:
    """The detail reaches the model's context and durable state. It says the rule."""
    with pytest.raises(payload_module.PayloadRefused) as caught:
        payload_module.build_outbound_payload(
            [
                {"label": "Login", "type": "text", "value": "ops@example.test"},
                {"label": "Password", "value": "example-not-a-real-secret-xyzzy "},
            ]
        )
    detail = caught.value.detail
    assert caught.value.field_index == 1
    assert "value 2" in detail
    assert "bad_value" in detail
    assert "xyzzy" not in detail
    assert "Password" not in detail


def test_a_generated_field_asks_rather_than_carries(payload_module) -> None:
    encoded, labels, generated = payload_module.build_outbound_payload(
        [
            {"label": "Login", "type": "text", "value": "ops@example.test"},
            {"label": "Password", "type": "secret", "generate": {}},
        ]
    )
    payload = json.loads(encoded)
    assert generated == 1
    assert labels == ["Login", "Password"]
    # No value anywhere in the request: the whole point is that the requester never
    # holds it, so there is nothing here for a transcript to keep.
    assert "value" not in payload["fields"][1]
    assert payload["fields"][1]["generate"] == {
        "kind": payload_module.DEFAULT_GENERATE_KIND,
        "length": payload_module.DEFAULT_GENERATE_LENGTH,
    }
    assert payload["fields"][1]["type"] == "secret"


def test_the_size_ceiling_is_measured_against_the_filled_in_payload(payload_module) -> None:
    """A generation request is smaller on the wire than the value it becomes.

    Measuring the *request* would let a payload through here that the broker refuses
    after generating — the bound learned a round trip and a language away from the
    model that has to act on it. So the ceiling is applied to the payload as it will
    be once every generated field is filled in.

    At the bounds as they stand the two measurements cannot actually straddle the
    ceiling: eight fields at 64 generated characters is ~850 bytes filled, well under
    1536, and the per-value cap is too low to close the gap. This is therefore
    defence for a future in which ``MAX_FIELDS``, ``MAX_VALUE_BYTES`` or a longer
    generator kind changes that — which is exactly the kind of change that would
    otherwise be discovered as a broker refusal in production.
    """
    request, _labels, _generated = payload_module.build_outbound_payload(
        [{"label": "Key", "type": "secret", "generate": {"kind": "base64url", "length": 64}}]
    )
    filled = payload_module._worst_case(json.loads(request))
    assert len(filled.encode()) > len(request.encode()), "the filled payload is the larger"
    assert '"value"' in filled and '"generate"' not in filled

    # ...and the ceiling itself is real, on the measurement that is taken.
    with pytest.raises(payload_module.PayloadRefused) as caught:
        payload_module.build_outbound_payload(
            [
                {"label": f"Field {i}", "value": "v" * payload_module.MAX_VALUE_BYTES}
                for i in range(3)
            ]
        )
    assert caught.value.reason == "payload_too_large"


def test_non_ascii_labels_and_values_are_accepted(payload_module) -> None:
    encoded, labels, _generated = payload_module.build_outbound_payload(
        [{"label": "Логін", "type": "text", "value": "оператор"}]
    )
    assert labels == ["Логін"]
    # ``ensure_ascii=False`` so a Cyrillic label costs its own bytes, not six each —
    # which is what keeps the byte ceiling meaningful for non-English users.
    assert "Логін" in encoded


# ── 3. the two languages, over a real socket ───────────────────────────────


@pytest.mark.asyncio
async def test_the_real_broker_accepts_everything_this_side_builds(
    plugin_module, real_broker
) -> None:
    """Every payload this side accepts, sent to the real validator.

    This is the assertion the whole two-implementation arrangement rests on. Numbers
    matching is necessary and not sufficient: the interesting drift is a rule one side
    reads differently, and only a live payload finds that.
    """
    control = plugin_module.drop.control_client
    payload_mod = plugin_module.drop.outbound_payload

    accepted = [
        (canon_fields(), "OpenRouter access"),
        ([{"label": "Token", "value": "abc"}], None),
        ([{"label": "API key", "type": "secret", "value": "sk-x"}], None),
        ([{"label": "Логін", "type": "text", "value": "оператор"}], "Український доступ"),
        ([{"label": "Pass phrase", "value": "correct horse battery staple"}], None),
        ([{"label": "Note", "type": "note", "value": "one\ntwo\nthree"}], None),
        ([{"label": "L" * payload_mod.MAX_LABEL_CHARS, "value": "x"}], None),
        ([{"label": "Max", "value": "v" * payload_mod.MAX_VALUE_BYTES}], None),
        ([{"label": "Gen", "type": "secret", "generate": {"kind": "hex", "length": 64}}], None),
        (
            [{"label": f"Field {i}", "value": "v"} for i in range(payload_mod.MAX_FIELDS)],
            "T" * payload_mod.MAX_TITLE_CHARS,
        ),
    ]

    for fields, title in accepted:
        encoded, _labels, _generated = payload_mod.build_outbound_payload(fields, title=title)
        answer = await control.create_outbound_drop(
            payload_json=encoded, ttl_seconds=60, socket_path=real_broker.socket_path
        )
        assert answer.get("ok") is True, (fields, answer)
        assert answer["payload_format"] == "structured"
        assert answer["field_count"] == len(fields)
        # ...and the capability check the service performs before posting.
        assert control.supports_outbound_drop(answer) is True


@pytest.mark.asyncio
async def test_the_real_broker_also_refuses_everything_this_side_refuses(
    plugin_module, real_broker
) -> None:
    """The mirror, and the half that is easy to forget.

    A payload this side refuses and the broker would have accepted is a bound this
    plugin invented — a refusal the user did not have to meet. So each refusal is sent
    raw, bypassing the builder, and the broker has to refuse it with the *same* reason
    code this side chose.
    """
    control = plugin_module.drop.control_client
    payload_mod = plugin_module.drop.outbound_payload

    cases = [
        ({"v": 1, "fields": []}, "no_fields"),
        ({"v": 2, "fields": [{"label": "A", "value": "x"}]}, "bad_version"),
        ({"v": 1, "fields": [{"label": "", "type": "secret", "value": "x"}]}, "bad_label"),
        ({"v": 1, "fields": [{"label": "A‮B", "type": "secret", "value": "x"}]}, "bad_label"),
        ({"v": 1, "fields": [{"label": "A B", "type": "secret", "value": "x"}]}, "bad_label"),
        ({"v": 1, "fields": [{"label": "A", "type": "html", "value": "x"}]}, "bad_type"),
        ({"v": 1, "fields": [{"label": "A", "type": "secret", "value": " x"}]}, "bad_value"),
        ({"v": 1, "fields": [{"label": "A", "type": "secret", "value": "x y"}]}, "bad_value"),
        (
            {"v": 1, "fields": [{"label": "A", "type": "url", "value": "javascript:alert(1)"}]},
            "bad_url",
        ),
        ({"v": 1, "fields": [{"label": "A", "type": "secret", "value": "x", "z": 1}]}, "unknown_key"),
        (
            {
                "v": 1,
                "fields": [
                    {"label": "A", "type": "secret", "value": "x"},
                    {"label": "a", "type": "secret", "value": "y"},
                ],
            },
            "duplicate_label",
        ),
        (
            {
                "v": 1,
                "fields": [
                    {"label": f"F{i}", "type": "secret", "value": "v" * 460} for i in range(4)
                ],
            },
            "payload_too_large",
        ),
        (
            {"v": 1, "title": "  ", "fields": [{"label": "A", "type": "secret", "value": "x"}]},
            "bad_title",
        ),
        (
            {
                "v": 1,
                "fields": [{"label": "L" * 41, "type": "secret", "value": "x"}],
            },
            "label_too_long",
        ),
    ]

    for payload, reason in cases:
        answer = await control.create_outbound_drop(
            payload_json=json.dumps(payload), socket_path=real_broker.socket_path
        )
        assert answer == {"ok": False, "error": "invalid_request", "reason": reason}, payload
        assert reason in payload_mod.REFUSAL_REASONS
        # Atomic: no drop, no link, no code on the way out.
        for key in ("drop_id", "url", "code"):
            assert key not in answer


@pytest.mark.asyncio
async def test_the_broker_reveals_exactly_the_bytes_this_side_built(
    plugin_module, real_public_broker
) -> None:
    """One end-to-end round trip through the real store, out to the real page client.

    The bytes are read back the way the browser reads them — claim, then decrypt with
    the key from the URL fragment — so this proves the payload survives the AEAD and
    the canonical re-encoding, not merely that the create was accepted.
    """
    import os
    import subprocess

    control = plugin_module.drop.control_client
    payload_mod = plugin_module.drop.outbound_payload

    encoded, _labels, _generated = payload_mod.build_outbound_payload(
        canon_fields(), title="OpenRouter access"
    )
    created = await control.create_outbound_drop(
        payload_json=encoded, ttl_seconds=120, socket_path=real_public_broker.socket_path
    )
    assert created["ok"] is True

    # Reveal through the repo's own browser client, in node, because that is the code
    # the page actually runs. Hand-rolling AES-GCM here would test this test.
    # Passed through the environment rather than argv: `node -e` puts no script path
    # in `process.argv`, so the usual `slice(2)` silently drops the first argument.
    script = (
        "const {revealSecret}=await import('./src/client/reveal-client.js');"
        "const {parseOutboundFragment}=await import('./src/outbound-envelope.js');"
        "const url=process.env.DROP_URL;"
        "const parsed=parseOutboundFragment(url.slice(url.indexOf('#')+1));"
        "if(!parsed)throw new Error('unparseable fragment: '+url);"
        "const out=await revealSecret({...parsed,code:process.env.DROP_CODE,"
        "origin:process.env.DROP_ORIGIN});"
        "process.stdout.write(JSON.stringify(out));"
    )
    result = subprocess.run(
        ["node", "--input-type=module", "-e", script],
        cwd=str(REPO_ROOT),
        env={
            **os.environ,
            "DROP_URL": created["url"],
            "DROP_CODE": created["code"],
            "DROP_ORIGIN": real_public_broker.base_url,
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    revealed = json.loads(result.stdout)
    assert revealed["status"] == "revealed"
    assert revealed["plaintext"] == encoded, "the bytes stored are the bytes built"
