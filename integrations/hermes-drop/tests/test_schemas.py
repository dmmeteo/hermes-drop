"""S4 — no destination field, at any depth.

"The model cannot express it" is the entire safety argument for initiation, so
it is asserted structurally rather than by reading the schema and agreeing that
it looks fine. The walk below descends through every dict key, every dict value,
and every list element of every schema.

Three schemas since the outbound direction landed, and the walk covers all three.
The argument is not weaker on ``SEND_PRIVATE_OUTPUT`` — it is stronger. A misrouted
inbound drop asks a stranger for a credential; a misrouted outbound one hands them
one, so the schema that hands things out is the last place a destination field could
be allowed to appear.

The one field that *sounds* like a destination and legitimately is not is
``purpose`` — a non-secret audit label — and ``minutes``, whose 1..60 range sits
inside the broker's ``maxTtlSeconds: 3600`` (``src/config.js:10``, not overridden
in ``compose.yml``).
"""

from __future__ import annotations

from typing import Any, Iterator

import pytest

from conftest import load_plugin_package


@pytest.fixture(scope="module")
def schemas():
    return load_plugin_package().drop.schemas


def walk(node: Any, path: str = "$") -> Iterator[tuple[str, Any]]:
    """Yield ``(path, value)`` for every key and scalar in a nested structure."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield f"{path}.{key}", key
            yield from walk(value, f"{path}.{key}")
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            yield from walk(value, f"{path}[{index}]")
    else:
        yield path, node


@pytest.mark.parametrize(
    "schema_name", ["REQUEST_PRIVATE_INPUT", "CLAIM_PRIVATE_INPUT", "SEND_PRIVATE_OUTPUT"]
)
def test_no_destination_field_at_any_depth(schemas, schema_name: str) -> None:
    schema = getattr(schemas, schema_name)
    offences = []
    for path, value in walk(schema):
        if not isinstance(value, str):
            continue
        # Only *identifier-shaped* values can be a parameter name; prose
        # descriptions legitimately contain the word "conversation".
        if path.endswith(".description") or path.endswith(".name"):
            continue
        if value in schemas.FORBIDDEN_DESTINATION_FIELDS:
            offences.append((path, value))
    assert offences == [], f"{schema_name} exposes destination field(s): {offences}"


@pytest.mark.parametrize(
    "schema_name", ["REQUEST_PRIVATE_INPUT", "CLAIM_PRIVATE_INPUT", "SEND_PRIVATE_OUTPUT"]
)
def test_parameter_names_are_an_exact_allowlist(schemas, schema_name: str) -> None:
    """A blocklist can be walked around by a new synonym; the allowlist cannot."""
    allowed = {
        "request_private_input": {"purpose", "minutes"},
        "claim_private_input": {"drop_id"},
        # No destination, and no free-text body either: the payload is a list of
        # labelled fields so the page can render a Copy button per value and mask the
        # sensitive ones (docs/OUTBOUND_SECRET_DROP_MVP.md and the reveal page).
        "send_private_output": {"fields", "title", "minutes"},
    }
    schema = getattr(schemas, schema_name)
    props = set(schema["parameters"]["properties"])
    assert props == allowed[schema["name"]]


def test_minutes_is_bounded_inside_the_brokers_max_ttl(schemas) -> None:
    minutes = schemas.REQUEST_PRIVATE_INPUT["parameters"]["properties"]["minutes"]
    assert minutes["minimum"] == 1
    assert minutes["maximum"] == 60
    assert minutes["maximum"] * 60 <= 3600  # src/config.js maxTtlSeconds


def test_request_takes_no_required_arguments(schemas) -> None:
    """``/drop`` with no arguments and a bare natural-language ask must both work."""
    assert schemas.REQUEST_PRIVATE_INPUT["parameters"]["required"] == []


def test_claim_requires_only_the_drop_id(schemas) -> None:
    assert schemas.CLAIM_PRIVATE_INPUT["parameters"]["required"] == ["drop_id"]


def test_the_description_tells_the_model_it_cannot_choose_a_destination(schemas) -> None:
    """Belt and braces with the schema shape: the model is told plainly, so it
    does not spend a turn trying to pass a channel it has no field for."""
    description = schemas.REQUEST_PRIVATE_INPUT["description"]
    assert "cannot choose where the link goes" in description
    assert "Never ask for a secret in plain chat" in description


def test_both_tools_share_one_toolset_key(schemas) -> None:
    assert schemas.TOOLSET == "hermes_drop"


def test_the_plugin_registers_exactly_three_tools_one_command_and_no_send_message(
    schemas,
) -> None:
    """``send_message`` is the tool whose home-channel default caused the
    incident (``tools/send_message_tool.py:446-465``). Drop must never register,
    wrap, or re-export it — least of all now that it has a tool of its own that
    *sends* a credential, which is what ``send_message`` was doing when it went wrong.

    The list is asserted exactly, not by membership, so a third registration
    fails here on the way in rather than being discovered on a live surface. S8
    added exactly one: the ``/drop`` command. ``register_command`` is recorded
    with a leading slash so a tool and a command can never satisfy this
    assertion for each other.
    """
    plugin = load_plugin_package()

    registered: list[str] = []

    class Ctx:
        class manifest:
            name = "hermes-drop"
            key = "hermes-drop"
            source = "user"

        def register_tool(self, name, **kwargs):
            registered.append(name)

        def register_hook(self, hook_name, callback):
            pass

        def register_command(self, name, handler, description="", args_hint=""):
            registered.append(f"/{name}")

    plugin.register(Ctx())
    # Three tools since the outbound direction landed, and the list is still asserted
    # exactly rather than by membership: a fourth registration fails here on the way
    # in rather than being discovered on a live surface.
    assert sorted(registered) == [
        "claim_private_input",
        "request_private_input",
        "send_private_output",
    ]
    assert not any("send_message" in name for name in registered)
    assert "/drop" not in registered, "the stock skill command must not be shadowed"
