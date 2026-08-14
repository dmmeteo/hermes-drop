"""Model-facing tool schemas.

**There is no destination field, and there never will be one.** Not
``platform``, not ``chat_id``, not ``channel``, ``channel_id``, ``thread_id``,
``user_id``, ``target`` or ``home``, at any depth. That absence *is* the safety
argument: the incident this design exists to prevent was a ``/drop`` typed in
Telegram whose link landed in a Discord channel, and the mechanism was a
generic send whose one-token ``target`` defaulted to the configured home
channel (``tools/send_message_tool.py:446-465``). A model that cannot express a
destination cannot pick the wrong one.

``tests/test_schemas.py`` walks every schema recursively and fails on any of
those names appearing anywhere — key or value.

There are three schemas: the two inbound ones (ask for a secret, retrieve it) and
``SEND_PRIVATE_OUTPUT``, which runs the other way. The no-destination rule is not
weaker on the outbound one — it is *stronger*, because a misrouted inbound drop asks
a stranger for a password and a misrouted outbound one hands them one.

``minutes`` is bounded 1..60, inside the broker's ``maxTtlSeconds: 3600``
(``src/config.js:10``, not overridden in ``compose.yml``).
"""

from __future__ import annotations

from typing import Any, Dict

REQUEST_PRIVATE_INPUT: Dict[str, Any] = {
    "name": "request_private_input",
    "description": (
        "Ask the user for a secret (password, token, key, private text) through a "
        "one-shot encrypted web form instead of the chat. Posts the link into THIS "
        "conversation and returns immediately; you are notified when it is used. "
        "Never ask for a secret in plain chat. You cannot choose where the link "
        "goes — it always goes to the conversation you are in."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "purpose": {
                "type": "string",
                "description": "Short non-secret label for the audit journal, e.g. 'deploy token'.",
            },
            "minutes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 60,
                "description": "Link lifetime. Default 30.",
            },
        },
        "required": [],
    },
}

CLAIM_PRIVATE_INPUT: Dict[str, Any] = {
    "name": "claim_private_input",
    "description": (
        "Retrieve the private input for a drop reported as received. "
        "One claim only; the payload is destroyed after."
    ),
    "parameters": {
        "type": "object",
        "properties": {"drop_id": {"type": "string"}},
        "required": ["drop_id"],
    },
}

#: The outbound direction (docs/OUTBOUND_SECRET_DROP_MVP.md): Hermes has a secret
#: and the user is the one who has to receive it.
#:
#: The same absence carries the same argument — no ``platform``, no ``chat_id``, no
#: destination of any kind — and it matters *more* here than on the inbound schema.
#: An inbound drop that went to the wrong conversation asks a stranger for a
#: password; an outbound one **hands** them one. There is no field for a destination
#: because a model that cannot express one cannot pick the wrong one.
#:
#: Two shapes are deliberately absent as well:
#:
#: * **No free-text body.** The payload is a list of labelled fields, so the page can
#:   render each with its own Copy button and mask the sensitive ones. A model handed
#:   a single ``text`` field would put "login: x, password: y" in it and the page
#:   would render one blob.
#: * **No ``code`` or ``url`` in the result.** The tool returns labels, a deadline
#:   and a drop id. The link and the code go to the conversation; putting them in a
#:   tool result would copy them into the model's context and from there into durable
#:   session state for no benefit.
SEND_PRIVATE_OUTPUT: Dict[str, Any] = {
    "name": "send_private_output",
    "description": (
        "Give the user a secret (password, token, key, credentials) through a one-time "
        "encrypted link instead of writing it in the chat. Use this whenever you are "
        "about to reveal or hand over a secret value, including one you just generated. "
        "Posts the link and a short code into THIS conversation and returns a receipt "
        "with no values in it. Send each value as its own labelled field so the page can "
        "show a Copy button for each and keep the sensitive ones hidden. Prefer "
        "'generate' over inventing a password yourself: the value is then created by the "
        "service and never passes through this conversation at all. After it is sent, "
        "never repeat the values in chat. You cannot choose where the link goes — it "
        "always goes to the conversation you are in."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "fields": {
                "type": "array",
                "minItems": 1,
                "maxItems": 8,
                "description": (
                    "The values to hand over, one entry each. Order is the order they "
                    "are shown in."
                ),
                "items": {
                    "type": "object",
                    "properties": {
                        "label": {
                            "type": "string",
                            "maxLength": 40,
                            "description": (
                                "Short heading shown above the value, e.g. 'Login', "
                                "'Password', 'API key'. One line, no two the same."
                            ),
                        },
                        "type": {
                            "type": "string",
                            "enum": ["text", "secret", "url", "note"],
                            "description": (
                                "'secret' is hidden behind a Show control until the user "
                                "asks — use it for passwords, tokens and keys. 'text', "
                                "'url' and 'note' are shown normally. Defaults to "
                                "'secret' when omitted."
                            ),
                        },
                        "value": {
                            "type": "string",
                            "maxLength": 512,
                            "description": (
                                "The value itself, exactly as the user must use it. Sent "
                                "unchanged — no trimming — so do not pad it. Give this or "
                                "'generate', never both."
                            ),
                        },
                        "generate": {
                            "type": "object",
                            "description": (
                                "Ask the service to create the value instead of supplying "
                                "it. Preferred for new passwords and keys: the value is "
                                "never in this conversation, so it cannot be logged or "
                                "repeated. Only for 'secret' fields."
                            ),
                            "properties": {
                                "kind": {
                                    "type": "string",
                                    "enum": ["password", "hex", "base64url"],
                                    "description": "Defaults to 'password'.",
                                },
                                "length": {
                                    "type": "integer",
                                    "minimum": 8,
                                    "maximum": 64,
                                    "description": "Characters to create. Defaults to 24.",
                                },
                            },
                        },
                    },
                    "required": ["label"],
                },
            },
            "title": {
                "type": "string",
                "maxLength": 60,
                "description": (
                    "Optional heading for the page, e.g. 'OpenRouter access'. Shown only "
                    "on the page, never in the chat message."
                ),
            },
            "minutes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 60,
                "description": "How long the link stays openable. Default 30.",
            },
        },
        "required": ["fields"],
    },
}

#: The toolset key. New plugin toolsets default ON per platform unless
#: ``known_plugin_toolsets`` already records that platform
#: (``hermes_cli/tools_config.py:2323-2342``), which is how Drop reaches both
#: Discord and Telegram with no config edit.
TOOLSET = "hermes_drop"

#: Names that must never appear in either schema. Enforced by test, not by
#: convention, because "the model cannot express it" is load-bearing.
FORBIDDEN_DESTINATION_FIELDS = frozenset(
    {
        "platform",
        "chat_id",
        "chat",
        "channel",
        "channel_id",
        "thread_id",
        "thread",
        "user_id",
        "target",
        "home",
        "home_channel",
        "destination",
        "to",
        "recipient",
    }
)

__all__ = [
    "CLAIM_PRIVATE_INPUT",
    "FORBIDDEN_DESTINATION_FIELDS",
    "REQUEST_PRIVATE_INPUT",
    "SEND_PRIVATE_OUTPUT",
    "TOOLSET",
]
