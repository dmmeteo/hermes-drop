"""Model-facing tool schemas.

**There is no destination field, and there never will be one.** Not
``platform``, not ``chat_id``, not ``channel``, ``channel_id``, ``thread_id``,
``user_id``, ``target`` or ``home``, at any depth. That absence *is* the safety
argument: the incident this design exists to prevent was a ``/drop`` typed in
Telegram whose link landed in a Discord channel, and the mechanism was a
generic send whose one-token ``target`` defaulted to the configured home
channel (``tools/send_message_tool.py:446-465``). A model that cannot express a
destination cannot pick the wrong one.

``tests/test_schemas.py`` walks both schemas recursively and fails on any of
those names appearing anywhere — key or value.

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
    "TOOLSET",
]
