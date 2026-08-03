"""The rendering matrix. Two tiers, one table, no fallbacks.

This table is the **only** place a platform's support tier lives. Splitting it
would let a refusal and a renderer disagree, and the way that disagreement
resolves in practice is "post it somewhere that works" — which is the incident.

* ``verified`` — Discord and Telegram. The broker renders their notices natively
  (``src/notice.js``), and their adapters implement ``edit_message`` with the
  signature the messenger actually calls.
* ``unsupported`` — everything else. Refused **before** anything is minted, with
  ``{"error": "platform_unsupported", "platform": "<p>"}`` naming the platform.
  Never a silent fallback to ``plain``; never a redirect to a platform that *is*
  supported.

Revision 1's third tier, ``expected`` ("any adapter implementing
``edit_message``"), is cut. It promised an ``edit_message`` call carrying
``metadata``, which is a ``TypeError`` on six of nine adapters, and Slack needs an
operator manifest update besides — slash commands are only emitted into a
*manifest fragment* (``hermes_cli/commands.py:1355-1380``).

``e2e_evidence`` is ``None`` for both supported platforms and stays ``None`` until
slice S11/M7 records a real run in ``E2E-EVIDENCE.md``. ``verified`` is the tier
the plan assigns; it is not a claim that a live platform accepted an edit. The CI
stand-in is the stub adapter: full path coverage, zero network, and no proof a
real platform accepted anything.
"""

from __future__ import annotations

from typing import Any, Dict, List

VERIFIED = "verified"
UNSUPPORTED = "unsupported"

#: Exactly two. A third tier is how "unsupported" quietly becomes "probably fine".
TIERS = (VERIFIED, UNSUPPORTED)

#: ``plain`` is a real broker renderer (S1) — a bare URL on its own line with an
#: absolute UTC deadline. It exists so an unsupported platform's *refusal* can be
#: honest about what it would have rendered, not so Drop can post there anyway.
PLAIN_RENDERER = "plain"

TABLE: Dict[str, Dict[str, Any]] = {
    # Masked Markdown link, no embed, so the capability stays in the #fragment.
    # Deadline via <t:UNIX:R>, client-rendered, zero API calls.
    "discord": {"renderer": "discord", "tier": VERIFIED, "e2e_evidence": None},
    # Masked Markdown link too — `format_message` translates it into a MarkdownV2
    # link, and the HTML this used to emit was escaped and *displayed*, capability
    # and all (review H1). Absolute UTC deadline, since Telegram re-renders
    # nothing. The link preview is **not** suppressed: `_link_preview_kwargs`
    # reads the adapter's own `_disable_link_previews` config
    # (`plugins/platforms/telegram/adapter.py:1495-1500`) and no `metadata` key
    # overrides it per message, so Drop cannot turn it off from here. Harmless as
    # it stands — a URL fragment is never sent to the server, so an unfurler
    # fetches the bare base URL and the capability is not in what it retrieves.
    "telegram": {"renderer": "telegram", "tier": VERIFIED, "e2e_evidence": None},
}

_UNSUPPORTED_ENTRY: Dict[str, Any] = {
    "renderer": PLAIN_RENDERER,
    "tier": UNSUPPORTED,
    "e2e_evidence": None,
}


def _platform_name(platform: Any) -> str:
    value = getattr(platform, "value", platform)
    return str(value or "").strip().lower()


def entry_for(platform: Any) -> Dict[str, Any]:
    """The table row for *platform*. Unknown platforms are ``unsupported``.

    Defaulting an unrecognised platform to ``unsupported`` rather than raising
    means a platform Hermes gains tomorrow refuses instead of guessing, and it
    refuses with a message naming itself.
    """
    return dict(TABLE.get(_platform_name(platform), _UNSUPPORTED_ENTRY))


def is_supported(platform: Any) -> bool:
    return entry_for(platform)["tier"] == VERIFIED


def renderer_for(platform: Any) -> str:
    """The ``notice_platform`` value to send the broker. Only meaningful for a
    supported platform; callers must gate on :func:`is_supported` first."""
    return entry_for(platform)["renderer"]


def supported_platforms() -> List[str]:
    return [name for name, entry in TABLE.items() if entry["tier"] == VERIFIED]


def unsupported_error(platform: Any) -> Dict[str, str]:
    return {"error": "platform_unsupported", "platform": _platform_name(platform)}


__all__ = [
    "PLAIN_RENDERER",
    "TABLE",
    "TIERS",
    "UNSUPPORTED",
    "VERIFIED",
    "entry_for",
    "is_supported",
    "renderer_for",
    "supported_platforms",
    "unsupported_error",
]
