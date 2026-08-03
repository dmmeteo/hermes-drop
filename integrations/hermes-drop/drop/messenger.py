"""Send and edit on the adapter that owns the originating conversation.

Async-native. Every method here is awaited directly by a caller already on the
gateway loop; there is no blocking call and no loop-scheduling anywhere in this
module. The single worker-thread crossing lives in ``bridge.py`` and is used once
per tool invocation, for the whole operation.

Two rules, both derived from the adapter ABC rather than chosen:

* ``metadata`` goes on ``send`` and **never** on ``edit_message``. ``send``'s
  signature includes it (``gateway/platforms/base.py:3477-3496``);
  ``edit_message``'s does not (``:3533-3540``), and ``metadata=`` exists on only
  three of nine adapters — discord, telegram, slack. On matrix, mattermost,
  whatsapp, google_chat, dingtalk and feishu it is a ``TypeError``: a crash, not a
  degradation.

* ``finalize=True`` goes on **every** ``edit_message``, and the contrast with
  ``metadata`` is the point: ``finalize`` *is* on the ABC and keyword-only on all
  nine adapters, so passing it is universally safe. It is also load-bearing on
  Telegram, whose ``finalize=False`` branch applies no ``parse_mode`` at all. See
  the call site for the full derivation.

* ``chat_id`` is only ever ``origin.source.chat_id``. There is no other
  expression in this module that can produce a chat id, ``send_message`` is never
  imported, and no home channel is ever consulted.

Thread/topic routing comes from ``_thread_metadata_for_source`` with the **real**
source, so Telegram DM topics (``direct_messages_topic_id`` plus a reply anchor)
and Slack workspace identity (``slack_team_id`` from ``source.scope_id``) behave
as core intends — neither of which survives a reconstruction.

The two ``*_status`` wrappers encode §7.2's asymmetry:

* ``post_status`` failing means **abort the drop** — no journal entry, no waiter.
  A live capability whose link was never delivered is pure risk.
* ``update_status`` failing means **carry on**. The state the edit would have
  shown no longer matters; the capability is already dead. What must not happen is
  an exception escaping into a long-lived waiter task.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

ERROR_POST_FAILED = "post_failed"
ERROR_EDIT_FAILED = "edit_failed"


def _thread_metadata(source: Any, reply_anchor: Optional[str]) -> Optional[Dict[str, Any]]:
    """Imported inside the call so ``gateway.platforms.base`` is not pulled into
    every CLI process that merely discovers plugins."""
    from gateway.platforms.base import _thread_metadata_for_source

    return _thread_metadata_for_source(source, reply_anchor)


class OriginMessenger:
    """The only thing in Drop that talks to a platform."""

    async def send(self, origin: Any, content: str) -> Any:
        metadata = _thread_metadata(origin.source, origin.reply_anchor)
        return await origin.adapter.send(origin.source.chat_id, content, metadata=metadata)

    async def edit(self, origin: Any, message_id: str, content: str) -> Any:
        # No `metadata` argument. See the module docstring: it is absent from the
        # edit_message ABC and from six of the nine adapters.
        #
        # `finalize=True`, and unlike `metadata` it is safe everywhere: it is on
        # the ABC (`gateway/platforms/base.py:3533-3540`) and keyword-only on all
        # nine adapters. It is also *required* here. Telegram's `edit_message`
        # with `finalize=False` calls `edit_message_text(text=content)` with no
        # `parse_mode` at all (`plugins/platforms/telegram/adapter.py:4755-4761`);
        # only the `finalize=True` branch runs `format_message` +
        # `MARKDOWN_V2` (`:4765-4771`). Without it the quiet notices landed as the
        # literal strings `✓ **Private input received**`, asterisks included
        # (review M7).
        #
        # Semantically right as well as necessary: `finalize` means "last edit in
        # a sequence", and Drop's edits are always terminal — a drop is edited
        # exactly once, into `received` or `expired`, and never again. There is no
        # streaming here to be mid-way through.
        return await origin.adapter.edit_message(
            origin.source.chat_id, message_id, content, finalize=True
        )

    # -- outcome-shaped wrappers -------------------------------------------

    async def post_status(self, origin: Any, content: str) -> Dict[str, Any]:
        """Post the status message. ``{"ok": True, "message_id": …}`` or
        ``{"error": "post_failed", …}``."""
        try:
            result = await self.send(origin, content)
        except Exception as exc:
            logger.warning(
                "hermes-drop: post failed on %s: %s", origin.platform_name, exc, exc_info=True
            )
            return {
                "error": ERROR_POST_FAILED,
                "detail": str(exc),
                "platform": origin.platform_name,
            }

        if not getattr(result, "success", False):
            return {
                "error": ERROR_POST_FAILED,
                "detail": getattr(result, "error", None) or "adapter reported failure",
                "platform": origin.platform_name,
            }

        message_id = getattr(result, "message_id", None)
        if not message_id:
            # An edit needs a target. A "successful" send with no id cannot be
            # edited into a terminal state, so it is treated as a failed post
            # rather than left to fail silently 30 minutes later.
            return {
                "error": ERROR_POST_FAILED,
                "detail": "adapter reported success without a message id",
                "platform": origin.platform_name,
            }

        return {"ok": True, "message_id": str(message_id)}

    async def update_status(
        self, origin: Any, message_id: str, content: str
    ) -> Dict[str, Any]:
        """Edit the status message in place. Never raises."""
        try:
            result = await self.edit(origin, message_id, content)
        except Exception as exc:
            logger.warning(
                "hermes-drop: edit failed on %s: %s", origin.platform_name, exc, exc_info=True
            )
            return {
                "error": ERROR_EDIT_FAILED,
                "detail": str(exc),
                "platform": origin.platform_name,
            }

        if not getattr(result, "success", False):
            return {
                "error": ERROR_EDIT_FAILED,
                "detail": getattr(result, "error", None) or "adapter reported failure",
                "platform": origin.platform_name,
            }

        return {"ok": True, "message_id": str(getattr(result, "message_id", message_id))}


__all__ = ["ERROR_EDIT_FAILED", "ERROR_POST_FAILED", "OriginMessenger"]
