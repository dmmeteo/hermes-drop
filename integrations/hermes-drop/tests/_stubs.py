"""Test doubles that stay faithful to the real seams.

Two deliberate choices:

* ``StubAdapter`` borrows the **real** ``BasePlatformAdapter.build_source``
  rather than hand-rolling a ``SessionSource``. That method is what stamps
  ``scope_id``, ``parent_chat_id``, ``chat_id_alt``, ``user_id_alt`` and
  ``source._transport_adapter_ref = weakref.ref(self)``
  (``gateway/platforms/base.py:6617-6641``). Provenance is exactly what a
  reconstruction loses, so a stub that fabricated it would test nothing.
  Subclassing the ABC is not an option — it has a large abstract surface and
  none of it is relevant here — so the one method we need is bound directly.

* ``StubAdapter.edit_message`` takes **no** ``metadata`` kwarg, mirroring the
  six of nine real adapters that lack it (matrix, mattermost, whatsapp,
  google_chat, dingtalk, feishu). Passing it there is a ``TypeError`` in
  production, so it is a ``TypeError`` here too.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from gateway.authz_mixin import GatewayAuthorizationMixin
from gateway.config import Platform
from gateway.platforms.base import BasePlatformAdapter, SendResult


@dataclass
class SentMessage:
    chat_id: str
    content: str
    reply_to: Optional[str]
    metadata: Optional[Dict[str, Any]]


@dataclass
class EditedMessage:
    chat_id: str
    message_id: str
    content: str
    finalize: bool


class StubAdapter:
    """A send/edit-recording adapter with real ``build_source`` provenance."""

    # Real provenance stamping, straight off the ABC.
    build_source = BasePlatformAdapter.build_source

    def __init__(
        self,
        platform: Platform,
        *,
        send_ok: bool = True,
        edit_ok: bool = True,
        send_error: str = "stub send refused",
        edit_error: str = "stub edit refused",
        next_message_id: str = "stub-msg-1",
    ) -> None:
        self.platform = platform
        # build_source consults this; None means "no profile_routes engine".
        self.gateway_runner = None
        self.sent: List[SentMessage] = []
        self.edited: List[EditedMessage] = []
        self._send_ok = send_ok
        self._edit_ok = edit_ok
        self._send_error = send_error
        self._edit_error = edit_error
        self._next_message_id = next_message_id

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        self.sent.append(SentMessage(chat_id, content, reply_to, metadata))
        if not self._send_ok:
            return SendResult(success=False, error=self._send_error)
        return SendResult(success=True, message_id=self._next_message_id)

    async def edit_message(
        self,
        chat_id: str,
        message_id: str,
        content: str,
        *,
        finalize: bool = False,
    ) -> SendResult:
        # NOTE: no ``metadata`` parameter, on purpose — see the module docstring.
        self.edited.append(EditedMessage(chat_id, message_id, content, finalize))
        if not self._edit_ok:
            return SendResult(success=False, error=self._edit_error)
        return SendResult(success=True, message_id=message_id)


class StubRunner(GatewayAuthorizationMixin):
    """Minimal ``GatewayRunner`` stand-in carrying the real adapter-resolution
    logic (``gateway/authz_mixin.py:101-149``) rather than a reimplementation."""

    def __init__(
        self,
        adapters: Optional[Dict[Platform, Any]] = None,
        *,
        profile_adapters: Optional[Dict[str, Dict[Platform, Any]]] = None,
        config: Any = None,
        gateway_loop: Any = None,
        active_profile: str = "default",
    ) -> None:
        self.adapters = adapters or {}
        self._profile_adapters = profile_adapters or {}
        self.config = config
        self._gateway_loop = gateway_loop
        self._active_profile = active_profile

    def _active_profile_name(self) -> str:
        return self._active_profile


def bind_session_context(
    *,
    platform: str,
    chat_id: str,
    thread_id: str = "",
    profile: str = "",
    session_key: str = "test-session",
    chat_type: str = "dm",
    user_id: str = "u-1",
    message_id: str = "",
) -> list:
    """Bind the session contextvars the way ``_set_session_env`` does.

    Field-for-field the same call ``gateway/run.py:20255-20269`` makes, so a test
    that binds context here is binding what production binds — including the
    fields it deliberately omits (``scope_id``, ``parent_chat_id``, ``*_alt``,
    ``delivered_via_upstream_relay``).
    """
    from gateway.session_context import set_session_vars

    return set_session_vars(
        platform=platform,
        chat_id=chat_id,
        chat_type=chat_type,
        chat_name="",
        thread_id=thread_id,
        user_id=user_id,
        user_name="",
        session_key=session_key,
        message_id=message_id,
        profile=profile,
        async_delivery=True,
    )
