"""Keep the claimed plaintext out of durable Hermes state.

``claim_private_input`` is the one path by which a secret enters a model turn,
and it enters as a tool result. The core lifecycle for a tool result, verified
read-only against the installed checkout at ``ebd91f8d56``, is:

1. ``model_tools.execute_tool`` dispatches the handler, emits ``post_tool_call``,
   then offers the **result string** to ``transform_tool_result``
   (``model_tools.py:1388-1412``) and returns whatever survives.
2. ``agent/tool_executor.py:1894-1901`` wraps that same string with
   ``make_tool_result_message``, appends it to ``messages`` and immediately
   flushes: ``_flush_session_db_after_tool_progress`` →
   ``_flush_messages_to_session_db`` → ``SessionDB.append_message``. So
   ``state.db``, the ``messages_fts*`` triggers and the JSON session log are all
   written **before** the API call that shows the model anything.
3. The request is built by ``build_api_kwargs`` — which is also where every
   provider-native message translation happens — and ``api_kwargs`` is then
   passed through ``apply_llm_request_middleware``
   (``agent/conversation_loop.py:2096-2112``); that call's returned payload *is*
   what reaches the provider.

There is therefore exactly one string at step 1, and it is simultaneously the
durable row and the wire. ``transform_tool_result`` cannot separate them —
redacting there redacts the model turn too. Nor is there a seam after step 2:
``pre_api_request``/``post_api_request`` discard their return values
(``conversation_loop.py:2146``), ``run_agent.py:1931+`` records the invariant
"No code path edits a persisted message's content/role in place expecting a
re-write", and ``SessionDB`` offers no per-row redaction — only a whole-session
``replace_messages``.

The two copies first diverge at step 3, so that is where the split is made:

* **Durable** — the plugin substitutes a placeholder *before* the dict becomes a
  tool-result string (``__init__.py::_guarded``). Nothing downstream of the
  plugin ever holds the plaintext, and that property depends on no core hook.
  Deliberately not ``transform_tool_result``: it is ``has_hook``-gated and
  wrapped in a bare ``except`` that logs at debug and carries on
  (``model_tools.py:1411``), so a hook that fails *open* cannot be what stands
  between a password and ``state.db``.
* **Wire** — ``llm_request`` middleware puts the plaintext back, into the deep
  copy ``apply_llm_request_middleware`` made (``middleware.py:94-95``), so the
  persisted dicts are never touched. ``ctx.register_middleware`` is a supported
  plugin API (``hermes_cli/plugins.py:1196``) and ``"llm_request"`` is in
  ``VALID_MIDDLEWARE`` (``hermes_cli/middleware.py:29-34``).

**The substitution walks the payload structurally**, because by step 3 the
tool result no longer has one shape. ``build_api_kwargs`` has already translated
it into whatever the active ``api_mode`` speaks, and the placeholder lands in a
different key in each (all verified in the adapters, and pinned by tests that
build the shapes with the real converters rather than by hand):

===================== ======================================================
``api_mode``          where the tool result ends up
===================== ======================================================
``chat_completions``  ``messages[].content`` — ``str``, or text parts
``anthropic_messages`` ``messages[].content[]`` → ``{"type": "tool_result",
                      "content": <str>}`` — note ``content``, not ``text``
                      (``agent/anthropic_adapter.py:2276-2281``)
``codex_responses``   ``input[]`` → ``{"type": "function_call_output",
                      "output": <str>}`` — no ``content`` key at all
                      (``agent/codex_responses_adapter.py:613-617``)
``bedrock_converse``  ``messages[].content[]`` → ``{"toolResult":
                      {"content": [{"text": <str>}]}}`` — two levels deeper
                      (``agent/bedrock_adapter.py:645-651``)
===================== ======================================================

Enumerating those four by key would be wrong the day a fifth transport lands, so
the walk descends every mapping, sequence and string in the payload and
substitutes wherever a live placeholder appears. A placeholder is a 128-bit
random token that exists nowhere but a transcript this vault minted, so "found
it" and "it belongs here" are the same statement. Nothing is rebuilt unless a
substitution actually happened, and the whole walk is skipped when the vault is
empty — which is every request in every session that never claimed.

**Both directions fail closed.** A middleware callback that raises is isolated
and logged by ``PluginManager.invoke_middleware``, leaving the placeholder on
the wire; anything this module refuses to stash raises :class:`VaultError`
through ``_guarded``'s catch-all into ``internal_error``. The failure mode is a
model that cannot read the secret, never a secret in ``state.db``.

**The placeholder is not a bearer capability.** It outlives the plaintext in the
durable transcript, so an entry is bound to the ``session_id`` that claimed it
(the same ``agent.session_id`` reaches both seams — ``tool_executor.py:1678``
and ``conversation_loop.py:2103``) and is resolved for that session only. A
claim that arrives with **no** session id is refused rather than stashed under
``""``, which would make one placeholder resolvable from any other session that
also lacked one.

**What this does not confine.** The model receives the real plaintext, so
anything it then does with it — echoing it into a reply, passing it as an
argument to another tool — is persisted like any other model output. That
exposure is unchanged and still accepted (§3.2); the model is a trusted
principal. Nor does it confine anything that reads the request *after*
middleware; see ``SECURITY.md``.
"""

from __future__ import annotations

import logging
import re
import secrets
import threading
import time
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

#: The middleware kind, spelled out rather than imported: this package must stay
#: importable in a plugin-discovery process without dragging in ``hermes_cli``.
#: ``test_sanitization.py::test_the_middleware_kind_matches_core`` pins it
#: against ``hermes_cli.middleware.LLM_REQUEST_MIDDLEWARE``.
MIDDLEWARE_KIND = "llm_request"

#: The result field that carries a secret, and the field that explains the
#: substitution to the model. The note is non-secret and fixed, so it costs one
#: constant sentence in the durable row.
SECRET_FIELD = "private_input"
NOTE_FIELD = "private_input_note"
NOTE = (
    "This value is held in gateway memory only and substituted into the model "
    "request; it is never written to Hermes' durable session state. If you are "
    "reading the bracketed placeholder itself, it has lapsed — ask the user for "
    "a new drop rather than guessing."
)

#: ASCII by construction: ``_sanitize_structure_non_ascii`` runs over
#: ``api_kwargs`` before middleware (``conversation_loop.py:2079-2080``), so a
#: non-ASCII token could be rewritten out from under the substitution.
PLACEHOLDER_RE = re.compile(r"\[hermes-drop:secret:([0-9a-f]{32})\]")

#: How long a claimed secret stays resolvable. The intended shape is claim then
#: use, so this is generous for that and still bounded; past it the transcript
#: keeps the placeholder and the model is told to ask again.
TTL_SECONDS = 900.0

#: Per-session ceiling. This is the one that protects a conversation from its
#: neighbours: one session cannot evict another's secret by claiming repeatedly,
#: because it evicts its *own* oldest entry first.
MAX_ENTRIES_PER_SESSION = 4

#: Process-wide ceiling, and an honest one — the vault is a module global in a
#: gateway that serves every session in one process, so this bound is shared.
#: Reaching it (8 sessions each holding their full 4) evicts the globally oldest
#: entry, which may belong to another session; that session's next request then
#: sees an unresolvable placeholder and its model is told to ask for a new drop.
#: It degrades, and it is bounded by ``TTL_SECONDS`` rather than by luck, but it
#: is cross-session interference and is not claimed otherwise.
MAX_ENTRIES = 32

#: Depth bound for the payload walk. Provider payloads nest three or four levels
#: (``bedrock_converse`` is the deepest at ``messages[].content[].toolResult
#: .content[].text``); this is far past any of them, and hitting it returns the
#: subtree unsubstituted, which is the fail-closed direction.
MAX_WALK_DEPTH = 24

#: Monotonic, so a wall-clock adjustment cannot extend an entry's life.
#: Patched by tests; not a constructor argument because the vault is
#: process-wide by nature — both seams are reached as bare callbacks.
_clock = time.monotonic


class VaultError(RuntimeError):
    """A secret could not be taken into memory, so it must not be returned."""


_LOCK = threading.Lock()
_ENTRIES: Dict[str, Tuple[str, str, float]] = {}  # token -> (session_id, plaintext, expiry)
_TIMERS: Dict[str, threading.Timer] = {}


def _placeholder(token: str) -> str:
    return f"[hermes-drop:secret:{token}]"


def _drop_locked(token: str) -> None:
    _ENTRIES.pop(token, None)
    timer = _TIMERS.pop(token, None)
    if timer is not None:
        # A no-op when this is the timer that just fired.
        timer.cancel()


def _expire(token: str) -> None:
    with _LOCK:
        _drop_locked(token)


def _purge_locked(now: float) -> None:
    for token in [t for t, (_s, _p, expiry) in _ENTRIES.items() if expiry <= now]:
        _drop_locked(token)


def stash(plaintext: str, *, session_id: str) -> str:
    """Hold *plaintext* in memory and return the placeholder that stands for it.

    Raises :class:`VaultError` rather than returning anything the caller could
    mistake for a placeholder. Every caller is on the path that would otherwise
    put a secret in ``state.db``, so refusing is the only safe failure.
    """
    if not isinstance(plaintext, str):
        raise VaultError(
            f"private_input must be a string to be redacted, got {type(plaintext).__name__}"
        )
    if not plaintext:
        raise VaultError("private_input is empty; a claim that yields nothing is a defect")
    session = str(session_id or "")
    if not session:
        raise VaultError(
            "no session_id reached the tool handler, so a claimed secret cannot be "
            "bound to the conversation that claimed it. Refusing to stash it under "
            "an empty key, which any other unbound session could then resolve."
        )

    token = secrets.token_hex(16)
    now = _clock()
    expiry = now + TTL_SECONDS
    timer = threading.Timer(TTL_SECONDS, _expire, args=(token,))
    timer.daemon = True

    with _LOCK:
        _purge_locked(now)
        # This session's own ceiling first, so a busy conversation spends its own
        # budget before it can reach anyone else's.
        mine = [t for t, (s, _p, _e) in _ENTRIES.items() if s == session]
        while len(mine) >= MAX_ENTRIES_PER_SESSION:
            oldest = min(mine, key=lambda t: _ENTRIES[t][2])
            _drop_locked(oldest)
            mine.remove(oldest)
        while len(_ENTRIES) >= MAX_ENTRIES:
            _drop_locked(min(_ENTRIES, key=lambda t: _ENTRIES[t][2]))
        _ENTRIES[token] = (session, plaintext, expiry)
        _TIMERS[token] = timer
        timer.start()

    return _placeholder(token)


def resolve(token: str, *, session_id: str) -> Optional[str]:
    """The plaintext for *token* in *session_id*, or ``None``.

    ``None`` for an unknown token, a lapsed one, one belonging to another
    session, or a caller with no session id at all — the caller cannot tell
    which, and does not need to.
    """
    session = str(session_id or "")
    if not session:
        return None
    now = _clock()
    with _LOCK:
        _purge_locked(now)
        entry = _ENTRIES.get(token)
        if entry is None or entry[0] != session:
            return None
        return entry[1]


def live_count(session_id: Optional[str] = None) -> int:
    """How many secrets are resident, in total or for one session.

    Exists so the lifecycle can be asserted without reaching into module
    privates, and so an operator can see the number without seeing the values.
    """
    with _LOCK:
        _purge_locked(_clock())
        if session_id is None:
            return len(_ENTRIES)
        session = str(session_id or "")
        return sum(1 for (s, _p, _e) in _ENTRIES.values() if s == session)


def clear() -> None:
    """Drop every entry and cancel every pending expiry."""
    with _LOCK:
        for token in list(_ENTRIES) + list(_TIMERS):
            _drop_locked(token)


# ── the durable seam ───────────────────────────────────────────────────────


def redact_tool_result(payload: Any, *, session_id: str) -> Any:
    """Replace a secret field with a placeholder before *payload* is serialised.

    Applied to *both* tool results, not just ``claim``: the invariant worth
    having is "no plugin tool result carries a secret field", which a future
    third result path then inherits rather than has to remember.

    Raises :class:`VaultError` for anything it cannot redact. Returning the
    payload unchanged on a surprise would serialise the surprise into
    ``state.db``, which is the one outcome this module exists to prevent.
    """
    if not isinstance(payload, Mapping) or SECRET_FIELD not in payload:
        return payload
    redacted = dict(payload)
    redacted[SECRET_FIELD] = stash(payload[SECRET_FIELD], session_id=session_id)
    redacted[NOTE_FIELD] = NOTE
    return redacted


# ── the wire seam ──────────────────────────────────────────────────────────


def _substitute_text(text: str, *, session_id: str) -> Tuple[str, bool]:
    hit = False

    def _one(match: "re.Match[str]") -> str:
        nonlocal hit
        plaintext = resolve(match.group(1), session_id=session_id)
        if plaintext is None:
            return match.group(0)
        hit = True
        return plaintext

    return PLACEHOLDER_RE.sub(_one, text), hit


def _substitute_tree(node: Any, *, session_id: str, depth: int = 0) -> Tuple[Any, bool]:
    """Substitute in every string reachable from *node*, rebuilding as needed.

    Returns ``(node, False)`` — the original object, not a copy — when nothing
    changed, so an unaffected payload costs no allocation. New containers
    everywhere a substitution did happen, never in-place mutation: ``_safe_copy``
    degrades to a shallow ``dict()`` when a payload holds something
    non-deepcopyable (``middleware.py:58-75``), in which case the structures
    handed here are the live, already-persisted ones.
    """
    if depth > MAX_WALK_DEPTH:
        return node, False
    if isinstance(node, str):
        return _substitute_text(node, session_id=session_id)
    if isinstance(node, Mapping):
        rebuilt: Dict[Any, Any] = {}
        changed = False
        for key, value in node.items():
            new_value, hit = _substitute_tree(value, session_id=session_id, depth=depth + 1)
            rebuilt[key] = new_value
            changed = changed or hit
        return (rebuilt, True) if changed else (node, False)
    # ``str``/``bytes`` are Sequences; the str case is handled above and bytes
    # cannot carry a placeholder that survived JSON encoding.
    if isinstance(node, Sequence) and not isinstance(node, (str, bytes, bytearray)):
        items: List[Any] = []
        changed = False
        for value in node:
            new_value, hit = _substitute_tree(value, session_id=session_id, depth=depth + 1)
            items.append(new_value)
            changed = changed or hit
        if not changed:
            return node, False
        return (tuple(items) if isinstance(node, tuple) else items), True
    return node, False


def llm_request_middleware(
    *, request: Any = None, session_id: str = "", **_kwargs: Any
) -> Optional[Dict[str, Any]]:
    """``llm_request`` middleware: put the plaintext on the wire, nowhere else.

    Returns ``{"request": ...}`` only when something was actually substituted, so
    a request with no live placeholder leaves ``RequestMiddlewareResult.changed``
    false and the payload identical.
    """
    if not isinstance(request, Mapping):
        return None
    if not str(session_id or ""):
        return None
    # The common case by a wide margin: no secret is resident, so no request in
    # this process can contain a resolvable placeholder. Skip the walk entirely
    # rather than regex every tool schema on every API call.
    if live_count() == 0:
        return None

    substituted, changed = _substitute_tree(request, session_id=session_id)
    if not changed:
        return None
    return {"request": substituted}


__all__ = [
    "MAX_ENTRIES",
    "MAX_ENTRIES_PER_SESSION",
    "MAX_WALK_DEPTH",
    "MIDDLEWARE_KIND",
    "NOTE",
    "NOTE_FIELD",
    "PLACEHOLDER_RE",
    "SECRET_FIELD",
    "TTL_SECONDS",
    "VaultError",
    "clear",
    "live_count",
    "llm_request_middleware",
    "redact_tool_result",
    "resolve",
    "stash",
]
