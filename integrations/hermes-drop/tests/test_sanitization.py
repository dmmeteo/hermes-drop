"""Durable secret sanitization: the plaintext must not reach ``state.db``.

**What the core lifecycle actually is**, established read-only against the
installed checkout at ``ebd91f8d56``:

1. ``model_tools.execute_tool`` dispatches the handler, emits ``post_tool_call``,
   then offers the result string to ``transform_tool_result``
   (``model_tools.py:1388-1412``) and returns it.
2. ``agent/tool_executor.py:1894-1901`` wraps that *same* string with
   ``make_tool_result_message``, appends it to ``messages``, and immediately
   calls ``_flush_session_db_after_tool_progress`` →
   ``_flush_messages_to_session_db`` → ``SessionDB.append_message`` — so
   ``state.db`` and the ``messages_fts*`` triggers are written **before** the
   API call that shows the result to the model.
3. Only then is the request built, and ``api_kwargs`` handed to
   ``apply_llm_request_middleware`` (``agent/conversation_loop.py:2096-2112``),
   whose returned payload *is* what goes to the provider.

That ordering is why ``transform_tool_result`` cannot be the seam on its own:
there is exactly one string at that point, and it is both the durable row and
the wire. Redacting there redacts the model turn too. And there is no seam
after it either — ``pre_api_request``/``post_api_request`` discard their return
values (``conversation_loop.py:2146``), and ``run_agent.py:1931+`` states the
invariant outright: "No code path edits a persisted message's content/role in
place expecting a re-write". ``SessionDB`` exposes no per-row redaction, only a
whole-session ``replace_messages``.

So the split is done where the two copies first diverge:

* **Durable side** — the plugin's own tool-result boundary
  (``__init__.py::_guarded``). The string handed to core already carries a
  placeholder, so nothing downstream of the plugin ever holds the plaintext.
  This depends on no core hook at all, which is the point: a hook that
  fails open (``model_tools.py:1411``) cannot be load-bearing for a secret.
* **Wire side** — ``llm_request`` middleware, a real supported plugin API
  (``ctx.register_middleware``, ``hermes_cli/plugins.py:1196``;
  ``VALID_MIDDLEWARE``, ``hermes_cli/middleware.py:29-34``), which rewrites a
  deep copy of the provider payload and never the persisted dicts.

Failure is closed in both directions: a middleware that raises is isolated and
logged (``plugins.py::invoke_middleware``), leaving the placeholder on the wire;
a vault that cannot stash raises through ``_guarded``'s catch-all into
``internal_error``. Neither path can emit the plaintext.
"""

from __future__ import annotations

import json
import sqlite3
import time

import pytest

from conftest import load_plugin_package

SECRET = "correct-horse-battery-staple-8ad31f"
SESSION = "sess-drop-1"


@pytest.fixture
def vault(plugin):
    v = plugin.drop.vault
    v.clear()
    try:
        yield v
    finally:
        v.clear()


@pytest.fixture
def plugin():
    return load_plugin_package()


@pytest.fixture
def claimed(plugin, vault, monkeypatch):
    """The tool-result string core would carry, for a successful claim."""
    monkeypatch.setattr(
        plugin.drop.tools,
        "claim_private_input",
        lambda args, **_kw: {"ok": True, "drop_id": "H" * 22, "private_input": SECRET},
    )
    return plugin.claim_private_input({"drop_id": "H" * 22}, session_id=SESSION)


# ── the durable side ───────────────────────────────────────────────────────


def test_the_claim_tool_result_string_carries_no_plaintext(claimed, vault) -> None:
    """This string is what ``tool_executor`` appends and flushes verbatim."""
    assert SECRET not in claimed
    payload = json.loads(claimed)
    assert payload["ok"] is True
    assert vault.PLACEHOLDER_RE.fullmatch(payload["private_input"]), payload


def test_the_placeholder_is_opaque_ascii(plugin, vault, monkeypatch) -> None:
    """``_sanitize_structure_non_ascii`` runs before middleware
    (``conversation_loop.py:2079``), so the token must survive it — and it must
    not be derived from the secret, which is what stashing the *same* plaintext
    twice and getting two different tokens actually demonstrates. (An earlier
    version asserted the secret's length did not appear in the token; 32 hex
    digits contain any two-digit string often enough that that was a coin flip,
    not a property.)"""
    monkeypatch.setattr(
        plugin.drop.tools,
        "claim_private_input",
        lambda args, **_kw: {"ok": True, "drop_id": "H" * 22, "private_input": SECRET},
    )
    first = json.loads(plugin.claim_private_input({"drop_id": "a"}, session_id=SESSION))
    second = json.loads(plugin.claim_private_input({"drop_id": "b"}, session_id=SESSION))

    for token in (first["private_input"], second["private_input"]):
        assert token.isascii()
        assert vault.PLACEHOLDER_RE.fullmatch(token)
    assert first["private_input"] != second["private_input"]


def test_a_refusal_is_untouched(plugin, vault, monkeypatch) -> None:
    """Redaction must not become a second refusal vocabulary."""
    monkeypatch.setattr(
        plugin.drop.tools,
        "claim_private_input",
        lambda args, **_kw: {"error": "unavailable", "detail": "no such drop"},
    )
    result = json.loads(plugin.claim_private_input({"drop_id": "x"}, session_id=SESSION))
    assert result == {"error": "unavailable", "detail": "no such drop"}


def test_state_db_and_fts_never_hold_the_plaintext(claimed, tmp_path) -> None:
    """The real ``SessionDB`` write path, including the ``messages_fts`` triggers.

    ``append_message`` is exactly what ``_flush_messages_to_session_db`` calls
    (``run_agent.py:2153``), with the tool-result string as ``content``.
    """
    from hermes_state import SessionDB

    db = SessionDB(db_path=tmp_path / "state.db")
    try:
        db.create_session("s1", source="test")
        db.append_message(
            "s1",
            role="tool",
            content=claimed,
            tool_name="claim_private_input",
            tool_call_id="call-1",
        )
        conn = sqlite3.connect(tmp_path / "state.db")
        try:
            blob = "\n".join(
                str(row) for row in conn.execute("SELECT * FROM messages").fetchall()
            )
            assert SECRET not in blob
            fts = conn.execute(
                "SELECT count(*) FROM messages_fts WHERE messages_fts MATCH ?",
                ("battery",),
            ).fetchone()[0]
            assert fts == 0, "the plaintext is discoverable through FTS"
        finally:
            conn.close()
    finally:
        db.close()


# ── the wire side ──────────────────────────────────────────────────────────


def _chat_messages(token: str) -> list:
    """The internal message list, before any provider translation.

    Shaped by ``make_tool_result_message`` — role ``tool``, a ``tool_call_id``,
    and the tool-result string as ``content``. Every provider-native list below
    is produced from *this* by the adapter Hermes itself uses.
    """
    return [
        {"role": "system", "content": "you are a helpful agent"},
        {"role": "user", "content": "log me in"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "claim_private_input", "arguments": "{}"},
                }
            ],
        },
        {
            "role": "tool",
            "tool_name": "claim_private_input",
            "tool_call_id": "call-1",
            "content": json.dumps({"ok": True, "private_input": token}),
        },
    ]


def _chat_completions_request(token: str) -> dict:
    return {"model": "test", "messages": _chat_messages(token)}


def _anthropic_messages_request(token: str) -> dict:
    """Real ``anthropic_messages`` shape.

    ``build_api_kwargs`` reaches this through
    ``AnthropicTransport.build_kwargs`` → ``convert_messages_to_anthropic``
    (``agent/chat_completion_helpers.py:1128-1143``). The tool result becomes a
    ``tool_result`` content part whose text hangs off ``content`` — *not*
    ``text`` — which a key-guessing walk misses.
    """
    from agent.anthropic_adapter import convert_messages_to_anthropic

    system, messages = convert_messages_to_anthropic(_chat_messages(token))
    return {"model": "test", "system": system, "messages": messages, "max_tokens": 1024}


def _codex_responses_request(token: str) -> dict:
    """Real ``codex_responses`` shape.

    ``build_api_kwargs`` reaches this through the Codex transport's
    ``build_kwargs`` → ``_chat_messages_to_responses_input``
    (``agent/chat_completion_helpers.py:1170-1186``). Tool results become
    ``function_call_output`` items keyed ``output``, in ``input`` rather than
    ``messages``, with no ``content`` key anywhere.
    """
    from agent.codex_responses_adapter import _chat_messages_to_responses_input

    return {"model": "test", "input": _chat_messages_to_responses_input(_chat_messages(token))}


def _bedrock_converse_request(token: str) -> dict:
    """Real ``bedrock_converse`` shape.

    ``build_api_kwargs`` reaches this through the Bedrock transport's
    ``build_kwargs`` → ``convert_messages_to_converse``
    (``agent/chat_completion_helpers.py:1155-1168``). The tool result lands two
    levels deeper than anywhere else: ``content[].toolResult.content[].text``.
    """
    from agent.bedrock_adapter import convert_messages_to_converse

    system, messages = convert_messages_to_converse(_chat_messages(token))
    return {"modelId": "test", "system": system, "messages": messages}


#: Every provider-native payload ``build_api_kwargs`` can hand to middleware.
#: Built by the real converters, so a core change to any of these shapes breaks
#: the test rather than silently stranding a secret on the durable side.
BUILDERS = {
    "chat_completions": _chat_completions_request,
    "anthropic_messages": _anthropic_messages_request,
    "codex_responses": _codex_responses_request,
    "bedrock_converse": _bedrock_converse_request,
}


@pytest.mark.parametrize("api_mode", sorted(BUILDERS))
def test_the_placeholder_really_is_in_the_provider_payload(claimed, api_mode) -> None:
    """Guard for the four tests below: if a converter stopped carrying the
    placeholder through at all, they would pass for the wrong reason."""
    token = json.loads(claimed)["private_input"]
    assert token in json.dumps(BUILDERS[api_mode](token))


@pytest.mark.parametrize("api_mode", sorted(BUILDERS))
def test_the_middleware_puts_the_plaintext_back_on_the_wire(claimed, vault, api_mode) -> None:
    token = json.loads(claimed)["private_input"]
    out = vault.llm_request_middleware(
        request=BUILDERS[api_mode](token), session_id=SESSION
    )
    assert out is not None, f"{api_mode}: nothing was substituted"
    wire = json.dumps(out["request"])
    assert SECRET in wire
    assert token not in wire, f"{api_mode}: a placeholder survived on the wire"


@pytest.mark.parametrize("api_mode", sorted(BUILDERS))
def test_the_middleware_leaves_the_persisted_structures_untouched(
    claimed, vault, api_mode
) -> None:
    """``_safe_copy`` can degrade to a shallow copy (``middleware.py:58-75``),
    so the structures handed to middleware may be the live, already-persisted
    ones. Nothing may be mutated in place at any depth."""
    token = json.loads(claimed)["private_input"]
    request = BUILDERS[api_mode](token)
    before = json.dumps(request, sort_keys=True)
    vault.llm_request_middleware(request=request, session_id=SESSION)
    assert json.dumps(request, sort_keys=True) == before


@pytest.mark.parametrize("api_mode", sorted(BUILDERS))
def test_a_placeholder_is_not_resolved_for_another_session(
    claimed, vault, api_mode
) -> None:
    """The placeholder is durable and the plaintext is not — so the token must
    not be a bearer capability for anyone who can read the transcript."""
    token = json.loads(claimed)["private_input"]
    out = vault.llm_request_middleware(
        request=BUILDERS[api_mode](token), session_id="other"
    )
    assert out is None


def test_a_lapsed_placeholder_stays_opaque(claimed, vault, monkeypatch) -> None:
    token = json.loads(claimed)["private_input"]
    monkeypatch.setattr(vault, "_clock", lambda: 10**9)
    out = vault.llm_request_middleware(
        request=_chat_completions_request(token), session_id=SESSION
    )
    assert out is None


def test_an_unknown_placeholder_is_left_alone(claimed, vault) -> None:
    """``claimed`` keeps the vault non-empty, so this exercises the walk rather
    than the empty-vault fast path."""
    out = vault.llm_request_middleware(
        request=_chat_completions_request("[hermes-drop:secret:" + "0" * 32 + "]"),
        session_id=SESSION,
    )
    assert out is None


def test_a_request_with_no_placeholder_is_not_rebuilt(claimed, vault) -> None:
    request = _chat_completions_request("nothing to see here")
    assert vault.llm_request_middleware(request=request, session_id=SESSION) is None


def test_a_caller_with_no_session_id_resolves_nothing(claimed, vault) -> None:
    token = json.loads(claimed)["private_input"]
    out = vault.llm_request_middleware(
        request=_chat_completions_request(token), session_id=""
    )
    assert out is None


# ── memory lifecycle ───────────────────────────────────────────────────────


def test_a_lapsed_entry_leaves_memory_with_no_further_claim(vault, monkeypatch) -> None:
    """The TTL has to be enforced by something, not merely checked the next time
    somebody happens to call in. A session that claims once and then goes quiet
    is the normal case, and it must not leave the plaintext resident."""
    monkeypatch.setattr(vault, "TTL_SECONDS", 0.05)
    vault.stash(SECRET, session_id=SESSION)
    assert vault.live_count() == 1

    deadline = time.monotonic() + 10
    while vault.live_count(SESSION) and time.monotonic() < deadline:
        time.sleep(0.01)

    # Read the module state directly: live_count() purges as a side effect, so on
    # its own it could not tell "a timer removed it" from "I just removed it".
    assert vault._ENTRIES == {}
    assert vault._TIMERS == {}


def test_clear_cancels_pending_expiries(vault) -> None:
    vault.stash(SECRET, session_id=SESSION)
    vault.clear()
    assert vault._ENTRIES == {}
    assert vault._TIMERS == {}


def test_a_busy_session_spends_its_own_budget_first(vault) -> None:
    """The cap is process-global, so the per-session ceiling is what stops one
    conversation evicting another's secret."""
    neighbour = vault.stash("neighbour-secret", session_id="other-session")
    for i in range(vault.MAX_ENTRIES_PER_SESSION * 2):
        vault.stash(f"mine-{i}", session_id=SESSION)

    assert vault.live_count(SESSION) == vault.MAX_ENTRIES_PER_SESSION
    token = vault.PLACEHOLDER_RE.fullmatch(neighbour).group(1)
    assert vault.resolve(token, session_id="other-session") == "neighbour-secret"


def test_the_global_ceiling_is_enforced(vault) -> None:
    sessions = vault.MAX_ENTRIES // vault.MAX_ENTRIES_PER_SESSION + 2
    for s in range(sessions):
        for i in range(vault.MAX_ENTRIES_PER_SESSION):
            vault.stash(f"s{s}-{i}", session_id=f"session-{s}")
    assert vault.live_count() <= vault.MAX_ENTRIES


# ── failing closed ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("bad", [None, 42, {"nested": "secret"}, ["secret"], b"bytes"])
def test_a_non_string_secret_is_refused_not_serialised(vault, bad) -> None:
    """Returning the payload unchanged would serialise the surprise straight
    into ``state.db`` — the one outcome this module exists to prevent."""
    with pytest.raises(vault.VaultError):
        vault.redact_tool_result(
            {"ok": True, "private_input": bad}, session_id=SESSION
        )


def test_an_empty_secret_is_refused(vault) -> None:
    with pytest.raises(vault.VaultError):
        vault.redact_tool_result({"ok": True, "private_input": ""}, session_id=SESSION)


def test_a_claim_with_no_session_id_is_refused_not_stashed_under_empty(vault) -> None:
    """Stashing under ``""`` would make one placeholder resolvable from any other
    session that also arrived without one."""
    with pytest.raises(vault.VaultError):
        vault.redact_tool_result({"ok": True, "private_input": SECRET}, session_id="")
    assert vault.live_count() == 0


def test_the_tool_handler_turns_a_refusal_into_internal_error(
    plugin, vault, monkeypatch
) -> None:
    """End to end: a vault refusal must reach the model as an error, never as the
    plaintext. ``session_id`` is absent exactly as a core path that forgot it
    would leave it."""
    monkeypatch.setattr(
        plugin.drop.tools,
        "claim_private_input",
        lambda args, **_kw: {"ok": True, "drop_id": "H" * 22, "private_input": SECRET},
    )
    result = json.loads(plugin.claim_private_input({"drop_id": "a"}))
    assert result["error"] == "internal_error"
    assert SECRET not in json.dumps(result)


def test_a_middleware_that_raises_leaves_the_placeholder_on_the_wire(
    claimed, vault, monkeypatch
) -> None:
    """``PluginManager.invoke_middleware`` isolates and logs a raising callback,
    so the failure mode is an unresolved placeholder, never a leak."""
    from hermes_cli.middleware import apply_llm_request_middleware
    from hermes_cli.plugins import get_plugin_manager

    def _boom(**_kwargs):
        raise RuntimeError("middleware is broken")

    manager = get_plugin_manager()
    monkeypatch.setitem(manager._middleware, vault.MIDDLEWARE_KIND, [_boom])

    token = json.loads(claimed)["private_input"]
    result = apply_llm_request_middleware(
        _chat_completions_request(token), session_id=SESSION
    )
    assert SECRET not in json.dumps(result.payload)
    assert token in json.dumps(result.payload)


# ── the seam itself ────────────────────────────────────────────────────────


def test_the_middleware_kind_matches_core(vault) -> None:
    from hermes_cli.middleware import LLM_REQUEST_MIDDLEWARE, VALID_MIDDLEWARE

    assert vault.MIDDLEWARE_KIND == LLM_REQUEST_MIDDLEWARE
    assert vault.MIDDLEWARE_KIND in VALID_MIDDLEWARE


def test_register_wires_the_middleware(plugin) -> None:
    registered: list = []

    class Ctx:
        class manifest:
            name = "hermes-drop"
            key = "hermes-drop"
            source = "user"

        def register_tool(self, name, **kwargs):
            pass

        def register_hook(self, hook_name, callback):
            pass

        def register_command(self, name, handler, **kwargs):
            pass

        def register_middleware(self, kind, callback):
            registered.append((kind, callback))

    plugin.register(Ctx())
    assert [kind for kind, _ in registered] == [plugin.drop.vault.MIDDLEWARE_KIND]


def test_register_survives_a_core_without_middleware_support(plugin) -> None:
    """A core that predates ``register_middleware`` must not break plugin load —
    ``register()`` raising takes the tools and ``/drop`` down with it."""

    class Ctx:
        class manifest:
            name = "hermes-drop"
            key = "hermes-drop"
            source = "user"

        def register_tool(self, name, **kwargs):
            pass

        def register_hook(self, hook_name, callback):
            pass

        def register_command(self, name, handler, **kwargs):
            pass

    plugin.register(Ctx())


def test_the_real_middleware_pass_reaches_the_provider_payload(
    claimed, vault, temp_hermes_home, monkeypatch
) -> None:
    """Through the real ``PluginManager`` and the real
    ``apply_llm_request_middleware``, which is the function whose return value
    becomes ``api_kwargs`` at ``conversation_loop.py:2112``."""
    from _seam import install_plugin_for_real
    from hermes_cli.middleware import apply_llm_request_middleware

    from conftest import PLUGIN_DIR

    install_plugin_for_real(monkeypatch, temp_hermes_home, PLUGIN_DIR)

    token = json.loads(claimed)["private_input"]
    request = _chat_completions_request(token)
    result = apply_llm_request_middleware(request, session_id=SESSION)

    assert result.changed is True
    assert SECRET in json.dumps(result.payload["messages"])
    assert SECRET not in json.dumps(request["messages"]), "the durable copy was rewritten"
