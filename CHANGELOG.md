# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); while the major version
is `0`, minor versions may carry breaking changes.

## [Unreleased]

Plugin `0.5.0`. The broker is unchanged at `0.4.0`.

### Added

- **Durable secret sanitization.** A claimed secret no longer reaches Hermes'
  durable session state. The tool result the plugin hands core carries an opaque
  ASCII placeholder (`[hermes-drop:secret:<32 hex>]`), so nothing downstream of
  the plugin — `state.db`, the `messages_fts*` index, the JSON session log, or a
  backup of any of them — ever holds the plaintext. New
  `integrations/hermes-drop/drop/vault.py` holds it in gateway memory instead and
  registers `llm_request` middleware, which substitutes it into the provider
  request payload (a deep copy core makes for middleware) so the active model turn
  still gets the real secret.

  The split exists because Hermes persists a tool result *before* the model sees
  it, and `transform_tool_result` sees only one string that is both the durable
  row and the wire. Redaction is therefore done in the plugin, upstream of core,
  and depends on no Hermes hook: `transform_tool_result` fails open, which is not
  a property to hang a password on. Both halves fail closed — a middleware error
  leaves the placeholder on the wire, and a vault that cannot hold the secret
  turns the claim into `internal_error`.

  Substitution walks the payload structurally rather than by key, because by the
  time middleware runs Hermes has already translated the tool result into the
  active `api_mode`'s shape and the placeholder lands somewhere different in each
  — `messages[].content` (`chat_completions`), a `tool_result` part's `content`
  (`anthropic_messages`), a `function_call_output`'s `output` under `input`
  (`codex_responses`), `toolResult.content[].text` (`bedrock_converse`). Tests
  build all four with Hermes' own converters.

  Entries are bound to the claiming `session_id`, so the placeholder that *does*
  persist is not a bearer capability; a claim that arrives with no session id is
  refused rather than stashed under `""`. Entries lapse after 15 minutes, enforced
  by a per-entry timer so a session that claims once and goes quiet does not leave
  the plaintext resident. At most 4 live secrets per session and 32 per process.
  A non-string or empty `private_input` is refused rather than serialised. Origin
  authorization and one-shot claim behaviour are untouched.

  Uses only supported plugin API (`ctx.register_middleware`); no new Hermes core
  patch. Residual exposures — post-middleware request observers, the model's own
  output, memory residency — are documented in `SECURITY.md`.

## [0.4.0] — 2026-08-03

First public release.

### Added

- **Broker.** Self-hosted Node.js service that mints one-shot drop links, serves a
  single-page browser form, opens RFC 9180 HPKE envelopes
  (`DHKEM(P-256, HKDF-SHA256)` / `HKDF-SHA256` / `AES-256-GCM`) and hands the
  plaintext to exactly one local claim over a `0600` Unix control socket. No admin
  HTTP endpoint. In-memory state only; per-drop private keys are never persisted.
- **Hermes plugin.** Native `/drop` slash command, plus the `request_private_input`
  and `claim_private_input` tools. Both entry points run the same async workflow.
- **Origin binding.** The link is posted to the conversation the request came from,
  resolved and then verified against the gateway's bound session context, or
  refused. Neither tool schema can express a destination.
- **Discord and Telegram support.** An unsupported platform is refused by name
  rather than degraded or redirected.
- **One chat message, edited in place** through three fixed states — waiting,
  received, expired — with a platform-rendered relative countdown and no
  per-minute edits.
- **Durable journal and reconciler**, so a gateway restart mid-drop does not orphan
  a live link or a stale status message.
- **Installer** (`bin/install-hermes-drop.sh`) with `install`, `--copy`,
  `--uninstall` and `--preflight`, profile-scoped through `HERMES_HOME` and never
  guessing a profile. Its `plugins.enabled` edit is validated by a YAML parser,
  applied as whole-line changes and written by atomic rename, so operator comments
  and formatting survive; an ambiguous layout is refused with the file untouched.
- **Local admin CLI** (`bin/handoff-admin.mjs`): `create`, `await`, `claim`,
  `notice`.
- **Hermes core patches** in `patches/hermes-agent/`, required until upstream has
  equivalent support. See that directory's README.
- Project documentation: README, `SECURITY.md`, `CONTRIBUTING.md`, MIT `LICENSE`.

### Fixed

- The config editor classified an ordinary plain scalar containing `/` — such as a
  namespaced plugin id like `dashboard_auth/basic` — as a non-scalar entry, and
  refused to install into any profile whose `plugins.enabled` listed one.
  Anchors, aliases, explicit tags and merge keys are now detected from the YAML
  parser's event stream rather than by a regex over raw text, so real machinery is
  still refused — including a merge key inside the `plugins` block, which the
  regex missed — while the same characters inside an ordinary quoted scalar are
  accepted.
- The config editor wrote `config.yaml` in place, so an interrupted write could
  leave a truncated document. It now writes a temp file in the same directory and
  renames it over the original, preserving the file's permission bits.
- One reconciler path consumed the process's single startup attempt without
  releasing it when the gateway loop had already gone away, and left an un-awaited
  coroutine behind.

### Known limitations

Not independently security-audited; the HPKE library is not formally audited
either. Not end-to-end encryption — the broker holds the decryption key. Requires
a patched Hermes. See [SECURITY.md](SECURITY.md) and the README's Limitations
section for the full list.

[0.4.0]: https://github.com/dmmeteo/hermes-drop/releases/tag/v0.4.0
