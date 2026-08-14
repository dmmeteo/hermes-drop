# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); while the major version
is `0`, minor versions may carry breaking changes.

## [Unreleased]

Plugin `0.5.0`, broker `0.5.0`. The control protocol moves to `version: 2` — an
additive revision: one optional `claim` request field, one new error, and a
`protocol_version` on the `create` response. A version 1 client sends none of them
and reads none of them, and behaves exactly as it did before.

### Added

- **Outbound drops, end to end: Hermes hands the user a secret.** The reveal page ships
  in the browser bundle and the plugin registers a third tool, `send_private_output`.
  Hermes posts one message into the conversation it was asked in — a link, a 3-digit
  code and what "one reveal" means — the user types the code, the browser decrypts
  locally with the key from the URL fragment, and the broker destroys the payload on
  acknowledgement. `GET`/`HEAD` still consume nothing, so a link preview, a scanner or
  an antivirus cannot spend a drop; three wrong codes destroy it. Nothing durable is
  written for an outbound drop and no waiter is armed — there is no submission to wait
  for and no later claim to authorise. Documented in
  `docs/OUTBOUND_SECRET_DROP_MVP.md` and `SECURITY.md`.

- **A revealed payload is structured, and the page renders however many fields it
  holds.** Login, password, API key, URL, note — each with its own label and Copy
  button, the sensitive ones masked behind a per-field Show/Hide, the rest displayed
  normally. Copy copies the real value while it is still masked, so a password never
  has to appear on screen to be pasted. A missing or unrecognised field type is treated
  as sensitive.

- **Bounded, atomic payload validation, in both languages.** `create_outbound_drop`
  takes a `payload_format` (`opaque` — the default, unchanged for existing callers — or
  `structured`) and validates a structured payload *before* minting anything: a closed
  type set, safe labels and titles (no Unicode control or bidi-format characters, no
  exotic whitespace, no duplicates), a bounded field count, per-value size and
  canonical total, and `http`/`https`-only URL values. A refusal is atomic — no drop,
  no link, no code — and carries a `reason` code from a closed set rather than prose
  quoting the payload. The bounds are published in `contract/control-protocol.json` →
  `outbound_payload` and mirrored by the plugin, which is held against the running
  broker by a cross-language test in both directions.

- **Broker-side value generation.** A field may carry
  `generate: {kind, length}` instead of a value, and the broker draws it with a CSPRNG
  inside the create call. For a freshly minted password or key the plaintext therefore
  never enters a tool argument, a model turn or a durable transcript — which is the one
  exposure the outbound direction could not otherwise close. See "The outbound tool's
  *arguments* carry the secret" in `SECURITY.md` for what remains true of a *relayed*
  value.

- **An outbound chat notice, rendered by the broker.** `create_outbound_drop` accepts
  the same `notice_platform` as `create` and answers with one ready-to-post message, so
  posting a link and a code costs one round trip and one implementation of a sentence
  that has to be right on every platform. It quotes **nothing** from the payload except
  its field count: the message is Markdown going to a platform that renders links, and a
  model-composed title could otherwise forge one.

- **Lifecycle/FSM verification.** A dedicated state-sequence suite now pins the
  broker's `pending → submitted → claimed/destroyed` machine, including concurrent
  and duplicate operations, expiry from every state, malformed calls, lossless
  oversized-claim refusal, shutdown, and randomized operation sequences. The
  verified lifecycle and the limits of best-effort deletion are documented in
  `SECURITY.md`.

- **Restart-recovery E2E.** A cross-language integration test now creates a real
  drop, crashes and restarts the real Node broker on the same control socket, and
  drives the Hermes journal/reconciler path to the quiet expired state. It proves
  the old secret is unavailable, the waiting message loses its URL, and journal
  temp-file debris cannot become a live entry. Reconciliation now retries transient
  broker-unavailable and unresolved-lane outcomes with bounded accounting instead
  of consuming its process latch forever.

- **Lossless claim boundary.** The broker no longer consumes a payload it cannot
  hand over. A claiming client states the largest response line it can read
  (`max_response_bytes` on `claim`), the broker sizes the whole answer against it
  *before* the record is retired, and an answer that would not fit comes back as
  `response_too_large` with `required_bytes` and the ceiling — payload untouched,
  still one-shot, still claimable until the TTL. The check lives inside
  `broker.claim`'s synchronous single-use gate, next to the retirement it guards,
  and the size is arithmetic on the real line (`claimResponseBytes`), not an
  estimate; a seam-4 test pins it against an actual response.

  This closes the last window in which a successful submission could be destroyed
  by the act of reading it. The plugin's control client reads at most 1 MiB and
  now advertises that same constant on every claim, so the one line it could fail
  to buffer is a line it is never sent. Omitting the field still means "unbounded
  reader", which is what `bin/handoff-admin.mjs` is — and is why the admin CLI
  remains the recovery path for a payload some other reader is too small for.

  An advertised ceiling has a floor: `transport.min_response_bytes` (1024), below
  which the claim is refused as `invalid_request`. Every answer `claim` can give
  other than a payload fits inside it — `unavailable` 35 bytes, `invalid_request`
  39, `response_too_large` 114 at its widest — so a client small enough to be
  refused can still read the refusal. Sizes are of the whole line *including its
  newline* (`transport.size_convention`), which is the unit `StreamReader` applies
  its own limit to; a test reads a line of exactly the limit to pin that the two
  conventions are one.

  `contract/control-protocol.json` carries all of it: `transport.max_response_bytes`
  and `min_response_bytes`, the new request field, and the third error body with a
  note on why it is deliberately distinguishable from `unavailable`.

- **`protocol_version` on the `create` response,** so a plugin can tell what it is
  talking to. The broker and the plugin ship from one repo but install and upgrade
  separately, and a protocol 1 broker accepts `max_response_bytes`, ignores it and
  destroys an oversized payload exactly as 0.4.0 did — so "I sent a ceiling" is not
  evidence the boundary is lossless. Absence of the field means version 1.

  The plugin reads it at create time and refuses the drop with the new
  `broker_too_old` error in **one** case: a protocol 1 broker whose advertised
  `max_plaintext_bytes` exceeds what this client can read back (~783 KB). That is
  the only combination in which a claim can still destroy a secret with no refusal
  available anywhere. The refusal lands before the link is posted — no message, no
  journal entry, no waiter, nobody asked for a secret — and the minted handoff
  lapses unused, so there is nothing to recover from it. Operator remedy, named
  with both numbers in `agent.log`: upgrade the broker to 0.5.0 or newer, or lower
  `HANDOFF_MAX_PLAINTEXT_BYTES` under the client ceiling.

  Every other combination proceeds. A protocol 1 broker at or under the readable
  range — including the shipped 64 KiB default — works as it always did, with one
  `agent.log` warning per drop naming the version gap. A protocol 2 broker with an
  oversized cap warns, because an oversized claim is now refused rather than
  destroyed and the cost is a round trip rather than a secret.

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

### Changed

- **A claim that could not be recorded no longer discards the secret.** The broker
  destroys its copy as it answers, so `claimed_at` is necessarily written after
  the plugin holds the only remaining copy. An `OSError` from that write — a full
  or read-only `$HERMES_HOME` — used to propagate into the tool guard and return
  `internal_error`, losing a secret the system had already delivered. The write is
  now contained: the payload is returned with a note telling the model not to
  retry, and the failure is an `ERROR` line for the operator. One-shot semantics
  are unchanged and unchanged in mechanism — the retry the unmarked entry appears
  to permit is refused by the broker's payload-free receipt, which is why this
  needs no distributed transaction. What remains true is that the journal
  understates the claim until the entry lapses, and the reconciler acts on that:
  `received` with no `claimed_at` past the 15-minute grace is re-announced, capped
  by `MAX_ANNOUNCE_ATTEMPTS` (5), so the model can be told again to claim a drop it
  already holds — bounded, answered `unavailable`, and named in `SECURITY.md`.

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
