# Changelog

All notable changes to this project are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); while the major version
is `0`, minor versions may carry breaking changes.

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
