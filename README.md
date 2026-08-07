# Hermes Drop

Ask for a secret without putting it in the chat.

Hermes Drop gives a [Hermes](https://github.com/NousResearch/hermes-agent) agent a
way to request a password, token or key from the person it is talking to: it posts
a short-lived link into **the conversation it is already in**, the user pastes the
secret into a one-page web form, the browser encrypts it, and the agent is woken
when it arrives. The plaintext never appears in a chat message.

Two pieces, both self-hosted by you:

- a **broker** — a small Node.js service behind your own HTTPS reverse proxy, which
  mints links, receives sealed envelopes and hands the plaintext to exactly one
  local claim; and
- a **Hermes plugin** — which provides the `/drop` command, the
  `request_private_input` and `claim_private_input` tools, and the durable
  bookkeeping that survives a restart.

---

> ### ⚠️ Not independently security-audited
>
> This project has had **no formal or third-party security audit**. It was built
> against a written threat model and has substantial automated test coverage,
> including RFC 9180 test vectors, but that is not the same thing as an audit.
>
> Its cryptography comes from [`@hpke/core`](https://github.com/dajiaji/hpke-js),
> which **also states that it has not been formally audited**.
>
> Read [Threat model](#threat-model) and [Limitations](#limitations) before you
> trust it with anything. In particular: this is **not** end-to-end encryption —
> the broker holds the decryption key by design, and your Hermes host, the broker
> process and the model are all trusted with the plaintext.

---

## Requires a patched Hermes

**Stock Hermes cannot run Hermes Drop correctly.** Two fixes to Hermes' gateway are
required, and no released Hermes version contains them yet. They are supplied as
`git format-patch` artifacts in [`patches/hermes-agent/`](patches/hermes-agent/),
based on Hermes commit `dd241cf0cd`:

| Patch | What it fixes |
|---|---|
| `0001` | A plugin slash command cannot see which conversation invoked it, so it reads whichever session last mirrored its identity into `os.environ`. This is what `/drop`'s origin binding rests on. |
| `0002` | A hyphenated plugin command invoked in its underscored form (`/hermes_drop` — the form Telegram's command menu sends) bypasses the slash-access policy entirely. |

Both are general fixes to Hermes' plugin-command path with their own tests, not
Drop-specific hooks. They are temporary: if equivalent support lands upstream, the
patches directory goes away. See
[`patches/hermes-agent/README.md`](patches/hermes-agent/README.md) for the base
SHA, apply order and test commands.

Without patch `0001`, the plugin still loads and refuses safely — `/drop` returns
`origin_unverified` rather than guessing a destination — but it will not work.

## Features

- **`/drop`** — a deterministic slash command. No model turn, no prose, no second
  interpretation of what the user asked for.
- **`request_private_input`** and **`claim_private_input`** — the same operation,
  reached from a model turn instead.
- **Origin-bound by construction.** Neither the command nor the tool schema has a
  destination field — no `platform`, `chat_id`, `channel`, `thread_id` or `target`
  at any depth. A model that cannot express a destination cannot pick the wrong
  one. The link goes to the conversation the request came from, verified against
  the gateway's own session context, or it is refused.
- **One-shot browser encryption.** RFC 9180 HPKE (`DHKEM(P-256, HKDF-SHA256)` /
  `HKDF-SHA256` / `AES-256-GCM`) sealed in the browser with `crypto.subtle`.
- **One claim.** The payload is destroyed as it is read; a second claim gets the
  same generic unavailable answer as a wrong capability.
- **Not written to `state.db`.** The claimed plaintext never enters Hermes'
  durable session store, FTS index, session log or backups — only a placeholder
  does. See [Durable sanitization](#durable-sanitization).
- **Durable journal and reconciler.** A gateway restart mid-drop does not orphan a
  live link or a waiting status message.
- **One chat message, edited in place**, through three fixed states — waiting,
  received, expired. The received and expired states carry no URL, capability or
  id. No per-minute edits: the countdown is a platform-rendered relative
  timestamp.
- **Discord and Telegram.** An unsupported platform is refused by name, never
  degraded to a plain notice and never redirected.
- **64 KiB** maximum plaintext, **30 minutes** default lifetime (1–60 configurable
  per drop).

## How it works

```
  user types /drop, or the model calls request_private_input
        │
        ▼
  plugin resolves the ORIGIN (platform, profile, chat, thread)
  and verifies it against the gateway's bound session context ──► refuse if unverified
        │
        ▼
  broker mints:  handoff_id · 128-bit capability · per-drop P-256 key pair
                 stores only SHA-256(capability); the private key never leaves memory
        │
        ▼
  plugin posts ONE message into that same conversation:  https://host/#<capability>
        │                                                          ▲
        │                                        capability is in the URL fragment,
        │                                        so it never reaches the request
        │                                        target, access logs or Referer
        ▼
  browser  GET / ──► one static page
           POST /api/metadata  (capability in a header) ──► public key, suite, deadline
           POST /api/submit    (one HPKE SealBase envelope)
        │
        ▼
  broker opens the envelope, atomically moves pending ──► submitted,
  drops the key pair, and wakes the waiting plugin (nothing polls)
        │
        ▼
  plugin edits the SAME message to "received", then claims ONCE over a
  0600 Unix socket; plaintext reaches the model as a tool result
```

`info = "hermes-handoff/v1" ‖ 0x00 ‖ version ‖ suite_id ‖ handoff_id ‖ SHA-256(capability)`
is bound into the AEAD, so an envelope cannot be replayed into another drop,
version or suite — it fails at decryption.

### State machine

```
pending ──submit(AEAD ok)──► submitted ──claim──► claimed (receipt only, no payload)
   │                             │                         │
   └── expiry / 3 AEAD failures / broker restart ──────────┴──► destroyed
```

An AEAD failure does not consume a drop; three of them destroy it. Retries are
idempotent by envelope digest: re-POSTing the *same* envelope returns the same
receipt for the rest of the lifetime and never delivers twice, while a *different*
envelope against a consumed drop gets the unavailable answer.

### Durable sanitization

A claimed secret arrives as a tool result, and Hermes persists a tool result
*before* the model ever sees it: `agent/tool_executor.py` appends the result
string to the message list and flushes it straight into `state.db`, the
`messages_fts*` index and the JSON session log, and only then builds the API
request. There is one string at that moment and it is both the durable row and
the wire, so no single seam can keep the plaintext out of one and in the other.

Hermes Drop splits them:

- the plugin substitutes an opaque ASCII placeholder —
  `[hermes-drop:secret:<32 hex>]` — into the tool result **before** it becomes a
  string, so nothing downstream of the plugin ever holds the plaintext. This
  depends on no Hermes hook, deliberately: `transform_tool_result` is
  `has_hook`-gated and fails open, which is not a property to hang a password on.
- `llm_request` middleware puts the plaintext back into the *provider payload*,
  which Hermes hands to middleware as a deep copy. The persisted message dicts
  are never touched.

By the time middleware runs, Hermes has already translated the tool result into
whatever the active `api_mode` speaks, and the placeholder sits in a different
key in each — `messages[].content` for `chat_completions`, a `tool_result` part's
`content` for `anthropic_messages`, a `function_call_output`'s `output` under
`input` for `codex_responses`, and `toolResult.content[].text` for
`bedrock_converse`. Rather than enumerate those, the substitution walks the
payload structurally, so a transport added later is covered too. Tests build all
four shapes with Hermes' own converters, so a change to any of them fails the
suite instead of quietly stranding a secret on the durable side.

Both halves fail closed. A middleware error is isolated and logged by Hermes,
leaving the placeholder on the wire; a vault that cannot hold the secret turns
the claim into `internal_error`. The failure mode is a model that cannot read
the secret — never a secret in `state.db`.

The placeholder outlives the plaintext in the transcript, so it is bound to the
session that claimed it and resolved for no other, and the plaintext lapses from
memory after **15 minutes**. Past that the model reads the placeholder and is
told to ask for a new drop.

`llm_request` middleware is a supported plugin API
(`ctx.register_middleware`); no Hermes core patch is involved. A Hermes without
it still loads the plugin — the claim then returns a placeholder the model
cannot resolve, and the plugin says so in `agent.log`.

## Threat model

**Trusted with the plaintext, by design:** the host running the broker, its root
user, the broker process, your Hermes gateway process, and the model handling the
conversation. Browser-side encryption is defence in depth against TLS-terminating
hops and request-body logging *in front of* the broker — not protection from any
of those principals.

**What it is designed to stop:**

| | |
|---|---|
| The secret in chat history | The plaintext is never sent as a message, on any platform. |
| The secret in URLs and logs | The capability rides in the URL `#fragment`; the plaintext is never in a request target, an access log, a `Referer` header or an HTTP response. |
| A link landing in the wrong conversation | No destination is expressible by the model; the origin is resolved and then verified, or refused. |
| Replay into another drop | The capability hash, drop id, version and suite are bound into the HPKE `info`. |
| A second reader | One claim, then a payload-free receipt. |
| Guessing a link | 128 bits of CSPRNG entropy, a 30-minute default lifetime, a uniform unavailable answer for every wrong guess, and nothing persisted to attack offline. |
| A stolen bot token editing history | The status message carries no capability once it leaves the waiting state. |
| The claimed secret in `state.db` | The tool result Hermes persists carries a placeholder, not the plaintext. The plaintext is held in gateway memory and substituted into the provider request only. See [Durable sanitization](#durable-sanitization). |

**Accepted residual risks:**

- **A stolen live URL can submit first.** Bounded by 128-bit entropy, the lifetime
  and one-shot consumption. The link is delivered through your chat platform, so
  anyone who can read that conversation can use it — which is the intended
  audience, and the reason the drop is origin-bound.
- **The claimed plaintext reaches the model's context.** The model is a trusted
  principal, and what it does next is not confined: if it echoes the secret into
  a reply or passes it as an argument to another tool, *that* is persisted like
  any other model output. What is no longer persisted is the claim itself — see
  below.
- **Authenticated HTTPS is load-bearing.** It authenticates the JavaScript that
  performs the encryption; `crypto.subtle` only exists in a secure context.

## Limitations

- **Not end-to-end encryption.** See above. The broker can decrypt.
- **Not independently audited**, and neither is the HPKE library. See the warning
  at the top.
- **Not hardened deletion.** "Destroyed" means dropped from an in-memory map and a
  best-effort zero-fill. Nothing is claimed about swap, core dumps or snapshots.
- **A broker restart destroys every pending drop.** Deliberate: the per-drop
  private keys are never persisted, so a restarted process cannot decrypt an old
  ciphertext. Live links stop working and their status messages are reconciled to
  expired.
- **The claim response has a size ceiling.** The plugin reads a claim response up
  to 1 MiB, which is ~783 KB of plaintext after base64. The shipped broker default
  is 64 KiB, an order of magnitude clear of it, and a test pins that — but if you
  raise `HANDOFF_MAX_PLAINTEXT_BYTES` past the ceiling, a payload above it is
  destroyed on claim and reported unavailable. The plugin warns in `agent.log` at
  create time when a broker advertises a cap it cannot read back.
- **Durable sanitization does not confine the model or the wire.** Three
  exposures survive it, all verified rather than assumed:
  - anything the model *does* with the secret — echoing it into a reply, passing
    it as a tool argument — is persisted normally. The model is trusted.
  - the plaintext is on the wire to your model provider. That is the point of the
    feature.
  - anything that reads the request *after* middleware sees the plaintext:
    Hermes' `pre_api_request` hook (so an observability plugin such as langfuse
    would ship it), **NeMo Relay** (which wraps the provider call itself, so every
    Relay interceptor and exporter in that profile sees the post-substitution
    body), and `HERMES_DUMP_REQUESTS=1` (which writes it to disk). None is on by
    default; do not enable any of them on a gateway that handles drops.
- **A claimed secret lapses after 15 minutes**, enforced by a timer rather than
  checked on the next call in. Past that the transcript keeps the placeholder and
  the model must ask for a new drop. Claim then use; do not claim and sit on it.
- **The memory cap is process-global.** At most 4 live secrets per session and 32
  across the gateway. The per-session cap means a busy conversation evicts its own
  oldest first, but the global one is shared: past it another session's secret can
  be evicted early, leaving its model with an unresolvable placeholder.
- **No file transfer**, no reverse/outbound delivery, no multi-recipient drops.
- **A drop cannot be opened during a wake turn** if the conversation's lane was
  rewritten in between: the plugin refuses rather than guessing, and the user types
  `/drop`. Claiming is unaffected.
- **Single broker process.** State is in-memory; there is no clustering story.

## Quick start (local, no Hermes)

Runs the broker on your own machine and drives it with the admin CLI — enough to
see the whole loop.

```bash
npm ci
npm run verify        # build the browser bundle, run every test, run the smoke test
npm start &           # broker on http://127.0.0.1:8787

node bin/handoff-admin.mjs create --ttl 1800   # prints the URL
# open it, paste something, press Send
node bin/handoff-admin.mjs claim <drop-id>     # prints the plaintext, once
node bin/handoff-admin.mjs claim <drop-id>     # exits 1: unavailable
```

The admin CLI is the local operator path; there is no admin HTTP endpoint.

| Command | What it does |
|---|---|
| `create [--ttl <s>] [--notice] [--platform <discord\|telegram\|plain>]` | Mints a drop. `--notice` prints the ready-to-post waiting message instead of the bare URL. An unlisted platform exits `2`, never falls back. |
| `await <id> [--timeout <s>]` | Blocks until the submission and prints one non-secret line. Exit `0` submitted, `1` transport failure, `2` usage, `3` unavailable. |
| `claim <id> [--wait <s>]` | Prints the plaintext to stdout, once. |
| `notice <received\|expired>` | Prints the content the waiting message is edited into. Needs no broker. |

## Deploying the broker

The broker expects to sit behind a reverse proxy that terminates HTTPS. The
supplied `compose.yml` targets [Traefik](https://traefik.io/) on an existing
external Docker network named `proxy`, publishing no port of its own; adapt the
labels if you use something else.

**1. Set your public hostname and socket directory.** Copy `.env.example` to
`.env`:

```bash
cp .env.example .env
# HANDOFF_PUBLIC_HOST=drop.example.com
# HANDOFF_SOCKET_DIR=/srv/hermes-drop/run
```

**2. Create the control-socket directory yourself, before first start.** The
control socket lives on a host directory so a local process — your Hermes gateway
— can reach the admin path without `docker exec`. Docker would create a missing
bind-mount source as `root:root`, which the broker refuses to serve out of:

```bash
install -d -m 700 -o 1000 -g 1000 /srv/hermes-drop/run
bin/install-hermes-drop.sh --preflight        # read-only: validates, changes nothing
```

**3. Build and start.**

```bash
docker compose build && docker compose up -d
docker compose exec handoff node bin/handoff-admin.mjs create
```

`build && up -d` is a **recreate**, and that matters: a bare `docker restart`
reuses the existing container, so it keeps both the old image *and* the old
environment — a container created when the default lifetime was 600 seconds keeps
600 forever, however often it is restarted and whatever `compose.yml` says today.

> **Never clean up a broker with a pattern kill.** A container's argv appears
> verbatim on the *host* process table, so `pkill -f "node src/main.js"` run from a
> checkout reaches into the running container and takes it down. The container
> runs `node /app/src/main.js --role=handoff-broker-container` so a careless
> pattern misses it, but the rule stands: kill the exact PID, or
> `docker compose stop`.

The container runs as a pinned `1000:1000` with a read-only root filesystem, all
capabilities dropped, and a `tmpfs` for `/tmp`.

## Installing the Hermes plugin

The installer never guesses a profile. Every invocation names its target.

```bash
HERMES_HOME="$HOME/.hermes" bin/install-hermes-drop.sh install
```

That symlinks this checkout into `$HERMES_HOME/plugins/hermes-drop` and adds
`hermes-drop` to `plugins.enabled` in that profile's `config.yaml`. The config edit
is surgical — validated by a YAML parser, applied as whole-line changes, written by
atomic rename — so your comments and formatting survive, and an ambiguous layout is
**refused** with the file untouched rather than guessed at.

| Flag | Use |
|---|---|
| `install` | Symlink the checkout. The repo stays the single source of truth. |
| `--copy` | Pin a versioned copy instead, for hosts where the profile must not depend on this checkout. |
| `--uninstall` | Remove the plugin directory and that one `plugins.enabled` entry. |
| `--preflight` | Validate the host control-socket directory. Read-only. |

Then point the plugin at the broker's socket, in that profile's `config.yaml`:

```yaml
plugins:
  entries:
    hermes-drop:
      control_socket: /srv/hermes-drop/run/control.sock
```

or with `HERMES_DROP_CONTROL_SOCKET`. The default is `/run/handoff/control.sock`.
An explicitly empty value switches the tools off. **Do not set
`plugins.entries.hermes-drop.allow_tool_override`** — Drop registers new tool names
and must never replace a built-in; the installer never writes it.

The installer restarts nothing. Plugin discovery and command registration run at
gateway start, so **restart your gateway** when you are ready.

### Multiple profiles

Everything is profile-scoped through `HERMES_HOME`; nothing falls back to
`~/.hermes`.

```bash
HERMES_HOME=/srv/profiles/work    bin/install-hermes-drop.sh install
HERMES_HOME=/srv/profiles/staging bin/install-hermes-drop.sh install
```

Each profile gets its own `plugins.enabled` entry, its own `control_socket`
setting, and its own journal at `$HERMES_HOME/state/hermes-drop`. Profiles can
share one broker — a drop is bound to its conversation, not to a profile — or you
can run a broker per profile with a socket directory each. If a gateway serves
several platforms at once, patch `0001` is what keeps each profile's drops from
reading another's session identity.

If PyYAML is not importable from the interpreter on your `PATH`, name one:

```bash
HERMES_DROP_PYTHON="$HERMES_HOME/hermes-agent/venv/bin/python" \
HERMES_HOME="$HERMES_HOME" bin/install-hermes-drop.sh install
```

## Verifying an install

```bash
npm run verify                                    # broker: build, tests, runtime smoke
cd integrations/hermes-drop/tests && python -m pytest -q    # plugin
```

Then, against the live pair:

```bash
# the socket the gateway will use is reachable and correctly owned
HANDOFF_SOCKET_DIR=/srv/hermes-drop/run bin/install-hermes-drop.sh --preflight

# the broker answers on it
docker compose exec handoff node bin/handoff-admin.mjs create --ttl 60

# the plugin is enabled and its tools registered (after a gateway restart)
hermes plugins list
```

Finally, type `/drop` in a Discord or Telegram conversation with your agent. The
link must arrive **in that conversation** — that is the property worth checking by
hand.

## Upgrading

```bash
git pull
npm ci && npm run verify
docker compose build && docker compose up -d      # broker: recreate, never restart
```

A symlinked plugin needs no reinstall — restart the gateway to pick up the new
code. A `--copy` install does: re-run `bin/install-hermes-drop.sh --copy`.

Re-check `patches/hermes-agent/` after upgrading: if the base SHA has moved, the
patches may need rebasing onto your Hermes checkout.

Treat a `@hpke/core` bump as a change that must re-run `test/hpke-vectors.test.js`
before it carries a real secret.

## Uninstalling

```bash
HERMES_HOME="$HOME/.hermes" bin/install-hermes-drop.sh --uninstall
docker compose down
```

`--uninstall` is complete on its own. It removes the plugin directory and exactly
one `plugins.enabled` entry — it does **not** restore a config snapshot, because
that would discard every unrelated change you made since installing. Any
`config.yaml.hermes-drop-backup-*` files are left as an audit trail; delete them
yourself. Nothing is restarted; a running gateway keeps the tools registered until
it restarts.

To revert the Hermes patches, `git switch` your Hermes checkout back to its base
and restart the gateway.

## Configuration

### Broker

| Env var | Default | Notes |
|---|---|---|
| `HANDOFF_PORT` / `HANDOFF_HOST` | `8787` / `0.0.0.0` | `0` picks an ephemeral port. |
| `HANDOFF_BASE_URL` | derived from the listening port | Absolute base for printed URLs. |
| `HANDOFF_TTL_SECONDS` | `1800` | Deployment policy; never client-supplied. |
| `HANDOFF_MAX_TTL_SECONDS` | `3600` | Ceiling for `create --ttl`. |
| `HANDOFF_MAX_PLAINTEXT_BYTES` | `65536` | Enforced by the broker. See the claim-ceiling limitation above before raising it. |
| `HANDOFF_MAX_BODY_BYTES` | `131072` | Request-body ceiling; also bounded at the proxy. |
| `HANDOFF_MAX_AEAD_FAILURES` | `3` | Destroys the drop after this many. |
| `HANDOFF_CONTROL_SOCKET` | `./run/control.sock` | `/run/handoff/control.sock` in the container. |
| `HANDOFF_SOCKET_DIR` | *(required by compose)* | Host directory bind-mounted at `/run/handoff`. Mode `0700`, owned by `1000:1000`, created before first start. |
| `HANDOFF_ENABLE_HSTS` | off | Enable only behind HTTPS. |

### Plugin

| Setting | Default | Notes |
|---|---|---|
| `HERMES_DROP_CONTROL_SOCKET` env, or `plugins.entries.hermes-drop.control_socket` | `/run/handoff/control.sock` | An explicitly empty value disables the tools. Latched once per process. |
| Journal | `$HERMES_HOME/state/hermes-drop` | One JSON file per drop. Non-secret: routing, state, timestamps, purpose label. Never the capability or the payload. |

## Dependencies

| Package | Version | License | Why |
|---|---|---|---|
| [`@hpke/core`](https://github.com/dajiaji/hpke-js) | 1.9.0 (exact) | MIT | RFC 9180 HPKE over WebCrypto only. Pulls `@hpke/common` 1.10.1, pinned via `overrides`. |
| [`esbuild`](https://github.com/evanw/esbuild) | 0.28.1 (exact, dev only) | MIT | Bundles the page into one self-hosted file, so the CSP needs no `unsafe-inline`. |

No GPL/AGPL dependency. No database, Redis, analytics, CDN, third-party script or
persistent payload store. The plugin needs only PyYAML, which Hermes already has.
Tests use Node's built-in runner and pytest.

`test/hpke-vectors.test.js` reproduces published Base-mode vectors in both
directions, including RFC 9180 Appendix A.3.1. That is the substitute for an audit
of the library, not a replacement for one.

## Layout

```
bin/handoff-admin.mjs           local admin CLI (create, await, claim, notice)
bin/install-hermes-drop.sh      installer, uninstaller and socket-directory preflight
bin/hermes-drop-config-edit.py  surgical, comment-preserving plugins.enabled editor
contract/control-protocol.json  the control protocol, as a fixture both languages read
src/main.js                     entrypoint: broker + public server + control socket
src/broker.js                   in-memory state, single-use gates, HPKE open
src/public-server.js            page, assets, /api/metadata, /api/submit, headers
src/control-server.js           0600 Unix socket, newline-delimited JSON admin path
src/hpke-suite.js               suite, code points, info construction (shared with the browser)
src/notice.js                   the one chat message and its three fixed states
src/client/                     browser: metadata fetch, seal, submit, countdown
src/public/                     index.html, app.css (assets/app.js is generated)
test/                           broker seams, HPKE vectors, page wiring, wake contract
integrations/hermes-drop/       the Hermes plugin
integrations/hermes-drop/tests/ the plugin's pytest suite
patches/hermes-agent/           the two required Hermes core patches
```

Internal identifiers say `handoff` throughout — the CLI, ids, environment
variables, container and service names. Hermes Drop is the product name; the
internal term was not worth a rename that would break every live deployment.

## Contributing and security

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to build, test and propose changes.
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability privately.
- [`CHANGELOG.md`](CHANGELOG.md) — release history.

## License

[MIT](LICENSE) © 2026 dmmeteo
