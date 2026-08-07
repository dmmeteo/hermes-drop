# Security policy

## Please read this first

**Hermes Drop has not had a formal or third-party security audit.** It was built
against a written threat model and has substantial automated test coverage,
including RFC 9180 test vectors, but that is not an audit and should not be read
as one.

Its cryptography comes from [`@hpke/core`](https://github.com/dajiaji/hpke-js),
which **also states that it has not been formally audited**.

Deploy accordingly.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting: go to this repository's **Security**
tab and choose **Report a vulnerability**. That opens a private advisory visible
only to you and the maintainers, and it is the only reporting channel this project
offers — there is no security mailing address.

If private reporting is unavailable to you for any reason, open a public issue
saying only that you have a security report and asking to be contacted. Do not
include details in it.

Helpful reports include:

- what an attacker can do, and what they need in order to do it;
- which component — broker, plugin, installer, the Hermes patches;
- a reproduction, ideally as a failing test against the seams in `test/` or
  `integrations/hermes-drop/tests/`;
- the version or commit you tested.

This is a small self-hosted project maintained on a best-effort basis. There is no
guaranteed response time and no bug bounty. Expect an acknowledgement rather than
a schedule, and please give a reasonable window before disclosing publicly.

## Scope

**In scope**

- The broker: link minting, capability handling, HPKE envelope handling, the
  single-use and expiry gates, the control socket, HTTP security headers.
- The Hermes plugin: origin resolution and verification, the tool schemas, the
  journal, the reconciler, refusal-vocabulary leaks.
- The installer and the `plugins.enabled` config editor.
- The Hermes core patches in `patches/hermes-agent/`.

**Out of scope** — these are documented design decisions, not defects:

- The broker holds the decryption key. This is **not** end-to-end encryption, and
  a compromise of the broker host, the Hermes host or the model exposes the
  plaintext. All are trusted principals in the threat model.
- The claimed plaintext enters the model's context, and it is on the wire to your
  model provider. The model is a trusted principal: if it echoes the secret into a
  reply or passes it as an argument to another tool, that output is persisted like
  any other. Hermes' durable session store is a different matter — see the
  durable-sanitization limitations below.
- The capability URL is posted into a chat conversation and therefore reaches your
  chat platform and Hermes' history. It is bounded by 128-bit entropy, a lifetime
  of at most 60 minutes, one-shot consumption and a uniform unavailable response.
- Anyone who can read the conversation can use the link. That is the intended
  audience; the drop is bound to that conversation and nowhere else.
- "Destroyed" means dropped from an in-memory map and best-effort zero-filled.
  Nothing is claimed about swap, core dumps or host snapshots.
- Findings against a deployment without HTTPS. Authenticated HTTPS is load-bearing
  — it authenticates the JavaScript that performs the encryption, and
  `crypto.subtle` only exists in a secure context.

## Known limitations tracked rather than fixed

- **Durable sanitization is bounded at the wire, not at the model.** The claimed
  plaintext is kept out of `state.db`, the FTS index, the session log and any
  backup taken from them: the tool result the plugin hands Hermes carries an
  opaque placeholder, and `llm_request` middleware substitutes the plaintext into
  the provider payload only (a deep copy Hermes makes for exactly this purpose).
  What that does **not** cover, and what an operator has to decide about:
  - **Post-middleware request observers see the plaintext.** Substitution is the
    last thing that happens to the payload, so everything downstream of it reads
    the real secret:
    - **`pre_api_request` hook** — fires *after* request middleware, so a plugin
      that ships request bodies out (langfuse is the bundled example) carries the
      secret with them.
    - **NeMo Relay** — when a profile has a Relay runtime, `relay_llm.execute`
      wraps the actual provider call and hands the **post-middleware request
      body** to `relay.LLMRequest`, so every Relay interceptor, codec and
      exporter in that profile sees the plaintext and may re-serialise or export
      it. This is the widest of the three: Relay sits *inside* the call, not
      beside it.
    - **`HERMES_DUMP_REQUESTS=1`** — writes the payload, plaintext included, to
      disk.

    None is enabled by default. Do not enable any of them on a gateway that
    handles drops, and treat an existing Relay or observability pipeline as a
    place the secret will reach.
  - **The in-memory cap is process-global.** One gateway process serves every
    session, and so does the vault. A per-session ceiling (4) means a busy
    conversation evicts its own oldest secret before anyone else's, but the
    process-wide ceiling (32) is shared: past it, the globally oldest entry goes,
    which may belong to another session. That session's model then reads an
    unresolvable placeholder and is told to ask for a new drop — degraded, never
    leaked, but it is cross-session interference and is not claimed otherwise.
  - **The model's own output is not confined.** A model that repeats the secret
    into a reply, or passes it to another tool, persists it. That is the accepted
    trust boundary, unchanged.
  - **It rests on a plugin API, not a patch.** `ctx.register_middleware` and the
    `llm_request` kind are supported Hermes plugin surface, and a test pins the
    kind against core's own constant. A Hermes that dropped either would leave the
    plugin loading and claims returning an unresolvable placeholder — degraded,
    not leaking. There is no fallback that would trade that for a durable secret.
  - **In-memory residency is bounded by a 15-minute TTL**, enforced by a per-entry
    timer rather than checked opportunistically, so a session that claims once and
    then goes quiet does not leave the plaintext resident. It is not hardened
    deletion: the existing swap / core-dump / snapshot caveat applies here too.
- **Claim response ceiling.** The plugin reads a claim response up to 1 MiB, which
  is ~783 KB of plaintext after base64. The shipped broker default is 64 KiB and a
  test pins that it stays below the ceiling, but an operator who raises
  `HANDOFF_MAX_PLAINTEXT_BYTES` past it will have oversized payloads destroyed on
  claim and reported unavailable — the broker retires the record before the
  response is written. The plugin warns at create time when a broker advertises a
  cap it cannot read back; it does not refuse, because that would break every
  small drop for a ceiling only a large one can reach.
- **Adapter `send` and `edit_message` are not covered by automated tests.** Both
  need live platform credentials. The formatting boundary either side of them is
  tested with real adapter code; the calls themselves are exercised only by manual
  end-to-end runs.
- **Telegram link previews are not suppressed** and cannot be from within the
  plugin. Argued harmless — URL fragments are never sent to a server, so an
  unfurler only ever sees the bare origin.
- **The Hermes core patches are unreleased upstream.** Running Hermes Drop means
  running a patched gateway. See `patches/hermes-agent/README.md`.

## Supported versions

Only the latest release. This project has no long-term support branches.
