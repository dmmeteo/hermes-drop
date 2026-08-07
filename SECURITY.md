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
  test pins that it stays below the ceiling. Past it the claim is **refused, not
  consumed**: the ceiling travels with the request (`max_response_bytes`,
  `contract/control-protocol.json`), the broker sizes the whole response line
  before it retires anything, and an answer that would not fit comes back as
  `response_too_large` with the payload untouched and still claimable — by the
  admin CLI, which reads an unbounded line, until the link expires. It used to be
  destroyed: the record was retired before the response was written, so a line the
  reader could not buffer was a secret nobody got. What remains is a drop the user
  has already filled in and the plugin cannot read, which is why the create-time
  warning stays; it does not refuse the drop, because that would break every small
  drop for a ceiling only a large one can reach. The floor under an advertised
  ceiling is `transport.min_response_bytes` (1024): every answer `claim` can give
  other than a payload fits inside it — `unavailable` 35 bytes,
  `invalid_request` 39, `response_too_large` 114 at its widest — so a conforming
  client can always read the refusal it gets, and a ceiling below the floor is
  rejected as `invalid_request` rather than honoured into a guaranteed transport
  fault. It bounds `claim` only; a `create` response carrying a rendered notice is
  around 570 bytes and is governed by `transport.max_response_bytes` instead.
- **A broker older than the pre-consumption check.** The check arrived with control
  protocol 2 (broker 0.5.0); protocol 1 accepts `max_response_bytes`, ignores it,
  and destroys an oversized payload as it answers. The plugin and the broker are
  installed and upgraded separately, so the plugin reads `protocol_version` off
  every `create` response — absent means 1 — instead of assuming the capability
  from its own version. It refuses the drop (`broker_too_old`, before the link is
  posted, so no message, no journal entry, no waiter and nothing submitted) in
  exactly one case: protocol 1 **and** an advertised `max_plaintext_bytes` above
  what this client can read back (~783 KB). A protocol 1 broker at or under that
  cap — including the shipped 64 KiB default — still works, with one warning in
  `agent.log` per drop, because nothing it accepts can overrun the reader and the
  exposure is exactly 0.4.0's. Operator remedy for the refusal: upgrade the broker
  to 0.5.0 or newer, or lower `HANDOFF_MAX_PLAINTEXT_BYTES` under ~783 KB. The
  refused handoff was never submitted to, so there is nothing to recover from it;
  it lapses at its TTL.
- **A claim the plugin received but could not record.** Marking the drop spent
  happens after the broker has destroyed its copy, so it cannot be made atomic
  with the delivery without a protocol this design deliberately does not have. The
  ordering is therefore ask → receive → record, and a `claimed_at` write that
  fails (full or read-only `$HERMES_HOME`) is logged as an `ERROR`, reported in
  the tool result, and **does not** withhold the secret — withholding it would
  destroy the only remaining copy. The durable record then understates what
  happened until the entry lapses. One-shot is unaffected: the retry the unmarked
  entry appears to permit is refused by the broker's payload-free receipt. The
  bounded side effect is a re-announce: the reconciler treats `received` with no
  `claimed_at` past the 15-minute grace as a drop the model never collected, clears
  `announced_at` and wakes it again — capped by `MAX_ANNOUNCE_ATTEMPTS` (5) like
  every other announce, so it cannot loop. The model can therefore be told to
  claim a drop whose secret it already has; those claims answer `unavailable`, and
  the note on the original result is what tells it not to try.
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
