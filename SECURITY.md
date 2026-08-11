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

## Handoff lifecycle and deletion guarantees

This is the authoritative statement of the broker's state machine and of what
"destroyed" is worth. Everything in it is pinned by `test/lifecycle-fsm.test.js`,
which drives the machine through its real seams — the browser client for
`/api/metadata` and `/api/submit`, the `0600` control socket for `await` and
`claim` — and re-checks the invariants after every transition, including under
randomised operation sequences.

### The four states

A handoff is minted `pending` and leaves the machine exactly once. There are no
other states, and no state carries a payload it is not named for.

| State | Holds the P-256 private key | Holds the payload | Entered by |
| --- | --- | --- | --- |
| `pending` | yes | no | `create` |
| `submitted` | no | yes | the one envelope that decrypted |
| `claimed` | no | no | the one `claim` that was handed over |
| destroyed | no | no | TTL lapse, AEAD-failure budget, container-failure budget, shutdown |

Key material exists **exactly** in `pending`, and the payload exists **exactly**
in `submitted`. Those are checked invariants rather than descriptions: every step
of every lifecycle test asserts `hasPrivateKey === (state is pending)` and
`hasPlaintext === (state is submitted)`, so "the key is gone" and "the payload is
gone" are observable facts, not intentions.

Destruction removes the record from both indexes, so `destroyed` has no
observable form beyond the record's absence — a destroyed handoff and one that
never existed are the same thing to every seam.

### The transitions, and there are no others

```
pending ──one envelope decrypts──► submitted ──one claim──► claimed
   │                                   │                      │
   │  AEAD-failure budget spent        │                      │
   └───────────────┬───────────────────┴──────────────────────┘
                   ▼
              destroyed   (also: TTL lapse from any state, shutdown)
```

- **`pending → submitted`** — one envelope opens under this handoff's own `info`
  binding. The check and the mutation are synchronous with no `await` between
  them, so exactly one submit wins however many arrive at once.
- **`submitted → claimed`** — one `claim` hands the bytes to the local caller.
  Also synchronous, so a second concurrent claim can never observe `submitted`.
- **`pending → destroyed`** — the AEAD-failure budget (`HANDOFF_MAX_AEAD_FAILURES`,
  3 by default) is spent, so the submit endpoint cannot become a retry oracle.
  Only a `pending` handoff can reach the AEAD at all, so only a `pending` handoff
  can be destroyed this way. A malformed envelope is rejected on shape and costs
  nothing against the budget.
- **`pending → destroyed`, the second way** — a *file* drop's container-failure
  budget is spent. Reachable only after a successful AEAD, so only on a drop
  minted `payload_kind: files`: the sender proved it holds the capability, and its
  decrypted payload then failed HDROP2 validation (bad magic, bad manifest, a
  digest that does not match the bytes). It is a separate counter from the AEAD
  one — a broken client is not a guesser — sharing the same
  `HANDOFF_MAX_AEAD_FAILURES` ceiling, and it is bounded rather than free because
  validating a container is a SHA-256 over every byte of it. A text drop has no
  such edge: nothing validates a secret beyond its size. The record stays
  `pending` and holds no payload until the budget is spent.
- **`pending | submitted | claimed → destroyed`** — the TTL lapses. Enforced both
  by the sweeper and lazily, on the next touch of the record, so a parked sweeper
  cannot extend a lifetime.
- **shutdown** destroys everything in every state.

There is no edge back. Nothing returns a handoff to `pending`, nothing re-arms a
`claimed` one, and nothing revives a destroyed one.

A file drop walks the same machine with two differences, both deliberate. Its
`pending → submitted` edge additionally requires the decrypted payload to be a
valid HDROP2 container, so the record never reaches `submitted` holding bytes
nobody has verified; and it has no `submitted → claimed` edge yet, because `claim`
answers the uniform `unavailable` for a file drop rather than base64 a 42 MiB
container into one newline-delimited response line. Until the framed transfer
lands (`docs/FILE_TRANSFER_MVP.md`, slice 3) a file drop leaves the machine only
by TTL lapse, a spent failure budget or shutdown.

Creation of a file drop is also refusable in a way a text drop's is not: each one
reserves the largest plaintext it could hold (42 MiB plus its container header and
manifest ceiling) against a process-wide live-file budget of four such
reservations, and a fifth is refused with the same uniform `unavailable` while
minting nothing. That budget bounds *resident payloads*. The transient cost of a
submission in flight — a buffered base64 body, and the copies parsing it produces
— is bounded separately, by admitting at most one widened upload at a time per
drop.

### What each seam answers, in each state

| | `pending` | `submitted` | `claimed` | destroyed / unknown |
| --- | --- | --- | --- | --- |
| `POST /api/metadata` | the form's metadata | unavailable | unavailable | unavailable |
| `POST /api/submit`, same envelope | received | received | received | unavailable |
| `POST /api/submit`, different envelope | received¹ | unavailable | unavailable | unavailable |
| `await` | blocks, then unavailable | submitted | unavailable | unavailable |
| `claim` | unavailable | **the payload, once** | unavailable | unavailable |

¹ Against a `pending` handoff a "different" envelope is simply the first submit,
and wins like any other. Only after one has won does a second, different envelope
become the refusal that row is about.

Three properties hold across that whole table:

- **Retries are idempotent by envelope digest, never a second delivery.**
  Re-POSTing the *same* envelope returns the same receipt for the rest of the
  lifetime — before the claim and after it — because a claimed handoff keeps a
  payload-free receipt until its TTL. A mobile retry or a lost response therefore
  never looks like a failure, and never produces a second payload.
- **A claim refused for size is not a transition.** When a caller advertises a
  `max_response_bytes` the answer would not fit in, the refusal happens *before*
  the retirement: the handoff is still `submitted`, still holding the same bytes,
  still one-shot, and still claimable by a reader that can hold it. It is
  repeatable and costs nothing each time.
- **A malformed call is never a transition.** Ill-typed handoff ids, unknown ops,
  unusable ceilings, garbage envelopes, capabilities that are not capabilities:
  all are refused with the contract's own vocabulary (`unavailable`,
  `invalid_request`, `response_too_large`) and leave the machine where it was.

### What deletion guarantees

- The payload is handed over **at most once**, to exactly one caller, over the
  `0600` control socket. Under randomised and fully concurrent operation
  sequences alike, no second delivery is reachable.
- The per-handoff private key is non-extractable, never leaves the broker
  process, and is dropped the instant the AEAD succeeds — before there is a
  payload to claim.
- What survives a claim until the TTL is a **payload-free receipt**: an envelope
  digest, the capability hash, and timestamps. No plaintext, no key material, and
  the record serialises without either.
- Every state is bounded by the handoff's own TTL (`HANDOFF_TTL_SECONDS`, 1800s
  by default; at most `HANDOFF_MAX_TTL_SECONDS`, 3600s). Claiming does not extend
  it, and neither does a refused claim.
- Buffers the broker owns are zero-filled before the reference is dropped.

### What it does not guarantee

- **Nothing about swap, core dumps or host snapshots.** "Destroyed" means dropped
  from an in-memory map and best-effort zero-filled, as stated in Scope above.
- **The claim path makes copies that cannot be zeroed.** Answering a claim encodes
  the bytes into a base64 JavaScript string and serialises them into the JSON line
  written to the socket. The broker zero-fills its own buffer immediately
  afterwards, but strings are immutable in V8: those copies persist until garbage
  collection, on the broker's heap and the caller's. Same class of caveat as swap,
  and it applies to the one seam that is *supposed* to emit plaintext.
- **Nothing survives a restart, deliberately.** The keys were never persisted, so
  a restart destroys every live handoff rather than resurrecting one. What the
  Hermes side then shows the user is the reconciler's business, not the broker's.
- **Nothing about what the claimant does next.** Once the bytes are on the socket
  they are the local caller's, and the limitations below govern where they go.

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
