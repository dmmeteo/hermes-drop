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
  plaintext. All are trusted principals in the threat model. **One exception, in
  the other direction:** an *outbound* drop's key is generated per drop, used
  once, handed back inside the URL fragment and then dropped, so the broker holds
  ciphertext it cannot open. That narrows what a later compromise of the broker
  yields for outbound drops only, and changes nothing else — the plaintext passed
  through this process to be encrypted, and the Hermes host and the model are
  trusted principals exactly as before. See the outbound lifecycle below.
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

## Two directions, two state machines

The broker runs two record spaces, and they share nothing but a sweep timer and a
shutdown:

- **Inbound handoffs** — the user sends a secret in. Documented immediately below,
  and pinned by `test/lifecycle-fsm.test.js`.
- **Outbound drops** — Hermes hands a secret out. Documented in *Outbound drop
  lifecycle and deletion guarantees* further down, and pinned by
  `test/outbound-drop.test.js`.

An outbound drop is not a payload kind of a handoff. It has its own ids, its own
capabilities, its own states and its own seams: `await`, `claim`,
`begin_file_claim` and `commit_file_claim` answer the uniform `unavailable` for an
outbound drop id, and the outbound endpoints answer it for an inbound capability.
Nothing in the next section applies to an outbound drop, and vice versa.

## Handoff lifecycle and deletion guarantees

This is the authoritative statement of the *inbound* state machine and of what
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
| `transferring` | no | yes | `begin_file_claim` — a substate of `submitted`, files drops only |
| `claimed` | no | no | the one claim that was handed over |
| destroyed | no | no | TTL lapse, AEAD-failure budget, container-failure budget, shutdown |

Key material exists **exactly** in `pending`, and the payload exists **exactly**
in `submitted` or `transferring`. Those are checked invariants rather than
descriptions: every step of every lifecycle test asserts
`hasPrivateKey === (state is pending)` and `hasPlaintext === (state is submitted)`,
so "the key is gone" and "the payload is gone" are observable facts, not
intentions.

`transferring` is a payload-bearing substate and nothing more. It is unreachable
for a text drop, it holds the same bytes `submitted` held, and every seam answers
in it exactly as it answers in `submitted` — including `await`, which reports
`submitted`, because whether a local receiver is currently reading a payload is not
news about whether the browser sent one. It exists because a 42 MiB container
cannot be handed over in one response line, so its claim is two operations with a
stream between them, and the state machine has to be able to say "handed out but
not yet given up".

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
- **`submitted → transferring → claimed`** — a *file* drop's claim, which is a
  conversation rather than one operation because its payload is too large for one
  response line. `begin_file_claim` takes the one transfer lease and writes the first
  frame; the receiver reads it, hashes it and sends an `ack_frame`; the broker checks
  that ack against the manifest and only then writes the next frame; and
  `commit_file_claim` retires the payload once every frame has been acked, which
  nothing else does. The commit is accepted only on the connection that opened the
  lease. The broker deliberately never sends the digests, so an ack is evidence of
  receipt rather than an assertion about it.

  One frame at a time is not politeness — it is what makes that evidence
  size-independent. A socket write completes when the *kernel* takes the bytes, so an
  earlier revision that streamed everything and totalled it at the end accepted an
  early commit for any payload below the send buffer (a tunable, ~208 KiB) and refused
  it above. An ack cannot be produced by a kernel: to answer, a receiver must have read
  the frame and hashed it. What remains forgeable is a caller that already knows the
  plaintext, and no exchange on this socket can change that — the socket is `0600` and
  that caller is already trusted with the payload. What the acks guarantee, uniformly at
  16 bytes and at 42 MiB, is that an ordinary or buggy receiver cannot retire a payload
  it never read.
- **`transferring → submitted`** — every way a transfer can fail: the receiver
  disconnects or half-closes, the bounded lease deadline
  (`HANDOFF_FILE_CLAIM_LEASE_MS`, 60 s by default) lapses, or a commit is refused
  for a byte count, a digest that does not match, or arriving out of turn. The
  payload is untouched and still one-shot, so the next `begin_file_claim` can
  collect it. This is the one edge in the machine that goes *backwards*, and it is
  what makes a lossy local receiver cost a refusal instead of the user's files. It is
  answered with `transfer_failed`, which a client must not treat like `unavailable`:
  the first means the drop is still there, the second means it is over.

  Repeatable, but not without limit. Each granted lease costs a full SHA-256 pass
  over the container and a failed transfer restores the drop for free, so one handoff
  grants at most `HANDOFF_MAX_TRANSFER_ATTEMPTS` (8) leases and then refuses with
  `transfer_failed` / `attempt_budget_spent`. Unlike the submit path's container
  budget this does **not** destroy the drop: the container is known good and the
  failures are the receiver's, so destroying would throw away the user's files over a
  broken consumer. The payload stays and lapses on its own TTL.

  The lease deadline is also clamped inside the handoff's own expiry, and a `begin`
  is refused outright (`transfer_failed` / `handoff_expiring`) when less than a
  second of TTL remains. Publishing a deadline the broker cannot honour would mean
  streaming up to 42 MiB and then destroying the payload under a receiver that did
  everything right.
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
nobody has verified; and it reaches `claimed` through the two-phase framed
transfer above rather than through `claim`, which answers the uniform
`unavailable` for a file drop rather than base64 a 42 MiB container into one
newline-delimited response line.

A live transfer keeps its live-file reservation for as long as it holds the lease,
which is why the lease has a deadline at all: a receiver that crashed mid-transfer
must not be able to hold a quarter of the process-wide file budget until the TTL
lapses. Expiry and shutdown reach a `transferring` record like any other — the
lease holder is told, its connection is dropped, and the reservation is released
before the bytes are wiped, so nothing is left streaming views into a payload that
has already been zeroized.

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
| `claim` | unavailable | **the payload, once** — text drops only² | unavailable | unavailable |
| `begin_file_claim` | unavailable | **the manifest and the frames** — files drops only² | unavailable | unavailable |
| `commit_file_claim` | invalid_request³ | invalid_request³ | invalid_request³ | invalid_request³ |

¹ Against a `pending` handoff a "different" envelope is simply the first submit,
and wins like any other. Only after one has won does a second, different envelope
become the refusal that row is about.

² The two claim paths are exclusive by payload kind, and each answers the uniform
`unavailable` for the other's kind. `transferring` is not a column because every
row answers there exactly as it does under `submitted`, with one addition: a
second `begin_file_claim` is refused with `transfer_failed` / `transfer_in_progress`
rather than `unavailable`, because the payload is still there and the caller is
entitled to try again.

³ A commit is accepted only on a connection that personally opened a lease and
streamed all of it. There is no state of the handoff in which a commit from
anywhere else is honoured, so the answer is about the caller rather than about the
handoff — which is why it is `invalid_request` and not `unavailable`.

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
- **A failed transfer is never a retirement.** A file claim retires the payload at
  the commit and nowhere else, so a disconnect, a truncated write, a lapsed lease,
  a mismatched digest or a commit from a connection that does not hold the lease
  all cost a refusal and leave the drop `submitted` and collectable. The refusal
  says so: `transfer_failed` means nothing was consumed.
- **The conversation is turn-taking, and enforced structurally rather than by
  timing.** Each op is accepted in exactly one state: `ack_frame` only while a frame is
  outstanding, `commit_file_claim` only once every frame has been acked. A commit
  pipelined behind the begin, sent instead of an ack, or sent while a frame is still
  outstanding is refused with `invalid_request` — identically at every payload size.
  Nothing legitimate is lost: a receiver cannot have hashed bytes it had not read.
- **One outcome is unknown, and is named rather than guessed.** `commit_file_claim`
  is one-shot, non-idempotent and not requeryable. A receiver that wrote one and read
  no answer — the connection closed, or its own deadline elapsed — cannot tell an
  accepted commit whose answer was lost from one that never landed, so it reports
  `transfer_indeterminate`, a verdict the broker never sends. The only safe response
  is to publish nothing, retry nothing and record nothing as spent, and let the TTL
  settle it. Reporting `transfer_failed` there would assert the payload survived;
  reporting success would assert it was verified. Neither is known.
- **A malformed call is never a transition.** Ill-typed handoff ids, unknown ops,
  unusable ceilings, garbage envelopes, capabilities that are not capabilities:
  all are refused with the contract's own vocabulary (`unavailable`,
  `invalid_request`, `response_too_large`, `transfer_failed`) and leave the machine
  where it was.

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

## Outbound drop lifecycle and deletion guarantees

The authoritative statement for the other direction: Hermes holds a short secret
and the broker hands it to exactly one browser, behind a code the user types
(`docs/OUTBOUND_SECRET_DROP_MVP.md`). Everything here is pinned by
`test/outbound-drop.test.js` at the two seams the parties actually reach — the
`0600` control socket for `create_outbound_drop`, and `POST /api/reveal/metadata`,
`/api/reveal/claim` and `/api/reveal/ack` for the browser.

### What the broker keeps, and what it deliberately does not

| | Kept | Why |
| --- | --- | --- |
| Ciphertext + IV | yes | AES-256-GCM, with the drop id as additional authenticated data, so one drop's ciphertext cannot be opened as another's. |
| The AES key | **no** | Generated per drop, used for exactly one encryption, returned inside the URL fragment, then zero-filled. Browsers never send a fragment, so it reaches no request, no access log and no unfurl. |
| The plaintext | **no** | Encrypted before the record exists; the buffer it arrived in is zero-filled on every path out of `create`, refusals included. |
| The code | **no** | What is stored is HMAC-SHA256 over the code under a per-record random key, compared in constant time. Never logged, never in metadata, never in a refusal. |

The key caveat that applies to `claim` applies here in mirror image: the base64 the
secret arrived as is an immutable V8 string until it is collected, and so is the
fragment string the key is handed back in. "Zero-filled" is about buffers.

### The three states, and there are no others

```
available ──correct code, one claim id──► reserved ──ack──► destroyed
    │                                        │
    │  three incorrect codes                 │  ack window lapses
    └──────────────────┬─────────────────────┘
                       ▼
                   destroyed        (also: TTL lapse from either state, shutdown)
```

- **`available → reserved`** — one correct code and one browser-drawn claim id. The
  verification and the reservation are synchronous with no `await` between them, so
  two browsers arriving together with the same correct code cannot both win. The
  loser gets the uniform refusal: it may not be told that someone else is revealing
  the drop.
- **`reserved → destroyed`, the acknowledgement** — the claimant reports that it
  decrypted the payload. The claim id alone authorizes this; the code is not
  re-checked. One-shot: the record is gone, so a second ack is the uniform refusal.
- **`reserved → destroyed`, the window** — a bounded ack window
  (`HANDOFF_OUTBOUND_ACK_WINDOW_MS`, 60 s, clamped inside the drop's own expiry)
  destroys the payload whether or not anyone acknowledged it. This is what makes
  "destroyed after reveal" true for a browser that reveals and then vanishes.
- **`available → destroyed`, the code budget** — three incorrect codes. At three
  digits the attempt budget *is* the rate limit, and the MVP states the trade:
  denial of delivery is preferred over allowing online brute force. The correct code
  buys nothing afterwards.
- **`available | reserved → destroyed`, the TTL** — enforced by the sweeper and
  lazily on the next touch, so a parked sweeper cannot extend a lifetime.
- **shutdown** destroys every outbound payload, like every other state.

There is no edge back. Nothing re-arms a destroyed drop, nothing returns a reserved
one to `available`, and no control op reports what happened to one.

### What each seam answers, in each state

| | `available` | `reserved` | destroyed / unknown |
| --- | --- | --- | --- |
| `POST /api/reveal/metadata` | the gate's non-secret status | unavailable | unavailable |
| `POST /api/reveal/claim`, correct code, the reserving claim id | **the ciphertext** | **the same ciphertext, again** | unavailable |
| `POST /api/reveal/claim`, correct code, any other claim id | reserves it | unavailable | unavailable |
| `POST /api/reveal/claim`, wrong code | `code_incorrect` with the count, or unavailable on the third | unavailable | unavailable |
| `POST /api/reveal/ack`, the reserving claim id | unavailable | **destroys the payload** | unavailable |
| `GET` / `HEAD`, any of the three | unavailable, and nothing changes | unavailable, and nothing changes | unavailable |

`code_incorrect` (403) is the one public answer on this surface that is not the
uniform 404, and it is deliberate: three attempts are worthless if a user cannot
tell a mistyped code from a dead link. It carries the remaining count and nothing
else, it is reachable only with a live capability — which whoever holds the link
already has — and it collapses into the uniform refusal the moment the budget is
spent.

An attempt is spent only in `available`, and only by a well-formed wrong code. A
malformed code, a malformed claim id, a missing or non-JSON body, an oversized body
and a losing concurrent claimant all cost nothing.

### What deletion guarantees

- The payload is decryptable by **at most one** browser, and the ciphertext is
  handed only to the claim id that reserved it.
- The broker cannot read its own outbound payloads: it holds no key for them from
  the moment `create` returns.
- Once **reserved**, the payload is gone at the acknowledgement or at the end of the
  bounded ack window, whichever comes first — never later. An **unclaimed** drop is
  destroyed at its TTL, by the sweeper or on the next touch, whichever reaches it
  first. So expiry alone destroys a payload nobody claimed, and it never *extends*
  the life of one that was.
- Destruction removes the record from both indexes, so a destroyed outbound drop
  and one that never existed are the same thing to every seam.

### What it does not guarantee

- **Three digits is a human-presence gate, not authentication.** The link and the
  code travel in the same conversation. A link-holder has ~3 chances in 1000 per
  drop, bounded only by the attempt budget, and anyone who can read the conversation
  is the intended audience anyway.
- **The stored verifier is brute-forceable by someone who already holds the
  record.** The HMAC key sits beside it, and 1000 candidates is not a search. The
  key defends a verifier that has *escaped* the record — a log line, a heap dump, a
  serialized snapshot — and nothing more.
- **A page reload costs the secret.** The claim id lives in the page's memory, so a
  reloaded page is a second claimant: metadata refuses a reserved drop, the new
  claim id is refused however correct the code, and the payload lapses at the ack
  window. There is no re-request path, because a drop is one-shot and no control op
  reports its fate. This is the accepted cost of one-browser reservation in this
  slice; the remedy is the browser slice's (persist the claim id in the page session
  before claiming, and let metadata answer a reserved drop to a caller presenting
  that drop's own id).
- **Activity timing is disclosed to a link-holder.** `/api/reveal/metadata`
  consumes nothing and is not rate-limited, and it flips from 200 to the uniform
  refusal the instant a reservation is taken — so a poller learns *when* the correct
  code was entered. They cannot separate that from a TTL lapse or a spent budget and
  cannot act on it, and removing the distinction would cost the gate its countdown
  and attempt display.
- **HTTPS is load-bearing here too.** The decryption key reaches the browser through
  a fragment and is used by page JavaScript, so plain HTTP cannot protect it against
  an active network attacker, and `crypto.subtle` does not exist outside a secure
  context.

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
- **An outbound drop's fate is not reportable.** There is no control op that says
  whether a drop was revealed, whether its code budget was spent, or whether it
  lapsed — so a caller that posted a link and a code learns nothing, and a user who
  meets the uniform refusal cannot be told which of "already revealed", "expired"
  and "three wrong codes" they hit. Deliberate for this slice: every alternative
  either discloses activity to the whole conversation or requires a status op the
  Hermes side does not have yet. It is the reason the TTL floor and the type check
  on `create_outbound_drop` matter — a drop that dies for a caller's mistake is
  indistinguishable to the user from a stolen secret, and nothing on either side
  would ever correct the impression.
- **The shipped page cannot open an outbound link yet.** `src/client/reveal-client.js`
  is not in the browser bundle and the page's fragment reader rejects an
  `r.<capability>.<key>` fragment, so a minted outbound link answers `unavailable`
  in a real browser. This fails safe — nothing is disclosed and nothing is consumed
  — but a broker running this slice can mint links no browser can open. Do not put
  the outbound op in front of users until the reveal UI ships.
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
