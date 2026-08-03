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
- The claimed plaintext enters the model's context and Hermes' durable state, like
  any other tool result. Nothing here scrubs it.
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
