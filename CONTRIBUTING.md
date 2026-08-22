# Contributing

Thanks for looking. This is a small self-hosted project; issues and pull requests
are welcome, and so is being told the threat model is wrong.

**Security problems do not go here.** See [SECURITY.md](SECURITY.md).

## Getting set up

The repository is two codebases that talk over one socket.

```bash
# broker (Node.js >= 22)
npm ci
npm run verify          # build the browser bundle, run every test, run the smoke test

# plugin (Python 3.11+, needs a Hermes checkout importable for its stubs)
cd integrations/hermes-drop/tests
python -m pytest -q
```

You do not need a running Hermes gateway or a deployed broker to work on either
side. The plugin's tests stub the gateway; the broker's tests start real
in-process brokers and a real Unix socket.

Useful individual targets:

```bash
npm test                # node:test suite only
npm run smoke           # local end-to-end: create → encrypt → submit → claim → re-claim fails
npm run build           # bundle the browser page
node bin/handoff-admin.mjs create --ttl 600
```

## How changes are expected to arrive

**Tests first, and they must fail first.** Every behavioural change in this
repository was written RED before GREEN, at a public seam, and that is what keeps
the security claims from drifting into aspiration. A pull request that changes
behaviour without a test that fails before it is unlikely to be merged, however
obviously correct it looks.

Write the test at the seam a user or an attacker actually reaches — the HTTP
endpoint, the control protocol, the tool result, the installed config file — not at
a private helper.

## Things that are deliberate

Please read these before proposing to change them; each is load-bearing, and each
has a test that will stop you.

- **No destination field, anywhere.** Not `platform`, `chat_id`, `channel`,
  `thread_id`, `target` or `home`, at any depth of either tool schema. A model that
  cannot express a destination cannot pick the wrong one. `tests/test_schemas.py`
  walks both schemas and fails on any of those names.
- **No fallback to a home channel, a default profile or `~/.hermes`.** Resolution
  either succeeds or refuses. There is no third outcome. This is the incident the
  project exists to prevent, restated as code.
- **The installer never guesses `HERMES_HOME`.** Every invocation names its target.
- **The config editor refuses rather than guesses.** An ambiguous YAML layout exits
  3 with the file untouched. Widening what it will *edit* is a much bigger change
  than widening what it will *read*.
- **Refusals carry a fixed vocabulary.** Error details that reach the model come
  from an allowlist, because adapter and broker error strings can carry socket
  paths and internals.
- **`allow_tool_override` is never written.** Drop registers new tool names and
  must never replace a Hermes built-in.
- **Nothing polls.** The wake path is event-driven end to end. A patch that adds a
  polling loop needs to argue why the event is unavailable.

## Style

Match the surrounding code. Both codebases comment *why*, not *what* — especially
where a line encodes a decision that would otherwise look arbitrary. If you remove
a guard, say in the comment what made it unnecessary.

Node code is ESM, no framework, no runtime dependency beyond `@hpke/core`. Python
is standard library plus PyYAML, with type hints. Please do not add dependencies
without a reason that survives the question "what breaks without it?", and please
do not add GPL- or AGPL-licensed ones at all.

## Hermes compatibility

Drop must remain compatible with released, unmodified Hermes. Use stock plugin,
tool, hook, middleware and skill-command seams. Do not add or revive local Hermes
core patches to make a Drop feature work.

## Pull requests

- One concern per pull request.
- Say what you ran. `npm run verify` and the plugin suite, with their counts, is
  the baseline.
- If it touches the security model, say which threat-model line moves and why.
- Do not include real capabilities, tokens, chat ids, hostnames or journal
  contents in tests, fixtures or issue text.
