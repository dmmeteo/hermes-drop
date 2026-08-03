# Hermes core patches

Hermes Drop's plugin needs two gateway seams that **stock Hermes does not have**.
Until they exist upstream, a self-hosted operator has to apply them to their own
Hermes checkout. There is no released Hermes version that includes them.

Without these patches the plugin still loads, but two things are wrong:

1. a plugin slash command cannot tell which conversation invoked it, so
   `/drop`'s origin binding — the property the whole security model rests on —
   reads whichever session mirrored its identity into `os.environ` most
   recently on a multi-platform gateway; and
2. a hyphenated plugin command invoked in its underscored form
   (`/hermes_drop`, which is what Telegram's command menu sends back) bypasses
   the slash-access policy entirely.

Both are bugs in Hermes' plugin-command path rather than in Drop. They are
written as general fixes with their own tests, not as Drop-specific hooks, so
they are offerable upstream as-is.

## Base commit

Both patches apply to Hermes at:

```
dd241cf0cda317f8ce2680ad3d24580998e6dc34
```

(`Merge pull request #74644 …`, 2026-07-30). They are `git format-patch` output
from a branch two commits ahead of that base — the same two commits running in
the environment where Hermes Drop 0.4.0 passed its Discord full-loop E2E.

## Order

Apply in numeric order. `0002` touches the same `gateway/run.py` dispatch block
that `0001` restructures, so it does not apply cleanly on its own.

| # | Commit | Subject | Touches |
|---|---|---|---|
| 0001 | `2f487f61a8` | `fix(gateway): bind session context for plugin slash commands` | `gateway/run.py` (+56/−16), `tests/gateway/test_plugin_command_context.py` (new, 401 lines) |
| 0002 | `ebd91f8d56` | `fix(gateway): apply slash-access policy to plugin commands` | `gateway/run.py`, `gateway/slash_access.py` (+37/−5), `tests/gateway/test_plugin_command_access.py` (new, 323 lines), `tests/gateway/test_slash_access.py` (+81) |

## Applying them

```bash
cd /path/to/your/hermes-agent
git switch --create hermes-drop-seams dd241cf0cd
git am /path/to/hermes-drop/patches/hermes-agent/*.patch
```

`git am` preserves the commit messages, which carry the full reasoning and the
reproducible symptom for each fix. If you would rather not create commits:

```bash
git apply --check patches/hermes-agent/0001-*.patch   # dry run
git apply patches/hermes-agent/0001-*.patch
git apply patches/hermes-agent/0002-*.patch
```

Restart the gateway afterwards — plugin discovery and command registration both
run at gateway start.

## Tests

Each patch ships its own tests; running them is the acceptance check.

```bash
# from the Hermes checkout, in its venv
python -m pytest tests/gateway/test_plugin_command_context.py \
                 tests/gateway/test_plugin_command_access.py \
                 tests/gateway/test_slash_access.py
```

The wider gateway suite should stay green as well — these are behaviour fixes on
a path with existing coverage, not new subsystems.

## These are temporary

They exist because Hermes has no public seam for what they do, not because Drop
wants private ones. If equivalent support lands upstream, this directory should
be deleted and the README's prerequisite section rewritten to name the Hermes
version that carries it. Nothing in the Drop plugin depends on the patches'
*implementation* — only on the resulting behaviour, which is:

- a plugin command handler can resolve its own session's platform, chat and user
  through the normal session-context API; and
- the slash-access policy is enforced on the normalized command name before
  dispatch.

## Provenance

Generated with `git format-patch dd241cf0cd..ebd91f8d56`. They contain source
and tests only — no credentials, no profile configuration, no machine-specific
paths. The `token="***"` strings inside the added tests are literal placeholders
in fixture objects, not redactions of a real value.
