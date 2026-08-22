# Historical Hermes core patches (retired)

Hermes Drop previously carried two patches for direct plugin slash-command
session binding and slash-access aliasing. They were required only because the
plugin registered `/drop` on the pre-agent plugin-command path.

The public command is now a stock Hermes skill command. It runs as an ordinary
authenticated agent turn and invokes origin-bound tools after core has bound the
conversation context. The plugin registers no slash command. Therefore neither
patch is part of the build, install, test, or deployment path.

The generic upstream findings remain useful history, but production must use an
exact upstream stable Hermes checkout with no Drop-specific core commits.
