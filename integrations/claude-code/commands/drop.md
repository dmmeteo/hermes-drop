---
description: Exchange a private value through the Drop broker
argument-hint: [intent only — never paste a secret]
allowed-tools: Bash
---

The user invoked `/drop $ARGUMENTS`.

Use `/home/me/projects/secure-secret-handoff/bin/claude-drop`. Never place a
secret in command arguments, Bash source, stdout, chat, or your answer.

- Empty arguments, or intent to give you a value: run `claude-drop request`.
  Tell the user the Drop notice was copied to their clipboard or written to the
  private file named by the receipt. Wait for submission. When the user says it
  was submitted, run `claude-drop claim <drop_id>`. The result is a mode-0600
  path. Do not read or print that file. Pass the path only to a subprocess that
  can consume it without logging; then run `claude-drop cleanup <path>`. If the
  task requires you to inspect the plaintext in model context, explain that the
  safe Claude-side flow cannot do that and stop.
- Intent to receive a newly generated credential: run `claude-drop
  send-generated` with non-secret title/label/kind/length options. The broker
  generates the value; it never enters this transcript.
- Existing outbound plaintext is unsupported here because a Bash/tool argument
  would persist it. Use Hermes Drop instead.
- On a headless Herdr worker without clipboard access, the notice is written to
  a private 0600 file and only its path is returned. Do not print the file. If
  the human cannot access that host path, stop; do not route it through chat.
- Any refusal is final. Do not retry through another channel or fall back to
  plaintext.
