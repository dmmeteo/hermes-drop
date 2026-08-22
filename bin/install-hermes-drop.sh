#!/usr/bin/env bash
# Host-side installer and preflight for the Hermes Drop integration.
#
# Two independent jobs, deliberately kept in one script because an operator runs
# them minutes apart:
#
#   --preflight   Read-only validation of the host control-socket directory that
#                 compose.yml bind-mounts at /run/handoff (slice S2). Validates
#                 and reports; creates nothing, chmods nothing, restarts nothing.
#
#   install       Link this repo's plugin and Drop skill into the named profile
#   --copy        (or copy both) and enable the plugin in config.yaml
#   --uninstall   (slice S3). Idempotent. Restarts nothing.
#
# WHY IT REFUSES TO GUESS $HERMES_HOME. There is no fallback to ~/.hermes. A
# profile-scoped installer that defaults to the live default profile is one
# mistyped command — or one test run — away from installing into it. Every
# invocation names its target: `HERMES_HOME=~/.hermes bin/install-hermes-drop.sh
# install`. This also keeps the script honest about AGENTS.md profile rule 1
# (resolve the profile, never hardcode Path.home()/".hermes").
#
# WHAT IT NEVER DOES, at any point:
#   - restart, reload or otherwise touch a running gateway or broker
#   - `docker compose up` anything
#   - delete or edit a skill it did not install
#   - write plugins.entries.hermes-drop.allow_tool_override (Drop registers new
#     tool names and must never replace a built-in — hermes_cli/plugins.py:439-445)
# Those are operator steps behind the S11 gate. The script prints them so the
# operator can see the boundary rather than infer it.
set -euo pipefail

SELF="$(basename "$0")"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_SRC="$REPO_ROOT/integrations/hermes-drop"
PLUGIN_ID="hermes-drop"
SKILL_SRC="$REPO_ROOT/integrations/drop-skill"
SKILL_ID="drop"
SKILL_MARKER=".hermes-drop-managed"
LEGACY_PLUGIN_ID="hermes-drop-command"
BACKUP_PREFIX="config.yaml.hermes-drop-backup-"

# The uid/gid the container declares in compose.yml. Overridable only so tests can
# run as whatever uid they happen to have; deployment uses the defaults.
EXPECTED_UID="${HANDOFF_SOCKET_UID:-1000}"
EXPECTED_GID="${HANDOFF_SOCKET_GID:-1000}"

usage() {
  cat >&2 <<EOF
usage: $SELF (install | --copy | --uninstall | --preflight)

  install       Symlink the plugin and stock /drop skill into \$HERMES_HOME
                and add '${PLUGIN_ID}' to plugins.enabled in config.yaml,
                removing '${LEGACY_PLUGIN_ID}' if present. Idempotent.
                A symlink keeps this repo the single source of truth.

  --copy        Same, but pin a versioned copy instead of a symlink (for hosts
                where \$HERMES_HOME must not depend on this checkout).

  --uninstall   Remove the managed plugin and /drop skill (link or copy) and
                remove '${PLUGIN_ID}' from plugins.enabled — that one entry and
                nothing else. No config.yaml backup is restored, so operator
                changes made since install are kept.

  --preflight   Validate the host control-socket directory named by
                HANDOFF_SOCKET_DIR: it must exist, be a directory, be mode 0700,
                and be owned by ${EXPECTED_UID}:${EXPECTED_GID} (the uid/gid
                compose.yml pins for the broker). Read-only.

  Environment:
    HERMES_HOME          profile root to install into (REQUIRED, never guessed)
    HERMES_DROP_PYTHON   python3 with PyYAML, for the config.yaml edit
    HANDOFF_SOCKET_DIR   host directory bind-mounted at /run/handoff (--preflight)
    HANDOFF_SOCKET_UID   expected owner uid (default 1000)
    HANDOFF_SOCKET_GID   expected owner gid (default 1000)
EOF
  exit 2
}

fail() {
  printf '%s: %s\n' "$SELF" "$1" >&2
  exit 1
}

# ── shared helpers ──────────────────────────────────────────────────────────

resolve_home() {
  local home="${HERMES_HOME:-}"
  if [ -z "$home" ]; then
    fail "HERMES_HOME is not set. This installer never guesses a profile — name the target explicitly, e.g. HERMES_HOME=\"\$HOME/.hermes\" $SELF install"
  fi
  if [ ! -d "$home" ]; then
    fail "HERMES_HOME ${home} does not exist (or is not a directory). Point it at a real Hermes profile root."
  fi
  printf '%s' "$home"
}

# Locate a python3 that can import yaml. config.yaml is a real YAML document with
# comments and nesting the operator cares about, so the edit is validated by a
# parser even though it is applied line by line (see bin/hermes-drop-config-edit.py).
#
# WHY NO ~/.hermes VENV IN THIS LIST. It used to end with
# `$HOME/.hermes/hermes-agent/venv/bin/python` — the one line in a script whose
# entire premise is "never hardcode ~/.hermes" that hardcoded ~/.hermes (review
# L7). Harmless in effect, since an interpreter is not a profile, but it meant
# `HERMES_HOME=/srv/profiles/staging install` could quietly run the default
# profile's interpreter. The candidates are now: an explicit override, the
# environment the operator is actually standing in, and PATH. If none of those has
# PyYAML the script says so and names the override — a preflight failure, not a
# guess. $HERMES_HOME's own checkout is consulted last and is *derived from the
# named profile*, never from $HOME.
resolve_python() {
  local home="$1"
  local candidate
  for candidate in \
    "${HERMES_DROP_PYTHON:-}" \
    "${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python3}" \
    "${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}" \
    "$(command -v python3 2>/dev/null || true)" \
    "$(command -v python 2>/dev/null || true)" \
    "$home/hermes-agent/venv/bin/python"; do
    [ -n "$candidate" ] || continue
    [ -x "$candidate" ] || continue
    if "$candidate" -c 'import yaml' >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  fail "no python3 with PyYAML found. Tried \$HERMES_DROP_PYTHON, \$VIRTUAL_ENV, python3 and python on PATH, and ${home}/hermes-agent/venv/bin/python. Set HERMES_DROP_PYTHON to an interpreter that can 'import yaml', e.g. HERMES_DROP_PYTHON=\"\$HERMES_HOME/hermes-agent/venv/bin/python\" $SELF install"
}

# ── config.yaml editing ─────────────────────────────────────────────────────
#
# The edit itself lives in bin/hermes-drop-config-edit.py, which validates with a
# YAML parser and writes by whole-line change so comments and formatting survive
# (review M4). Two passes, so a no-op re-run leaves no backup behind: `plan`
# reports whether an edit is needed, and only then is a backup taken.
#
# Exit 3 from that script means "refused, and nothing was written" — an ambiguous
# layout it will not guess at. The installer treats that as fatal and, crucially,
# checks it *before* creating anything (see do_install's ordering).

CONFIG_EDITOR="$REPO_ROOT/bin/hermes-drop-config-edit.py"

config_edit() {
  local python="$1" mode="$2" config="$3"
  "$python" "$CONFIG_EDITOR" "$mode" "$config" "$PLUGIN_ID" "$LEGACY_PLUGIN_ID"
}

# ── install / --copy ────────────────────────────────────────────────────────

# Ordering is the whole point of this function, and it changed with review M4.
#
# It used to create the symlink first and edit config.yaml second. Under `set -e`
# that meant a refused or failing config edit exited *after* the symlink was in
# place: a half-install, with the plugin directory linked and the config not
# naming it. Now the config is validated, then edited, and only then is anything
# created — and if creation fails the config edit is rolled back from the backup
# this function just took. Either both happened or neither did.
do_install() {
  local mode="$1"   # link | copy
  local home python target skill_target plugins_dir skills_dir config backup plan

  home="$(resolve_home)"
  python="$(resolve_python "$home")"

  [ -f "$PLUGIN_SRC/plugin.yaml" ] || fail "plugin source ${PLUGIN_SRC} has no plugin.yaml — wrong checkout?"
  [ -f "$SKILL_SRC/SKILL.md" ] || fail "skill source ${SKILL_SRC} has no SKILL.md — wrong checkout?"
  [ -f "$CONFIG_EDITOR" ] || fail "config editor ${CONFIG_EDITOR} is missing — wrong checkout?"

  # Refuse to replace an unrelated skill. The old installer never managed this
  # path, so an existing directory without our marker belongs to the operator.
  skill_target="$home/skills/$SKILL_ID"
  if [ -L "$skill_target" ]; then
    [ "$(readlink -f "$skill_target")" = "$(readlink -f "$SKILL_SRC")" ] \
      || fail "${skill_target} is a symlink not owned by Hermes Drop; nothing was changed"
  elif [ -e "$skill_target" ] && [ ! -f "$skill_target/$SKILL_MARKER" ]; then
    fail "${skill_target} already exists and is not marked as a Hermes Drop install; nothing was changed"
  fi

  config="$home/config.yaml"

  # 1. Plan. This validates config.yaml and refuses (exit 3) on any layout it
  #    cannot line-edit — while nothing has been created and nothing written.
  #    `set -e` would kill us silently, so the status is captured deliberately.
  plan=""
  if ! plan="$(config_edit "$python" plan "$config")"; then
    fail "config.yaml could not be planned; nothing was created or changed"
  fi

  # 2. Edit the config, backing it up first. Still nothing created.
  backup=""
  if [ "$plan" = "edit" ]; then
    if [ -f "$config" ]; then
      backup="$home/${BACKUP_PREFIX}$(date -u +%Y%m%dT%H%M%SZ)"
      cp -p "$config" "$backup"
      printf 'backed up %s -> %s\n' "$config" "$backup"
    fi
    if ! config_edit "$python" apply "$config"; then
      # The editor writes nothing on refusal, but restore anyway rather than
      # reason about which failure this was.
      if [ -n "$backup" ] && [ -f "$backup" ]; then
        cp -p "$backup" "$config"
        rm -f "$backup"
      fi
      fail "config.yaml could not be edited; nothing was created or changed"
    fi
    printf 'enabled %s in %s (removed %s if present)\n' "$PLUGIN_ID" "$config" "$LEGACY_PLUGIN_ID"
    printf 'comments and formatting preserved: only the plugins.enabled list changed\n'
  else
    printf 'config already correct: %s is enabled and %s is absent; left %s untouched\n' \
      "$PLUGIN_ID" "$LEGACY_PLUGIN_ID" "$config"
  fi

  # 3. Create the plugin directory. From here a failure has to undo step 2.
  rollback_config() {
    if [ -n "$backup" ] && [ -f "$backup" ]; then
      cp -p "$backup" "$config"
      rm -f "$backup"
      printf 'rolled back the config edit: %s is as it was\n' "$config" >&2
    fi
  }

  plugins_dir="$home/plugins"
  if ! mkdir -p "$plugins_dir"; then
    rollback_config
    fail "could not create ${plugins_dir}"
  fi
  target="$plugins_dir/$PLUGIN_ID"

  # Remove whatever is there before writing the new form, so switching between
  # link and copy is a supported, idempotent operation rather than an error.
  if [ -L "$target" ] || [ -e "$target" ]; then
    if ! rm -rf "$target"; then
      rollback_config
      fail "could not replace the existing ${target}"
    fi
  fi

  if [ "$mode" = "link" ]; then
    if ! ln -s "$PLUGIN_SRC" "$target"; then
      rollback_config
      fail "could not link ${target}"
    fi
    printf 'linked %s -> %s\n' "$target" "$PLUGIN_SRC"
  else
    # An installed plugin is source only: no tests, no bytecode caches. Core's
    # scanner only reads plugin.yaml and __init__.py, and shipping the test tree
    # into a profile would put a node harness and a pytest conftest somewhere
    # nobody will ever run them from.
    if ! mkdir -p "$target" \
      || ! (cd "$PLUGIN_SRC" && tar --exclude=tests --exclude=__pycache__ --exclude='*.pyc' -cf - .) \
        | (cd "$target" && tar -xf -); then
      rm -rf "$target"
      rollback_config
      fail "could not copy the plugin into ${target}"
    fi
    printf 'copied %s -> %s\n' "$PLUGIN_SRC" "$target"
  fi

  # 4. Install the stock skill command. A plugin without this skill has tools but
  # no /drop command, so both artifacts are one install operation.
  skills_dir="$home/skills"
  if ! mkdir -p "$skills_dir"; then
    rm -rf "$target"
    rollback_config
    fail "could not create ${skills_dir}"
  fi
  if [ -L "$skill_target" ] || [ -e "$skill_target" ]; then
    rm -rf "$skill_target"
  fi
  if [ "$mode" = "link" ]; then
    if ! ln -s "$SKILL_SRC" "$skill_target"; then
      rm -rf "$target"
      rollback_config
      fail "could not link ${skill_target}"
    fi
    printf 'linked %s -> %s\n' "$skill_target" "$SKILL_SRC"
  else
    if ! mkdir -p "$skill_target" \
      || ! (cd "$SKILL_SRC" && tar --exclude=__pycache__ --exclude='*.pyc' -cf - .) \
        | (cd "$skill_target" && tar -xf -) \
      || ! printf 'managed by hermes-drop\n' > "$skill_target/$SKILL_MARKER"; then
      rm -rf "$skill_target" "$target"
      rollback_config
      fail "could not copy ${SKILL_SRC} into ${skill_target}"
    fi
    printf 'copied %s -> %s\n' "$SKILL_SRC" "$skill_target"
  fi

  cat <<EOF

not done here, on purpose:
    - no gateway or broker was restarted or reloaded (plugin discovery runs at
      gateway start, so the tools appear only after an operator-approved restart)
    - no docker compose service was started or stopped
    - no unrelated skill was deleted or edited
    - plugins.entries.${PLUGIN_ID}.allow_tool_override was NOT written and must
      stay unset
    - no host control-socket directory was created (run --preflight, then create
      it yourself)

rollback, each complete on its own:
    - ${SELF} --uninstall
    - or add '${PLUGIN_ID}' to plugins.disabled (hard deny-list)
EOF
}

# ── --uninstall ─────────────────────────────────────────────────────────────

# Review L6 changed what this means. It used to `mv` the newest backup over
# config.yaml, which is wrong in both directions:
#
#   - it DISCARDED every operator change made after install. A backup is a snapshot
#     of a moment, and restoring it silently reverts unrelated edits — a new MCP
#     server, a model change, an allowlist entry — that have nothing to do with
#     Drop. "Left exactly as it was found" was the intent; "left as it was found
#     three weeks ago" was the behaviour.
#   - and when install was a config no-op (no backup taken), it removed the plugin
#     directory and left `hermes-drop` in plugins.enabled, pointing at nothing.
#
# So uninstall now performs the inverse *edit*: remove exactly one entry from
# plugins.enabled, through the same surgical editor, touching nothing else. The
# backup is left on disk as an audit artefact rather than consumed as a time
# machine.
do_uninstall() {
  local home python target skill_target config plan backup
  home="$(resolve_home)"
  python="$(resolve_python "$home")"
  target="$home/plugins/$PLUGIN_ID"
  skill_target="$home/skills/$SKILL_ID"
  config="$home/config.yaml"

  [ -f "$CONFIG_EDITOR" ] || fail "config editor ${CONFIG_EDITOR} is missing — wrong checkout?"

  if [ -L "$target" ] || [ -e "$target" ]; then
    rm -rf "$target"
    printf 'removed %s\n' "$target"
  else
    printf 'nothing to remove at %s\n' "$target"
  fi

  if [ -L "$skill_target" ]; then
    if [ "$(readlink -f "$skill_target")" = "$(readlink -f "$SKILL_SRC")" ]; then
      rm -f "$skill_target"
      printf 'removed %s\n' "$skill_target"
    else
      printf '%s: left unrelated skill symlink %s untouched\n' "$SELF" "$skill_target" >&2
    fi
  elif [ -d "$skill_target" ] && [ -f "$skill_target/$SKILL_MARKER" ]; then
    rm -rf "$skill_target"
    printf 'removed %s\n' "$skill_target"
  elif [ -e "$skill_target" ]; then
    printf '%s: left unrelated skill %s untouched\n' "$SELF" "$skill_target" >&2
  fi

  plan=""
  if ! plan="$(config_edit "$python" remove-plan "$config")"; then
    printf '%s: config.yaml could not be planned; %s is still in plugins.enabled and must be removed by hand\n' \
      "$SELF" "$PLUGIN_ID" >&2
    plan="skip"
  fi

  if [ "$plan" = "edit" ]; then
    backup="$home/${BACKUP_PREFIX}$(date -u +%Y%m%dT%H%M%SZ)"
    cp -p "$config" "$backup"
    if config_edit "$python" remove "$config"; then
      printf 'removed %s from plugins.enabled in %s (nothing else changed)\n' "$PLUGIN_ID" "$config"
      printf 'backed up %s -> %s\n' "$config" "$backup"
    else
      cp -p "$backup" "$config"
      rm -f "$backup"
      printf '%s: could not remove %s from plugins.enabled; %s is unchanged\n' \
        "$SELF" "$PLUGIN_ID" "$config" >&2
    fi
  elif [ "$plan" = "noop" ]; then
    printf '%s was not in plugins.enabled; left %s untouched\n' "$PLUGIN_ID" "$config"
  fi

  cat <<EOF

not done here, on purpose:
    - no config.yaml backup was restored. Only the one plugins.enabled entry was
      removed, so operator changes made since install are kept. Any
      ${BACKUP_PREFIX}* files are left in place as an audit trail; delete them
      yourself when you no longer want them.
    - nothing was restarted; a running gateway keeps the tools registered until
      it restarts
    - no docker compose service was touched
    - no unrelated skill was changed or restored
EOF
}

# ── --preflight (S2, unchanged in scope) ────────────────────────────────────

preflight() {
  local dir="${HANDOFF_SOCKET_DIR:-}"
  if [ -z "$dir" ]; then
    printf '%s: HANDOFF_SOCKET_DIR is not set\n' "$SELF" >&2
    usage
  fi

  local fix="install -d -m 700 -o ${EXPECTED_UID} -g ${EXPECTED_GID} ${dir}"

  if [ ! -e "$dir" ]; then
    fail "host control-socket directory ${dir} does not exist. Create it yourself, as: ${fix}"
  fi
  if [ ! -d "$dir" ]; then
    fail "host control-socket path ${dir} is not a directory. Expected one, as: ${fix}"
  fi

  # GNU stat (Linux hosts only, which is what this deploys to).
  local mode owner group
  mode="$(stat -c '%a' "$dir")"
  owner="$(stat -c '%u' "$dir")"
  group="$(stat -c '%g' "$dir")"

  if [ "$mode" != "700" ]; then
    fail "host control-socket directory ${dir} is mode 0${mode}, not 0700. Fix it as: ${fix}"
  fi
  if [ "$owner" != "$EXPECTED_UID" ] || [ "$group" != "$EXPECTED_GID" ]; then
    fail "host control-socket directory ${dir} is owned by uid ${owner} gid ${group}, not uid ${EXPECTED_UID} gid ${EXPECTED_GID} — the broker runs as that uid and could not secure it. Fix it as: ${fix}"
  fi

  cat <<EOF
ok: ${dir} is mode 0700 owned by uid ${EXPECTED_UID} gid ${EXPECTED_GID}.
    The broker can create its 0600 control socket there, and the same host uid
    can reach it without docker.

not done here, on purpose:
    - nothing was created, chmodded or restarted
    - no compose service was started (\`docker compose up -d\` is an operator step)
    - no Hermes profile, plugin or config was touched
EOF
}

case "${1:-}" in
  --preflight)
    [ "$#" -eq 1 ] || usage
    preflight
    ;;
  install)
    [ "$#" -eq 1 ] || usage
    do_install link
    ;;
  --copy)
    [ "$#" -eq 1 ] || usage
    do_install copy
    ;;
  --uninstall)
    [ "$#" -eq 1 ] || usage
    do_uninstall
    ;;
  *)
    usage
    ;;
esac
