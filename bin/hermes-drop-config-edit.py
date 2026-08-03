#!/usr/bin/env python3
"""Surgical, comment-preserving edit of one key: ``plugins.enabled``.

Extracted from ``install-hermes-drop.sh`` because it stopped being a heredoc's
worth of code — and because a config editor an operator has to trust should be
readable and testable on its own.

WHY NOT ``yaml.safe_dump``. The previous version round-tripped the whole document
through the parser. That is semantically faithful and operationally hostile:
against the live 749-line profile it turned **21 comment lines into 0**, 749 lines
into 727, and produced a 232-line diff for a one-line change (review M4). The
script's own comment promised "a diff of the operator's config stays readable".

WHY NOT ``ruamel.yaml`` EITHER. Its round-trip loader keeps comments, but it still
re-emits the entire document: quoting style, flow-vs-block choices, key order
within a re-created node, and blank-line runs all shift. The diff gets smaller, not
small. And it is a dependency the profile is not guaranteed to have.

WHAT THIS DOES INSTEAD. It reads the file twice, for two different purposes:

1. ``yaml.safe_load`` — to **understand and validate**. Is it valid YAML? Is the
   top level a mapping? Is ``plugins.enabled`` a list? What is in it? Nothing from
   this parse is ever written back.
2. The raw lines — to **edit**. Every change is a whole-line delete or insert, or a
   single-line substitution. Every other byte of the file is preserved exactly,
   comments and blank lines included.

WHAT IT REFUSES. Anything it cannot edit by line without guessing: invalid YAML, a
duplicated ``plugins:`` key, an anchor/alias/tag/merge-key anywhere in the
``plugins`` block, a flow sequence spanning lines, a sequence whose items are not
plain or quoted scalars. Refusing is the whole point — a config editor that guesses
at an unfamiliar layout is the "corruption waiting to happen" the original comment
was worried about. Exit 3 means "refused, and the file is untouched"; the installer
treats that as fatal *before* it has created anything.

What it does **not** refuse is a value that merely *looks* like machinery. A plain
scalar containing ``/`` (``dashboard_auth/basic``) and a quoted one containing
``!``, ``&`` or ``*`` are ordinary strings, and are edited around like any other.
That line is drawn by the YAML parser's event stream rather than by a regex over
the raw text, because only the parser knows which is which.

When it does write, it writes a temp file in the same directory and renames it
over the original, so the operator's config is either the old document or the new
one and never a truncated stub.

Modes, all of which leave the file untouched unless they say otherwise:

  plan          print ``edit`` or ``noop`` — is an install edit needed?
  apply         perform the install edit (add plugin_id, drop legacy_id)
  remove-plan   print ``edit`` or ``noop`` — is an uninstall edit needed?
  remove        perform the uninstall edit (drop plugin_id only)

usage: hermes-drop-config-edit.py MODE PATH PLUGIN_ID LEGACY_ID
"""

from __future__ import annotations

import os
import re
import stat
import sys
import tempfile

import yaml

REFUSED = 3

# A mapping key line: indent, key, everything after the colon.
_KEY_RE = re.compile(r"^(\s*)([A-Za-z0-9_.\-]+|\"[^\"]*\"|'[^']*')\s*:(.*)$")
# A block-sequence item line: indent, then "- ", then the item text.
_ITEM_RE = re.compile(r"^(\s*)-\s+(.*)$")
# An empty block-sequence item (``-`` alone) — a null entry, which we will not edit.
_BARE_DASH_RE = re.compile(r"^\s*-\s*$")
# A plain or quoted scalar, optionally followed by a comment. Anything else — a
# nested mapping, a flow collection, a tag — is not something to line-edit.
#
# ``/`` is in the plain class because it is not a YAML indicator character
# anywhere in a plain scalar, and namespaced plugin ids are ordinary: a live
# profile listing ``dashboard_auth/basic`` was refused as "a non-scalar entry",
# which it never was. Refusing an unfamiliar *layout* is this script's job;
# refusing an unfamiliar *character inside a value* was a bug.
_SCALAR_ITEM_RE = re.compile(
    r"^(?P<value>[A-Za-z0-9_.\-/]+|\"[^\"]*\"|'[^']*')\s*(?P<comment>#.*)?$"
)


def refuse(message: str) -> "NoReturn":  # type: ignore[valid-type]
    sys.stderr.write(
        "refusing to edit plugins.enabled: %s\n"
        "Nothing was changed. Edit config.yaml by hand — add '%s' to plugins.enabled "
        "and remove '%s' if present — then re-run this installer, which will report "
        "the config as already correct.\n" % (message, PLUGIN_ID, LEGACY_ID)
    )
    raise SystemExit(REFUSED)


def unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def is_structural(line: str) -> bool:
    """A line that carries structure, as opposed to a blank or a comment."""
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


# ── validation: what the parser says the file means ────────────────────────


def validate(raw: str) -> list:
    """Return the current ``plugins.enabled`` list. Refuses on anything odd."""
    try:
        cfg = yaml.safe_load(raw) if raw.strip() else {}
    except yaml.YAMLError as exc:
        refuse("config.yaml is not valid YAML (%s)" % str(exc).replace("\n", " "))
    if cfg is None:
        cfg = {}
    if not isinstance(cfg, dict):
        refuse("the top level of config.yaml is not a mapping")

    plugins = cfg.get("plugins")
    if plugins is not None and not isinstance(plugins, dict):
        refuse("plugins is present but is not a mapping")
    plugins = plugins or {}

    enabled = plugins.get("enabled")
    if enabled is not None and not isinstance(enabled, list):
        refuse("plugins.enabled is present but is not a list")
    for item in enabled or []:
        if not isinstance(item, (str, int, float, bool)) or item is None:
            refuse("plugins.enabled contains a non-scalar entry (%r)" % (item,))

    # Never written by this script, and asserted so a future edit here cannot
    # introduce it silently: Drop registers new tool names and must never
    # override a built-in (hermes_cli/plugins.py:439-445).
    entries = plugins.get("entries")
    if isinstance(entries, dict):
        entry = entries.get(PLUGIN_ID)
        if isinstance(entry, dict) and "allow_tool_override" in entry:
            refuse(
                "plugins.entries.%s.allow_tool_override is set. Drop registers new "
                "tool names and must never override a built-in" % PLUGIN_ID
            )

    return [str(item) for item in (enabled or [])]


def unsafe_lines(raw: str) -> set:
    """Line indices carrying YAML machinery whose meaning is not local to the line.

    Anchors, aliases, explicit tags and merge keys all make a line mean something
    that depends on another line, which is precisely what a line editor cannot see.

    Derived from the **parser**, not from a regex over the raw text, because the
    distinction that matters is between real machinery and the same characters
    sitting harmlessly inside an ordinary scalar. ``note: "deploy !now"`` and
    ``- vendor/plugin`` are strings; ``!!str x``, ``&a``, ``*a`` and ``<<:`` are
    machinery. A regex conflates them and refuses configs it should have edited;
    the event stream tells them apart and reports the exact line.
    """
    marked = set()
    try:
        events = list(yaml.parse(raw))
    except yaml.YAMLError:
        # ``validate`` refuses on the same error, with a better message.
        return marked
    for event in events:
        line = event.start_mark.line
        if isinstance(event, yaml.AliasEvent):
            marked.add(line)
            continue
        if getattr(event, "anchor", None) is not None:
            marked.add(line)
        if getattr(event, "tag", None) is not None:
            marked.add(line)
        if isinstance(event, yaml.ScalarEvent) and event.value == "<<":
            marked.add(line)
    return marked


# ── location: finding the lines that hold the list ─────────────────────────


class Location:
    """Where ``plugins.enabled`` lives, in line terms."""

    def __init__(self) -> None:
        self.plugins_line = None      # index of the `plugins:` key line
        self.block_indent = None      # indent of keys inside the plugins block
        self.enabled_line = None      # index of the `enabled:` key line
        self.flow = None              # (prefix, inner, suffix) for `enabled: [...]`
        self.items = []               # [(line_index, value)] for a block sequence
        self.item_indent = None       # indent of those `- ` lines
        self.block_end = None         # first line index past the plugins block


def locate(lines: list, marked: set) -> Location:
    loc = Location()

    tops = [
        i
        for i, line in enumerate(lines)
        if indent_of(line) == 0 and _KEY_RE.match(line) and unquote(_KEY_RE.match(line).group(2)) == "plugins"
    ]
    if len(tops) > 1:
        refuse("config.yaml has %d top-level 'plugins:' keys" % len(tops))
    if not tops:
        return loc  # absent; the caller appends a fresh block
    loc.plugins_line = tops[0]

    # The block runs until the next structural line at indent 0.
    end = len(lines)
    for i in range(loc.plugins_line + 1, len(lines)):
        if is_structural(lines[i]) and indent_of(lines[i]) == 0:
            end = i
            break
    loc.block_end = end

    # Anywhere inside the block — the `plugins:` line itself included — an anchor,
    # alias, tag or merge key means this script cannot reason about the list from
    # the lines it can see.
    inside = sorted(i for i in marked if loc.plugins_line <= i < end)
    if inside:
        refuse(
            "the plugins block uses an anchor, alias, tag or merge key "
            "(line %d)" % (inside[0] + 1)
        )

    body = [i for i in range(loc.plugins_line + 1, end) if is_structural(lines[i])]
    if not body:
        return loc  # `plugins:` with an empty body; the caller inserts a key
    loc.block_indent = indent_of(lines[body[0]])

    enabled_lines = []
    for i in body:
        if indent_of(lines[i]) != loc.block_indent:
            continue
        match = _KEY_RE.match(lines[i])
        if match and unquote(match.group(2)) == "enabled":
            enabled_lines.append(i)
    if len(enabled_lines) > 1:
        refuse("the plugins block has %d 'enabled:' keys" % len(enabled_lines))
    if not enabled_lines:
        return loc  # no `enabled:`; the caller inserts one
    loc.enabled_line = enabled_lines[0]

    line = lines[loc.enabled_line]
    after = _KEY_RE.match(line).group(3)
    value = after.split("#", 1)[0].strip()

    if value.startswith("["):
        if not value.endswith("]"):
            refuse("plugins.enabled is a flow sequence spanning more than one line")
        open_at = after.index("[")
        close_at = after.rindex("]")
        loc.flow = (after[: open_at + 1], after[open_at + 1 : close_at], after[close_at:])
        return loc
    if value:
        refuse("plugins.enabled has an inline value this script cannot line-edit (%r)" % value)

    # A block sequence. Note the indentation: YAML lets a sequence nested in a
    # mapping sit at the *same* indent as its key, and that is exactly what
    # ``yaml.safe_dump`` emits —
    #
    #     plugins:
    #       enabled:
    #       - one
    #       - two
    #
    # so "more indented than the key" is not the test. What ends the sequence is
    # the first structural line that is not a ``- `` item; a sibling key at or
    # below the block indent is one such line. (Getting this wrong read the list as
    # empty, which ``cross_check`` then caught — which is what it is for.)
    for i in range(loc.enabled_line + 1, end):
        if not is_structural(lines[i]):
            continue
        line = lines[i]
        if _BARE_DASH_RE.match(line):
            refuse("plugins.enabled has an empty '-' entry")
        item = _ITEM_RE.match(line)
        if item is None:
            break  # a sibling key, or a layout cross_check will reject
        if indent_of(line) < loc.block_indent:
            break  # dedented out of the plugins block entirely
        scalar = _SCALAR_ITEM_RE.match(item.group(2).strip())
        if not scalar:
            refuse("plugins.enabled contains a non-scalar entry (%r)" % item.group(2).strip())
        if loc.item_indent is None:
            loc.item_indent = len(item.group(1))
        loc.items.append((i, unquote(scalar.group("value"))))

    return loc


def cross_check(loc: Location, parsed: list) -> None:
    """The two readings must agree, or the line reading is not trustworthy.

    This is the guard that makes line editing defensible: the parser is the
    authority on what the file *means*, and if a hand-rolled line scan disagrees
    with it about the list's contents, the scan has misunderstood the layout and
    must not write. Cheap, and it converts a whole class of silent
    misinterpretation into a refusal.
    """
    if loc.flow is not None:
        seen = [unquote(part) for part in loc.flow[1].split(",") if part.strip()]
    else:
        seen = [value for _i, value in loc.items]
    if seen != parsed:
        refuse(
            "the line scan read plugins.enabled as %r but the YAML parser reads it "
            "as %r; the layout is not one this script can edit safely" % (seen, parsed)
        )


# ── editing: whole-line changes only ───────────────────────────────────────


def desired(current: list, *, add: str = "", drop: tuple = ()) -> list:
    out = [item for item in current if item not in drop]
    if add and add not in out:
        out.append(add)
    return out


def render_flow(loc: Location, lines: list, items: list) -> None:
    """Rewrite a one-line flow sequence, preserving the key and any comment."""
    key_line = lines[loc.enabled_line]
    match = _KEY_RE.match(key_line)
    newline = "\n" if key_line.endswith("\n") else ""
    prefix, _inner, suffix = loc.flow
    inner = ", ".join(items)
    lines[loc.enabled_line] = "%s%s:%s%s%s%s" % (
        match.group(1),
        match.group(2),
        prefix,
        inner,
        suffix,
        newline,
    )


def apply_edit(lines: list, loc: Location, current: list, wanted: list) -> list:
    """Turn *current* into *wanted* with the fewest whole-line changes possible."""
    out = list(lines)

    # -- no plugins block at all: append one. Pure append; nothing is rewritten.
    if loc.plugins_line is None:
        if out and not out[-1].endswith("\n"):
            out[-1] = out[-1] + "\n"
        block = ["plugins:\n", "  enabled:\n"] + ["    - %s\n" % item for item in wanted]
        return out + block

    # -- a plugins block with no `enabled:` key: insert one at the top of it.
    if loc.enabled_line is None:
        indent = " " * (loc.block_indent if loc.block_indent is not None else 2)
        item_indent = indent + "  "
        inserted = ["%senabled:\n" % indent] + ["%s- %s\n" % (item_indent, i) for i in wanted]
        at = loc.plugins_line + 1
        return out[:at] + inserted + out[at:]

    # -- a flow sequence: one line in, one line out.
    if loc.flow is not None:
        render_flow(loc, out, wanted)
        return out

    # -- a block sequence. Delete the lines for removed items, append the rest.
    removed = [item for item in current if item not in wanted]
    doomed = {i for i, value in loc.items if value in removed}

    additions = [item for item in wanted if item not in current]
    survivors = [i for i, _v in loc.items if i not in doomed]

    if additions:
        item_indent = " " * (
            loc.item_indent
            if loc.item_indent is not None
            else (loc.block_indent or 2) + 2
        )
        new_lines = ["%s- %s\n" % (item_indent, item) for item in additions]
        if survivors:
            at = max(survivors) + 1
        elif loc.items:
            # Every existing item is being removed; put the new one where the
            # first of them was, so it lands inside the block rather than after it.
            at = min(i for i, _v in loc.items)
        else:
            at = loc.enabled_line + 1
        out = out[:at] + new_lines + out[at:]
        # Deleting by index after an insert needs the shift applied.
        doomed = {i if i < at else i + len(new_lines) for i in doomed}

    if doomed:
        out = [line for i, line in enumerate(out) if i not in doomed]

    # An emptied block sequence would leave a bare `enabled:` — which parses as
    # null, not as an empty list, and this script's own validation would refuse it
    # next time. Say `[]` explicitly instead.
    if not wanted and loc.items:
        key_line = out[loc.enabled_line]
        match = _KEY_RE.match(key_line)
        comment = ""
        after = match.group(3)
        if "#" in after:
            comment = " " + after[after.index("#") :].strip()
        newline = "\n" if key_line.endswith("\n") else ""
        out[loc.enabled_line] = "%s%s: []%s%s" % (
            match.group(1),
            match.group(2),
            comment,
            newline,
        )

    return out


# ── writing: temp file, then rename ────────────────────────────────────────


def write_atomically(path: str, blob: str) -> None:
    """Replace *path* with *blob* in one step, or leave it exactly as it was.

    ``open(path, "w")`` truncates the operator's ``config.yaml`` and only then
    starts writing; a kill in between leaves a stub recoverable solely from the
    backup the installer took moments earlier (review N3). A temp file in the same
    directory plus ``os.replace`` makes the change atomic on POSIX — the same
    pattern ``drop/journal.py`` already uses, for the same reason.

    The temp file inherits the original's permission bits, because ``mkstemp``
    hands out ``0600`` and a config may legitimately be group-readable. Ownership
    is copied on a best-effort basis, which only matters when the installer is run
    as a user who can change it.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    try:
        existing = os.stat(path)
        mode = stat.S_IMODE(existing.st_mode)
    except OSError:
        existing = None
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask

    fd, temp = tempfile.mkstemp(dir=directory, prefix=".hermes-drop-config-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        if existing is not None:
            try:
                os.chown(temp, existing.st_uid, existing.st_gid)
            except (OSError, AttributeError):
                pass
        os.replace(temp, path)
    except BaseException:
        # BaseException on purpose: an interrupt between write and rename is the
        # very case this function exists for, and it must not leave a temp file
        # beside the operator's config for someone to puzzle over later.
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


# ── entry point ────────────────────────────────────────────────────────────


def main(argv: list) -> int:
    global PLUGIN_ID, LEGACY_ID

    if len(argv) != 5:
        sys.stderr.write(__doc__.strip().splitlines()[-1] + "\n")
        return 2
    mode, path, PLUGIN_ID, LEGACY_ID = argv[1:5]

    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    except FileNotFoundError:
        raw = ""

    current = validate(raw)
    lines = raw.splitlines(keepends=True)
    loc = locate(lines, unsafe_lines(raw))
    if loc.enabled_line is not None or loc.flow is not None:
        cross_check(loc, current)

    if mode in ("plan", "apply"):
        wanted = desired(current, add=PLUGIN_ID, drop=(LEGACY_ID,))
    elif mode in ("remove-plan", "remove"):
        wanted = desired(current, drop=(PLUGIN_ID,))
    else:
        sys.stderr.write("unknown mode: %s\n" % mode)
        return 2

    # An absent `plugins:` or `enabled:` still needs writing even when the list
    # itself would not change — the key has to exist for core to read it.
    structural = loc.plugins_line is None or loc.enabled_line is None
    needs_edit = wanted != current or (structural and mode in ("plan", "apply"))

    if mode in ("plan", "remove-plan"):
        sys.stdout.write("edit\n" if needs_edit else "noop\n")
        return 0

    if not needs_edit:
        return 0

    edited = apply_edit(lines, loc, current, wanted)
    blob = "".join(edited)

    # Verify before writing, not after: re-parse the bytes we are about to commit
    # and confirm they mean exactly what was intended and that nothing else moved.
    try:
        after = yaml.safe_load(blob) or {}
    except yaml.YAMLError as exc:
        refuse("the edited document would not parse (%s)" % str(exc).replace("\n", " "))
    if not isinstance(after, dict):
        refuse("the edited document would not be a mapping")
    if [str(x) for x in ((after.get("plugins") or {}).get("enabled") or [])] != wanted:
        refuse("the edit did not produce the intended plugins.enabled")

    before_cfg = yaml.safe_load(raw) if raw.strip() else {}
    before_cfg = before_cfg if isinstance(before_cfg, dict) else {}
    before_rest = {k: v for k, v in before_cfg.items() if k != "plugins"}
    after_rest = {k: v for k, v in after.items() if k != "plugins"}
    if before_rest != after_rest:
        refuse("the edit would have changed a key other than plugins")
    before_plugins = {k: v for k, v in (before_cfg.get("plugins") or {}).items() if k != "enabled"}
    after_plugins = {k: v for k, v in (after.get("plugins") or {}).items() if k != "enabled"}
    if before_plugins != after_plugins:
        refuse("the edit would have changed a key inside plugins other than enabled")

    write_atomically(path, blob)
    return 0


if __name__ == "__main__":
    PLUGIN_ID = ""
    LEGACY_ID = ""
    raise SystemExit(main(sys.argv))
