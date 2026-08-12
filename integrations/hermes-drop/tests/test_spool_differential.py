"""The label and type rules, differentially, against the real browser code.

``drop/spool.py`` re-sanitizes every filename and MIME hint it is handed, on the
argument that a guarantee inherited from a peer is not a guarantee. That argument
only holds if the two implementations *agree*: a Python sanitizer that is merely
similar to ``src/file-container.js`` would mean the label the browser hashed into
a manifest and the label a model is shown can differ, which is the disagreement
the container's "sanitization is a fixed point" rule exists to forbid.

So this file runs both. The corpus is built from the characters the two rule sets
interact through — separators, drive prefixes, C0 controls, format characters, the
whitespace JS's ``trim()`` recognises and Python's ``str.strip()`` does not, and
combining sequences that normalize — and every case is put through the real JS
module in ``node`` and through ``sanitize_label`` / ``sanitize_type`` here.

It is a fuzz with a fixed seed-free corpus: same cases every run, so a divergence
is a reproducible failure rather than a flake. ``node`` missing is a skip, not a
failure, for the same reason the broker fixtures skip: a toolchain gap is an
environment fact.

Lone surrogates are deliberately **not** in the corpus — they cannot survive a
round trip through two JSON parsers, and they are covered directly in
``test_spool.py`` where the requirement is that they degrade rather than raise.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import REPO_ROOT, TESTS_DIR, load_plugin_package

#: Every token the two rule sets can disagree about.
TOKENS = [
    "",
    "a",
    "Z9",
    ".",
    "..",
    "/",
    "\\",
    ":",
    "C:",
    "c:",
    " ",
    "\t",
    "\n",
    "\r",
    "\v",
    "\f",
    "\x00",
    "\x07",
    "\x1c",
    "\x1f",
    "\x7f",
    "\x9f",
    "\xa0",
    " ",
    " ",
    " ",
    " ",
    "​",
    "‎",
    " ",
    "⁠",
    "　",
    "﻿",
    "é",
    "é",
    "ß",
    "🙂",
]

#: Suffixes that turn a pair into a plausible filename, plus the two that hide a
#: separator or a normalizing sequence behind a truncation boundary.
TAILS = ["", ".txt", "/x", "﻿", "é" * 40]

#: The 255-byte cap, from both sides of it.
LONG = ["a" * 300, "é" * 200, "日" * 100, "a" * 254 + "é", " " * 300 + "x"]


def _corpus() -> list:
    cases = []
    for first in TOKENS:
        for second in TOKENS:
            cases.append(first + second)
            for tail in TAILS:
                cases.append(first + second + tail)
    cases.extend(LONG)
    # Deduplicated but order-stable, so a failure names the same case every run.
    seen = set()
    unique = []
    for case in cases:
        if case not in seen:
            seen.add(case)
            unique.append(case)
    return unique


_JS_DRIVER = """
import { sanitizeFileName, sanitizeFileType } from '%(module)s';

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { raw += chunk; });
process.stdin.on('end', () => {
  const cases = JSON.parse(raw);
  const out = cases.map((value) => [sanitizeFileName(value), sanitizeFileType(value)]);
  process.stdout.write(JSON.stringify(out));
});
"""


@pytest.fixture(scope="module")
def spool_mod():
    return load_plugin_package().drop.spool


@pytest.fixture(scope="module")
def js_results(tmp_path_factory) -> list:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; cannot run the differential corpus")

    module = REPO_ROOT / "src" / "file-container.js"
    assert module.is_file(), module
    driver = tmp_path_factory.mktemp("differential") / "js_side.mjs"
    driver.write_text(_JS_DRIVER % {"module": module.as_posix()}, encoding="utf-8")

    completed = subprocess.run(
        [node, str(driver)],
        input=json.dumps(_corpus(), ensure_ascii=True),
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_the_corpus_is_large_enough_to_be_worth_running() -> None:
    corpus = _corpus()
    assert len(corpus) > 3000, len(corpus)
    assert len(set(corpus)) == len(corpus)


def test_every_label_matches_the_browsers_sanitizer_exactly(spool_mod, js_results) -> None:
    corpus = _corpus()
    assert len(js_results) == len(corpus)

    divergences = [
        (case, js_name, spool_mod.sanitize_label(case))
        for case, (js_name, _) in zip(corpus, js_results)
        if spool_mod.sanitize_label(case) != js_name
    ]

    assert divergences == [], f"{len(divergences)} label divergence(s), first: {divergences[:3]!r}"


def test_every_type_hint_matches_the_browsers_sanitizer_exactly(spool_mod, js_results) -> None:
    """The one that was wrong: ``str.strip()`` removes the C0 separators
    U+001C–U+001F that JS's ``trim()`` keeps, and keeps the U+FEFF that ``trim()``
    removes — so a value the canonical rules reject wholesale had its control
    characters stripped and the remainder *displayed*, which is the "never
    repaired" invariant failing in the more dangerous direction."""
    corpus = _corpus()

    divergences = [
        (case, js_type, spool_mod.sanitize_type(case))
        for case, (_, js_type) in zip(corpus, js_results)
        if spool_mod.sanitize_type(case) != js_type
    ]

    assert divergences == [], f"{len(divergences)} type divergence(s), first: {divergences[:3]!r}"


def test_sanitizing_a_label_twice_changes_nothing(spool_mod) -> None:
    """The container decoder refuses any name it would have changed, so the
    displayed label and the hashed bytes can never disagree. That rule is only
    checkable if sanitization is a fixed point on this side too."""
    not_fixed = [
        case
        for case in _corpus()
        if spool_mod.sanitize_label(spool_mod.sanitize_label(case))
        != spool_mod.sanitize_label(case)
    ]

    assert not_fixed == [], f"{len(not_fixed)} case(s) sanitize further on a second pass"


def test_sanitizing_a_type_twice_changes_nothing(spool_mod) -> None:
    not_fixed = [
        case
        for case in _corpus()
        if spool_mod.sanitize_type(spool_mod.sanitize_type(case))
        != spool_mod.sanitize_type(case)
    ]

    assert not_fixed == [], f"{len(not_fixed)} case(s) sanitize further on a second pass"


def test_no_label_exceeds_the_byte_cap_and_none_is_empty(spool_mod) -> None:
    for case in _corpus():
        label = spool_mod.sanitize_label(case)
        assert label, f"{case!r} sanitized to nothing instead of the fallback"
        assert len(label.encode("utf-8")) <= 255, case
        assert "/" not in label and "\\" not in label and "\x00" not in label
        assert label not in (".", "..")


def test_the_fixture_file_lives_next_to_the_suite_that_uses_it() -> None:
    """A guard against the corpus quietly becoming a temp-file artefact: the
    driver is generated, but the cases are in this file and reviewable."""
    assert (TESTS_DIR / "test_spool_differential.py").is_file()
