"""The isolation guard for this whole suite.

Everything else here imports hermes modules, boots plugin managers, and runs an
installer. Any one of those reaching the operator's real ``~/.hermes`` would be
a silent, durable side effect of running tests. This file makes that loud.

It is deliberately cheap and deliberately first-principles: it records the real
profile's mtimes at session start and re-checks them, rather than trusting that
every call site used ``get_hermes_home()``.
"""

from __future__ import annotations

import os
from pathlib import Path

from conftest import (
    REAL_HERMES_HOME,
    REAL_PROFILE_AT_SESSION_START,
    real_profile_signature,
)


def test_hermes_home_is_a_throwaway_tempdir() -> None:
    home = Path(os.environ["HERMES_HOME"]).resolve()
    assert home != REAL_HERMES_HOME.resolve()
    assert REAL_HERMES_HOME.resolve() not in home.parents
    assert "hermes-drop-test-home-" in home.name or "hermes-home" == home.name


def test_no_session_identity_is_inherited_from_the_operators_gateway() -> None:
    """A leaked ``HERMES_SESSION_*`` would let an origin lookup that should
    refuse succeed instead — the exact failure S4 is built to prevent."""
    leaked = sorted(n for n in os.environ if n.startswith("HERMES_SESSION_"))
    assert leaked == []


def test_no_drop_configuration_is_inherited() -> None:
    leaked = sorted(n for n in os.environ if n.startswith("HERMES_DROP_"))
    assert leaked == []


def test_the_suite_left_the_real_profile_exactly_as_it_found_it() -> None:
    """The installer tests run against temp profiles. This proves it.

    Not "the plugin is absent from the real profile" — that was the right check
    while Drop was unreleased and is the wrong one now. Anyone who installs
    Hermes Drop and then runs its test suite has it present, legitimately, and a
    guard that fails for them is a guard nobody keeps.

    The invariant that actually matters, and the one this file's docstring always
    claimed, is that **running the tests changes nothing live**. So a signature of
    the real profile is taken at session start, before any hermes import or
    installer run, and compared here: a pre-existing install passes, an install,
    an uninstall, a config edit or a stray backup written during the run does not.
    """
    now = real_profile_signature()

    assert now == REAL_PROFILE_AT_SESSION_START, (
        "running this suite modified the operator's real profile at "
        f"{REAL_HERMES_HOME}.\n"
        f"  at session start: {REAL_PROFILE_AT_SESSION_START}\n"
        f"  now:              {now}"
    )
