"""Slice 4, the filesystem half: the private spool and its atomic publish.

Everything here is about the boundary between "bytes arrived" and "a path exists
that something else may read". The bytes come from ``drop/file_claim.py``; what
this file exercises is ``drop/spool.py``, on its own, with no broker involved —
so every hostile filesystem case can be built directly instead of being provoked
through a socket.

The properties under test, and why each one is here rather than assumed:

* **A label is never a path.** The container decoder already refuses a
  non-canonical name (``src/file-container.js``), so a *real* broker cannot send
  ``../../etc/passwd``. That is exactly why the refusal is re-proved here against
  a broker that can: the spool's guarantee must not be inherited from a peer.
  ``test_spool_differential.py`` holds the other half — that the label and type
  rules are byte-identical to the browser's.
* **Exclusive creation, no symlink following.** Every create is ``O_EXCL`` and
  every open is ``O_NOFOLLOW``, and the root is reached by walking its ancestors
  descriptor-relative from the Hermes home rather than by absolute path — so
  swapping any component afterwards cannot redirect a write.
* **Nothing partial is ever reachable.** Files are written into a dot-prefixed
  staging directory and the *directory* is renamed into place. There is no
  moment at which a published path holds an unverified byte.
* **Deletion is bounded by provenance, not by validation.** A private
  user-owned directory is not a spool. Only a root carrying this plugin's marker
  is ever swept, and only entries whose names this plugin generates are ever
  removed — a mis-pointed ``spool_root`` must refuse, not be emptied.
* **Cleanup is not best-effort about the things that matter.** A crash leaves
  staging directories and possibly published ones; a restart purges both, a
  janitor sweeps on a period, and a root shared with another live gateway falls
  back to TTL-safe behaviour rather than deleting that gateway's claims.
"""

from __future__ import annotations

import asyncio
import fcntl
import hashlib
import json
import logging
import os
import stat
import threading
import time
from pathlib import Path

import pytest

from conftest import load_plugin_package


@pytest.fixture(scope="module")
def plugin():
    return load_plugin_package()


@pytest.fixture(scope="module")
def spool_mod(plugin):
    return plugin.drop.spool


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A throwaway Hermes home, which is the spool's trusted base for creation."""
    base = tmp_path / "home"
    base.mkdir(mode=0o700)
    monkeypatch.setenv("HERMES_HOME", str(base))
    return base


@pytest.fixture
def spool(spool_mod, home: Path):
    """A spool on a fresh root under the trusted base, not yet created."""
    return spool_mod.Spool(root=home / "state" / "hermes-drop" / "spool")


@pytest.fixture(autouse=True)
def _no_leaked_process_state(spool_mod):
    """Every process-wide latch this module owns, reset around every test.

    ``run_tests.sh`` gives each *file* its own interpreter, not each test, so a
    janitor left running, a consumed startup latch or a leaked byte reservation
    would make the next test pass or fail for reasons of its own.
    """
    yield
    spool_mod.stop_janitor()
    spool_mod.reset_process_state()


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _claim_name(seed: str) -> str:
    """A claim-shaped name: exactly 32 lowercase hex characters."""
    return (seed * 32)[:32]


async def _write_one(claim, index: int, name: str, payload: bytes, type_hint: str = "") -> None:
    """Feed one file to a staging claim exactly the way the chunk sink does."""
    entry = {"name": name, "size": len(payload), "type": type_hint}
    if not payload:
        await claim.accept(index, entry, b"", True)
        return
    step = 8
    for offset in range(0, len(payload), step):
        chunk = payload[offset : offset + step]
        await claim.accept(index, entry, chunk, offset + len(chunk) >= len(payload))


def _entries(spool) -> list:
    """Everything under the root that is not this plugin's own bookkeeping.

    The marker is written when the root is created and the lock when a startup
    purge runs, so a test asserting "nothing of ours is left" has to say that
    rather than "the directory is empty".
    """
    housekeeping = {spool.MARKER_NAME, spool.LOCK_NAME}
    return sorted(p.name for p in spool.root.iterdir() if p.name not in housekeeping)


def _empty_counts() -> dict:
    return {
        "published": 0,
        "staging": 0,
        "quarantine": 0,
        "foreign": 0,
        "errors": 0,
        "skipped": 0,
    }


def _private_chain(path: Path) -> None:
    """Every missing directory above *path*, at 0700.

    ``mkdir(parents=True)`` leaves intermediates at ``0o777 & ~umask``, which a
    default umask of 002 makes group-writable — and the ancestor check refuses
    that, correctly, for reasons that have nothing to do with the test using it.
    """
    for ancestor in reversed(path.parents):
        if not ancestor.exists():
            ancestor.mkdir(mode=0o700)


def _root_from_another_process(spool_mod, root: Path) -> Path:
    """A marked spool root this process did not establish.

    Built by hand rather than through ``ensure_root`` on purpose: what the
    startup purge exists for is entries some *other* process left, and going
    through this process's own creation path would record it as ours.
    """
    _private_chain(root)
    root.mkdir(mode=0o700)
    marker = root / spool_mod.MARKER_NAME
    marker.write_text(
        json.dumps({"plugin": "hermes-drop", "purpose": "claimed-file spool", "created_at": 0}),
        encoding="utf-8",
    )
    marker.chmod(0o600)
    return root


# ── configuration ──────────────────────────────────────────────────────────


def test_the_default_spool_root_is_profile_scoped_and_never_created(
    plugin, temp_hermes_home: Path
) -> None:
    """``get_hermes_home()``, like the journal — never ``Path.home()``. And
    resolving a path must not be what creates it: a CLI process that merely
    imports the plugin has no business making directories."""
    config = plugin.drop.config

    root = config.spool_root()

    assert root == str(temp_hermes_home / "state" / "hermes-drop" / "spool")
    assert not Path(root).exists(), "resolving the root created it"


def test_the_spool_root_is_resolved_per_call_so_a_profile_switch_follows(
    plugin, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unlike the control socket, this one is deliberately *not* latched: the
    socket is latched because ``check_fn`` must be process-constant, and no
    tool schema depends on where the spool is."""
    config = plugin.drop.config

    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "one"))
    first = config.spool_root()
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "two"))
    second = config.spool_root()

    assert first != second


def test_the_env_var_overrides_the_configured_root(
    plugin, temp_hermes_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = plugin.drop.config
    (temp_hermes_home / "config.yaml").write_text(
        f"plugins:\n  entries:\n    hermes-drop:\n      spool_root: {tmp_path / 'from-config'}\n",
        encoding="utf-8",
    )

    assert config.spool_root() == str(tmp_path / "from-config")

    monkeypatch.setenv("HERMES_DROP_SPOOL_ROOT", str(tmp_path / "from-env"))
    assert config.spool_root() == str(tmp_path / "from-env")


def test_an_explicitly_empty_root_means_not_configured(
    plugin, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The kill switch, and it fails closed: with no root there is nowhere safe
    to put bytes, so a file claim must refuse rather than pick somewhere."""
    config = plugin.drop.config
    monkeypatch.setenv("HERMES_DROP_SPOOL_ROOT", "")

    assert config.spool_root() == ""
    assert config.spool_configured() is False


def test_the_ttl_defaults_to_fifteen_minutes_and_is_clamped(
    plugin, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operator may shorten the window. A ttl of zero (delete immediately) or
    a day (bytes at rest until someone notices) are both misconfigurations, and a
    clamp beats a refusal here: the spool must not become unusable because of a
    typo in an optional knob."""
    config = plugin.drop.config

    assert config.spool_ttl_seconds() == 900

    monkeypatch.setenv("HERMES_DROP_SPOOL_TTL_SECONDS", "120")
    assert config.spool_ttl_seconds() == 120

    monkeypatch.setenv("HERMES_DROP_SPOOL_TTL_SECONDS", "0")
    assert config.spool_ttl_seconds() == config.MIN_SPOOL_TTL_SECONDS

    monkeypatch.setenv("HERMES_DROP_SPOOL_TTL_SECONDS", "999999")
    assert config.spool_ttl_seconds() == config.MAX_SPOOL_TTL_SECONDS

    monkeypatch.setenv("HERMES_DROP_SPOOL_TTL_SECONDS", "not-a-number")
    assert config.spool_ttl_seconds() == config.DEFAULT_SPOOL_TTL_SECONDS


def test_a_tilde_in_the_configured_root_is_refused_rather_than_expanded(spool_mod) -> None:
    """``~`` is ``$HOME``, and this package's profile rule is ``get_hermes_home()``
    and never ``Path.home()`` — a ``~/spool`` root would silently escape profile
    scoping and be shared by every profile on the host."""
    with pytest.raises(spool_mod.SpoolUnsafe) as refusal:
        spool_mod.Spool(root="~/spool").ensure_root()

    assert "~" in str(refusal.value)


def test_the_limits_are_the_mvp_defaults(spool_mod) -> None:
    """Server-enforced, not inherited from the peer that advertises them
    (``docs/FILE_TRANSFER_MVP.md`` → MVP limits). The live budget is the broker's
    168 MiB reasoning restated on this side: four fully-reserved claims."""
    assert spool_mod.MAX_CLAIM_FILES == 5
    assert spool_mod.MAX_CLAIM_FILE_BYTES == 42 * 1024 * 1024
    assert spool_mod.MAX_CLAIM_TOTAL_BYTES == 42 * 1024 * 1024
    assert spool_mod.MAX_LIVE_CLAIM_BYTES == 4 * spool_mod.MAX_CLAIM_TOTAL_BYTES


# ── root safety, provenance and ancestors ──────────────────────────────────


def test_a_created_root_is_private_regardless_of_umask(spool_mod, home: Path) -> None:
    """``mkdir(mode=…)`` is masked by umask, so the mode has to be set again on
    the descriptor. Run under the most permissive umask there is, which is the
    one that would expose the bug."""
    previous = os.umask(0o000)
    try:
        spool = spool_mod.Spool(root=home / "state" / "hermes-drop" / "spool")
        spool.ensure_root()
    finally:
        os.umask(previous)

    assert stat.S_IMODE((home / "state" / "hermes-drop" / "spool").stat().st_mode) == 0o700


def test_every_ancestor_this_call_creates_is_private_too(spool_mod, home: Path) -> None:
    """``os.makedirs(mode=…)`` applies the mode to the leaf only; intermediates get
    ``0o777 & ~umask``. ``state/`` is also where the journal lives, and a
    world-writable ancestor lets a local attacker swap the directory the published
    paths point into — the one place the descriptor discipline cannot protect,
    because the caller is handed strings."""
    previous = os.umask(0o000)
    try:
        spool_mod.Spool(root=home / "state" / "hermes-drop" / "spool").ensure_root()
    finally:
        os.umask(previous)

    for path in (
        home / "state",
        home / "state" / "hermes-drop",
        home / "state" / "hermes-drop" / "spool",
    ):
        assert stat.S_IMODE(path.stat().st_mode) == 0o700, path


def test_a_group_writable_ancestor_is_refused_not_used(spool_mod, home: Path) -> None:
    loose = home / "state"
    loose.mkdir()
    loose.chmod(0o775)  # Deterministic despite the runner's umask.

    with pytest.raises(spool_mod.SpoolUnsafe) as refusal:
        spool_mod.Spool(root=home / "state" / "hermes-drop" / "spool").ensure_root()

    assert "state" in str(refusal.value)
    assert not (loose / "hermes-drop").exists(), "a root was created under an unsafe ancestor"


def test_a_symlinked_ancestor_is_refused(spool_mod, home: Path, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (home / "state").symlink_to(elsewhere, target_is_directory=True)

    with pytest.raises(spool_mod.SpoolUnsafe):
        spool_mod.Spool(root=home / "state" / "hermes-drop" / "spool").ensure_root()

    assert list(elsewhere.iterdir()) == []


def test_a_root_outside_the_trusted_base_needs_its_parent_to_exist_already(
    spool_mod, home: Path, tmp_path: Path
) -> None:
    """A configured root such as ``/run/hermes-drop/claims`` is legitimate, but
    creating an arbitrary ancestor chain outside the profile is not this plugin's
    business — that directory is the operator's (or systemd's, or the container
    runtime's) to create with a mode they chose."""
    outside = tmp_path / "outside" / "deep" / "spool"

    with pytest.raises(spool_mod.SpoolUnsafe) as refusal:
        spool_mod.Spool(root=outside).ensure_root()

    assert not outside.parent.exists()
    assert "0700" in str(refusal.value), "the refusal has to say what to create"

    # With the parent in place and private, the leaf is created as usual. Created
    # one level at a time on purpose: ``parents=True`` applies the mode to the leaf
    # only, so the intermediate would be group-writable and the ancestor check —
    # correctly — refuses that too.
    (tmp_path / "outside").mkdir(mode=0o700)
    outside.parent.mkdir(mode=0o700)
    spool_mod.Spool(root=outside).ensure_root()
    assert stat.S_IMODE(outside.stat().st_mode) == 0o700


def test_a_relative_root_is_refused(spool_mod) -> None:
    """A relative root would resolve against the gateway's cwd, which nothing in
    this plugin controls."""
    with pytest.raises(spool_mod.SpoolUnsafe):
        spool_mod.Spool(root="relative/spool").ensure_root()


def test_an_unconfigured_root_is_refused(spool_mod, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HERMES_DROP_SPOOL_ROOT", "")

    with pytest.raises(spool_mod.SpoolUnsafe):
        spool_mod.Spool().ensure_root()


def test_a_symlinked_root_is_refused_and_never_written_through(
    spool_mod, home: Path, tmp_path: Path
) -> None:
    """The classic: point the configured root at somewhere else entirely. The
    root is opened ``O_NOFOLLOW``, so this is a refusal and not a redirect."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    link = home / "spool"
    link.symlink_to(elsewhere, target_is_directory=True)

    with pytest.raises(spool_mod.SpoolUnsafe):
        spool_mod.Spool(root=link).ensure_root()

    assert list(elsewhere.iterdir()) == []


def test_a_root_that_is_not_a_directory_is_refused(spool_mod, home: Path) -> None:
    plain = home / "spool"
    plain.write_bytes(b"")

    with pytest.raises(spool_mod.SpoolUnsafe):
        spool_mod.Spool(root=plain).ensure_root()


@pytest.mark.parametrize("mode", [0o777, 0o755, 0o750, 0o701])
def test_a_pre_existing_root_with_loose_modes_is_refused_not_tightened(
    spool_mod, home: Path, mode: int
) -> None:
    """Refused, and deliberately not repaired. Tightening someone else's
    directory is the more dangerous of the two behaviours — an operator who
    pointed the spool at ``/tmp`` by mistake would have this plugin chmod
    ``/tmp`` — so a root this process did not create has to already be private."""
    root = home / "spool"
    root.mkdir(mode=0o700)
    root.chmod(mode)

    with pytest.raises(spool_mod.SpoolUnsafe):
        spool_mod.Spool(root=root).ensure_root()

    assert stat.S_IMODE(root.stat().st_mode) == mode, "the mode was changed under the operator"


def test_a_root_owned_by_somebody_else_is_refused(
    spool_mod, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proved by moving *this* process's identity rather than the directory's:
    creating a foreign-owned directory needs root, and the check is the same
    comparison either way."""
    root = home / "spool"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 4242)

    with pytest.raises(spool_mod.SpoolUnsafe):
        spool_mod.Spool(root=root).ensure_root()


def test_a_root_this_plugin_created_carries_a_provenance_marker(spool_mod, spool) -> None:
    marker = spool.root / spool_mod.MARKER_NAME

    spool.ensure_root()

    assert marker.is_file()
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    body = json.loads(marker.read_text(encoding="utf-8"))
    assert body["plugin"] == "hermes-drop"


def test_a_private_directory_of_the_operators_is_refused_never_adopted(
    spool_mod, home: Path
) -> None:
    """The destructive case. ``~/.ssh``, ``~/.gnupg``, ``~/.aws`` and
    ``$HERMES_HOME/state`` are all user-owned and 0700, so *validation* passes on
    every one of them — which is why validation is not the test that decides
    whether a directory may be swept. Provenance is."""
    private = home / "dot-ssh"
    private.mkdir(mode=0o700)
    (private / "id_ed25519").write_bytes(b"PRIVATE KEY")
    (private / "known_hosts").write_bytes(b"host key")
    (private / "subdir").mkdir(mode=0o700)

    spool = spool_mod.Spool(root=private)

    with pytest.raises(spool_mod.SpoolUnsafe) as refusal:
        spool.ensure_root()
    assert spool_mod.MARKER_NAME in str(refusal.value), "the refusal must name the marker"

    # And the same refusal from the sweeping side, which is the one that deletes.
    assert spool.cleanup_at_startup() == {**_empty_counts(), "errors": 1}
    assert sorted(p.name for p in private.iterdir()) == ["id_ed25519", "known_hosts", "subdir"]
    assert (private / "id_ed25519").read_bytes() == b"PRIVATE KEY"


def test_an_empty_private_directory_is_adopted_by_marking_it(spool_mod, home: Path) -> None:
    """An operator (or a container runtime, or a tmpfs mount) creating the root
    ahead of time is normal and must keep working. An *empty* private directory
    has nothing to lose, so it is adopted by writing the marker — which is what
    makes every later sweep legitimate."""
    prepared = home / "prepared"
    prepared.mkdir(mode=0o700)

    spool_mod.Spool(root=prepared).ensure_root()

    assert (prepared / spool_mod.MARKER_NAME).is_file()


def test_a_root_being_marked_by_a_racing_creator_is_not_read_as_a_strangers(
    spool_mod, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two claims arriving together on a spool that has never been used both try
    to create the root. Whoever loses the ``mkdir`` reaches the provenance check
    while the winner is still between its own lookup and its marker write, and
    the emptiness gate — the one that protects ``~/.ssh`` — then sees a
    directory that has entries and no marker.

    Refusing there is refusing a root this process is itself in the middle of
    creating, which surfaces as ``spool_unavailable`` on a perfectly good claim.
    Re-reading the marker *after* the listing is what tells the two apart: a
    stranger's directory does not sprout one.
    """
    root = home / "state" / "hermes-drop" / "spool"
    _private_chain(root)
    root.mkdir(mode=0o700)  # the winner's mkdir; its marker has not landed yet
    real_listdir = os.listdir
    raced = {"done": False}

    def listdir_the_winner_finishes_during(target):
        entries = real_listdir(target)
        if not raced["done"]:
            raced["done"] = True
            marker = root / spool_mod.MARKER_NAME
            marker.write_text('{"plugin": "hermes-drop"}', encoding="utf-8")
            marker.chmod(0o600)
            (root / (spool_mod.STAGING_PREFIX + _claim_name("a"))).mkdir(mode=0o700)
            entries = real_listdir(target)
        return entries

    monkeypatch.setattr(os, "listdir", listdir_the_winner_finishes_during)
    spool_mod.Spool(root=root).ensure_root()
    monkeypatch.undo()

    assert raced["done"], "the race window was never entered"
    assert (root / spool_mod.MARKER_NAME).is_file()


def test_dir_fd_support_is_required_and_refused_when_absent(
    spool_mod, spool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every safety property here rests on descriptor-relative syscalls, which are
    POSIX. On a platform without them the answer is a refusal, not a claim that
    quietly loses the guarantees — and not an ``AttributeError`` surfacing as an
    indeterminate verdict either."""
    monkeypatch.setattr(os, "supports_dir_fd", frozenset())

    with pytest.raises(spool_mod.SpoolUnsafe) as refusal:
        spool.ensure_root()

    assert "dir_fd" in str(refusal.value)


# ── staging and publish ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_claim_is_invisible_until_it_is_published(spool) -> None:
    """The whole point of the staging directory. While bytes are arriving there
    must be no name under the root that a consumer would mistake for a result,
    and the one that exists must be dot-prefixed and 0700."""
    async with spool.stage() as claim:
        await _write_one(claim, 0, "notes.txt", b"hello")
        assert _entries(spool) == [claim.staging_name]
        assert claim.staging_name.startswith(spool.STAGING_PREFIX)
        assert stat.S_IMODE((spool.root / claim.staging_name).stat().st_mode) == 0o700
        assert claim.published is False

        published = await claim.publish("drop-1")

    assert _entries(spool) == [claim.claim_id]
    assert published["files"][0]["path"] == str(
        spool.root / claim.claim_id / claim.entries()[0]["storage"]
    )
    assert Path(published["files"][0]["path"]).read_bytes() == b"hello"


@pytest.mark.asyncio
async def test_published_files_are_0600_under_a_0700_directory_whatever_the_umask(
    spool_mod, home: Path
) -> None:
    previous = os.umask(0o000)
    try:
        spool = spool_mod.Spool(root=home / "state" / "hermes-drop" / "spool")
        async with spool.stage() as claim:
            await _write_one(claim, 0, "a.bin", b"x" * 64)
            published = await claim.publish("drop-1")
    finally:
        os.umask(previous)

    path = Path(published["files"][0]["path"])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.parent.parent.stat().st_mode) == 0o700


@pytest.mark.asyncio
async def test_storage_names_are_opaque_and_carry_nothing_from_the_label(
    spool, home: Path
) -> None:
    labels = [
        "../../etc/passwd",
        "..\\..\\windows\\system32\\config\\sam",
        "C:report.pdf",
        "/absolute/secret.pem",
        "spaces and (parens).tar.gz",
    ]
    async with spool.stage() as claim:
        for index, label in enumerate(labels):
            await _write_one(claim, index, label, f"file-{index}".encode())
        published = await claim.publish("drop-1")

    directory = Path(published["files"][0]["path"]).parent
    for entry in published["files"]:
        storage = Path(entry["path"]).name
        assert len(storage) == 2 * spool.STORAGE_NAME_BYTES
        assert all(character in "0123456789abcdef" for character in storage)
        assert Path(entry["path"]).parent == directory, "every byte lands in the claim directory"
        # The label survives as a label — sanitized for display, never joined.
        assert "/" not in entry["name"] and "\\" not in entry["name"]

    assert sorted(p.name for p in directory.iterdir() if not p.name.startswith(".")) == sorted(
        Path(entry["path"]).name for entry in published["files"]
    )
    # And nothing was created anywhere near the traversal targets.
    assert not (home / "etc").exists()
    assert not (spool.root.parent / "passwd").exists()


@pytest.mark.asyncio
async def test_hostile_labels_are_sanitized_for_display_only(spool) -> None:
    """The labels a *real* broker cannot send, because the container decoder
    refuses them. The spool re-runs the rules anyway: a label reaches a model's
    context, and this is the last place that can be true of a broker that lies."""
    cases = [
        ("../../etc/passwd", "passwd"),
        ("", "unnamed"),
        (".", "unnamed"),
        ("..", "unnamed"),
        ("with\x00nul.txt", "withnul.txt"),
        ("line\nbreak.txt", "linebreak.txt"),
        ("bell\x07.txt", "bell.txt"),
        ("  padded.txt  ", "padded.txt"),
        ("é" * 200, None),  # capped, not refused
        (12345, "unnamed"),  # not even a string
    ]
    async with spool.stage() as claim:
        for index, (label, _) in enumerate(cases[:5]):
            await _write_one(claim, index, label, b"x")
        first = claim.entries()

    for entry, (label, expected) in zip(first, cases[:5]):
        assert entry["name"] == expected, f"{label!r}"

    async with spool.stage() as claim:
        for index, (label, _) in enumerate(cases[5:]):
            await _write_one(claim, index, label, b"x")
        second = claim.entries()

    for entry, (label, expected) in zip(second, cases[5:]):
        if expected is not None:
            assert entry["name"] == expected, f"{label!r}"
        assert len(entry["name"].encode("utf-8")) <= 255
        assert "\x00" not in entry["name"]


@pytest.mark.asyncio
async def test_an_unpaired_surrogate_in_a_label_degrades_instead_of_wedging_the_claim(
    spool_mod, spool
) -> None:
    """``json.loads('"\\ud800"')`` produces a lone surrogate, and encoding one to
    UTF-8 raises ``UnicodeEncodeError`` — a ``ValueError``, which is neither
    ``StagingFailed`` nor ``OSError``, so it used to escape the sink and wedge the
    drop in the one verdict that can be neither retried nor marked spent. A real
    broker cannot send it (the manifest is decoded strictly), which is precisely
    why it is refused here rather than relied upon there."""
    lone = json.loads('"\\ud800"')
    assert spool_mod.sanitize_label(lone) == spool_mod.FALLBACK_LABEL
    assert spool_mod.sanitize_label("a" + lone + "b.txt") == "ab.txt"
    assert spool_mod.sanitize_type("text/" + lone) == ""

    async with spool.stage() as claim:
        await _write_one(claim, 0, lone + "name.txt", b"payload", type_hint="text/" + lone)
        published = await claim.publish("drop-1")

    assert published["files"][0]["name"] == "name.txt"
    assert published["files"][0]["type"] == ""


@pytest.mark.asyncio
async def test_a_type_hint_is_printable_ascii_or_nothing(spool) -> None:
    async with spool.stage() as claim:
        await _write_one(claim, 0, "a", b"x", type_hint="application/json")
        await _write_one(claim, 1, "b", b"x", type_hint="text/\x01plain")
        await _write_one(claim, 2, "c", b"x", type_hint="é/é")
        await _write_one(claim, 3, "d", b"x", type_hint="x/" + "y" * 300)
        entries = claim.entries()

    assert [entry["type"] for entry in entries] == ["application/json", "", "", ""]


def test_a_type_is_never_repaired_only_emptied(spool_mod) -> None:
    """``docs/FILE_TRANSFER_MVP.md`` and ``src/file-container.js`` both say an
    unusable type becomes empty "rather than being repaired". Python's
    ``str.strip()`` removes C0 separators that JS's ``trim()`` keeps, so stripping
    first would *display the remainder* of a value the rules reject outright.
    ``test_spool_differential.py`` proves the general case against the real JS."""
    assert spool_mod.sanitize_type(" \x1cD") == "", "a control character is not trimmed away"
    assert spool_mod.sanitize_type("\x1c\xa0C:") == ""
    # ...and U+FEFF *is* whitespace to JS's trim(), where str.strip() keeps it.
    assert spool_mod.sanitize_type(":﻿\n") == ":"


@pytest.mark.asyncio
async def test_duplicate_labels_are_allowed_and_get_distinct_storage(spool) -> None:
    async with spool.stage() as claim:
        await _write_one(claim, 0, "config.json", b"first")
        await _write_one(claim, 1, "config.json", b"second")
        published = await claim.publish("drop-1")

    paths = [entry["path"] for entry in published["files"]]
    assert [entry["name"] for entry in published["files"]] == ["config.json", "config.json"]
    assert len(set(paths)) == 2
    assert [Path(path).read_bytes() for path in paths] == [b"first", b"second"]


@pytest.mark.asyncio
async def test_an_empty_file_is_published_as_an_empty_file(spool) -> None:
    """The sink is called exactly once with ``b""`` for a zero-byte file
    (``drop/file_claim.py``), and a consumer that creates files in the callback
    has to create that one too — otherwise a five-file claim publishes four."""
    async with spool.stage() as claim:
        await _write_one(claim, 0, "empty.txt", b"")
        await _write_one(claim, 1, "full.txt", b"content")
        published = await claim.publish("drop-1")

    assert [entry["size"] for entry in published["files"]] == [0, 7]
    first = Path(published["files"][0]["path"])
    assert first.exists() and first.read_bytes() == b""
    assert published["files"][0]["sha256"] == _digest(b"")


@pytest.mark.asyncio
async def test_files_are_published_in_manifest_order_whatever_order_they_arrive_in(
    spool,
) -> None:
    """The broker picks the next index in its ack answer (``file_claim.py``), so
    arrival order is its business. Manifest order is what a caller is given, and
    ``arrival_order`` is what lets a cross-check line up two lists that need not
    agree on order."""
    async with spool.stage() as claim:
        await _write_one(claim, 2, "third.txt", b"three")
        await _write_one(claim, 0, "first.txt", b"one")
        await _write_one(claim, 1, "second.txt", b"two")
        assert claim.arrival_order() == [2, 0, 1]
        published = await claim.publish("drop-1")

    assert [entry["name"] for entry in published["files"]] == [
        "first.txt",
        "second.txt",
        "third.txt",
    ]
    assert [Path(entry["path"]).read_bytes() for entry in published["files"]] == [
        b"one",
        b"two",
        b"three",
    ]


@pytest.mark.asyncio
async def test_the_verified_digest_is_computed_from_the_bytes_on_disk(
    spool, spool_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not from the stream. A digest taken over what was received says nothing
    about what landed, and the whole point of the spool is what landed — so the
    file is re-read through the same descriptor and hashed again before its
    frame may be acked.

    Corrupted at **constant length**, deliberately: dropping a byte trips the
    ``st_size`` check first and never reaches the digest comparison, so a
    byte-dropping test proves the size check and only *names* this one."""
    real_write_all = spool_mod._write_all

    def flipping_write_all(fd, data):
        real_write_all(fd, bytes(byte ^ 0xFF for byte in data))

    async with spool.stage() as claim:
        monkeypatch.setattr(spool_mod, "_write_all", flipping_write_all)
        with pytest.raises(spool.StagingFailed) as failure:
            await _write_one(claim, 0, "a.bin", b"0123456789" * 4)
        monkeypatch.undo()
        assert "does not match" in str(failure.value), "the size check answered instead"
        assert claim.published is False


@pytest.mark.asyncio
async def test_a_file_shorter_on_disk_than_advertised_is_refused(
    spool, spool_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other corruption shape, and a separate check: a short write that
    reports success is caught by ``fstat`` before the digest is ever compared."""
    real_write_all = spool_mod._write_all

    def truncating_write_all(fd, data):
        real_write_all(fd, data[:-1] if len(data) > 1 else data)

    async with spool.stage() as claim:
        monkeypatch.setattr(spool_mod, "_write_all", truncating_write_all)
        with pytest.raises(spool.StagingFailed) as failure:
            await _write_one(claim, 0, "a.bin", b"0123456789" * 4)
        monkeypatch.undo()

    assert "on disk" in str(failure.value)


@pytest.mark.asyncio
async def test_more_bytes_than_advertised_are_refused_not_written(spool) -> None:
    """A frame longer than its manifest entry cannot happen against the real
    broker — the receiver checks the framed length first. It is refused here so
    the spool's own accounting is not a restatement of the receiver's."""
    async with spool.stage() as claim:
        entry = {"name": "a", "size": 4, "type": ""}
        await claim.accept(0, entry, b"aaaa", False)
        with pytest.raises(spool.StagingFailed):
            await claim.accept(0, entry, b"b", True)


@pytest.mark.asyncio
async def test_fewer_bytes_than_advertised_are_refused_at_the_end(spool) -> None:
    async with spool.stage() as claim:
        entry = {"name": "a", "size": 8, "type": ""}
        with pytest.raises(spool.StagingFailed):
            await claim.accept(0, entry, b"short", True)


@pytest.mark.asyncio
async def test_a_second_file_at_the_same_index_is_refused(spool) -> None:
    """Index reuse would mean one file overwriting another's storage name, and
    the returned list would then describe bytes that are not there."""
    async with spool.stage() as claim:
        await _write_one(claim, 0, "a", b"first")
        with pytest.raises(spool.StagingFailed):
            await _write_one(claim, 0, "a", b"second")


# ── the MVP ceilings, enforced on this side ────────────────────────────────


@pytest.mark.asyncio
async def test_a_sixth_file_is_refused(spool) -> None:
    """5 files is an MVP limit that must be "server-enforced, not trusted from
    the browser" — and by the same argument not trusted from the broker either.
    Without this, 200 files published and a 62 KB tool result headed for
    ``state.db`` was reachable from one broker regression."""
    async with spool.stage() as claim:
        for index in range(5):
            await _write_one(claim, index, f"f{index}", b"x")
        with pytest.raises(spool.StagingFailed) as failure:
            await _write_one(claim, 5, "sixth", b"x")

    assert "5" in str(failure.value)


@pytest.mark.asyncio
async def test_a_file_advertising_more_than_the_per_file_cap_is_refused_before_a_byte_is_written(
    spool, spool_mod
) -> None:
    async with spool.stage() as claim:
        entry = {"name": "huge.bin", "size": spool_mod.MAX_CLAIM_FILE_BYTES + 1, "type": ""}
        with pytest.raises(spool.StagingFailed):
            await claim.accept(0, entry, b"x", False)
        assert claim.entries() == []
        assert list((spool.root / claim.staging_name).iterdir()) == []


@pytest.mark.asyncio
async def test_files_whose_advertised_sizes_exceed_the_total_cap_are_refused(
    spool, spool_mod
) -> None:
    """Refused on the *advertised* total, before the bytes arrive: discovering it
    at 42 MiB + 1 would mean having written 42 MiB first."""
    half = spool_mod.MAX_CLAIM_TOTAL_BYTES // 2 + 1
    async with spool.stage() as claim:
        await claim.accept(0, {"name": "a", "size": half, "type": ""}, b"", False)
        with pytest.raises(spool.StagingFailed) as failure:
            await claim.accept(1, {"name": "b", "size": half, "type": ""}, b"", False)

    assert "total" in str(failure.value)


@pytest.mark.asyncio
async def test_only_four_claims_may_be_staged_at_once(spool_mod, spool) -> None:
    """The disk mirror of the broker's ``HANDOFF_MAX_LIVE_FILE_BYTES``: each
    staging claim reserves its full 42 MiB, so a process holds at most the
    broker's own 168 MiB of live file bytes. The fifth is refused with the drop
    untouched, which is a retry a second later — not a full disk."""
    claims = []
    try:
        for _ in range(4):
            claim = spool.stage()
            await claim.__aenter__()
            claims.append(claim)
        assert spool_mod.reserved_claim_bytes() == spool_mod.MAX_LIVE_CLAIM_BYTES

        with pytest.raises(spool_mod.SpoolBusy):
            await spool.stage().__aenter__()

        # Releasing one makes room for the next, so this is a queue and not a wall.
        await claims.pop().__aexit__(None, None, None)
        fifth = spool.stage()
        await fifth.__aenter__()
        claims.append(fifth)
    finally:
        for claim in claims:
            await claim.__aexit__(None, None, None)

    assert spool_mod.reserved_claim_bytes() == 0


@pytest.mark.asyncio
async def test_a_write_failure_leaves_nothing_behind(
    spool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disk full, mid-file. The verdict is a ``StagingFailed`` — deliberately not
    an ``OSError``, because ``receive_file_claim`` catches ``OSError`` and would
    report it as ``broker_unavailable``, blaming the socket for a full disk."""
    def enospc(fd, data):
        raise OSError(28, "No space left on device")

    with pytest.raises(spool.StagingFailed):
        async with spool.stage() as claim:
            monkeypatch.setattr(os, "write", enospc)
            await _write_one(claim, 0, "a.bin", b"payload")

    monkeypatch.undo()
    assert _entries(spool) == []


@pytest.mark.asyncio
async def test_an_fsync_failure_is_a_staging_failure_not_a_publish(
    spool, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_fsync(fd):
        raise OSError(5, "Input/output error")

    with pytest.raises(spool.StagingFailed):
        async with spool.stage() as claim:
            monkeypatch.setattr(os, "fsync", failing_fsync)
            await _write_one(claim, 0, "a.bin", b"payload")

    monkeypatch.undo()
    assert _entries(spool) == []


@pytest.mark.asyncio
async def test_a_rename_failure_publishes_nothing_and_leaves_no_partial_directory(
    spool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The publish is one rename. If it fails there is no half-published claim:
    the staging directory is the only thing that ever existed, and it goes."""
    def failing_rename(*args, **kwargs):
        raise OSError(18, "Invalid cross-device link")

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"payload")
        monkeypatch.setattr(os, "rename", failing_rename)
        with pytest.raises(spool.StagingFailed):
            await claim.publish("drop-1")
        monkeypatch.undo()
        assert claim.published is False

    assert _entries(spool) == []


@pytest.mark.asyncio
async def test_the_rename_is_the_commit_point_and_a_later_fsync_failure_is_a_warning(
    spool, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A directory ``fsync`` can fail (EINVAL on some filesystems, EIO on a dying
    device) *after* a successful rename. The claim is published at that point —
    complete and readable — so reporting a failure would tell the user their files
    are gone while they sit on disk. It is a durability warning, not a loss."""
    real_fsync = os.fsync

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"hello")
        storage = [entry["storage"] for entry in claim.entries()]

        def fsync_that_fails_after_the_rename(fd):
            if (spool.root / claim.claim_id).exists():
                raise OSError(22, "Invalid argument")
            return real_fsync(fd)

        monkeypatch.setattr(os, "fsync", fsync_that_fails_after_the_rename)
        with caplog.at_level(logging.WARNING):
            published = await claim.publish("drop-1")
        monkeypatch.undo()

    assert claim.published is True
    assert Path(published["files"][0]["path"]).read_bytes() == b"hello"
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "durab" in logged.lower(), logged
    assert "discard" not in logged.lower(), "a published claim must not be reported as lost"
    assert (spool.root / claim.claim_id / storage[0]).is_file()


@pytest.mark.asyncio
async def test_an_exception_inside_the_claim_discards_the_staging_directory(spool) -> None:
    with pytest.raises(RuntimeError):
        async with spool.stage() as claim:
            await _write_one(claim, 0, "a.bin", b"payload")
            raise RuntimeError("the caller gave up")

    assert _entries(spool) == []


@pytest.mark.asyncio
async def test_cancellation_discards_the_staging_directory_and_publishes_nothing(
    spool,
) -> None:
    """A cancelled turn is a ``BaseException``, so the cleanup has to happen
    without awaiting anything: an ``await`` inside a cancelled task raises
    immediately, which would leave the directory behind for the sweeper."""
    started = asyncio.Event()

    async def transfer() -> None:
        async with spool.stage() as claim:
            await _write_one(claim, 0, "a.bin", b"payload")
            started.set()
            await asyncio.sleep(30)
            await claim.publish("drop-1")

    task = asyncio.ensure_future(transfer())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert _entries(spool) == []


@pytest.mark.asyncio
async def test_a_cancelled_claim_can_still_be_quarantined_without_awaiting(spool) -> None:
    """The synchronous quarantine that the post-commit cancellation path needs.
    ``asyncio.shield`` is not enough on its own — the shielded await still raises
    in a cancelled task, so the rename has to be able to complete inline."""
    started = asyncio.Event()
    held: dict = {}

    async def transfer() -> None:
        async with spool.stage() as claim:
            await _write_one(claim, 0, "a.bin", b"the only copy")
            started.set()
            try:
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                held["name"] = claim.quarantine_now()
                raise

    task = asyncio.ensure_future(transfer())
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert held["name"].startswith(spool.QUARANTINE_PREFIX)
    directory = spool.root / held["name"]
    assert [p.read_bytes() for p in directory.iterdir()] == [b"the only copy"]


@pytest.mark.asyncio
async def test_a_pre_created_staging_name_is_never_written_into(
    spool, spool_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Storage and claim ids are 128-bit random, so this is not a realistic
    guess — it is the assertion that a collision *refuses* instead of adopting
    somebody else's directory. Forced by pinning the generator."""
    monkeypatch.setattr(spool_mod, "_token", lambda nbytes: "ab" * nbytes)
    spool.ensure_root()
    squatted = spool.root / (spool.STAGING_PREFIX + "ab" * spool_mod.CLAIM_ID_BYTES)
    squatted.mkdir(mode=0o700)
    (squatted / "planted").write_bytes(b"not ours")

    with pytest.raises(spool.SpoolUnsafe):
        async with spool.stage():
            pass

    assert (squatted / "planted").read_bytes() == b"not ours", "an existing directory was reused"
    assert spool_mod.reserved_claim_bytes() == 0, "a failed claim kept its reservation"


@pytest.mark.asyncio
async def test_a_staging_directory_is_registered_before_it_becomes_visible(
    spool, spool_mod, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The registration is what exempts a live claim from a purge. Registering it
    *after* ``mkdir`` leaves a window in which a concurrent startup purge deletes
    a directory that is about to be written into — and the writes then continue
    into an unlinked directory, surfacing only past the commit."""
    observed: dict = {}
    real_mkdir_at = spool_mod._mkdir_at

    def watching_mkdir_at(dir_fd, name, mode):
        observed[name] = (str(spool.root), name) in spool_mod._ACTIVE_STAGING
        return real_mkdir_at(dir_fd, name, mode)

    monkeypatch.setattr(spool_mod, "_mkdir_at", watching_mkdir_at)
    async with spool.stage() as claim:
        pass

    assert observed[claim.staging_name] is True


@pytest.mark.asyncio
async def test_a_symlink_at_the_storage_name_is_refused_not_followed(
    spool, spool_mod, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``O_CREAT|O_EXCL|O_NOFOLLOW``: the target must stay untouched even though
    the attacker won the race for the name."""
    target = tmp_path / "outside.txt"
    target.write_bytes(b"original")

    async with spool.stage() as claim:
        monkeypatch.setattr(spool_mod, "_token", lambda nbytes: "cd" * nbytes)
        storage = "cd" * spool_mod.STORAGE_NAME_BYTES
        os.symlink(target, spool.root / claim.staging_name / storage)

        with pytest.raises(spool.StagingFailed):
            await _write_one(claim, 0, "a.bin", b"overwritten")

    assert target.read_bytes() == b"original"


@pytest.mark.asyncio
async def test_the_published_metadata_holds_labels_and_never_bytes(spool) -> None:
    """The sidecar exists so a sweep after a crash knows when a directory
    expires without having to trust its mtime. It is a dotfile, 0600, and it is
    not among the paths handed back — a consumer gets files, not bookkeeping."""
    async with spool.stage() as claim:
        await _write_one(claim, 0, "secrets.env", b"PGPASSWORD=example-not-real")
        published = await claim.publish("drop-42")

    directory = Path(published["files"][0]["path"]).parent
    sidecar = directory / spool.METADATA_NAME
    assert sidecar.name.startswith("."), "the sidecar must not look like a payload file"
    assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
    assert sidecar.name not in [Path(entry["path"]).name for entry in published["files"]]

    body = json.loads(sidecar.read_text(encoding="utf-8"))
    assert body["drop_id"] == "drop-42"
    assert body["expires_at"] == published["expires_at"]
    assert body["files"][0]["name"] == "secrets.env"
    assert "PGPASSWORD" not in sidecar.read_text(encoding="utf-8")
    assert "bytes" not in body["files"][0]


@pytest.mark.asyncio
async def test_two_concurrent_claims_publish_independently(spool) -> None:
    async def one(marker: bytes) -> dict:
        async with spool.stage() as claim:
            await _write_one(claim, 0, "a.bin", marker)
            return await claim.publish("drop-" + marker.decode())

    first, second = await asyncio.gather(one(b"one"), one(b"two"))

    assert first["claim_id"] != second["claim_id"]
    assert Path(first["files"][0]["path"]).read_bytes() == b"one"
    assert Path(second["files"][0]["path"]).read_bytes() == b"two"
    assert _entries(spool) == sorted([first["claim_id"], second["claim_id"]])


# ── quarantine ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_quarantine_moves_the_bytes_out_of_reach_without_publishing(spool) -> None:
    """For ``transfer_indeterminate``: the verdict never arrived, so nothing may
    be published — but the bytes may be the only copy left, so they are kept for
    the TTL rather than deleted on the spot (``contract/control-protocol.json`` →
    ``file_claim.client_verdicts``)."""
    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"maybe the only copy")
        name = await claim.quarantine()
        assert claim.published is False

    assert _entries(spool) == [name]
    assert name.startswith(spool.QUARANTINE_PREFIX)
    assert stat.S_IMODE((spool.root / name).stat().st_mode) == 0o700
    assert not (spool.root / claim.claim_id).exists(), "a quarantined claim is never published"


@pytest.mark.asyncio
async def test_a_published_claim_can_no_longer_be_quarantined_or_discarded(spool) -> None:
    """Once the rename has happened the bytes are the caller's, and a late error
    path must not be able to take them away again."""
    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"published")
        published = await claim.publish("drop-1")
        await claim.discard()
        assert await claim.quarantine() == ""

    assert Path(published["files"][0]["path"]).read_bytes() == b"published"


# ── sweeping, expiry and recovery ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_published_claim_is_swept_when_its_ttl_lapses(spool_mod, home: Path) -> None:
    now = [1_000_000.0]
    spool = spool_mod.Spool(root=home / "spool", ttl_seconds=900, clock=lambda: now[0])

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"payload")
        published = await claim.publish("drop-1")

    assert published["expires_at"] == int(now[0]) + 900

    now[0] += 899
    assert spool.sweep()["published"] == 0
    assert Path(published["files"][0]["path"]).exists()

    now[0] += 2
    assert spool.sweep()["published"] == 1
    assert not Path(published["files"][0]["path"]).exists()
    assert _entries(spool) == []


@pytest.mark.asyncio
async def test_a_sidecar_expiry_is_clamped_to_the_ttl(spool_mod, home: Path) -> None:
    """The sidecar is this plugin's own record, but it is a *file*, and a clock
    that jumped forward at publish time (or a corrupted record) would otherwise
    pin bytes on disk for as long as it says. The directory's own mtime plus the
    TTL is the ceiling."""
    now = [1_000_000.0]
    spool = spool_mod.Spool(root=home / "spool", ttl_seconds=900, clock=lambda: now[0])
    spool.ensure_root()
    directory = spool.root / _claim_name("a")
    directory.mkdir(mode=0o700)
    (directory / ("0" * 8)).write_bytes(b"payload")
    (directory / spool.METADATA_NAME).write_text(
        json.dumps({"claim_id": directory.name, "drop_id": "d", "expires_at": 4_000_000_000}),
        encoding="utf-8",
    )
    os.utime(directory, (now[0], now[0]))

    now[0] += 901
    assert spool.sweep()["published"] == 1
    assert not directory.exists()


@pytest.mark.asyncio
async def test_an_expiry_during_use_takes_the_path_away_and_nothing_else(
    spool_mod, home: Path
) -> None:
    """A consumer holding an open descriptor keeps reading; the path is gone.
    That is the contract for a spooled file, and it is why the tool result
    carries ``expires_at``."""
    now = [1_000_000.0]
    spool = spool_mod.Spool(root=home / "spool", ttl_seconds=60, clock=lambda: now[0])

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"still readable")
        published = await claim.publish("drop-1")

    path = Path(published["files"][0]["path"])
    with path.open("rb") as handle:
        now[0] += 61
        spool.sweep()
        assert handle.read() == b"still readable"
    assert not path.exists()


@pytest.mark.asyncio
async def test_a_sweep_does_not_touch_a_staging_directory_that_is_still_filling(
    spool_mod, home: Path
) -> None:
    """The race that would be worst: a janitor tick landing in the middle of a
    42 MiB transfer. An in-process claim is registered, so the sweeper skips it
    regardless of age — the age gate is only for what a crash left behind."""
    now = [1_000_000.0]
    spool = spool_mod.Spool(root=home / "spool", ttl_seconds=60, clock=lambda: now[0])

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"half a transfer")
        os.utime(spool.root / claim.staging_name, (0, 0))  # ancient, and still live

        swept = spool.sweep()
        assert swept["staging"] == 0
        assert (spool.root / claim.staging_name).exists()

        published = await claim.publish("drop-1")

    assert Path(published["files"][0]["path"]).read_bytes() == b"half a transfer"


def test_an_orphaned_staging_directory_is_swept_once_it_is_old_enough(
    spool_mod, home: Path
) -> None:
    """What a SIGKILL mid-transfer leaves. Age-gated for the same reason the
    journal's temp sweep is: an orphan and a live transfer from another process
    look identical on disk, and the grace is longer than any lease can be."""
    spool = spool_mod.Spool(root=home / "spool")
    spool.ensure_root()
    orphan = spool.root / (spool.STAGING_PREFIX + _claim_name("d"))
    orphan.mkdir(mode=0o700)
    (orphan / ("0" * 8)).write_bytes(b"partial")

    assert spool.sweep()["staging"] == 0, "a fresh orphan may be somebody's live transfer"
    assert orphan.exists()

    os.utime(orphan, (0, 0))
    assert spool.sweep()["staging"] == 1
    assert not orphan.exists()


def test_a_quarantined_claim_is_swept_at_the_ttl(spool_mod, home: Path) -> None:
    now = [1_000_000.0]
    spool = spool_mod.Spool(root=home / "spool", ttl_seconds=60, clock=lambda: now[0])
    spool.ensure_root()
    held = spool.root / (spool.QUARANTINE_PREFIX + _claim_name("c"))
    held.mkdir(mode=0o700)
    (held / ("0" * 8)).write_bytes(b"unknown fate")
    os.utime(held, (now[0], now[0]))

    assert spool.sweep()["quarantine"] == 0
    now[0] += 61
    assert spool.sweep()["quarantine"] == 1
    assert not held.exists()


def test_foreign_entries_are_reported_and_never_removed(
    spool_mod, home: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Only names this plugin generates are ever deleted. Anything else under the
    root — an operator's file, a stray symlink, a directory from another tool —
    is counted and named in a warning, however old it is. Deleting it would make
    the blast radius of a mis-pointed root unbounded, and the marker check is not
    a licence to treat everything inside as litter."""
    spool = spool_mod.Spool(root=home / "spool")
    spool.ensure_root()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"do not touch")
    stray = spool.root / "operator-notes.txt"
    stray.write_bytes(b"litter")
    link = spool.root / "link"
    link.symlink_to(outside)
    foreign_dir = spool.root / "not-a-claim-id"
    foreign_dir.mkdir(mode=0o700)
    for path in (stray, link, foreign_dir):
        os.utime(path, (0, 0), follow_symlinks=False)

    with caplog.at_level(logging.WARNING):
        swept = spool.sweep()
        purged = spool.cleanup_at_startup()

    assert swept["foreign"] == 3 and swept["published"] == 0
    assert purged["foreign"] == 3, "not even the startup purge may widen this"
    assert stray.read_bytes() == b"litter"
    assert link.is_symlink()
    assert foreign_dir.is_dir()
    assert outside.read_bytes() == b"do not touch", "the symlink was followed"
    assert "operator-notes.txt" in " ".join(r.getMessage() for r in caplog.records)


def test_the_marker_and_the_lock_are_never_swept(spool_mod, home: Path) -> None:
    spool = spool_mod.Spool(root=home / "spool")
    spool.ensure_root()
    spool.sweep()
    purged = spool.cleanup_at_startup()

    assert (spool.root / spool_mod.MARKER_NAME).is_file()
    assert purged["foreign"] == 0, "the marker must not even be counted as foreign"


def test_deep_litter_inside_a_claim_is_reported_at_warning_rather_than_retried_forever(
    spool_mod, home: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Nothing here creates nested directories, so this is corruption or an
    operator's stray files. The removal is depth-bounded so a hostile tree cannot
    turn a sweep into a walk — which means the entry survives, and an operator has
    to be told at a level they will see rather than at DEBUG forever."""
    now = [1_000_000.0]
    spool = spool_mod.Spool(root=home / "spool", ttl_seconds=60, clock=lambda: now[0])
    spool.ensure_root()
    directory = spool.root / _claim_name("b")
    deep = directory
    for level in range(spool_mod.MAX_REMOVE_DEPTH + 2):
        deep = deep / f"level{level}"
    deep.mkdir(mode=0o700, parents=True)
    (deep / "payload").write_bytes(b"buried")
    os.utime(directory, (now[0], now[0]))

    now[0] += 61
    with caplog.at_level(logging.WARNING):
        swept = spool.sweep()

    assert swept["errors"] == 1
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert str(spool.root) in logged and "depth" in logged.lower()


def test_a_concurrent_sweep_of_the_same_root_is_not_an_error(spool_mod, home: Path) -> None:
    """Two janitors (a restart racing a live gateway, two profiles sharing a
    root) must not turn a lost race into a raised exception."""
    spool = spool_mod.Spool(root=home / "spool")
    spool.ensure_root()
    for index in range(4):
        stale = spool.root / (spool.STAGING_PREFIX + f"{index:032x}")
        stale.mkdir(mode=0o700)
        (stale / "0000").write_bytes(b"x")
        os.utime(stale, (0, 0))

    assert spool.sweep()["staging"] == 4
    # And again on an empty root, which is what the loser of every race sees.
    assert spool.sweep() == _empty_counts()


@pytest.mark.asyncio
async def test_startup_cleanup_purges_the_claims_a_previous_process_left(
    spool_mod, home: Path
) -> None:
    """A restart is the one moment where age gates and TTLs are beside the
    point: no transfer can be live, and no conversation can be mid-claim, so
    every claim under the root is from a process that is gone. Leaving an
    unexpired directory would leave bytes with no janitor scheduled for them."""
    now = [1_000_000.0]
    spool = spool_mod.Spool(root=home / "spool", ttl_seconds=900, clock=lambda: now[0])

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"published before the crash")
        published = await claim.publish("drop-1")
    fresh_staging = spool.root / (spool.STAGING_PREFIX + _claim_name("0"))
    fresh_staging.mkdir(mode=0o700)
    (fresh_staging / "0000").write_bytes(b"mid-transfer when it died")
    held = spool.root / (spool.QUARANTINE_PREFIX + _claim_name("1"))
    held.mkdir(mode=0o700)

    # Not expired, not old — and gone anyway, because the process that owned it is.
    swept = spool.cleanup_at_startup()

    assert swept["published"] == 1 and swept["staging"] == 1 and swept["quarantine"] == 1
    assert _entries(spool) == []
    assert not Path(published["files"][0]["path"]).exists()
    assert stat.S_IMODE(spool.root.stat().st_mode) == 0o700, "the root itself survives, private"


@pytest.mark.asyncio
async def test_a_root_shared_with_another_live_gateway_is_swept_ttl_safely(
    spool_mod, home: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Two gateways on one spool root is a configuration this design does not
    want but cannot prevent. What it can prevent is one of them purging the
    other's *unexpired* claims on its way up: the aggressive purge happens only
    while holding an exclusive lock on the root, and otherwise degrades to the
    ordinary TTL-and-grace sweep."""
    now = [1_000_000.0]
    spool = spool_mod.Spool(root=home / "spool", ttl_seconds=60, clock=lambda: now[0])

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"the other gateway's claim")
        published = await claim.publish("drop-1")
    expired = spool.root / (spool.QUARANTINE_PREFIX + _claim_name("e"))
    expired.mkdir(mode=0o700)
    os.utime(expired, (now[0] - 3600, now[0] - 3600))

    # Stand in for the other gateway: an independent open file description on the
    # same lock file, which conflicts with ``flock`` even within one process.
    other = os.open(spool.root / spool_mod.LOCK_NAME, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with caplog.at_level(logging.WARNING):
            swept = spool.cleanup_at_startup()
    finally:
        os.close(other)

    assert Path(published["files"][0]["path"]).exists(), "another gateway's live claim was purged"
    assert swept["quarantine"] == 1, "an expired entry is still swept"
    assert not expired.exists()
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "shared" in logged.lower() and str(spool.root) in logged


def test_startup_cleanup_runs_once_per_process_and_blocks_the_second_caller(
    spool_mod, home: Path
) -> None:
    """The latch used to be set *before* the purge ran, so a second claim started
    staging into a root that was still being walked. Whoever loses the race has
    to wait for the purge, not skip past it."""
    order: list = []

    class SlowSpool(spool_mod.Spool):
        def cleanup_at_startup(self):
            order.append("purge:start")
            time.sleep(0.3)
            order.append("purge:end")
            return _empty_counts()

    spool = SlowSpool(root=home / "spool")
    results: list = []

    first = threading.Thread(target=lambda: results.append(spool_mod.ensure_started(spool)))
    first.start()
    while "purge:start" not in order:
        time.sleep(0.01)

    results.append(spool_mod.ensure_started(spool))
    order.append("second-caller-returned")
    first.join(timeout=5)

    assert order == ["purge:start", "purge:end", "second-caller-returned"]
    assert sorted(results) == [False, True], "exactly one caller ran the purge"


def test_sweeping_a_root_that_does_not_exist_is_not_an_error(spool_mod, home: Path) -> None:
    """The janitor ticks whether or not anything was ever claimed, and it must
    not create the root as a side effect of looking."""
    spool = spool_mod.Spool(root=home / "never-used")

    assert spool.sweep() == {**_empty_counts(), "skipped": 1}
    assert not (home / "never-used").exists()


def test_sweeping_a_root_whose_ancestors_do_not_exist_is_silent(
    spool_mod, spool, home: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The common case on every gateway start: nothing has ever been claimed, so
    ``$HERMES_HOME/state`` does not exist yet either.

    A missing *ancestor* used to reach the operator as an ERROR ending "file
    claims refuse for the same reason", which is false — the claim path creates
    the chain under the Hermes home and publishes normally. A directory that is
    simply not there is the same nothing as a root that is not there, and the
    sweep already treats that as silence.
    """
    assert not (home / "state").exists(), "the fixture is supposed to start bare"

    with caplog.at_level(logging.DEBUG):
        counts = spool.cleanup_at_startup()

    assert counts == {**_empty_counts(), "skipped": 1}
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
    assert not (home / "state").exists(), "looking created it"

    # And the sentence that used to be logged really was false.
    spool.ensure_root()
    assert spool.root.is_dir()


def test_sweeping_an_unsafe_root_refuses_rather_than_deleting(
    spool_mod, home: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A sweep is a recursive delete. Pointed at a root this process cannot
    vouch for, the only safe move is to do nothing at all — and to say so, which
    is the case the silence above must not have swallowed: here the root exists,
    the refusal is real, and claims do refuse for the same reason."""
    root = home / "spool"
    root.mkdir(mode=0o755)
    (root / "somebody-elses-file").write_bytes(b"important")
    spool = spool_mod.Spool(root=root)

    with caplog.at_level(logging.ERROR):
        swept = spool.sweep()

    assert swept["errors"] == 1 and not swept["skipped"]
    assert (root / "somebody-elses-file").read_bytes() == b"important"
    assert [r for r in caplog.records if r.levelno >= logging.ERROR], "a real refusal is loud"


def test_a_startup_purge_with_no_root_to_walk_does_not_spend_the_latch(
    spool_mod, spool, home: Path
) -> None:
    """The purge runs once per process, so it matters *which* once.

    Spending the latch on a call that walked nothing left a root created a moment
    later — by another gateway, by an operator restoring a backup — with only the
    janitor's TTL sweep behind it. Nothing was purged, so nothing was spent.
    """
    assert spool_mod.ensure_started(spool) is False, "there was nothing to purge"

    # Now the root appears, with a previous process's leftovers in it.
    _root_from_another_process(spool_mod, spool.root)
    left_behind = spool.root / _claim_name("a")
    left_behind.mkdir(mode=0o700)
    (left_behind / "0000").write_bytes(b"published before the restart")
    held = spool.root / (spool.QUARANTINE_PREFIX + _claim_name("b"))
    held.mkdir(mode=0o700)

    assert spool_mod.ensure_started(spool) is True, "the deferred purge never ran"
    assert _entries(spool) == []


@pytest.mark.asyncio
async def test_a_deferred_startup_purge_may_not_delete_this_process_own_claim(
    spool_mod, spool, home: Path
) -> None:
    """The bound on deferring it, and the reason the latch cannot simply be left
    open. A purge ignores TTLs; once this process has staged into the root, the
    entries under it are no longer "what a previous process left" and deleting
    them would be taking back files a caller was handed. Staging is what spends
    the latch when the startup walk found nothing to spend it on.
    """
    assert spool_mod.ensure_started(spool) is False

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"this process's own claim")
        published = await claim.publish("drop-1")

    assert spool_mod.ensure_started(spool) is False, "a purge past this point is not a startup"
    assert Path(published["files"][0]["path"]).read_bytes() == b"this process's own claim"


def test_a_sweep_reads_its_configuration_once(
    spool_mod, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``root`` and ``ttl_seconds`` used to be read per swept entry, each a
    potential ``config.yaml`` load inside the loop — and a root that changed
    mid-sweep would mean deciding one entry's fate against another's spool."""
    spool = spool_mod.Spool(root=home / "spool")
    spool.ensure_root()
    for index in range(3):
        stale = spool.root / (spool.STAGING_PREFIX + f"{index:032x}")
        stale.mkdir(mode=0o700)
        os.utime(stale, (0, 0))

    reads = {"ttl": 0}
    real_ttl = spool_mod.config_mod.spool_ttl_seconds

    def counting_ttl():
        reads["ttl"] += 1
        return real_ttl()

    monkeypatch.setattr(spool_mod.config_mod, "spool_ttl_seconds", counting_ttl)
    spool.sweep()

    assert reads["ttl"] <= 1, f"configuration was read {reads['ttl']} times in one sweep"


@pytest.mark.asyncio
async def test_a_claim_resolves_its_root_once_however_the_environment_moves(
    spool_mod, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One claim, one root — the claim-side half of the sweep's snapshot.

    ``config.spool_root()`` is per-call and deliberately unlatched, and
    ``HERMES_DROP_SPOOL_ROOT`` is a plain environment variable, so two reads
    inside one ``_create`` could disagree. They did: the purge exemption was
    registered against the *first* value and the directory created under the
    *second*, which put a live claim back in front of the concurrent purge that
    ``_ACTIVE_STAGING`` exists to keep it out of — and the published paths would
    have been built from the stale root as well.
    """
    first = home / "state" / "hermes-drop" / "spool-a"
    second = home / "state" / "hermes-drop" / "spool-b"
    pending = [str(first)]

    def a_root_that_moves_under_the_claim() -> str:
        # Reads after the first see somewhere else, which is what an environment
        # mutated mid-claim looks like from in here.
        value = pending[0]
        pending[0] = str(second)
        return value

    monkeypatch.setattr(spool_mod.config_mod, "spool_root", a_root_that_moves_under_the_claim)
    spool = spool_mod.Spool()  # configuration-driven, as production builds it

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"one claim, one root")

        registered = {
            root for root, name in spool_mod._ACTIVE_STAGING if name == claim.staging_name
        }
        assert registered == {str(first)}
        assert (first / claim.staging_name).is_dir(), "the claim was created under another root"
        assert not second.exists(), "a second resolution created a second spool"

        # The exemption has to cover the root the bytes are actually in.
        purged = spool_mod.Spool(root=first).sweep(purge_all=True)
        assert purged["staging"] == 0, "a concurrent purge removed a live claim"
        assert (first / claim.staging_name).is_dir()

        published = await claim.publish("drop-1")

    path = Path(published["files"][0]["path"])
    assert path.parent.parent == first
    assert path.read_bytes() == b"one claim, one root"
    assert not second.exists()


@pytest.mark.asyncio
async def test_the_janitor_sweeps_on_a_period_without_anybody_asking(
    spool_mod, home: Path
) -> None:
    """The half that a gateway which never restarts depends on."""
    now = [1_000_000.0]
    spool = spool_mod.Spool(root=home / "spool", ttl_seconds=60, clock=lambda: now[0])

    async with spool.stage() as claim:
        await _write_one(claim, 0, "a.bin", b"payload")
        published = await claim.publish("drop-1")

    spool_mod.ensure_janitor(spool, interval=0.01)
    now[0] += 61
    path = Path(published["files"][0]["path"])
    for _ in range(200):
        await asyncio.sleep(0.01)
        if not path.exists():
            break

    assert not path.exists(), "the janitor never swept"


@pytest.mark.asyncio
async def test_the_janitor_is_one_per_process_and_survives_a_failing_sweep(
    spool_mod, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool = spool_mod.Spool(root=home / "spool")
    calls = []

    def exploding_sweep(**kwargs):
        calls.append(1)
        raise RuntimeError("the filesystem went away")

    monkeypatch.setattr(spool, "sweep", exploding_sweep)

    first = spool_mod.ensure_janitor(spool, interval=0.01)
    second = spool_mod.ensure_janitor(spool, interval=0.01)
    assert first is second, "two janitors would double every delete"

    for _ in range(200):
        await asyncio.sleep(0.01)
        if len(calls) >= 3:
            break

    assert len(calls) >= 3, "a raising sweep killed the janitor"
    assert first.done() is False
