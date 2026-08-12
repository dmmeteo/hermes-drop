"""The private spool: where a claimed file becomes a path, and nothing sooner.

This is the boundary slice 3 deliberately stopped short of. ``file_claim.py``
streams bytes to a callback and keeps nothing; this module is the callback's other
end — it creates the directory, generates the storage names, writes the bytes,
verifies them, and publishes the result with one rename. The bytes never enter the
model's context, the journal or ``state.db``: what crosses the service boundary is
a path, a label, a size and a digest.

**A label is never a path.** The submitted filename is display text and nothing
else. Storage names are 128 bits of ``secrets.token_hex``, so duplicate labels,
traversal, drive prefixes, control characters and 255-byte names are all
non-problems by construction rather than by escaping. The label is re-sanitized
here anyway, with the container decoder's own rules (``src/file-container.js``):
that decoder already refuses a non-canonical name, but a guarantee inherited from
a peer is not a guarantee, and the label is what reaches a model.
``tests/test_spool_differential.py`` runs both implementations over one corpus, so
"the same rules" is checked rather than claimed.

**Nothing partial is ever reachable.** Files are written into ``.staging-<id>``
and the *directory* is renamed to ``<id>``. A consumer therefore sees either no
claim or a complete, verified one — there is no window in which a published path
holds an unfinished file, and the dot prefix means even a directory listing
cannot mistake one for the other. **The rename is the commit point**: past it the
claim is the caller's, and no later failure (including the durability ``fsync``)
may report it as lost or take it away again.

**Verified before the ack, published after the commit.** Two different checks,
and both matter:

* Each file is fsynced and then *re-read through its own descriptor* and hashed
  again before its frame may be acked. A digest over bytes that arrived on a
  socket says nothing about bytes that reached a disk, and the ack is what lets
  the broker move on.
* The broker does not send per-file digests (``contract/control-protocol.json`` →
  ``file_claim.digests_are_not_echoed``), so ``commit → ok`` is *the* verification
  verdict and the publish happens strictly after it. A spool that published on
  its own self-check would be asserting something weaker.

**The MVP's limits are enforced here too.** 5 files, 42 MiB per file, 42 MiB per
claim, and at most four staged claims at once — the same 168 MiB of live file
bytes the broker budgets for (``HANDOFF_MAX_LIVE_FILE_BYTES``). The MVP requires
these to be "server-enforced, not trusted from the browser"; this side writes the
bytes to a disk, so it does not trust the broker for them either.

**Deletion is bounded by provenance, not by validation.** ``~/.ssh``, ``~/.gnupg``
and ``$HERMES_HOME/state`` are all user-owned and ``0700``, so a validator that
only asks "is this directory private?" would happily recursively delete any of
them after one typo in ``spool_root``. So a root is swept only if it carries this
plugin's marker (:data:`MARKER_NAME`), only entries whose *names this plugin
generates* are ever removed, and anything else is counted and named in a warning.
An empty private directory is adopted by marking it, because an operator or a
container runtime creating the mount point ahead of time is normal.

**Failures are ``StagingFailed``, not ``OSError``.** Deliberately: the sink runs
inside ``receive_file_claim``, which catches ``OSError`` and reports it as
``broker_unavailable`` — so a full disk would be blamed on the socket, complete
with the socket path in the detail. A non-``OSError`` exception propagates out
past that handler (closing the connection on the way, which returns the lease and
leaves the payload claimable) to the caller that can name it correctly.

**Every operation is descriptor-relative, ancestors included.** The root's
ancestor chain is walked from ``/`` with ``O_NOFOLLOW|O_DIRECTORY``, each
component checked for ownership and for group/other write access, and the root is
opened relative to its parent's descriptor. Missing components are created only
under the Hermes home — one at a time, at ``0700``, because ``os.makedirs(mode=…)``
applies its mode to the leaf alone and leaves intermediates at
``0o777 & ~umask``. Outside the profile nothing is created: that directory belongs
to whoever configured it.

The one limit this cannot cover, stated because it is real: the published
``path`` handed to a caller is a *name*, not a descriptor. Its integrity rests on
the ancestor chain staying private, which is what the ancestor checks are for.

**Blocking work runs off the loop.** Writes, fsyncs, re-reads, renames and sweeps
all go through ``asyncio.to_thread``. Drop's waits run on the gateway loop and a
42 MiB claim is long enough that doing this inline would stall every other
session on it — the same argument ``control_client`` and ``file_claim`` make about
their sockets. The two exceptions are deliberate and documented at their call
sites: cleanup under ``CancelledError`` runs inline, because an ``await`` in a
cancelled task raises before it can finish the rename that saves the bytes.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import hashlib
import json
import logging
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple

from . import config as config_mod

logger = logging.getLogger(__name__)

#: In-progress claims. Dot-prefixed so nothing that lists the root can mistake
#: one for a result, and so the sweeper can tell "filling" from "published"
#: without opening anything.
STAGING_PREFIX = ".staging-"

#: Bytes that were received but whose verdict never arrived
#: (``transfer_indeterminate``, a cancellation past the commit, a publish that
#: could not complete). Never published, never handed to a caller, swept at the
#: TTL like everything else.
QUARANTINE_PREFIX = ".quarantine-"

#: Written last, inside the staging directory, so the rename publishes the files
#: and the record of when they expire in one step. A dotfile: it is bookkeeping,
#: not a payload, and it is not among the paths a caller is given.
METADATA_NAME = ".metadata.json"

#: Provenance. Its presence is what makes a directory *this plugin's spool* rather
#: than merely a private directory, and nothing without it is ever swept.
MARKER_NAME = ".hermes-drop-spool"

#: An advisory ``flock`` held for the life of the process. Holding it means no
#: other gateway is using this root, which is the only condition under which the
#: startup purge may remove *unexpired* claims.
LOCK_NAME = ".hermes-drop-spool.lock"

CLAIM_ID_BYTES = 16
STORAGE_NAME_BYTES = 16

#: A claim-shaped name: exactly the hex a 16-byte token produces. Anything else
#: under the root is somebody else's and is never removed.
_CLAIM_ID_RE = re.compile(r"^[0-9a-f]{%d}$" % (2 * CLAIM_ID_BYTES))

#: ``docs/FILE_TRANSFER_MVP.md`` → MVP limits, restated as this side's own.
MAX_CLAIM_FILES = 5
MAX_CLAIM_FILE_BYTES = 42 * 1024 * 1024
MAX_CLAIM_TOTAL_BYTES = 42 * 1024 * 1024

#: The broker's ``HANDOFF_MAX_LIVE_FILE_BYTES`` (168 MiB, "enough for four fully
#: reserved file drops") mirrored on the disk side: each staging claim reserves its
#: whole 42 MiB for as long as it is open, so a process can hold at most four.
#: The fifth is refused with the drop untouched, which costs a retry rather than a
#: full filesystem.
MAX_LIVE_CLAIM_BYTES = 4 * MAX_CLAIM_TOTAL_BYTES

#: How stale an abandoned staging directory must look before a sweep removes it.
#: Age-gated for the reason the journal's temp sweep is: an orphan from a killed
#: process and a live transfer in *another* process are indistinguishable on
#: disk. Comfortably longer than any lease the broker will grant
#: (``HANDOFF_FILE_CLAIM_LEASE_MS``, and its ceiling is the handoff TTL), and this
#: process's own claims are exempt regardless of age — they are registered before
#: they exist.
STAGING_GRACE_SECONDS = 600

#: The janitor's period. The TTL is what decides when a claim dies; this only
#: decides how promptly.
SWEEP_INTERVAL_SECONDS = 60

#: A name collision is 128-bit-improbable, so a handful of attempts is not a
#: retry loop so much as a refusal that cannot be provoked.
MAX_NAME_ATTEMPTS = 4

#: How deep a removal will recurse. Nothing here creates nested directories, so
#: this exists only so that litter cannot turn a sweep into an unbounded walk.
#: Exhausting it is reported at WARNING: the entry survives, and an operator
#: seeing it only at DEBUG would never know why bytes stayed on disk.
MAX_REMOVE_DEPTH = 3

#: Re-read in pieces, like the transfer itself: a 42 MiB file must not be
#: assembled in memory to be verified.
VERIFY_CHUNK_BYTES = 256 * 1024

#: ``src/file-container.js``'s rules, restated. ``\p{Cc}\p{Cf}`` there; plus
#: ``Cs``, because a lone surrogate reaches a UTF-8 encoder as a ``ValueError``
#: rather than as a character, and one byte of hostile metadata must not be able
#: to wedge a claim.
_CONTROL_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})
_PRINTABLE_ASCII = re.compile(r"^[\x20-\x7e]*$")

#: What JavaScript's ``String.prototype.trim`` removes: WhiteSpace +
#: LineTerminator. Spelled out rather than delegated to ``str.strip()``, which
#: removes the C0 separators U+001C–U+001F that ``trim()`` keeps and keeps the
#: U+FEFF that ``trim()`` removes. For a *type* that difference is visible — the
#: rules say an unusable hint becomes empty rather than being repaired, and
#: ``str.strip()`` would strip the control characters out of a rejected value and
#: display the remainder.
_JS_WHITESPACE = (
    "\t\n\v\f\r\u0020\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)

MAX_LABEL_BYTES = 255
MAX_TYPE_BYTES = 255
FALLBACK_LABEL = "unnamed"

#: Staging directories this process is actively filling, as
#: ``(root, staging_name)``. Process-wide rather than per-``Spool`` because the
#: janitor and a claim are not the same object, and the sweeper has to know the
#: difference between "abandoned" and "42 MiB in".
_ACTIVE_STAGING: Set[Tuple[str, str]] = set()

#: Reserved disk bytes, and the lock that makes the check-and-reserve atomic
#: across the threads ``asyncio.to_thread`` runs staging on.
_RESERVE_LOCK = threading.Lock()
_reserved_bytes = 0

#: Root locks held by this process, keyed by root path. ``flock`` is per open file
#: description, so these are held open for the process's lifetime.
_LOCK_GUARD = threading.Lock()
_ROOT_LOCKS: Dict[str, int] = {}

#: The startup purge's latch. A ``Lock`` and not a flag: the flag was set *before*
#: the purge ran, so a second claim staged into a root that was still being walked
#: — and the writes then continued into an unlinked directory, surfacing only past
#: the commit.
_STARTUP_LOCK = threading.Lock()
_started = False

_janitor: Optional["asyncio.Task[None]"] = None


class SpoolUnsafe(Exception):
    """The spool cannot be used, and nothing was written.

    A root that is missing, relative, ``~``-relative, a symlink, foreign-owned,
    group- or world-accessible, sitting under an unsafe ancestor, or without this
    plugin's provenance marker; a staging name that could not be created
    privately; a platform without descriptor-relative syscalls. Raised *before* a
    transfer begins, so a caller may retry once an operator has fixed it.
    """


class SpoolBusy(SpoolUnsafe):
    """Too many claims are already staged. Nothing is wrong; come back shortly."""


class SpoolAbsent(SpoolUnsafe):
    """The root, or a directory above it, is simply not there.

    A subclass and not a separate exception because to a *claim* this is the same
    refusal as any other unusable root. It is told apart on the sweeping side
    only, where it means something different from every sibling: there is nothing
    to sweep and nothing wrong. A missing root already returns quietly
    (``_open_root`` answers ``None``); a missing ancestor is the same nothing one
    level up, and reporting it as a misconfiguration sends an operator looking
    for a problem the claim path fixes by itself.
    """


class StagingFailed(Exception):
    """Bytes could not be staged, or could not be proved to have landed.

    Not an ``OSError`` on purpose — see this module's docstring. Never carries a
    filename, a label or the file's contents: it is logged, and its message must
    be safe in ``agent.log``.
    """


class _TooDeep(Exception):
    """Removal hit :data:`MAX_REMOVE_DEPTH`. Internal to the sweeper."""


def _token(nbytes: int) -> str:
    """Random, opaque, and the only source of names on disk."""
    return secrets.token_hex(nbytes)


def _write_all(fd: int, data: bytes) -> None:
    """``os.write`` until the buffer is gone. A short write is not an error."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:  # pragma: no cover - a kernel that violates write(2)
            raise OSError(errno.EIO, "short write")
        view = view[written:]


def _mkdir_at(dir_fd: int, name: str, mode: int) -> None:
    """Named so the "registered before it exists" ordering can be observed."""
    os.mkdir(name, mode, dir_fd=dir_fd)


def _reserve_claim_bytes() -> None:
    global _reserved_bytes
    with _RESERVE_LOCK:
        if _reserved_bytes + MAX_CLAIM_TOTAL_BYTES > MAX_LIVE_CLAIM_BYTES:
            raise SpoolBusy(
                f"{_reserved_bytes // (1024 * 1024)} MiB of file claims are already staged; "
                f"at most {MAX_LIVE_CLAIM_BYTES // (1024 * 1024)} MiB may be in flight"
            )
        _reserved_bytes += MAX_CLAIM_TOTAL_BYTES


def _release_claim_bytes() -> None:
    global _reserved_bytes
    with _RESERVE_LOCK:
        _reserved_bytes = max(0, _reserved_bytes - MAX_CLAIM_TOTAL_BYTES)


def reserved_claim_bytes() -> int:
    with _RESERVE_LOCK:
        return _reserved_bytes


def _truncate_bytes(value: str, limit: int) -> str:
    encoded = value.encode("utf-8", errors="ignore")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", errors="ignore")


def _collapse_to_basename(value: str) -> str:
    """Trim, drop everything up to the last separator, drop a drive prefix —
    until the string stops changing. A single pass would leave ``a/ b`` and
    ``C:x/C:y`` half-handled; the fixed point is what the decoder promises."""
    previous = None
    while value != previous:
        previous = value
        value = value.strip()
        separator = max(value.rfind("/"), value.rfind("\\"))
        if separator >= 0:
            value = value[separator + 1 :]
        value = re.sub(r"^[A-Za-z]:", "", value)
    return value


def sanitize_label(raw: Any) -> str:
    """A submitted filename as display text. Never joined onto a directory.

    ``src/file-container.js``'s ``sanitizeFileName``, restated in Python:
    invisibles out first (a format character sitting between a base letter and its
    combining mark blocks composition), NFC, basename only, capped at 255 UTF-8
    bytes, and ``unnamed`` when nothing usable is left. Lone surrogates go out
    with the invisibles — they are not characters a display can use, and they
    raise on the way to UTF-8.
    """
    if not isinstance(raw, str):
        return FALLBACK_LABEL
    stripped = "".join(ch for ch in raw if unicodedata.category(ch) not in _CONTROL_CATEGORIES)
    value = unicodedata.normalize("NFC", stripped)
    value = _collapse_to_basename(value)
    # Safe to truncate last: the string holds no separators by now, so a cut
    # cannot uncover one.
    value = _truncate_bytes(value, MAX_LABEL_BYTES).rstrip()
    if value in ("", ".", ".."):
        return FALLBACK_LABEL
    return value


def sanitize_type(raw: Any) -> str:
    """An untrusted MIME hint. Anything unusable becomes empty, never repaired —
    nothing sniffs, dispatches or executes on it.

    The trim is JavaScript's, not Python's (see :data:`_JS_WHITESPACE`), and it
    happens before the printability test exactly as it does in the browser, so the
    two implementations answer identically on every input.
    """
    if not isinstance(raw, str):
        return ""
    value = raw.strip(_JS_WHITESPACE)
    if not _PRINTABLE_ASCII.match(value):
        return ""
    if len(value.encode("utf-8")) > MAX_TYPE_BYTES:
        return ""
    return value


class _FileState:
    """One file, mid-arrival."""

    __slots__ = ("index", "fd", "storage", "label", "type_hint", "expected", "written", "digest")

    def __init__(self, index: int, fd: int, storage: str, label: str, type_hint: str, expected: int):
        self.index = index
        self.fd = fd
        self.storage = storage
        self.label = label
        self.type_hint = type_hint
        self.expected = expected
        self.written = 0
        self.digest = hashlib.sha256()


class StagingClaim:
    """One claim's private directory, from ``mkdir`` to ``rename``.

    Used as an async context manager. Leaving the block without a publish or a
    quarantine discards everything — including under ``CancelledError``, where the
    cleanup runs *inline*, because an ``await`` in a cancelled task raises before
    it can do anything.
    """

    def __init__(self, spool: "Spool") -> None:
        self._spool = spool
        self._root: Optional[Path] = None
        self._root_fd: Optional[int] = None
        self._staging_fd: Optional[int] = None
        self.claim_id = ""
        self.staging_name = ""
        self._open: Dict[int, _FileState] = {}
        self._done: Dict[int, Dict[str, Any]] = {}
        self._arrival: List[int] = []
        self._advertised = 0
        self._written = 0
        self._published = False
        self._quarantined = False
        self._reserved = False
        self._registered = False

    # -- lifecycle ----------------------------------------------------------

    async def __aenter__(self) -> "StagingClaim":
        await asyncio.to_thread(self._create)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        if self._published or self._quarantined:
            return False
        if exc_type is not None and not issubclass(exc_type, Exception):
            # ``CancelledError`` / ``KeyboardInterrupt``: every ``await`` from here
            # raises immediately, so the cleanup has to happen on this thread or
            # not at all — and "not at all" means a staging directory left for the
            # grace period.
            self._discard()
        else:
            await self.discard()
        return False

    @property
    def published(self) -> bool:
        return self._published

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    def _create(self) -> None:
        spool = self._spool
        _reserve_claim_bytes()
        self._reserved = True
        root_fd: Optional[int] = None
        try:
            # Resolved once, and every later step in this claim is handed *this*
            # value: the registration below, the directory, and the paths
            # ``_publish`` hands out. ``spool.root`` re-reads its configuration on
            # every access, so a second read here could register the exemption
            # against one root and create the claim under another — which puts a
            # live claim back in front of the concurrent purge the registration
            # exists to keep it out of.
            root = spool.root
            root_fd = spool._open_root(create=True, root=root)
            assert root_fd is not None
            # This process is now writing into the spool. Whatever the startup
            # purge did or did not manage, it is over: from here the entries under
            # this root may be ours, and a purge that ignores TTLs would be
            # deleting live work rather than a previous process's leftovers.
            _spend_startup_latch()
            claim_id = ""
            staging = ""
            for _ in range(MAX_NAME_ATTEMPTS):
                claim_id = _token(CLAIM_ID_BYTES)
                staging = STAGING_PREFIX + claim_id
                if _lexists_at(root_fd, claim_id) or _lexists_at(root_fd, staging):
                    # The published name is claimed at the same time as the staging
                    # one: discovering that collision at publish time would mean
                    # discovering it after the payload was retired.
                    continue
                # Registered *before* the directory exists. The registration is what
                # exempts a live claim from a concurrent purge, and a window between
                # the two is a window in which the purge wins.
                _ACTIVE_STAGING.add((str(root), staging))
                self._root = root
                self.staging_name = staging
                self._registered = True
                try:
                    _mkdir_at(root_fd, staging, 0o700)
                except FileExistsError:
                    self._unregister()
                    continue
                except OSError as exc:
                    raise SpoolUnsafe(
                        f"could not create a staging directory: errno {exc.errno}"
                    ) from exc
                break
            else:
                raise SpoolUnsafe("could not create a private staging directory")

            try:
                staging_fd = os.open(
                    staging,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=root_fd,
                )
            except OSError as exc:
                _remove_entry_quietly(root_fd, staging)
                raise SpoolUnsafe(
                    f"could not open the staging directory: errno {exc.errno}"
                ) from exc
            try:
                # mkdir's mode is masked by umask; the descriptor's is not.
                os.fchmod(staging_fd, 0o700)
            except OSError as exc:
                os.close(staging_fd)
                _remove_entry_quietly(root_fd, staging)
                raise SpoolUnsafe(
                    f"could not make the staging directory private: errno {exc.errno}"
                ) from exc

            self._root_fd = root_fd
            self._staging_fd = staging_fd
            self.claim_id = claim_id
        except BaseException:
            if root_fd is not None and self._root_fd is None:
                os.close(root_fd)
            self._unregister()
            self._release_reservation()
            raise

    # -- the chunk sink -----------------------------------------------------

    async def accept(self, index: int, entry: Mapping[str, Any], chunk: bytes, done: bool) -> None:
        """One call per chunk, exactly as :data:`file_claim.ChunkSink` describes.

        A zero-byte file arrives as a single ``b""`` with ``done=True``, and it
        gets a file like any other — a five-file claim that published four
        because one of them was empty would be a silent loss.
        """
        await asyncio.to_thread(self._accept, int(index), entry, chunk, bool(done))

    def _accept(self, index: int, entry: Mapping[str, Any], chunk: bytes, done: bool) -> None:
        try:
            state = self._open.get(index)
            if state is None:
                if index in self._done:
                    raise StagingFailed(f"file {index} was already completed")
                state = self._open_file(index, entry)
            if state.written + len(chunk) > state.expected:
                # Cannot happen against the real broker — the receiver checks the
                # framed length against the manifest first. Refused here so the
                # spool's accounting is its own, not a restatement of a peer's.
                raise StagingFailed(
                    f"file {index} sent more bytes than the {state.expected} advertised"
                )
            if self._written + len(chunk) > MAX_CLAIM_TOTAL_BYTES:
                raise StagingFailed(
                    f"the claim exceeded its total of {MAX_CLAIM_TOTAL_BYTES} bytes"
                )
            if chunk:
                _write_all(state.fd, chunk)
                state.written += len(chunk)
                self._written += len(chunk)
                state.digest.update(chunk)
            if done:
                self._finish(state)
        except StagingFailed:
            raise
        except OSError as exc:
            # Wrapped, always: an OSError escaping here would be swallowed by
            # ``receive_file_claim``'s handler and reported as an unreachable
            # broker (see the module docstring).
            raise StagingFailed(f"could not stage file {index}: errno {exc.errno}") from exc

    def _open_file(self, index: int, entry: Mapping[str, Any]) -> _FileState:
        expected = entry.get("size") if isinstance(entry, Mapping) else None
        if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
            raise StagingFailed(f"file {index} arrived without a usable size")
        if len(self._open) + len(self._done) >= MAX_CLAIM_FILES:
            raise StagingFailed(f"a claim may hold at most {MAX_CLAIM_FILES} files")
        if expected > MAX_CLAIM_FILE_BYTES:
            raise StagingFailed(
                f"file {index} advertises {expected} bytes, over the {MAX_CLAIM_FILE_BYTES} cap"
            )
        if self._advertised + expected > MAX_CLAIM_TOTAL_BYTES:
            raise StagingFailed(
                f"the advertised total would exceed {MAX_CLAIM_TOTAL_BYTES} bytes"
            )
        assert self._staging_fd is not None
        for _ in range(MAX_NAME_ATTEMPTS):
            storage = _token(STORAGE_NAME_BYTES)
            try:
                fd = os.open(
                    storage,
                    # O_RDWR rather than O_WRONLY: the descriptor is what the
                    # post-write verification re-reads through, and re-opening the
                    # path to read it would hand a swapped name a second chance.
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=self._staging_fd,
                )
            except FileExistsError:
                # Either an astonishing collision or a squatted name — including a
                # symlink, which O_EXCL refuses rather than following. Never
                # reused, always renamed around.
                continue
            os.fchmod(fd, 0o600)
            state = _FileState(
                index,
                fd,
                storage,
                sanitize_label(entry.get("name")),
                sanitize_type(entry.get("type")),
                expected,
            )
            self._open[index] = state
            self._arrival.append(index)
            self._advertised += expected
            return state
        raise StagingFailed(f"could not create a private file for {index}")

    def _finish(self, state: _FileState) -> None:
        if state.written != state.expected:
            raise StagingFailed(
                f"file {state.index} ended at {state.written} of {state.expected} bytes"
            )
        os.fsync(state.fd)
        info = os.fstat(state.fd)
        if not stat.S_ISREG(info.st_mode):  # pragma: no cover - O_EXCL made it
            raise StagingFailed(f"file {state.index} is not a regular file")
        if info.st_nlink != 1:
            raise StagingFailed(f"file {state.index} has {info.st_nlink} links")
        if info.st_size != state.expected:
            raise StagingFailed(
                f"file {state.index} is {info.st_size} bytes on disk, not {state.expected}"
            )
        if stat.S_IMODE(info.st_mode) != 0o600:  # pragma: no cover - fchmod set it
            raise StagingFailed(f"file {state.index} is not private on disk")

        # The check that cannot be skipped: hash what is *on the disk*, through
        # the descriptor we own, not the path. The streaming digest proves what
        # arrived; this proves what landed, and only this may precede an ack.
        on_disk = hashlib.sha256()
        os.lseek(state.fd, 0, os.SEEK_SET)
        while True:
            piece = os.read(state.fd, VERIFY_CHUNK_BYTES)
            if not piece:
                break
            on_disk.update(piece)
        if on_disk.hexdigest() != state.digest.hexdigest():
            raise StagingFailed(f"file {state.index} does not match what was written")

        os.close(state.fd)
        del self._open[state.index]
        self._done[state.index] = {
            "index": state.index,
            "storage": state.storage,
            "name": state.label,
            "type": state.type_hint,
            "size": state.expected,
            "sha256": state.digest.hexdigest(),
        }

    def entries(self) -> List[Dict[str, Any]]:
        """Every *completed* file, in manifest order. An unfinished one is absent
        rather than represented, so a caller comparing this against what the
        receiver committed catches the gap."""
        return [dict(self._done[index]) for index in sorted(self._done)]

    def arrival_order(self) -> List[int]:
        """The indices in the order the sink first saw them.

        The broker names the next index in its ack answer, so arrival order need
        not be manifest order. A cross-check that zipped the receiver's list
        against manifest order positionally would fail a *perfect* transfer, after
        the commit — which is total loss rather than a retry.
        """
        return list(self._arrival)

    # -- publish, quarantine, discard ---------------------------------------

    async def publish(self, drop_id: str) -> Dict[str, Any]:
        """One rename. Call it only after the broker's ``commit → ok``."""
        return await asyncio.to_thread(self._publish, str(drop_id))

    def _publish(self, drop_id: str) -> Dict[str, Any]:
        if self._published:  # pragma: no cover - defensive
            raise StagingFailed("this claim was already published")
        entries = self.entries()
        if not entries:
            raise StagingFailed("nothing was staged")
        if self._open:
            raise StagingFailed(f"{len(self._open)} file(s) never completed")
        if sorted(self._done) != list(range(len(entries))):
            raise StagingFailed("the staged files are not a contiguous manifest")

        assert self._root is not None and self._root_fd is not None and self._staging_fd is not None
        expires_at = int(self._spool.now()) + self._spool.ttl_seconds
        record = {
            "claim_id": self.claim_id,
            "drop_id": drop_id,
            "expires_at": expires_at,
            "files": [
                {key: entry[key] for key in ("storage", "name", "type", "size", "sha256")}
                for entry in entries
            ],
        }
        try:
            self._write_metadata(record)
            # The directory's own entries have to be durable before the rename
            # that makes them reachable.
            os.fsync(self._staging_fd)
            os.rename(
                self.staging_name,
                self.claim_id,
                src_dir_fd=self._root_fd,
                dst_dir_fd=self._root_fd,
            )
        except OSError as exc:
            raise StagingFailed(f"could not publish the claim: errno {exc.errno}") from exc

        # The rename **is** the commit point. Everything from here is best-effort:
        # the claim exists, is complete and is the caller's, so no later failure
        # may report it as lost or take it away again.
        self._published = True
        try:
            os.fsync(self._root_fd)
        except OSError as exc:
            logger.warning(
                "hermes-drop: published a file claim for drop %s but could not confirm the "
                "durability of the directory entry (errno %s). The files are on disk and "
                "readable; a power loss in the next moment could lose the name.",
                drop_id,
                exc.errno,
            )

        directory = self._root / self.claim_id
        published = {
            "claim_id": self.claim_id,
            "expires_at": expires_at,
            "files": [
                {
                    "path": str(directory / entry["storage"]),
                    "name": entry["name"],
                    "type": entry["type"],
                    "size": entry["size"],
                    "sha256": entry["sha256"],
                }
                for entry in entries
            ],
        }
        self._release()
        return published

    def _write_metadata(self, record: Mapping[str, Any]) -> None:
        assert self._staging_fd is not None
        blob = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fd = os.open(
            METADATA_NAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=self._staging_fd,
        )
        try:
            os.fchmod(fd, 0o600)
            _write_all(fd, blob.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    async def quarantine(self) -> str:
        """Move the bytes out of reach without publishing them.

        For ``transfer_indeterminate``: the verdict never arrived, so nothing may
        be published — but the bytes may be the only copy left, so they are kept
        for the TTL rather than deleted on the spot (contract,
        ``file_claim.client_verdicts``). Nothing hands the caller this path.

        ``""`` when there is nothing to hold, which includes a claim that was
        already published: past the rename the bytes are the caller's.
        """
        return await asyncio.to_thread(self._quarantine)

    def quarantine_now(self) -> str:
        """:meth:`quarantine` without an ``await``, for cancellation paths.

        ``asyncio.shield`` is not sufficient on its own here: the shielded await
        still raises ``CancelledError`` in a cancelled task, so the rename could be
        left half-scheduled. One rename and one ``fsync`` on the calling thread is
        a few microseconds and is *guaranteed* to finish before the cancellation
        propagates, which is what the bytes need.
        """
        return self._quarantine()

    def _quarantine(self) -> str:
        if self._published or self._quarantined or self._root_fd is None:
            return ""
        name = QUARANTINE_PREFIX + self.claim_id
        self._close_open_files()
        try:
            os.rename(self.staging_name, name, src_dir_fd=self._root_fd, dst_dir_fd=self._root_fd)
        except OSError as exc:
            raise StagingFailed(f"could not quarantine the claim: errno {exc.errno}") from exc
        self._quarantined = True
        try:
            os.fsync(self._root_fd)
        except OSError:  # pragma: no cover - durability only; the rename happened
            logger.debug("hermes-drop: could not fsync after a quarantine", exc_info=True)
        self._release()
        return name

    async def discard(self) -> None:
        await asyncio.to_thread(self._discard)

    def _discard(self) -> None:
        if self._published:
            # Past the rename there is nothing of ours to remove, and removing the
            # published claim would be taking back what a caller was handed.
            return
        self._close_open_files()
        if self._root_fd is not None and self.staging_name:
            _remove_entry_quietly(self._root_fd, self.staging_name)
        self._release()

    def _close_open_files(self) -> None:
        for state in list(self._open.values()):
            try:
                os.close(state.fd)
            except OSError:  # pragma: no cover - already closed
                pass
        self._open.clear()

    def _unregister(self) -> None:
        if self._registered and self._root is not None and self.staging_name:
            _ACTIVE_STAGING.discard((str(self._root), self.staging_name))
        self._registered = False

    def _release_reservation(self) -> None:
        if self._reserved:
            _release_claim_bytes()
            self._reserved = False

    def _release(self) -> None:
        self._unregister()
        self._release_reservation()
        for attr in ("_staging_fd", "_root_fd"):
            fd = getattr(self, attr)
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:  # pragma: no cover - already closed
                    pass
                setattr(self, attr, None)


class Spool:
    """A validated, marked private root, and the operations inside it."""

    SpoolUnsafe = SpoolUnsafe
    SpoolBusy = SpoolBusy
    StagingFailed = StagingFailed
    STAGING_PREFIX = STAGING_PREFIX
    QUARANTINE_PREFIX = QUARANTINE_PREFIX
    METADATA_NAME = METADATA_NAME
    MARKER_NAME = MARKER_NAME
    LOCK_NAME = LOCK_NAME
    CLAIM_ID_BYTES = CLAIM_ID_BYTES
    STORAGE_NAME_BYTES = STORAGE_NAME_BYTES
    STAGING_GRACE_SECONDS = STAGING_GRACE_SECONDS

    def __init__(
        self,
        root: Any = None,
        *,
        ttl_seconds: Optional[int] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._configured_root = root
        self._ttl_override = ttl_seconds
        self._clock = clock

    def now(self) -> float:
        return self._clock()

    @property
    def ttl_seconds(self) -> int:
        if self._ttl_override is not None:
            return int(self._ttl_override)
        return config_mod.spool_ttl_seconds()

    @property
    def root(self) -> Path:
        """The configured root, absolute, unresolved and uncreated.

        Raises :class:`SpoolUnsafe` for the three answers that are not a usable
        path: nothing configured; something relative, which would resolve against
        whatever directory the gateway happens to have been started in; and
        anything ``~``-relative, because ``~`` is ``$HOME`` and this package's
        profile rule is ``get_hermes_home()`` — a ``~/spool`` root would be shared
        by every profile on the host.
        """
        raw = self._configured_root
        if raw is None:
            raw = config_mod.spool_root()
        text = str(raw or "").strip()
        if not text:
            raise SpoolUnsafe("no spool root is configured")
        if text.startswith("~"):
            raise SpoolUnsafe(
                "the spool root must not start with ~: it would resolve against $HOME "
                "rather than the Hermes profile. Configure an absolute path."
            )
        path = Path(text)
        if not path.is_absolute():
            raise SpoolUnsafe("the spool root must be an absolute path")
        if path.parent == path:
            raise SpoolUnsafe("the spool root must not be the filesystem root")
        return path

    def ensure_root(self) -> Path:
        """Create the root if it is missing, validate and mark it either way."""
        root = self.root
        fd = self._open_root(create=True, root=root)
        if fd is not None:
            os.close(fd)
        return root

    # -- the root, its ancestors and its provenance -------------------------

    @staticmethod
    def _require_posix() -> None:
        # Membership is tested by *name* rather than by identity: a test (or a
        # profiler, or a tracing hook) that wraps ``os.rename`` must not read as a
        # platform without ``renameat`` — the capability belongs to the platform,
        # not to the object currently bound to the name.
        capable = {getattr(fn, "__name__", "") for fn in os.supports_dir_fd}
        missing = []
        if not {"open", "rename"} <= capable:
            missing.append("dir_fd")
        if not hasattr(os, "geteuid"):
            missing.append("geteuid")
        if missing:
            raise SpoolUnsafe(
                "this platform does not support the descriptor-relative syscalls the "
                f"spool's safety rests on ({', '.join(missing)}); file claims are refused "
                "rather than run without them"
            )

    @staticmethod
    def _trusted_base() -> Optional[Path]:
        """The Hermes home: the one place this plugin may create directories.

        Anywhere else, a missing component is somebody's deliberate choice not to
        have created it yet — an operator's, systemd's, a container runtime's —
        and the mode it should carry is theirs to pick.
        """
        try:
            from hermes_constants import get_hermes_home

            return Path(get_hermes_home())
        except Exception:  # pragma: no cover - a non-Hermes interpreter
            return None

    def _open_parent(self, root: Path, *, create: bool) -> int:
        """A descriptor for ``root.parent``, reached one validated component at a time.

        ``O_NOFOLLOW`` on every component, so a swapped symlink anywhere in the
        chain is a refusal rather than a redirect; ownership and group/other write
        access checked on each, because a writable ancestor lets a local attacker
        move the directory the published paths point into. World-writable *sticky*
        directories (``/tmp``) are allowed: the sticky bit is what stops a
        non-owner renaming our entry out of them.
        """
        trusted = self._trusted_base() if create else None
        fd = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        walked = Path(os.sep)
        try:
            for part in root.parts[1:-1]:
                walked = walked / part
                created = False
                try:
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=fd,
                    )
                except FileNotFoundError:
                    if not (create and trusted is not None and trusted in walked.parents):
                        raise SpoolAbsent(
                            f"{walked} does not exist. Create it (mode 0700) before "
                            "configuring a spool root inside it."
                        )
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                    except FileExistsError:  # pragma: no cover - lost a benign race
                        pass
                    except OSError as exc:
                        raise SpoolUnsafe(
                            f"could not create {walked}: errno {exc.errno}"
                        ) from exc
                    created = True
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=fd,
                    )
                except OSError as exc:
                    raise SpoolUnsafe(
                        f"{walked} is not a usable directory: errno {exc.errno}"
                    ) from exc

                try:
                    if created:
                        # ``os.makedirs(mode=…)`` applies its mode to the leaf only;
                        # this is why the chain is walked rather than delegated.
                        os.fchmod(child, 0o700)
                    self._check_ancestor(child, walked)
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _check_ancestor(fd: int, path: Path) -> None:
        info = os.fstat(fd)
        if info.st_uid not in (os.geteuid(), 0):
            raise SpoolUnsafe(f"{path} is owned by another user")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 and not mode & stat.S_ISVTX:
            raise SpoolUnsafe(
                f"{path} is writable by other users (mode {mode:04o}); a spool root "
                "underneath it could be moved out from under the paths this plugin hands out"
            )

    def _open_root(self, *, create: bool, root: Optional[Path] = None) -> Optional[int]:
        """A validated, marked descriptor for the root, or ``None`` when absent.

        Absent is only ``None`` for ``create=False`` — a sweep of a spool nobody
        has used yet must not be what brings it into existence.

        *root* is the caller's already-resolved root. :attr:`root` is per-call by
        design (it follows a profile switch, and the environment variable behind
        it is not latched), so a caller that has *acted* on one value — registered
        a purge exemption against it, or is about to build published paths from it
        — has to hand that same value down rather than let a second read disagree
        with the first.

        The checks, in order, and each one is load-bearing:

        * the ancestor chain (:meth:`_open_parent`);
        * ``O_NOFOLLOW|O_DIRECTORY`` — a symlinked or non-directory root refuses
          rather than redirecting every write that follows;
        * the effective uid must own it;
        * no group or other bits — 0700 or refuse. A root **this call creates** is
          chmodded (``mkdir``'s mode is masked by umask); one that already existed
          is never modified, because an operator who pointed the spool at ``/tmp``
          must get a refusal rather than a plugin that chmods ``/tmp``;
        * provenance (:meth:`_check_marker`) — private is not the same as ours.
        """
        self._require_posix()
        if root is None:
            root = self.root
        parent_fd = self._open_parent(root, create=create)
        created = False
        try:
            if create and not _lexists_at(parent_fd, root.name):
                try:
                    os.mkdir(root.name, 0o700, dir_fd=parent_fd)
                    created = True
                except FileExistsError:  # pragma: no cover - lost a benign race
                    created = False
                except OSError as exc:
                    raise SpoolUnsafe(
                        f"could not create the spool root: errno {exc.errno}"
                    ) from exc
            try:
                fd = os.open(
                    root.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                if create:  # pragma: no cover - we just created it
                    raise SpoolUnsafe("the spool root disappeared while it was being created")
                return None
            except OSError as exc:
                raise SpoolUnsafe(
                    f"the spool root is not a usable private directory: errno {exc.errno}"
                ) from exc
        finally:
            os.close(parent_fd)

        try:
            if created:
                os.fchmod(fd, 0o700)
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):  # pragma: no cover - O_DIRECTORY did it
                raise SpoolUnsafe("the spool root is not a directory")
            if info.st_uid != os.geteuid():
                raise SpoolUnsafe("the spool root is owned by another user")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise SpoolUnsafe(
                    f"the spool root is not private (mode {stat.S_IMODE(info.st_mode):04o})"
                )
            self._check_marker(fd, root, created=created)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _check_marker(self, root_fd: int, root: Path, *, created: bool) -> None:
        """Provenance: is this directory *this plugin's spool*?

        Validation cannot answer that. ``~/.ssh``, ``~/.gnupg``, ``~/.aws`` and
        ``$HERMES_HOME/state`` are all user-owned and 0700, so a mis-pointed
        ``spool_root`` would pass every safety check and then be recursively
        emptied by the first startup purge. The marker is the answer: a root this
        plugin created (or an *empty* directory prepared for it, which has nothing
        to lose) is marked, and nothing unmarked is ever swept.
        """

        def marker_vouches() -> bool:
            try:
                info = os.lstat(MARKER_NAME, dir_fd=root_fd)
            except FileNotFoundError:
                return False
            if stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid():
                return True
            raise SpoolUnsafe(f"{root / MARKER_NAME} is not a regular file owned by this user")

        if marker_vouches():
            return

        if not created:
            try:
                existing = [name for name in os.listdir(root_fd) if name != LOCK_NAME]
            except OSError as exc:  # pragma: no cover - unreadable root
                raise SpoolUnsafe(f"could not read the spool root: errno {exc.errno}") from exc
            # Read again, *after* the listing, and only to answer the question the
            # listing just raised. Two claims arriving together both try to create
            # the root; whoever loses the ``mkdir`` gets here while the winner is
            # between its own lookup and its marker write, and would refuse a root
            # this process is itself in the middle of creating. A stranger's
            # directory does not grow a marker in that window — ``~/.ssh`` is
            # still refused, which is the property this gate exists for.
            if existing:
                if marker_vouches():
                    return
                raise SpoolUnsafe(
                    f"{root} is not empty and carries no {MARKER_NAME} marker, so this "
                    "plugin will not treat it as its spool — it deletes what it finds "
                    "under a spool root. Point spool_root at a directory this plugin "
                    "created, or at an empty private directory."
                )

        try:
            fd = os.open(
                MARKER_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=root_fd,
            )
        except FileExistsError:  # pragma: no cover - lost a benign race
            return
        except OSError as exc:
            raise SpoolUnsafe(f"could not mark the spool root: errno {exc.errno}") from exc
        try:
            os.fchmod(fd, 0o600)
            _write_all(
                fd,
                json.dumps(
                    {
                        "plugin": config_mod.PLUGIN_ID,
                        "purpose": "claimed-file spool; entries here are deleted at their TTL",
                        "created_at": int(self.now()),
                    },
                    sort_keys=True,
                ).encode("utf-8"),
            )
            os.fsync(fd)
        finally:
            os.close(fd)

    def stage(self) -> StagingClaim:
        """A fresh private directory for one claim. ``async with`` it."""
        return StagingClaim(self)

    # -- sweeping -----------------------------------------------------------

    def sweep(self, *, purge_all: bool = False) -> Dict[str, int]:
        """Remove what has expired. Never raises; counts what it did.

        A sweep is a recursive delete, so it is bounded twice: the root must carry
        the provenance marker, and only entries whose names this plugin generates
        are removed. Everything else is counted as ``foreign``, named in a
        warning, and left exactly where it is.

        ``purge_all`` ignores TTLs and age gates, which is only safe when no other
        gateway shares the root — so it is honoured only while this process holds
        the root lock, and degrades to an ordinary sweep with a warning otherwise.

        ``skipped`` is 1 when the walk never happened because there was nothing to
        walk: no spool configured, or no root and no ancestor chain yet. That is
        not an error and is not logged — but it is not a clean sweep of an empty
        root either, and :func:`ensure_started` needs to tell the two apart.
        """
        counts = {
            "published": 0,
            "staging": 0,
            "quarantine": 0,
            "foreign": 0,
            "errors": 0,
            "skipped": 0,
        }
        # Snapshotted once: these used to be read per entry, each a potential
        # ``config.yaml`` load inside the loop, and a root that changed mid-sweep
        # would decide one entry's fate against another spool.
        try:
            root = self.root
        except SpoolUnsafe:
            # Not configured: nothing can have been written, so there is nothing
            # to sweep and nothing to complain about on every tick.
            counts["skipped"] = 1
            return counts
        root_str = str(root)
        ttl = self.ttl_seconds
        now = self.now()

        try:
            fd = self._open_root(create=False, root=root)
        except SpoolAbsent:
            # The root, or a directory above it, does not exist. On a profile that
            # has never claimed a file that is every start, and the ERROR below is
            # false there: it ends "file claims refuse for the same reason", and
            # they do not — the claim path creates the chain under the Hermes home
            # and publishes. Nothing to sweep is nothing to say.
            counts["skipped"] = 1
            return counts
        except SpoolUnsafe as exc:
            counts["errors"] += 1
            logger.error(
                "hermes-drop: refusing to sweep the spool root at %s (%s). Claimed files "
                "cannot be cleaned up until this is resolved, and file claims refuse for "
                "the same reason.",
                root,
                exc,
            )
            return counts
        if fd is None:
            counts["skipped"] = 1
            return counts

        try:
            if purge_all and not _acquire_root_lock(fd, root_str):
                logger.warning(
                    "hermes-drop: the spool root at %s appears to be shared with another "
                    "live gateway, so the startup purge is limited to entries that have "
                    "actually expired. A spool root should belong to one gateway.",
                    root,
                )
                purge_all = False

            names = os.listdir(fd)
            foreign: List[str] = []
            for name in names:
                try:
                    info = os.lstat(name, dir_fd=fd)
                    kind = _classify(name, info)
                    if kind == "marker":
                        continue
                    if kind == "foreign":
                        counts["foreign"] += 1
                        foreign.append(name)
                        continue
                    if not self._expired(fd, name, kind, info, now, ttl, purge_all, root_str):
                        continue
                    _remove_entry(fd, name)
                    counts[kind] += 1
                except FileNotFoundError:
                    # Another sweeper won the race. That is the sweep working.
                    continue
                except _TooDeep:
                    counts["errors"] += 1
                    logger.warning(
                        "hermes-drop: %s under the spool root at %s is nested past the "
                        "%d-level depth bound, so it was left in place. Nothing this plugin "
                        "writes is nested; remove it by hand or those bytes stay on disk.",
                        name,
                        root,
                        MAX_REMOVE_DEPTH,
                    )
                except OSError:
                    counts["errors"] += 1
                    logger.debug("hermes-drop: could not sweep a spool entry", exc_info=True)
            if foreign:
                logger.warning(
                    "hermes-drop: the spool root at %s holds %d entr%s this plugin did not "
                    "create (%s%s). They are left untouched — only generated names are ever "
                    "removed — but a spool root is not a general-purpose directory.",
                    root,
                    len(foreign),
                    "y" if len(foreign) == 1 else "ies",
                    ", ".join(sorted(foreign)[:5]),
                    "…" if len(foreign) > 5 else "",
                )
        except OSError:
            counts["errors"] += 1
            logger.debug("hermes-drop: could not list the spool root", exc_info=True)
        finally:
            os.close(fd)
        return counts

    def _expired(
        self,
        root_fd: int,
        name: str,
        kind: str,
        info: os.stat_result,
        now: float,
        ttl: int,
        purge_all: bool,
        root_str: str,
    ) -> bool:
        if kind == "staging" and (root_str, name) in _ACTIVE_STAGING:
            # A live transfer in this process. Its mtime says nothing useful — a
            # 42 MiB claim can be minutes old and still be filling.
            return False
        if purge_all:
            return True
        if kind == "published":
            return self._published_expiry(root_fd, name, info, ttl) <= now
        if kind == "quarantine":
            return info.st_mtime + ttl <= now
        return info.st_mtime + STAGING_GRACE_SECONDS < now

    def _published_expiry(
        self, root_fd: int, name: str, info: os.stat_result, ttl: int
    ) -> float:
        """The sidecar's ``expires_at``, clamped, or the directory's own age.

        Clamped because the record is a *file*: a clock that jumped forward at
        publish time, or a corrupted digit, would otherwise pin bytes on disk for
        as long as it says. The fallback is what makes a crash survivable — a
        directory whose record is unreadable still expires, just on its mtime.
        """
        fallback = info.st_mtime + ttl
        if not stat.S_ISDIR(info.st_mode):
            return fallback
        try:
            child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd
            )
        except OSError:
            return fallback
        try:
            fd = os.open(METADATA_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=child)
            with os.fdopen(fd, "rb") as handle:
                record = json.loads(handle.read(64 * 1024).decode("utf-8"))
            value = record.get("expires_at")
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return min(float(value), fallback)
            return fallback
        except (OSError, ValueError, UnicodeDecodeError):
            return fallback
        finally:
            os.close(child)

    def cleanup_at_startup(self) -> Dict[str, int]:
        """Purge this plugin's claims, ignoring TTLs and age gates.

        A restart is the one moment when neither is informative: no transfer of
        *ours* can be in flight, and nothing that survived is being watched by a
        janitor that also restarted. Leaving an unexpired claim directory would
        leave bytes on disk with nothing scheduled to remove them.

        Two bounds keep that from being dangerous: the marker (an unmarked root is
        refused, not emptied) and the root lock (a root another gateway is using
        gets a TTL-safe sweep instead, because *its* claims are live).
        """
        counts = self.sweep(purge_all=True)
        removed = counts["published"] + counts["staging"] + counts["quarantine"]
        if removed:
            logger.info(
                "hermes-drop: cleared %d spool entr%s left by a previous process "
                "(%d published, %d in progress, %d quarantined)",
                removed,
                "y" if removed == 1 else "ies",
                counts["published"],
                counts["staging"],
                counts["quarantine"],
            )
        return counts


# ── module-level helpers ───────────────────────────────────────────────────


def _classify(name: str, info: os.stat_result) -> str:
    """What a root entry is: by provenance first, then type, then name.

    Only the three generated shapes are removable. The spool creates directories
    named ``<32 hex>`` and ``.staging-``/``.quarantine-`` plus those, so anything
    else — a plain file, a symlink, a directory with somebody else's name — is
    ``foreign`` and is never a deletion candidate.
    """
    if name in (MARKER_NAME, LOCK_NAME):
        return "marker"
    if not stat.S_ISDIR(info.st_mode):
        return "foreign"
    if name.startswith(STAGING_PREFIX) and _CLAIM_ID_RE.match(name[len(STAGING_PREFIX) :]):
        return "staging"
    if name.startswith(QUARANTINE_PREFIX) and _CLAIM_ID_RE.match(name[len(QUARANTINE_PREFIX) :]):
        return "quarantine"
    if _CLAIM_ID_RE.match(name):
        return "published"
    return "foreign"


def _acquire_root_lock(root_fd: int, root_str: str) -> bool:
    """Hold an advisory exclusive lock on the root for this process's lifetime.

    ``flock`` and not a pid file: it is released by the kernel when the process
    dies, however it dies, so a crashed gateway never leaves a lock that stops the
    next one from cleaning up.
    """
    with _LOCK_GUARD:
        if root_str in _ROOT_LOCKS:
            return True
        try:
            fd = os.open(
                LOCK_NAME,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=root_fd,
            )
        except OSError:
            logger.debug("hermes-drop: could not open the spool lock", exc_info=True)
            return False
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        _ROOT_LOCKS[root_str] = fd
        return True


def _lexists_at(dir_fd: int, name: str) -> bool:
    try:
        os.lstat(name, dir_fd=dir_fd)
        return True
    except OSError:
        return False


def _remove_entry(dir_fd: int, name: str, depth: int = 0) -> None:
    """Remove *name* under *dir_fd*, without ever following a symlink.

    ``lstat`` then ``unlink`` for anything that is not a directory — a symlink is
    unlinked, never traversed, so litter pointing at somebody's home directory
    costs nothing. Directories are emptied through their own descriptor and
    ``rmdir``'d; nothing here creates nested directories, so the depth bound
    exists only to keep a hostile tree from turning a sweep into a walk, and
    hitting it is reported rather than retried forever.
    """
    info = os.lstat(name, dir_fd=dir_fd)
    if not stat.S_ISDIR(info.st_mode):
        os.unlink(name, dir_fd=dir_fd)
        return

    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        for inner in os.listdir(child):
            try:
                inner_info = os.lstat(inner, dir_fd=child)
                if stat.S_ISDIR(inner_info.st_mode):
                    if depth >= MAX_REMOVE_DEPTH:
                        raise _TooDeep(name)
                    _remove_entry(child, inner, depth + 1)
                    continue
                os.unlink(inner, dir_fd=child)
            except FileNotFoundError:
                continue
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=dir_fd)


def _remove_entry_quietly(dir_fd: int, name: str) -> None:
    """For cleanup on an error path, where a second failure would replace the
    first one's diagnosis with a worse one. The sweeper is the backstop."""
    try:
        _remove_entry(dir_fd, name)
    except (OSError, _TooDeep):
        logger.debug("hermes-drop: could not clean up a spool entry", exc_info=True)


# ── startup purge and the periodic janitor ─────────────────────────────────


def ensure_started(spool: Spool) -> bool:
    """Run the startup purge, once per process. ``True`` if this call ran it.

    **Blocking, and that is the fix.** The latch used to be a flag set before the
    purge, so a second caller returned immediately and staged into a root that was
    still being walked — the purge then unlinked a directory that was about to be
    written into, and the writes continued into it, surfacing only past the commit.
    Whoever loses this race waits for the purge instead.

    Latched to a claim and to the reconciler's pass rather than to ``register()``,
    because plugin discovery happens in every CLI process and a directory walk in
    ``hermes --help`` is a footprint nobody asked for.

    A purge that found no root at all does not spend the latch. It walked nothing,
    so there is nothing for it to have been spent on, and a root that appears a
    moment later — another gateway's, an operator's restored backup — would
    otherwise have only the janitor's TTL sweep behind it. The deferral is bounded
    on the other side by :meth:`StagingClaim._create`, which spends the latch as
    soon as *this* process starts writing: past that point the entries under the
    root may be ours, and a purge is no longer a startup.
    """
    global _started
    with _STARTUP_LOCK:
        if _started:
            return False
        counts: Optional[Dict[str, int]] = None
        try:
            counts = spool.cleanup_at_startup()
        except Exception:  # noqa: BLE001 - a cleanup failure must not fail a claim
            logger.warning("hermes-drop: the spool startup cleanup failed", exc_info=True)
        if counts is not None and counts.get("skipped"):
            return False
        _started = True
        return True


def _spend_startup_latch() -> None:
    """Record that the startup purge may no longer run in this process.

    Assigned without ``_STARTUP_LOCK`` deliberately: this is called from the
    staging path, which can run on a worker thread while another thread holds the
    lock for the purge itself, and a plain lock is not reentrant. The assignment
    is atomic, and the only interleaving it can produce is the safe one — a purge
    already under way finishes, and the next caller sees the latch spent.
    """
    global _started
    _started = True


def reset_startup_latch() -> None:
    """For tests, and for a process that legitimately re-initialises."""
    global _started
    with _STARTUP_LOCK:
        _started = False


def reset_process_state() -> None:
    """Every process-wide latch this module owns. Tests only."""
    global _reserved_bytes
    reset_startup_latch()
    with _RESERVE_LOCK:
        _reserved_bytes = 0
    _ACTIVE_STAGING.clear()
    with _LOCK_GUARD:
        for fd in _ROOT_LOCKS.values():
            try:
                os.close(fd)
            except OSError:  # pragma: no cover
                pass
        _ROOT_LOCKS.clear()


def ensure_janitor(
    spool: Spool, *, interval: float = SWEEP_INTERVAL_SECONDS
) -> "Optional[asyncio.Task[None]]":
    """Start the periodic sweep, at most one per process.

    The startup purge covers a restart; this covers the gateway that runs for
    weeks. Two janitors would double every delete and race each other into
    ``FileNotFoundError``, so the task is latched.

    The latch holds the *first* ``Spool`` object. A default-constructed one
    re-resolves its root and TTL per sweep, so it follows a profile switch; one
    constructed with an explicit root pins the janitor to that root for the life of
    the process, which is what a caller passing an explicit root is choosing.
    """
    global _janitor
    if _janitor is not None and not _janitor.done():
        return _janitor
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # pragma: no cover - no loop, nothing to schedule on
        return None
    _janitor = loop.create_task(_janitor_loop(spool, interval))
    return _janitor


def janitor_task() -> "Optional[asyncio.Task[None]]":
    return _janitor


def stop_janitor() -> None:
    global _janitor
    task, _janitor = _janitor, None
    if task is not None and not task.done():
        try:
            task.cancel()
        except RuntimeError:  # pragma: no cover - a closed loop
            pass


async def _janitor_loop(spool: Spool, interval: float) -> None:
    while True:
        try:
            await asyncio.sleep(interval)
            await asyncio.to_thread(spool.sweep)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failing sweep must not end the sweeps
            logger.debug("hermes-drop: a spool sweep failed", exc_info=True)


__all__ = [
    "CLAIM_ID_BYTES",
    "FALLBACK_LABEL",
    "LOCK_NAME",
    "MARKER_NAME",
    "MAX_CLAIM_FILES",
    "MAX_CLAIM_FILE_BYTES",
    "MAX_CLAIM_TOTAL_BYTES",
    "MAX_LIVE_CLAIM_BYTES",
    "MAX_REMOVE_DEPTH",
    "METADATA_NAME",
    "QUARANTINE_PREFIX",
    "STAGING_GRACE_SECONDS",
    "STAGING_PREFIX",
    "STORAGE_NAME_BYTES",
    "SWEEP_INTERVAL_SECONDS",
    "Spool",
    "SpoolAbsent",
    "SpoolBusy",
    "SpoolUnsafe",
    "StagingClaim",
    "StagingFailed",
    "ensure_janitor",
    "ensure_started",
    "janitor_task",
    "reserved_claim_bytes",
    "reset_process_state",
    "reset_startup_latch",
    "sanitize_label",
    "sanitize_type",
    "stop_janitor",
]
