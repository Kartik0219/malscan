"""In-memory archive traversal with explicit resource budgets.

Ported from the Mongoose project and adapted for malscan.

Why in-memory: members are never extracted to disk, so hostile member names
(``../../etc/cron.d/job``, absolute paths) are inert report strings here -
the zip-slip class of vulnerabilities cannot occur. Why budgets: archives are
the classic scanner denial-of-service vector ("zip bombs": tiny files that
decompress to terabytes, contain millions of members, or nest forever). Every
expansion this module performs is capped by a :class:`Budget`, and anything
skipped leaves an audit note instead of disappearing silently.

Supported containers: zip, tar (including gzip/bzip2/xz-compressed tar), and
bare gzip streams. Member names compose with ``!`` for nesting, e.g.
``inner.zip!docs/sample.com``.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field

_ZIP_MAGIC = b"PK\x03\x04"
_GZIP_MAGIC = b"\x1f\x8b"
_BZ2_MAGIC = b"BZh"
_XZ_MAGIC = b"\xfd7zXZ\x00"
_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"

#: Name given to the single member of a bare (non-tar) gzip stream.
GZIP_MEMBER_NAME = "<decompressed>"


def detect(data: bytes) -> str | None:
    """Classify ``data`` as a container we can walk, or ``None``.

    Returns ``"zip"``, ``"tar"``, or ``"compressed"`` (a gzip/bzip2/xz stream
    that may turn out to be a compressed tar or a bare stream).
    """
    if data.startswith(_ZIP_MAGIC):
        return "zip"
    if (
        len(data) > _TAR_MAGIC_OFFSET + len(_TAR_MAGIC)
        and data[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + len(_TAR_MAGIC)] == _TAR_MAGIC
    ):
        return "tar"
    if data.startswith((_GZIP_MAGIC, _BZ2_MAGIC, _XZ_MAGIC)):
        return "compressed"
    return None


@dataclass
class Budget:
    """Shared expansion limits for one archive walk (including nesting).

    ``max_member_bytes`` caps a single decompressed member; ``max_total_bytes``
    caps the sum across all members - the backstop against high-ratio
    decompression bombs.
    """

    max_members: int
    max_member_bytes: int
    max_total_bytes: int
    members_used: int = 0
    bytes_used: int = 0
    _noted: set[str] = field(default_factory=set)

    def try_member(self) -> bool:
        if self.members_used >= self.max_members:
            return False
        self.members_used += 1
        return True

    def try_bytes(self, count: int) -> bool:
        if self.bytes_used + count > self.max_total_bytes:
            return False
        self.bytes_used += count
        return True

    def note_once(self, notes: list[str], key: str, message: str) -> None:
        """Record a budget note only the first time it occurs."""
        if key not in self._noted:
            self._noted.add(key)
            notes.append(message)


def walk(
    data: bytes,
    *,
    budget: Budget,
    depth: int,
    notes: list[str],
    prefix: str = "",
) -> Iterator[tuple[str, bytes]]:
    """Yield ``(member_path, member_bytes)`` for every member within budget.

    Recurses into nested archives up to ``depth`` levels, composing member
    paths with ``!``. Anything unreadable or out of budget is recorded in
    ``notes`` and skipped; this function never raises for hostile input.
    """
    kind = detect(data)
    if kind is None or depth <= 0:
        return
    if kind == "zip":
        yield from _walk_zip(data, budget, depth, notes, prefix)
    else:
        yield from _walk_tar_or_stream(data, budget, depth, notes, prefix)


def _walk_zip(
    data: bytes, budget: Budget, depth: int, notes: list[str], prefix: str
) -> Iterator[tuple[str, bytes]]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError) as exc:
        notes.append(f"archive: unreadable zip {prefix or '<file>'!s}: {exc}")
        return
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = prefix + info.filename
            if not budget.try_member():
                budget.note_once(
                    notes,
                    "members",
                    f"archive: member budget ({budget.max_members}) exhausted; "
                    "remaining members not scanned",
                )
                return
            try:
                with zf.open(info) as handle:
                    member = handle.read(budget.max_member_bytes + 1)
            except (RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                # Encrypted or unsupported-compression members land here.
                notes.append(f"archive: cannot read member {name!r}: {exc}")
                continue
            yield from _emit(name, member, budget, depth, notes)


def _walk_tar_or_stream(
    data: bytes, budget: Budget, depth: int, notes: list[str], prefix: str
) -> Iterator[tuple[str, bytes]]:
    """Walk a tar (optionally compressed); fall back to a bare gzip stream."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError:
        if data.startswith(_GZIP_MAGIC):
            yield from _walk_bare_gzip(data, budget, depth, notes, prefix)
        else:
            notes.append(
                f"archive: unsupported compressed stream {prefix or '<file>'!s} "
                "(not a tar); contents not scanned"
            )
        return
    with tf:
        for info in tf.getmembers():
            if not info.isfile():
                continue
            name = prefix + info.name
            if not budget.try_member():
                budget.note_once(
                    notes,
                    "members",
                    f"archive: member budget ({budget.max_members}) exhausted; "
                    "remaining members not scanned",
                )
                return
            handle = tf.extractfile(info)
            if handle is None:
                continue
            try:
                member = handle.read(budget.max_member_bytes + 1)
            except (tarfile.TarError, OSError) as exc:
                notes.append(f"archive: cannot read member {name!r}: {exc}")
                continue
            yield from _emit(name, member, budget, depth, notes)


def _walk_bare_gzip(
    data: bytes, budget: Budget, depth: int, notes: list[str], prefix: str
) -> Iterator[tuple[str, bytes]]:
    name = prefix + GZIP_MEMBER_NAME
    if not budget.try_member():
        budget.note_once(
            notes,
            "members",
            f"archive: member budget ({budget.max_members}) exhausted; "
            "remaining members not scanned",
        )
        return
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            member = handle.read(budget.max_member_bytes + 1)
    except (OSError, EOFError) as exc:
        notes.append(f"archive: unreadable gzip stream {prefix or '<file>'!s}: {exc}")
        return
    yield from _emit(name, member, budget, depth, notes)


def _emit(
    name: str, member: bytes, budget: Budget, depth: int, notes: list[str]
) -> Iterator[tuple[str, bytes]]:
    """Apply size budgets, yield the member, then descend if it nests."""
    if len(member) > budget.max_member_bytes:
        notes.append(
            f"archive: member {name!r} skipped (decompresses past "
            f"{budget.max_member_bytes} bytes)"
        )
        return
    if not budget.try_bytes(len(member)):
        budget.note_once(
            notes,
            "bytes",
            f"archive: total decompressed budget ({budget.max_total_bytes} bytes) "
            "exhausted; remaining members not scanned",
        )
        return
    yield name, member
    if detect(member) is not None:
        if depth <= 1:
            notes.append(
                f"archive: nested archive {name!r} not expanded (depth limit reached)"
            )
            return
        yield from walk(
            member, budget=budget, depth=depth - 1, notes=notes, prefix=name + "!"
        )
