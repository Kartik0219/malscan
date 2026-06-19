"""Scanner orchestrator: walks paths, runs every engine per file, aggregates."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterator

from . import archive
from .engines.hashes import HashEngine
from .engines.heuristics import HeuristicEngine
from .engines.filetype import FileTypeEngine
from .engines.yara_engine import YaraEngine
from .models import FileResult, Finding, Severity
from ._paths import resource_root

# Skip files larger than this to keep scans fast and memory-bounded (bytes).
DEFAULT_MAX_SIZE = 100 * 1024 * 1024  # 100 MB

# Archive-walk budgets (defend against zip bombs). The total decompressed
# budget caps peak memory; depth caps nesting; members caps fan-out.
ARCHIVE_MAX_DEPTH = 3
ARCHIVE_MAX_MEMBERS = 1000
ARCHIVE_MAX_TOTAL_BYTES = 64 * 1024 * 1024  # 64 MB


def _signatures_dir() -> Path:
    return resource_root() / "signatures"


class Scanner:
    def __init__(
        self,
        signatures_dir: Path | None = None,
        max_size: int = DEFAULT_MAX_SIZE,
        vt_api_key: str | None = None,
        scan_archives: bool = True,
    ):
        sig = signatures_dir or _signatures_dir()
        self.max_size = max_size
        self.scan_archives = scan_archives
        self.hash_engine = HashEngine(sig / "hash_blocklist.txt")
        self.heuristic_engine = HeuristicEngine()
        self.filetype_engine = FileTypeEngine()
        self.yara_engine = YaraEngine(sig / "yara")
        self._engines = [
            self.hash_engine, self.heuristic_engine,
            self.filetype_engine, self.yara_engine,
        ]

        # VirusTotal is opt-in: only added when a key is supplied. The public
        # web demo constructs Scanner() with no key, so it never phones home.
        self.vt_engine = None
        if vt_api_key:
            from .engines.virustotal import VirusTotalEngine
            self.vt_engine = VirusTotalEngine(vt_api_key)
            self._engines.append(self.vt_engine)

    @property
    def engine_status(self) -> dict[str, str]:
        status = {
            "hash": "ready",
            "heuristic": "ready",
            "filetype": "ready",
            "yara": self.yara_engine.status,
        }
        if self.vt_engine is not None:
            status["virustotal"] = "ready"
        return status

    def scan_bytes(self, name: str, data: bytes) -> FileResult:
        """Run every engine against in-memory bytes. Touches no filesystem path.

        This is the safe core used by both on-disk scanning and the upload-based
        public demo: nothing is read from or written to disk here.
        """
        sha256 = hashlib.sha256(data).hexdigest()
        result = FileResult(path=name, size=len(data), sha256=sha256)
        for engine in self._engines:
            try:
                result.findings.extend(engine.scan(name, data))
            except Exception as exc:  # one engine failing shouldn't sink the file
                result.findings.append(
                    Finding(
                        engine=getattr(engine, "name", "unknown"),
                        severity=Severity.INFO,
                        message=f"engine error: {exc}",
                    )
                )
        return result

    def scan_file(self, path: str | Path) -> FileResult:
        path = Path(path)
        try:
            size = path.stat().st_size
        except OSError as exc:
            return FileResult(path=str(path), size=0, sha256="", error=str(exc))

        if size > self.max_size:
            return FileResult(
                path=str(path), size=size, sha256="",
                error=f"skipped: exceeds max size ({size} > {self.max_size} bytes)",
            )

        try:
            data = path.read_bytes()
        except OSError as exc:
            return FileResult(path=str(path), size=size, sha256="", error=str(exc))

        return self.scan_bytes(str(path), data)

    def iter_results(
        self, name: str, data: bytes, *, scan_archives: bool | None = None
    ) -> Iterator[FileResult]:
        """Yield the container's own result, then one result per archive member.

        Archive members are walked in memory under strict budgets (never
        extracted to disk). Member paths compose with ``!``, e.g.
        ``bundle.zip!evil.exe``. Budget notes (truncations, bombs, unreadable
        members) attach to the container result as INFO findings.
        """
        expand = self.scan_archives if scan_archives is None else scan_archives

        members: list[tuple[str, bytes]] = []
        notes: list[str] = []
        if expand and archive.detect(data) is not None:
            budget = archive.Budget(
                max_members=ARCHIVE_MAX_MEMBERS,
                max_member_bytes=self.max_size,
                max_total_bytes=ARCHIVE_MAX_TOTAL_BYTES,
            )
            members = list(
                archive.walk(data, budget=budget, depth=ARCHIVE_MAX_DEPTH, notes=notes)
            )

        container = self.scan_bytes(name, data)
        for note in notes:
            container.findings.append(
                Finding(engine="archive", severity=Severity.INFO, message=note)
            )
        yield container

        for member_name, member_bytes in members:
            yield self.scan_bytes(f"{name}!{member_name}", member_bytes)

    def scan_path(self, target: str | Path, recursive: bool = True) -> Iterator[FileResult]:
        target = Path(target)
        if target.is_file():
            yield from self._scan_disk_file(target)
            return
        if target.is_dir():
            walker = target.rglob("*") if recursive else target.glob("*")
            for child in walker:
                if child.is_file():
                    yield from self._scan_disk_file(child)
            return
        yield FileResult(path=str(target), size=0, sha256="", error="path not found")

    def _scan_disk_file(self, path: Path) -> Iterator[FileResult]:
        """Read one file (with guards) and yield its result(s), expanding archives."""
        try:
            size = path.stat().st_size
        except OSError as exc:
            yield FileResult(path=str(path), size=0, sha256="", error=str(exc))
            return
        if size > self.max_size:
            yield FileResult(
                path=str(path), size=size, sha256="",
                error=f"skipped: exceeds max size ({size} > {self.max_size} bytes)",
            )
            return
        try:
            data = path.read_bytes()
        except OSError as exc:
            yield FileResult(path=str(path), size=size, sha256="", error=str(exc))
            return
        yield from self.iter_results(str(path), data)
