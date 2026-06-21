"""Real-time directory monitoring — on-access-style scanning.

**Scope, stated honestly:** true kernel-level on-access interception — scanning a
file *before* it is opened, with the power to **block** the open — requires a
platform driver: Linux ``fanotify`` (``FAN_OPEN_PERM``), a Windows minifilter, or
the macOS Endpoint Security framework. That is native kernel code and is out of
scope for a pure-Python tool. This module is the faithful *user-space*
approximation: it watches directories and scans files as they are **created or
modified**, then reports and (optionally) quarantines bad verdicts. It is
*monitor-and-react*, not *intercept-and-block* — useful for a Downloads folder or
an upload directory, and the same control-flow a real-time engine drives.

Implementation is stdlib polling (no ``watchdog``/``inotify`` dependency), so it
runs everywhere malscan does. A changed file is only scanned once it has
**settled** — its size and mtime are stable across two polls — so half-written
downloads aren't scanned mid-flight. The ``Scanner`` is injected, so a monitor
inherits whatever engines you configured (YARA, ML model, VirusTotal, …).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from .models import FileResult, Severity
from .quarantine import Quarantine
from .scanner import Scanner


@dataclass
class MonitorEvent:
    """One file the monitor scanned because it appeared or changed."""

    path: str
    result: FileResult
    quarantined: str | None = None  # quarantine entry id, if isolated


class Monitor:
    """Watch paths and scan files as they are created or modified."""

    def __init__(
        self,
        scanner: Scanner,
        paths: list[str | Path],
        *,
        recursive: bool = True,
        quarantine: Quarantine | None = None,
    ):
        self.scanner = scanner
        self.paths = [Path(p) for p in paths]
        self.recursive = recursive
        self.quarantine = quarantine
        # key -> (mtime, size) for files already scanned and unchanged since.
        self._seen: dict[str, tuple[float, int]] = {}
        # key -> (mtime, size) for changed files awaiting a stable second look.
        self._pending: dict[str, tuple[float, int]] = {}

    def _iter_files(self) -> Iterator[Path]:
        vault = self.quarantine.vault.resolve() if self.quarantine else None
        for base in self.paths:
            candidates: Iterator[Path]
            if base.is_file():
                candidates = iter([base])
            elif base.is_dir():
                candidates = base.rglob("*") if self.recursive else base.glob("*")
            else:
                continue
            for child in candidates:
                if not child.is_file():
                    continue
                # Never re-scan our own quarantine vault (obfuscated blobs).
                if vault is not None:
                    try:
                        if vault in child.resolve().parents:
                            continue
                    except OSError:
                        continue
                yield child

    def prime(self) -> int:
        """Record the current files as a baseline without scanning them.

        After priming, only files created or modified *after* this point are
        scanned. Returns the number of files baselined.
        """
        count = 0
        for f in self._iter_files():
            try:
                st = f.stat()
            except OSError:
                continue
            self._seen[str(f)] = (st.st_mtime, st.st_size)
            count += 1
        return count

    def poll(self) -> list[MonitorEvent]:
        """One pass: scan files that are new/changed *and* have settled."""
        events: list[MonitorEvent] = []
        for f in self._iter_files():
            key = str(f)
            try:
                st = f.stat()
            except OSError:
                continue
            sig = (st.st_mtime, st.st_size)
            if self._seen.get(key) == sig:
                continue  # unchanged since last scan
            if self._pending.get(key) == sig:
                # Stable across two polls -> safe to scan now.
                events.append(self._scan(f))
                self._seen[key] = sig
                self._pending.pop(key, None)
            else:
                # New or still-changing: remember and wait one more poll.
                self._pending[key] = sig
        return events

    def _scan(self, path: Path) -> MonitorEvent:
        result = self.scanner.scan_file(path)
        quarantined = None
        if (
            self.quarantine is not None
            and result.verdict == Severity.MALICIOUS
            and Path(result.path).is_file()
        ):
            try:
                entry = self.quarantine.quarantine_file(
                    result.path,
                    verdict=result.verdict.value,
                    reasons=[f.message for f in result.findings],
                )
                quarantined = entry.id
            except OSError:
                quarantined = None
        return MonitorEvent(path=str(path), result=result, quarantined=quarantined)

    def run(
        self,
        *,
        interval: float = 1.0,
        on_event: Callable[[MonitorEvent], None] | None = None,
        iterations: int | None = None,
    ) -> None:
        """Baseline existing files, then poll forever (or ``iterations`` times).

        ``iterations`` bounds the loop for tests; ``None`` runs until interrupted
        (Ctrl-C). ``on_event`` is called for every scanned file.
        """
        self.prime()
        count = 0
        try:
            while iterations is None or count < iterations:
                time.sleep(interval)
                for event in self.poll():
                    if on_event is not None:
                        on_event(event)
                count += 1
        except KeyboardInterrupt:
            pass
