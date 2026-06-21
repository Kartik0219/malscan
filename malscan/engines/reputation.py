"""Reputation engine: flag never-before-seen executables using the local cache.

Records every scanned file's hash in the local prevalence store and raises an
INFO finding the first time an **executable** is seen on this host — the
single-machine analogue of "block at first sight". INFO, not suspicious: an
unknown file is not a bad file, it's an *unvouched* one, and that context is what
a human (or a later engine) weighs. Opt-in and only attached when a store is
supplied, so a scan is never stateful by accident.
"""

from __future__ import annotations

from ..models import Finding, Severity
from ..reputation import ReputationStore

#: Magic prefixes that mark a file as a runnable binary worth tracking by rarity.
_EXECUTABLE_MAGICS: tuple[bytes, ...] = (
    b"MZ", b"\x7fELF",
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
)


class ReputationEngine:
    name = "reputation"

    def __init__(self, store: ReputationStore):
        self.store = store

    def scan(self, path: str, data: bytes) -> list[Finding]:
        import hashlib
        sha256 = hashlib.sha256(data).hexdigest()
        is_exec = data.startswith(_EXECUTABLE_MAGICS)
        info = self.store.record(sha256, size=len(data), is_executable=is_exec)

        if info.first_seen and is_exec:
            return [Finding(
                engine=self.name,
                severity=Severity.INFO,
                message="First time this executable has been seen on this host "
                        "(no local reputation)",
                detail={"first_seen": True, "times_seen": info.times_seen},
            )]
        return []
