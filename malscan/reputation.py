"""A local file-reputation cache — the honest, single-host slice of the
"cloud reputation / block-at-first-sight" idea.

Commercial AV treats a file the whole world has never seen very differently from
one running on fifty million machines: rarity is signal. We can't replicate a
global telemetry network, but we *can* keep a local prevalence record — every
hash this installation has ever scanned, when it was first seen, and how often.
A never-before-seen **executable** is then flaggable as "unknown / no
reputation", which is exactly the prevalence reasoning, scoped honestly to one
host.

Storage is a tiny SQLite database (stdlib ``sqlite3``), kept under the writable
user-data root. It is **opt-in**: a scan only records reputation when a database
is supplied, so the dependency-free core and the public web demo never persist
anything.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hashes (
    sha256        TEXT PRIMARY KEY,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    times_seen    INTEGER NOT NULL,
    is_executable INTEGER NOT NULL,
    size          INTEGER NOT NULL
);
"""


@dataclass
class ReputationInfo:
    """What the cache knew about a file at the moment it was recorded."""

    first_seen: bool       # True if this scan is the first time we've seen the hash
    times_seen: int        # total observations including this one
    first_seen_at: str     # ISO timestamp of the first observation


class ReputationStore:
    """SQLite-backed prevalence record of every hash this host has scanned."""

    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path))
        self._db.execute(_SCHEMA)
        self._db.commit()

    def record(self, sha256: str, *, size: int, is_executable: bool) -> ReputationInfo:
        """Record one observation of ``sha256`` and return what we knew before."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        row = self._db.execute(
            "SELECT first_seen, times_seen FROM hashes WHERE sha256 = ?", (sha256,)
        ).fetchone()
        if row is None:
            self._db.execute(
                "INSERT INTO hashes (sha256, first_seen, last_seen, times_seen, "
                "is_executable, size) VALUES (?, ?, ?, 1, ?, ?)",
                (sha256, now, now, 1 if is_executable else 0, size),
            )
            self._db.commit()
            return ReputationInfo(first_seen=True, times_seen=1, first_seen_at=now)

        first_seen_at, prior = row
        self._db.execute(
            "UPDATE hashes SET last_seen = ?, times_seen = times_seen + 1 WHERE sha256 = ?",
            (now, sha256),
        )
        self._db.commit()
        return ReputationInfo(first_seen=False, times_seen=prior + 1, first_seen_at=first_seen_at)

    def stats(self) -> dict:
        """Summary counts for the `reputation` CLI command."""
        total = self._db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
        execs = self._db.execute(
            "SELECT COUNT(*) FROM hashes WHERE is_executable = 1"
        ).fetchone()[0]
        top = self._db.execute(
            "SELECT sha256, times_seen FROM hashes ORDER BY times_seen DESC LIMIT 5"
        ).fetchall()
        return {"total": total, "executables": execs,
                "most_seen": [{"sha256": s, "times_seen": n} for s, n in top]}

    def close(self) -> None:
        self._db.close()
