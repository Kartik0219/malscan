"""Hash-based detection: match a file's SHA-256/MD5 against a blocklist.

The blocklist is a plain text file (signatures/hash_blocklist.txt), one entry
per line in the form:

    <hexdigest>  <optional label>

Lines starting with '#' are comments. Both MD5 (32 hex chars) and SHA-256
(64 hex chars) digests are supported; the length determines which is matched.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ..models import Finding, Severity


def _load_blocklist(path: Path) -> dict[str, str]:
    """Return {lowercased_hexdigest: label}."""
    entries: dict[str, str] = {}
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        digest = parts[0].lower()
        label = parts[1] if len(parts) > 1 else "known-bad hash"
        entries[digest] = label
    return entries


class HashEngine:
    name = "hash"

    def __init__(self, blocklist_path: Path):
        self._blocklist = _load_blocklist(blocklist_path)

    def scan(self, path: str, data: bytes) -> list[Finding]:
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()
        for digest in (sha256, md5):
            if digest in self._blocklist:
                return [
                    Finding(
                        engine=self.name,
                        severity=Severity.MALICIOUS,
                        message=f"Matches known-bad hash: {self._blocklist[digest]}",
                        detail={"digest": digest},
                    )
                ]
        return []
