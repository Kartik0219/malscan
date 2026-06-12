"""Quarantine vault: isolate flagged files so they can't execute, with restore.

Design notes:
- Quarantined files are XOR-obfuscated with a fixed key as they're stored. This
  is NOT encryption for confidentiality — it exists so the stored blob is no
  longer a runnable executable and won't re-trip on-access AV inside the vault.
- The original bytes are recoverable exactly (XOR is symmetric), so restore is
  lossless.
- Each entry has a sidecar `<id>.json` recording original path, hashes, verdict,
  and timestamp, so we can restore to the right place and audit later.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Fixed XOR key — purely to render the stored blob non-executable, not a secret.
_XOR_KEY = b"malscan-quarantine-v1"


def _xor(data: bytes, key: bytes = _XOR_KEY) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _default_vault() -> Path:
    return Path(__file__).resolve().parent.parent / "quarantine"


@dataclass
class QuarantineEntry:
    id: str
    original_path: str
    sha256: str
    size: int
    verdict: str
    quarantined_at: str
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "original_path": self.original_path,
            "sha256": self.sha256,
            "size": self.size,
            "verdict": self.verdict,
            "quarantined_at": self.quarantined_at,
            "reasons": self.reasons,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "QuarantineEntry":
        return cls(
            id=d["id"],
            original_path=d["original_path"],
            sha256=d["sha256"],
            size=d["size"],
            verdict=d["verdict"],
            quarantined_at=d["quarantined_at"],
            reasons=d.get("reasons", []),
        )


class Quarantine:
    def __init__(self, vault_dir: str | Path | None = None):
        self.vault = Path(vault_dir) if vault_dir else _default_vault()
        self.vault.mkdir(parents=True, exist_ok=True)

    def _blob_path(self, entry_id: str) -> Path:
        return self.vault / f"{entry_id}.bin"

    def _meta_path(self, entry_id: str) -> Path:
        return self.vault / f"{entry_id}.json"

    def quarantine_file(
        self, path: str | Path, verdict: str = "malicious", reasons: list[str] | None = None
    ) -> QuarantineEntry:
        """Move `path` into the vault (obfuscated) and remove the original."""
        path = Path(path)
        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        entry_id = secrets.token_hex(8)

        self._blob_path(entry_id).write_bytes(_xor(data))
        entry = QuarantineEntry(
            id=entry_id,
            original_path=str(path.resolve()),
            sha256=sha256,
            size=len(data),
            verdict=verdict,
            quarantined_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
            reasons=reasons or [],
        )
        self._meta_path(entry_id).write_text(
            json.dumps(entry.to_dict(), indent=2), encoding="utf-8"
        )

        # Remove the original only after the vault copy is safely written.
        path.unlink()
        return entry

    def list_entries(self) -> list[QuarantineEntry]:
        entries = []
        for meta in sorted(self.vault.glob("*.json")):
            entries.append(QuarantineEntry.from_dict(json.loads(meta.read_text("utf-8"))))
        return entries

    def get(self, entry_id: str) -> QuarantineEntry | None:
        meta = self._meta_path(entry_id)
        if not meta.exists():
            return None
        return QuarantineEntry.from_dict(json.loads(meta.read_text("utf-8")))

    def restore(self, entry_id: str, dest: str | Path | None = None) -> Path:
        """Restore a quarantined file. Returns the path it was written to."""
        entry = self.get(entry_id)
        if entry is None:
            raise KeyError(f"no quarantine entry {entry_id}")
        blob = self._blob_path(entry_id)
        data = _xor(blob.read_bytes())

        target = Path(dest) if dest else Path(entry.original_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

        blob.unlink(missing_ok=True)
        self._meta_path(entry_id).unlink(missing_ok=True)
        return target

    def delete(self, entry_id: str) -> bool:
        """Permanently delete a quarantined entry (blob + metadata)."""
        blob = self._blob_path(entry_id)
        meta = self._meta_path(entry_id)
        existed = meta.exists()
        blob.unlink(missing_ok=True)
        meta.unlink(missing_ok=True)
        return existed
