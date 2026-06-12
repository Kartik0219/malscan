"""Shared data types for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered severity levels. CLEAN < INFO < SUSPICIOUS < MALICIOUS."""

    CLEAN = "clean"
    INFO = "info"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

    @property
    def rank(self) -> int:
        order = [Severity.CLEAN, Severity.INFO, Severity.SUSPICIOUS, Severity.MALICIOUS]
        return order.index(self)


@dataclass
class Finding:
    """A single observation from one engine about one file."""

    engine: str
    severity: Severity
    message: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class FileResult:
    """Aggregated findings for one scanned file."""

    path: str
    size: int
    sha256: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def verdict(self) -> Severity:
        """The highest severity across all findings (CLEAN if none)."""
        if not self.findings:
            return Severity.CLEAN
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        for finding in d["findings"]:
            finding["severity"] = (
                finding["severity"].value
                if isinstance(finding["severity"], Severity)
                else finding["severity"]
            )
        return d
