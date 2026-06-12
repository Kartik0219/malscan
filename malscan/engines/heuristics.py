"""Heuristic detection: Shannon entropy and PE structure analysis.

Neither heuristic is conclusive on its own (legitimate packed installers have
high entropy too), so findings here are INFO/SUSPICIOUS, never MALICIOUS. They
add signal to the aggregate verdict rather than condemning a file outright.
"""

from __future__ import annotations

import math
from collections import Counter

from ..models import Finding, Severity

# Entropy above this (bits/byte, max 8.0) suggests compression/encryption/packing.
ENTROPY_THRESHOLD = 7.2

# Imports commonly abused by malware (injection, dynamic resolution, anti-debug).
SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "SetWindowsHookEx",
    "GetProcAddress",
    "LoadLibraryA",
    "WinExec",
    "ShellExecuteA",
    "IsDebuggerPresent",
    "NtUnmapViewOfSection",
}


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte (0.0-8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


class HeuristicEngine:
    name = "heuristic"

    def scan(self, path: str, data: bytes) -> list[Finding]:
        findings: list[Finding] = []

        entropy = shannon_entropy(data)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append(
                Finding(
                    engine=self.name,
                    severity=Severity.SUSPICIOUS,
                    message=f"High entropy ({entropy:.2f}/8.0) - possibly packed or encrypted",
                    detail={"entropy": round(entropy, 3)},
                )
            )

        findings.extend(self._pe_findings(data))
        return findings

    def _pe_findings(self, data: bytes) -> list[Finding]:
        if not data.startswith(b"MZ"):
            return []
        try:
            import pefile  # noqa: PLC0415  (optional dependency, lazy import)
        except ImportError:
            return [
                Finding(
                    engine=self.name,
                    severity=Severity.INFO,
                    message="PE file detected; install 'pefile' for deeper analysis",
                )
            ]

        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
        except Exception as exc:  # malformed PE is itself notable
            return [
                Finding(
                    engine=self.name,
                    severity=Severity.SUSPICIOUS,
                    message=f"Malformed PE header: {exc}",
                )
            ]

        flagged: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imp in entry.imports:
                if imp.name:
                    fn = imp.name.decode("utf-8", "ignore")
                    if fn in SUSPICIOUS_IMPORTS:
                        flagged.append(fn)

        findings: list[Finding] = []
        if flagged:
            findings.append(
                Finding(
                    engine=self.name,
                    severity=Severity.SUSPICIOUS,
                    message=f"Imports often abused by malware: {', '.join(sorted(set(flagged)))}",
                    detail={"imports": sorted(set(flagged))},
                )
            )
        return findings
