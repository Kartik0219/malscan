"""YARA rule matching. Compiles all .yar/.yara files under a rules directory
and scans file bytes against them.

YARA is an optional dependency: if yara-python isn't installed, the engine
degrades gracefully to a no-op rather than breaking the whole scan.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

#: Matches MITRE ATT&CK technique IDs like ``T1059`` or ``T1059.001``.
_ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?")


def _parse_attack(value: str) -> list[str]:
    """Pull ATT&CK technique IDs out of a YARA rule's ``attack`` meta string."""
    return _ATTACK_ID.findall(value or "")


class YaraEngine:
    name = "yara"

    def __init__(self, rules_dir: Path):
        self._rules = None
        self._error: str | None = None
        try:
            import yara  # noqa: PLC0415  (optional dependency)
        except ImportError:
            self._error = "yara-python not installed"
            return

        filepaths = {
            p.stem: str(p)
            for p in sorted(rules_dir.glob("*.yar")) + sorted(rules_dir.glob("*.yara"))
        }
        if not filepaths:
            self._error = f"no rule files in {rules_dir}"
            return
        try:
            self._rules = yara.compile(filepaths=filepaths)
        except yara.Error as exc:
            self._error = f"rule compilation failed: {exc}"

    @property
    def available(self) -> bool:
        return self._rules is not None

    @property
    def status(self) -> str:
        return "ready" if self.available else (self._error or "unavailable")

    def scan(self, path: str, data: bytes) -> list[Finding]:
        if self._rules is None:
            return []
        matches = self._rules.match(data=data)
        findings: list[Finding] = []
        for match in matches:
            sev = match.meta.get("severity", "malicious")
            try:
                severity = Severity(sev)
            except ValueError:
                severity = Severity.MALICIOUS
            findings.append(
                Finding(
                    engine=self.name,
                    severity=severity,
                    message=f"YARA rule matched: {match.rule}",
                    detail={
                        "rule": match.rule,
                        "tags": list(match.tags),
                        "description": match.meta.get("description", ""),
                    },
                    techniques=_parse_attack(match.meta.get("attack", "")),
                )
            )
        return findings
