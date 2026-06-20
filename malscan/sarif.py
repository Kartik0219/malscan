"""Render scan results as a SARIF 2.1.0 log.

SARIF (Static Analysis Results Interchange Format) is the lingua franca for
security tooling. Emitting it lets malscan's findings be uploaded to GitHub
code scanning (``github/codeql-action/upload-sarif``) so they surface as alerts
in a repository's **Security** tab — the same place CodeQL and other scanners
report — and feed any other SARIF-aware dashboard.

Each engine *finding* becomes one SARIF ``result``; each engine becomes a
reporting rule. Severity maps onto SARIF levels (and GitHub's
``security-severity`` band) like so:

    malicious -> error    (security-severity 9.0)
    suspicious -> warning (security-severity 5.5)
    info -> note          (security-severity 2.0)

The serializer is pure stdlib and takes the same ``report`` dict the JSON/HTML
reporters consume, so it adds no dependencies and no new scan logic.
"""

from __future__ import annotations

import hashlib
import json

from .models import Severity

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Kartik0219/malscan"

#: malscan verdict -> SARIF result level.
_LEVEL = {"malicious": "error", "suspicious": "warning", "info": "note", "clean": "none"}

#: malscan verdict -> GitHub code-scanning ``security-severity`` (0.0-10.0).
_SECURITY_SEVERITY = {"malicious": "9.0", "suspicious": "5.5", "info": "2.0", "clean": "0.0"}

#: Human descriptions for each engine's reporting rule.
_RULE_DESC = {
    "hash": "File matches a known-malicious hash blocklist",
    "heuristic": "Static heuristic traits (entropy, suspicious imports) suggest packing or injection",
    "filetype": "File type contradicts the type its name claims (masquerading or double extension)",
    "yara": "Matched a YARA detection rule",
    "virustotal": "VirusTotal multi-engine consensus",
    "archive": "Archive-walk note (truncation, decompression budget, or unreadable member)",
}


def _rank(severity: str) -> int:
    try:
        return Severity(severity).rank
    except ValueError:
        return 0


def _uri(path: str) -> str:
    """Normalise a filesystem path to a forward-slash URI reference."""
    return path.replace("\\", "/")


def render_sarif(report: dict) -> str:
    """Serialise a malscan ``report`` dict into a SARIF 2.1.0 JSON string."""
    results_in = report.get("results", [])

    # Pre-compute the highest severity each engine emitted, so a rule's
    # security-severity reflects what that engine actually found this run.
    engine_max: dict[str, str] = {}
    for result in results_in:
        for finding in result.get("findings", []):
            engine = finding.get("engine", "unknown")
            sev = finding.get("severity", "info")
            if engine not in engine_max or _rank(sev) > _rank(engine_max[engine]):
                engine_max[engine] = sev

    rule_index: dict[str, int] = {}
    rules: list[dict] = []

    def ensure_rule(engine: str) -> int:
        if engine in rule_index:
            return rule_index[engine]
        idx = len(rules)
        rule_index[engine] = idx
        worst = engine_max.get(engine, "info")
        rules.append({
            "id": engine,
            "name": f"{engine}-detection",
            "shortDescription": {"text": _RULE_DESC.get(engine, f"{engine} engine finding")},
            "helpUri": INFORMATION_URI,
            "properties": {
                "tags": ["security", "malware"],
                "security-severity": _SECURITY_SEVERITY.get(worst, "2.0"),
            },
        })
        return idx

    sarif_results: list[dict] = []
    for result in results_in:
        path = result.get("path", "")
        for finding in result.get("findings", []):
            engine = finding.get("engine", "unknown")
            sev = finding.get("severity", "info")
            message = finding.get("message", "")
            idx = ensure_rule(engine)

            fingerprint = hashlib.sha256(
                f"{path}|{engine}|{message}".encode("utf-8", "replace")
            ).hexdigest()

            sarif_result = {
                "ruleId": engine,
                "ruleIndex": idx,
                "level": _LEVEL.get(sev, "note"),
                "message": {"text": f"[{sev}] {message}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(path)},
                        # Binary files have no meaningful line; anchor at 1 so the
                        # alert renders as a file-level finding in code scanning.
                        "region": {"startLine": 1},
                    }
                }],
                "partialFingerprints": {"malscanFinding/v1": fingerprint},
            }

            techniques = finding.get("techniques") or []
            if techniques:
                sarif_result["properties"] = {"mitreAttackTechniques": techniques}

            sarif_results.append(sarif_result)

    sarif = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "malscan",
                    "informationUri": INFORMATION_URI,
                    "version": report.get("version", ""),
                    "rules": rules,
                }
            },
            "results": sarif_results,
        }],
    }
    return json.dumps(sarif, indent=2)
