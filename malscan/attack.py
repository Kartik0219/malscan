"""A small, curated slice of the MITRE ATT&CK catalog.

malscan's engines tag findings with ATT&CK technique IDs (e.g. ``T1059.001``)
so a verdict speaks the same language as enterprise EDR/SIEM tooling. This module
is just the lookup table: ID -> human name + tactic + canonical URL. It is
deliberately tiny (only the techniques our engines can map to today) rather than
a full ATT&CK mirror; extend ``TECHNIQUES`` as detections grow.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


#: ID -> Technique. Keep in sync with the engine mappings (heuristics imports,
#: YARA rule ``attack`` meta). Tests assert every engine-referenced ID lives here.
TECHNIQUES: dict[str, "Technique"] = {
    "T1027":     Technique("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    "T1027.002": Technique("T1027.002", "Software Packing", "Defense Evasion"),
    "T1036.007": Technique("T1036.007", "Double File Extension", "Defense Evasion"),
    "T1036.008": Technique("T1036.008", "Masquerade File Type", "Defense Evasion"),
    "T1055":     Technique("T1055", "Process Injection", "Defense Evasion"),
    "T1056.001": Technique("T1056.001", "Keylogging", "Collection"),
    "T1059":     Technique("T1059", "Command and Scripting Interpreter", "Execution"),
    "T1059.001": Technique("T1059.001", "PowerShell", "Execution"),
    "T1105":     Technique("T1105", "Ingress Tool Transfer", "Command and Control"),
    "T1622":     Technique("T1622", "Debugger Evasion", "Defense Evasion"),
}


def url(technique_id: str) -> str:
    """Canonical attack.mitre.org URL for a technique or sub-technique ID.

    ``T1059`` -> ``.../techniques/T1059/``;
    ``T1059.001`` -> ``.../techniques/T1059/001/``.
    """
    base, _, sub = technique_id.partition(".")
    tail = f"{sub}/" if sub else ""
    return f"https://attack.mitre.org/techniques/{base}/{tail}"


def name(technique_id: str) -> str:
    """Human-readable technique name, falling back to the bare ID if unknown."""
    tech = TECHNIQUES.get(technique_id)
    return tech.name if tech else technique_id


def label(technique_id: str) -> str:
    """Compact ``"T1059.001 PowerShell"`` label for CLI output / badges."""
    tech = TECHNIQUES.get(technique_id)
    return f"{technique_id} {tech.name}" if tech else technique_id


def enrich(ids: list[str]) -> list[dict[str, str]]:
    """Expand technique IDs into ``{id, name, tactic, url}`` dicts for reports."""
    out: list[dict[str, str]] = []
    for tid in ids:
        tech = TECHNIQUES.get(tid)
        out.append(
            {
                "id": tid,
                "name": tech.name if tech else tid,
                "tactic": tech.tactic if tech else "",
                "url": url(tid),
            }
        )
    return out
