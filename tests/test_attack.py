"""Tests for MITRE ATT&CK technique tagging (malscan.attack + engine wiring)."""

from __future__ import annotations

import re

from malscan import attack
from malscan.engines.heuristics import HeuristicEngine, IMPORT_TECHNIQUES
from malscan.engines.yara_engine import _parse_attack
from malscan.models import FileResult, Finding, Severity

_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def test_catalog_ids_are_wellformed():
    for key, tech in attack.TECHNIQUES.items():
        assert _ID_RE.match(key), f"bad technique id: {key}"
        assert tech.id == key
        assert tech.name and tech.tactic


def test_url_format():
    assert attack.url("T1027") == "https://attack.mitre.org/techniques/T1027/"
    assert attack.url("T1059.001") == "https://attack.mitre.org/techniques/T1059/001/"


def test_label_and_enrich():
    assert attack.label("T1059.001") == "T1059.001 PowerShell"
    assert attack.label("T9999") == "T9999"  # unknown id -> bare id
    enriched = attack.enrich(["T1027"])
    assert enriched[0]["name"] == "Obfuscated Files or Information"
    assert enriched[0]["url"].endswith("/T1027/")


def test_engine_referenced_ids_are_in_catalog():
    # Every technique the heuristics engine can emit must exist in the catalog.
    for tid in set(IMPORT_TECHNIQUES.values()) | {"T1027", "T1027.002"}:
        assert tid in attack.TECHNIQUES, f"{tid} missing from catalog"


def test_parse_attack_meta():
    assert _parse_attack("T1059.001, T1105") == ["T1059.001", "T1105"]
    assert _parse_attack("") == []
    assert _parse_attack("see T1027 only") == ["T1027"]


def test_high_entropy_file_tagged_t1027():
    # Uniform byte distribution -> entropy 8.0 -> SUSPICIOUS finding tagged T1027.
    data = bytes(range(256)) * 16  # 4096 bytes, deterministic, not a known magic
    findings = HeuristicEngine().scan("rand.bin", data)
    assert findings, "expected a heuristic finding on high-entropy data"
    assert "T1027" in findings[0].techniques


def test_techniques_flow_into_to_dict():
    fr = FileResult(
        path="x", size=1, sha256="a",
        findings=[
            Finding("heuristic", Severity.SUSPICIOUS, "msg", techniques=["T1027"]),
            Finding("yara", Severity.MALICIOUS, "msg2", techniques=["T1059.001", "T1027"]),
        ],
    )
    assert fr.techniques == ["T1027", "T1059.001"]  # unique + sorted
    d = fr.to_dict()
    assert d["techniques"] == ["T1027", "T1059.001"]
    assert d["findings"][0]["techniques"] == ["T1027"]
