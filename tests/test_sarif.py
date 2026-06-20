"""Tests for the SARIF 2.1.0 reporter."""

from __future__ import annotations

import json

from malscan.sarif import render_sarif


def _report() -> dict:
    """A report dict shaped exactly like cli._cmd_scan builds."""
    return {
        "tool": "malscan",
        "version": "0.5.0",
        "target": "downloads",
        "results": [
            {
                "path": r"C:\downloads\invoice.pdf",
                "size": 4096,
                "sha256": "ab" * 32,
                "verdict": "suspicious",
                "techniques": ["T1036.008"],
                "findings": [
                    {"engine": "filetype", "severity": "suspicious",
                     "message": "Name claims a .pdf file, but the contents are a Windows executable (PE)",
                     "detail": {}, "techniques": ["T1036.008"]},
                ],
            },
            {
                "path": "downloads/evil.bin",
                "size": 120,
                "sha256": "cd" * 32,
                "verdict": "malicious",
                "techniques": [],
                "findings": [
                    {"engine": "hash", "severity": "malicious",
                     "message": "Matches known-bad hash: EICAR", "detail": {}, "techniques": []},
                ],
            },
            {  # clean file -> contributes no results
                "path": "downloads/notes.txt", "size": 10, "sha256": "ef" * 32,
                "verdict": "clean", "techniques": [], "findings": [],
            },
        ],
    }


def test_output_is_valid_json_and_sarif_shell():
    doc = json.loads(render_sarif(_report()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    assert len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "malscan"
    assert driver["version"] == "0.5.0"


def test_one_result_per_finding_clean_files_excluded():
    doc = json.loads(render_sarif(_report()))
    results = doc["runs"][0]["results"]
    assert len(results) == 2  # the clean .txt produces nothing


def test_severity_maps_to_sarif_level():
    results = json.loads(render_sarif(_report()))["runs"][0]["results"]
    by_rule = {r["ruleId"]: r for r in results}
    assert by_rule["filetype"]["level"] == "warning"   # suspicious
    assert by_rule["hash"]["level"] == "error"         # malicious


def test_rules_carry_security_severity():
    driver = json.loads(render_sarif(_report()))["runs"][0]["tool"]["driver"]
    rules = {r["id"]: r for r in driver["rules"]}
    assert rules["hash"]["properties"]["security-severity"] == "9.0"
    assert rules["filetype"]["properties"]["security-severity"] == "5.5"
    # every result's ruleIndex points at a real rule
    for r in json.loads(render_sarif(_report()))["runs"][0]["results"]:
        assert driver["rules"][r["ruleIndex"]]["id"] == r["ruleId"]


def test_location_uri_is_forward_slashed():
    results = json.loads(render_sarif(_report()))["runs"][0]["results"]
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results]
    assert "C:/downloads/invoice.pdf" in uris
    assert all("\\" not in u for u in uris)


def test_fingerprints_and_mitre_properties():
    results = json.loads(render_sarif(_report()))["runs"][0]["results"]
    ft = next(r for r in results if r["ruleId"] == "filetype")
    assert ft["partialFingerprints"]["malscanFinding/v1"]
    assert ft["properties"]["mitreAttackTechniques"] == ["T1036.008"]


def test_empty_report_is_well_formed():
    doc = json.loads(render_sarif({"version": "0.5.0", "results": []}))
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_end_to_end_from_scanner():
    from malscan.scanner import Scanner
    pe_as_pdf = b"MZ\x90\x00" + b"\x00" * 64
    result = Scanner().scan_bytes("statement.pdf", pe_as_pdf)
    report = {"version": "0.5.0", "results": [result.to_dict()]}
    doc = json.loads(render_sarif(report))
    assert any(r["ruleId"] == "filetype" for r in doc["runs"][0]["results"])
