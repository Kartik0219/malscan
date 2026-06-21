"""Tests for the logical (multi-condition) signature engine."""

from __future__ import annotations

import pytest

from malscan import attack
from malscan.engines.logical import (
    LogicalSignatureEngine,
    compile_pattern,
    evaluate,
    load_rules,
    parse_expression,
)
from malscan.models import Severity
from malscan.scanner import Scanner

SIG_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent / "signatures"


# ── sub-signature compilation ──

def test_str_pattern_matches_literal_bytes():
    pat = compile_pattern("str:VirtualAllocEx")
    assert pat.search(b"...VirtualAllocEx...")
    assert not pat.search(b"nothing here")


def test_hex_pattern_exact():
    assert compile_pattern("4d5a").search(b"MZ\x00")
    assert not compile_pattern("4d5a").search(b"ZM")


def test_hex_wildcard_and_gap():
    assert compile_pattern("4d??5a").search(b"M\x99Z")        # ?? = any single byte
    assert compile_pattern("4d5a*504500").search(b"MZ____PE\x00\x00")  # * = gap


def test_bad_hex_raises():
    with pytest.raises(ValueError):
        compile_pattern("4dzz")
    with pytest.raises(ValueError):
        compile_pattern("4d5")  # dangling nibble


# ── boolean expression parser / evaluator ──

def test_expression_precedence_and_parens():
    ast = parse_expression("(0 | 1) & 2", 3)
    assert evaluate(ast, [True, False, True]) is True
    assert evaluate(ast, [True, False, False]) is False
    assert evaluate(ast, [False, False, True]) is False


def test_and_or_basic():
    assert evaluate(parse_expression("0 & 1", 2), [True, True]) is True
    assert evaluate(parse_expression("0 & 1", 2), [True, False]) is False
    assert evaluate(parse_expression("0 | 1", 2), [False, True]) is True


def test_expression_rejects_bad_index_and_syntax():
    with pytest.raises(ValueError):
        parse_expression("0 & 5", 2)      # index out of range
    with pytest.raises(ValueError):
        parse_expression("0 &", 2)        # dangling operator
    with pytest.raises(ValueError):
        parse_expression("(0 & 1", 2)     # unbalanced parens


# ── bundled rules + engine ──

def test_bundled_rules_load_without_errors():
    rules, errors = load_rules(SIG_DIR / "logical")
    assert rules, "expected bundled demo rules to load"
    assert errors == [], f"demo rules had parse errors: {errors}"


def test_injection_trio_requires_all_three():
    eng = LogicalSignatureEngine(SIG_DIR / "logical")
    full = b"MZ" + b"\x00" * 8 + b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"
    findings = eng.scan("evil.exe", full)
    assert any(f.detail["rule"] == "PE_Injection_Trio" for f in findings)
    assert all(f.severity == Severity.SUSPICIOUS for f in findings
               if f.detail["rule"] == "PE_Injection_Trio")
    # Missing one import -> the AND fails, no injection-trio finding.
    partial = b"MZ" + b"\x00" * 8 + b"VirtualAllocEx WriteProcessMemory"
    assert not any(f.detail["rule"] == "PE_Injection_Trio"
                   for f in eng.scan("x.exe", partial))


def test_eicar_logical_is_malicious():
    eicar = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    findings = LogicalSignatureEngine(SIG_DIR / "logical").scan("eicar.com", eicar)
    assert any(f.severity == Severity.MALICIOUS for f in findings)


def test_clean_data_no_match():
    assert LogicalSignatureEngine(SIG_DIR / "logical").scan("a.txt", b"hello world") == []


def test_malformed_rules_are_skipped_not_fatal(tmp_path):
    d = tmp_path / "logical"
    d.mkdir()
    (d / "x.msig").write_text(
        "good ; suspicious ; ; 0 ; str:abc\n"
        "bad-no-fields ; suspicious\n"            # too few fields -> skipped
        "bad-expr ; ; ; 9 & 9 ; str:z\n",         # bad index -> skipped
        encoding="utf-8",
    )
    rules, errors = load_rules(d)
    assert len(rules) == 1 and len(errors) == 2


def test_engine_wired_into_scanner():
    status = Scanner().engine_status
    assert "logical" in status and status["logical"].startswith("ready")


def test_demo_rule_techniques_are_in_catalog():
    rules, _ = load_rules(SIG_DIR / "logical")
    for rule in rules:
        for tid in rule.techniques:
            assert tid in attack.TECHNIQUES, f"{tid} missing from catalog"
