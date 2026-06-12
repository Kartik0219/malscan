"""Tests for malscan engines and scanner, using the harmless EICAR test file."""

from __future__ import annotations

from pathlib import Path

import pytest

from malscan.engines.hashes import HashEngine
from malscan.engines.heuristics import HeuristicEngine, shannon_entropy
from malscan.models import Severity
from malscan.scanner import Scanner

# Standard EICAR anti-malware test string (not real malware).
EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()

SIG_DIR = Path(__file__).resolve().parent.parent / "signatures"


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == pytest.approx(0.0)
    # All 256 byte values once each = maximum entropy of 8 bits/byte.
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_hash_engine_flags_eicar():
    engine = HashEngine(SIG_DIR / "hash_blocklist.txt")
    findings = engine.scan("eicar.txt", EICAR)
    assert any(f.severity == Severity.MALICIOUS for f in findings)


def test_hash_engine_clean_file():
    engine = HashEngine(SIG_DIR / "hash_blocklist.txt")
    assert engine.scan("hello.txt", b"hello world") == []


def test_heuristic_high_entropy_flagged():
    engine = HeuristicEngine()
    findings = engine.scan("packed.bin", bytes(range(256)) * 8)
    assert any(f.severity == Severity.SUSPICIOUS for f in findings)


def test_heuristic_clean_text():
    engine = HeuristicEngine()
    assert engine.scan("note.txt", b"just some plain readable text here") == []


import hashlib


def _scanner_with_blocklisted(tmp_path, payload: bytes, label: str = "test-malware") -> Scanner:
    """Build a Scanner whose signatures dir blocklists `payload`'s hash.

    We deliberately avoid writing the real EICAR file to disk: on Windows the
    host antivirus quarantines it before our scanner can read it, which would
    make these tests flaky. A synthetic blocklisted payload exercises the same
    disk-read + hash-match code path without tripping the host AV.
    """
    sig = tmp_path / "signatures"
    (sig / "yara").mkdir(parents=True)
    digest = hashlib.sha256(payload).hexdigest()
    (sig / "hash_blocklist.txt").write_text(f"{digest}  {label}\n", encoding="utf-8")
    return Scanner(signatures_dir=sig)


def test_scanner_verdict_on_blocklisted(tmp_path):
    payload = b"synthetic-malicious-content-for-testing"
    bad = tmp_path / "sample.bin"
    bad.write_bytes(payload)
    scanner = _scanner_with_blocklisted(tmp_path, payload)
    result = scanner.scan_file(bad)
    assert result.verdict == Severity.MALICIOUS
    assert result.sha256


def test_scanner_clean_file(tmp_path):
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing to see here")
    scanner = Scanner()
    result = scanner.scan_file(clean)
    assert result.verdict == Severity.CLEAN


def test_scanner_directory_walk(tmp_path):
    payload = b"synthetic-malicious-content-for-testing"
    (tmp_path / "a.txt").write_text("clean a")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "sample.bin").write_bytes(payload)
    scanner = _scanner_with_blocklisted(tmp_path, payload)
    # Scan only the content tree, not the signatures dir we just created.
    results = list(scanner.scan_path(tmp_path / "sub")) + list(
        scanner.scan_path(tmp_path / "a.txt")
    )
    verdicts = {Path(r.path).name: r.verdict for r in results}
    assert verdicts["sample.bin"] == Severity.MALICIOUS
    assert verdicts["a.txt"] == Severity.CLEAN
