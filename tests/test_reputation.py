"""Tests for the local reputation cache and engine."""

from __future__ import annotations

from malscan.engines.reputation import ReputationEngine
from malscan.models import Severity
from malscan.reputation import ReputationStore

PE = b"MZ\x90\x00" + b"\x00" * 64


def test_first_sight_then_known(tmp_path):
    store = ReputationStore(tmp_path / "rep.db")
    a = store.record("a" * 64, size=100, is_executable=True)
    assert a.first_seen is True and a.times_seen == 1
    b = store.record("a" * 64, size=100, is_executable=True)
    assert b.first_seen is False and b.times_seen == 2
    assert b.first_seen_at == a.first_seen_at        # first-seen time is preserved


def test_stats(tmp_path):
    store = ReputationStore(tmp_path / "rep.db")
    store.record("a" * 64, size=10, is_executable=True)
    store.record("a" * 64, size=10, is_executable=True)
    store.record("b" * 64, size=20, is_executable=False)
    stats = store.stats()
    assert stats["total"] == 2
    assert stats["executables"] == 1
    assert stats["most_seen"][0]["sha256"] == "a" * 64
    assert stats["most_seen"][0]["times_seen"] == 2


def test_persists_across_reopen(tmp_path):
    path = tmp_path / "rep.db"
    s1 = ReputationStore(path)
    s1.record("c" * 64, size=5, is_executable=True)
    s1.close()
    s2 = ReputationStore(path)
    again = s2.record("c" * 64, size=5, is_executable=True)
    assert again.first_seen is False and again.times_seen == 2


def test_engine_flags_first_seen_executable(tmp_path):
    eng = ReputationEngine(ReputationStore(tmp_path / "rep.db"))
    findings = eng.scan("new.exe", PE)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].engine == "reputation"
    # Seen again -> no longer first sight -> silent.
    assert eng.scan("new.exe", PE) == []


def test_engine_silent_on_non_executable(tmp_path):
    eng = ReputationEngine(ReputationStore(tmp_path / "rep.db"))
    assert eng.scan("notes.txt", b"plain text, first seen but not an executable") == []


def test_engine_opt_in_only(tmp_path):
    from malscan.scanner import Scanner
    assert Scanner().reputation_engine is None
    scanner = Scanner(reputation_db=tmp_path / "rep.db")
    assert "reputation" in scanner.engine_status
    # The executable is recorded and flagged INFO on first sight.
    result = scanner.scan_bytes("first.exe", PE)
    assert any(f.engine == "reputation" for f in result.findings)
