"""Tests for the fanotify on-access backend's *testable* logic.

The live kernel path (fanotify_init/mark/read/respond) is Linux+root only and is
NOT exercised here. These tests cover the pure, portable pieces — event-struct
parsing and the allow/deny policy — plus the platform guard.
"""

from __future__ import annotations

import struct
import sys

import pytest

from malscan import fanotify
from malscan.fanotify import (
    FAN_OPEN_PERM,
    FANOTIFY_METADATA_VERSION,
    FanotifyEvent,
    FanotifyMonitor,
    decide,
    parse_event,
)
from malscan.models import FileResult, Finding, Severity


def _meta(mask=FAN_OPEN_PERM, fd=7, pid=1234, event_len=fanotify.META_LEN, vers=FANOTIFY_METADATA_VERSION):
    return struct.pack("<IBBHQii", event_len, vers, 0, fanotify.META_LEN, mask, fd, pid)


def test_parse_event_roundtrip():
    ev = parse_event(_meta(mask=FAN_OPEN_PERM, fd=9, pid=42))
    assert ev.fd == 9 and ev.pid == 42
    assert ev.is_perm is True
    assert ev.event_len == fanotify.META_LEN


def test_parse_event_rejects_short_buffer():
    with pytest.raises(ValueError):
        parse_event(b"\x00\x00\x00")


def test_parse_event_rejects_bad_version():
    with pytest.raises(ValueError):
        parse_event(_meta(vers=99))


def test_non_perm_event_flag():
    ev = parse_event(_meta(mask=0))
    assert ev.is_perm is False


def _result(verdict: Severity, error=None) -> FileResult:
    f = FileResult(path="x", size=1, sha256="a", error=error)
    if verdict != Severity.CLEAN and error is None:
        f.findings.append(Finding("hash", verdict, "msg"))
    return f


def test_decide_blocks_malicious_allows_clean():
    assert decide(_result(Severity.MALICIOUS)) is False
    assert decide(_result(Severity.CLEAN)) is True
    assert decide(_result(Severity.SUSPICIOUS)) is True          # not by default
    assert decide(_result(Severity.SUSPICIOUS), block_suspicious=True) is False


def test_decide_fails_open_on_error():
    assert decide(_result(Severity.CLEAN, error="unreadable")) is True


def test_handle_event_uses_scanner_and_policy(monkeypatch):
    class FakeScanner:
        def scan_file(self, path):
            return _result(Severity.MALICIOUS)

    mon = FanotifyMonitor(FakeScanner())
    monkeypatch.setattr(mon, "_path_for", lambda event: "/tmp/evil.bin")
    ev = FanotifyEvent(event_len=24, version=3, mask=FAN_OPEN_PERM, fd=5, pid=1)
    assert mon.handle_event(ev) is False        # malicious -> deny


def test_handle_event_fails_open_when_path_unresolved(monkeypatch):
    mon = FanotifyMonitor(object())
    monkeypatch.setattr(mon, "_path_for", lambda event: None)
    ev = FanotifyEvent(event_len=24, version=3, mask=FAN_OPEN_PERM, fd=5, pid=1)
    assert mon.handle_event(ev) is True


def test_is_supported_false_off_linux():
    if not sys.platform.startswith("linux"):
        assert fanotify.is_supported() is False


def test_run_raises_cleanly_when_unsupported():
    if not fanotify.is_supported():
        with pytest.raises(fanotify.FanotifyError):
            FanotifyMonitor(object()).run(["/"])
