"""Tests for the VirusTotal engine. All HTTP is mocked - no real network calls."""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from malscan.engines import virustotal as vt
from malscan.engines.virustotal import VirusTotalEngine
from malscan.models import Severity
from malscan.scanner import Scanner


class _FakeResp:
    def __init__(self, payload: dict):
        self._data = json.dumps(payload).encode()

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _stats_payload(malicious=0, suspicious=0, harmless=0, undetected=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                }
            }
        }
    }


def test_vt_malicious_consensus(monkeypatch):
    monkeypatch.setattr(
        vt.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResp(_stats_payload(malicious=58, harmless=4, undetected=8)),
    )
    findings = VirusTotalEngine("fake-key").scan("x", b"data")
    assert len(findings) == 1
    assert findings[0].severity == Severity.MALICIOUS
    assert findings[0].detail["malicious"] == 58


def test_vt_low_detections_are_suspicious(monkeypatch):
    monkeypatch.setattr(
        vt.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResp(_stats_payload(malicious=1, harmless=60)),
    )
    findings = VirusTotalEngine("fake-key").scan("x", b"data")
    assert findings[0].severity == Severity.SUSPICIOUS


def test_vt_clean_known_file_is_info(monkeypatch):
    monkeypatch.setattr(
        vt.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResp(_stats_payload(harmless=70)),
    )
    findings = VirusTotalEngine("fake-key").scan("x", b"data")
    assert findings[0].severity == Severity.INFO


def test_vt_unknown_file_404_returns_nothing(monkeypatch):
    def raise_404(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(vt.urllib.request, "urlopen", raise_404)
    assert VirusTotalEngine("fake-key").scan("x", b"data") == []


def test_vt_rate_limit_is_info(monkeypatch):
    def raise_429(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, io.BytesIO(b""))

    monkeypatch.setattr(vt.urllib.request, "urlopen", raise_429)
    findings = VirusTotalEngine("fake-key").scan("x", b"data")
    assert findings[0].severity == Severity.INFO
    assert "rate limit" in findings[0].message.lower()


def test_scanner_includes_vt_only_with_key():
    assert "virustotal" not in Scanner().engine_status
    assert "virustotal" in Scanner(vt_api_key="fake-key").engine_status
