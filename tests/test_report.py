"""Tests for HTML report rendering."""

from __future__ import annotations

from malscan.report import render_html


def _report() -> dict:
    return {
        "tool": "malscan",
        "version": "0.1.0",
        "target": "samples",
        "generated_at": "2026-06-12 10:00:00",
        "elapsed_seconds": 0.12,
        "engine_status": {"hash": "ready", "yara": "ready"},
        "summary": {"malicious": 1, "suspicious": 0, "info": 0, "clean": 1},
        "results": [
            {"path": "clean.txt", "size": 10, "sha256": "a" * 64,
             "findings": [], "error": None, "verdict": "clean"},
            {"path": "bad.exe", "size": 2048, "sha256": "b" * 64,
             "findings": [{"engine": "hash", "severity": "malicious",
                           "message": "Matches known-bad hash", "detail": {}}],
             "error": None, "verdict": "malicious"},
        ],
    }


def test_render_html_is_wellformed():
    out = render_html(_report())
    assert out.startswith("<!DOCTYPE html>")
    assert "</html>" in out
    assert "mal<span>scan</span>" in out
    assert "bad.exe" in out
    assert "Matches known-bad hash" in out
    assert "samples" in out


def test_malicious_sorted_above_clean():
    out = render_html(_report())
    assert out.index("bad.exe") < out.index("clean.txt")


def test_size_has_thousands_separator():
    out = render_html(_report())
    assert "2,048" in out


def test_filename_is_html_escaped_against_xss():
    rep = _report()
    rep["results"][0]["path"] = "<script>alert('xss')</script>.txt"
    out = render_html(rep)
    # The raw script tag must NOT appear as live markup...
    assert "<script>alert('xss')</script>" not in out
    # ...it must be escaped instead.
    assert "&lt;script&gt;" in out


def test_finding_message_is_escaped():
    rep = _report()
    rep["results"][1]["findings"][0]["message"] = "<img src=x onerror=alert(1)>"
    out = render_html(rep)
    assert "<img src=x onerror=alert(1)>" not in out
    assert "&lt;img" in out


def test_empty_results():
    rep = _report()
    rep["results"] = []
    rep["summary"] = {"malicious": 0, "suspicious": 0, "info": 0, "clean": 0}
    out = render_html(rep)
    assert "No files scanned." in out
