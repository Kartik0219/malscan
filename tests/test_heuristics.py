"""Tests for the ported weighted-trait heuristic engine."""

from __future__ import annotations

import gzip
import os

from malscan.engines.heuristics import HeuristicEngine, shannon_entropy
from malscan.models import Severity


def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert round(shannon_entropy(bytes(range(256))), 6) == 8.0


def test_high_entropy_flagged_suspicious():
    eng = HeuristicEngine()
    findings = eng.scan("packed.bin", bytes(range(256)) * 8)
    assert len(findings) == 1
    assert findings[0].severity == Severity.SUSPICIOUS
    assert "entropy" in findings[0].message.lower()


def test_small_files_are_not_entropy_judged():
    eng = HeuristicEngine()
    # Below MIN_SIZE_FOR_ENTROPY even though bytes are random.
    assert eng.scan("tiny.bin", os.urandom(64)) == []


def test_clean_text_has_no_findings():
    eng = HeuristicEngine()
    assert eng.scan("note.txt", b"just some plain readable text here, nothing odd at all") == []


def test_compressed_format_is_exempt_from_entropy():
    # A gzip stream of random data is high-entropy and >256 bytes, but its magic
    # marks it compressed-by-design, so the whole-file entropy check stays quiet.
    blob = gzip.compress(os.urandom(4096))
    assert len(blob) > 256
    eng = HeuristicEngine()
    assert eng.scan("payload.gz", blob) == []


def test_png_magic_is_exempt():
    # Fake PNG header followed by high-entropy bytes — exempt by magic.
    blob = b"\x89PNG\r\n\x1a\n" + os.urandom(2048)
    eng = HeuristicEngine()
    assert eng.scan("image.png", blob) == []


def test_report_threshold_validation():
    import pytest
    with pytest.raises(ValueError):
        HeuristicEngine(report_threshold=0.0)
    with pytest.raises(ValueError):
        HeuristicEngine(report_threshold=1.5)
