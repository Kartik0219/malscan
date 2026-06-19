"""Tests for the file-type masquerading engine."""

from __future__ import annotations

from malscan import attack
from malscan.engines.filetype import (
    FileTypeEngine,
    MASQUERADE_TECHNIQUE,
    DOUBLE_EXTENSION_TECHNIQUE,
)
from malscan.models import Severity

PE = b"MZ\x90\x00" + b"\x00" * 64       # Windows executable magic
ELF = b"\x7fELF" + b"\x00" * 64          # Linux executable magic
MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 64  # macOS Mach-O (64-bit LE)


def test_pe_disguised_as_pdf_is_flagged():
    findings = FileTypeEngine().scan("invoice.pdf", PE)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.SUSPICIOUS
    assert f.engine == "filetype"
    assert f.detail["kind"] == "magic-mismatch"
    assert f.detail["claimed_extension"] == "pdf"
    assert MASQUERADE_TECHNIQUE in f.techniques


def test_elf_and_macho_lures_are_flagged():
    assert FileTypeEngine().scan("photo.jpg", ELF)[0].severity == Severity.SUSPICIOUS
    assert FileTypeEngine().scan("report.docx", MACHO)[0].severity == Severity.SUSPICIOUS


def test_correctly_named_executable_is_silent():
    # A PE that honestly calls itself .exe is not masquerading.
    assert FileTypeEngine().scan("setup.exe", PE) == []
    assert FileTypeEngine().scan("driver.dll", PE) == []


def test_real_document_is_silent():
    # Genuine PDF magic in a .pdf file — no mismatch.
    assert FileTypeEngine().scan("real.pdf", b"%PDF-1.7\n...") == []


def test_office_file_is_a_zip_not_an_executable():
    # .docx/.xlsx legitimately *are* zip containers (PK magic); not executables.
    assert FileTypeEngine().scan("budget.xlsx", b"PK\x03\x04rest") == []


def test_double_extension_is_flagged_regardless_of_content():
    # The name alone is the tell here; content can be anything.
    findings = FileTypeEngine().scan("invoice.pdf.exe", b"anything")
    assert len(findings) == 1
    assert findings[0].detail["kind"] == "double-extension"
    assert findings[0].detail["claimed_extension"] == "pdf"
    assert findings[0].detail["real_extension"] == "exe"
    assert DOUBLE_EXTENSION_TECHNIQUE in findings[0].techniques


def test_benign_double_extension_is_silent():
    # .tar.gz is a normal compound extension, not a disguise.
    assert FileTypeEngine().scan("backup.tar.gz", b"\x1f\x8bcompressed") == []


def test_no_extension_is_silent():
    assert FileTypeEngine().scan("README", PE) == []


def test_archive_member_name_is_resolved():
    # Engine should judge the innermost member name, not the container path.
    findings = FileTypeEngine().scan("dl/bundle.zip!docs/resume.pdf", PE)
    assert len(findings) == 1
    assert findings[0].detail["claimed_extension"] == "pdf"


def test_techniques_are_in_catalog():
    for tid in (MASQUERADE_TECHNIQUE, DOUBLE_EXTENSION_TECHNIQUE):
        assert tid in attack.TECHNIQUES, f"{tid} missing from ATT&CK catalog"


def test_engine_is_wired_into_scanner():
    from malscan.scanner import Scanner
    result = Scanner().scan_bytes("statement.pdf", PE)
    assert result.verdict == Severity.SUSPICIOUS
    assert any(f.engine == "filetype" for f in result.findings)
    assert "filetype" in Scanner().engine_status
