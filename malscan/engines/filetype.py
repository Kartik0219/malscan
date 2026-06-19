"""File-type masquerading detection: does the file *look* like what it claims?

A favourite delivery trick is to dress an executable up as something harmless —
``invoice.pdf`` that is really a Windows ``.exe``, or ``photo.jpg.scr`` relying on
the OS hiding the final extension. The bytes betray the lie: a real PDF starts
with ``%PDF``, a PE with ``MZ``. This engine compares the *claimed* type (from the
filename) against the *actual* type (from the magic bytes) and flags two classic
masquerades:

* **magic/extension mismatch** — a lure extension (``.pdf``, ``.jpg``, ``.docx``…)
  whose contents are actually a compiled executable (PE/ELF/Mach-O). MITRE
  ``T1036.008`` (Masquerade File Type).
* **double extension** — ``something.<lure>.<dangerous>`` such as
  ``invoice.pdf.exe``. MITRE ``T1036.007`` (Double File Extension).

Like the heuristic engine this is *inference*, not a signature, so it never
returns MALICIOUS — it raises a single SUSPICIOUS finding. It is kept deliberately
conservative (only compiled-executable content counts as a mismatch, and only
document/media lure extensions trigger it) so false positives stay near zero. It
is pure stdlib and touches no filesystem path, so it is safe in the web demo.
"""

from __future__ import annotations

from ..models import Finding, Severity

#: Magic-byte prefixes that mean "this is a compiled, runnable binary", with a
#: human label. Only binaries count: scripts (``#!``) are intentionally excluded
#: to avoid flagging the common, harmless case of a snippet pasted into a ``.txt``.
EXECUTABLE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ",            "a Windows executable (PE)"),
    (b"\x7fELF",       "a Linux/Unix executable (ELF)"),
    (b"\xfe\xed\xfa\xce", "a macOS executable (Mach-O)"),
    (b"\xfe\xed\xfa\xcf", "a macOS executable (Mach-O)"),
    (b"\xcf\xfa\xed\xfe", "a macOS executable (Mach-O)"),
    (b"\xce\xfa\xed\xfe", "a macOS executable (Mach-O)"),
)

#: Extensions a victim is meant to read as harmless (documents, media, data).
#: A compiled executable wearing one of these is the masquerade we care about.
LURE_EXTENSIONS: frozenset[str] = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt",
    "txt", "csv", "log", "md", "json", "xml", "html", "htm", "yaml", "yml",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "svg", "ico", "tif", "tiff",
    "mp3", "mp4", "avi", "mov", "mkv", "wav", "flac", "webm",
    "zip", "rar", "7z", "gz", "tar", "bz2", "xz",
})

#: Final extensions that the OS will actually execute. Used for the
#: double-extension trick where a lure extension precedes one of these.
DANGEROUS_EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset({
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "jar", "msi", "hta", "cpl", "lnk", "scf", "reg", "dll",
})

#: MITRE ATT&CK techniques this engine can emit. Asserted against the catalog.
MASQUERADE_TECHNIQUE = "T1036.008"       # Masquerade File Type
DOUBLE_EXTENSION_TECHNIQUE = "T1036.007"  # Double File Extension


def _leaf_name(path: str) -> str:
    """Innermost filename for ``path`` — strips directories and archive prefixes.

    Archive members compose as ``container!member`` (and the member may itself
    contain directories), e.g. ``downloads/bundle.zip!docs/invoice.pdf`` -> the
    name we judge is ``invoice.pdf``.
    """
    name = path.rsplit("!", 1)[-1]
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def _actual_executable(data: bytes) -> str | None:
    """Return the executable label if ``data`` begins with a known binary magic."""
    for magic, label in EXECUTABLE_SIGNATURES:
        if data.startswith(magic):
            return label
    return None


class FileTypeEngine:
    """Detects files whose real type contradicts the type their name claims."""

    name = "filetype"

    def scan(self, path: str, data: bytes) -> list[Finding]:
        leaf = _leaf_name(path)
        parts = leaf.lower().split(".")
        if len(parts) < 2:
            return []  # no extension -> nothing is being claimed

        ext = parts[-1]
        prev_ext = parts[-2] if len(parts) >= 3 else ""
        findings: list[Finding] = []

        # 1) Lure extension, but the bytes are a compiled executable.
        if ext in LURE_EXTENSIONS:
            actual = _actual_executable(data)
            if actual is not None:
                findings.append(Finding(
                    engine=self.name,
                    severity=Severity.SUSPICIOUS,
                    message=(
                        f"Name claims a .{ext} file, but the contents are {actual} "
                        "- possible file-type masquerading"
                    ),
                    detail={"claimed_extension": ext, "actual_type": actual,
                            "kind": "magic-mismatch"},
                    techniques=[MASQUERADE_TECHNIQUE],
                ))

        # 2) Double extension: a lure extension immediately before an executable one.
        if ext in DANGEROUS_EXECUTABLE_EXTENSIONS and prev_ext in LURE_EXTENSIONS:
            findings.append(Finding(
                engine=self.name,
                severity=Severity.SUSPICIOUS,
                message=(
                    f"Double extension '.{prev_ext}.{ext}' disguises an executable "
                    f"(.{ext}) as a .{prev_ext} file"
                ),
                detail={"claimed_extension": prev_ext, "real_extension": ext,
                        "kind": "double-extension"},
                techniques=[DOUBLE_EXTENSION_TECHNIQUE],
            ))

        return findings
