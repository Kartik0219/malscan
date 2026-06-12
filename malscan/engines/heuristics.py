"""Heuristic static analysis: entropy and PE-import risk scoring.

Ported from the Mongoose project and adapted to malscan's engine interface.

Unlike signatures, heuristics describe *traits* that malware tends to share
with some legitimate software - packed/encrypted payloads (high entropy) and
imports associated with code injection or downloading. Each observed trait
contributes a weight; the capped sum is a risk score in ``[0, 1]``. Because
traits are circumstantial, this engine never returns MALICIOUS: when the score
crosses ``report_threshold`` it emits a single SUSPICIOUS finding carrying the
score and the contributing traits, and otherwise stays silent.

Expect false positives by design: debuggers legitimately import injection APIs.
That is why the verdict stays soft. Compressed/media files are exempt from the
whole-file entropy check (they are high-entropy by design and are inspected
properly by the archive walker instead).

``pefile`` is optional; without it (or for non-PE files) only the whole-file
entropy check runs.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import NamedTuple

from ..models import Finding, Severity

try:  # Optional dependency: degrade to entropy-only analysis, not ImportError.
    import pefile
except ImportError:  # pragma: no cover - exercised only when pefile is absent
    pefile = None  # type: ignore[assignment]

#: Skip entropy judgement below this size; tiny samples make entropy noise.
MIN_SIZE_FOR_ENTROPY = 256

#: Magic prefixes of formats that are high-entropy *by design* (compressed
#: containers and media). Entropy says nothing suspicious about them, so the
#: whole-file check stays quiet; containers are inspected by the archive walker.
COMPRESSED_FORMAT_MAGICS: tuple[bytes, ...] = (
    b"PK\x03\x04",        # zip (also docx/xlsx/jar/apk)
    b"\x1f\x8b",          # gzip
    b"BZh",               # bzip2
    b"\xfd7zXZ\x00",      # xz
    b"\x28\xb5\x2f\xfd",  # zstd
    b"7z\xbc\xaf\x27\x1c",# 7-zip
    b"Rar!\x1a\x07",      # rar
    b"\x89PNG",           # png
    b"\xff\xd8\xff",      # jpeg
    b"GIF8",              # gif
)

#: Whole-file entropy at or above this (of max 8.0) suggests packed/encrypted data.
WHOLE_FILE_ENTROPY_THRESHOLD = 7.5

#: PE section entropy at or above this suggests a packed section.
SECTION_ENTROPY_THRESHOLD = 7.2

#: Windows API imports commonly associated with malicious behaviour, with the
#: risk weight each contributes. All are also used by legitimate software
#: (debuggers, installers, monitoring tools) - hence weights, not verdicts.
SUSPICIOUS_IMPORTS: dict[str, float] = {
    "createremotethread": 0.20,  # classic code-injection primitive
    "writeprocessmemory": 0.20,  # writing into another process
    "virtualallocex": 0.20,      # allocating memory in another process
    "setwindowshookexa": 0.15,   # global hooks (keylogging)
    "setwindowshookexw": 0.15,
    "urldownloadtofilea": 0.15,  # downloader behaviour
    "urldownloadtofilew": 0.15,
    "isdebuggerpresent": 0.10,   # anti-analysis
    "winexec": 0.10,             # legacy process launch
}


class Trait(NamedTuple):
    """One observed suspicious trait and its contribution to the score."""

    name: str
    weight: float
    description: str


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits per byte (0.0 - 8.0).

    Uniformly random bytes approach 8.0; English text sits near 4.5; long runs
    of one byte approach 0.0.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


class HeuristicEngine:
    """Scores files on static traits instead of matching known signatures."""

    name = "heuristic"

    def __init__(self, report_threshold: float = 0.4) -> None:
        if not 0.0 < report_threshold <= 1.0:
            raise ValueError("report_threshold must be in (0.0, 1.0]")
        self.report_threshold = report_threshold

    def scan(self, path: str, data: bytes) -> list[Finding]:
        """Collect traits, sum their weights, report once if above threshold."""
        traits = self._entropy_traits(data) + self._pe_traits(data)
        if not traits:
            return []
        score = min(1.0, sum(trait.weight for trait in traits))
        if score < self.report_threshold:
            return []
        return [
            Finding(
                engine=self.name,
                severity=Severity.SUSPICIOUS,
                message=f"Static traits (risk {score:.2f}/1.0): "
                        + "; ".join(t.description for t in traits),
                detail={"score": round(score, 2), "traits": [t.name for t in traits]},
            )
        ]

    def _entropy_traits(self, data: bytes) -> list[Trait]:
        """Flag whole-file entropy typical of packed or encrypted content."""
        if len(data) < MIN_SIZE_FOR_ENTROPY:
            return []
        if data.startswith(COMPRESSED_FORMAT_MAGICS):
            return []
        entropy = shannon_entropy(data)
        if entropy >= WHOLE_FILE_ENTROPY_THRESHOLD:
            return [
                Trait("high-entropy", 0.5, f"high overall entropy ({entropy:.2f}/8.00)")
            ]
        return []

    def _pe_traits(self, data: bytes) -> list[Trait]:
        """Inspect PE files: packed-looking sections and risky imports."""
        if pefile is None or not data.startswith(b"MZ"):
            return []
        try:
            pe = pefile.PE(data=data)
        except pefile.PEFormatError:
            return []  # MZ magic but not a parseable PE; not our judgement call

        traits: list[Trait] = []
        packed = self._packed_section(pe)
        if packed is not None:
            traits.append(packed)
        traits.extend(self._import_traits(self._import_names(pe)))
        return traits

    @staticmethod
    def _packed_section(pe: "pefile.PE") -> Trait | None:
        """Return a trait for the highest-entropy packed-looking section."""
        worst_name, worst_entropy = "", 0.0
        for section in getattr(pe, "sections", []):
            section_data = section.get_data()
            if len(section_data) < MIN_SIZE_FOR_ENTROPY:
                continue
            entropy = shannon_entropy(section_data)
            if entropy > worst_entropy:
                worst_name = section.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
                worst_entropy = entropy
        if worst_entropy >= SECTION_ENTROPY_THRESHOLD:
            return Trait(
                "packed-section", 0.4,
                f"high-entropy PE section {worst_name!r} ({worst_entropy:.2f}/8.00)",
            )
        return None

    @staticmethod
    def _import_names(pe: "pefile.PE") -> list[str]:
        """Flatten imported symbol names from the PE import directory."""
        names: list[str] = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for imported in entry.imports:
                if imported.name:
                    names.append(imported.name.decode("latin-1", errors="replace"))
        return names

    @staticmethod
    def _import_traits(import_names: list[str]) -> list[Trait]:
        """Map imported symbols onto the suspicious-import weight table."""
        traits: list[Trait] = []
        for original in import_names:
            weight = SUSPICIOUS_IMPORTS.get(original.lower())
            if weight is not None:
                traits.append(Trait(f"import:{original}", weight, f"suspicious import {original}"))
        return traits
