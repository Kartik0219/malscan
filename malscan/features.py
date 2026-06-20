"""Numeric feature extraction for the ML classifier.

Turns a file's raw bytes into a fixed-length vector of floats that a model can
score. Features are deliberately cheap, deterministic, and pure-stdlib (``pefile``
is optional and only deepens the PE-specific features); the same extractor runs
at training time and at inference time, so a model trained on these features can
be scored anywhere malscan runs — including the dependency-free frozen binary.

The feature set mixes whole-file byte statistics (entropy, printable/null ratios,
histogram shape) with structural PE signals (section count and entropy, import
counts, suspicious-import hits). It is intentionally compact and documented rather
than exhaustive: the point is a clean, reproducible baseline you can retrain on a
real labelled corpus (e.g. the EMBER dataset), not a state-of-the-art feature bank.

``FEATURE_NAMES`` is the contract between training and inference — its order must
never change without retraining, so models carry their own copy to detect drift.
"""

from __future__ import annotations

import math
from collections import Counter

from .engines.heuristics import (
    SUSPICIOUS_IMPORTS,
    shannon_entropy,
)

try:  # Optional: PE-structure features degrade to zeros without pefile.
    import pefile
except ImportError:  # pragma: no cover - exercised only when pefile is absent
    pefile = None  # type: ignore[assignment]

#: Ordered feature names. The index of each name is its position in the vector.
#: NEVER reorder or remove without retraining every model — models store a copy
#: of this list and refuse to score if it disagrees.
FEATURE_NAMES: tuple[str, ...] = (
    "log_size",            # log2(size + 1)
    "entropy",             # whole-file Shannon entropy, 0..8
    "printable_ratio",     # fraction of bytes in printable ASCII range
    "null_ratio",          # fraction of 0x00 bytes
    "mean_byte",           # mean byte value, normalised 0..1
    "byte_stddev",         # stddev of the byte histogram, normalised
    "is_pe",               # starts with MZ
    "is_executable",       # starts with a PE/ELF/Mach-O magic
    "pe_section_count",    # log2(sections + 1)
    "pe_max_section_entropy",   # highest section entropy, 0..8
    "pe_mean_section_entropy",  # mean section entropy, 0..8
    "pe_import_count",     # log2(imported symbols + 1)
    "pe_suspicious_imports",    # count of injection/download-style imports
    "pe_has_resources",    # 1 if a resource directory is present
)

_EXECUTABLE_MAGICS: tuple[bytes, ...] = (
    b"MZ", b"\x7fELF",
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
)
_PRINTABLE = set(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}


def _byte_stats(data: bytes) -> tuple[float, float, float, float]:
    """Return (printable_ratio, null_ratio, mean_byte/255, histogram stddev)."""
    length = len(data)
    if length == 0:
        return 0.0, 0.0, 0.0, 0.0
    counts = Counter(data)
    printable = sum(c for b, c in counts.items() if b in _PRINTABLE) / length
    null = counts.get(0, 0) / length
    mean = sum(b * c for b, c in counts.items()) / length / 255.0
    # Standard deviation of the 256-bin histogram (how uneven the distribution is).
    expected = length / 256.0
    variance = sum((counts.get(b, 0) - expected) ** 2 for b in range(256)) / 256.0
    stddev = math.sqrt(variance) / length  # normalise by length -> scale-free
    return printable, null, mean, stddev


def _pe_features(data: bytes) -> tuple[float, float, float, float, float, float]:
    """PE structural features; all zero for non-PE files or when pefile is absent.

    Returns (log_section_count, max_section_entropy, mean_section_entropy,
    log_import_count, suspicious_import_count, has_resources).
    """
    if pefile is None or not data.startswith(b"MZ"):
        return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
    except Exception:  # malformed PE -> no structural signal, not our judgement
        return 0.0, 0.0, 0.0, 0.0, 0.0, 0.0

    sections = getattr(pe, "sections", [])
    entropies = []
    for section in sections:
        body = section.get_data()
        if body:
            entropies.append(shannon_entropy(body))
    max_ent = max(entropies) if entropies else 0.0
    mean_ent = sum(entropies) / len(entropies) if entropies else 0.0

    imports = 0
    suspicious = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if imp.name:
                imports += 1
                if imp.name.decode("latin-1", "replace").lower() in SUSPICIOUS_IMPORTS:
                    suspicious += 1

    has_resources = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") else 0.0
    return (
        math.log2(len(sections) + 1), max_ent, mean_ent,
        math.log2(imports + 1), float(suspicious), has_resources,
    )


def extract(data: bytes) -> list[float]:
    """Extract the fixed-length feature vector for ``data`` (order = FEATURE_NAMES)."""
    printable, null, mean, stddev = _byte_stats(data)
    sec_count, max_sent, mean_sent, imp_count, susp, has_res = _pe_features(data)
    vector = [
        math.log2(len(data) + 1),
        shannon_entropy(data),
        printable,
        null,
        mean,
        stddev,
        1.0 if data.startswith(b"MZ") else 0.0,
        1.0 if data.startswith(_EXECUTABLE_MAGICS) else 0.0,
        sec_count,
        max_sent,
        mean_sent,
        imp_count,
        susp,
        has_res,
    ]
    assert len(vector) == len(FEATURE_NAMES), "feature vector / names out of sync"
    return vector
