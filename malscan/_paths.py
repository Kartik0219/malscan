"""Filesystem paths that work both from source and as a frozen (PyInstaller) binary.

Two distinct needs:

- ``resource_root()`` — base for *read-only* bundled data (``signatures/``). In a
  PyInstaller build these are unpacked under ``sys._MEIPASS``; from source it's
  the repo root, so behaviour is unchanged for development and tests.
- ``user_data_root()`` — a *persistent, writable* base for the quarantine vault.
  ``sys._MEIPASS`` is a temp dir that PyInstaller wipes on exit, so writing the
  vault there would silently lose quarantined files. When frozen we therefore use
  ``~/.malscan``; from source we keep the repo root (unchanged dev behaviour).
"""

from __future__ import annotations

import sys
from pathlib import Path

# .../malscan (the package dir); its parent is the repo root when run from source.
_SOURCE_ROOT = Path(__file__).resolve().parent.parent


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_root() -> Path:
    """Directory holding read-only bundled resources (e.g. ``signatures/``)."""
    if _is_frozen():
        return Path(getattr(sys, "_MEIPASS", _SOURCE_ROOT))
    return _SOURCE_ROOT


def user_data_root() -> Path:
    """Persistent, writable base dir (quarantine vault, etc.)."""
    if _is_frozen():
        return Path.home() / ".malscan"
    return _SOURCE_ROOT
