"""Tests for in-memory archive walking and its integration with the scanner."""

from __future__ import annotations

import gzip
import hashlib
import io
import tarfile
import zipfile

from malscan import archive
from malscan.models import Severity
from malscan.scanner import Scanner


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _budget(members=100, member_bytes=1 << 20, total=1 << 20):
    return archive.Budget(
        max_members=members, max_member_bytes=member_bytes, max_total_bytes=total
    )


def test_detect_formats():
    assert archive.detect(_zip({"a.txt": b"hi"})) == "zip"
    assert archive.detect(_tar({"a.txt": b"hi"})) == "tar"
    assert archive.detect(gzip.compress(b"hello world")) == "compressed"
    assert archive.detect(b"not an archive at all") is None


def test_walk_zip_members():
    data = _zip({"a.txt": b"alpha", "b.txt": b"beta"})
    notes: list[str] = []
    members = dict(archive.walk(data, budget=_budget(), depth=2, notes=notes))
    assert members == {"a.txt": b"alpha", "b.txt": b"beta"}
    assert notes == []


def test_walk_tar_members():
    data = _tar({"x.bin": b"xray", "y.bin": b"yankee"})
    members = dict(archive.walk(data, budget=_budget(), depth=2, notes=[]))
    assert members == {"x.bin": b"xray", "y.bin": b"yankee"}


def test_member_count_budget_is_noted():
    data = _zip({f"f{i}.txt": b"data" for i in range(6)})
    notes: list[str] = []
    members = list(archive.walk(data, budget=_budget(members=2), depth=2, notes=notes))
    assert len(members) == 2
    assert any("member budget" in n for n in notes)


def test_total_bytes_budget_is_noted():
    data = _zip({"big.bin": b"A" * 10_000})
    notes: list[str] = []
    members = list(archive.walk(data, budget=_budget(total=5_000), depth=2, notes=notes))
    assert members == []
    assert any("budget" in n for n in notes)


def test_nested_zip_is_expanded():
    inner = _zip({"deep.txt": b"deep"})
    outer = _zip({"inner.zip": inner})
    members = dict(archive.walk(outer, budget=_budget(), depth=3, notes=[]))
    assert "inner.zip!deep.txt" in members
    assert members["inner.zip!deep.txt"] == b"deep"


def test_nested_depth_limit_is_noted():
    inner = _zip({"deep.txt": b"deep"})
    outer = _zip({"inner.zip": inner})
    notes: list[str] = []
    members = dict(archive.walk(outer, budget=_budget(), depth=1, notes=notes))
    assert "inner.zip" in members            # outer expanded
    assert "inner.zip!deep.txt" not in members  # inner not descended
    assert any("depth limit" in n for n in notes)


def test_zip_slip_member_name_is_inert():
    # A hostile path traversal name must just be a string, never a written file.
    data = _zip({"../../etc/passwd": b"root:x:0:0:"})
    members = dict(archive.walk(data, budget=_budget(), depth=2, notes=[]))
    assert "../../etc/passwd" in members  # present as a label only


def test_scanner_flags_blocklisted_archive_member(tmp_path):
    payload = b"member-malware-content-for-testing"
    data = _zip({"readme.txt": b"hello", "evil.bin": payload})

    sig = tmp_path / "signatures"
    (sig / "yara").mkdir(parents=True)
    (sig / "hash_blocklist.txt").write_text(
        f"{hashlib.sha256(payload).hexdigest()}  member-mal\n", encoding="utf-8"
    )

    scanner = Scanner(signatures_dir=sig)
    results = {r.path: r for r in scanner.iter_results("bundle.zip", data)}

    assert results["bundle.zip"].verdict == Severity.CLEAN            # zip itself clean
    assert results["bundle.zip!evil.bin"].verdict == Severity.MALICIOUS
    assert results["bundle.zip!readme.txt"].verdict == Severity.CLEAN


def test_scanner_no_archives_flag_skips_members(tmp_path):
    payload = b"member-malware-content-for-testing"
    data = _zip({"evil.bin": payload})
    sig = tmp_path / "signatures"
    (sig / "yara").mkdir(parents=True)
    (sig / "hash_blocklist.txt").write_text(
        f"{hashlib.sha256(payload).hexdigest()}  member-mal\n", encoding="utf-8"
    )
    scanner = Scanner(signatures_dir=sig, scan_archives=False)
    results = list(scanner.iter_results("bundle.zip", data))
    assert len(results) == 1  # container only, no members expanded
    assert results[0].path == "bundle.zip"
