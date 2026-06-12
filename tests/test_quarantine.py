"""Tests for the quarantine vault and web dashboard."""

from __future__ import annotations

from pathlib import Path

from malscan.quarantine import Quarantine
from malscan.web.app import create_app


def test_quarantine_round_trip(tmp_path):
    vault = tmp_path / "vault"
    payload = b"pretend-malware-bytes"
    sample = tmp_path / "bad.bin"
    sample.write_bytes(payload)

    q = Quarantine(vault)
    entry = q.quarantine_file(sample, verdict="malicious", reasons=["test"])

    # Original is gone; vault blob is obfuscated (not the original bytes).
    assert not sample.exists()
    blob = vault / f"{entry.id}.bin"
    assert blob.exists()
    assert blob.read_bytes() != payload

    # Listed, then restored losslessly.
    assert len(q.list_entries()) == 1
    restored = q.restore(entry.id)
    assert Path(restored).read_bytes() == payload
    assert q.list_entries() == []


def test_quarantine_delete(tmp_path):
    vault = tmp_path / "vault"
    sample = tmp_path / "x.bin"
    sample.write_bytes(b"data")
    q = Quarantine(vault)
    entry = q.quarantine_file(sample)
    assert q.delete(entry.id) is True
    assert q.delete(entry.id) is False
    assert q.list_entries() == []


def test_restore_to_custom_dest(tmp_path):
    vault = tmp_path / "vault"
    sample = tmp_path / "y.bin"
    sample.write_bytes(b"hello")
    q = Quarantine(vault)
    entry = q.quarantine_file(sample)
    dest = tmp_path / "restored" / "y.bin"
    q.restore(entry.id, dest)
    assert dest.read_bytes() == b"hello"


def test_web_health(tmp_path):
    app = create_app(vault_dir=tmp_path / "vault")
    client = app.test_client()
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_web_index_renders(tmp_path):
    app = create_app(vault_dir=tmp_path / "vault")
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"malscan" in resp.data
    assert b"Quarantine vault" in resp.data


def test_web_scan_clean_dir(tmp_path):
    target = tmp_path / "files"
    target.mkdir()
    (target / "note.txt").write_text("harmless")
    app = create_app(vault_dir=tmp_path / "vault")
    client = app.test_client()
    resp = client.post("/scan", data={"target": str(target)}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"clean" in resp.data
