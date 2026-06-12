"""Tests for the public, deploy-safe demo app.

These also serve as regression guards on the security boundary: the demo must
never accept a filesystem path or expose quarantine.
"""

from __future__ import annotations

import io

from malscan.web.demo import MAX_UPLOAD_BYTES, create_demo_app

EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode()


def _client():
    app = create_demo_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_health():
    resp = _client().get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_index_renders_upload_form():
    resp = _client().get("/")
    assert resp.status_code == 200
    assert b"Upload a file" in resp.data
    assert b'type="file"' in resp.data


def test_upload_eicar_flagged_malicious():
    # EICAR uploaded as bytes is scanned in memory - no disk write, so the
    # host antivirus can't intercept it the way it does for on-disk tests.
    data = {"file": (io.BytesIO(EICAR), "eicar.txt")}
    resp = _client().post("/scan", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"malicious" in resp.data
    assert b"known-bad hash" in resp.data


def test_upload_clean_file():
    data = {"file": (io.BytesIO(b"just some harmless text"), "note.txt")}
    resp = _client().post("/scan", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"No detections" in resp.data


def test_scan_without_file_shows_error():
    resp = _client().post("/scan", data={}, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"Please choose a file" in resp.data


def test_demo_does_not_accept_filesystem_path():
    """Security guard: a 'target' path param must NOT trigger any path scan."""
    resp = _client().post(
        "/scan",
        data={"target": "/etc/passwd"},
        content_type="multipart/form-data",
    )
    # No file part -> error, and certainly no filesystem contents leaked.
    assert b"Please choose a file" in resp.data
    assert b"root:" not in resp.data


def test_oversized_upload_rejected():
    big = io.BytesIO(b"\x00" * (MAX_UPLOAD_BYTES + 1024))
    resp = _client().post(
        "/scan", data={"file": (big, "big.bin")}, content_type="multipart/form-data"
    )
    assert resp.status_code == 413
