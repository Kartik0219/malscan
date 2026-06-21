"""Tests for the real-time directory monitor."""

from __future__ import annotations

import hashlib
import os

from malscan.monitor import Monitor
from malscan.models import Severity
from malscan.quarantine import Quarantine
from malscan.scanner import Scanner


def _scanner_with_blocklisted(tmp_path, payload: bytes) -> Scanner:
    """A Scanner whose blocklist contains `payload`'s hash (-> MALICIOUS)."""
    sig = tmp_path / "signatures"
    (sig / "yara").mkdir(parents=True)
    digest = hashlib.sha256(payload).hexdigest()
    (sig / "hash_blocklist.txt").write_text(f"{digest}  test-malware\n", encoding="utf-8")
    return Scanner(signatures_dir=sig)


def _settle_and_collect(monitor, passes=2):
    """A file is only scanned after it is stable across two polls."""
    events = []
    for _ in range(passes):
        events.extend(monitor.poll())
    return events


def test_baseline_files_are_not_rescanned(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    (watch / "old.txt").write_text("already here")
    monitor = Monitor(Scanner(), [watch])
    monitor.prime()
    # No new files -> nothing scanned even across several polls.
    assert _settle_and_collect(monitor, passes=3) == []


def test_new_high_entropy_file_is_detected(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    monitor = Monitor(Scanner(), [watch])
    monitor.prime()
    (watch / "packed.bin").write_bytes(os.urandom(4096))
    events = _settle_and_collect(monitor)
    assert len(events) == 1
    assert events[0].result.verdict == Severity.SUSPICIOUS
    assert events[0].path.endswith("packed.bin")


def test_unsettled_file_waits_for_stability(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    monitor = Monitor(Scanner(), [watch])
    monitor.prime()
    target = watch / "growing.bin"
    target.write_bytes(os.urandom(2048))
    # First poll only marks it pending (not yet scanned).
    assert monitor.poll() == []
    # It changes again before settling -> still not scanned.
    target.write_bytes(os.urandom(8192))
    assert monitor.poll() == []
    # Now stable -> scanned on the next poll.
    events = monitor.poll()
    assert len(events) == 1


def test_malicious_file_is_quarantined(tmp_path):
    payload = b"synthetic-malicious-content-for-testing" * 4
    watch = tmp_path / "watch"
    watch.mkdir()
    scanner = _scanner_with_blocklisted(tmp_path, payload)
    quarantine = Quarantine(tmp_path / "vault")
    monitor = Monitor(scanner, [watch], quarantine=quarantine)
    monitor.prime()

    bad = watch / "dropper.bin"
    bad.write_bytes(payload)
    events = _settle_and_collect(monitor)

    assert len(events) == 1
    assert events[0].result.verdict == Severity.MALICIOUS
    assert events[0].quarantined is not None
    assert not bad.exists()                       # original removed
    assert len(quarantine.list_entries()) == 1


def test_vault_contents_are_not_rescanned(tmp_path):
    # The vault lives inside the watched tree; its obfuscated blobs are high
    # entropy and must not be picked up as new "suspicious" files.
    payload = b"synthetic-malicious-content-for-testing" * 4
    watch = tmp_path / "watch"
    watch.mkdir()
    scanner = _scanner_with_blocklisted(tmp_path, payload)
    quarantine = Quarantine(watch / "vault")       # vault under the watched dir
    monitor = Monitor(scanner, [watch], quarantine=quarantine)
    monitor.prime()

    bad = watch / "dropper.bin"
    bad.write_bytes(payload)
    _settle_and_collect(monitor)
    # Further polls must not surface the quarantined blob as a new event.
    assert _settle_and_collect(monitor, passes=3) == []


def test_run_with_bounded_iterations(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    monitor = Monitor(Scanner(), [watch])
    seen = []
    (watch / "seed.bin").write_bytes(os.urandom(4096))
    # run() primes first (baseline), so a file created *before* run won't fire;
    # create one after priming by writing on the first event-less pass instead.
    monitor.run(interval=0, on_event=seen.append, iterations=1)
    # Nothing fired yet (seed was baselined); add a file and poll once more.
    (watch / "new.bin").write_bytes(os.urandom(4096))
    monitor.poll(); events = monitor.poll()
    assert any(e.path.endswith("new.bin") for e in events)
