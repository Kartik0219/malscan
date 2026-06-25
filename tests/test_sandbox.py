"""Tests for the dynamic-analysis sandbox's testable logic.

The live ``docker run`` detonation path is NOT executed here. These cover the
hardened command builder and the strace behaviour parser.
"""

from __future__ import annotations

import pytest

from malscan import attack
from malscan.models import Severity
from malscan.sandbox import DockerSandbox, BehaviorReport, parse_strace


# ── command hardening ──

def test_build_command_has_all_isolation_flags():
    cmd = DockerSandbox(timeout=30).build_command("/abs/sample")
    joined = " ".join(cmd)
    assert "--network none" in joined          # no egress
    assert "--read-only" in joined             # immutable rootfs
    assert "--cap-drop ALL" in joined          # drop everything...
    assert "--cap-add SYS_PTRACE" in joined    # ...except what strace needs
    assert "--security-opt no-new-privileges" in joined
    assert "--pids-limit 64" in joined
    assert "--memory 256m" in joined
    assert "--user 1000:1000" in joined        # non-root
    assert "/abs/sample:/sample:ro" in joined  # sample mounted read-only
    assert "--rm" in cmd
    assert "timeout" in cmd and "30" in cmd


def test_build_command_uses_chosen_image():
    cmd = DockerSandbox(image="ubuntu:22.04").build_command("/x")
    assert "ubuntu:22.04" in cmd


# ── behaviour parsing ──

NET = 'connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = 0'
WRITE = 'openat(AT_FDCWD, "/tmp/dropped.sh", O_WRONLY|O_CREAT, 0644) = 4'
EXEC_CHILD = 'execve("/bin/sh", ["sh", "-c", "x"], ...) = 0'
PTRACE = 'ptrace(PTRACE_TRACEME) = 0'
UNLINK = 'unlink("/tmp/self") = 0'


def test_parses_network_endpoint():
    r = parse_strace(NET)
    assert r.network_endpoints == ["93.184.216.34:443"]
    assert r.verdict == Severity.SUSPICIOUS
    assert "T1071" in r.techniques


def test_parses_file_write_and_delete():
    r = parse_strace(WRITE + "\n" + UNLINK)
    assert "/tmp/dropped.sh" in r.file_writes
    assert "/tmp/self" in r.deleted_files
    assert r.verdict == Severity.INFO            # writes alone -> info, not suspicious


def test_parses_child_process_excluding_self():
    r = parse_strace('execve("/sample", ["/sample"], ...) = 0\n' + EXEC_CHILD,
                     sample_argv0="/sample")
    assert r.processes == ["/bin/sh"]            # the sample's own execve is excluded
    assert r.verdict == Severity.SUSPICIOUS      # spawning a child shell
    assert "T1059" in r.techniques


def test_parses_anti_debug():
    r = parse_strace(PTRACE)
    assert r.anti_debug is True
    assert r.verdict == Severity.SUSPICIOUS
    assert "T1622" in r.techniques


def test_benign_behaviour_is_clean():
    r = parse_strace('openat(AT_FDCWD, "/etc/hosts", O_RDONLY) = 3\nread(3, ...) = 100')
    assert r.verdict == Severity.CLEAN
    assert r.techniques == []


def test_report_to_dict_roundtrips_fields():
    d = parse_strace(NET + "\n" + PTRACE).to_dict()
    assert d["verdict"] == "suspicious"
    assert d["anti_debug"] is True
    assert "T1071" in d["techniques"] and "T1622" in d["techniques"]


def test_sandbox_techniques_are_in_catalog():
    r = parse_strace(NET + "\n" + EXEC_CHILD + "\n" + PTRACE, sample_argv0="/sample")
    for tid in r.techniques:
        assert tid in attack.TECHNIQUES, f"{tid} missing from catalog"


# ── safety guard ──

def test_run_refuses_without_docker(monkeypatch):
    monkeypatch.setattr(DockerSandbox, "is_available", staticmethod(lambda: False))
    with pytest.raises(RuntimeError):
        DockerSandbox().run("/x")
