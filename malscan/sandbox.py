"""Dynamic analysis — detonate a sample in an isolated sandbox and watch it.

Static engines judge a file by what it *is*; dynamic analysis judges it by what
it *does*. This runs a sample inside a locked-down Docker container under
``strace`` and turns the observed syscalls — network connections, file writes,
child processes, anti-debug ``ptrace`` — into a behavioural verdict. It's the
idea behind Bitdefender's Advanced Threat Defense and every malware sandbox.

**Safety is the whole design.** Executing an unknown sample is dangerous, so:

* It **never runs on the host** — only inside ``docker run`` with the network
  cut, root filesystem read-only, all capabilities dropped (bar the one
  ``SYS_PTRACE`` strace needs), no-new-privileges, a non-root user, and memory /
  pid / time limits. The sample is mounted **read-only**.
* It is a **separate, explicit command** (``malscan detonate``), never part of a
  normal scan, and defaults to a **dry run** that only prints the sandbox command
  — you must pass ``--confirm`` to actually execute, and only ever in a
  disposable VM.

**Status: experimental / unverified.** Authored on a host without Docker; the
live detonation path has **not been executed here**. The testable pieces — the
hardened command builder and the strace behaviour parser — are unit-tested. The
``docker run`` path needs validating on a Docker host with throwaway samples.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

from .models import Severity

#: Default minimal Linux image to detonate ELF samples in.
DEFAULT_IMAGE = "alpine:latest"
DEFAULT_TIMEOUT = 20  # seconds

# ── behaviour parsing (pure, testable) ──

_RE_CONNECT = re.compile(r'connect\([^)]*sa_family=AF_INET6?\b')
_RE_INET_ADDR = re.compile(r'inet_addr\("([0-9.]+)"\)')
_RE_PORT = re.compile(r'htons\((\d+)\)')
_RE_OPEN = re.compile(r'open(?:at)?\((?:[^,]+,\s*)?"([^"]+)"\s*,\s*([^,)]+)')
_RE_EXECVE = re.compile(r'execve\("([^"]+)"')
_RE_CLONE = re.compile(r'\b(?:clone|fork|vfork)\(')
_RE_PTRACE = re.compile(r'\bptrace\(')
_RE_UNLINK = re.compile(r'\bunlink(?:at)?\(')


@dataclass
class BehaviorReport:
    """Structured summary of what a detonated sample did."""

    network_endpoints: list[str] = field(default_factory=list)
    file_writes: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    deleted_files: list[str] = field(default_factory=list)
    anti_debug: bool = False
    timed_out: bool = False

    def to_dict(self) -> dict:
        return {
            "network_endpoints": self.network_endpoints,
            "file_writes": self.file_writes,
            "processes": self.processes,
            "deleted_files": self.deleted_files,
            "anti_debug": self.anti_debug,
            "timed_out": self.timed_out,
            "verdict": self.verdict.value,
            "techniques": self.techniques,
        }

    @property
    def techniques(self) -> list[str]:
        tids: list[str] = []
        if self.network_endpoints:
            tids.append("T1071")        # Application Layer Protocol (C2)
        if self.processes:              # any child process beyond the sample itself
            tids.append("T1059")        # Command and Scripting Interpreter
        if self.anti_debug:
            tids.append("T1622")        # Debugger Evasion
        return sorted(set(tids))

    @property
    def verdict(self) -> Severity:
        """Behavioural verdict. Inference -> never MALICIOUS (max SUSPICIOUS)."""
        if self.network_endpoints or self.anti_debug or self.processes:
            return Severity.SUSPICIOUS
        if self.file_writes or self.deleted_files:
            return Severity.INFO
        return Severity.CLEAN


def parse_strace(output: str, *, sample_argv0: str | None = None) -> BehaviorReport:
    """Turn raw ``strace -f`` output into a :class:`BehaviorReport`.

    Pure and testable — no container or execution involved. ``sample_argv0`` is
    the sample's own path, excluded from the spawned-process list so the sample
    executing itself doesn't count as spawning a child.
    """
    report = BehaviorReport()
    for line in output.splitlines():
        if _RE_CONNECT.search(line):
            addr = _RE_INET_ADDR.search(line)
            port = _RE_PORT.search(line)
            if addr:
                endpoint = addr.group(1) + (f":{port.group(1)}" if port else "")
                if endpoint not in report.network_endpoints:
                    report.network_endpoints.append(endpoint)
        m = _RE_OPEN.search(line)
        if m and any(flag in m.group(2) for flag in ("O_WRONLY", "O_RDWR", "O_CREAT")):
            if m.group(1) not in report.file_writes:
                report.file_writes.append(m.group(1))
        m = _RE_EXECVE.search(line)
        if m and m.group(1) != sample_argv0 and m.group(1) not in report.processes:
            report.processes.append(m.group(1))
        if _RE_PTRACE.search(line):
            report.anti_debug = True
        m = _RE_UNLINK.search(line)
        if m:
            path = re.search(r'"([^"]+)"', line)
            if path and path.group(1) not in report.deleted_files:
                report.deleted_files.append(path.group(1))
    return report


# ── Docker sandbox runner ──

@dataclass
class SandboxResult:
    report: BehaviorReport
    raw_output: str
    command: list[str]


class DockerSandbox:
    """Detonate a sample inside a hardened, network-isolated Docker container."""

    def __init__(self, image: str = DEFAULT_IMAGE, timeout: int = DEFAULT_TIMEOUT):
        self.image = image
        self.timeout = timeout

    @staticmethod
    def is_available() -> bool:
        return shutil.which("docker") is not None

    def build_command(self, sample_path: str) -> list[str]:
        """Construct the hardened ``docker run`` argv (no execution).

        Pure and testable: asserts in tests verify the isolation flags are all
        present. The sample is mounted read-only at ``/sample`` and run under
        strace; the container has no network and a read-only root filesystem.
        """
        return [
            "docker", "run", "--rm",
            "--network", "none",                       # no network egress
            "--read-only",                             # immutable root fs
            "--tmpfs", "/tmp:rw,size=16m,noexec",      # scratch, non-executable
            "--memory", "256m", "--memory-swap", "256m",
            "--pids-limit", "64",
            "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE",  # only what strace needs
            "--security-opt", "no-new-privileges",
            "--user", "1000:1000",                     # non-root
            "-v", f"{sample_path}:/sample:ro",         # sample is read-only
            self.image,
            "timeout", str(self.timeout),
            "strace", "-f", "-qq", "-e",
            "trace=network,execve,clone,fork,vfork,open,openat,ptrace,unlink,unlinkat",
            "/sample",
        ]

    def run(self, sample_path: str) -> SandboxResult:
        """Detonate the sample (requires Docker). Never runs on the host."""
        if not self.is_available():
            raise RuntimeError("docker is not available; cannot detonate safely")
        cmd = self.build_command(sample_path)
        timed_out = False
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout + 15,  # outer guard beyond the in-container timeout
            )
            output = proc.stderr + proc.stdout  # strace writes to stderr
        except subprocess.TimeoutExpired as exc:
            output = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            timed_out = True
        report = parse_strace(output, sample_argv0="/sample")
        report.timed_out = timed_out
        return SandboxResult(report=report, raw_output=output, command=cmd)
