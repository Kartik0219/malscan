"""Linux fanotify on-access backend — *real* intercept-and-block.

Unlike the cross-platform polling `monitor` (which reacts *after* a file lands),
this watches with the kernel's **fanotify** permission events
(``FAN_OPEN_PERM``): the kernel pauses an ``open()`` and asks us to **allow or
deny** it *before* the process gets the file. Deny a malicious file and the open
fails — true on-access blocking, the model commercial AV uses.

**Platform + verification status.** fanotify is Linux-only and ``FAN_OPEN_PERM``
requires ``CAP_SYS_ADMIN`` (root). This module was authored on a non-Linux host
and the **kernel-syscall path has not been executed here** — the testable parts
(event-struct parsing and the allow/deny policy) have unit tests; the libc/ioctl
path needs validating on a real Linux box (see ``docs``/README). Everything is
guarded so importing the module is safe on any OS; ``is_supported()`` tells you
whether the live path is available.

Design: the raw kernel I/O (init, mark, read, respond) is isolated in thin
methods, while the decision logic — parse an event, scan the file, decide
allow/deny — is pure and unit-tested against crafted buffers and fake scanners.
"""

from __future__ import annotations

import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .models import FileResult, Severity
from .scanner import Scanner

# ── fanotify constants (from <linux/fanotify.h>) ──
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_CLASS_CONTENT = 0x00000004
FAN_MARK_ADD = 0x00000001
FAN_MARK_MOUNT = 0x00000010
FAN_OPEN_PERM = 0x00010000
FAN_ALLOW = 0x01
FAN_DENY = 0x02
FANOTIFY_METADATA_VERSION = 3

O_RDONLY = 0
AT_FDCWD = -100

#: struct fanotify_event_metadata: u32 event_len, u8 vers, u8 reserved,
#: u16 metadata_len, u64 mask, s32 fd, s32 pid. 24 bytes, naturally aligned.
_META_FMT = "<IBBHQii"
META_LEN = struct.calcsize(_META_FMT)  # 24

#: struct fanotify_response: s32 fd, u32 response.
_RESP_FMT = "<iI"


class FanotifyError(RuntimeError):
    """Raised when fanotify is unavailable or a kernel call fails."""


@dataclass
class FanotifyEvent:
    """One parsed permission event the kernel is waiting on us to answer."""

    event_len: int
    version: int
    mask: int
    fd: int
    pid: int

    @property
    def is_perm(self) -> bool:
        return bool(self.mask & FAN_OPEN_PERM)


def parse_event(buf: bytes, offset: int = 0) -> FanotifyEvent:
    """Parse one ``fanotify_event_metadata`` struct out of ``buf`` at ``offset``.

    Pure and testable — no kernel involved. Raises ``ValueError`` on a short or
    wrong-version record.
    """
    if len(buf) - offset < META_LEN:
        raise ValueError("buffer too short for a fanotify event")
    event_len, vers, _res, _mlen, mask, fd, pid = struct.unpack_from(_META_FMT, buf, offset)
    if vers != FANOTIFY_METADATA_VERSION:
        raise ValueError(f"unexpected fanotify metadata version {vers}")
    return FanotifyEvent(event_len=event_len, version=vers, mask=mask, fd=fd, pid=pid)


def decide(result: FileResult, *, block_suspicious: bool = False) -> bool:
    """Policy: return True to ALLOW the open, False to DENY it.

    Pure and testable. Deny malicious always; deny suspicious only when
    ``block_suspicious`` is set (off by default — blocking on inference is
    false-positive-prone). Scan errors fail open (allow) so the monitor can't
    brick the system on an unreadable file.
    """
    if result.error:
        return True
    verdict = result.verdict
    if verdict == Severity.MALICIOUS:
        return False
    if block_suspicious and verdict == Severity.SUSPICIOUS:
        return False
    return True


def is_supported() -> bool:
    """True only if the live fanotify path can plausibly run (Linux + libc)."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes
        ctypes.CDLL("libc.so.6", use_errno=True)
        return True
    except OSError:
        return False


class FanotifyMonitor:
    """Block-on-open scanner backed by the Linux fanotify permission API.

    Kernel I/O is confined to ``_init_fd``/``_mark``/``_read``/``_respond``; the
    surrounding scan-and-decide flow reuses :func:`decide` and the injected
    ``Scanner`` so it can be reasoned about (and unit-tested) without root.
    """

    def __init__(self, scanner: Scanner, *, block_suspicious: bool = False):
        self.scanner = scanner
        self.block_suspicious = block_suspicious
        self._fan_fd: int | None = None
        self._libc = None

    # ── kernel I/O (Linux + root only; unverified on this host) ──
    def _libc_handle(self):
        import ctypes
        if self._libc is None:
            self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        return self._libc

    def _init_fd(self) -> int:
        import ctypes
        libc = self._libc_handle()
        fd = libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY)
        if fd < 0:
            err = ctypes.get_errno()
            raise FanotifyError(f"fanotify_init failed: {os.strerror(err)} "
                                "(needs Linux and root/CAP_SYS_ADMIN)")
        self._fan_fd = fd
        return fd

    def _mark(self, path: str) -> None:
        import ctypes
        libc = self._libc_handle()
        rc = libc.fanotify_mark(
            self._fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_PERM,
            AT_FDCWD, ctypes.c_char_p(path.encode()),
        )
        if rc < 0:
            err = ctypes.get_errno()
            raise FanotifyError(f"fanotify_mark({path}) failed: {os.strerror(err)}")

    def _respond(self, fd: int, allow: bool) -> None:
        response = struct.pack(_RESP_FMT, fd, FAN_ALLOW if allow else FAN_DENY)
        os.write(self._fan_fd, response)

    # ── pure flow ──
    def _path_for(self, event: FanotifyEvent) -> str | None:
        try:
            return os.readlink(f"/proc/self/fd/{event.fd}")
        except OSError:
            return None

    def handle_event(self, event: FanotifyEvent) -> bool:
        """Scan the file behind a permission event and return the allow decision."""
        if not event.is_perm:
            return True
        path = self._path_for(event)
        if path is None:
            return True  # can't resolve -> fail open
        result = self.scanner.scan_file(path)
        return decide(result, block_suspicious=self.block_suspicious)

    def run(self, paths: list[str], *, on_decision: Callable[[str, bool], None] | None = None) -> None:
        """Mark ``paths`` and answer permission events until interrupted.

        Live kernel loop — Linux + root only. Each ``open()`` under a watched
        mount is paused, scanned, and allowed/denied before the process proceeds.
        """
        if not is_supported():
            raise FanotifyError("fanotify is only available on Linux with libc")
        self._init_fd()
        for p in paths:
            self._mark(p)
        try:
            while True:
                try:
                    buf = os.read(self._fan_fd, 4096)
                except BlockingIOError:
                    continue
                offset = 0
                while offset < len(buf):
                    event = parse_event(buf, offset)
                    allow = self.handle_event(event)
                    if event.is_perm:
                        self._respond(event.fd, allow)
                    if event.fd >= 0:
                        os.close(event.fd)
                    if on_decision is not None:
                        path = self._path_for(event) or f"fd={event.fd}"
                        on_decision(path, allow)
                    offset += event.event_len
        except KeyboardInterrupt:
            pass
        finally:
            if self._fan_fd is not None:
                os.close(self._fan_fd)
                self._fan_fd = None
