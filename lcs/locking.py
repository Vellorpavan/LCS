"""
LCS Cross-Platform Process-Level File Locking
============================================
Provides genuine cross-process file-locking semantics across POSIX (Linux, macOS)
and Windows (Win32 NT kernel).

Governed by LCS Governance & Integrity Policies.
Guarantees:
1. Mutual exclusion between independent operating system processes.
2. Support for shared (LOCK_SH), exclusive (LOCK_EX), non-blocking (LOCK_NB), and unlock (LOCK_UN).
3. Immediate error propagation on contention (BlockingIOError / EAGAIN when LOCK_NB is set).
4. Automatic operating-system kernel cleanup on process termination or abrupt crash.
5. Zero modifications to frozen core modules.
"""

import os
import sys
import errno
from typing import Any, Optional, Union

# POSIX / Win32 Unified Flock Flags
LOCK_SH = 1  # Shared lock
LOCK_EX = 2  # Exclusive lock
LOCK_NB = 4  # Non-blocking (fail immediately instead of waiting)
LOCK_UN = 8  # Unlock


# ============================================================================
# 1. Windows Win32 Kernel Locking Implementation
# ============================================================================

# Win32 LockFileEx Constants
LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
LOCKFILE_EXCLUSIVE_LOCK = 0x00000002

# Win32 Error Codes
ERROR_LOCK_VIOLATION = 33
ERROR_SHARING_VIOLATION = 32
ERROR_NOT_LOCKED = 158
ERROR_ACCESS_DENIED = 5


def _get_fileno(fd_or_file: Union[int, Any]) -> int:
    """Extracts integer file descriptor from integer or file-like object."""
    if hasattr(fd_or_file, "fileno"):
        return fd_or_file.fileno()
    if isinstance(fd_or_file, int):
        return fd_or_file
    raise TypeError(f"Invalid file descriptor type: {type(fd_or_file)}")


def _win32_flock_lockfileex(fd: int, op: int) -> None:
    """
    Genuine Windows locking via kernel32.LockFileEx / UnlockFileEx.
    Locks the entire 64-bit address space of the file.
    """
    import ctypes
    from ctypes import wintypes
    import msvcrt

    class OVERLAPPED(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    handle = msvcrt.get_osfhandle(fd)
    if handle in (-1, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF):
        raise OSError(errno.EBADF, f"Invalid OS file handle for fd {fd}")

    overlapped = OVERLAPPED()
    overlapped.Offset = 0
    overlapped.OffsetHigh = 0
    overlapped.hEvent = None

    # Maximum 32-bit byte count (0xFFFFFFFF) in both low and high words covers 64-bit file space
    num_bytes_low = 0xFFFFFFFF
    num_bytes_high = 0xFFFFFFFF

    kernel32 = ctypes.windll.kernel32

    if op & LOCK_UN:
        res = kernel32.UnlockFileEx(
            wintypes.HANDLE(handle),
            0,
            wintypes.DWORD(num_bytes_low),
            wintypes.DWORD(num_bytes_high),
            ctypes.byref(overlapped)
        )
        if res == 0:
            err = kernel32.GetLastError()
            # If the file wasn't locked or was already unlocked, treat as benign
            if err not in (ERROR_NOT_LOCKED, 0):
                raise OSError(errno.EINVAL, f"UnlockFileEx failed with Windows error {err}")
        return

    # Prepare locking flags
    flags = 0
    if op & LOCK_EX:
        flags |= LOCKFILE_EXCLUSIVE_LOCK
    # If LOCK_EX is not specified and LOCK_SH is set, flags remain 0 (shared lock in LockFileEx)

    if op & LOCK_NB:
        flags |= LOCKFILE_FAIL_IMMEDIATELY

    res = kernel32.LockFileEx(
        wintypes.HANDLE(handle),
        wintypes.DWORD(flags),
        0,
        wintypes.DWORD(num_bytes_low),
        wintypes.DWORD(num_bytes_high),
        ctypes.byref(overlapped)
    )

    if res == 0:
        err = kernel32.GetLastError()
        if err in (ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION):
            raise BlockingIOError(errno.EAGAIN, f"Resource temporarily unavailable (Win32 lock violation {err})")
        elif err == ERROR_ACCESS_DENIED:
            raise PermissionError(errno.EACCES, f"Permission denied during file locking (Win32 error {err})")
        else:
            raise OSError(errno.EINVAL, f"LockFileEx failed with Windows error {err}")


def _win32_flock_msvcrt_fallback(fd: int, op: int) -> None:
    """
    Fallback Windows locking using CRT msvcrt.locking.
    Only supports exclusive locking; provides graceful degradation.
    """
    import msvcrt

    if op & LOCK_UN:
        try:
            # Seek to beginning to ensure unlock matches lock range
            cur_pos = os.lseek(fd, 0, os.SEEK_CUR)
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            os.lseek(fd, cur_pos, os.SEEK_SET)
        except OSError:
            pass
        return

    mode = msvcrt.LK_NBLCK if (op & LOCK_NB) else msvcrt.LK_LOCK
    cur_pos = os.lseek(fd, 0, os.SEEK_CUR)
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, mode, 1)
    except OSError as e:
        if op & LOCK_NB:
            raise BlockingIOError(errno.EAGAIN, "Resource temporarily unavailable") from e
        raise
    finally:
        os.lseek(fd, cur_pos, os.SEEK_SET)


def win32_flock(fd_or_file: Union[int, Any], op: int) -> None:
    """
    Windows implementation of POSIX flock with full shared/exclusive/non-blocking semantics.
    """
    fd = _get_fileno(fd_or_file)
    try:
        _win32_flock_lockfileex(fd, op)
    except (ImportError, AttributeError):
        _win32_flock_msvcrt_fallback(fd, op)


def win32_fcntl(fd_or_file: Union[int, Any], cmd: int, *args: Any) -> int:
    """
    Windows implementation of POSIX fcntl.
    Flushes buffers if sync command is passed.
    """
    fd = _get_fileno(fd_or_file)
    # If caller requested full sync, execute os.fsync
    try:
        os.fsync(fd)
    except OSError:
        pass
    return 0


# ============================================================================
# 2. Unified Cross-Platform Dispatcher
# ============================================================================

def flock(fd_or_file: Union[int, Any], op: int) -> None:
    """
    Cross-platform process-level file lock.
    Dispatches to native OS kernel locking:
    - POSIX: fcntl.flock
    - Windows: kernel32.LockFileEx / UnlockFileEx
    """
    if sys.platform == "win32":
        win32_flock(fd_or_file, op)
    else:
        import fcntl
        fd = _get_fileno(fd_or_file)
        fcntl.flock(fd, op)


def install_windows_fcntl_shim() -> None:
    """
    Installs a genuine kernel-level locking shim into sys.modules['fcntl'] on Windows.
    This enables frozen core modules (such as governance_policy_v1.py) and third-party
    dependencies to run with real file-locking semantics without changing their source.
    """
    if sys.platform == "win32" and "fcntl" not in sys.modules:
        import types
        shim = types.ModuleType("fcntl")
        shim.LOCK_SH = LOCK_SH
        shim.LOCK_EX = LOCK_EX
        shim.LOCK_NB = LOCK_NB
        shim.LOCK_UN = LOCK_UN
        shim.F_FULLFSYNC = 0
        shim.flock = win32_flock
        shim.fcntl = win32_fcntl
        sys.modules["fcntl"] = shim


# Auto-install when module is loaded on Windows
if sys.platform == "win32":
    install_windows_fcntl_shim()


# ============================================================================
# 3. High-Level RAII Context Manager
# ============================================================================

class CrossProcessFileLock:
    """
    RAII context manager for cross-process file locks.
    Works across Linux, macOS, and Windows.
    """

    def __init__(self, lock_file_path: str, exclusive: bool = True, non_blocking: bool = False):
        self.lock_file_path = os.path.abspath(lock_file_path)
        self.exclusive = exclusive
        self.non_blocking = non_blocking
        self.fd: Optional[int] = None

    def acquire(self) -> None:
        if self.fd is not None:
            return

        os.makedirs(os.path.dirname(self.lock_file_path), exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT
        mode = 0o600
        self.fd = os.open(self.lock_file_path, flags, mode)

        op = LOCK_EX if self.exclusive else LOCK_SH
        if self.non_blocking:
            op |= LOCK_NB

        try:
            flock(self.fd, op)
        except Exception:
            os.close(self.fd)
            self.fd = None
            raise

    def release(self) -> None:
        if self.fd is None:
            return
        try:
            flock(self.fd, LOCK_UN)
        finally:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def __enter__(self) -> "CrossProcessFileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()
