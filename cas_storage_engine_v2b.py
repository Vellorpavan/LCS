#!/usr/bin/env python3
"""
LCS Stage 2B Secure CAS Storage Engine
==========================================
Implements production-grade descriptor-relative CAS publication, trusted anchor
root initialization, strict partial/short-write handling with EINTR and orphan
quarantine, persistent HMAC key management, and full GC / publisher database-filesystem coordination.

Architecture & Security Invariants:
  1. Trusted Anchor Root Resolution & Inode Pinning:
     - Root initialization anchors to a trusted operator directory.
     - Traverses down step-by-step using descriptor-relative mkdirat and openat
       with O_DIRECTORY | O_NOFOLLOW.
     - Verifies st_dev on every step to prevent mount/symlink redirection attacks.
  2. Short-Write, EINTR & Partial-Write Safety:
     - os.write() executes in a loop using memoryviews, retrying on EINTR.
     - Only bytes accepted by kernel are hashed and added to total_written.
     - On write interruption, disk-full (ENOSPC), or premature EOF, staging file
       descriptor is closed and unlinked descriptor-relative.
     - Staging unlink failures are NEVER silently suppressed: failed unlinks
       are quarantined into a recovery registry and raise CASStagingCleanupError.
  3. Publisher & GC State Coordination:
     - Coordinates database reservation with physical filesystem deletion.
     - Prevents concurrent re-registration or linking while a blob is reserved
       for garbage collection (COMMITTED_FOR_UNLINK).
     - Provides restart recovery for interrupted GC unlinks.
  4. Strict Durability Guarantees:
     - Directory synchronization failures are NEVER suppressed.
     - macOS F_FULLFSYNC is distinguished from FSYNC_FALLBACK.
"""

import os
import sys
import json
import stat
import uuid
import hmac
import time
import errno
import fcntl
import sqlite3
import hashlib
import threading
from typing import Tuple, Dict, Any, Optional, Iterable, Union, List
from contextlib import contextmanager

class CASError(Exception):
    """Base exception for all CAS storage engine errors."""
    pass

class CASDeviceBoundaryViolationError(CASError):
    """Raised when traversal attempts to cross filesystem device boundaries."""
    pass

class CASPartialWriteError(CASError):
    """Raised when writing to staging fails, is truncated, or produces a partial file."""
    pass

class CASStagingCleanupError(CASError):
    """Raised when cleaning up a staging file fails (never silently suppressed)."""
    pass

class CASDigestMismatchError(CASError):
    """Raised when payload bytes do not match expected cryptographic digest."""
    pass

class CASDestinationCorruptionError(CASError):
    """Raised when destination exists but contains mismatched/corrupted payload."""
    pass

class CASDirectorySyncError(CASError):
    """Raised when directory fsync fails (never suppressed)."""
    pass

class CASDurabilityError(CASError):
    """Raised when strict durability guarantee cannot be satisfied."""
    pass

class CASSecurityViolationError(CASError):
    """Raised when symlinks or unauthorized ancestor replacements are detected."""
    pass

class CASPublicationConflictError(CASError):
    """Raised when a publisher conflicts with an active GC reservation."""
    pass

class CASInterruptionError(CASError):
    """Raised to simulate process crash or power interruption at specific operational boundaries."""
    pass

class CASValidationError(CASSecurityViolationError):
    """Raised when an invalid digest, path, or argument is provided."""
    pass

class CASDeletionError(CASError):
    """Raised when physical deletion of a CAS blob fails."""
    pass

class CASCorruptedKeyRingError(CASSecurityViolationError):
    """Raised when the persistent key ring is missing, truncated, corrupted, or structurally invalid."""
    pass

class CASSigningSuspendedError(CASSecurityViolationError):
    """Raised when receipt signing is requested while key persistence is indeterminate or suspended."""
    pass

class CASKeySyncError(CASDurabilityError):
    """Raised when synchronizing key ring file or directory fails."""
    pass
class CASBlobNotFoundError(CASError):
    """Raised when a requested CAS blob does not exist in storage."""
    pass


class SecureCASDirectoryWalker:
    """
    Component-by-component traversal engine that pins directory descriptors
    and enforces st_dev invariants to defeat ancestor swaps and symlink traps.
    """
    def __init__(self, cas_root: str, existing_fd: Optional[int] = None):
        self.cas_root = os.path.abspath(cas_root)
        
        if existing_fd is not None:
            self.root_fd = existing_fd
        else:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
            try:
                self.root_fd = os.open(self.cas_root, flags)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EEXIST, errno.EMLINK):
                    raise CASSecurityViolationError(f"CAS root path '{self.cas_root}' is a symbolic link or non-directory: {e}") from e
                if e.errno == errno.ENOENT:
                    raise FileNotFoundError(f"CAS root directory does not exist: {self.cas_root}") from e
                raise
            
        st = os.fstat(self.root_fd)
        if not stat.S_ISDIR(st.st_mode):
            os.close(self.root_fd)
            raise NotADirectoryError(f"CAS root path is not a directory: {self.cas_root}")
            
        self.dev = st.st_dev
        self.root_ino = st.st_ino

    def close(self):
        if self.root_fd is not None:
            try:
                os.close(self.root_fd)
            except OSError:
                pass
            self.root_fd = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open_subpath_descriptor(self, relative_path: str, create: bool = False) -> int:
        """
        Walks subpath component by component starting strictly from root_fd.
        Every intermediate component is opened with O_DIRECTORY | O_NOFOLLOW.
        If create is True, components are created descriptor-relative via os.mkdir(..., dir_fd=current_fd).
        Validates st_dev on every component against root_dev.
        """
        components = [c for c in relative_path.strip('/').split('/') if c and c != '.']
        for c in components:
            if c == '..':
                raise CASSecurityViolationError("Relative path navigation ('..') is strictly forbidden")
                
        current_fd = os.dup(self.root_fd)
        for comp in components:
            if create:
                try:
                    os.mkdir(comp, 0o755, dir_fd=current_fd)
                except FileExistsError:
                    pass
                except OSError as e:
                    os.close(current_fd)
                    raise CASSecurityViolationError(f"Failed to create directory component '{comp}' descriptor-relative: {e}") from e
                    
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
            try:
                next_fd = os.open(comp, flags, dir_fd=current_fd)
            except OSError as e:
                os.close(current_fd)
                if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EEXIST, errno.EMLINK):
                    raise CASSecurityViolationError(f"Directory traversal component '{comp}' is a symlink or non-directory: {e}") from e
                raise
                
            st = os.fstat(next_fd)
            if not stat.S_ISDIR(st.st_mode):
                os.close(next_fd)
                os.close(current_fd)
                raise NotADirectoryError(f"Component '{comp}' is not a directory")
                
            if st.st_dev != self.dev:
                os.close(next_fd)
                os.close(current_fd)
                raise CASDeviceBoundaryViolationError(
                    f"Cross-device link rejected at component '{comp}' (st_dev {st.st_dev} != root {self.dev})"
                )
                
            os.close(current_fd)
            current_fd = next_fd
            
        return current_fd


class PersistentReceiptKeyStore:
    """
    Manages persistent, versioned HMAC signing and verification keys for LCS physical evidence receipts.
    Ensures keys survive process restarts, supports key rotation with backwards compatibility,
    enforces strict POSIX permissions (0700 dir, 0600 file), prevents symlink hijacking,
    coordinates writers via advisory file locking, and enforces fail-closed durability.
    """
    def __init__(self, key_store_dir: str, allow_bootstrap: bool = True):
        self.key_store_dir = os.path.abspath(key_store_dir)
        self.allow_bootstrap = allow_bootstrap
        
        # Ensure 0700 permissions on directory without following symlinks
        if not os.path.exists(self.key_store_dir):
            if not self.allow_bootstrap:
                raise CASCorruptedKeyRingError(
                    f"CAS_KEY_STORE_NOT_FOUND: Key store directory '{self.key_store_dir}' does not exist and bootstrap is disabled."
                )
            os.makedirs(self.key_store_dir, mode=0o700, exist_ok=True)
            
        # Verify directory is a real directory and not a symlink
        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            dir_fd = os.open(self.key_store_dir, dir_flags)
        except OSError as e:
            raise CASSecurityViolationError(f"Key store directory '{self.key_store_dir}' is invalid or a symlink: {e}") from e
        try:
            st = os.fstat(dir_fd)
            if not stat.S_ISDIR(st.st_mode):
                raise CASSecurityViolationError(f"Key store directory '{self.key_store_dir}' is not a directory")
            if stat.S_IMODE(st.st_mode) != 0o700:
                try:
                    os.fchmod(dir_fd, 0o700)
                except OSError:
                    pass
                st_after = os.fstat(dir_fd)
                if stat.S_IMODE(st_after.st_mode) != 0o700:
                    raise CASSecurityViolationError(
                        f"Key store directory '{self.key_store_dir}' permissions {oct(stat.S_IMODE(st_after.st_mode))} != 0700"
                    )
        finally:
            os.close(dir_fd)

        self.key_file_path = os.path.join(self.key_store_dir, "key_ring.json")
        self.lock_file_path = os.path.join(self.key_store_dir, ".lock")
        self.active_key_id: str = "k1"
        self.keys: Dict[str, bytes] = {}
        self.signing_suspended: bool = False
        self.persistence_state: str = "INITIALIZING"

        # Load or initialize under exclusive lock
        with self._locked_transaction():
            self._load_or_initialize_under_lock()
            self._cleanup_stale_temp_files_under_lock()

    @contextmanager
    def _locked_transaction(self):
        lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(self.lock_file_path, lock_flags, 0o600)
        except OSError as e:
            raise CASSecurityViolationError(f"Failed to open lock file '{self.lock_file_path}': {e}") from e

        try:
            st = os.fstat(lock_fd)
            if not stat.S_ISREG(st.st_mode):
                raise CASSecurityViolationError(f"Lock file '{self.lock_file_path}' is not a regular file")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            os.close(lock_fd)

    def _sync_fd(self, fd: int, is_directory: bool = False) -> str:
        """
        Executes physical write-through flush on file or directory descriptor.
        Prefers Darwin F_FULLFSYNC when available, falling back to os.fsync on ENOTSUP/ENOTTY/EINVAL.
        """
        if sys.platform == "darwin" and hasattr(fcntl, "F_FULLFSYNC"):
            try:
                fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
                return "F_FULLFSYNC"
            except OSError as e:
                if e.errno in (errno.ENOTSUP, errno.ENOTTY, errno.EINVAL, getattr(errno, "EOPNOTSUPP", 45)):
                    os.fsync(fd)
                    return "FSYNC_FALLBACK"
                raise
        else:
            os.fsync(fd)
            return "FSYNC"

    @classmethod
    def _validate_key_ring_dict(cls, data: Any) -> Dict[str, Any]:
        """
        Validates the complete key-ring structure and semantics:
        1. JSON top-level object.
        2. schema_version is integer 1 (or version == 1).
        3. active_key_id is non-empty string.
        4. keys dictionary is non-empty.
        5. active_key_id is a member of keys.
        6. Each key has valid key_id, algorithm HMAC-SHA256, 64-char hex secret (32 bytes), valid status.
        7. Active key has status 'ACTIVE'; all other keys have status 'RETIRED' or 'DEPRECATED'.
        """
        if not isinstance(data, dict):
            raise CASCorruptedKeyRingError(f"Key ring payload must be a JSON object, got {type(data).__name__}")
        
        version = data.get("schema_version", data.get("version"))
        if version != 1:
            raise CASCorruptedKeyRingError(f"Unsupported key ring schema_version: {version} (expected 1)")
        
        active_id = data.get("active_key_id")
        if not isinstance(active_id, str) or not active_id:
            raise CASCorruptedKeyRingError(f"Invalid or missing active_key_id: {active_id!r}")
        
        raw_keys = data.get("keys")
        if not isinstance(raw_keys, dict) or not raw_keys:
            raise CASCorruptedKeyRingError("Key ring 'keys' must be a non-empty object")
        
        if active_id not in raw_keys:
            raise CASCorruptedKeyRingError(f"Active key '{active_id}' is not present in keys collection")
        
        validated_keys: Dict[str, bytes] = {}
        for k_id, k_val in raw_keys.items():
            if not isinstance(k_id, str) or not k_id:
                raise CASCorruptedKeyRingError(f"Invalid key identifier: {k_id!r}")
            if not isinstance(k_val, dict):
                raise CASCorruptedKeyRingError(f"Key entry for '{k_id}' must be an object")
            if k_val.get("key_id") != k_id:
                raise CASCorruptedKeyRingError(f"Key entry id '{k_val.get('key_id')}' does not match dictionary key '{k_id}'")
            if k_val.get("algorithm") != "HMAC-SHA256":
                raise CASCorruptedKeyRingError(f"Key '{k_id}' specifies unsupported algorithm '{k_val.get('algorithm')}'")
            
            secret_hex = k_val.get("secret_hex")
            if not isinstance(secret_hex, str) or len(secret_hex) != 64:
                raise CASCorruptedKeyRingError(f"Key '{k_id}' has invalid secret_hex (expected 64 hex characters)")
            try:
                secret_bytes = bytes.fromhex(secret_hex)
            except ValueError as e:
                raise CASCorruptedKeyRingError(f"Key '{k_id}' secret_hex is not valid hex: {e}") from e
            if len(secret_bytes) != 32:
                raise CASCorruptedKeyRingError(f"Key '{k_id}' secret bytes length {len(secret_bytes)} != 32")
            
            status = k_val.get("status")
            if k_id == active_id:
                if status != "ACTIVE":
                    raise CASCorruptedKeyRingError(f"Active key '{k_id}' must have status 'ACTIVE', got '{status}'")
            else:
                if status not in ("RETIRED", "DEPRECATED"):
                    raise CASCorruptedKeyRingError(f"Inactive key '{k_id}' must have status 'RETIRED', got '{status}'")
            
            validated_keys[k_id] = secret_bytes
            
        return {
            "schema_version": 1,
            "active_key_id": active_id,
            "keys": validated_keys,
            "raw": data
        }

    def _load_or_initialize_under_lock(self) -> None:
        if not os.path.exists(self.key_file_path):
            if not self.allow_bootstrap:
                raise CASCorruptedKeyRingError(
                    f"CAS_KEY_RING_NOT_FOUND: Key ring file '{self.key_file_path}' does not exist; silent regeneration is prohibited"
                )
            initial_secret = os.urandom(32)
            self.active_key_id = "k1"
            self.keys = {"k1": initial_secret}
            self._save_under_lock(atomic_create_only=True)
            self.signing_suspended = False
            self.persistence_state = "COMMITTED"
            return

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.key_file_path, flags)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise CASSecurityViolationError(f"Key ring file '{self.key_file_path}' is a symbolic link: {e}") from e
            raise CASCorruptedKeyRingError(f"Failed to open key ring file '{self.key_file_path}': {e}") from e

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise CASSecurityViolationError(f"Key ring file '{self.key_file_path}' is not a regular file")
            if stat.S_IMODE(st.st_mode) != 0o600:
                raise CASSecurityViolationError(
                    f"Key ring file '{self.key_file_path}' permissions {oct(stat.S_IMODE(st.st_mode))} != 0600"
                )
            content = os.read(fd, st.st_size if st.st_size > 0 else 65536)
            if not content:
                raise CASCorruptedKeyRingError(f"Key ring file '{self.key_file_path}' is empty / zero-length")
            try:
                data = json.loads(content.decode("utf-8"))
            except Exception as e:
                raise CASCorruptedKeyRingError(f"Key ring file '{self.key_file_path}' contains corrupted JSON: {e}") from e
        finally:
            os.close(fd)

        val = self._validate_key_ring_dict(data)
        self.active_key_id = val["active_key_id"]
        self.keys = val["keys"]
        self.signing_suspended = False
        self.persistence_state = "COMMITTED"

    def _save_under_lock(
        self,
        atomic_create_only: bool = False,
        inject_crash_before_replace: bool = False,
        inject_crash_after_replace: bool = False,
        inject_dir_sync_error: bool = False
    ) -> None:
        data = {
            "schema_version": 1,
            "active_key_id": self.active_key_id,
            "keys": {
                k: {
                    "key_id": k,
                    "algorithm": "HMAC-SHA256",
                    "secret_hex": v.hex(),
                    "status": "ACTIVE" if k == self.active_key_id else "RETIRED",
                    "created_at_ns": int(time.time() * 1e9)
                }
                for k, v in self.keys.items()
            }
        }
        
        tmp_name = f".key_ring.json.tmp.{os.getpid()}_{threading.get_ident()}_{uuid.uuid4().hex}"
        tmp_path = os.path.join(self.key_store_dir, tmp_name)
        open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        
        fd = os.open(tmp_path, open_flags, 0o600)
        try:
            payload_bytes = json.dumps(data, indent=2).encode("utf-8")
            total_written = 0
            while total_written < len(payload_bytes):
                try:
                    n = os.write(fd, payload_bytes[total_written:])
                    if n == 0:
                        raise OSError("Premature EOF during key write")
                    total_written += n
                except InterruptedError:
                    continue
            
            self._sync_fd(fd)
        finally:
            os.close(fd)

        if inject_crash_before_replace:
            raise CASInterruptionError("INJECTED_CRASH_BEFORE_REPLACE")

        if atomic_create_only:
            try:
                os.link(tmp_path, self.key_file_path)
            except FileExistsError:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
            except OSError as e:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise CASKeySyncError(f"Failed to atomically link key ring file: {e}") from e
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
        else:
            try:
                os.replace(tmp_path, self.key_file_path)
            except OSError as e:
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                raise CASKeySyncError(f"Failed to atomically replace key ring file: {e}") from e

        try:
            os.chmod(self.key_file_path, 0o600)
        except OSError:
            pass

        if inject_crash_after_replace:
            raise CASInterruptionError("INJECTED_CRASH_AFTER_REPLACE")

        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            dir_fd = os.open(self.key_store_dir, dir_flags)
        except OSError as e:
            self.signing_suspended = True
            self.persistence_state = "FAILED_INDETERMINATE"
            raise CASDirectorySyncError(f"Failed to open key directory '{self.key_store_dir}' for sync: {e}") from e

        try:
            if inject_dir_sync_error:
                raise OSError(errno.EIO, "Simulated I/O error during directory sync")
            self._sync_fd(dir_fd, is_directory=True)
        except OSError as e:
            self.signing_suspended = True
            self.persistence_state = "FAILED_INDETERMINATE"
            raise CASDirectorySyncError(f"Failed to synchronize key directory '{self.key_store_dir}': {e}") from e
        finally:
            os.close(dir_fd)

        self.signing_suspended = False
        self.persistence_state = "COMMITTED"

    def rotate_key(
        self,
        new_key_id: Optional[str] = None,
        inject_crash_before_replace: bool = False,
        inject_crash_after_replace: bool = False,
        inject_dir_sync_error: bool = False
    ) -> Tuple[str, bytes]:
        with self._locked_transaction():
            # Read phase of read-modify-write under exclusive lock
            self._load_or_initialize_under_lock()
            old_active_id = self.active_key_id
            old_keys = dict(self.keys)
            
            if new_key_id is None:
                new_key_id = f"k{len(self.keys) + 1}"
            if new_key_id in self.keys:
                raise CASValidationError(f"Key ID '{new_key_id}' already exists in key ring")
                
            new_secret = os.urandom(32)
            self.keys[new_key_id] = new_secret
            self.active_key_id = new_key_id
            
            try:
                self._save_under_lock(
                    atomic_create_only=False,
                    inject_crash_before_replace=inject_crash_before_replace,
                    inject_crash_after_replace=inject_crash_after_replace,
                    inject_dir_sync_error=inject_dir_sync_error
                )
            except Exception:
                self.active_key_id = old_active_id
                self.keys = old_keys
                self.signing_suspended = True
                self.persistence_state = "FAILED_INDETERMINATE"
                raise
                
            return new_key_id, new_secret

    def get_active_key(self) -> Tuple[str, bytes]:
        if self.signing_suspended or self.persistence_state != "COMMITTED":
            raise CASSigningSuspendedError(
                f"CAS_SIGNING_SUSPENDED: Key persistence state is '{self.persistence_state}'; receipt signing is strictly forbidden."
            )
        if self.active_key_id not in self.keys:
            raise CASCorruptedKeyRingError(f"Active key '{self.active_key_id}' missing from memory keys")
        return self.active_key_id, self.keys[self.active_key_id]

    def get_key(self, key_id: str) -> bytes:
        if key_id not in self.keys:
            raise CASSecurityViolationError(
                f"CAS_TAMPERING_DETECTED: Key ID '{key_id}' not found in persistent key store"
            )
        return self.keys[key_id]

    def recover_key_ring(self) -> bool:
        """
        Reconciles in-memory key ring with authoritative on-disk state under lock.
        Attempts directory sync to clear FAILED_INDETERMINATE state if disk contains valid key ring.
        Returns True if signing is re-enabled, False if directory sync still fails.
        """
        with self._locked_transaction():
            try:
                self._load_or_initialize_under_lock()
            except Exception:
                self.signing_suspended = True
                self.persistence_state = "CORRUPTED"
                raise
                
            dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                dir_fd = os.open(self.key_store_dir, dir_flags)
            except OSError:
                self.signing_suspended = True
                self.persistence_state = "FAILED_INDETERMINATE"
                return False
                
            try:
                self._sync_fd(dir_fd, is_directory=True)
                self.signing_suspended = False
                self.persistence_state = "COMMITTED"
                self._cleanup_stale_temp_files_under_lock()
                return True
            except OSError:
                self.signing_suspended = True
                self.persistence_state = "FAILED_INDETERMINATE"
                return False
            finally:
                os.close(dir_fd)

    def _cleanup_stale_temp_files_under_lock(self, stale_threshold_seconds: float = 60.0) -> int:
        cleaned_count = 0
        now = time.time()
        try:
            entries = os.listdir(self.key_store_dir)
        except OSError:
            return 0
            
        for entry in entries:
            if not entry.startswith(".key_ring.json.tmp."):
                continue
            entry_path = os.path.join(self.key_store_dir, entry)
            try:
                st = os.stat(entry_path, follow_symlinks=False)
            except OSError:
                continue
                
            if stat.S_ISLNK(st.st_mode):
                try:
                    os.unlink(entry_path)
                    cleaned_count += 1
                except OSError:
                    pass
                continue
                
            parts = entry.split(".")
            is_dead_pid = False
            if len(parts) >= 5:
                pid_thread_uuid = parts[4]
                pid_str = pid_thread_uuid.split("_")[0]
                try:
                    pid = int(pid_str)
                    os.kill(pid, 0)
                except ProcessLookupError:
                    is_dead_pid = True
                except (ValueError, PermissionError, OSError):
                    is_dead_pid = False
                    
            age = now - st.st_mtime
            if is_dead_pid or age > stale_threshold_seconds:
                try:
                    os.unlink(entry_path)
                    cleaned_count += 1
                except OSError:
                    pass
                    
        return cleaned_count


class SecureCASStorageEngine:
    """
    Authoritative Descriptor-Relative CAS Storage Engine with robust short-write
    handling, atomic partial-write recovery, unsuppressed directory sync,
    persistent HMAC key management, and trusted anchor root initialization.
    """
    def __init__(
        self,
        cas_root: str,
        strict_fullfsync: bool = True,
        trusted_anchor: Optional[str] = None,
        key_store_dir: Optional[str] = None
    ):
        if trusted_anchor is None:
            raise CASSecurityViolationError(
                "Explicit trusted_anchor directory is required; implicit parent guessing is prohibited."
            )
        if not isinstance(trusted_anchor, str) or not os.path.isabs(trusted_anchor):
            raise CASSecurityViolationError(
                f"Trusted anchor must be an absolute directory path, got: {trusted_anchor}"
            )
            
        self.cas_root = os.path.abspath(cas_root)
        self.strict_fullfsync = strict_fullfsync
        self.quarantined_orphans: List[Dict[str, Any]] = []
        
        # 1. Validate anchor ancestry from filesystem root down to trusted_anchor with O_NOFOLLOW
        norm_anchor = os.path.normpath(trusted_anchor)
        parts = [p for p in norm_anchor.split(os.sep) if p]
        
        root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            curr_fd = os.open("/", root_flags)
        except OSError as e:
            raise CASSecurityViolationError(f"Failed to open filesystem root descriptor: {e}") from e
            
        try:
            for part in parts:
                try:
                    st = os.stat(part, dir_fd=curr_fd, follow_symlinks=False)
                except OSError as e:
                    raise CASSecurityViolationError(f"Failed to inspect anchor path component '{part}': {e}") from e
                    
                if stat.S_ISLNK(st.st_mode):
                    raise CASSecurityViolationError(
                        f"Symlink detected in trusted anchor ancestry at component '{part}': "
                        f"symlinks are prohibited within trusted anchor hierarchy."
                    )
                if not stat.S_ISDIR(st.st_mode):
                    raise CASSecurityViolationError(
                        f"Component '{part}' in trusted anchor path is not a directory."
                    )
                    
                next_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
                try:
                    next_fd = os.open(part, next_flags, dir_fd=curr_fd)
                except OSError as e:
                    raise CASSecurityViolationError(
                        f"Cannot securely open anchor component '{part}' with O_NOFOLLOW: {e}"
                    ) from e
                os.close(curr_fd)
                curr_fd = next_fd
                
            anchor_fd = curr_fd
            anchor_st = os.fstat(anchor_fd)
        except Exception:
            os.close(curr_fd)
            raise
            
                # Align cas_root if an ancestor resolves to norm_anchor (e.g. system aliases like /var -> /private/var)
        if not self.cas_root.startswith(norm_anchor):
            p = self.cas_root
            sub = []
            while p and p != os.path.dirname(p):
                if os.path.exists(p) and os.path.realpath(p) == norm_anchor:
                    self.cas_root = os.path.join(norm_anchor, *sub) if sub else norm_anchor
                    break
                sub.insert(0, os.path.basename(p))
                p = os.path.dirname(p)

        # 2. Verify cas_root is located beneath or equal to trusted_anchor
        rel_to_anchor = os.path.relpath(self.cas_root, norm_anchor)
        if rel_to_anchor == ".." or rel_to_anchor.startswith(".." + os.sep):
            os.close(anchor_fd)
            raise CASSecurityViolationError(
                f"cas_root '{self.cas_root}' is outside trusted_anchor '{norm_anchor}'"
            )
            
        current_fd = anchor_fd
        if rel_to_anchor != ".":
            components = [c for c in rel_to_anchor.strip('/').split('/') if c and c != '.']
            for comp in components:
                if comp == '..':
                    os.close(current_fd)
                    raise CASSecurityViolationError("Parent path traversal forbidden in root initialization")
                    
                # Descriptor-relative check before creation
                try:
                    comp_st = os.stat(comp, dir_fd=current_fd, follow_symlinks=False)
                    if stat.S_ISLNK(comp_st.st_mode):
                        os.close(current_fd)
                        raise CASSecurityViolationError(f"Symlink detected beneath trusted anchor at '{comp}'")
                    if not stat.S_ISDIR(comp_st.st_mode):
                        os.close(current_fd)
                        raise CASSecurityViolationError(f"Component '{comp}' beneath trusted anchor is not a directory")
                except FileNotFoundError:
                    try:
                        os.mkdir(comp, 0o755, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    except OSError as e:
                        os.close(current_fd)
                        raise CASSecurityViolationError(f"Failed to create root directory component '{comp}' descriptor-relative: {e}") from e
                    comp_st = os.stat(comp, dir_fd=current_fd, follow_symlinks=False)
                    if stat.S_ISLNK(comp_st.st_mode) or not stat.S_ISDIR(comp_st.st_mode):
                        os.close(current_fd)
                        raise CASSecurityViolationError(f"Component '{comp}' created beneath anchor is invalid")
                        
                next_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
                try:
                    next_fd = os.open(comp, next_flags, dir_fd=current_fd)
                except OSError as e:
                    os.close(current_fd)
                    raise CASSecurityViolationError(f"Failed to open root directory component '{comp}' securely: {e}") from e
                    
                st = os.fstat(next_fd)
                if not stat.S_ISDIR(st.st_mode):
                    os.close(next_fd)
                    os.close(current_fd)
                    raise CASSecurityViolationError(f"Root component '{comp}' is not a directory")
                if st.st_dev != anchor_st.st_dev:
                    os.close(next_fd)
                    os.close(current_fd)
                    raise CASDeviceBoundaryViolationError(f"Cross-device boundary detected at component '{comp}'")
                    
                os.close(current_fd)
                current_fd = next_fd
                
        # current_fd is now the verified, pinned file descriptor for cas_root
        self.walker = SecureCASDirectoryWalker(self.cas_root, existing_fd=current_fd)
        
        # Ensure standard subdirectories exist descriptor-relative without following symlinks
        self.staging_dir_fd = self.walker.open_subpath_descriptor("staging", create=True)
        obj_fd = self.walker.open_subpath_descriptor("objects", create=True)
        os.close(obj_fd)

        # Initialize persistent key store within trusted anchor
        if key_store_dir is None:
            self.key_store_dir = os.path.join(norm_anchor, ".lcs_keys")
        else:
            self.key_store_dir = os.path.abspath(key_store_dir)
        self.key_store = PersistentReceiptKeyStore(self.key_store_dir)

    @property
    def session_secret(self) -> bytes:
        """Backwards compatibility property returning the active key secret."""
        return self.key_store.get_active_key()[1]

    def close(self):
        if self.staging_dir_fd is not None:
            try:
                os.close(self.staging_dir_fd)
            except OSError:
                pass
            self.staging_dir_fd = None
        self.walker.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_shard_dir_descriptor(self, shard_prefix: str) -> int:
        """Opens or creates a 2-character shard directory descriptor-relative."""
        shard_path = f"objects/{shard_prefix}"
        return self.walker.open_subpath_descriptor(shard_path, create=True)

    def write_payload_to_staging(
        self,
        pub_id: str,
        token: str,
        expected_digest: str,
        data_generator_or_bytes: Union[bytes, bytearray, Iterable[bytes]],
        short_write_limit: Optional[int] = None,
        simulated_write_failure_after_bytes: Optional[int] = None,
        simulate_eintr_times: int = 0,
        simulate_unlink_failure: bool = False
    ) -> Tuple[str, int, str]:
        """
        Writes data descriptor-relative to staging with robust short-write loop and EINTR handling.
        Never assumes a single os.write() call writes the entire buffer.
        Maintains exact byte count and hashes strictly the bytes written.
        On any error or truncation, closes descriptor and attempts descriptor-relative unlink.
        If unlink fails, the orphan state is recorded in quarantined_orphans and CASStagingCleanupError is raised.
        Returns: (tmp_filename, total_bytes, durability_level)
        """
        tmp_filename = f"tmp_{pub_id}_{token}_{expected_digest[:16]}.part"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW
        
        try:
            staging_file_fd = os.open(tmp_filename, flags, mode=0o600, dir_fd=self.staging_dir_fd)
        except OSError as e:
            raise CASError(f"Failed to create staging file '{tmp_filename}' descriptor-relative: {e}") from e
            
        hasher = hashlib.sha256()
        total_written = 0
        eintr_count = 0
        
        try:
            chunks = [data_generator_or_bytes] if isinstance(data_generator_or_bytes, (bytes, bytearray)) else data_generator_or_bytes
            for chunk in chunks:
                mv = memoryview(chunk)
                while len(mv) > 0:
                    # Enforce simulated failure threshold
                    if simulated_write_failure_after_bytes is not None and total_written >= simulated_write_failure_after_bytes:
                        raise OSError(errno.ENOSPC, "No space left on device (simulated disk full)")
                        
                    # Handle simulated EINTR
                    if eintr_count < simulate_eintr_times:
                        eintr_count += 1
                        # Simulates interrupt; loop continues seamlessly
                        continue
                        
                    # Determine write chunk size (allowing short-write testing)
                    write_size = len(mv)
                    if short_write_limit is not None and short_write_limit > 0:
                        write_size = min(write_size, short_write_limit)
                    if simulated_write_failure_after_bytes is not None:
                        allowed = simulated_write_failure_after_bytes - total_written
                        write_size = min(write_size, allowed)
                        
                    try:
                        written = os.write(staging_file_fd, mv[:write_size])
                    except OSError as oe:
                        if oe.errno == errno.EINTR:
                            continue
                        raise
                        
                    if written == 0:
                        raise CASPartialWriteError(f"Zero bytes returned by os.write for staging file '{tmp_filename}'")
                        
                    # Maintain strict invariant: only hash and count bytes actually committed to kernel
                    hasher.update(mv[:written])
                    total_written += written
                    mv = mv[written:]
                    
                    if simulated_write_failure_after_bytes is not None and total_written >= simulated_write_failure_after_bytes:
                        raise OSError(errno.ENOSPC, "No space left on device (simulated disk full)")
                        
            actual_digest = hasher.hexdigest()
            if actual_digest != expected_digest:
                raise CASDigestMismatchError(
                    f"DIGEST_MISMATCH_ERROR: payload hash '{actual_digest}' != expected '{expected_digest}'"
                )
                
            # Apply read-only permissions descriptor-relative (0o444)
            os.fchmod(staging_file_fd, 0o444)
            
            # Durability flush
            durability_level = "FSYNC"
            if hasattr(fcntl, "F_FULLFSYNC"):
                try:
                    fcntl.fcntl(staging_file_fd, fcntl.F_FULLFSYNC)
                    durability_level = "F_FULLFSYNC"
                except OSError as e:
                    if self.strict_fullfsync:
                        raise CASDurabilityError(f"F_FULLFSYNC required on macOS but failed: {e}") from e
                    os.fsync(staging_file_fd)
                    durability_level = "FSYNC_FALLBACK"
            else:
                if hasattr(os, "fdatasync"):
                    os.fdatasync(staging_file_fd)
                    durability_level = "FDATASYNC"
                else:
                    os.fsync(staging_file_fd)
                    durability_level = "FSYNC"
                    
        except Exception as write_err:
            # Atomic partial-write cleanup: close descriptor and unlink staging file relative to staging_dir_fd
            try:
                os.close(staging_file_fd)
            except OSError:
                pass
                
            unlink_failed = False
            unlink_err_msg = ""
            
            if simulate_unlink_failure:
                unlink_failed = True
                unlink_err_msg = "Simulated unlink failure (EIO/EBUSY)"
            else:
                try:
                    os.unlink(tmp_filename, dir_fd=self.staging_dir_fd)
                except OSError as ue:
                    unlink_failed = True
                    unlink_err_msg = str(ue)
                    
            if unlink_failed:
                orphan_rec = {
                    "tmp_filename": tmp_filename,
                    "pub_id": pub_id,
                    "token": token,
                    "expected_digest": expected_digest,
                    "bytes_written": total_written,
                    "error": unlink_err_msg,
                    "quarantined_at": time.time()
                }
                self.quarantined_orphans.append(orphan_rec)
                raise CASStagingCleanupError(
                    f"Failed to unlink staging file '{tmp_filename}' descriptor-relative: {unlink_err_msg}. "
                    f"Recorded in orphan quarantine registry for recovery."
                ) from write_err
                
            raise write_err
            
        os.close(staging_file_fd)
        return tmp_filename, total_written, durability_level

    def durable_scan_and_recover_staging_orphans(
        self,
        conn: Optional[sqlite3.Connection] = None,
        max_age_seconds: int = 0
    ) -> int:
        """
        Durable staging directory sweeper that enumerates entries directly via self.staging_dir_fd.
        Inspects entries descriptor-relative with follow_symlinks=False.
        Rejects symlinks and unexpected file types with CASSecurityViolationError.
        Unlinks descriptor-relative via self.staging_dir_fd.
        Synchronizes staging directory descriptor after any cleanup.
        """
        recovered = 0
        now = time.time()
        
        # Enumerate directory entries descriptor-relative
        try:
            entries = os.listdir(self.staging_dir_fd)
        except OSError as e:
            raise CASError(f"Failed to scan staging directory descriptor: {e}") from e
            
        for entry in entries:
            # Check descriptor-relative metadata without following symlinks
            try:
                st = os.stat(entry, dir_fd=self.staging_dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError as e:
                raise CASError(f"Failed to stat staging entry '{entry}' descriptor-relative: {e}") from e
                
            # Strictly reject symlinks and non-regular files
            if stat.S_ISLNK(st.st_mode):
                raise CASSecurityViolationError(
                    f"Security violation in staging directory: entry '{entry}' is a symbolic link. "
                    f"Symlinks are strictly prohibited in CAS staging."
                )
            if not stat.S_ISREG(st.st_mode):
                raise CASSecurityViolationError(
                    f"Security violation in staging directory: entry '{entry}' is not a regular file (mode: {oct(st.st_mode)})."
                )
                
            if not entry.endswith(".part"):
                continue
                
            age = now - st.st_mtime
            should_unlink = False
            
            if conn is not None:
                cur = conn.cursor()
                cur.execute("""
                    SELECT 1 FROM active_cas_publications
                    WHERE ? LIKE 'tmp_' || publication_id || '_' || lease_token || '_%'
                      AND lease_state IN ('ACQUIRED', 'HEARTBEAT_ACTIVE', 'PUBLISHED')
                      AND datetime('now') <= lease_expires_at;
                """, (entry,))
                if cur.fetchone() is None:
                    should_unlink = True
            else:
                if max_age_seconds <= 0 or age >= max_age_seconds:
                    should_unlink = True
                    
            if should_unlink:
                try:
                    os.unlink(entry, dir_fd=self.staging_dir_fd)
                    recovered += 1
                except FileNotFoundError:
                    pass
                except OSError as e:
                    raise CASStagingCleanupError(f"Failed to unlink orphan staging file '{entry}': {e}") from e
                    
        if recovered > 0:
            try:
                if hasattr(fcntl, "F_FULLFSYNC") and self.strict_fullfsync:
                    try:
                        fcntl.fcntl(self.staging_dir_fd, fcntl.F_FULLFSYNC)
                    except OSError:
                        os.fsync(self.staging_dir_fd)
                else:
                    os.fsync(self.staging_dir_fd)
            except OSError as e:
                raise CASDirectorySyncError(f"Failed to sync staging directory after durable sweep: {e}") from e
                
        # Clean up in-memory quarantine records descriptor-relative
        surviving_quarantine = []
        for o in self.quarantined_orphans:
            try:
                os.stat(o["tmp_filename"], dir_fd=self.staging_dir_fd, follow_symlinks=False)
                surviving_quarantine.append(o)
            except (FileNotFoundError, OSError):
                pass
        self.quarantined_orphans = surviving_quarantine
        
        return recovered
    def recover_quarantined_orphans(self) -> int:
        """
        Attempts repeated cleanup of all quarantined staging orphan files.
        Returns the number of successfully unlinked orphan files.
        """
        recovered_count = 0
        still_quarantined = []
        for orphan in self.quarantined_orphans:
            fn = orphan["tmp_filename"]
            try:
                os.unlink(fn, dir_fd=self.staging_dir_fd)
                recovered_count += 1
            except FileNotFoundError:
                recovered_count += 1
            except OSError:
                still_quarantined.append(orphan)
        self.quarantined_orphans = still_quarantined
        return recovered_count

    def publish_staging_to_cas(
        self,
        tmp_filename: str,
        blob_digest: str
    ) -> Dict[str, Any]:
        """
        Publishes staging file to destination shard directory via descriptor-relative hard link.
        Guarantees no-replace semantics.
        Detects EEXIST:
          - If destination digest matches -> safe deduplication, unlinks staging file.
          - If destination digest differs -> raises CASDestinationCorruptionError, preserves destination.
        Never suppresses directory synchronization failures.
        """
        shard_prefix = blob_digest[:2]
        shard_dir_fd = self.get_shard_dir_descriptor(shard_prefix)
        is_deduplicated = False
        
        try:
            # POSIX linkat(staging_dir_fd, tmp_filename, shard_dir_fd, blob_digest)
            try:
                os.link(
                    tmp_filename,
                    blob_digest,
                    src_dir_fd=self.staging_dir_fd,
                    dst_dir_fd=shard_dir_fd,
                    follow_symlinks=False
                )
            except FileExistsError:
                # EEXIST: inspect existing destination file descriptor-relative
                dst_fd = os.open(blob_digest, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=shard_dir_fd)
                try:
                    hasher = hashlib.sha256()
                    while True:
                        buf = os.read(dst_fd, 65536)
                        if not buf:
                            break
                        hasher.update(buf)
                    existing_digest = hasher.hexdigest()
                finally:
                    os.close(dst_fd)
                    
                if existing_digest != blob_digest:
                    raise CASDestinationCorruptionError(
                        f"CORRUPT_DESTINATION_DETECTED: Destination 'objects/{shard_prefix}/{blob_digest}' "
                        f"exists but has digest '{existing_digest}' != requested '{blob_digest}'. Overwrite aborted!"
                    )
                is_deduplicated = True
                
            # Flush shard directory entry (NEVER SUPPRESSED)
            try:
                os.fsync(shard_dir_fd)
            except OSError as e:
                raise CASDirectorySyncError(f"Failed to synchronize shard directory 'objects/{shard_prefix}': {e}") from e
                
            # Unlink staging file descriptor-relative
            os.unlink(tmp_filename, dir_fd=self.staging_dir_fd)
            
            # Flush staging directory entry (NEVER SUPPRESSED)
            try:
                os.fsync(self.staging_dir_fd)
            except OSError as e:
                raise CASDirectorySyncError(f"Failed to synchronize staging directory: {e}") from e
                
        finally:
            os.close(shard_dir_fd)
            
        return {
            "status": "PUBLISHED",
            "blob_digest": blob_digest,
            "shard": shard_prefix,
            "is_deduplicated": is_deduplicated
        }

    def delete_cas_blob_descriptor_relative_with_evidence(
        self,
        blob_digest: str,
        reservation_token: str = "",
        simulate_crash_before_unlink: bool = False,
        simulate_crash_before_dir_sync: bool = False,
        real_crash_boundary: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes descriptor-relative physical unlink and shard directory fsync.
        Captures rich, cryptographic evidence of physical removal bound to the reservation token.
        Supports deterministic boundary interruption testing (in-process and real-process).
        """
        if blob_digest.startswith("sha256:"):
            hex_digest = blob_digest[7:]
        else:
            hex_digest = blob_digest
        if len(hex_digest) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_digest):
            raise CASValidationError(f"Invalid digest for deletion: {blob_digest}")
        hex_digest = hex_digest.lower()
        prefix = hex_digest[:2]
        filename = hex_digest
        shard_fd = self.get_shard_dir_descriptor(prefix)
        shard_st = os.fstat(shard_fd)
        shard_ino = shard_st.st_ino
        dev_id = shard_st.st_dev

        # Inspect target file descriptor-relative before unlinking
        try:
            file_st = os.stat(filename, dir_fd=shard_fd, follow_symlinks=False)
            unlinked_inode = file_st.st_ino
            unlinked_bytes = file_st.st_size
            was_present = True
        except FileNotFoundError:
            unlinked_inode = 0
            unlinked_bytes = 0
            was_present = False
        except OSError as e:
            raise CASDeletionError(f"Failed to stat CAS blob '{blob_digest}' before unlink: {e}") from e

        # Boundary A Interruption Point: before physical unlink
        if real_crash_boundary == "A":
            os._exit(42)
        if simulate_crash_before_unlink:
            raise CASInterruptionError(f"Simulated crash at Boundary A: before unlink of blob '{blob_digest}'")

        if was_present:
            try:
                os.unlink(filename, dir_fd=shard_fd)
            except FileNotFoundError:
                was_present = False
            except OSError as e:
                raise CASDeletionError(f"Failed to unlink CAS blob '{blob_digest}': {e}") from e

        # Boundary B Interruption Point: after physical unlink, before directory synchronization
        if real_crash_boundary == "B":
            os._exit(42)
        if simulate_crash_before_dir_sync:
            raise CASInterruptionError(f"Simulated crash at Boundary B: after unlink, before shard directory sync of blob '{blob_digest}'")

        # Synchronize shard directory descriptor
        sync_method = "FSYNC"
        sync_timestamp_ns = time.time_ns()
        try:
            if hasattr(fcntl, "F_FULLFSYNC") and self.strict_fullfsync:
                try:
                    fcntl.fcntl(shard_fd, fcntl.F_FULLFSYNC)
                    sync_method = "F_FULLFSYNC"
                except OSError:
                    os.fsync(shard_fd)
                    sync_method = "FSYNC"
            else:
                os.fsync(shard_fd)
                sync_method = "FSYNC"
        except OSError as e:
            raise CASDirectorySyncError(f"Failed to synchronize shard directory '{prefix}' after deletion: {e}") from e

        key_id, key_secret = self.key_store.get_active_key()
        sig_payload = f"LCS-DEL-RECEIPT-v1:{key_id}:{hex_digest}:{reservation_token}:{unlinked_inode}:{shard_ino}:{dev_id}:{sync_method}:{sync_timestamp_ns}".encode("utf-8")
        receipt_signature = hmac.new(key_secret, sig_payload, hashlib.sha256).hexdigest()

        return {
            "unlinked": was_present,
            "unlinked_inode": unlinked_inode,
            "shard_inode": shard_ino,
            "device_id": dev_id,
            "sync_method": sync_method,
            "sync_timestamp_ns": sync_timestamp_ns,
            "key_id": key_id,
            "receipt_signature": receipt_signature
        }

    def delete_cas_blob_descriptor_relative(self, blob_digest: str, reservation_token: str = "") -> bool:
        evidence = self.delete_cas_blob_descriptor_relative_with_evidence(blob_digest, reservation_token=reservation_token)
        return evidence["unlinked"]

    @staticmethod
    def _ensure_connection_foreign_keys(conn: sqlite3.Connection) -> None:
        """
        Enforces that SQLite foreign keys are active on the supplied connection.
        Fails closed with CASSecurityViolationError if foreign keys cannot be guaranteed.
        """
        if not isinstance(conn, sqlite3.Connection):
            raise CASSecurityViolationError(f"Expected sqlite3.Connection, got {type(conn).__name__}")

        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys;")
        row = cur.fetchone()
        current_state = row[0] if row else 0

        if current_state == 1:
            return

        if getattr(conn, "in_transaction", False):
            raise CASSecurityViolationError(
                "Cannot enable SQLite foreign-key enforcement during an active uncommitted transaction. "
                "In SQLite, 'PRAGMA foreign_keys = ON' is a no-op inside transactions."
            )

        try:
            conn.execute("PRAGMA foreign_keys = ON;")
        except Exception as e:
            raise CASSecurityViolationError(
                f"Failed to execute 'PRAGMA foreign_keys = ON': {e}"
            ) from e

        cur.execute("PRAGMA foreign_keys;")
        row = cur.fetchone()
        new_state = row[0] if row else 0
        if new_state != 1:
            raise CASSecurityViolationError(
                f"SQLite foreign-key enforcement failed: PRAGMA foreign_keys returned {new_state} (expected 1)"
            )

    def gc_reserve_blob_for_deletion(
        self,
        conn: sqlite3.Connection,
        blob_digest: str,
        gc_worker_id: str,
        reservation_token: Optional[str] = None,
        lease_seconds: int = 60
    ) -> str:
        """
        Coordinates database deletion reservation with physical filesystem deletion.
        Inserts COMMITTED_FOR_UNLINK reservation and deletes blob from content_chunk_blobs
        in a single immediate write transaction.
        """
        self._ensure_connection_foreign_keys(conn)
        if blob_digest.startswith("sha256:"):
            hex_digest = blob_digest[7:]
        else:
            hex_digest = blob_digest
        if len(hex_digest) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_digest):
            raise CASValidationError(f"Invalid digest for GC reservation: {blob_digest}")
        hex_digest = hex_digest.lower()
        if reservation_token is None:
            reservation_token = f"gc_tok_{uuid.uuid4().hex}"
            
        conn.execute("BEGIN IMMEDIATE;")
        try:
            conn.execute("""
                INSERT INTO cas_gc_deletion_reservations (
                    blob_digest, reservation_state, gc_worker_id,
                    reservation_token, reserved_at, expires_at
                ) VALUES (
                    ?, 'COMMITTED_FOR_UNLINK', ?, ?,
                    datetime('now'),
                    datetime('now', ? || ' seconds')
                );
            """, (hex_digest, gc_worker_id, reservation_token, str(lease_seconds)))
            conn.execute("DELETE FROM content_chunk_blobs WHERE blob_digest = ?;", (hex_digest,))
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        return reservation_token

    def gc_complete_physical_deletion(
        self,
        conn: sqlite3.Connection,
        blob_digest: str,
        reservation_token: str,
        simulate_crash_before_unlink: bool = False,
        simulate_crash_before_dir_sync: bool = False,
        simulate_crash_before_db_commit: bool = False,
        real_crash_boundary: Optional[str] = None
    ) -> bool:
        """
        Executes verified physical deletion protocol with strict pre-validation:
        1. Validates reservation existence, COMMITTED_FOR_UNLINK state, and token ownership in SQLite.
           A wrong token or missing reservation will raise CASPublicationConflictError before any disk unlink.
        2. Executes descriptor-relative physical unlink and shard directory fsync.
        3. Inserts verified physical deletion receipt into cas_physical_deletion_receipts.
        4. Updates reservation_state to PHYSICALLY_DELETED within the write transaction.
        5. Commits transaction and returns whether file was physically present prior to unlink.
        """
        if blob_digest.startswith("sha256:"):
            hex_digest = blob_digest[7:]
        else:
            hex_digest = blob_digest
        if len(hex_digest) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_digest):
            raise CASValidationError(f"Invalid digest for GC deletion: {blob_digest}")
        hex_digest = hex_digest.lower()
        
        self._ensure_connection_foreign_keys(conn)
        conn.execute("BEGIN IMMEDIATE;")
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT reservation_token, reservation_state
                FROM cas_gc_deletion_reservations
                WHERE blob_digest = ?;
            """, (hex_digest,))
            row = cur.fetchone()
            if not row:
                raise CASPublicationConflictError(
                    f"GC physical deletion failed for blob '{blob_digest}': reservation does not exist"
                )
            existing_token, existing_state = row[0], row[1]
            if existing_token != reservation_token:
                raise CASPublicationConflictError(
                    f"GC physical deletion failed for blob '{blob_digest}': "
                    f"token mismatch (supplied '{reservation_token}' does not match reservation)"
                )
            if existing_state != 'COMMITTED_FOR_UNLINK':
                raise CASPublicationConflictError(
                    f"GC physical deletion failed for blob '{blob_digest}': "
                    f"reservation state is '{existing_state}', expected 'COMMITTED_FOR_UNLINK'"
                )
                
            # Perform descriptor-relative physical deletion
            evidence = self.delete_cas_blob_descriptor_relative_with_evidence(
                hex_digest,
                reservation_token=reservation_token,
                simulate_crash_before_unlink=simulate_crash_before_unlink,
                simulate_crash_before_dir_sync=simulate_crash_before_dir_sync,
                real_crash_boundary=real_crash_boundary
            )
            
            # Boundary C Interruption Point: after unlink and dir sync, before database commit
            if real_crash_boundary == "C":
                os._exit(42)
            if simulate_crash_before_db_commit:
                raise CASInterruptionError(f"Simulated crash at Boundary C: after physical unlink and dir sync, before DB commit of blob '{blob_digest}'")
            
            # Record durable physical deletion evidence receipt
            cur.execute("""
                INSERT INTO cas_physical_deletion_receipts (
                    blob_digest, reservation_token, key_id, unlinked_inode, shard_inode,
                    device_id, sync_method, sync_timestamp_ns, receipt_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                hex_digest, reservation_token, evidence["key_id"],
                evidence["unlinked_inode"], evidence["shard_inode"],
                evidence["device_id"], evidence["sync_method"],
                evidence["sync_timestamp_ns"], evidence["receipt_signature"]
            ))
            
            # Advance reservation state to PHYSICALLY_DELETED
            cur.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'PHYSICALLY_DELETED'
                WHERE blob_digest = ? AND reservation_token = ? AND reservation_state = 'COMMITTED_FOR_UNLINK';
            """, (hex_digest, reservation_token))
            
            conn.execute("COMMIT;")
            return evidence["unlinked"]
        except Exception:
            conn.execute("ROLLBACK;")
            raise

    def gc_cancel_reservation(
        self,
        conn: sqlite3.Connection,
        blob_digest: str,
        reservation_token: str
    ) -> bool:
        """
        Authoritative GC reservation cancellation protocol.
        Safely reverts a reservation only if physical existence is positively verified on disk.
        Prevents phantom blob resurrection if physical unlink already completed.
        """
        if blob_digest.startswith("sha256:"):
            hex_digest = blob_digest[7:]
        else:
            hex_digest = blob_digest
        if len(hex_digest) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_digest):
            raise CASValidationError(f"Invalid digest for GC cancellation: {blob_digest}")
        hex_digest = hex_digest.lower()
        prefix = hex_digest[:2]
        filename = hex_digest
        
        self._ensure_connection_foreign_keys(conn)
        conn.execute("BEGIN IMMEDIATE;")
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT reservation_token, reservation_state
                FROM cas_gc_deletion_reservations
                WHERE blob_digest = ?;
            """, (hex_digest,))
            row = cur.fetchone()
            if not row:
                raise CASPublicationConflictError(
                    f"GC cancellation failed for blob '{blob_digest}': reservation does not exist"
                )
            existing_token, existing_state = row[0], row[1]
            if existing_token != reservation_token:
                raise CASPublicationConflictError(
                    f"GC cancellation failed for blob '{blob_digest}': "
                    f"token mismatch (supplied '{reservation_token}' does not match reservation)"
                )
            if existing_state not in ('RESERVED', 'COMMITTED_FOR_UNLINK'):
                raise CASPublicationConflictError(
                    f"GC cancellation failed for blob '{blob_digest}': "
                    f"reservation state is '{existing_state}', expected RESERVED or COMMITTED_FOR_UNLINK"
                )
                
            # Positively verify physical existence descriptor-relative
            shard_fd = self.get_shard_dir_descriptor(prefix)
            try:
                file_st = os.stat(filename, dir_fd=shard_fd, follow_symlinks=False)
                if not stat.S_ISREG(file_st.st_mode):
                    raise CASDeletionError(
                        f"GC cancellation failed for blob '{blob_digest}': path exists but is not a regular file"
                    )
                verified_inode = file_st.st_ino
                verified_bytes = file_st.st_size
                shard_st = os.fstat(shard_fd)
                dev_id = shard_st.st_dev
            except FileNotFoundError:
                raise CASDeletionError(
                    f"Cannot cancel reservation for blob '{blob_digest}': physical file does not exist on disk! "
                    f"Physical unlink has already completed; cannot resurrect phantom blob."
                )
                
            # If state is COMMITTED_FOR_UNLINK, record cryptographic cancellation receipt
            if existing_state == 'COMMITTED_FOR_UNLINK':
                key_id, key_secret = self.key_store.get_active_key()
                ts_ns = time.time_ns()
                cancel_payload = f"LCS-CANCEL-RECEIPT-v1:{key_id}:{hex_digest}:{reservation_token}:{verified_inode}:{verified_bytes}:{dev_id}:{ts_ns}".encode("utf-8")
                cancel_sig = hmac.new(key_secret, cancel_payload, hashlib.sha256).hexdigest()
                
                cur.execute("""
                    INSERT INTO cas_gc_cancellation_receipts (
                        blob_digest, reservation_token, key_id, verified_inode,
                        verified_bytes, device_id, verified_timestamp_ns, receipt_signature
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    hex_digest, reservation_token, key_id, verified_inode,
                    verified_bytes, dev_id, ts_ns, cancel_sig
                ))
                
            # Update state to REVERTED
            cur.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'REVERTED'
                WHERE blob_digest = ? AND reservation_token = ?;
            """, (hex_digest, reservation_token))
            
            conn.execute("COMMIT;")
            return True
        except Exception:
            conn.execute("ROLLBACK;")
            raise

    def recover_gc_reservations(
        self,
        conn: sqlite3.Connection,
        real_crash_boundary_d_after_count: Optional[int] = None
    ) -> int:
        """
        Restart recovery sweeper: scans for COMMITTED_FOR_UNLINK reservations across all crash boundaries
        and completes physical deletion, evidence recording, and state advancement via gc_complete_physical_deletion.
        """
        self._ensure_connection_foreign_keys(conn)
        cur = conn.cursor()
        cur.execute("""
            SELECT blob_digest, reservation_token
            FROM cas_gc_deletion_reservations
            WHERE reservation_state = 'COMMITTED_FOR_UNLINK';
        """)
        candidates = cur.fetchall()
        recovered = 0
        for digest, token in candidates:
            try:
                full_digest = f"sha256:{digest}"
                self.gc_complete_physical_deletion(conn, full_digest, token)
                recovered += 1
                if real_crash_boundary_d_after_count is not None and recovered >= real_crash_boundary_d_after_count:
                    os._exit(42)
            except CASPublicationConflictError:
                continue
        return recovered


    def read_blob(self, blob_digest: str) -> bytes:
        """
        Reads a blob descriptor-relative from its shard directory with O_NOFOLLOW.
        Validates the SHA-256 digest of the read bytes against the expected blob_digest.
        Raises CASBlobNotFoundError if file does not exist.
        Raises CASDigestMismatchError if read bytes do not match expected digest.
        """
        if blob_digest.startswith("sha256:"):
            hex_digest = blob_digest[7:]
        else:
            hex_digest = blob_digest
        if len(hex_digest) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_digest):
            raise CASValidationError(f"Invalid digest for read: {blob_digest}")
        hex_digest = hex_digest.lower()
        prefix = hex_digest[:2]
        filename = hex_digest
        
        shard_fd = self.get_shard_dir_descriptor(prefix)
        try:
            try:
                fd = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=shard_fd)
            except FileNotFoundError as e:
                raise CASBlobNotFoundError(f"CAS blob '{hex_digest}' not found in shard '{prefix}'") from e
            except OSError as e:
                if e.errno == errno.ELOOP:
                    raise CASSecurityViolationError(f"CAS blob '{hex_digest}' is a symlink: {e}") from e
                raise
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise CASSecurityViolationError(f"CAS blob '{hex_digest}' is not a regular file")
                data = os.read(fd, st.st_size if st.st_size > 0 else 1048576)
                while len(data) < st.st_size:
                    chunk = os.read(fd, st.st_size - len(data))
                    if not chunk:
                        break
                    data += chunk
            finally:
                os.close(fd)
        finally:
            os.close(shard_fd)

        actual_digest = hashlib.sha256(data).hexdigest()
        if actual_digest != hex_digest:
            raise CASDigestMismatchError(
                f"CAS blob corruption detected: expected digest '{hex_digest}', got '{actual_digest}'"
            )
        return data

    def blob_exists(self, blob_digest: str) -> bool:
        """Checks descriptor-relative whether a blob exists in physical storage without following symlinks."""
        if blob_digest.startswith("sha256:"):
            hex_digest = blob_digest[7:]
        else:
            hex_digest = blob_digest
        if len(hex_digest) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hex_digest):
            return False
        hex_digest = hex_digest.lower()
        prefix = hex_digest[:2]
        filename = hex_digest
        
        shard_fd = self.get_shard_dir_descriptor(prefix)
        try:
            st = os.stat(filename, dir_fd=shard_fd, follow_symlinks=False)
            return stat.S_ISREG(st.st_mode)
        except OSError:
            return False
        finally:
            os.close(shard_fd)

    def audit_physical_deletion_consistency(
        self,
        conn: sqlite3.Connection,
        blob_digest: str
    ) -> Dict[str, Any]:
        """
        Authoritative reconciliation audit gate:
        Verifies whether physical disk state correlates with database deletion and cancellation records.
        """
        self._ensure_connection_foreign_keys(conn)
        if blob_digest.startswith("sha256:"):
            hex_digest = blob_digest[7:]
        else:
            hex_digest = blob_digest
        hex_digest = hex_digest.lower()
        prefix = hex_digest[:2]
        filename = hex_digest
        shard_fd = self.get_shard_dir_descriptor(prefix)
        
        # Check physical presence
        try:
            st = os.stat(filename, dir_fd=shard_fd, follow_symlinks=False)
            physically_exists = True
            disk_inode = st.st_ino
            disk_size = st.st_size
        except FileNotFoundError:
            physically_exists = False
            disk_inode = 0
            disk_size = 0
            
        cur = conn.cursor()
        cur.execute("""
            SELECT reservation_state, reservation_token
            FROM cas_gc_deletion_reservations
            WHERE blob_digest = ?;
        """, (hex_digest,))
        res_row = cur.fetchone()
        
        cur.execute("""
            SELECT receipt_id, reservation_token, key_id, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature
            FROM cas_physical_deletion_receipts
            WHERE blob_digest = ?;
        """, (hex_digest,))
        receipt_rows = cur.fetchall()

        cur.execute("""
            SELECT cancellation_id, reservation_token, key_id, verified_inode, verified_bytes, device_id, verified_timestamp_ns, receipt_signature
            FROM cas_gc_cancellation_receipts
            WHERE blob_digest = ?;
        """, (hex_digest,))
        cancel_rows = cur.fetchall()
        
        # Invariant 1: If DB claims PHYSICALLY_DELETED, physical file MUST NOT exist on disk!
        if res_row and res_row[0] == "PHYSICALLY_DELETED" and physically_exists:
            raise CASSecurityViolationError(
                f"CAS_TAMPERING_DETECTED: Fabricated deletion record detected for blob '{blob_digest}'! "
                f"Database claims reservation is PHYSICALLY_DELETED, but physical blob still exists on disk "
                f"at inode {disk_inode} (size: {disk_size} B). SQLite triggers cannot verify filesystem state!"
            )
            
        # Invariant 2: If a deletion receipt exists for this blob, physical file MUST NOT exist on disk!
        if len(receipt_rows) > 0 and physically_exists:
            raise CASSecurityViolationError(
                f"CAS_TAMPERING_DETECTED: Fabricated deletion receipt detected for blob '{blob_digest}'! "
                f"Database contains {len(receipt_rows)} physical deletion receipt(s), but physical blob still exists on disk "
                f"at inode {disk_inode} (size: {disk_size} B)."
            )

        # Invariant 3: If DB claims REVERTED, physical file MUST exist on disk!
        if res_row and res_row[0] == "REVERTED" and not physically_exists:
            raise CASSecurityViolationError(
                f"CAS_TAMPERING_DETECTED: Phantom blob detected! Database claims reservation is REVERTED, "
                f"but physical blob does not exist on disk for blob '{blob_digest}'!"
            )
            
        # Invariant 4: Verify cryptographic signatures of deletion receipts using persistent key store
        for r in receipt_rows:
            r_id, r_tok, r_key_id, r_unlinked_ino, r_shard_ino, r_dev_id, r_sync, r_sync_ts, r_sig = r
            key_secret = self.key_store.get_key(r_key_id)
            expected_payload = f"LCS-DEL-RECEIPT-v1:{r_key_id}:{hex_digest}:{r_tok}:{r_unlinked_ino}:{r_shard_ino}:{r_dev_id}:{r_sync}:{r_sync_ts}".encode("utf-8")
            expected_sig = hmac.new(key_secret, expected_payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(r_sig, expected_sig):
                raise CASSecurityViolationError(
                    f"CAS_TAMPERING_DETECTED: Forged deletion receipt signature for blob '{blob_digest}'! "
                    f"Receipt ID {r_id} has invalid signature '{r_sig}' (expected '{expected_sig}')."
                )

        # Invariant 5: Verify cryptographic signatures of cancellation receipts using persistent key store
        for c in cancel_rows:
            c_id, c_tok, c_key_id, c_ino, c_bytes, c_dev, c_ts, c_sig = c
            key_secret = self.key_store.get_key(c_key_id)
            expected_cancel_payload = f"LCS-CANCEL-RECEIPT-v1:{c_key_id}:{hex_digest}:{c_tok}:{c_ino}:{c_bytes}:{c_dev}:{c_ts}".encode("utf-8")
            expected_cancel_sig = hmac.new(key_secret, expected_cancel_payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(c_sig, expected_cancel_sig):
                raise CASSecurityViolationError(
                    f"CAS_TAMPERING_DETECTED: Forged cancellation receipt signature for blob '{blob_digest}'! "
                    f"Cancellation ID {c_id} has invalid signature '{c_sig}' (expected '{expected_cancel_sig}')."
                )
            
        return {
            "blob_digest": hex_digest,
            "physically_exists": physically_exists,
            "disk_inode": disk_inode,
            "reservation_state": res_row[0] if res_row else None,
            "receipt_count": len(receipt_rows),
            "cancellation_count": len(cancel_rows)
        }
