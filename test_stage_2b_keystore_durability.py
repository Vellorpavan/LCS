#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 1 Key Store Durability & Lifecycle Test Suite
=====================================================================
Authoritative verification suite for Milestone 1 durability contract:
1. Crash before atomic replacement (os._exit(42)).
2. Crash after replacement but before directory synchronization.
3. Injected directory synchronization failure and fail-closed SIGNING_SUSPENDED state.
4. Engine recovery, reconciliation, and re-enabling of signing.
5. Historical receipt verification across multiple key generations.
6. Concurrent key rotations serialized cleanly via fcntl.flock.
7. Safe stale temporary-file cleanup protecting active writers.
8. Key-ring corruption, zero-length files, and symlink rejection.
9. Complete structural and semantic key-ring schema validation.
10. Darwin F_FULLFSYNC and portable fsync fallback hierarchy.
"""

import os
import sys
import time
import stat
import json
import errno
import fcntl
import signal
import hashlib
import sqlite3
import tempfile
import multiprocessing
from typing import Dict, Any

# Ensure local stage_2b modules are imported
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from cas_storage_engine_v2b import (
    PersistentReceiptKeyStore,
    SecureCASStorageEngine,
    CASSecurityViolationError,
    CASCorruptedKeyRingError,
    CASSigningSuspendedError,
    CASKeySyncError,
    CASDirectorySyncError,
    CASInterruptionError,
    CASValidationError
)

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = FULL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    schema_path = os.path.join(CURRENT_DIR, "lcs_schema_v2b.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    return conn


def _worker_crash_before_replace(key_store_dir: str):
    """Worker process that attempts key rotation and crashes before os.replace()."""
    ks = PersistentReceiptKeyStore(key_store_dir)
    try:
        ks.rotate_key("k_crashed", inject_crash_before_replace=True)
    except CASInterruptionError:
        os._exit(42)
    os._exit(0)


def _worker_crash_after_replace(key_store_dir: str):
    """Worker process that executes os.replace() and crashes before directory sync."""
    ks = PersistentReceiptKeyStore(key_store_dir)
    try:
        ks.rotate_key("k_crashed_after", inject_crash_after_replace=True)
    except CASInterruptionError:
        os._exit(43)
    os._exit(0)


def _worker_concurrent_rotate(key_store_dir: str, worker_id: int):
    """Worker process that performs key rotation under concurrency."""
    try:
        ks = PersistentReceiptKeyStore(key_store_dir)
        new_k_id = f"k_worker_{worker_id}"
        ks.rotate_key(new_k_id)
        os._exit(0)
    except Exception as e:
        print(f"Worker {worker_id} failed: {e}", file=sys.stderr)
        os._exit(1)


# ============================================================================
# TEST CASES
# ============================================================================

def test_01_crash_before_atomic_replacement():
    print("--- Test 01: Crash Before Atomic Replacement ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        ks_dir = os.path.join(tmp_dir, ".lcs_keys")
        ks_initial = PersistentReceiptKeyStore(ks_dir)
        assert ks_initial.active_key_id == "k1"
        initial_secret = ks_initial.get_active_key()[1]
        
        # Spawn child process to crash before os.replace()
        ctx = multiprocessing.get_context("fork")
        p = ctx.Process(target=_worker_crash_before_replace, args=(ks_dir,))
        p.start()
        p.join()
        assert p.exitcode == 42, f"Expected worker exit code 42, got {p.exitcode}"
        
        # Verify active file is intact and contains k1
        ks_restart = PersistentReceiptKeyStore(ks_dir)
        assert ks_restart.active_key_id == "k1"
        assert ks_restart.get_active_key()[1] == initial_secret
        assert "k_crashed" not in ks_restart.keys
        print("  Verified: Key ring on disk remained intact after pre-replacement crash.")


def test_02_crash_after_replacement_before_directory_sync():
    print("--- Test 02: Crash After Replacement Before Directory Sync ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        ks_dir = os.path.join(tmp_dir, ".lcs_keys")
        ks_initial = PersistentReceiptKeyStore(ks_dir)
        assert ks_initial.active_key_id == "k1"
        
        # Spawn child process to crash after os.replace() before directory sync
        ctx = multiprocessing.get_context("fork")
        p = ctx.Process(target=_worker_crash_after_replace, args=(ks_dir,))
        p.start()
        p.join()
        assert p.exitcode == 43, f"Expected worker exit code 43, got {p.exitcode}"
        
        # Verify on-disk file was replaced and contains k_crashed_after
        ks_restart = PersistentReceiptKeyStore(ks_dir)
        assert ks_restart.active_key_id == "k_crashed_after"
        assert "k1" in ks_restart.keys
        assert "k_crashed_after" in ks_restart.keys
        assert ks_restart.persistence_state == "COMMITTED"
        assert not ks_restart.signing_suspended
        print("  Verified: Restarted engine recovered authoritative key ring after post-replacement crash.")


def test_03_injected_directory_sync_failure_and_fail_closed():
    print("--- Test 03: Injected Directory Sync Failure & Fail-Closed Behavior ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        ks_dir = os.path.join(tmp_dir, ".lcs_keys")
        ks = PersistentReceiptKeyStore(ks_dir)
        assert ks.active_key_id == "k1"
        k1_secret = ks.get_active_key()[1]
        
        # Attempt key rotation with injected directory sync failure
        try:
            ks.rotate_key("k2", inject_dir_sync_error=True)
            assert False, "Expected CASDirectorySyncError was not raised!"
        except CASDirectorySyncError as e:
            print(f"  Caught expected directory sync failure: {e}")
            
        # Assert fail-closed state:
        assert ks.signing_suspended is True
        assert ks.persistence_state == "FAILED_INDETERMINATE"
        # In-memory active key MUST NOT be advanced to k2!
        assert ks.active_key_id == "k1"
        
        # Assert get_active_key() raises CASSigningSuspendedError
        try:
            ks.get_active_key()
            assert False, "Expected CASSigningSuspendedError on get_active_key!"
        except CASSigningSuspendedError as e:
            print(f"  Verified: Signing is suspended: {e}")
            
        # Assert historical verification with k1 is PRESERVED
        assert ks.get_key("k1") == k1_secret
        print("  Verified: Historical key retrieval remains functional during signing suspension.")


def test_04_signing_suspension_recovery():
    print("--- Test 04: Signing Suspension Recovery ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        ks_dir = os.path.join(tmp_dir, ".lcs_keys")
        ks = PersistentReceiptKeyStore(ks_dir)
        
        # Trigger directory sync error
        try:
            ks.rotate_key("k2", inject_dir_sync_error=True)
        except CASDirectorySyncError:
            pass
            
        assert ks.signing_suspended is True
        
        # Execute recover_key_ring()
        recovered = ks.recover_key_ring()
        assert recovered is True
        assert ks.signing_suspended is False
        assert ks.persistence_state == "COMMITTED"
        
        # Signing is now re-enabled
        active_id, active_secret = ks.get_active_key()
        assert active_id == "k2"  # On disk, the replacement succeeded and directory sync completed during recovery
        print("  Verified: recover_key_ring() cleared FAILED_INDETERMINATE and re-enabled signing.")


def test_05_historical_receipt_verification_multigeneration():
    print("--- Test 05: Multi-Generation Historical Receipt Verification ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "receipts.db")
        conn = init_db(db_path)
        
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        # Generation 1
        k1_id, k1_secret = engine.key_store.get_active_key()
        assert k1_id == "k1"
        p1 = b"Blob Generation 1"
        d1 = hashlib.sha256(p1).hexdigest()
        tmp1, _, _ = engine.write_payload_to_staging("pub1", "tok1", d1, p1)
        engine.publish_staging_to_cas(tmp1, d1)
        tok1 = engine.gc_reserve_blob_for_deletion(conn, f"sha256:{d1}", "worker1")
        engine.gc_complete_physical_deletion(conn, f"sha256:{d1}", tok1)
        
        # Rotate to Generation 2
        k2_id, k2_secret = engine.key_store.rotate_key()
        assert k2_id == "k2"
        p2 = b"Blob Generation 2"
        d2 = hashlib.sha256(p2).hexdigest()
        tmp2, _, _ = engine.write_payload_to_staging("pub2", "tok2", d2, p2)
        engine.publish_staging_to_cas(tmp2, d2)
        tok2 = engine.gc_reserve_blob_for_deletion(conn, f"sha256:{d2}", "worker2")
        engine.gc_complete_physical_deletion(conn, f"sha256:{d2}", tok2)
        
        # Rotate to Generation 3
        k3_id, k3_secret = engine.key_store.rotate_key()
        assert k3_id == "k3"
        p3 = b"Blob Generation 3"
        d3 = hashlib.sha256(p3).hexdigest()
        tmp3, _, _ = engine.write_payload_to_staging("pub3", "tok3", d3, p3)
        engine.publish_staging_to_cas(tmp3, d3)
        tok3 = engine.gc_reserve_blob_for_deletion(conn, f"sha256:{d3}", "worker3")
        engine.gc_complete_physical_deletion(conn, f"sha256:{d3}", tok3)
        
        # Audit consistency of all 3 historical generations
        audit1 = engine.audit_physical_deletion_consistency(conn, d1)
        audit2 = engine.audit_physical_deletion_consistency(conn, d2)
        audit3 = engine.audit_physical_deletion_consistency(conn, d3)
        
        assert audit1["receipt_count"] == 1
        assert audit2["receipt_count"] == 1
        assert audit3["receipt_count"] == 1
        print("  Verified: Receipts across Generations 1, 2, and 3 validated successfully.")
        engine.close()


def test_06_concurrent_key_rotations():
    print("--- Test 06: Concurrent Key Rotations Serialized via flock ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        ks_dir = os.path.join(tmp_dir, ".lcs_keys")
        PersistentReceiptKeyStore(ks_dir)
        
        ctx = multiprocessing.get_context("fork")
        procs = []
        for i in range(5):
            p = ctx.Process(target=_worker_concurrent_rotate, args=(ks_dir, i + 1))
            procs.append(p)
            p.start()
            
        for p in procs:
            p.join()
            assert p.exitcode == 0, f"Worker process failed with exit code {p.exitcode}"
            
        # Verify final state
        ks_final = PersistentReceiptKeyStore(ks_dir)
        assert len(ks_final.keys) == 6  # k1 + 5 workers
        for i in range(1, 6):
            assert f"k_worker_{i}" in ks_final.keys
        print(f"  Verified: 5 concurrent workers serialized cleanly; total keys = {len(ks_final.keys)}.")


def test_07_safe_stale_temporary_file_cleanup():
    print("--- Test 07: Safe Stale Temporary-File Cleanup ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        ks_dir = os.path.join(tmp_dir, ".lcs_keys")
        ks = PersistentReceiptKeyStore(ks_dir)
        
        # Plant File A: Alive PID (current process) and fresh mtime
        alive_pid = os.getpid()
        live_tmp_name = f".key_ring.json.tmp.{alive_pid}_0_{os.urandom(8).hex()}"
        live_tmp_path = os.path.join(ks_dir, live_tmp_name)
        with open(live_tmp_path, "w") as f:
            f.write("temporary data from active writer")
            
        # Plant File B: Dead PID (pid 99999999)
        dead_pid = 99999999
        dead_tmp_name = f".key_ring.json.tmp.{dead_pid}_0_{os.urandom(8).hex()}"
        dead_tmp_path = os.path.join(ks_dir, dead_tmp_name)
        with open(dead_tmp_path, "w") as f:
            f.write("temporary data from dead process")
            
        # Plant File C: Old mtime (> 120 seconds ago)
        old_tmp_name = f".key_ring.json.tmp.unknown_0_{os.urandom(8).hex()}"
        old_tmp_path = os.path.join(ks_dir, old_tmp_name)
        with open(old_tmp_path, "w") as f:
            f.write("old temporary data")
        os.utime(old_tmp_path, (time.time() - 300, time.time() - 300))
        
        # Execute cleanup under lock
        with ks._locked_transaction():
            cleaned = ks._cleanup_stale_temp_files_under_lock(stale_threshold_seconds=60.0)
            
        assert cleaned == 2, f"Expected 2 stale files cleaned, got {cleaned}"
        assert os.path.exists(live_tmp_path), "Active writer file was erroneously deleted!"
        assert not os.path.exists(dead_tmp_path), "Dead process file was not cleaned up!"
        assert not os.path.exists(old_tmp_path), "Old temp file was not cleaned up!"
        print("  Verified: Active writer file preserved; dead PID and aged files cleanly unlinked.")


def test_08_key_ring_corruption_and_symlink_rejection():
    print("--- Test 08: Key Ring Corruption & Symlink Rejection ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        ks_dir = os.path.join(tmp_dir, ".lcs_keys")
        PersistentReceiptKeyStore(ks_dir)
        key_file = os.path.join(ks_dir, "key_ring.json")
        
        # 1. Truncate file to zero bytes
        with open(key_file, "w") as f:
            f.write("")
        try:
            PersistentReceiptKeyStore(ks_dir, allow_bootstrap=False)
            assert False, "Expected CASCorruptedKeyRingError on zero-byte file!"
        except CASCorruptedKeyRingError as e:
            print(f"  Verified zero-byte rejection: {e}")
            
        # 2. Corrupt JSON
        with open(key_file, "w") as f:
            f.write('{"schema_version": 1, "active_key_id": "k1", "keys": { truncated')
        try:
            PersistentReceiptKeyStore(ks_dir, allow_bootstrap=False)
            assert False, "Expected CASCorruptedKeyRingError on invalid JSON!"
        except CASCorruptedKeyRingError as e:
            print(f"  Verified invalid JSON rejection: {e}")
            
        # 3. Missing file when allow_bootstrap=False
        os.unlink(key_file)
        try:
            PersistentReceiptKeyStore(ks_dir, allow_bootstrap=False)
            assert False, "Expected CASCorruptedKeyRingError on missing file with bootstrap=False!"
        except CASCorruptedKeyRingError as e:
            print(f"  Verified missing file rejection (no silent regeneration): {e}")
            
        # 4. Symlink planted at key_ring.json
        evil_target = os.path.join(tmp_dir, "evil_target.json")
        with open(evil_target, "w") as f:
            f.write("{}")
        os.symlink(evil_target, key_file)
        try:
            PersistentReceiptKeyStore(ks_dir, allow_bootstrap=False)
            assert False, "Expected CASSecurityViolationError on symlink!"
        except CASSecurityViolationError as e:
            print(f"  Verified symlink rejection: {e}")
        os.unlink(key_file)
        
        # 5. Invalid permissions (0666)
        PersistentReceiptKeyStore(ks_dir, allow_bootstrap=True)
        os.chmod(key_file, 0o666)
        try:
            PersistentReceiptKeyStore(ks_dir, allow_bootstrap=False)
            assert False, "Expected CASSecurityViolationError on permissions 0666!"
        except CASSecurityViolationError as e:
            print(f"  Verified invalid permissions rejection: {e}")


def test_09_complete_structural_and_semantic_validation():
    print("--- Test 09: Complete Structural and Semantic Validation ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        ks_dir = os.path.join(tmp_dir, ".lcs_keys")
        PersistentReceiptKeyStore(ks_dir)
        key_file = os.path.join(ks_dir, "key_ring.json")
        
        bad_payloads = [
            ("Unsupported schema_version", {"schema_version": 99, "active_key_id": "k1", "keys": {"k1": {}}}),
            ("Missing active_key_id in keys", {"schema_version": 1, "active_key_id": "k999", "keys": {"k1": {}}}),
            ("Secret hex not 64 chars", {"schema_version": 1, "active_key_id": "k1", "keys": {"k1": {"key_id": "k1", "algorithm": "HMAC-SHA256", "secret_hex": "abcd", "status": "ACTIVE"}}}),
            ("Empty keys object", {"schema_version": 1, "active_key_id": "k1", "keys": {}}),
            ("Active key status RETIRED", {"schema_version": 1, "active_key_id": "k1", "keys": {"k1": {"key_id": "k1", "algorithm": "HMAC-SHA256", "secret_hex": "a"*64, "status": "RETIRED"}}}),
            ("Inactive key status ACTIVE", {"schema_version": 1, "active_key_id": "k1", "keys": {
                "k1": {"key_id": "k1", "algorithm": "HMAC-SHA256", "secret_hex": "a"*64, "status": "ACTIVE"},
                "k2": {"key_id": "k2", "algorithm": "HMAC-SHA256", "secret_hex": "b"*64, "status": "ACTIVE"}
            }})
        ]
        
        for name, payload in bad_payloads:
            with open(key_file, "w") as f:
                json.dump(payload, f)
            try:
                PersistentReceiptKeyStore(ks_dir, allow_bootstrap=False)
                assert False, f"Expected CASCorruptedKeyRingError for '{name}'!"
            except CASCorruptedKeyRingError as e:
                print(f"  Verified semantic validation catch: {name} -> {e}")


def test_10_darwin_fullfsync_and_fallback():
    print("--- Test 10: Darwin F_FULLFSYNC and Fallback Hierarchy ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        ks_dir = os.path.join(tmp_dir, ".lcs_keys")
        ks = PersistentReceiptKeyStore(ks_dir)
        
        # Test _sync_fd on regular file
        fpath = os.path.join(tmp_dir, "test_sync.bin")
        fd = os.open(fpath, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, b"durability test bytes")
        method = ks._sync_fd(fd)
        os.close(fd)
        print(f"  Regular file sync returned method: {method}")
        assert method in ("F_FULLFSYNC", "FSYNC_FALLBACK", "FSYNC")
        
        # Test _sync_fd on directory
        dir_fd = os.open(ks_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        dir_method = ks._sync_fd(dir_fd, is_directory=True)
        os.close(dir_fd)
        print(f"  Directory sync returned method: {dir_method}")
        assert dir_method in ("F_FULLFSYNC", "FSYNC_FALLBACK", "FSYNC")


def main():
    print("======================================================================")
    print("LCS Stage 2B — Milestone 1 Key Store Durability Verification Suite")
    print("======================================================================")
    
    test_01_crash_before_atomic_replacement()
    test_02_crash_after_replacement_before_directory_sync()
    test_03_injected_directory_sync_failure_and_fail_closed()
    test_04_signing_suspension_recovery()
    test_05_historical_receipt_verification_multigeneration()
    test_06_concurrent_key_rotations()
    test_07_safe_stale_temporary_file_cleanup()
    test_08_key_ring_corruption_and_symlink_rejection()
    test_09_complete_structural_and_semantic_validation()
    test_10_darwin_fullfsync_and_fallback()
    
    print("\n======================================================================")
    print("ALL 10 MILESTONE 1 DURABILITY TESTS PASSED CLEANLY (0 FAILURES)")
    print("======================================================================")

if __name__ == "__main__":
    main()
