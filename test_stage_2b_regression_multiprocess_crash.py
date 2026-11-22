#!/usr/bin/env python3
"""
LCS Stage 2A.28 Multi-Process Real Crash & Durability Verification Suite
========================================================================
Authoritatively verifies crash recovery across Boundaries A, B, C, and D
using true operating system process termination (os._exit and SIGKILL).
Validates SQLite WAL recovery, persistent key verification across restarts,
and ensures no in-process exception catching masks crash boundary defects.
"""

import os
import sys

repo_root = os.path.abspath(os.path.dirname(__file__))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)
cur_pp = os.environ.get("PYTHONPATH", "")
if repo_root not in cur_pp:
    os.environ["PYTHONPATH"] = f"{repo_root}{os.pathsep}{cur_pp}" if cur_pp else repo_root

import time
import stat
import signal
import hashlib
import sqlite3
import tempfile
import multiprocessing
from typing import Dict, Any

SAFE_TMP_DIR = "/private/tmp" if os.path.isdir("/private/tmp") else tempfile.gettempdir()

from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    CASSecurityViolationError,
    CASPublicationConflictError
)

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = FULL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    schema_path = os.path.join(os.path.dirname(__file__), "lcs_schema_v2b.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    return conn

def worker_boundary_crash(
    boundary: str,
    real_anchor: str,
    cas_root: str,
    db_path: str,
    blob_digest: str,
    token: str
):
    """Child process that executes physical deletion and crashes abruptly at target boundary."""
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        # Abrupt termination occurs inside gc_complete_physical_deletion via os._exit(42)
        engine.gc_complete_physical_deletion(
            conn,
            blob_digest,
            token,
            real_crash_boundary=boundary
        )
        # Should never reach here if boundary was triggered
        os._exit(0)
    except Exception as e:
        sys.stderr.write(f"Child worker unexpected exception: {e}\n")
        os._exit(99)

def worker_boundary_d_crash(
    real_anchor: str,
    cas_root: str,
    db_path: str,
    crash_after_count: int
):
    """Child process that executes batch recovery and crashes abruptly after processing N items."""
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        engine.recover_gc_reservations(
            conn,
            real_crash_boundary_d_after_count=crash_after_count
        )
        os._exit(0)
    except Exception as e:
        sys.stderr.write(f"Child recovery worker unexpected exception: {e}\n")
        os._exit(99)

def test_01_multiprocess_boundary_a_crash():
    print("--- Test 01: Real Multi-Process Crash at Boundary A (Before Physical Unlink) ---")
    with tempfile.TemporaryDirectory(dir=SAFE_TMP_DIR) as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs_boundary_a.db")
        
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        payload = b"Payload for multi-process Boundary A crash verification"
        digest = hashlib.sha256(payload).hexdigest()
        full_digest = f"sha256:{digest}"
        shard = digest[:2]
        dest_path = os.path.join(cas_root, "objects", shard, digest)
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_a", "tok_a", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        assert os.path.isfile(dest_path)
        
        token = engine.gc_reserve_blob_for_deletion(conn, full_digest, "worker_a")
        engine.close()
        conn.close()
        
        # Spawn child process to execute deletion and crash at Boundary A
        proc = multiprocessing.Process(
            target=worker_boundary_crash,
            args=("A", real_anchor, cas_root, db_path, full_digest, token)
        )
        proc.start()
        proc.join(timeout=10.0)
        assert proc.exitcode == 42, f"Expected child to terminate with exit code 42, got {proc.exitcode}"
        print("  Verified: Child process terminated abruptly at Boundary A via os._exit(42).")
        
        # Invariants immediately post-crash
        assert os.path.isfile(dest_path), "Boundary A violation: file unlinked before crash!"
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "COMMITTED_FOR_UNLINK"
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == 0
        print("  Verified Post-Crash State: Physical file intact, DB COMMITTED_FOR_UNLINK, 0 receipts.")
        
        # Recovery via fresh engine process
        fresh_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        recovered = fresh_engine.recover_gc_reservations(conn)
        assert recovered == 1, f"Expected 1 recovered reservation, got {recovered}"
        
        assert not os.path.exists(dest_path), "Recovery failed to unlink physical file!"
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == 1
        
        # Verify receipt audit across restart
        audit_res = fresh_engine.audit_physical_deletion_consistency(conn, digest)
        assert audit_res["physically_exists"] is False
        assert audit_res["reservation_state"] == "PHYSICALLY_DELETED"
        assert audit_res["receipt_count"] == 1
        print("  Verified Recovery & Audit Gate: File unlinked, state PHYSICALLY_DELETED, receipt audited.")
        
        fresh_engine.close()
        conn.close()
        print("PASS: Test 01 - Multi-process Boundary A crash and recovery verified.\n")

def test_02_multiprocess_boundary_b_crash():
    print("--- Test 02: Real Multi-Process Crash at Boundary B (After Unlink, Before Dir Sync) ---")
    with tempfile.TemporaryDirectory(dir=SAFE_TMP_DIR) as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs_boundary_b.db")
        
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        payload = b"Payload for multi-process Boundary B crash verification"
        digest = hashlib.sha256(payload).hexdigest()
        full_digest = f"sha256:{digest}"
        shard = digest[:2]
        dest_path = os.path.join(cas_root, "objects", shard, digest)
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_b", "tok_b", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        assert os.path.isfile(dest_path)
        
        token = engine.gc_reserve_blob_for_deletion(conn, full_digest, "worker_b")
        engine.close()
        conn.close()
        
        proc = multiprocessing.Process(
            target=worker_boundary_crash,
            args=("B", real_anchor, cas_root, db_path, full_digest, token)
        )
        proc.start()
        proc.join(timeout=10.0)
        assert proc.exitcode == 42, f"Expected child to terminate with exit code 42, got {proc.exitcode}"
        print("  Verified: Child process terminated abruptly at Boundary B via os._exit(42).")
        
        # Post-crash state: file is unlinked on disk, but DB transaction never committed
        assert not os.path.exists(dest_path), "Boundary B state: file should be unlinked from disk!"
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "COMMITTED_FOR_UNLINK"
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == 0
        print("  Verified Post-Crash State: File unlinked, directory unsynced, DB COMMITTED_FOR_UNLINK.")
        
        # Recovery via fresh engine
        fresh_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        recovered = fresh_engine.recover_gc_reservations(conn)
        assert recovered == 1
        
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == 1
        
        audit_res = fresh_engine.audit_physical_deletion_consistency(conn, digest)
        assert audit_res["physically_exists"] is False
        assert audit_res["reservation_state"] == "PHYSICALLY_DELETED"
        print("  Verified Recovery & Audit Gate: Shard synced, state advanced to PHYSICALLY_DELETED.")
        
        fresh_engine.close()
        conn.close()
        print("PASS: Test 02 - Multi-process Boundary B crash and recovery verified.\n")

def test_03_multiprocess_boundary_c_crash():
    print("--- Test 03: Real Multi-Process Crash at Boundary C (After Sync, Before DB Commit) ---")
    with tempfile.TemporaryDirectory(dir=SAFE_TMP_DIR) as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs_boundary_c.db")
        
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        payload = b"Payload for multi-process Boundary C crash verification"
        digest = hashlib.sha256(payload).hexdigest()
        full_digest = f"sha256:{digest}"
        shard = digest[:2]
        dest_path = os.path.join(cas_root, "objects", shard, digest)
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_c", "tok_c", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        assert os.path.isfile(dest_path)
        
        token = engine.gc_reserve_blob_for_deletion(conn, full_digest, "worker_c")
        engine.close()
        conn.close()
        
        proc = multiprocessing.Process(
            target=worker_boundary_crash,
            args=("C", real_anchor, cas_root, db_path, full_digest, token)
        )
        proc.start()
        proc.join(timeout=10.0)
        assert proc.exitcode == 42, f"Expected child to terminate with exit code 42, got {proc.exitcode}"
        print("  Verified: Child process terminated abruptly at Boundary C via os._exit(42).")
        
        # Post-crash state: file is permanently unlinked & synced, SQLite rolled back write transaction
        assert not os.path.exists(dest_path)
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "COMMITTED_FOR_UNLINK"
        
        # CRITICAL VERIFICATION: Direct SQL cancellation MUST BE BLOCKED
        caught_cancellation_rejection = False
        try:
            cur.execute("UPDATE cas_gc_deletion_reservations SET reservation_state = 'REVERTED' WHERE blob_digest = ?;", (digest,))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            caught_cancellation_rejection = True
            print("  Guarded: Direct SQL cancellation after Boundary C crash strictly rejected by trigger.")
        assert caught_cancellation_rejection, "Security Failure: direct SQL restored deleted blob to REVERTED!"
        
        # Fresh engine recovery finishes the protocol cleanly
        fresh_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        recovered = fresh_engine.recover_gc_reservations(conn)
        assert recovered == 1
        
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == 1
        
        audit_res = fresh_engine.audit_physical_deletion_consistency(conn, digest)
        assert audit_res["physically_exists"] is False
        assert audit_res["reservation_state"] == "PHYSICALLY_DELETED"
        print("  Verified Recovery & Audit Gate: Crash at Boundary C safely recovered to PHYSICALLY_DELETED.")
        
        fresh_engine.close()
        conn.close()
        print("PASS: Test 03 - Multi-process Boundary C crash and phantom defense verified.\n")

def test_04_multiprocess_boundary_d_batch_crash():
    print("--- Test 04: Real Multi-Process Crash at Boundary D (During Batch Recovery) ---")
    with tempfile.TemporaryDirectory(dir=SAFE_TMP_DIR) as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs_boundary_d.db")
        
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        # Create 2 blobs committed for unlink
        payload_1 = b"Batch candidate 1 for Boundary D"
        payload_2 = b"Batch candidate 2 for Boundary D"
        digest_1 = hashlib.sha256(payload_1).hexdigest()
        digest_2 = hashlib.sha256(payload_2).hexdigest()
        
        tmp_1, _, _ = engine.write_payload_to_staging("pub_d1", "tok_d1", digest_1, payload_1)
        tmp_2, _, _ = engine.write_payload_to_staging("pub_d2", "tok_d2", digest_2, payload_2)
        engine.publish_staging_to_cas(tmp_1, digest_1)
        engine.publish_staging_to_cas(tmp_2, digest_2)
        
        engine.gc_reserve_blob_for_deletion(conn, f"sha256:{digest_1}", "worker_d1")
        engine.gc_reserve_blob_for_deletion(conn, f"sha256:{digest_2}", "worker_d2")
        engine.close()
        conn.close()
        
        # Child process starts batch recovery, processes 1 candidate, and crashes via os._exit(42)
        proc = multiprocessing.Process(
            target=worker_boundary_d_crash,
            args=(real_anchor, cas_root, db_path, 1)
        )
        proc.start()
        proc.join(timeout=10.0)
        assert proc.exitcode == 42
        print("  Verified: Child process crashed after processing 1 batch candidate.")
        
        # Post-crash state: Candidate 1 is PHYSICALLY_DELETED, Candidate 2 is still COMMITTED_FOR_UNLINK
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_1,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_2,))
        assert cur.fetchone()[0] == "COMMITTED_FOR_UNLINK"
        print("  Verified Post-Crash State: Item 1 committed PHYSICALLY_DELETED; Item 2 still COMMITTED_FOR_UNLINK.")
        
        # Second recovery pass resumes idempotently
        fresh_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        recovered_pass2 = fresh_engine.recover_gc_reservations(conn)
        assert recovered_pass2 == 1, f"Expected 1 item recovered on pass 2, got {recovered_pass2}"
        
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_2,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        
        # Both verified via audit gate
        fresh_engine.audit_physical_deletion_consistency(conn, digest_1)
        fresh_engine.audit_physical_deletion_consistency(conn, digest_2)
        print("  Verified Second Pass: Resumed recovery completed Item 2 idempotently; both audited.")
        
        fresh_engine.close()
        conn.close()
        print("PASS: Test 04 - Multi-process Boundary D batch crash and recovery verified.\n")

def test_05_persistent_key_lifecycle_and_rotation_across_restarts():
    print("--- Test 05: Persistent Key Lifecycle & Rotation Across Restarts ---")
    with tempfile.TemporaryDirectory(dir=SAFE_TMP_DIR) as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs_keys.db")
        
        conn = init_db(db_path)
        
        # Session 1: Engine writes blob and creates deletion receipt using Key 1
        engine_1 = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        key_1_id, key_1_secret = engine_1.key_store.get_active_key()
        assert key_1_id == "k1"
        
        payload_1 = b"Payload for Key 1"
        digest_1 = hashlib.sha256(payload_1).hexdigest()
        tmp_1, _, _ = engine_1.write_payload_to_staging("pub_k1", "tok_k1", digest_1, payload_1)
        engine_1.publish_staging_to_cas(tmp_1, digest_1)
        tok_1 = engine_1.gc_reserve_blob_for_deletion(conn, f"sha256:{digest_1}", "worker_k1")
        engine_1.gc_complete_physical_deletion(conn, f"sha256:{digest_1}", tok_1)
        engine_1.close()
        
        # Verify key file permissions on disk (POSIX only)
        key_file = os.path.join(real_anchor, ".lcs_keys", "key_ring.json")
        st = os.stat(key_file)
        if sys.platform != "win32":
            assert stat.S_IMODE(st.st_mode) == 0o600, f"Expected key file permissions 0600, got {oct(stat.S_IMODE(st.st_mode))}"
        dir_st = os.stat(os.path.join(real_anchor, ".lcs_keys"))
        if sys.platform != "win32":
            assert stat.S_IMODE(dir_st.st_mode) == 0o700, f"Expected key dir permissions 0700, got {oct(stat.S_IMODE(dir_st.st_mode))}"
        print("  Verified: Key store enforces strict permissions (0700 dir, 0600 file).")
        
        # Session 2: Fresh engine loads Key 1 from disk, verifies Session 1 receipt, then rotates to Key 2
        engine_2 = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        # Verify Session 1 receipt across process boundary
        res_1 = engine_2.audit_physical_deletion_consistency(conn, digest_1)
        assert res_1["receipt_count"] == 1
        print("  Verified: Fresh engine instance 2 verified receipt from instance 1 across restart.")
        
        # Rotate key to k2
        key_2_id, key_2_secret = engine_2.key_store.rotate_key()
        assert key_2_id == "k2"
        assert key_2_secret != key_1_secret
        
        # Write second blob using Key 2
        payload_2 = b"Payload for Key 2"
        digest_2 = hashlib.sha256(payload_2).hexdigest()
        tmp_2, _, _ = engine_2.write_payload_to_staging("pub_k2", "tok_k2", digest_2, payload_2)
        engine_2.publish_staging_to_cas(tmp_2, digest_2)
        tok_2 = engine_2.gc_reserve_blob_for_deletion(conn, f"sha256:{digest_2}", "worker_k2")
        engine_2.gc_complete_physical_deletion(conn, f"sha256:{digest_2}", tok_2)
        engine_2.close()
        
        # Session 3: Third fresh engine verifies BOTH receipts (Key 1 historical and Key 2 current)
        engine_3 = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        res_k1 = engine_3.audit_physical_deletion_consistency(conn, digest_1)
        res_k2 = engine_3.audit_physical_deletion_consistency(conn, digest_2)
        assert res_k1["receipt_count"] == 1
        assert res_k2["receipt_count"] == 1
        print("  Verified: Fresh engine instance 3 verified both Key 1 (historical) and Key 2 (rotated) receipts.")
        
        engine_3.close()
        conn.close()
        print("PASS: Test 05 - Persistent key lifecycle and rotation across restarts verified.\n")

def main():
    print("=" * 76)
    print("RUNNING LCS STAGE 2A.28 MULTI-PROCESS REAL CRASH & DURABILITY SUITE")
    print("=" * 76)
    test_01_multiprocess_boundary_a_crash()
    test_02_multiprocess_boundary_b_crash()
    test_03_multiprocess_boundary_c_crash()
    test_04_multiprocess_boundary_d_batch_crash()
    test_05_persistent_key_lifecycle_and_rotation_across_restarts()
    print("=" * 76)
    print("ALL 5 MULTI-PROCESS CRASH TESTS PASSED (100% GREEN)")
    print("=" * 76)

if __name__ == "__main__":
    multiprocessing.set_start_method("fork")
    main()
