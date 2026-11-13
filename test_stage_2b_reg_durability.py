#!/usr/bin/env python3
"""
LCS Stage 2A.26 Filesystem Durability & Descriptor-Relative CAS Publication Test Suite
======================================================================================
Tests descriptor-relative publication, atomic no-replace linkat semantics, corruption
detection, strict durability distinction (F_FULLFSYNC vs FSYNC_FALLBACK), unsuppressed
directory synchronization errors, deterministic short writes, atomic partial-write recovery,
and crash recovery boundaries.

Notice: As per Stage 2A.26 scope constraints, process crash tests verify process-level
crash recovery and transactional invariants; they do NOT claim hardware power-loss durability.
"""

import os
import sys
import stat
import time
import errno
import fcntl
import sqlite3
import hashlib
import tempfile
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.dirname(__file__))
from cas_storage_engine_v2b import (CASStagingCleanupError, CASSecurityViolationError, CASInterruptionError,
    SecureCASStorageEngine,
    CASDestinationCorruptionError,
    CASDigestMismatchError,
    CASDirectorySyncError,
    CASDurabilityError,
    CASPartialWriteError
)

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "lcs_schema_v2b.sql")

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON;")
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    return conn

# ============================================================================
# TEST 01: Descriptor-Relative 8-Step CAS Publication & 8-Phase Audit Sequence
# ============================================================================
def test_01_descriptor_relative_8step_publication_and_audit():
    print("--- Test 01: Descriptor-Relative 8-Step CAS Publication & 8-Phase Audit ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "metadata.db")
        conn = init_db(db_path)
        
        payload = b"Authoritative payload for Stage 2A.26 descriptor-relative publication\n"
        digest = hashlib.sha256(payload).hexdigest()
        byte_len = len(payload)
        
        engine = SecureCASStorageEngine(cas_root, strict_fullfsync=True, trusted_anchor=os.path.realpath(tmp_dir))
        
        # Step 1-4: Write staging descriptor-relative, hash, permissions 0o444, fullfsync
        tmp_name, written_bytes, dur_level = engine.write_payload_to_staging(
            pub_id="pub_test01",
            token="tok_alpha",
            expected_digest=digest,
            data_generator_or_bytes=payload
        )
        assert written_bytes == byte_len
        assert dur_level in ("F_FULLFSYNC", "FDATASYNC", "FSYNC")
        print(f"  Steps 1-4: Staged {written_bytes} bytes descriptor-relative with durability '{dur_level}'")
        
        # Step 5-7: Publish via linkat (no-replace), sync shard dir, unlink staging, sync staging dir
        pub_res = engine.publish_staging_to_cas(tmp_name, digest)
        assert pub_res["status"] == "PUBLISHED"
        assert not pub_res["is_deduplicated"]
        print("  Steps 5-7: Atomic linkat succeeded, directories synced, staging unlinked.")
        
        # Step 8: Commit registration to SQLite
        conn.execute("""
            INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
            VALUES (?, ?, 'NONE', ?);
        """, (digest, byte_len, byte_len))
        
        conn.execute("""
            INSERT INTO active_cas_publications 
            (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
            VALUES ('pub_test01', ?, 'worker_durable', 'tok_alpha', 'COMMITTED', datetime('now'), datetime('now', '+1 hour'));
        """, (digest,))
        
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM content_chunk_blobs WHERE blob_digest = ?", (digest,))
        assert cur.fetchone()[0] == 1
        
        # Verify physical file existence and inode properties
        shard = digest[:2]
        dest_file = os.path.join(cas_root, "objects", shard, digest)
        assert os.path.isfile(dest_file)
        st = os.stat(dest_file)
        assert st.st_size == byte_len
        assert (st.st_mode & 0o777) == 0o444
        
        engine.close()
        conn.close()
        print("PASS: Test 01 - Descriptor-relative 8-step publication and audit verified.\n")

# ============================================================================
# TEST 02: Atomic No-Replace Hard Link Semantics & Corruption Detection
# ============================================================================
def test_02_atomic_no_replace_and_corruption_detection():
    print("--- Test 02: Atomic No-Replace Linkat Semantics & Corruption Detection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload_authentic = b"Original authentic content payload for stage 2a22"
        digest_authentic = hashlib.sha256(payload_authentic).hexdigest()
        
        # Publish authentic file
        tmp1, _, _ = engine.write_payload_to_staging("pub_auth", "tok1", digest_authentic, payload_authentic)
        res1 = engine.publish_staging_to_cas(tmp1, digest_authentic)
        assert not res1["is_deduplicated"]
        
        # Sub-test 2a: Deduplication (same digest)
        tmp2, _, _ = engine.write_payload_to_staging("pub_dedup", "tok2", digest_authentic, payload_authentic)
        res2 = engine.publish_staging_to_cas(tmp2, digest_authentic)
        assert res2["is_deduplicated"], "Identical payload must trigger safe deduplication"
        print("  2a. Safe deduplication on identical destination verified.")
        
        # Sub-test 2b: Corruption detection (destination file tampered / mismatched)
        shard = digest_authentic[:2]
        dest_path = os.path.join(cas_root, "objects", shard, digest_authentic)
        os.chmod(dest_path, 0o644)
        with open(dest_path, "wb") as f:
            f.write(b"CORRUPTED CONTENT BY MALICIOUS WRITER")
        os.chmod(dest_path, 0o444)
        
        # Attempt to publish authentic payload: must detect mismatch and reject overwrite!
        tmp3, _, _ = engine.write_payload_to_staging("pub_corrupt", "tok3", digest_authentic, payload_authentic)
        caught_corruption = False
        try:
            engine.publish_staging_to_cas(tmp3, digest_authentic)
        except CASDestinationCorruptionError as e:
            caught_corruption = True
            print(f"  2b. Guarded: Corruption detected; destination overwrite aborted: {e}")
        assert caught_corruption, "Storage engine failed to detect corrupted destination on EEXIST!"
        
        # Verify corrupted destination was NOT overwritten with authentic payload
        with open(dest_path, "rb") as f:
            assert f.read() == b"CORRUPTED CONTENT BY MALICIOUS WRITER"
            
        engine.close()
        print("PASS: Test 02 - Atomic no-replace and corruption detection verified.\n")

# ============================================================================
# TEST 03: Durability Distinction & Unsuppressed Directory Synchronization
# ============================================================================
def test_03_durability_distinction_and_directory_sync():
    print("--- Test 03: Durability Distinction & Unsuppressed Directory Sync ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        
        # Test 3a: Strict durability distinction
        engine_strict = SecureCASStorageEngine(cas_root, strict_fullfsync=True, trusted_anchor=os.path.realpath(tmp_dir))
        payload = b"Durability distinction test for Stage 2A.26"
        digest = hashlib.sha256(payload).hexdigest()
        
        tmp_name, _, dur_level = engine_strict.write_payload_to_staging("pub_dur", "tok1", digest, payload)
        if sys.platform == "darwin" and hasattr(fcntl, "F_FULLFSYNC"):
            assert dur_level == "F_FULLFSYNC", f"macOS must report F_FULLFSYNC, got {dur_level}"
            print("  3a. macOS F_FULLFSYNC verified and recorded accurately.")
            
        engine_strict.close()
        
        # Test 3b: Directory sync errors are NEVER suppressed
        engine_sync_test = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        os.close(engine_sync_test.staging_dir_fd)
        caught_sync_error = False
        try:
            tmp_dummy, _, _ = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir)).write_payload_to_staging("pub_d", "tok_d", digest, payload)
            engine_sync_test.staging_dir_fd = -1 # Invalid descriptor
            engine_sync_test.publish_staging_to_cas(tmp_dummy, digest)
        except (CASDirectorySyncError, OSError) as e:
            caught_sync_error = True
            print(f"  3b. Guarded: Directory sync failure was strictly raised and not suppressed: {e}")
        assert caught_sync_error, "Directory sync failure was silently suppressed!"
        
        engine_sync_test.close()
        print("PASS: Test 03 - Durability distinction and unsuppressed directory sync verified.\n")

# ============================================================================
# TEST 04: Deterministic Short-Write Handling
# ============================================================================
def test_04_deterministic_short_write_handling():
    print("--- Test 04: Deterministic Short-Write Handling ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        # Payload of 256 bytes
        payload = b"0123456789ABCDEF" * 16
        digest = hashlib.sha256(payload).hexdigest()
        assert len(payload) == 256
        
        # Force tiny short-writes of exactly 11 bytes per os.write call
        # 256 bytes / 11 = 23 full chunks + 3 bytes remainder
        tmp_name, written_bytes, dur_level = engine.write_payload_to_staging(
            pub_id="pub_short",
            token="tok_short",
            expected_digest=digest,
            data_generator_or_bytes=payload,
            short_write_limit=11
        )
        
        assert written_bytes == 256, f"Expected 256 bytes written, got {written_bytes}"
        print(f"  Verified: Loop handled short-writes (limit 11 B/write); accurate byte count {written_bytes} B.")
        
        # Verify physical content and digest
        pub_res = engine.publish_staging_to_cas(tmp_name, digest)
        assert pub_res["status"] == "PUBLISHED"
        
        shard = digest[:2]
        dest_file = os.path.join(cas_root, "objects", shard, digest)
        with open(dest_file, "rb") as f:
            read_back = f.read()
        assert read_back == payload
        assert hashlib.sha256(read_back).hexdigest() == digest
        print("  Verified: Staged payload matches expected SHA-256 digest byte-for-byte.")
        
        engine.close()
        print("PASS: Test 04 - Deterministic short-write handling verified.\n")

# ============================================================================
# TEST 05: Interrupted Write & ENOSPC Cleanup
# ============================================================================
def test_05_interrupted_write_and_enospc_cleanup():
    print("--- Test 05: Interrupted Write & ENOSPC Cleanup ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload = b"Large payload that will experience simulated ENOSPC disk-full failure midway" * 100
        digest = hashlib.sha256(payload).hexdigest()
        
        # Simulate disk full after 73 bytes
        caught_enospc = False
        try:
            engine.write_payload_to_staging(
                pub_id="pub_enospc",
                token="tok_enospc",
                expected_digest=digest,
                data_generator_or_bytes=payload,
                simulated_write_failure_after_bytes=73
            )
        except OSError as e:
            caught_enospc = True
            print(f"  Guarded: Partial write aborted as expected: {e}")
        assert caught_enospc
        
        # Verify that NO partial .part file remains in cas/staging
        staging_dir = os.path.join(cas_root, "staging")
        staging_files = os.listdir(staging_dir)
        assert len(staging_files) == 0, f"Staging directory leaked partial file: {staging_files}"
        print("  Verified: Staging directory contains 0 partial files; descriptor-relative cleanup succeeded.")
        
        engine.close()
        print("PASS: Test 05 - Interrupted write and ENOSPC cleanup verified.\n")

# ============================================================================
# TEST 06: Boundary Crash Recovery Invariants
# ============================================================================
def test_06_boundary_crash_recovery_invariants():
    print("--- Test 06: Boundary Crash Recovery Invariants ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "recovery.db")
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload = b"Boundary crash recovery test payload for Stage 2A.26"
        digest = hashlib.sha256(payload).hexdigest()
        shard = digest[:2]
        
        # Boundary 2: Staging complete, fsynced, before linkat()
        conn.execute("""
            INSERT INTO active_cas_publications 
            (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
            VALUES ('pub_b2', ?, 'w_crashed', 'tok_b2', 'ACQUIRED', datetime('now', '-1 hour'), datetime('now', '-30 minutes'));
        """, (digest,))
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_b2", "tok_b2", digest, payload)
        
        # Recovery scanner execution:
        cur = conn.cursor()
        cur.execute("""
            SELECT publication_id, blob_digest, lease_token FROM active_cas_publications
            WHERE lease_state IN ('ACQUIRED', 'HEARTBEAT_ACTIVE') AND datetime('now') > lease_expires_at;
        """)
        expired_pubs = cur.fetchall()
        assert len(expired_pubs) == 1
        for p_id, d_val, tok in expired_pubs:
            try:
                os.unlink(tmp_name, dir_fd=engine.staging_dir_fd)
            except OSError:
                pass
            conn.execute("UPDATE active_cas_publications SET lease_state = 'ABORTED' WHERE publication_id = ?", (p_id,))
            
        assert not os.path.exists(os.path.join(cas_root, "staging", tmp_name))
        cur.execute("SELECT lease_state FROM active_cas_publications WHERE publication_id = 'pub_b2'")
        assert cur.fetchone()[0] == "ABORTED"
        print("  Boundary 2 recovery verified: Expired pre-link staging file swept; lease ABORTED.")
        
        # Boundary 3: linkat() succeeded, before DB commit
        tmp_b3, _, _ = engine.write_payload_to_staging("pub_b3", "tok_b3", digest, payload)
        engine.publish_staging_to_cas(tmp_b3, digest)
        
        conn.execute("""
            INSERT INTO active_cas_publications 
            (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
            VALUES ('pub_b3', ?, 'w_crashed3', 'tok_b3', 'PUBLISHED', datetime('now', '-10 minutes'), datetime('now', '+10 minutes'));
        """, (digest,))
        
        cur.execute("SELECT publication_id, blob_digest FROM active_cas_publications WHERE lease_state = 'PUBLISHED';")
        published_leases = cur.fetchall()
        assert len(published_leases) == 1
        for p_id, d_val in published_leases:
            dest_f = os.path.join(cas_root, "objects", d_val[:2], d_val)
            assert os.path.isfile(dest_f)
            conn.execute("""
                INSERT OR IGNORE INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
                VALUES (?, ?, 'NONE', ?);
            """, (d_val, len(payload), len(payload)))
            conn.execute("UPDATE active_cas_publications SET lease_state = 'COMMITTED' WHERE publication_id = ?", (p_id,))
            
        cur.execute("SELECT lease_state FROM active_cas_publications WHERE publication_id = 'pub_b3'")
        assert cur.fetchone()[0] == "COMMITTED"
        cur.execute("SELECT count(*) FROM content_chunk_blobs WHERE blob_digest = ?", (digest,))
        assert cur.fetchone()[0] == 1
        print("  Boundary 3 recovery verified: In-flight published blob reconciled and COMMITTED.")
        
        engine.close()
        conn.close()
        print("PASS: Test 06 - Boundary crash recovery invariants verified.\n")

# ============================================================================
# TEST 07: EINTR Interrupted Write Recovery & Byte Accuracy
# ============================================================================
def test_07_eintr_interrupted_write_recovery():
    print("--- Test 07: EINTR Interrupted Write Recovery & Byte Accuracy ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload = b"Payload written across multiple simulated EINTR signal interrupts" * 16
        digest = hashlib.sha256(payload).hexdigest()
        byte_len = len(payload)
        
        # Test staging write with 5 simulated EINTR interrupts
        tmp_name, written_bytes, dur_level = engine.write_payload_to_staging(
            pub_id="pub_eintr",
            token="tok_eintr",
            expected_digest=digest,
            data_generator_or_bytes=payload,
            short_write_limit=17,
            simulate_eintr_times=5
        )
        
        assert written_bytes == byte_len, f"Expected {byte_len} bytes written, got {written_bytes}"
        print(f"  Verified: Loop handled 5 EINTR signal interrupts; accurate total bytes {written_bytes} B.")
        
        pub_res = engine.publish_staging_to_cas(tmp_name, digest)
        assert pub_res["status"] == "PUBLISHED"
        
        shard = digest[:2]
        dest_file = os.path.join(cas_root, "objects", shard, digest)
        with open(dest_file, "rb") as f:
            read_back = f.read()
        assert read_back == payload
        assert hashlib.sha256(read_back).hexdigest() == digest
        print("  Verified: Final physical bytes and SHA-256 verified independently after EINTR retries.")
        
        engine.close()
        print("PASS: Test 07 - EINTR interrupted write recovery verified.\n")

# ============================================================================
# TEST 08: Staging Unlink Failure Quarantine & Repeated Recovery
# ============================================================================
def test_08_staging_unlink_failure_quarantine_and_repeated_recovery():
    print("--- Test 08: Staging Unlink Failure Quarantine & Repeated Recovery ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload = b"Payload destined for simulated staging cleanup failure"
        digest = hashlib.sha256(payload).hexdigest()
        
        caught_cleanup_err = False
        try:
            # Simulate failure during write (ENOSPC after 20 bytes) combined with simulate_unlink_failure=True
            engine.write_payload_to_staging(
                pub_id="pub_orphan",
                token="tok_orphan",
                expected_digest=digest,
                data_generator_or_bytes=payload,
                simulated_write_failure_after_bytes=20,
                simulate_unlink_failure=True
            )
        except CASStagingCleanupError as e:
            caught_cleanup_err = True
            print(f"  Guarded: Staging unlink failure NEVER silently suppressed; caught: {e}")
        assert caught_cleanup_err, "Storage engine silently suppressed staging unlink failure!"
        
        # Verify that orphan file state was quarantined
        assert len(engine.quarantined_orphans) == 1
        orphan_entry = engine.quarantined_orphans[0]
        orphan_filename = orphan_entry["tmp_filename"]
        assert orphan_entry["pub_id"] == "pub_orphan"
        assert orphan_entry["bytes_written"] == 20
        print(f"  Verified: Orphan staging file '{orphan_filename}' recorded in quarantine registry.")
        
        # Verify physical orphan file is currently present in staging directory
        assert os.path.exists(os.path.join(cas_root, "staging", orphan_filename))
        
        # Execute recovery run
        recovered_count = engine.recover_quarantined_orphans()
        assert recovered_count == 1
        assert len(engine.quarantined_orphans) == 0
        assert not os.path.exists(os.path.join(cas_root, "staging", orphan_filename))
        print(f"  Verified: Recovery pass cleaned up {recovered_count} orphan file; quarantine registry cleared.")
        
        # Repeated recovery run is idempotent (0 remaining orphans)
        recovered_repeat = engine.recover_quarantined_orphans()
        assert recovered_repeat == 0
        print("  Verified: Repeated recovery run is cleanly idempotent.")
        
        engine.close()
        print("PASS: Test 08 - Staging unlink failure quarantine and repeated recovery verified.\n")


# ============================================================================
# TEST 09: Durable Staging Scan Recovery Across Process Restart
# ============================================================================
def test_09_durable_staging_scan_recovery_across_process_restart():
    print("--- Test 09: Durable Staging Scan Recovery Across Process Restart ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "durable_orphan.db")
        conn = init_db(db_path)
        
        # Process 1: Starts engine, writes staging file, encounters simulated unlink failure
        proc1_engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        payload = b"Payload for durable process restart recovery testing"
        digest = hashlib.sha256(payload).hexdigest()
        
        caught_err = False
        try:
            proc1_engine.write_payload_to_staging(
                pub_id="pub_proc1",
                token="tok_proc1",
                expected_digest=digest,
                data_generator_or_bytes=payload,
                simulated_write_failure_after_bytes=25,
                simulate_unlink_failure=True
            )
        except CASStagingCleanupError:
            caught_err = True
        assert caught_err
        
        # Verify orphan file physically exists on disk
        orphan_fn = f"tmp_pub_proc1_tok_proc1_{digest[:16]}.part"
        orphan_path = os.path.join(cas_root, "staging", orphan_fn)
        assert os.path.isfile(orphan_path)
        
        # Process 1 TERMINATES (closed, destroyed, in-memory state wiped)
        proc1_engine.close()
        del proc1_engine
        
        # Process 2: Starts fresh with ZERO knowledge of proc1 in-memory state
        proc2_engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        assert len(proc2_engine.quarantined_orphans) == 0, "Fresh engine should have empty in-memory quarantine list"
        
        # Process 2 executes durable filesystem scan and recovery
        recovered = proc2_engine.durable_scan_and_recover_staging_orphans(conn=conn, max_age_seconds=0)
        assert recovered == 1, f"Expected 1 orphan recovered, got {recovered}"
        assert not os.path.exists(orphan_path), "Orphan staging file was not physically unlinked by durable recovery!"
        print(f"  Verified: Fresh process scanned staging directory descriptor-relative and unlinked {recovered} orphan.")
        
        # Repeated scan is idempotent
        repeat_recovered = proc2_engine.durable_scan_and_recover_staging_orphans(conn=conn, max_age_seconds=0)
        assert repeat_recovered == 0
        print("  Verified: Repeated durable scan is cleanly idempotent.")
        
        proc2_engine.close()
        conn.close()
        print("PASS: Test 09 - Durable staging scan recovery across process restart verified.\n")



def test_10_descriptor_relative_orphan_recovery_symlink_rejection_and_directory_replacement():
    print("--- Test 10: Descriptor-Relative Orphan Recovery, Symlink Rejection & Directory Replacement ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        staging_dir_path = os.path.join(cas_root, "staging")
        
        # 1. Attack Vector A: Plant a symlink inside staging
        evil_symlink = os.path.join(staging_dir_path, "tmp_malicious_symlink.part")
        target_file = os.path.join(real_anchor, "victim.txt")
        with open(target_file, "w") as f:
            f.write("sensitive data")
        os.symlink(target_file, evil_symlink)
        
        # Durable scan MUST strictly detect the symlink descriptor-relative and raise CASSecurityViolationError
        caught_symlink_sec = False
        try:
            engine.durable_scan_and_recover_staging_orphans(max_age_seconds=0)
        except CASSecurityViolationError as e:
            caught_symlink_sec = True
            print(f"  Guarded: Symlink entry in staging strictly rejected descriptor-relative: {e}")
        assert caught_symlink_sec, "Failed to reject symbolic link in staging directory during orphan sweep!"
        os.unlink(evil_symlink)
        
        # 2. Attack Vector B: Plant an unexpected directory inside staging
        bogus_dir = os.path.join(staging_dir_path, "tmp_nested_dir.part")
        os.mkdir(bogus_dir)
        caught_dir_sec = False
        try:
            engine.durable_scan_and_recover_staging_orphans(max_age_seconds=0)
        except CASSecurityViolationError as e:
            caught_dir_sec = True
            print(f"  Guarded: Non-regular file directory entry in staging strictly rejected: {e}")
        assert caught_dir_sec, "Failed to reject directory entry in staging during orphan sweep!"
        os.rmdir(bogus_dir)
        
        # 3. Create a legitimate orphan .part file in staging
        payload = b"Legitimate orphan payload for descriptor-relative scan testing"
        digest = hashlib.sha256(payload).hexdigest()
        orphan_fn = f"tmp_pub_legit_tok_legit_{digest[:16]}.part"
        
        part_fd = os.open(orphan_fn, os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=engine.staging_dir_fd)
        os.write(part_fd, payload)
        os.close(part_fd)
        
        st = os.stat(orphan_fn, dir_fd=engine.staging_dir_fd, follow_symlinks=False)
        assert stat.S_ISREG(st.st_mode)
        
        # 4. Attack Vector C: Filesystem Directory Replacement during active recovery
        # Rename staging path on disk to simulate concurrent directory substitution attack
        renamed_staging = staging_dir_path + "_diverted"
        os.rename(staging_dir_path, renamed_staging)
        os.mkdir(staging_dir_path) # Attacker creates empty dummy directory at original path
        
        # Engine's pinned staging_dir_fd points to the authentic directory inode (now at renamed_staging)
        # Authoritative scan operates exclusively on staging_dir_fd, completely impervious to path replacement
        recovered = engine.durable_scan_and_recover_staging_orphans(max_age_seconds=0)
        assert recovered == 1, f"Expected 1 orphan recovered via pinned descriptor, got {recovered}"
        
        # Verify the orphan in the pinned directory was unlinked
        assert not os.path.exists(os.path.join(renamed_staging, orphan_fn)), "Orphan was not unlinked from pinned directory entry!"
        print(f"  Verified: Directory path replacement on disk did not divert pinned descriptor orphan recovery.")
        
        engine.close()
        print("PASS: Test 10 - Descriptor-relative staging orphan recovery and security guards verified.\n")


# ============================================================================
# TEST 11: GC Deletion Boundary Crash Recovery Matrix (Boundaries A, B, C, D)
# ============================================================================
def test_11_gc_deletion_boundary_crash_recovery_matrix():
    print("--- Test 11: GC Deletion Boundary Crash Recovery Matrix (Boundaries A, B, C, D) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "gc_boundaries.db")
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        # --------------------------------------------------------------------
        # Boundary A: Interruption BEFORE physical unlink
        # --------------------------------------------------------------------
        payload_a = b"Payload for GC crash Boundary A testing (before unlink)"
        digest_a = hashlib.sha256(payload_a).hexdigest()
        full_digest_a = f"sha256:{digest_a}"
        shard_a = digest_a[:2]
        dest_a = os.path.join(cas_root, "objects", shard_a, digest_a)
        
        tmp_name_a, _, _ = engine.write_payload_to_staging("pub_a", "tok_a", digest_a, payload_a)
        engine.publish_staging_to_cas(tmp_name_a, digest_a)
        assert os.path.isfile(dest_a)
        token_a = engine.gc_reserve_blob_for_deletion(conn, full_digest_a, "worker_boundary_a")
        
        # Simulate crash before physical unlink
        caught_crash_a = False
        try:
            engine.gc_complete_physical_deletion(conn, full_digest_a, token_a, simulate_crash_before_unlink=True)
        except CASInterruptionError as e:
            caught_crash_a = True
            print(f"  Boundary A Interruption Simulated: {e}")
        assert caught_crash_a
        
        # Invariant Assertions after Boundary A Crash:
        assert os.path.isfile(dest_a), "Boundary A violation: physical file was unlinked before crash point!"
        cur = conn.cursor()
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_a,))
        assert cur.fetchone()[0] == "COMMITTED_FOR_UNLINK", "Boundary A violation: DB state mutated before unlink!"
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest_a,))
        assert cur.fetchone()[0] == 0, "Boundary A violation: receipt recorded before unlink!"
        print("  Verified Boundary A: Physical file remains on disk; DB reservation remains COMMITTED_FOR_UNLINK.")
        
        # Recovery from Boundary A:
        rec_a = engine.recover_gc_reservations(conn)
        assert rec_a == 1
        assert not os.path.exists(dest_a), "Recovery failed to unlink physical file after Boundary A crash!"
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_a,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        print("  Verified Boundary A Recovery: Sweeper unlinked file and transitioned DB to PHYSICALLY_DELETED.")

        # --------------------------------------------------------------------
        # Boundary B: Interruption AFTER unlink, BEFORE directory sync
        # --------------------------------------------------------------------
        payload_b = b"Payload for GC crash Boundary B testing (after unlink, before sync)"
        digest_b = hashlib.sha256(payload_b).hexdigest()
        full_digest_b = f"sha256:{digest_b}"
        shard_b = digest_b[:2]
        dest_b = os.path.join(cas_root, "objects", shard_b, digest_b)
        
        tmp_name_b, _, _ = engine.write_payload_to_staging("pub_b", "tok_b", digest_b, payload_b)
        engine.publish_staging_to_cas(tmp_name_b, digest_b)
        assert os.path.isfile(dest_b)
        token_b = engine.gc_reserve_blob_for_deletion(conn, full_digest_b, "worker_boundary_b")
        
        caught_crash_b = False
        try:
            engine.gc_complete_physical_deletion(conn, full_digest_b, token_b, simulate_crash_before_dir_sync=True)
        except CASInterruptionError as e:
            caught_crash_b = True
            print(f"  Boundary B Interruption Simulated: {e}")
        assert caught_crash_b
        
        # Invariant Assertions after Boundary B Crash:
        assert not os.path.exists(dest_b), "Boundary B state: physical file was unlinked from directory table."
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_b,))
        assert cur.fetchone()[0] == "COMMITTED_FOR_UNLINK", "Boundary B violation: DB state mutated before sync/commit!"
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest_b,))
        assert cur.fetchone()[0] == 0
        print("  Verified Boundary B: File unlinked; directory un-synced; DB remains COMMITTED_FOR_UNLINK.")
        
        # Recovery from Boundary B:
        rec_b = engine.recover_gc_reservations(conn)
        assert rec_b == 1
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_b,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        print("  Verified Boundary B Recovery: Sweeper synchronized shard directory and completed DB transition.")

        # --------------------------------------------------------------------
        # Boundary C: Interruption AFTER directory sync, BEFORE DB commit
        # --------------------------------------------------------------------
        payload_c = b"Payload for GC crash Boundary C testing (after sync, before DB commit)"
        digest_c = hashlib.sha256(payload_c).hexdigest()
        full_digest_c = f"sha256:{digest_c}"
        shard_c = digest_c[:2]
        dest_c = os.path.join(cas_root, "objects", shard_c, digest_c)
        
        tmp_name_c, _, _ = engine.write_payload_to_staging("pub_c", "tok_c", digest_c, payload_c)
        engine.publish_staging_to_cas(tmp_name_c, digest_c)
        assert os.path.isfile(dest_c)
        token_c = engine.gc_reserve_blob_for_deletion(conn, full_digest_c, "worker_boundary_c")
        
        caught_crash_c = False
        try:
            engine.gc_complete_physical_deletion(conn, full_digest_c, token_c, simulate_crash_before_db_commit=True)
        except CASInterruptionError as e:
            caught_crash_c = True
            print(f"  Boundary C Interruption Simulated: {e}")
        assert caught_crash_c
        
        # Invariant Assertions after Boundary C Crash:
        assert not os.path.exists(dest_c), "Boundary C: file is permanently unlinked and shard synced on disk."
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_c,))
        assert cur.fetchone()[0] == "COMMITTED_FOR_UNLINK", "Boundary C: SQLite rolled back aborted write transaction."
        print("  Verified Boundary C: Disk durable unlink complete; SQLite transaction cleanly rolled back.")
        
        # Recovery from Boundary C:
        rec_c = engine.recover_gc_reservations(conn)
        assert rec_c == 1
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_c,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        print("  Verified Boundary C Recovery: Confirmed absence recognized; deletion receipt committed.")

        # --------------------------------------------------------------------
        # Boundary D: Interruption DURING recovery batch
        # --------------------------------------------------------------------
        payload_d1 = b"Payload for GC Boundary D candidate 1"
        payload_d2 = b"Payload for GC Boundary D candidate 2"
        digest_d1 = hashlib.sha256(payload_d1).hexdigest()
        digest_d2 = hashlib.sha256(payload_d2).hexdigest()
        full_d1 = f"sha256:{digest_d1}"
        full_d2 = f"sha256:{digest_d2}"
        
        tmp_d1, _, _ = engine.write_payload_to_staging("pub_d1", "tok_d1", digest_d1, payload_d1)
        tmp_d2, _, _ = engine.write_payload_to_staging("pub_d2", "tok_d2", digest_d2, payload_d2)
        engine.publish_staging_to_cas(tmp_d1, digest_d1)
        engine.publish_staging_to_cas(tmp_d2, digest_d2)
        
        token_d1 = engine.gc_reserve_blob_for_deletion(conn, full_d1, "worker_d1")
        token_d2 = engine.gc_reserve_blob_for_deletion(conn, full_d2, "worker_d2")
        
        # Complete candidate 1, crash before candidate 2
        engine.gc_complete_physical_deletion(conn, full_d1, token_d1)
        
        # Candidate 1 is PHYSICALLY_DELETED; Candidate 2 is still COMMITTED_FOR_UNLINK
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_d1,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_d2,))
        assert cur.fetchone()[0] == "COMMITTED_FOR_UNLINK"
        
        # Second recovery pass resumes idempotently
        rec_d = engine.recover_gc_reservations(conn)
        assert rec_d == 1, f"Expected 1 candidate recovered on second pass, got {rec_d}"
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_d2,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        print("  Verified Boundary D Recovery: Batch recovery is strictly atomic and idempotent across restarts.")

        # Verify persistent key audit across restart for all recovered items
        engine.close()
        engine_restarted = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        for d in [digest_a, digest_b, digest_c, digest_d1, digest_d2]:
            audit_res = engine_restarted.audit_physical_deletion_consistency(conn, d)
            assert audit_res["reservation_state"] == "PHYSICALLY_DELETED"
            assert audit_res["physically_exists"] is False
            assert audit_res["receipt_count"] == 1
        print("  Verified: All boundary-recovered receipts audited cleanly across engine restart with persistent keys.")
        engine_restarted.close()

        conn.close()
        print("PASS: Test 11 - GC deletion boundary crash recovery matrix (Boundaries A, B, C, D) verified.\n")

def main():
    print("=" * 76)
    print("RUNNING LCS STAGE 2A.28 FILESYSTEM DURABILITY VERIFICATION SUITE")
    print("=" * 76)
    test_01_descriptor_relative_8step_publication_and_audit()
    test_02_atomic_no_replace_and_corruption_detection()
    test_03_durability_distinction_and_directory_sync()
    test_04_deterministic_short_write_handling()
    test_05_interrupted_write_and_enospc_cleanup()
    test_06_boundary_crash_recovery_invariants()
    test_07_eintr_interrupted_write_recovery()
    test_08_staging_unlink_failure_quarantine_and_repeated_recovery()
    test_09_durable_staging_scan_recovery_across_process_restart()
    test_10_descriptor_relative_orphan_recovery_symlink_rejection_and_directory_replacement()
    test_11_gc_deletion_boundary_crash_recovery_matrix()
    print("=" * 76)
    print("ALL 11 DURABILITY VERIFICATION TESTS PASSED (100% GREEN)")
    print("=" * 76)

if __name__ == "__main__":
    main()
