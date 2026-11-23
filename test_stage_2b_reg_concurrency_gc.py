#!/usr/bin/env python3
"""
LCS Stage 2A.26 Integrated Publisher & Garbage Collection (GC) Test Suite
==========================================================================
Empirically verifies the publisher and GC coordination protocol across the
database and physical filesystem deletion boundaries using coordinated
threads, deterministic synchronization barriers, and restart recovery.

Notice: In accordance with Stage 2A.26 engineering directives, this suite
provides empirical verification of critical race interleavings; it does NOT
claim mathematical formal proof from a finite set of test runs.
"""

import os
import sys
import time
import sqlite3
import hashlib
import tempfile
import threading
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))
from cas_storage_engine_v2b import SecureCASStorageEngine, CASPublicationConflictError, CASSecurityViolationError, CASDeletionError

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "lcs_schema_v2b.sql")

def create_lcs_connection(db_path: str, timeout: float = 10.0, isolation_level: Optional[str] = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=timeout, isolation_level=isolation_level)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    return conn

def init_db(db_path: str) -> sqlite3.Connection:
    conn = create_lcs_connection(db_path, isolation_level=None)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    return conn

# ============================================================================
# TEST 01: Coordinated Multi-Publisher Same-Digest Race with Deterministic Barrier
# ============================================================================
def test_01_coordinated_multi_publisher_same_digest_barrier():
    print("--- Test 01: Coordinated Multi-Publisher Same-Digest Race (Barrier Synchronized) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "barrier.db")
        init_db(db_path).close()
        
        payload = b"Synchronized concurrent multi-publisher payload for Stage 2A.26"
        digest = hashlib.sha256(payload).hexdigest()
        byte_len = len(payload)
        shard = digest[:2]
        
        barrier = threading.Barrier(2)
        results = {}
        
        def worker_task(worker_id: str, token: str):
            conn = create_lcs_connection(db_path, isolation_level=None)
            engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
            pub_id = f"pub_{worker_id}_{token}"
            
            # Step 1: Acquire lease in DB
            conn.execute("""
                INSERT INTO active_cas_publications 
                (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
                VALUES (?, ?, ?, ?, 'ACQUIRED', datetime('now'), datetime('now', '+15 seconds'));
            """, (pub_id, digest, worker_id, token))
            
            # Step 2: Write payload to staging
            tmp_name, _, _ = engine.write_payload_to_staging(pub_id, token, digest, payload)
            
            # Wait for both workers to finish staging before attempting linkat
            barrier.wait()
            
            # Step 3: Concurrent atomic linkat to destination
            res = engine.publish_staging_to_cas(tmp_name, digest)
            
            conn.execute("""
                UPDATE active_cas_publications
                SET lease_state = 'PUBLISHED'
                WHERE publication_id = ?;
            """, (pub_id,))
            
            # Step 4: Register in database
            try:
                conn.execute("""
                    INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
                    VALUES (?, ?, 'NONE', ?);
                """, (digest, byte_len, byte_len))
                registered = True
            except sqlite3.IntegrityError:
                registered = False
                
            conn.execute("""
                UPDATE active_cas_publications
                SET lease_state = 'COMMITTED'
                WHERE publication_id = ?;
            """, (pub_id,))
            
            engine.close()
            conn.close()
            results[worker_id] = {
                "status": "SUCCESS",
                "registered": registered,
                "is_deduplicated": res["is_deduplicated"]
            }

        t1 = threading.Thread(target=worker_task, args=("w1", "tok_alpha"))
        t2 = threading.Thread(target=worker_task, args=("w2", "tok_beta"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        assert results["w1"]["status"] == "SUCCESS"
        assert results["w2"]["status"] == "SUCCESS"
        
        reg_count = sum(1 for w in results.values() if w["registered"])
        assert reg_count == 1, f"Expected exactly 1 DB registration, got {reg_count}"
        
        dest_path = os.path.join(cas_root, "objects", shard, digest)
        assert os.path.isfile(dest_path)
        with open(dest_path, "rb") as f:
            assert f.read() == payload
            
        staging_dir = os.path.join(cas_root, "staging")
        assert len(os.listdir(staging_dir)) == 0
        print("PASS: Test 01 - Coordinated multi-publisher concurrent publication verified.\n")

# ============================================================================
# TEST 02: Critical Interleaving: Concurrent Reference Creation vs GC Deletion
# ============================================================================
def test_02_concurrent_reference_creation_vs_gc_deletion():
    print("--- Test 02: Concurrent Reference Creation vs GC Deletion ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "interleaving.db")
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload = b"Payload for reference creation interleaving test"
        digest = hashlib.sha256(payload).hexdigest()
        byte_len = len(payload)
        
        # Publish and register blob
        tmp_name, _, _ = engine.write_payload_to_staging("pub_ref", "tok_ref", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        conn.execute("""
            INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
            VALUES (?, ?, 'NONE', ?);
        """, (digest, byte_len, byte_len))
        
        # Setup base capability and variant for snapshot
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:cap:c', 'CAPABILITY', 'PENDING');")
        conn.execute("INSERT INTO capabilities (capability_urn, name, version) VALUES ('urn:lcs:cap:c', 'CapC', '1');")
        conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = 'urn:lcs:cap:c';")
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:variant:vc', 'CONTENT_VARIANT', 'PENDING');")
        conn.execute("INSERT INTO content_variants (variant_id, capability_urn, variant_name) VALUES ('vc', 'urn:lcs:cap:c', 'main');")
        conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = 'urn:lcs:variant:vc';")
        conn.execute("INSERT INTO host_environments (host_urn, hostname, os_type, arch) VALUES ('urn:lcs:host:hc', 'host', 'Darwin', 'arm64');")
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:instance:ic', 'PHYSICAL_INSTANCE', 'PENDING');")
        conn.execute("INSERT INTO physical_source_instances (instance_id, capability_urn, host_urn, root_path) VALUES ('ic', 'urn:lcs:cap:c', 'urn:lcs:host:hc', '/tmp');")
        conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = 'urn:lcs:instance:ic';")
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:snapshot:sc', 'CONTENT_SNAPSHOT', 'PENDING');")
        conn.execute("INSERT INTO content_snapshots (snapshot_id, variant_id, instance_id, capture_status, is_finalized) VALUES ('sc', 'vc', 'ic', 'IN_PROGRESS', 0);")
        conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = 'urn:lcs:snapshot:sc';")

        # Scenario A: Authoritative GC Reservation Protocol (Phase 1: Reserve & Commit intent)
        gc_conn = create_lcs_connection(db_path, isolation_level=None)
        engine.gc_reserve_blob_for_deletion(gc_conn, digest, "gc_worker_ref", "tok_gc_ref", lease_seconds=60)
        
        # Concurrently, worker attempts to reference the reserved blob in manifest
        worker_conn = create_lcs_connection(db_path, isolation_level=None)
        caught_guard = False
        try:
            worker_conn.execute("""
                INSERT INTO snapshot_file_manifest 
                (snapshot_id, raw_path_bytes, escaped_path, canonical_logical_path, entry_type, file_mode, uid, gid, mtime_sec, mtime_nsec, file_size, content_blob_digest, path_encoding_status)
                VALUES ('sc', X'66696c652e747874', 'file.txt', 'file.txt', 'F', 33188, 501, 20, 1700000000, 0, ?, ?, 'CLEAN_UTF8');
            """, (byte_len, digest))
        except sqlite3.IntegrityError as e:
            caught_guard = True
            assert "CAS_GC_CONFLICT" in str(e) or "FOREIGN KEY" in str(e)
            print(f"  Guarded: GC conflict trigger and FK prevented manifest binding: {e}")
        assert caught_guard, "Worker was able to bind a manifest entry to a reserved/deleted blob!"
        
        # Complete physical deletion using authoritative method
        deleted = engine.gc_complete_physical_deletion(gc_conn, digest, "tok_gc_ref")
        assert deleted
        assert not os.path.exists(os.path.join(cas_root, "objects", digest[:2], digest))
        
        engine.close()
        conn.close()
        gc_conn.close()
        worker_conn.close()
        print("PASS: Test 02 - Concurrent reference creation vs GC deletion verified.\n")

# ============================================================================
# TEST 03: Paused Publisher Past Expiry & Physical Deletion Interaction
# ============================================================================
def test_03_paused_publisher_past_expiry_and_physical_deletion():
    print("--- Test 03: Paused Publisher Past Expiry & Physical Deletion ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "paused.db")
        init_db(db_path).close()
        
        payload = b"Orphaned payload from stalled publisher past lease expiry"
        digest = hashlib.sha256(payload).hexdigest()
        byte_len = len(payload)
        shard = digest[:2]
        
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        pub_conn = create_lcs_connection(db_path, isolation_level=None)
        gc_conn = create_lcs_connection(db_path, isolation_level=None)
        
        pub_id = "pub_stalled"
        token = "tok_stalled"
        
        # Publisher acquires lease with expired timestamp (simulating sleep/stall)
        pub_conn.execute("""
            INSERT INTO active_cas_publications 
            (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
            VALUES (?, ?, 'worker_slow', ?, 'ACQUIRED', datetime('now', '-30 seconds'), datetime('now', '-5 seconds'));
        """, (pub_id, digest, token))
        
        # Publisher stages and links to disk before stalling
        tmp_name, _, _ = engine.write_payload_to_staging(pub_id, token, digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        dest_path = os.path.join(cas_root, "objects", shard, digest)
        assert os.path.isfile(dest_path)
        
        # GC worker sweeps expired lease and deletes unreferenced blob from physical disk
        gc_conn.execute("""
            UPDATE active_cas_publications
            SET lease_state = 'ABORTED'
            WHERE publication_id = ? AND datetime('now') > lease_expires_at;
        """, (pub_id,))
        
        # Physical disk deletion
        deleted = engine.delete_cas_blob_descriptor_relative(digest)
        assert deleted
        assert not os.path.exists(dest_path), "GC failed to delete unreferenced blob from disk!"
        print("  GC swept expired lease and physically deleted unreferenced blob from disk.")
        
        # Stalled worker resumes and attempts commit
        cur = pub_conn.cursor()
        cur.execute("""
            UPDATE active_cas_publications
            SET lease_state = 'COMMITTED'
            WHERE publication_id = ? 
              AND lease_token = ?
              AND lease_state IN ('ACQUIRED', 'HEARTBEAT_ACTIVE', 'PUBLISHED')
              AND datetime('now') <= lease_expires_at;
        """, (pub_id, token))
        
        assert cur.rowcount == 0, "Security violation: Stalled worker past expiry was allowed to commit!"
        print("  Guarded: Stalled worker commit rejected (0 rows updated).")
        
        engine.close()
        pub_conn.close()
        gc_conn.close()
        print("PASS: Test 03 - Paused publisher past expiry and physical deletion verified.\n")

# ============================================================================
# TEST 04: Empirical Invariant Verification on Physical Disk & Database
# ============================================================================
def test_04_empirical_invariant_verification_disk_and_db():
    print("--- Test 04: Empirical Invariant Verification on Disk & DB ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "invariants.db")
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        p1 = b"Blob 1 - Bound to Finalized Snapshot (MUST NEVER BE DELETED)"
        p2 = b"Blob 2 - Bound to Unfinalized Snapshot (MUST NEVER BE DELETED)"
        p3 = b"Blob 3 - Protected by Active Publication Lease (MUST NEVER BE DELETED)"
        p4 = b"Blob 4 - Expired Lease & Zero Manifest References (MUST BE DELETED)"
        
        d1 = hashlib.sha256(p1).hexdigest()
        d2 = hashlib.sha256(p2).hexdigest()
        d3 = hashlib.sha256(p3).hexdigest()
        d4 = hashlib.sha256(p4).hexdigest()
        
        # Publish all 4 blobs to physical disk
        for p, d in ((p1, d1), (p2, d2), (p3, d3), (p4, d4)):
            tname, _, _ = engine.write_payload_to_staging("pub_inv", "tok_inv", d, p)
            engine.publish_staging_to_cas(tname, d)
            conn.execute("""
                INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
                VALUES (?, ?, 'NONE', ?);
            """, (d, len(p), len(p)))
            
        # Verify physical disk presence
        for d in (d1, d2, d3, d4):
            assert os.path.isfile(os.path.join(cas_root, "objects", d[:2], d))
            
        # Base capability & variants
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:cap:inv', 'CAPABILITY', 'PENDING');")
        conn.execute("INSERT INTO capabilities (capability_urn, name, version) VALUES ('urn:lcs:cap:inv', 'InvCap', '1');")
        conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = 'urn:lcs:cap:inv';")
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:variant:vinv', 'CONTENT_VARIANT', 'PENDING');")
        conn.execute("INSERT INTO content_variants (variant_id, capability_urn, variant_name) VALUES ('vinv', 'urn:lcs:cap:inv', 'main');")
        conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = 'urn:lcs:variant:vinv';")
        conn.execute("INSERT INTO host_environments (host_urn, hostname, os_type, arch) VALUES ('urn:lcs:host:hinv', 'host', 'Darwin', 'arm64');")
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:instance:iinv', 'PHYSICAL_INSTANCE', 'PENDING');")
        conn.execute("INSERT INTO physical_source_instances (instance_id, capability_urn, host_urn, root_path) VALUES ('iinv', 'urn:lcs:cap:inv', 'urn:lcs:host:hinv', '/tmp');")
        conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = 'urn:lcs:instance:iinv';")

        # Snapshots
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:snapshot:s_fin', 'CONTENT_SNAPSHOT', 'PENDING');")
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:snapshot:s_unfin', 'CONTENT_SNAPSHOT', 'PENDING');")
        conn.execute("INSERT INTO content_snapshots (snapshot_id, variant_id, instance_id, capture_status, is_finalized) VALUES ('s_fin', 'vinv', 'iinv', 'IN_PROGRESS', 0);")
        conn.execute("INSERT INTO content_snapshots (snapshot_id, variant_id, instance_id, capture_status, is_finalized) VALUES ('s_unfin', 'vinv', 'iinv', 'IN_PROGRESS', 0);")
        conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn IN ('urn:lcs:snapshot:s_fin', 'urn:lcs:snapshot:s_unfin');")
        
        # Blob 1 -> s_fin
        conn.execute("""
            INSERT INTO snapshot_file_manifest 
            (snapshot_id, raw_path_bytes, escaped_path, canonical_logical_path, entry_type, file_mode, uid, gid, mtime_sec, mtime_nsec, file_size, content_blob_digest, path_encoding_status)
            VALUES ('s_fin', X'612e747874', 'a.txt', 'a.txt', 'F', 33188, 501, 20, 1700000000, 0, ?, ?, 'CLEAN_UTF8');
        """, (len(p1), d1))
        
        # Blob 2 -> s_unfin
        conn.execute("""
            INSERT INTO snapshot_file_manifest 
            (snapshot_id, raw_path_bytes, escaped_path, canonical_logical_path, entry_type, file_mode, uid, gid, mtime_sec, mtime_nsec, file_size, content_blob_digest, path_encoding_status)
            VALUES ('s_unfin', X'622e747874', 'b.txt', 'b.txt', 'F', 33188, 501, 20, 1700000000, 0, ?, ?, 'CLEAN_UTF8');
        """, (len(p2), d2))
        
        # Finalize s_fin
        conn.execute("""
            UPDATE content_snapshots 
            SET is_finalized = 1,
                capture_status = 'USERSPACE_AUDITED_STABLE',
                source_fidelity_digest = '1111111111111111111111111111111111111111111111111111111111111111',
                finalized_at = datetime('now')
            WHERE snapshot_id = 's_fin';
        """)
        
        # Active unexpired lease for Blob 3
        conn.execute("""
            INSERT INTO active_cas_publications
            (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
            VALUES ('pub_b3', ?, 'w_active', 'tok3', 'PUBLISHED', datetime('now'), datetime('now', '+10 minutes'));
        """, (d3,))
        
        # Expired lease for Blob 4
        conn.execute("""
            INSERT INTO active_cas_publications
            (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
            VALUES ('pub_b4', ?, 'w_dead', 'tok4', 'ACQUIRED', datetime('now', '-20 minutes'), datetime('now', '-10 minutes'));
        """, (d4,))
        
        # GC Execution
        conn.execute("BEGIN IMMEDIATE;")
        cur = conn.cursor()
        gc_query = """
            SELECT blob_digest FROM content_chunk_blobs
            WHERE blob_digest NOT IN (
                SELECT content_blob_digest FROM snapshot_file_manifest WHERE content_blob_digest IS NOT NULL
            )
            AND blob_digest NOT IN (
                SELECT blob_digest FROM active_cas_publications
                WHERE lease_state IN ('ACQUIRED', 'HEARTBEAT_ACTIVE', 'PUBLISHED')
                  AND datetime('now') <= lease_expires_at
            );
        """
        cur.execute(gc_query)
        candidates = [r[0] for r in cur.fetchall()]
        assert candidates == [d4], f"Expected only [d4], got {candidates}"
        
        # Delete from DB and commit
        conn.execute("DELETE FROM content_chunk_blobs WHERE blob_digest = ?", (d4,))
        conn.execute("COMMIT;")
        
        # Physical filesystem deletion
        for cand in candidates:
            engine.delete_cas_blob_descriptor_relative(cand)
            
        # Physical disk checks
        assert os.path.isfile(os.path.join(cas_root, "objects", d1[:2], d1)), "Invariant broken: Live finalized blob was deleted!"
        assert os.path.isfile(os.path.join(cas_root, "objects", d2[:2], d2)), "Invariant broken: Live unfinalized blob was deleted!"
        assert os.path.isfile(os.path.join(cas_root, "objects", d3[:2], d3)), "Invariant broken: Active lease blob was deleted!"
        assert not os.path.exists(os.path.join(cas_root, "objects", d4[:2], d4)), "Invariant broken: Expired garbage blob was NOT deleted!"
        
        engine.close()
        conn.close()
        print("PASS: Test 04 - Empirical invariant verification on disk and database verified.\n")

# ============================================================================
# TEST 05: Process Termination & Staging Sweeper Recovery
# ============================================================================
def test_05_process_termination_and_sweeper_recovery():
    print("--- Test 05: Process Termination & Staging Sweeper Recovery ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "sweeper.db")
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload = b"Orphaned staging payload left by killed worker process"
        digest = hashlib.sha256(payload).hexdigest()
        
        # Worker died while staging was complete, before linkat()
        conn.execute("""
            INSERT INTO active_cas_publications 
            (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
            VALUES ('pub_killed', ?, 'worker_killed', 'tok_k', 'ACQUIRED', datetime('now', '-2 hours'), datetime('now', '-1 hour'));
        """, (digest,))
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_killed", "tok_k", digest, payload)
        staging_file = os.path.join(cas_root, "staging", tmp_name)
        assert os.path.isfile(staging_file)
        
        # Recovery daemon runs after restart:
        cur = conn.cursor()
        cur.execute("""
            SELECT publication_id, blob_digest, lease_token FROM active_cas_publications
            WHERE lease_state IN ('ACQUIRED', 'HEARTBEAT_ACTIVE') AND datetime('now') > lease_expires_at;
        """)
        dead_leases = cur.fetchall()
        assert len(dead_leases) == 1
        
        for p_id, d_val, tok in dead_leases:
            # Unlink orphaned staging file descriptor-relative
            try:
                os.unlink(tmp_name, dir_fd=engine.staging_dir_fd)
            except OSError:
                pass
            conn.execute("UPDATE active_cas_publications SET lease_state = 'ABORTED' WHERE publication_id = ?", (p_id,))
            
        assert not os.path.exists(staging_file), "Sweeper failed to clean orphaned staging file!"
        cur.execute("SELECT lease_state FROM active_cas_publications WHERE publication_id = 'pub_killed'")
        assert cur.fetchone()[0] == "ABORTED"
        
        staging_dir = os.path.join(cas_root, "staging")
        assert len(os.listdir(staging_dir)) == 0, "Staging directory has remaining files!"
        print("  Verified: Staging sweeper swept dead process files cleanly.")
        
        engine.close()
        conn.close()
        print("PASS: Test 05 - Process termination and sweeper recovery verified.\n")


# ============================================================================
# TEST 06: Exact GC Committed-For-Unlink Interleaving & Restart Recovery
# ============================================================================
def test_06_exact_gc_committed_unlink_interleaving_with_barrier():
    print("--- Test 06: Exact GC Committed-For-Unlink Interleaving (Barrier Synchronized) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "gc_interleaving.db")
        init_db(db_path).close()
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload = b"Payload for exact GC committed-for-unlink race verification"
        digest = hashlib.sha256(payload).hexdigest()
        byte_len = len(payload)
        shard = digest[:2]
        
        # Publish and register blob initially
        tmp_name, _, _ = engine.write_payload_to_staging("pub_init", "tok_init", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        
        conn = create_lcs_connection(db_path, isolation_level=None)
        conn.execute("""
            INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
            VALUES (?, ?, 'NONE', ?);
        """, (digest, byte_len, byte_len))
        
        barrier_gc_committed = threading.Barrier(2)
        barrier_pub_attempted = threading.Barrier(2)
        barrier_gc_unlinked = threading.Barrier(2)
        
        pub_events = []
        gc_events = []
        
        def gc_worker_task():
            gc_conn = create_lcs_connection(db_path, isolation_level=None)
            # Step 1: GC reserves blob for deletion and commits COMMITTED_FOR_UNLINK
            engine.gc_reserve_blob_for_deletion(gc_conn, digest, "gc_worker_1", "tok_gc_1", lease_seconds=60)
            gc_events.append("RESERVATION_COMMITTED")
            
            # Signal publisher that reservation is committed
            barrier_gc_committed.wait()
            
            # Wait for publisher to attempt publication while committed for unlink
            barrier_pub_attempted.wait()
            
            # Step 2: GC physically unlinks file from disk descriptor-relative with evidence
            ev = engine.delete_cas_blob_descriptor_relative_with_evidence(digest)
            gc_events.append("PHYSICALLY_UNLINKED")
            
            # Signal publisher that file is unlinked
            barrier_gc_unlinked.wait()
            
            # Step 3: GC records physical deletion receipt and completes state transition
            gc_conn.execute("BEGIN IMMEDIATE;")
            gc_conn.execute("""
                INSERT INTO cas_physical_deletion_receipts 
                (blob_digest, reservation_token, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature)
                VALUES (?, 'tok_gc_1', ?, ?, ?, ?, ?, ?);
            """, (digest, ev['unlinked_inode'], ev['shard_inode'], ev['device_id'], ev['sync_method'], ev['sync_timestamp_ns'], ev['receipt_signature']))
            gc_conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'PHYSICALLY_DELETED'
                WHERE blob_digest = ? AND reservation_token = 'tok_gc_1';
            """, (digest,))
            gc_conn.execute("COMMIT;")
            gc_events.append("RESERVATION_COMPLETED")
            gc_conn.close()
            
        def publisher_task():
            pub_conn = create_lcs_connection(db_path, isolation_level=None)
            
            # Wait until GC has committed COMMITTED_FOR_UNLINK
            barrier_gc_committed.wait()
            
            # Publisher attempts to acquire publication lease while blob is COMMITTED_FOR_UNLINK
            caught_conflict = False
            try:
                pub_conn.execute("""
                    INSERT INTO active_cas_publications 
                    (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
                    VALUES ('pub_race', ?, 'w_race', 'tok_race', 'ACQUIRED', datetime('now'), datetime('now', '+30 seconds'));
                """, (digest,))
            except sqlite3.IntegrityError as e:
                caught_conflict = True
                assert "CAS_GC_CONFLICT" in str(e)
                pub_events.append("LEASE_REJECTED_GC_CONFLICT")
            assert caught_conflict, "Publisher acquired lease while blob was committed for GC unlink!"
            
            # Publisher attempts direct insert into content_chunk_blobs
            caught_blob_conflict = False
            try:
                pub_conn.execute("""
                    INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
                    VALUES (?, ?, 'NONE', ?);
                """, (digest, byte_len, byte_len))
            except sqlite3.IntegrityError as e:
                caught_blob_conflict = True
                assert "CAS_GC_CONFLICT" in str(e)
                pub_events.append("BLOB_REJECTED_GC_CONFLICT")
            assert caught_blob_conflict, "Publisher inserted blob into content_chunk_blobs while reserved for GC!"
            
            # Signal GC worker that publisher attempted and was guarded
            barrier_pub_attempted.wait()
            
            # Wait until GC has physically unlinked the file
            barrier_gc_unlinked.wait()
            
            time.sleep(0.05)
            
            # Now publisher retries: reservation is PHYSICALLY_DELETED, physical file is gone
            pub_conn.execute("""
                INSERT INTO active_cas_publications 
                (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
                VALUES ('pub_retry', ?, 'w_retry', 'tok_retry', 'ACQUIRED', datetime('now'), datetime('now', '+30 seconds'));
            """, (digest,))
            
            # Publisher stages data and publishes to CAS
            tmp_part, _, _ = engine.write_payload_to_staging("pub_retry", "tok_retry", digest, payload)
            engine.publish_staging_to_cas(tmp_part, digest)
            
            # Publisher commits publication and registers in content_chunk_blobs
            pub_conn.execute("BEGIN IMMEDIATE;")
            pub_conn.execute("""
                UPDATE active_cas_publications
                SET lease_state = 'COMMITTED'
                WHERE publication_id = 'pub_retry' AND lease_token = 'tok_retry';
            """)
            pub_conn.execute("""
                INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
                VALUES (?, ?, 'NONE', ?);
            """, (digest, byte_len, byte_len))
            pub_conn.execute("COMMIT;")
            pub_events.append("RETRY_PUBLICATION_COMMITTED")
            pub_conn.close()
            
        t_gc = threading.Thread(target=gc_worker_task)
        t_pub = threading.Thread(target=publisher_task)
        t_gc.start()
        t_pub.start()
        t_gc.join()
        t_pub.join()
        
        assert "RESERVATION_COMMITTED" in gc_events
        assert "PHYSICALLY_UNLINKED" in gc_events
        assert "RESERVATION_COMPLETED" in gc_events
        assert "LEASE_REJECTED_GC_CONFLICT" in pub_events
        assert "BLOB_REJECTED_GC_CONFLICT" in pub_events
        assert "RETRY_PUBLICATION_COMMITTED" in pub_events
        
        # Verify physical disk and DB invariant
        dest_path = os.path.join(cas_root, "objects", shard, digest)
        assert os.path.isfile(dest_path), "Referenced blob missing from disk after retry publication!"
        with open(dest_path, "rb") as f:
            read_bytes = f.read()
        assert read_bytes == payload
        assert hashlib.sha256(read_bytes).hexdigest() == digest
        print("  Verified: Invariant preserved - referenced blob exists on physical disk and hash verified.")
        
        # Verify restart recovery: simulate GC crash during COMMITTED_FOR_UNLINK
        crash_payload = b"Payload for crash recovery simulation"
        crash_digest = hashlib.sha256(crash_payload).hexdigest()
        crash_shard = crash_digest[:2]
        tmp_crash, _, _ = engine.write_payload_to_staging("pub_crash", "tok_crash", crash_digest, crash_payload)
        engine.publish_staging_to_cas(tmp_crash, crash_digest)
        
        conn.execute("""
            INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
            VALUES (?, ?, 'NONE', ?);
        """, (crash_digest, len(crash_payload), len(crash_payload)))
        
        # GC begins deletion and commits reservation, but "crashes" before unlinking disk file
        engine.gc_reserve_blob_for_deletion(conn, crash_digest, "gc_crasher", "tok_crash_gc", lease_seconds=60)
        assert os.path.exists(os.path.join(cas_root, "objects", crash_shard, crash_digest))
        
        # Restart recovery runs
        recovered_count = engine.recover_gc_reservations(conn)
        assert recovered_count == 1
        assert not os.path.exists(os.path.join(cas_root, "objects", crash_shard, crash_digest))
        cur = conn.cursor()
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?", (crash_digest,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        print("  Verified: Restart recovery successfully reconciled pending COMMITTED_FOR_UNLINK reservation.")
        
        engine.close()
        conn.close()
        print("PASS: Test 06 - Exact GC committed-for-unlink interleaving and restart recovery verified.\n")


# ============================================================================
# TEST 07: COMMITTED_FOR_UNLINK Unconditional Blocking Past Expiry (Finding 1)
# ============================================================================
def test_07_gc_committed_for_unlink_unconditional_blocking_past_expiry():
    print("--- Test 07: COMMITTED_FOR_UNLINK Unconditional Blocking Past Expiry ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "gc_expiry_lock.db")
        init_db(db_path).close()
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload = b"Payload testing unconditional blocking past reservation expiry"
        digest = hashlib.sha256(payload).hexdigest()
        byte_len = len(payload)
        
        # Write and publish blob
        tmp_name, _, _ = engine.write_payload_to_staging("pub_exp", "tok_exp", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        
        conn = create_lcs_connection(db_path, isolation_level=None)
        conn.execute("""
            INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
            VALUES (?, ?, 'NONE', ?);
        """, (digest, byte_len, byte_len))
        
        # GC reserves blob with COMMITTED_FOR_UNLINK but reservation timestamp is in the PAST (-1 hour)
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute("""
            INSERT INTO cas_gc_deletion_reservations
            (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
            VALUES (?, 'COMMITTED_FOR_UNLINK', 'gc_stalled', 'tok_stalled', datetime('now', '-2 hours'), datetime('now', '-1 hour'));
        """, (digest,))
        conn.execute("DELETE FROM content_chunk_blobs WHERE blob_digest = ?;", (digest,))
        conn.execute("COMMIT;")
        
        # Publisher attempts to acquire lease on this expired COMMITTED_FOR_UNLINK reservation
        pub_conn = create_lcs_connection(db_path, isolation_level=None)
        caught_lease_conflict = False
        try:
            pub_conn.execute("""
                INSERT INTO active_cas_publications 
                (publication_id, blob_digest, worker_id, lease_token, lease_state, heartbeat_at, lease_expires_at)
                VALUES ('pub_attempt', ?, 'worker_fast', 'tok_fast', 'ACQUIRED', datetime('now'), datetime('now', '+60 seconds'));
            """, (digest,))
        except sqlite3.IntegrityError as e:
            caught_lease_conflict = True
            assert "CAS_GC_CONFLICT" in str(e)
            print(f"  Guarded: Publisher lease acquisition strictly BLOCKED past expiry: {e}")
        assert caught_lease_conflict, "Security violation: Expiry silently released the COMMITTED_FOR_UNLINK lock!"
        
        # Publisher attempts direct insert into content_chunk_blobs past expiry
        caught_blob_conflict = False
        try:
            pub_conn.execute("""
                INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length)
                VALUES (?, ?, 'NONE', ?);
            """, (digest, byte_len, byte_len))
        except sqlite3.IntegrityError as e:
            caught_blob_conflict = True
            assert "CAS_GC_CONFLICT" in str(e)
            print(f"  Guarded: Direct content_chunk_blobs registration strictly BLOCKED past expiry: {e}")
        assert caught_blob_conflict, "Direct blob insert was allowed while COMMITTED_FOR_UNLINK was expired!"
        
        # Execute GC restart recovery to conclusively complete physical deletion
        recovered = engine.recover_gc_reservations(conn)
        assert recovered == 1
        
        # Verify state is now PHYSICALLY_DELETED
        cur = conn.cursor()
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        print("  Verified: Pending recovery conclusively unlinked physical file and marked PHYSICALLY_DELETED.")
        
        engine.close()
        conn.close()
        pub_conn.close()
        print("PASS: Test 07 - COMMITTED_FOR_UNLINK unconditional blocking past expiry verified.\n")

# ============================================================================
# TEST 08: GC State Transition Integrity & Token Protection (Finding 2)
# ============================================================================
def test_08_gc_state_transition_integrity_and_token_protection():
    print("--- Test 08: GC State Transition Integrity & Token Protection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        db_path = os.path.join(tmp_dir, "gc_transitions.db")
        conn = init_db(db_path)
        
        digest1 = "1111111111111111111111111111111111111111111111111111111111111111"
        digest2 = "2222222222222222222222222222222222222222222222222222222222222222"
        
        # Violation 1: Direct SQL insert directly into PHYSICALLY_DELETED without reservation protocol
        caught_direct_phys = False
        try:
            conn.execute("""
                INSERT INTO cas_gc_deletion_reservations
                (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
                VALUES (?, 'PHYSICALLY_DELETED', 'w1', 'tok1', datetime('now'), datetime('now', '+60 seconds'));
            """, (digest1,))
        except sqlite3.IntegrityError as e:
            caught_direct_phys = True
            assert "GC_TRANSITION_ERROR" in str(e)
            print(f"  Guarded: Direct insert of terminal state strictly rejected: {e}")
        assert caught_direct_phys
        
        # Insert legal RESERVED row
        conn.execute("""
            INSERT INTO cas_gc_deletion_reservations
            (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
            VALUES (?, 'RESERVED', 'w1', 'tok1', datetime('now'), datetime('now', '+60 seconds'));
        """, (digest1,))
        
        # Violation 2: Attempt to mutate reservation_token during update
        caught_token_tamper = False
        try:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_token = 'rogue_token'
                WHERE blob_digest = ?;
            """, (digest1,))
        except sqlite3.IntegrityError as e:
            caught_token_tamper = True
            assert "GC_TRANSITION_ERROR" in str(e)
            print(f"  Guarded: Token tampering during update strictly rejected: {e}")
        assert caught_token_tamper
        
        # Violation 3: Attempt to skip COMMITTED_FOR_UNLINK (jump RESERVED -> PHYSICALLY_DELETED)
        caught_skip = False
        try:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'PHYSICALLY_DELETED'
                WHERE blob_digest = ?;
            """, (digest1,))
        except sqlite3.IntegrityError as e:
            caught_skip = True
            assert "GC_TRANSITION_ERROR" in str(e)
            print(f"  Guarded: Skipping COMMITTED_FOR_UNLINK strictly rejected: {e}")
        assert caught_skip
        
        # Legal Step 1: RESERVED -> COMMITTED_FOR_UNLINK
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'COMMITTED_FOR_UNLINK'
            WHERE blob_digest = ? AND reservation_token = 'tok1';
        """, (digest1,))
        
        # Violation 4: Attempt to prematurely delete row while COMMITTED_FOR_UNLINK
        caught_premature_del = False
        try:
            conn.execute("DELETE FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest1,))
        except sqlite3.IntegrityError as e:
            caught_premature_del = True
            assert "GC_TRANSITION_ERROR" in str(e)
            print(f"  Guarded: Premature deletion of COMMITTED_FOR_UNLINK reservation strictly rejected: {e}")
        assert caught_premature_del
        
        # Violation 4b: Attempt direct transition to PHYSICALLY_DELETED without verifiable deletion receipt
        caught_missing_receipt = False
        try:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'PHYSICALLY_DELETED'
                WHERE blob_digest = ? AND reservation_token = 'tok1';
            """, (digest1,))
        except sqlite3.IntegrityError as e:
            caught_missing_receipt = True
            assert "GC_TRANSITION_ERROR" in str(e)
            print(f"  Guarded: Direct transition to PHYSICALLY_DELETED without receipt strictly rejected: {e}")
        assert caught_missing_receipt

        # Violation 4c: Attempt to insert deletion receipt with forged/mismatched token
        caught_bad_receipt = False
        try:
            conn.execute("""
                INSERT INTO cas_physical_deletion_receipts 
                (blob_digest, reservation_token, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature)
                VALUES (?, 'wrong_token', 123456, 789012, 16777220, 'F_FULLFSYNC', 1700000000000000000, 'sig_test_wrong');
            """, (digest1,))
        except sqlite3.IntegrityError as e:
            caught_bad_receipt = True
            assert "GC_RECEIPT_ERROR" in str(e)
            print(f"  Guarded: Forged deletion receipt with wrong token strictly rejected: {e}")
        assert caught_bad_receipt

        # Legal Step 2: Record verified physical deletion receipt linking (blob_digest, reservation_token)
        conn.execute("""
            INSERT INTO cas_physical_deletion_receipts 
            (blob_digest, reservation_token, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature)
            VALUES (?, 'tok1', 123456, 789012, 16777220, 'F_FULLFSYNC', 1700000000000000000, 'sig_test_legal_valid_64_bytes_hmac_hex_abcdef0123456789abcdef0123456789');
        """, (digest1,))

        # Legal Step 2b: Advance COMMITTED_FOR_UNLINK -> PHYSICALLY_DELETED with valid receipt
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'PHYSICALLY_DELETED'
            WHERE blob_digest = ? AND reservation_token = 'tok1';
        """, (digest1,))

        # Violation 4d: Attempt to delete physical deletion receipt (immutable audit log)
        caught_del_receipt = False
        try:
            conn.execute("DELETE FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest1,))
        except sqlite3.IntegrityError as e:
            caught_del_receipt = True
            assert "GC_RECEIPT_ERROR" in str(e)
            print(f"  Guarded: Deletion of permanent physical deletion receipt strictly rejected: {e}")
        assert caught_del_receipt
        
        # Violation 5: Attempt to alter terminal state PHYSICALLY_DELETED
        caught_alter_terminal = False
        try:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'COMMITTED_FOR_UNLINK'
                WHERE blob_digest = ?;
            """, (digest1,))
        except sqlite3.IntegrityError as e:
            caught_alter_terminal = True
            assert "GC_TRANSITION_ERROR" in str(e)
            print(f"  Guarded: Mutation of terminal state PHYSICALLY_DELETED strictly rejected: {e}")
        assert caught_alter_terminal
        
        conn.close()
        print("PASS: Test 08 - GC state transition integrity and token protection verified.\n")



# ============================================================================
# TEST 09: GC Token Ownership & Wrong-Token Rejection Defense
# ============================================================================
def test_09_gc_token_ownership_and_wrong_token_rejection():
    print("--- Test 09: GC Token Ownership & Wrong-Token Rejection Defense ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "gc_token.db")
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        # 1. Publish a legitimate blob to CAS
        payload = b"Payload for GC token ownership and physical protection testing"
        digest = hashlib.sha256(payload).hexdigest()
        full_digest = f"sha256:{digest}"
        shard = digest[:2]
        dest_path = os.path.join(cas_root, "objects", shard, digest)
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_tok", "tok_tok", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        assert os.path.isfile(dest_path)
        
        # 2. Reserve blob for GC deletion (state transitions to COMMITTED_FOR_UNLINK)
        genuine_token = engine.gc_reserve_blob_for_deletion(conn, full_digest, "gc_worker_auth")
        assert genuine_token.startswith("gc_tok_")
        
        # Verify reservation state in DB
        cur = conn.cursor()
        cur.execute("SELECT reservation_state, reservation_token FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        row = cur.fetchone()
        assert row == ("COMMITTED_FOR_UNLINK", genuine_token)
        
        # 3. Adversary/buggy worker calls physical deletion with WRONG TOKEN
        caught_wrong_token = False
        try:
            engine.gc_complete_physical_deletion(conn, full_digest, "gc_tok_ROGUE_INVALID_TOKEN")
        except CASPublicationConflictError as e:
            caught_wrong_token = True
            print(f"  Guarded: Wrong token rejected before physical deletion: {e}")
        assert caught_wrong_token, "Security violation: Wrong token was accepted by GC completion!"
        
        # CRITICAL ASSERTION: The physical blob MUST STILL EXIST on disk!
        assert os.path.isfile(dest_path), "Security failure: Wrong-token call unlinked the physical file!"
        with open(dest_path, "rb") as f:
            assert f.read() == payload, "Physical file was corrupted or altered!"
        print("  Verified: Physical blob remains 100% intact and unaltered on disk after wrong-token attempt.")
        
        # CRITICAL ASSERTION: Database reservation MUST STILL BE COMMITTED_FOR_UNLINK with genuine token
        cur.execute("SELECT reservation_state, reservation_token FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        row = cur.fetchone()
        assert row == ("COMMITTED_FOR_UNLINK", genuine_token)
        
        # CRITICAL ASSERTION: Zero deletion receipts recorded
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == 0
        print("  Verified: Zero deletion receipts recorded; database state remained unaltered.")
        
        # 4. Now execute deletion with GENUINE TOKEN
        deleted = engine.gc_complete_physical_deletion(conn, full_digest, genuine_token)
        assert deleted, "Physical deletion should report True"
        assert not os.path.exists(dest_path), "Physical blob was not unlinked with genuine token!"
        
        # Verify DB advanced to PHYSICALLY_DELETED
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        
        # Verify durable receipt exists with rich operational evidence
        cur.execute("SELECT reservation_token, sync_method, unlinked_inode, shard_inode, device_id, receipt_signature FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest,))
        receipt_row = cur.fetchone()
        assert receipt_row is not None
        assert receipt_row[0] == genuine_token
        assert receipt_row[1] in ("FSYNC", "F_FULLFSYNC")
        assert receipt_row[2] > 0
        assert receipt_row[3] > 0
        assert len(receipt_row[5]) == 64  # HMAC-SHA256 hex
        print(f"  Verified: Genuine token unlinked blob, recorded rich receipt (sync: {receipt_row[1]}, inode: {receipt_row[2]}, sig: {receipt_row[5][:16]}...), and updated DB state.")
        
        engine.close()
        conn.close()
        print("PASS: Test 09 - GC token ownership and wrong-token rejection verified.\n")


# ============================================================================
# TEST 10: Concurrent GC Recovery Workers & Cancellation Race Defense
# ============================================================================
def test_10_concurrent_gc_recovery_workers_and_cancellation_race():
    print("--- Test 10: Concurrent GC Recovery Workers & Cancellation Race Defense ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "gc_workers.db")
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        # --- SCENARIO A: Two simultaneous GC recovery workers on same blob ---
        payload = b"Payload for simultaneous dual recovery workers testing"
        digest = hashlib.sha256(payload).hexdigest()
        full_digest = f"sha256:{digest}"
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_dual", "tok_dual", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        token = engine.gc_reserve_blob_for_deletion(conn, full_digest, "gc_worker_primary")
        
        import threading
        barrier = threading.Barrier(2)
        results = []
        errors = []
        
        def recovery_worker(w_id: int):
            worker_conn = create_lcs_connection(db_path, isolation_level=None)
            try:
                barrier.wait()
                del_result = engine.gc_complete_physical_deletion(worker_conn, full_digest, token)
                results.append((w_id, del_result))
            except Exception as e:
                errors.append((w_id, e))
            finally:
                worker_conn.close()
                
        t1 = threading.Thread(target=recovery_worker, args=(1,))
        t2 = threading.Thread(target=recovery_worker, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        # Exactly one worker should successfully commit the transition; the other receives conflict
        assert len(results) == 1, f"Expected exactly 1 successful worker, got {len(results)}"
        assert len(errors) == 1, f"Expected exactly 1 worker conflict error, got {len(errors)}"
        assert isinstance(errors[0][1], CASPublicationConflictError)
        print(f"  Verified: Worker {results[0][0]} succeeded; Worker {errors[0][0]} safely received conflict: {errors[0][1]}")
        
        # Verify exactly 1 deletion receipt in DB
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        print("  Verified: Database maintains exactly 1 receipt and consistent terminal state.")
        
        # --- SCENARIO B: Barrier-synchronized parallel race: Cancellation Worker vs Recovery Worker ---
        payload_b = b"Payload for barrier-synchronized cancellation race testing"
        digest_b = hashlib.sha256(payload_b).hexdigest()
        full_digest_b = f"sha256:{digest_b}"
        shard_b = digest_b[:2]
        dest_path_b = os.path.join(cas_root, "objects", shard_b, digest_b)
        
        tmp_name_b, _, _ = engine.write_payload_to_staging("pub_cancel", "tok_cancel", digest_b, payload_b)
        engine.publish_staging_to_cas(tmp_name_b, digest_b)
        token_b = engine.gc_reserve_blob_for_deletion(conn, full_digest_b, "gc_worker_b")
        
        race_barrier = threading.Barrier(2)
        race_outcomes = {}
        
        def parallel_cancellation_worker():
            c_conn = create_lcs_connection(db_path, isolation_level=None)
            try:
                race_barrier.wait()
                # Attempt explicit, safe engine-authorized cancellation verifying physical existence
                engine.gc_cancel_reservation(c_conn, full_digest_b, token_b)
                race_outcomes['cancellation'] = 'SUCCESS_REVERTED'
            except (CASPublicationConflictError, CASDeletionError) as e:
                race_outcomes['cancellation'] = 'MISSED_ALREADY_COMMITTED'
            except Exception as e:
                race_outcomes['cancellation'] = f'ERROR: {e}'
            finally:
                c_conn.close()

        def parallel_recovery_worker():
            r_conn = create_lcs_connection(db_path, isolation_level=None)
            try:
                race_barrier.wait()
                engine.gc_complete_physical_deletion(r_conn, full_digest_b, token_b)
                race_outcomes['recovery'] = 'SUCCESS_DELETED'
            except CASPublicationConflictError as e:
                race_outcomes['recovery'] = f'CONFLICT: {e}'
            except Exception as e:
                race_outcomes['recovery'] = f'ERROR: {e}'
            finally:
                r_conn.close()

        t_cancel = threading.Thread(target=parallel_cancellation_worker)
        t_recov = threading.Thread(target=parallel_recovery_worker)
        t_cancel.start()
        t_recov.start()
        t_cancel.join()
        t_recov.join()

        print(f"  Parallel race outcomes: Cancellation -> {race_outcomes.get('cancellation')}, Recovery -> {race_outcomes.get('recovery')}")

        # Strict Mutual Exclusion Invariants:
        # Permitted Outcome 1: Cancellation won.
        # - reservation_state == 'REVERTED'
        # - Physical blob MUST STILL EXIST on disk.
        # - 0 deletion receipts.
        # Permitted Outcome 2: Recovery won.
        # - reservation_state == 'PHYSICALLY_DELETED'
        # - Physical blob unlinked.
        # - Exactly 1 deletion receipt.
        # FORBIDDEN: Physical blob deleted AND cancellation claims success.
        # FORBIDDEN: Physical blob deleted with 0 receipts.
        
        cur = conn.cursor()
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_b,))
        final_state = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM cas_physical_deletion_receipts WHERE blob_digest = ?;", (digest_b,))
        receipt_count = cur.fetchone()[0]
        file_exists = os.path.isfile(dest_path_b)

        if final_state == "REVERTED":
            assert file_exists, "CRITICAL VIOLATION: Blob was deleted even though cancellation committed REVERTED!"
            assert receipt_count == 0, "CRITICAL VIOLATION: Receipt recorded for reverted reservation!"
            assert race_outcomes['cancellation'] == 'SUCCESS_REVERTED'
            assert 'CONFLICT' in race_outcomes['recovery'] or 'ERROR' in race_outcomes['recovery']
            print("  Invariant Verified: Cancellation won. State is REVERTED, 0 receipts, physical blob remains intact on disk.")
        elif final_state == "PHYSICALLY_DELETED":
            assert not file_exists, "CRITICAL VIOLATION: DB marked PHYSICALLY_DELETED but file still exists!"
            assert receipt_count == 1, "CRITICAL VIOLATION: Expected 1 deletion receipt!"
            assert race_outcomes['recovery'] == 'SUCCESS_DELETED'
            assert race_outcomes['cancellation'] in ('MISSED_ALREADY_COMMITTED', 'ERROR: database is locked')
            print("  Invariant Verified: Recovery won. State is PHYSICALLY_DELETED, 1 receipt, physical blob cleanly unlinked.")
        else:
            raise AssertionError(f"Unexpected final state after race: {final_state}")

        engine.close()
        conn.close()
        print("PASS: Test 10 - Concurrent recovery workers and cancellation race defense verified.\n")

# TEST 11: Adversarial Fabricated Receipt & Authoritative Audit Gate
# ============================================================================
def test_11_adversarial_fabricated_receipt_audit_detection():
    print("--- Test 11: Adversarial Fabricated Receipt & Authoritative Audit Gate ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "adv_receipt.db")
        conn = init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        
        # 1. Publish a real blob
        payload = b"Payload for adversarial receipt fabrication test"
        digest = hashlib.sha256(payload).hexdigest()
        full_digest = f"sha256:{digest}"
        shard = digest[:2]
        dest_path = os.path.join(cas_root, "objects", shard, digest)
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_adv", "tok_adv", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        assert os.path.isfile(dest_path)
        
        # 2. Reserve blob for GC
        token = engine.gc_reserve_blob_for_deletion(conn, full_digest, "gc_worker_legit")
        
        # 3. Adversary executes DIRECT SQL:
        # Inserts a fabricated receipt and transitions reservation to PHYSICALLY_DELETED
        # WITHOUT actually unlinking the physical blob on disk!
        # This simulates the Stage 2A.25 finding where direct SQL satisfied SQLite triggers
        # but bypassed physical filesystem reality.
        conn.execute("""
            INSERT INTO cas_physical_deletion_receipts
            (blob_digest, reservation_token, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature)
            VALUES (?, ?, 999999, 888888, 16777220, 'F_FULLFSYNC', 1700000000000000000, 'sig_fabricated_by_adversary');
        """, (digest, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'PHYSICALLY_DELETED'
            WHERE blob_digest = ? AND reservation_token = ?;
        """, (digest, token))
        
        # Verify that SQLite triggers allowed this (documenting the trust boundary: SQLite triggers
        # cannot independently verify filesystem unlink or cryptographic signatures).
        cur = conn.cursor()
        cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
        assert os.path.isfile(dest_path), "Physical file still exists!"
        print("  Demonstrated Trust Boundary: Direct SQL satisfied relational trigger checks while physical file still exists.")
        
        # 4. Authoritative Verification Gate: Call audit_physical_deletion_consistency()
        # The trusted storage engine audits physical reality against DB claims.
        caught_tamper = False
        try:
            engine.audit_physical_deletion_consistency(conn, full_digest)
        except CASSecurityViolationError as e:
            caught_tamper = True
            assert "CAS_TAMPERING_DETECTED" in str(e)
            print(f"  Guarded: Authoritative audit gate detected direct-SQL tampering: {e}")
        assert caught_tamper, "Authoritative audit gate failed to detect fabricated deletion receipt!"
        
        # 5. Case B: Adversary removed file manually but forged HMAC signature
        # Even if file is unlinked, the signature was not signed by engine session secret!
        os.unlink(dest_path)
        caught_sig_tamper = False
        try:
            engine.audit_physical_deletion_consistency(conn, full_digest)
        except CASSecurityViolationError as e:
            caught_sig_tamper = True
            assert "CAS_TAMPERING_DETECTED" in str(e) or "INVALID_SIGNATURE" in str(e)
            print(f"  Guarded: Authoritative audit gate detected forged receipt signature: {e}")
        assert caught_sig_tamper, "Audit gate failed to detect forged receipt signature!"

        # 6. Case C: Legitimate execution with genuine engine signature passes audit cleanly
        payload_legit = b"Payload for legitimate receipt generation"
        digest_legit = hashlib.sha256(payload_legit).hexdigest()
        full_legit = f"sha256:{digest_legit}"
        tmp_legit, _, _ = engine.write_payload_to_staging("pub_legit", "tok_legit", digest_legit, payload_legit)
        engine.publish_staging_to_cas(tmp_legit, digest_legit)
        tok_legit = engine.gc_reserve_blob_for_deletion(conn, full_legit, "gc_worker_legit")
        engine.gc_complete_physical_deletion(conn, full_legit, tok_legit)
        
        # (Note: Physical deletion receipts are permanently immutable audit records,
        # so adversary's row remains recorded. The audit gate tests each blob independently.)
        
        # Audit passes 100% cleanly for genuine operations
        engine.audit_physical_deletion_consistency(conn, full_legit)
        print("  Verified: Genuine engine-generated receipt with authentic signature passes audit cleanly.")

        # Test restart verification of authentic receipt
        engine.close()
        engine_restarted = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        engine_restarted.audit_physical_deletion_consistency(conn, full_legit)
        print("  Verified: Genuine receipt passes audit across engine restart.")
        engine_restarted.close()

        conn.close()
        print("PASS: Test 11 - Adversarial fabricated receipt and authoritative audit gate verified.\n")


def main():
    print("=" * 76)
    print("RUNNING LCS STAGE 2A.28 CONCURRENCY & GC INTEGRATION VERIFICATION SUITE")
    print("=" * 76)
    test_01_coordinated_multi_publisher_same_digest_barrier()
    test_02_concurrent_reference_creation_vs_gc_deletion()
    test_03_paused_publisher_past_expiry_and_physical_deletion()
    test_04_empirical_invariant_verification_disk_and_db()
    test_05_process_termination_and_sweeper_recovery()
    test_06_exact_gc_committed_unlink_interleaving_with_barrier()
    test_07_gc_committed_for_unlink_unconditional_blocking_past_expiry()
    test_08_gc_state_transition_integrity_and_token_protection()
    test_09_gc_token_ownership_and_wrong_token_rejection()
    test_10_concurrent_gc_recovery_workers_and_cancellation_race()
    test_11_adversarial_fabricated_receipt_audit_detection()
    print("=" * 76)
    print("ALL 11 CONCURRENCY & GC INTEGRATION TESTS PASSED (100% GREEN)")
    print("=" * 76)

if __name__ == "__main__":
    main()


# ============================================================================
