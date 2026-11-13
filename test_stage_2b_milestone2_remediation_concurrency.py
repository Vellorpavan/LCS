#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 2 Remediation & Concurrency Verification Suite
======================================================================
Authoritatively tests:
1. SQLite foreign-key enforcement contract in CapabilityRegistrationService:
   - Default fresh connection (PRAGMA foreign_keys = ON automatically enabled and verified).
   - Already-enabled connection.
   - Active uncommitted transaction detection (fails closed with SQLiteForeignKeyEnforcementError).
   - Actual foreign-key violation rejection (INSERT & ON DELETE RESTRICT).
2. Concurrency verification across separate processes and connections:
   - Concurrent identical registrations (idempotency, zero duplicate records).
   - Concurrent conflicting registrations (one succeeds, one raises conflict, zero overwrite).
   - Registration racing with GC deletion (active publication lease blocks GC via trigger).
   - GC reservation racing before registration (CASPublicationConflictError).
   - Final database and CAS consistency across all races.
"""

import os
import sys
import time
import stat
import uuid
import hashlib
import sqlite3
import tempfile
import multiprocessing
from typing import Dict, Any, Tuple

from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    CASBlobNotFoundError,
    CASPublicationConflictError,
    CASSecurityViolationError
)
from capability_registry_v2b import (
    CapabilityDefinition,
    CapabilityRegistrationService,
    RegistrationResult,
    SQLiteForeignKeyEnforcementError,
    CapabilityRegistrationConflictError,
    CapabilityNotFoundError,
    EVAL_ADD_CAPABILITY_DEF
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

# ----------------------------------------------------------------------------
# Top-Level Multiprocessing Workers (Spawn-Compatible on macOS)
# ----------------------------------------------------------------------------

def worker_identical_registration(
    db_path: str,
    cas_root: str,
    real_anchor: str,
    worker_idx: int,
    barrier: Any,
    out_q: Any
):
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, engine)

        # Synchronize before registration attempt
        barrier.wait()

        res = reg_service.register_capability(
            EVAL_ADD_CAPABILITY_DEF,
            pub_id=f"pub_worker_{worker_idx}_{uuid.uuid4().hex[:8]}"
        )
        out_q.put((True, res.is_duplicate, res.blob_digest))
        engine.close()
        conn.close()
    except Exception as e:
        out_q.put((False, type(e).__name__, str(e)))


def worker_conflicting_registration(
    db_path: str,
    cas_root: str,
    real_anchor: str,
    definition: CapabilityDefinition,
    worker_idx: int,
    barrier: Any,
    out_q: Any
):
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, engine)

        # Synchronize before registration attempt
        barrier.wait()

        res = reg_service.register_capability(
            definition,
            pub_id=f"pub_conf_{worker_idx}_{uuid.uuid4().hex[:8]}"
        )
        out_q.put((True, res.is_duplicate, res.blob_digest))
        engine.close()
        conn.close()
    except CapabilityRegistrationConflictError as e:
        out_q.put((False, "CapabilityRegistrationConflictError", str(e)))
    except Exception as e:
        out_q.put((False, type(e).__name__, str(e)))


def worker_registration_with_lease_hold(
    db_path: str,
    cas_root: str,
    real_anchor: str,
    barrier_lease_acquired: Any,
    barrier_gc_attempted: Any,
    out_q: Any
):
    """
    Simulates registration that acquires publication lease, writes to CAS,
    signals GC worker, waits for GC attempt to be rejected, and then commits.
    """
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, engine)

        urn = EVAL_ADD_CAPABILITY_DEF.capability_id
        payload_bytes = EVAL_ADD_CAPABILITY_DEF.to_deterministic_json_bytes()
        digest = hashlib.sha256(payload_bytes).hexdigest()
        byte_len = len(payload_bytes)

        actual_pub_id = f"pub_race_{uuid.uuid4().hex[:8]}"
        pub_token = f"tok_race_{uuid.uuid4().hex[:8]}"

        # Step 1: Acquire lease in active_cas_publications
        conn.execute("""
            INSERT INTO active_cas_publications (
                publication_id, blob_digest, worker_id, lease_token, lease_state,
                heartbeat_at, lease_expires_at
            ) VALUES (?, ?, 'worker_race_reg', ?, 'ACQUIRED', datetime('now'), datetime('now', '+60 seconds'));
        """, (actual_pub_id, digest, pub_token))
        conn.commit()

        # Step 2: Write staging and publish to CAS
        tmp_name, total_bytes, durability = engine.write_payload_to_staging(
            actual_pub_id, pub_token, digest, payload_bytes
        )
        engine.publish_staging_to_cas(tmp_name, digest)

        # Signal GC worker that lease is held and blob is on disk
        barrier_lease_acquired.wait()

        # Wait for GC worker to attempt deletion
        barrier_gc_attempted.wait()

        # Step 3: Complete SQLite registration
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute("""
            INSERT OR IGNORE INTO content_chunk_blobs (
                blob_digest, byte_length, storage_compression, stored_byte_length
            ) VALUES (?, ?, 'NONE', ?);
        """, (digest, byte_len, byte_len))

        conn.execute("""
            INSERT INTO entity_urn_registry (
                entity_urn, entity_kind, lifecycle_state
            ) VALUES (?, 'CAPABILITY', 'PENDING');
        """, (urn,))

        conn.execute("""
            INSERT INTO capabilities (
                capability_urn, name, version, description
            ) VALUES (?, ?, '1.0.0', ?);
        """, (urn, EVAL_ADD_CAPABILITY_DEF.display_name, EVAL_ADD_CAPABILITY_DEF.description))

        conn.execute("""
            UPDATE entity_urn_registry
            SET lifecycle_state = 'ACTIVE'
            WHERE entity_urn = ?;
        """, (urn,))

        conn.execute("""
            INSERT INTO capability_declarations (
                capability_urn, definition_blob_digest, schema_version, display_name, capability_type
            ) VALUES (?, ?, 1, ?, 'tool');
        """, (urn, digest, EVAL_ADD_CAPABILITY_DEF.display_name))

        conn.execute("""
            UPDATE active_cas_publications
            SET lease_state = 'COMMITTED'
            WHERE publication_id = ?;
        """, (actual_pub_id,))
        conn.commit()

        out_q.put((True, "REGISTRATION_COMMITTED", digest))
        engine.close()
        conn.close()
    except Exception as e:
        out_q.put((False, type(e).__name__, str(e)))


def worker_gc_during_lease(
    db_path: str,
    cas_root: str,
    real_anchor: str,
    blob_digest: str,
    barrier_lease_acquired: Any,
    barrier_gc_attempted: Any,
    out_q: Any
):
    """GC worker that attempts deletion while registration holds active lease."""
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)

        # Wait until registration has acquired lease and published file
        barrier_lease_acquired.wait()

        # Attempt GC reservation
        try:
            engine.gc_reserve_blob_for_deletion(
                conn, blob_digest, "gc_worker_race", f"gc_tok_{uuid.uuid4().hex[:8]}", lease_seconds=60
            )
            out_q.put((True, "UNEXPECTED_GC_RESERVED", "GC reservation should have been blocked!"))
        except sqlite3.IntegrityError as e:
            # Expected: Trigger trg_gc_reservation_check_eligibility blocked the reservation
            out_q.put((False, "BLOCKED_BY_LEASE", str(e)))

        barrier_gc_attempted.wait()
        engine.close()
        conn.close()
    except Exception as e:
        out_q.put((False, type(e).__name__, str(e)))


def worker_heartbeat_renewal_registration(
    db_path: str,
    cas_root: str,
    real_anchor: str,
    barrier_lease_acquired: Any,
    barrier_heartbeat_renewed: Any,
    barrier_gc_attempted: Any,
    out_q: Any
):
    """
    Simulates registration with a short initial lease (2s), renews the lease via heartbeat (extend by 4s),
    waits past the original 2s expiration while keeping registration uncommitted, and verifies
    that concurrent GC reservation cannot claim or unlink the blob.
    """
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, engine)

        urn = EVAL_ADD_CAPABILITY_DEF.capability_id
        payload_bytes = EVAL_ADD_CAPABILITY_DEF.to_deterministic_json_bytes()
        digest = hashlib.sha256(payload_bytes).hexdigest()
        byte_len = len(payload_bytes)

        actual_pub_id = f"pub_hb_{uuid.uuid4().hex[:8]}"
        pub_token = f"tok_hb_{uuid.uuid4().hex[:8]}"

        # Step 1: Acquire lease with short 2-second lifetime
        conn.execute("""
            INSERT INTO active_cas_publications (
                publication_id, blob_digest, worker_id, lease_token, lease_state,
                heartbeat_at, lease_expires_at
            ) VALUES (?, ?, 'worker_hb_reg', ?, 'ACQUIRED', datetime('now'), datetime('now', '+2 seconds'));
        """, (actual_pub_id, digest, pub_token))
        conn.commit()

        # Step 2: Write staging and publish to CAS
        tmp_name, total_bytes, durability = engine.write_payload_to_staging(
            actual_pub_id, pub_token, digest, payload_bytes
        )
        engine.publish_staging_to_cas(tmp_name, digest)

        # Signal that lease is acquired and blob is in CAS
        barrier_lease_acquired.wait()

        # Sleep 1.1s (lease still has ~0.9s remaining before initial 2s expiration)
        time.sleep(1.1)

        # Renew lease via heartbeat for an additional 4 seconds
        renewed = reg_service.renew_publication_lease(actual_pub_id, extend_seconds=4)
        assert renewed, "Heartbeat lease renewal must succeed!"

        # Signal that heartbeat renewal succeeded
        barrier_heartbeat_renewed.wait()

        # Wait until GC worker attempts deletion (GC will attempt at elapsed time > 2.2s, past original 2s)
        barrier_gc_attempted.wait()

        # Step 3: Complete SQLite registration
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute("""
            INSERT OR IGNORE INTO content_chunk_blobs (
                blob_digest, byte_length, storage_compression, stored_byte_length
            ) VALUES (?, ?, 'NONE', ?);
        """, (digest, byte_len, byte_len))
        conn.execute("""
            INSERT INTO entity_urn_registry (
                entity_urn, entity_kind, lifecycle_state
            ) VALUES (?, 'CAPABILITY', 'PENDING');
        """, (urn,))
        conn.execute("""
            INSERT INTO capabilities (
                capability_urn, name, version, description
            ) VALUES (?, ?, '1.0.0', ?);
        """, (urn, EVAL_ADD_CAPABILITY_DEF.display_name, EVAL_ADD_CAPABILITY_DEF.description))
        conn.execute("""
            UPDATE entity_urn_registry
            SET lifecycle_state = 'ACTIVE'
            WHERE entity_urn = ?;
        """, (urn,))
        conn.execute("""
            INSERT INTO capability_declarations (
                capability_urn, definition_blob_digest, schema_version, display_name, capability_type
            ) VALUES (?, ?, 1, ?, 'tool');
        """, (urn, digest, EVAL_ADD_CAPABILITY_DEF.display_name))
        conn.execute("""
            UPDATE active_cas_publications
            SET lease_state = 'COMMITTED'
            WHERE publication_id = ?;
        """, (actual_pub_id,))
        conn.commit()

        out_q.put((True, "REGISTRATION_COMMITTED", digest))
        engine.close()
        conn.close()
    except Exception as e:
        out_q.put((False, type(e).__name__, str(e)))


def worker_gc_attempt_after_initial_lease(
    db_path: str,
    cas_root: str,
    real_anchor: str,
    blob_digest: str,
    barrier_lease_acquired: Any,
    barrier_heartbeat_renewed: Any,
    barrier_gc_attempted: Any,
    out_q: Any
):
    """
    GC worker that attempts deletion after the initial 2s lease expiration,
    verifying that the heartbeat extension blocked GC reservation.
    """
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)

        barrier_lease_acquired.wait()
        start_time = time.time()

        barrier_heartbeat_renewed.wait()

        # Wait until at least 2.2 seconds have passed since initial lease was acquired
        elapsed = time.time() - start_time
        if elapsed < 2.2:
            time.sleep(2.2 - elapsed)

        # At this point, the initial 2-second lease would have expired without heartbeat renewal!
        try:
            engine.gc_reserve_blob_for_deletion(
                conn, blob_digest, "gc_worker_hb_test", f"gc_tok_{uuid.uuid4().hex[:8]}", lease_seconds=60
            )
            out_q.put((True, "UNEXPECTED_GC_RESERVED", "GC reservation should have been blocked by renewed lease!"))
        except sqlite3.IntegrityError as e:
            out_q.put((False, "BLOCKED_BY_RENEWED_LEASE", str(e)))

        barrier_gc_attempted.wait()
        engine.close()
        conn.close()
    except Exception as e:
        out_q.put((False, type(e).__name__, str(e)))


# ----------------------------------------------------------------------------
# Test Cases
# ----------------------------------------------------------------------------

def test_01_foreign_key_fresh_default_connection():
    print("--- Test 01: Foreign Key Enforcement on Fresh Default Connection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "fk_fresh.db")
        init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)

        # Fresh default connection without explicit foreign_keys pragma
        raw_conn = sqlite3.connect(db_path)
        cur = raw_conn.cursor()
        cur.execute("PRAGMA foreign_keys;")
        assert cur.fetchone()[0] == 0, "Default connection should have PRAGMA foreign_keys = 0"

        # Initialize CapabilityRegistrationService
        reg_service = CapabilityRegistrationService(raw_conn, engine)

        # Verify PRAGMA foreign_keys was automatically enabled and verified as 1
        cur.execute("PRAGMA foreign_keys;")
        assert cur.fetchone()[0] == 1, "CapabilityRegistrationService must enable and verify PRAGMA foreign_keys == 1"
        print("  Verified: Fresh connection with default FK=0 automatically configured to FK=1.")

        engine.close()
        raw_conn.close()


def test_02_foreign_key_already_enabled_connection():
    print("--- Test 02: Foreign Key Enforcement on Pre-Enabled Connection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "fk_enabled.db")
        init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)

        # Pre-enabled connection
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        assert conn.execute("PRAGMA foreign_keys;").fetchone()[0] == 1

        reg_service = CapabilityRegistrationService(conn, engine)
        assert conn.execute("PRAGMA foreign_keys;").fetchone()[0] == 1
        print("  Verified: Pre-enabled connection accepted and preserved.")

        engine.close()
        conn.close()


def test_03_foreign_key_initialization_during_active_transaction():
    print("--- Test 03: Foreign Key Initialization Rejection During Active Transaction ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "fk_trans.db")
        init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)

        # Open connection with FK disabled
        conn = sqlite3.connect(db_path)
        assert conn.execute("PRAGMA foreign_keys;").fetchone()[0] == 0

        # Start an uncommitted transaction
        conn.execute("INSERT INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES ('urn:lcs:temp:test', 'CAPABILITY', 'PENDING');")
        assert conn.in_transaction, "Connection must be inside an active transaction"

        # Attempt to initialize CapabilityRegistrationService
        caught_err = False
        try:
            reg_service = CapabilityRegistrationService(conn, engine)
        except SQLiteForeignKeyEnforcementError as e:
            caught_err = True
            print(f"  Guarded: Active transaction detected and initialization rejected: {e}")

        assert caught_err, "Service must fail initialization if connection is inside an active transaction with FK disabled!"

        conn.rollback()
        engine.close()
        conn.close()


def test_04_actual_foreign_key_violation_rejection():
    print("--- Test 04: Actual Foreign Key Violation Rejection (INSERT & ON DELETE RESTRICT) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "fk_violation.db")
        init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)

        conn = sqlite3.connect(db_path)
        reg_service = CapabilityRegistrationService(conn, engine)

        # 1. Foreign Key Violation on capability_urn (not in capabilities table)
        bogus_urn = "urn:lcs:tool:system.math:non-existent"
        bogus_digest = "a" * 64
        # Register blob in content_chunk_blobs so digest is valid
        conn.execute("INSERT INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length) VALUES (?, 10, 'NONE', 10);", (bogus_digest,))
        
        caught_fk_insert = False
        try:
            conn.execute("""
                INSERT INTO capability_declarations (
                    capability_urn, definition_blob_digest, schema_version, display_name, capability_type
                ) VALUES (?, ?, 1, 'Bogus', 'tool');
            """, (bogus_urn, bogus_digest))
        except sqlite3.IntegrityError as e:
            caught_fk_insert = True
            print(f"  Guarded: Invalid capability_urn rejected by foreign key: {e}")
        assert caught_fk_insert, "FK must reject capability_declarations insert with non-existent capability_urn!"

        # 2. Register valid capability normally
        res = reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        assert res.is_duplicate is False

        # 3. Foreign Key Violation on ON DELETE RESTRICT: Attempt to delete referenced blob
        caught_fk_delete = False
        try:
            conn.execute("DELETE FROM content_chunk_blobs WHERE blob_digest = ?;", (res.blob_digest,))
        except sqlite3.IntegrityError as e:
            caught_fk_delete = True
            print(f"  Guarded: Blob deletion blocked by ON DELETE RESTRICT foreign key: {e}")
        assert caught_fk_delete, "FK must block deletion of blob referenced in capability_declarations!"

        engine.close()
        conn.close()


def test_05_concurrent_identical_registrations_multiprocess():
    print("--- Test 05: Concurrent Identical Registrations (Multiprocess Coordination) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "concurrent_ident.db")
        init_db(db_path).close()

        barrier = multiprocessing.Barrier(2)
        out_q = multiprocessing.Queue()

        p1 = multiprocessing.Process(
            target=worker_identical_registration,
            args=(db_path, cas_root, real_anchor, 1, barrier, out_q)
        )
        p2 = multiprocessing.Process(
            target=worker_identical_registration,
            args=(db_path, cas_root, real_anchor, 2, barrier, out_q)
        )

        p1.start()
        p2.start()
        p1.join()
        p2.join()

        assert p1.exitcode == 0, f"Worker 1 failed with exit code {p1.exitcode}"
        assert p2.exitcode == 0, f"Worker 2 failed with exit code {p2.exitcode}"

        res1 = out_q.get(timeout=5)
        res2 = out_q.get(timeout=5)

        assert res1[0] is True, f"Worker 1 returned error: {res1}"
        assert res2[0] is True, f"Worker 2 returned error: {res2}"

        # Exactly one worker should report is_duplicate=False, and one is_duplicate=True
        duplicate_flags = [res1[1], res2[1]]
        assert sorted(duplicate_flags) == [False, True], f"Expected [False, True], got {duplicate_flags}"
        print(f"  Verified: Concurrent identical workers synchronized cleanly; duplicate flags: {duplicate_flags}")

        # Verify database consistency
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM capability_declarations WHERE capability_urn = ?;", (EVAL_ADD_CAPABILITY_DEF.capability_id,))
        assert cur.fetchone()[0] == 1, "Exactly 1 declaration row must exist!"

        cur.execute("SELECT COUNT(*) FROM capabilities WHERE capability_urn = ?;", (EVAL_ADD_CAPABILITY_DEF.capability_id,))
        assert cur.fetchone()[0] == 1, "Exactly 1 capability row must exist!"

        cur.execute("SELECT COUNT(*) FROM content_chunk_blobs WHERE blob_digest = ?;", (EVAL_ADD_CAPABILITY_DEF.compute_sha256(),))
        assert cur.fetchone()[0] == 1, "Exactly 1 content_chunk_blobs row must exist!"

        # Verify CAS physical file
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        assert engine.blob_exists(EVAL_ADD_CAPABILITY_DEF.compute_sha256())
        print("  Verified: Database and CAS physical storage maintain 100% single-instance consistency.")

        engine.close()
        conn.close()


def test_06_concurrent_conflicting_registrations_multiprocess():
    print("--- Test 06: Concurrent Conflicting Registrations (Multiprocess Coordination) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "concurrent_conf.db")
        init_db(db_path).close()

        # Definition A
        def_a = EVAL_ADD_CAPABILITY_DEF

        # Definition B: Same URN, different description and license
        def_b = CapabilityDefinition(
            capability_id=EVAL_ADD_CAPABILITY_DEF.capability_id,
            display_name="Math Evaluator: Add Conflicting Variant",
            description="Conflicting variant specification for deterministic integer addition.",
            capability_type="tool",
            schema_version=1,
            input_interface_ref=EVAL_ADD_CAPABILITY_DEF.input_interface_ref,
            output_interface_ref=EVAL_ADD_CAPABILITY_DEF.output_interface_ref,
            provenance={
                "author": "Adversarial Worker",
                "created_at": "2026-11-11T00:00:00Z",
                "license": "GPL-3.0",
                "source_origin": "lcs.adversarial.math.eval_add"
            },
            content_integrity={"digest_algorithm": "sha256"}
        )

        assert def_a.compute_sha256() != def_b.compute_sha256(), "Test requires differing digests"

        barrier = multiprocessing.Barrier(2)
        out_q = multiprocessing.Queue()

        p1 = multiprocessing.Process(
            target=worker_conflicting_registration,
            args=(db_path, cas_root, real_anchor, def_a, 1, barrier, out_q)
        )
        p2 = multiprocessing.Process(
            target=worker_conflicting_registration,
            args=(db_path, cas_root, real_anchor, def_b, 2, barrier, out_q)
        )

        p1.start()
        p2.start()
        p1.join()
        p2.join()

        assert p1.exitcode == 0
        assert p2.exitcode == 0

        res1 = out_q.get(timeout=5)
        res2 = out_q.get(timeout=5)

        successes = [r for r in (res1, res2) if r[0] is True]
        conflicts = [r for r in (res1, res2) if r[0] is False and r[1] == "CapabilityRegistrationConflictError"]

        assert len(successes) == 1, f"Expected exactly 1 successful registration, got: {successes}"
        assert len(conflicts) == 1, f"Expected exactly 1 conflict rejection, got: {conflicts}"
        print(f"  Verified: Exactly 1 worker succeeded and 1 worker caught CapabilityRegistrationConflictError: {conflicts[0][2]}")

        # Verify database holds the winning definition only
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT definition_blob_digest FROM capability_declarations WHERE capability_urn = ?;", (def_a.capability_id,))
        committed_digest = cur.fetchone()[0]
        assert committed_digest == successes[0][2], "Database must hold the winning worker's digest"
        print("  Verified: Database was not overwritten by conflicting registration.")

        conn.close()


def test_07_registration_racing_with_garbage_collection():
    print("--- Test 07: Registration Racing with Garbage Collection (Publication Lease Protection) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "race_gc.db")
        init_db(db_path).close()

        digest = EVAL_ADD_CAPABILITY_DEF.compute_sha256()

        barrier_lease = multiprocessing.Barrier(2)
        barrier_gc = multiprocessing.Barrier(2)
        out_q_reg = multiprocessing.Queue()
        out_q_gc = multiprocessing.Queue()

        p_reg = multiprocessing.Process(
            target=worker_registration_with_lease_hold,
            args=(db_path, cas_root, real_anchor, barrier_lease, barrier_gc, out_q_reg)
        )
        p_gc = multiprocessing.Process(
            target=worker_gc_during_lease,
            args=(db_path, cas_root, real_anchor, digest, barrier_lease, barrier_gc, out_q_gc)
        )

        p_reg.start()
        p_gc.start()
        p_gc.join()
        p_reg.join()

        assert p_reg.exitcode == 0
        assert p_gc.exitcode == 0

        res_reg = out_q_reg.get(timeout=5)
        res_gc = out_q_gc.get(timeout=5)

        # Registration must succeed
        assert res_reg[0] is True, f"Registration failed: {res_reg}"

        # GC must be blocked by trigger trg_gc_reservation_check_eligibility
        assert res_gc[0] is False and res_gc[1] == "BLOCKED_BY_LEASE", f"GC was not blocked by lease: {res_gc}"
        assert "CAS_GC_ELIGIBILITY_ERROR" in res_gc[2]
        print(f"  Verified: Concurrent GC reservation was blocked by publication lease: {res_gc[2]}")

        # Verify final database and CAS consistency
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT definition_blob_digest FROM capability_declarations WHERE capability_urn = ?;", (EVAL_ADD_CAPABILITY_DEF.capability_id,))
        assert cur.fetchone()[0] == digest

        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        assert engine.blob_exists(digest)

        # Test retrieval
        reg_service = CapabilityRegistrationService(conn, engine)
        retrieved = reg_service.retrieve_capability(EVAL_ADD_CAPABILITY_DEF.capability_id)
        assert retrieved.blob_digest == digest
        assert retrieved.raw_bytes == EVAL_ADD_CAPABILITY_DEF.to_deterministic_json_bytes()
        print("  Verified: Registration committed successfully and capability retrieved intact.")

        engine.close()
        conn.close()


def test_08_gc_reservation_before_registration_racing():
    print("--- Test 08: GC Reservation Before Registration Racing ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "gc_before_reg.db")
        init_db(db_path)
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)

        digest = EVAL_ADD_CAPABILITY_DEF.compute_sha256()
        payload = EVAL_ADD_CAPABILITY_DEF.to_deterministic_json_bytes()

        # Place unreferenced blob on physical disk
        tmp_name, _, _ = engine.write_payload_to_staging("pub_pre", "tok_pre", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        assert engine.blob_exists(digest)

        # Step 1: GC reserves blob for deletion FIRST
        gc_conn = sqlite3.connect(db_path, timeout=30.0)
        gc_conn.execute("PRAGMA journal_mode = WAL;")
        gc_conn.execute("PRAGMA foreign_keys = ON;")
        token = engine.gc_reserve_blob_for_deletion(
            gc_conn, digest, "gc_worker_pre", "gc_tok_pre", lease_seconds=60
        )
        print("  GC reserved blob prior to registration.")

        # Step 2: Capability registration attempts to register the same blob
        reg_conn = sqlite3.connect(db_path, timeout=30.0)
        reg_conn.execute("PRAGMA journal_mode = WAL;")
        reg_conn.execute("PRAGMA foreign_keys = ON;")
        reg_service = CapabilityRegistrationService(reg_conn, engine)

        caught_conflict = False
        try:
            reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        except CASPublicationConflictError as e:
            caught_conflict = True
            print(f"  Guarded: Registration blocked by pre-existing GC reservation: {e}")

        assert caught_conflict, "Registration must fail with CASPublicationConflictError if blob is reserved by GC!"

        # Step 3: Complete GC deletion
        deleted = engine.gc_complete_physical_deletion(gc_conn, digest, token)
        assert deleted
        print("  Verified: GC physical deletion proceeded without interference.")

        engine.close()
        reg_conn.close()
        gc_conn.close()


def test_09_publication_lease_heartbeat_renewal_blocks_gc():
    print("--- Test 09: Publication Lease Heartbeat Renewal Blocks Concurrent GC ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "heartbeat_gc.db")
        init_db(db_path).close()

        digest = EVAL_ADD_CAPABILITY_DEF.compute_sha256()

        barrier_lease = multiprocessing.Barrier(2)
        barrier_renew = multiprocessing.Barrier(2)
        barrier_gc = multiprocessing.Barrier(2)
        out_q_reg = multiprocessing.Queue()
        out_q_gc = multiprocessing.Queue()

        p_reg = multiprocessing.Process(
            target=worker_heartbeat_renewal_registration,
            args=(db_path, cas_root, real_anchor, barrier_lease, barrier_renew, barrier_gc, out_q_reg)
        )
        p_gc = multiprocessing.Process(
            target=worker_gc_attempt_after_initial_lease,
            args=(db_path, cas_root, real_anchor, digest, barrier_lease, barrier_renew, barrier_gc, out_q_gc)
        )

        p_reg.start()
        p_gc.start()
        p_gc.join()
        p_reg.join()

        assert p_reg.exitcode == 0
        assert p_gc.exitcode == 0

        res_reg = out_q_reg.get(timeout=5)
        res_gc = out_q_gc.get(timeout=5)

        # Registration must succeed
        assert res_reg[0] is True, f"Registration failed: {res_reg}"

        # GC must have been blocked even though elapsed time exceeded initial 2s lease!
        assert res_gc[0] is False and res_gc[1] == "BLOCKED_BY_RENEWED_LEASE", f"GC was not blocked: {res_gc}"
        assert "CAS_GC_ELIGIBILITY_ERROR" in res_gc[2]
        print(f"  Verified: GC reservation after initial lease expiration was blocked by active heartbeat renewal: {res_gc[2]}")

        # Verify final database and CAS consistency
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT definition_blob_digest FROM capability_declarations WHERE capability_urn = ?;", (EVAL_ADD_CAPABILITY_DEF.capability_id,))
        assert cur.fetchone()[0] == digest

        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        assert engine.blob_exists(digest)

        # Verify that now, after commit, while lease is active, trigger blocks GC
        raw_gc_conn = sqlite3.connect(db_path)
        raw_gc_conn.execute("PRAGMA foreign_keys = ON;")
        caught_trigger = False
        trigger_err = ""
        try:
            engine.gc_reserve_blob_for_deletion(
                raw_gc_conn, digest, "gc_post_commit_1", "tok_post_1", lease_seconds=60
            )
        except sqlite3.IntegrityError as e:
            caught_trigger = True
            trigger_err = str(e)
            print(f"  Verified: Active lease blocks GC: {e}")
        assert caught_trigger and "CAS_GC_ELIGIBILITY_ERROR" in trigger_err

        # Now expire the publication lease
        conn.execute("UPDATE active_cas_publications SET lease_expires_at = datetime('now', '-10 seconds');")
        conn.commit()

        # Verify that after publication lease expires, ON DELETE RESTRICT foreign key blocks GC!
        caught_fk = False
        fk_err = ""
        try:
            engine.gc_reserve_blob_for_deletion(
                raw_gc_conn, digest, "gc_post_commit_2", "tok_post_2", lease_seconds=60
            )
        except sqlite3.IntegrityError as e:
            caught_fk = True
            fk_err = str(e)
            print(f"  Verified: Post-expiration GC reservation blocked by foreign key constraint: {e}")
        assert caught_fk and "FOREIGN KEY constraint failed" in fk_err, "Committed declaration must block GC via foreign key constraint!"

        engine.close()
        raw_gc_conn.close()
        conn.close()


def test_10_failed_heartbeat_aborts_registration_safely():
    print("--- Test 10: Failed Heartbeat Aborts Registration Safely Before Publish ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "failed_hb.db")
        init_db(db_path).close()

        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, engine)

        # 1. Direct test of renew_publication_lease on an expired lease
        fake_pub_id = "pub_expired_test"
        conn.execute("""
            INSERT INTO active_cas_publications (
                publication_id, blob_digest, worker_id, lease_token, lease_state,
                heartbeat_at, lease_expires_at
            ) VALUES (?, ?, 'worker_exp', 'tok_exp', 'ACQUIRED', datetime('now', '-10 seconds'), datetime('now', '-5 seconds'));
        """, (fake_pub_id, EVAL_ADD_CAPABILITY_DEF.compute_sha256()))
        conn.commit()

        renewed = reg_service.renew_publication_lease(fake_pub_id, extend_seconds=60)
        assert renewed is False, "renew_publication_lease must return False on an expired lease!"
        print("  Verified: renew_publication_lease correctly rejected expired lease renewal.")

        # 2. Test registration abort when lease expires during slow staging write
        # Wrap write_payload_to_staging to simulate a slow operation that exceeds lease duration
        original_write = engine.write_payload_to_staging
        def slow_write(*args, **kwargs):
            # Sleep 2.5s to ensure the 1s lease expires before heartbeat renewal
            time.sleep(2.5)
            return original_write(*args, **kwargs)

        engine.write_payload_to_staging = slow_write

        caught_conflict = False
        try:
            reg_service.register_capability(
                EVAL_ADD_CAPABILITY_DEF,
                pub_id="pub_slow_test",
                lease_seconds=1
            )
        except CASPublicationConflictError as e:
            caught_conflict = True
            print(f"  Guarded: Registration safely aborted on expired heartbeat: {e}")

        assert caught_conflict, "Registration must abort with CASPublicationConflictError when heartbeat fails!"

        # Verify the blob was NOT linked or published to the CAS objects directory
        digest = EVAL_ADD_CAPABILITY_DEF.compute_sha256()
        assert not engine.blob_exists(digest), "Blob must NOT be published in CAS when heartbeat fails!"

        # Verify SQLite has no declaration records
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM capability_declarations WHERE capability_urn = ?;", (EVAL_ADD_CAPABILITY_DEF.capability_id,))
        assert cur.fetchone()[0] == 0

        # Verify publication lease was transitioned to ABORTED
        cur.execute("SELECT lease_state FROM active_cas_publications WHERE publication_id = 'pub_slow_test';")
        row = cur.fetchone()
        assert row is not None and row[0] == "ABORTED"
        print("  Verified: Publication state safely transitioned to ABORTED; CAS storage remained untouched.")

        engine.close()
        conn.close()


def test_11_gc_fresh_default_connection_enforces_foreign_keys():
    print("--- Test 11: GC Fresh Default Connection Enforces Foreign Keys & Rejects Active Transactions ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "gc_fk.db")
        init_db(db_path).close()

        engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)

        # 1. Register a capability using a proper connection
        reg_conn = sqlite3.connect(db_path)
        reg_conn.execute("PRAGMA journal_mode = WAL;")
        reg_conn.execute("PRAGMA synchronous = FULL;")
        reg_conn.execute("PRAGMA foreign_keys = ON;")
        reg_service = CapabilityRegistrationService(reg_conn, engine)
        res = reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        digest = res.blob_digest
        reg_conn.close()

        assert engine.blob_exists(digest)

        # Expire publication lease so trigger does not preempt foreign key check
        with sqlite3.connect(db_path) as exp_conn:
            exp_conn.execute("UPDATE active_cas_publications SET lease_expires_at = datetime('now', '-10 seconds');")
            exp_conn.commit()

        # 2. Open a FRESH DEFAULT connection without foreign keys (default PRAGMA foreign_keys == 0)
        fresh_gc_conn = sqlite3.connect(db_path)
        cur = fresh_gc_conn.cursor()
        cur.execute("PRAGMA foreign_keys;")
        assert cur.fetchone()[0] == 0, "Default sqlite3 connection must have PRAGMA foreign_keys == 0"

        # 3. Call engine.gc_reserve_blob_for_deletion using the fresh default connection
        # It must automatically call _ensure_connection_foreign_keys(fresh_gc_conn),
        # which enables foreign keys and causes DELETE FROM content_chunk_blobs to fail
        # with IntegrityError (FOREIGN KEY constraint failed) because capability_declarations references it!
        caught_fk_error = False
        try:
            engine.gc_reserve_blob_for_deletion(
                fresh_gc_conn, digest, "gc_worker_default", "tok_def", lease_seconds=60
            )
        except sqlite3.IntegrityError as e:
            caught_fk_error = True
            print(f"  Guarded: GC reservation on fresh default connection blocked by foreign key: {e}")

        assert caught_fk_error, "Fresh default connection must enforce foreign keys and block GC of referenced blob!"

        # Verify PRAGMA foreign_keys is now 1 on fresh_gc_conn
        cur.execute("PRAGMA foreign_keys;")
        assert cur.fetchone()[0] == 1, "Connection must have PRAGMA foreign_keys == 1 after GC entry"

        # Verify physical blob was NOT unlinked or reserved
        assert engine.blob_exists(digest), "Physical blob must remain on disk!"
        cur.execute("SELECT COUNT(*) FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest,))
        assert cur.fetchone()[0] == 0, "No reservation must exist!"

        # 4. Test fail-closed rejection when connection has an active uncommitted transaction
        tx_conn = sqlite3.connect(db_path)
        tx_conn.execute("BEGIN;")
        assert tx_conn.in_transaction

        caught_security_violation = False
        try:
            engine.gc_reserve_blob_for_deletion(
                tx_conn, digest, "gc_worker_tx", "tok_tx", lease_seconds=60
            )
        except CASSecurityViolationError as e:
            caught_security_violation = True
            print(f"  Guarded: GC reservation during active transaction rejected fail-closed: {e}")

        assert caught_security_violation, "GC methods must raise CASSecurityViolationError if foreign keys cannot be guaranteed!"
        tx_conn.rollback()

        # Also test direct _ensure_connection_foreign_keys on tx_conn
        tx_conn.execute("BEGIN;")
        caught_direct = False
        try:
            SecureCASStorageEngine._ensure_connection_foreign_keys(tx_conn)
        except CASSecurityViolationError as e:
            caught_direct = True
        assert caught_direct, "_ensure_connection_foreign_keys must raise CASSecurityViolationError inside transaction"
        tx_conn.rollback()

        print("  Verified: GC connection foreign-key enforcement is 100% fail-closed across all paths.")

        engine.close()
        fresh_gc_conn.close()
        tx_conn.close()


def main():
    print("======================================================================")
    print("LCS Stage 2B — M2 Remediation & Concurrency Verification Suite")
    print("======================================================================")
    test_01_foreign_key_fresh_default_connection()
    test_02_foreign_key_already_enabled_connection()
    test_03_foreign_key_initialization_during_active_transaction()
    test_04_actual_foreign_key_violation_rejection()
    test_05_concurrent_identical_registrations_multiprocess()
    test_06_concurrent_conflicting_registrations_multiprocess()
    test_07_registration_racing_with_garbage_collection()
    test_08_gc_reservation_before_registration_racing()
    test_09_publication_lease_heartbeat_renewal_blocks_gc()
    test_10_failed_heartbeat_aborts_registration_safely()
    test_11_gc_fresh_default_connection_enforces_foreign_keys()
    print("======================================================================")
    print("ALL 11 REMEDIATION & CONCURRENCY TESTS PASSED (100% GREEN)")
    print("======================================================================")

if __name__ == "__main__":
    main()
