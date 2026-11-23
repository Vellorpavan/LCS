#!/usr/bin/env python3
"""
LCS — SQLite Cross-Platform Compatibility & Migration Integrity Test Suite
==========================================================================
Verifies:
  1. Fresh database initialization across all 4 migrations.
  2. Legacy database upgrade compatibility: historical v3.0.1 baseline hash passes
     strictly with the approved portable v3.0.2 baseline on disk.
  3. Disk tampering detection: modifying the baseline SQL on disk fails integrity verification.
  4. Unrelated migration tampering detection: tampering with any other migration is caught.
  5. GC state-machine transition validation and error prefix preservation.
  6. Physical deletion receipt sync_method validation:
     - sync_method='NONE' rejected.
     - sync_method='F_FULLFSYNC' accepted.
     - sync_method='FSYNC' accepted.
  7. Terminal-state immutability (PHYSICALLY_DELETED and REVERTED).
  8. Migration idempotency and transaction safety.
"""

import os
import sys
import shutil
import tempfile
import sqlite3
import pytest

from migration_manager import (
    MigrationManager,
    MIGRATIONS_REGISTRY,
    APPROVED_HISTORICAL_TRANSITIONS,
    HISTORICAL_MIGRATION_BASELINES
)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORICAL_V3_HASH = "3fb567d2b67e63ef66b3aa36547a4ad1eca0d5d7822a5ee9608e302c49659a9c"
PORTABLE_V3_HASH = "49ee7ff523e6740f01d52ba279da77055047f1ea0325a7042614befb7401e421"


@pytest.fixture
def temp_db_path():
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield os.path.join(tmp_dir, "compat_test.db")


def test_01_fresh_database_initialization(temp_db_path):
    """Verifies that a fresh database successfully applies all 4 migrations in registry order."""
    mgr = MigrationManager(temp_db_path, schema_dir=CURRENT_DIR)
    
    # Pre-check: 4 migrations pending
    status = mgr.get_status()
    assert len(status) == 4
    assert all(not m["applied"] for m in status)
    assert [m["migration_id"] for m in status] == [
        "001_v2b_baseline",
        "002_m3_interface_policy",
        "003_m4_discovery",
        "004_m5_sqlite_compat"
    ]

    # Apply all migrations
    applied = mgr.apply_pending()
    assert len(applied) == 4
    assert applied == [
        "001_v2b_baseline",
        "002_m3_interface_policy",
        "003_m4_discovery",
        "004_m5_sqlite_compat"
    ]

    # Post-check: all applied, integrity clean
    status_after = mgr.get_status()
    assert all(m["applied"] for m in status_after)
    ok, issues = mgr.verify_integrity()
    assert ok, f"Expected clean integrity, got issues: {issues}"


def test_02_legacy_database_historical_baseline_passes_with_approved_portable_disk(temp_db_path):
    """
    Demonstrates Requirement 4:
    A legacy database recording the historical baseline hash ('3fb567d2...')
    passes integrity verification when the approved portable baseline ('49ee7ff5...') is on disk,
    and upgrades cleanly to 4/4 applied via forward migration 004.
    """
    conn = sqlite3.connect(temp_db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")

    # Apply original schemas directly
    for s in ("lcs_schema_v2b.sql", "lcs_schema_m3_migration.sql", "lcs_schema_m4_migration.sql"):
        p = os.path.join(CURRENT_DIR, s)
        with open(p, "r", encoding="utf-8") as f:
            conn.executescript(f.read())

    # Populate historical migration table as created by v3.0.0/v3.0.1
    conn.execute("""
        CREATE TABLE IF NOT EXISTS lcs_schema_migrations (
            migration_id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            description TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );
    """)
    conn.execute("""
        INSERT INTO lcs_schema_migrations VALUES
        ('001_v2b_baseline', 'lcs_schema_v2b.sql', ?, 'Baseline', '2026-11-11T06:02:55.353283+00:00'),
        ('002_m3_interface_policy', 'lcs_schema_m3_migration.sql', '65652fa722ddb4fe1334071cd01369cb13e11923a3dd55d313008f73bdefb652', 'M3', '2026-11-11T06:02:55.356896+00:00'),
        ('003_m4_discovery', 'lcs_schema_m4_migration.sql', '6644e0ead9752ba2c136c5414a6dde72a8ad5eed126ceebe246e7f84ab1817dc', 'M4', '2026-11-11T06:02:55.358076+00:00');
    """, (HISTORICAL_V3_HASH,))
    conn.commit()
    conn.close()

    mgr = MigrationManager(temp_db_path, schema_dir=CURRENT_DIR)
    
    # 1. Verify historical baseline integrity is accepted with approved disk file
    ok, issues = mgr.verify_integrity()
    assert ok, f"Historical baseline should be accepted with approved disk file, got: {issues}"

    # 2. Migration status shows 3 applied, 1 pending (004_m5_sqlite_compat)
    status = mgr.get_status()
    applied_ids = [m["migration_id"] for m in status if m["applied"]]
    pending_ids = [m["migration_id"] for m in status if not m["applied"]]
    assert len(applied_ids) == 3
    assert pending_ids == ["004_m5_sqlite_compat"]

    # 3. Apply forward migration 004
    applied = mgr.apply_pending()
    assert applied == ["004_m5_sqlite_compat"]

    # 4. Post-upgrade verification: 4/4 applied and verified
    status_post = mgr.get_status()
    assert all(m["applied"] for m in status_post)
    ok_post, issues_post = mgr.verify_integrity()
    assert ok_post, f"Post-upgrade integrity check failed: {issues_post}"


def test_03_legacy_database_fails_when_baseline_on_disk_is_modified(temp_db_path):
    """
    Demonstrates Requirement 5:
    Modifying the baseline SQL on disk causes integrity verification to fail
    even for a legacy database that records the historical hash.
    Never bypasses disk validation.
    """
    # Create isolated schema directory with an unexpected/tampered baseline file
    with tempfile.TemporaryDirectory() as custom_schema_dir:
        for s in ("lcs_schema_m3_migration.sql", "lcs_schema_m4_migration.sql", "lcs_schema_m5_sqlite_compat.sql"):
            shutil.copy(os.path.join(CURRENT_DIR, s), os.path.join(custom_schema_dir, s))
        
        # Write tampered lcs_schema_v2b.sql
        tampered_v2b = os.path.join(custom_schema_dir, "lcs_schema_v2b.sql")
        with open(tampered_v2b, "w", encoding="utf-8") as f:
            f.write("-- Tampered baseline schema content\nSELECT 1;\n")

        # Create database recording historical baseline hash
        conn = sqlite3.connect(temp_db_path)
        conn.execute("""
            CREATE TABLE lcs_schema_migrations (
                migration_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            INSERT INTO lcs_schema_migrations VALUES
            ('001_v2b_baseline', 'lcs_schema_v2b.sql', ?, 'Baseline', '2026-11-11T06:02:55.353283+00:00');
        """, (HISTORICAL_V3_HASH,))
        conn.commit()
        conn.close()

        mgr = MigrationManager(temp_db_path, schema_dir=custom_schema_dir)
        ok, issues = mgr.verify_integrity()
        
        # Must FAIL integrity verification
        assert not ok, "Integrity check MUST fail when on-disk baseline is tampered with!"
        assert any("Checksum mismatch for 001_v2b_baseline" in i for i in issues)


def test_04_unrelated_migration_tampering_detected(temp_db_path):
    """
    Demonstrates Requirement 6:
    Unrelated migration tampering (e.g. 002_m3_interface_policy, 004_m5_sqlite_compat)
    continues to be strictly detected and rejected.
    """
    mgr = MigrationManager(temp_db_path, schema_dir=CURRENT_DIR)
    mgr.apply_pending()

    # Tamper with recorded hash of 002_m3_interface_policy
    conn = mgr.get_connection()
    with conn:
        conn.execute("""
            UPDATE lcs_schema_migrations
            SET sha256 = 'forged_bogus_hash_0000000000000000000000000000000000000000'
            WHERE migration_id = '002_m3_interface_policy';
        """)
    conn.close()

    ok, issues = mgr.verify_integrity()
    assert not ok, "Integrity check must fail when migration 002 hash is forged."
    assert any("Checksum mismatch for 002_m3_interface_policy" in i for i in issues)


def test_05_gc_state_machine_valid_and_invalid_transitions(temp_db_path):
    """
    Verifies state-machine transition guard rules on cas_gc_deletion_reservations:
      - Valid transition: RESERVED -> COMMITTED_FOR_UNLINK
      - Invalid transition: RESERVED -> PHYSICALLY_DELETED (skipping COMMITTED_FOR_UNLINK)
      - Invalid transition: RESERVED -> UNKNOWN_STATE
      - Error message preservation: 'GC_TRANSITION_ERROR' prefix present
    """
    mgr = MigrationManager(temp_db_path, schema_dir=CURRENT_DIR)
    mgr.apply_pending()

    conn = mgr.get_connection()
    digest1 = "a" * 64
    worker_id = "test-gc-worker-1"
    token = "reservation-token-12345"

    with conn:
        conn.execute("""
            INSERT INTO cas_gc_deletion_reservations
            (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
            VALUES (?, 'RESERVED', ?, ?, datetime('now'), datetime('now', '+60 seconds'));
        """, (digest1, worker_id, token))

    # Violation 1: Illegal transition RESERVED -> PHYSICALLY_DELETED (skipping COMMITTED_FOR_UNLINK)
    with pytest.raises(sqlite3.IntegrityError) as exc_info:
        with conn:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'PHYSICALLY_DELETED'
                WHERE blob_digest = ?;
            """, (digest1,))
    err_msg = str(exc_info.value)
    assert "GC_TRANSITION_ERROR" in err_msg
    assert "Illegal state transition from RESERVED to PHYSICALLY_DELETED; cannot bypass COMMITTED_FOR_UNLINK" in err_msg

    # Violation 2: Illegal transition RESERVED -> BOGUS_STATE
    with pytest.raises(sqlite3.IntegrityError) as exc_info:
        with conn:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'BOGUS_INVALID_STATE'
                WHERE blob_digest = ?;
            """, (digest1,))
    err_msg = str(exc_info.value)
    assert "GC_TRANSITION_ERROR" in err_msg
    assert "Illegal state transition from RESERVED" in err_msg

    # Legal Transition: RESERVED -> COMMITTED_FOR_UNLINK
    with conn:
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'COMMITTED_FOR_UNLINK'
            WHERE blob_digest = ?;
        """, (digest1,))

    # Violation 3: Transition from COMMITTED_FOR_UNLINK to BOGUS_STATE
    with pytest.raises(sqlite3.IntegrityError) as exc_info:
        with conn:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'UNKNOWN_STATE'
                WHERE blob_digest = ?;
            """, (digest1,))
    err_msg = str(exc_info.value)
    assert "GC_TRANSITION_ERROR" in err_msg
    assert "Illegal state transition from COMMITTED_FOR_UNLINK" in err_msg

    # Violation 4: Attempt transition to PHYSICALLY_DELETED without valid receipt
    with pytest.raises(sqlite3.IntegrityError) as exc_info:
        with conn:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'PHYSICALLY_DELETED'
                WHERE blob_digest = ?;
            """, (digest1,))
    err_msg = str(exc_info.value)
    assert "GC_TRANSITION_ERROR" in err_msg
    assert "Cannot transition to PHYSICALLY_DELETED without verified physical deletion receipt linking blob_digest and reservation_token" in err_msg

    conn.close()


def test_06_gc_physical_deletion_receipt_sync_method_enforcement(temp_db_path):
    """
    Demonstrates Requirements 1, 2, 3:
    1. A receipt with sync_method='NONE' cannot authorize PHYSICALLY_DELETED.
    2. A receipt with F_FULLFSYNC is accepted when all other required receipt conditions are valid.
    3. A receipt with FSYNC is accepted when all other required receipt conditions are valid.
    4. A receipt with signature length < 16 cannot authorize PHYSICALLY_DELETED.
    """
    mgr = MigrationManager(temp_db_path, schema_dir=CURRENT_DIR)
    mgr.apply_pending()

    conn = mgr.get_connection()
    digest = "d" * 64
    worker_id = "test-worker"
    token = "token-sync-test-1234"

    with conn:
        conn.execute("""
            INSERT INTO cas_gc_deletion_reservations
            (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
            VALUES (?, 'RESERVED', ?, ?, datetime('now'), datetime('now', '+60 seconds'));
        """, (digest, worker_id, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'COMMITTED_FOR_UNLINK'
            WHERE blob_digest = ?;
        """, (digest,))

    # Case 1: Attempting to insert a receipt with sync_method='NONE' is rejected by integrity constraints,
    # ensuring sync_method='NONE' cannot exist to authorize PHYSICALLY_DELETED.
    with pytest.raises(sqlite3.IntegrityError) as exc_check:
        with conn:
            conn.execute("""
                INSERT INTO cas_physical_deletion_receipts
                (blob_digest, reservation_token, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature)
                VALUES (?, ?, 100, 200, 300, 'NONE', 1700000000000000000, 'valid_signature_16_bytes_long');
            """, (digest, token))
    assert "CHECK constraint failed" in str(exc_check.value)
    assert "sync_method" in str(exc_check.value)

    # Transition to PHYSICALLY_DELETED without an authorized receipt is rejected by trigger
    with pytest.raises(sqlite3.IntegrityError) as exc_no_receipt:
        with conn:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'PHYSICALLY_DELETED'
                WHERE blob_digest = ?;
            """, (digest,))
    err_none = str(exc_no_receipt.value)
    assert "GC_TRANSITION_ERROR" in err_none
    assert "Cannot transition to PHYSICALLY_DELETED without verified physical deletion receipt" in err_none

    # Case 2: Receipt with short signature (< 16 chars) cannot authorize PHYSICALLY_DELETED
    digest_short = "1" * 64
    with conn:
        conn.execute("""
            INSERT INTO cas_gc_deletion_reservations
            (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
            VALUES (?, 'RESERVED', ?, ?, datetime('now'), datetime('now', '+60 seconds'));
        """, (digest_short, worker_id, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'COMMITTED_FOR_UNLINK'
            WHERE blob_digest = ?;
        """, (digest_short,))
        conn.execute("""
            INSERT INTO cas_physical_deletion_receipts
            (blob_digest, reservation_token, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature)
            VALUES (?, ?, 100, 200, 300, 'F_FULLFSYNC', 1700000000000000000, 'short_sig');
        """, (digest_short, token))

    with pytest.raises(sqlite3.IntegrityError) as exc_info:
        with conn:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'PHYSICALLY_DELETED'
                WHERE blob_digest = ?;
            """, (digest_short,))
    assert "GC_TRANSITION_ERROR" in str(exc_info.value)

    # Case 3: Receipt with sync_method='FSYNC' and valid signature is accepted
    digest_fsync = "2" * 64
    with conn:
        conn.execute("""
            INSERT INTO cas_gc_deletion_reservations
            (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
            VALUES (?, 'RESERVED', ?, ?, datetime('now'), datetime('now', '+60 seconds'));
        """, (digest_fsync, worker_id, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'COMMITTED_FOR_UNLINK'
            WHERE blob_digest = ?;
        """, (digest_fsync,))
        conn.execute("""
            INSERT INTO cas_physical_deletion_receipts
            (blob_digest, reservation_token, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature)
            VALUES (?, ?, 100, 200, 300, 'FSYNC', 1700000000000000000, 'valid_signature_16_bytes_long');
        """, (digest_fsync, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'PHYSICALLY_DELETED'
            WHERE blob_digest = ?;
        """, (digest_fsync,))

    cur = conn.cursor()
    cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_fsync,))
    assert cur.fetchone()[0] == "PHYSICALLY_DELETED"

    # Case 4: Receipt with sync_method='F_FULLFSYNC' and valid signature is accepted
    digest_full = "3" * 64
    with conn:
        conn.execute("""
            INSERT INTO cas_gc_deletion_reservations
            (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
            VALUES (?, 'RESERVED', ?, ?, datetime('now'), datetime('now', '+60 seconds'));
        """, (digest_full, worker_id, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'COMMITTED_FOR_UNLINK'
            WHERE blob_digest = ?;
        """, (digest_full,))
        conn.execute("""
            INSERT INTO cas_physical_deletion_receipts
            (blob_digest, reservation_token, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature)
            VALUES (?, ?, 100, 200, 300, 'F_FULLFSYNC', 1700000000000000000, 'valid_signature_16_bytes_long');
        """, (digest_full, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'PHYSICALLY_DELETED'
            WHERE blob_digest = ?;
        """, (digest_full,))

    cur.execute("SELECT reservation_state FROM cas_gc_deletion_reservations WHERE blob_digest = ?;", (digest_full,))
    assert cur.fetchone()[0] == "PHYSICALLY_DELETED"
    conn.close()


def test_07_gc_terminal_state_protection(temp_db_path):
    """Verifies that terminal states (PHYSICALLY_DELETED, REVERTED) cannot be altered under any circumstance."""
    mgr = MigrationManager(temp_db_path, schema_dir=CURRENT_DIR)
    mgr.apply_pending()

    conn = mgr.get_connection()
    digest1 = "b" * 64
    digest2 = "c" * 64
    token = "token-term-test"

    with conn:
        # Set up a PHYSICALLY_DELETED terminal row
        conn.execute("""
            INSERT INTO cas_gc_deletion_reservations
            (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
            VALUES (?, 'RESERVED', 'w', ?, datetime('now'), datetime('now', '+60 seconds'));
        """, (digest1, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'COMMITTED_FOR_UNLINK'
            WHERE blob_digest = ?;
        """, (digest1,))
        conn.execute("""
            INSERT INTO cas_physical_deletion_receipts
            (blob_digest, reservation_token, unlinked_inode, shard_inode, device_id, sync_method, sync_timestamp_ns, receipt_signature)
            VALUES (?, ?, 1, 2, 3, 'F_FULLFSYNC', 1700000000000000000, 'valid_signature_16_bytes_long');
        """, (digest1, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'PHYSICALLY_DELETED'
            WHERE blob_digest = ?;
        """, (digest1,))

        # Set up a REVERTED terminal row
        conn.execute("""
            INSERT INTO cas_gc_deletion_reservations
            (blob_digest, reservation_state, gc_worker_id, reservation_token, reserved_at, expires_at)
            VALUES (?, 'RESERVED', 'w', ?, datetime('now'), datetime('now', '+60 seconds'));
        """, (digest2, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'COMMITTED_FOR_UNLINK'
            WHERE blob_digest = ?;
        """, (digest2,))
        conn.execute("""
            INSERT INTO cas_gc_cancellation_receipts
            (blob_digest, reservation_token, key_id, verified_inode, verified_bytes, device_id, verified_timestamp_ns, receipt_signature)
            VALUES (?, ?, 'k1', 1, 100, 2, 1700000000000000000, 'valid_signature_16_bytes_long');
        """, (digest2, token))
        conn.execute("""
            UPDATE cas_gc_deletion_reservations
            SET reservation_state = 'REVERTED'
            WHERE blob_digest = ?;
        """, (digest2,))

    # Violation 1: Attempt to mutate PHYSICALLY_DELETED row
    with pytest.raises(sqlite3.IntegrityError) as exc_info:
        with conn:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'RESERVED'
                WHERE blob_digest = ?;
            """, (digest1,))
    err1 = str(exc_info.value)
    assert "GC_TRANSITION_ERROR" in err1
    assert "Cannot alter terminal reservation state PHYSICALLY_DELETED" in err1

    # Violation 2: Attempt to mutate REVERTED row
    with pytest.raises(sqlite3.IntegrityError) as exc_info:
        with conn:
            conn.execute("""
                UPDATE cas_gc_deletion_reservations
                SET reservation_state = 'RESERVED'
                WHERE blob_digest = ?;
            """, (digest2,))
    err2 = str(exc_info.value)
    assert "GC_TRANSITION_ERROR" in err2
    assert "Cannot alter terminal reservation state REVERTED" in err2

    conn.close()


def test_08_migration_idempotency_and_transaction_safety(temp_db_path):
    """Verifies that re-running apply_pending() is an idempotent no-op and runs in WAL mode with foreign keys enabled."""
    mgr = MigrationManager(temp_db_path, schema_dir=CURRENT_DIR)
    
    first_run = mgr.apply_pending()
    assert len(first_run) == 4

    # Second run should apply 0 migrations
    second_run = mgr.apply_pending()
    assert len(second_run) == 0

    conn = mgr.get_connection()
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys;")
    assert cur.fetchone()[0] == 1
    cur.execute("PRAGMA journal_mode;")
    assert cur.fetchone()[0].lower() == "wal"
    conn.close()
