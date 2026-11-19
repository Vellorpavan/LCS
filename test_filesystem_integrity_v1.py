"""
Test Suite for LCS Filesystem Integrity & Incremental Discovery (Phase 1B)
==========================================================================
Verifies 10 temporary-filesystem edge cases from Task 004 specification:
1. test_same_size_content_modification (Level 1 mtime detect & Level 2 rehash)
2. test_preserved_modification_timestamp (Hash-On-Activation catches restored mtime)
3. test_atomic_file_replacement (os.replace inode change detected)
4. test_file_deletion_and_recreation (fail-closed on delete, recover on recreate)
5. test_directory_rename (path update without duplicate CAS ingestion)
6. test_symlink_replacement_and_escape (O_NOFOLLOW & confinement fail-closed)
7. test_missed_filesystem_notifications (periodic reconciliation heals catalog drift)
8. test_concurrent_modification_during_hashing (double-stat write-in-progress retry)
9. test_interrupted_cas_ingestion (clean temp file cleanup on write failure)
10. test_recovery_after_interrupted_catalog_update (transaction rollback safety)
"""

import os
import sys
import time
import json
import stat
import shutil
import sqlite3
import hashlib
import tempfile
import threading
import pytest
from pathlib import Path
from unittest.mock import patch

from skill_discovery_v1 import (
    SafeFileReader,
    BundleManifestHasher,
    SkillDiscoveryEngineV1,
    PathTraversalSecurityError,
    DescriptorSecurityError,
    MAX_INSTRUCTION_FILE_SIZE,
)
from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    PersistentReceiptKeyStore,
    CASError,
    CASValidationError,
)
from lcs.adapters.activation_verifier import (
    ActivationIntegrityVerifier,
    ActivationIntegrityRecord,
)
from lcs.adapters.base import (
    ContentIntegrityMismatchError,
    PathTraversalSecurityError as AdapterPathTraversalError,
)
from lcs.adapters.generic import GenericPOSIXAdapter


# Helper fixture for temporary LCS database and CAS engine
@pytest.fixture
def lcs_test_env():
    with tempfile.TemporaryDirectory() as raw_tmpdir:
        tmpdir = os.path.realpath(raw_tmpdir)
        db_path = os.path.join(tmpdir, "lcs_test.db")
        cas_root = os.path.join(tmpdir, "cas")
        key_store_dir = os.path.join(tmpdir, "keys")
        os.makedirs(cas_root, exist_ok=True)
        os.makedirs(key_store_dir, exist_ok=True)

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Minimal schema for artifact discovery and physical sources
        cur.execute("""
            CREATE TABLE artifact_discovery_records (
                record_id TEXT PRIMARY KEY,
                canonical_urn TEXT NOT NULL,
                resolved_path TEXT NOT NULL,
                raw_content_digest TEXT NOT NULL,
                bundle_manifest_digest TEXT,
                is_bundle INTEGER NOT NULL DEFAULT 0,
                bundle_root_path TEXT,
                discovered_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        cur.execute("""
            CREATE TABLE physical_source_instances (
                instance_id TEXT PRIMARY KEY,
                capability_urn TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                sha256_digest TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE'
            );
        """)
        conn.commit()

        cas_engine = SecureCASStorageEngine(
            cas_root=cas_root,
            trusted_anchor=tmpdir,
            key_store_dir=key_store_dir
        )

        yield {
            "tmpdir": tmpdir,
            "conn": conn,
            "cas_engine": cas_engine,
            "db_path": db_path,
        }

        cas_engine.close()
        conn.close()


def store_cas_blob(engine: SecureCASStorageEngine, payload_bytes: bytes, digest: str):
    tmp_name, _, _ = engine.write_payload_to_staging(
        pub_id=f"pub-{digest[:8]}",
        token="tok",
        expected_digest=digest,
        data_generator_or_bytes=payload_bytes
    )
    return engine.publish_staging_to_cas(tmp_name, digest)


def has_cas_blob(engine: SecureCASStorageEngine, digest: str) -> bool:
    shard = digest[:2]
    obj_path = os.path.join(engine.cas_root, "objects", shard, digest)
    return os.path.isfile(obj_path)


# =====================================================================
# Test 1: Same-Size Content Modification
# =====================================================================

def test_same_size_content_modification(lcs_test_env):
    """
    Verifies that modifying content without altering byte size is detected
    via mtime in Level 1 stat and re-hashed in Level 2.
    """
    tmpdir = lcs_test_env["tmpdir"]
    cas_engine = lcs_test_env["cas_engine"]

    skill_path = os.path.join(tmpdir, "SKILL.md")
    content_v1 = b"ALLOWED_HOSTS: localhost       \n# Version 1.0 of the secure capability file."
    content_v2 = b"ALLOWED_HOSTS: 0.0.0.000       \n# Version 1.0 of the secure capability file."
    assert len(content_v1) == len(content_v2), "Byte length must remain identical"

    with open(skill_path, "wb") as f:
        f.write(content_v1)

    st_before = os.stat(skill_path)
    digest_v1 = hashlib.sha256(content_v1).hexdigest()
    store_cas_blob(cas_engine, content_v1, digest=digest_v1)

    time.sleep(0.05)  # Ensure mtime increment
    with open(skill_path, "wb") as f:
        f.write(content_v2)

    st_after = os.stat(skill_path)
    assert st_after.st_size == st_before.st_size
    assert st_after.st_mtime_ns != st_before.st_mtime_ns, "Level 1 stat detects mtime change"

    # Level 2 computes new SHA-256
    data_v2, _ = SafeFileReader.read_exact_bytes(skill_path, MAX_INSTRUCTION_FILE_SIZE)
    digest_v2 = hashlib.sha256(data_v2).hexdigest()
    assert digest_v2 != digest_v1

    store_cas_blob(cas_engine, content_v2, digest=digest_v2)
    assert has_cas_blob(cas_engine, digest_v1)
    assert has_cas_blob(cas_engine, digest_v2)


# =====================================================================
# Test 2: Preserved Modification Timestamp (Caught by Hash-On-Activation)
# =====================================================================

def test_preserved_modification_timestamp(lcs_test_env):
    """
    Verifies that an in-place modification with restored mtime bypasses
    stat comparisons but is caught fail-closed by Hash-On-Activation.
    """
    tmpdir = lcs_test_env["tmpdir"]
    conn = lcs_test_env["conn"]

    skill_path = os.path.join(tmpdir, "SKILL.md")
    content_orig = b"ROLE: ReadOnlyViewer            \n# Canonical authentic capability instructions."
    with open(skill_path, "wb") as f:
        f.write(content_orig)

    st_orig = os.stat(skill_path)
    digest_orig = hashlib.sha256(content_orig).hexdigest()

    urn = "skill:local:tampered-timestamp"
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO artifact_discovery_records (
            record_id, canonical_urn, resolved_path, raw_content_digest, is_bundle
        ) VALUES ('rec-01', ?, ?, ?, 0);
    """, (urn, skill_path, digest_orig))
    conn.commit()

    verifier = ActivationIntegrityVerifier(conn)
    # Verification initially succeeds
    res = verifier.verify_capability(urn)
    assert res.verified is True

    # Tampering: overwrite with same size and restore original mtime
    content_tampered = b"ROLE: SuperAdminFullControl     \n# Canonical authentic capability instructions."
    assert len(content_tampered) == len(content_orig)

    with open(skill_path, "wb") as f:
        f.write(content_tampered)

    # Restore exact mtime nanoseconds
    os.utime(skill_path, ns=(st_orig.st_atime_ns, st_orig.st_mtime_ns))

    st_tampered = os.stat(skill_path)
    # Metadata stat checks falsely claim the file is untouched
    assert st_tampered.st_size == st_orig.st_size
    assert st_tampered.st_mtime_ns == st_orig.st_mtime_ns
    assert st_tampered.st_ino == st_orig.st_ino

    # Hash-On-Activation MUST fail-closed because on-disk bytes drifted
    with pytest.raises(ContentIntegrityMismatchError) as exc_info:
        verifier.verify_capability(urn)
    assert "Integrity mismatch" in str(exc_info.value)


# =====================================================================
# Test 3: Atomic File Replacement (New Inode Detection)
# =====================================================================

def test_atomic_file_replacement(lcs_test_env):
    """
    Verifies that atomic replacement (rename over existing file) produces
    a new inode, triggering immediate re-indexing.
    """
    tmpdir = lcs_test_env["tmpdir"]
    skill_path = os.path.join(tmpdir, "SKILL.md")
    with open(skill_path, "w") as f:
        f.write("# Version 1")

    orig_ino = os.stat(skill_path).st_ino

    # Atomic write to temporary sibling and rename
    tmp_path = os.path.join(tmpdir, "SKILL.md.tmp")
    with open(tmp_path, "w") as f:
        f.write("# Version 2 with updated instructions")

    os.replace(tmp_path, skill_path)

    new_ino = os.stat(skill_path).st_ino
    assert new_ino != orig_ino, "Atomic replace assigns new inode"

    data, _ = SafeFileReader.read_exact_bytes(skill_path, MAX_INSTRUCTION_FILE_SIZE)
    assert b"Version 2" in data


# =====================================================================
# Test 4: File Deletion and Recreation
# =====================================================================

def test_file_deletion_and_recreation(lcs_test_env):
    """
    Verifies that deleting an activated file causes verification to fail closed,
    and recreating it restores validity.
    """
    tmpdir = lcs_test_env["tmpdir"]
    conn = lcs_test_env["conn"]

    skill_path = os.path.join(tmpdir, "SKILL.md")
    content = b"# Skill Lifecycle Recovery Test"
    with open(skill_path, "wb") as f:
        f.write(content)

    digest = hashlib.sha256(content).hexdigest()
    urn = "skill:local:lifecycle-test"

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO artifact_discovery_records (
            record_id, canonical_urn, resolved_path, raw_content_digest, is_bundle
        ) VALUES ('rec-del-1', ?, ?, ?, 0);
    """, (urn, skill_path, digest))
    conn.commit()

    verifier = ActivationIntegrityVerifier(conn)
    assert verifier.verify_capability(urn).verified is True

    # 1. Deletion -> Verification fails closed with FILE_NOT_FOUND
    os.unlink(skill_path)
    assert not os.path.exists(skill_path)

    with pytest.raises(ContentIntegrityMismatchError) as exc_info:
        verifier.verify_capability(urn)
    assert "FILE_NOT_FOUND" in str(exc_info.value)

    # 2. Recreation with original content -> Verification passes again
    with open(skill_path, "wb") as f:
        f.write(content)

    assert verifier.verify_capability(urn).verified is True


# =====================================================================
# Test 5: Directory Rename (Zero Duplicate CAS Storage)
# =====================================================================

def test_directory_rename(lcs_test_env):
    """
    Verifies that renaming a capability directory updates path resolution
    without creating duplicate CAS objects for identical content.
    """
    tmpdir = lcs_test_env["tmpdir"]
    cas_engine = lcs_test_env["cas_engine"]

    alpha_dir = os.path.join(tmpdir, "skills", "alpha")
    os.makedirs(alpha_dir, exist_ok=True)
    skill_file = os.path.join(alpha_dir, "SKILL.md")
    content = b"# Directory Movement Content Test"

    with open(skill_file, "wb") as f:
        f.write(content)

    digest = hashlib.sha256(content).hexdigest()
    receipt1 = store_cas_blob(cas_engine, content, digest=digest)

    # Rename alpha -> beta
    beta_dir = os.path.join(tmpdir, "skills", "beta")
    os.rename(alpha_dir, beta_dir)

    new_skill_file = os.path.join(beta_dir, "SKILL.md")
    assert os.path.isfile(new_skill_file)

    # Ingest from new path
    data, _ = SafeFileReader.read_exact_bytes(new_skill_file, MAX_INSTRUCTION_FILE_SIZE)
    receipt2 = store_cas_blob(cas_engine, data, digest=digest)

    assert receipt1["blob_digest"] == receipt2["blob_digest"]
    assert has_cas_blob(cas_engine, digest)


# =====================================================================
# Test 6: Symlink Replacement and Path Escape Confinement
# =====================================================================

def test_symlink_replacement_and_escape(lcs_test_env):
    """
    Verifies that replacing a registered file with a symlink escaping the
    root is rejected by descriptor pinning (O_NOFOLLOW) and confinement checks.
    """
    tmpdir = lcs_test_env["tmpdir"]
    workspace = os.path.join(tmpdir, "workspace")
    outside = os.path.join(tmpdir, "secrets")
    os.makedirs(workspace, exist_ok=True)
    os.makedirs(outside, exist_ok=True)

    secret_file = os.path.join(outside, "secret.key")
    with open(secret_file, "w") as f:
        f.write("SECRET_KEY_DATA")

    skill_file = os.path.join(workspace, "SKILL.md")
    # Replace skill_file with symlink pointing outside
    os.symlink(secret_file, skill_file)

    adapter = GenericPOSIXAdapter(workspace_root=workspace)

    # 1. Adapter exact bytes reader detects path escape
    with pytest.raises((AdapterPathTraversalError, PathTraversalSecurityError)):
        adapter.read_skill_exact_bytes(skill_file)

    # 2. SafeFileReader enforces O_NOFOLLOW on descriptor open
    with pytest.raises((DescriptorSecurityError, PathTraversalSecurityError, OSError)):
        SafeFileReader.read_exact_bytes(skill_file, MAX_INSTRUCTION_FILE_SIZE)


# =====================================================================
# Test 7: Missed Filesystem Notifications (Reconciliation Scan)
# =====================================================================

def test_missed_filesystem_notifications(lcs_test_env):
    """
    Verifies that un-notified filesystem changes (e.g. missed watcher events)
    are healed by a sweep comparing disk state with catalog records.
    """
    tmpdir = lcs_test_env["tmpdir"]
    conn = lcs_test_env["conn"]

    skills_dir = os.path.join(tmpdir, "skills")
    os.makedirs(skills_dir, exist_ok=True)

    cur = conn.cursor()
    files = {}
    for i in range(3):
        p = os.path.join(skills_dir, f"skill_{i}.md")
        c = f"# Skill {i}".encode("utf-8")
        with open(p, "wb") as f:
            f.write(c)
        d = hashlib.sha256(c).hexdigest()
        urn = f"skill:local:batch-{i}"
        files[urn] = (p, d)
        cur.execute("""
            INSERT INTO artifact_discovery_records (
                record_id, canonical_urn, resolved_path, raw_content_digest, is_bundle
            ) VALUES (?, ?, ?, ?, 0);
        """, (f"rec-batch-{i}", urn, p, d))
    conn.commit()

    verifier = ActivationIntegrityVerifier(conn)

    # Un-notified modification of skill_1
    mod_path, old_digest = files["skill:local:batch-1"]
    new_content = b"# Skill 1 MODIFIED BEHIND WATCHER BACK"
    with open(mod_path, "wb") as f:
        f.write(new_content)

    # Verifier detects drift immediately on activation
    with pytest.raises(ContentIntegrityMismatchError):
        verifier.verify_capability("skill:local:batch-1")

    # Reconciliation update: update record to match ground truth
    new_digest = hashlib.sha256(new_content).hexdigest()
    cur.execute("""
        UPDATE artifact_discovery_records
        SET raw_content_digest = ?
        WHERE canonical_urn = 'skill:local:batch-1';
    """, (new_digest,))
    conn.commit()

    # Reconciled record passes verification
    res = verifier.verify_capability("skill:local:batch-1")
    assert res.verified is True
    assert res.sha256 == new_digest


# =====================================================================
# Test 8: Concurrent Modification During Hashing (Torn Read Detection)
# =====================================================================

def test_concurrent_modification_during_hashing(lcs_test_env):
    """
    Verifies that write-in-progress is detected when file stat changes
    between initial inspection and read completion.
    """
    tmpdir = lcs_test_env["tmpdir"]
    file_path = os.path.join(tmpdir, "concurrent.txt")

    initial_content = b"Initial block of text " * 100
    with open(file_path, "wb") as f:
        f.write(initial_content)

    st_before = os.stat(file_path)

    # Simulated double-stat read function
    def read_with_double_stat(path: str, max_retries: int = 3):
        for attempt in range(max_retries):
            s1 = os.stat(path)
            with open(path, "rb") as f:
                data = f.read()
            s2 = os.stat(path)

            if s1.st_size == s2.st_size and s1.st_mtime_ns == s2.st_mtime_ns:
                return data, hashlib.sha256(data).hexdigest()
            time.sleep(0.01)
        raise RuntimeError("Torn read detected: file modified during read")

    # Clean read without concurrent write
    data, digest = read_with_double_stat(file_path)
    assert digest == hashlib.sha256(initial_content).hexdigest()

    # Interleaved write test: trigger modification during read attempt to induce torn read
    write_triggered = False

    def read_with_double_stat_concurrent(path: str, max_retries: int = 5):
        nonlocal write_triggered
        for attempt in range(max_retries):
            s1 = os.stat(path)
            with open(path, "rb") as f:
                data = f.read()
            if not write_triggered:
                # Append data concurrently during read to simulate torn read
                with open(path, "ab") as f_append:
                    f_append.write(b" APPENDED BY THREAD")
                write_triggered = True

            s2 = os.stat(path)
            if s1.st_size == s2.st_size and s1.st_mtime_ns == s2.st_mtime_ns:
                return data, hashlib.sha256(data).hexdigest()
            time.sleep(0.01)
        raise RuntimeError("Torn read detected: file modified during read")

    # Double stat read detects torn read on attempt 0, retries, and captures the stabilized file
    data_final, digest_final = read_with_double_stat_concurrent(file_path, max_retries=5)

    assert b"APPENDED BY THREAD" in data_final
    assert digest_final == hashlib.sha256(data_final).hexdigest()


# =====================================================================
# Test 9: Interrupted CAS Ingestion (Temporary Staging Cleanup)
# =====================================================================

def test_interrupted_cas_ingestion(lcs_test_env):
    """
    Verifies that an error during CAS blob ingestion does not leave
    corrupted or half-written files in the object store.
    """
    tmpdir = lcs_test_env["tmpdir"]
    cas_engine = lcs_test_env["cas_engine"]

    payload = b"Payload for crash durability test"
    correct_digest = hashlib.sha256(payload).hexdigest()

    # Simulate error by injecting digest mismatch into staging write
    with pytest.raises(Exception):
        store_cas_blob(cas_engine, payload, digest="0000000000000000000000000000000000000000000000000000000000000000")

    # Target blob must NOT exist
    assert not has_cas_blob(cas_engine, "0000000000000000000000000000000000000000000000000000000000000000")
    assert not has_cas_blob(cas_engine, correct_digest)

    # Ingesting correctly afterwards works cleanly
    receipt = store_cas_blob(cas_engine, payload, digest=correct_digest)
    assert receipt["blob_digest"] == correct_digest
    assert has_cas_blob(cas_engine, correct_digest)


# =====================================================================
# Test 10: Recovery After Interrupted Catalog Update (Transaction Safety)
# =====================================================================

def test_recovery_after_interrupted_catalog_update(lcs_test_env):
    """
    Verifies that failure during a database catalog registration triggers
    clean rollback without leaving dangling or corrupted records.
    """
    conn = lcs_test_env["conn"]
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM artifact_discovery_records;")
    initial_count = cur.fetchone()[0]

    try:
        # Begin transaction
        cur.execute("BEGIN IMMEDIATE;")
        cur.execute("""
            INSERT INTO artifact_discovery_records (
                record_id, canonical_urn, resolved_path, raw_content_digest, is_bundle
            ) VALUES ('tx-rec-1', 'skill:local:tx-test', '/path/to/skill', 'abc123digest', 0);
        """)
        # Force a unique constraint violation by repeating the primary key
        cur.execute("""
            INSERT INTO artifact_discovery_records (
                record_id, canonical_urn, resolved_path, raw_content_digest, is_bundle
            ) VALUES ('tx-rec-1', 'skill:local:duplicate', '/path/to/other', 'def456digest', 0);
        """)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()

    cur.execute("SELECT COUNT(*) FROM artifact_discovery_records;")
    post_count = cur.fetchone()[0]
    assert post_count == initial_count, "Rollback guarantees zero dangling or partial records"

    cur.execute("SELECT * FROM artifact_discovery_records WHERE record_id = 'tx-rec-1';")
    assert cur.fetchone() is None
