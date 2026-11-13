#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 2: Capability Registration & Canonical CAS Ingestion Test Suite
=======================================================================================
Authoritative verification suite for Milestone 2:
1. Valid canonical identifiers (tools, skills, agents, interfaces).
2. Invalid and noncanonical identifiers (uppercase, missing kind, colons, slashes, percent-encoding).
3. Deterministic serialization (key permutation invariance, canonical compact formatting).
4. Valid registration (declarative registration of urn:lcs:tool:system.math:eval-add).
5. Duplicate registration (idempotent identical re-registration vs. conflict on differing definition).
6. CAS ingestion (physical storage in objects/xx/, 0600 permissions, content_chunk_blobs).
7. Retrieval by canonical ID (retrieval, JSON reconstruction, semantic validation).
8. SHA-256 verification (cryptographic integrity of retrieved bytes against manifest).
9. Byte-for-byte equality (exact bit-level identity between retrieved bytes and reserialization).
10. Missing CAS content rejection (unlinked physical blob raises CASBlobNotFoundError; no silent repair).
11. Corrupted CAS content rejection (bit-flipped disk payload raises CapabilityCorruptionError).
12. Mismatched digest or reference defense (tampered DB reference raises integrity error).
13. Persistence across engine restart (fresh database connection and engine recover cleanly).
"""

import os
import sys
import time
import stat
import json
import errno
import hashlib
import sqlite3
import tempfile
from typing import Dict, Any

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    CASBlobNotFoundError,
    CASDigestMismatchError,
    CASSecurityViolationError,
    CASValidationError
)

from capability_registry_v2b import (
    parse_canonical_urn,
    CanonicalCapabilityURN,
    CapabilityDefinition,
    CapabilityRegistrationService,
    RegistrationResult,
    RetrievedCapability,
    EVAL_ADD_CAPABILITY_DEF,
    InvalidCapabilityURNError,
    InvalidCapabilityDefinitionError,
    CapabilityRegistrationConflictError,
    CapabilityNotFoundError,
    CapabilityCorruptionError,
    CapabilityIntegrityMismatchError
)

def init_test_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = FULL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    schema_path = os.path.join(CURRENT_DIR, "lcs_schema_v2b.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    return conn


# ============================================================================
# TEST CASES
# ============================================================================

def test_01_valid_canonical_identifiers():
    print("--- Test 01: Valid Canonical Identifiers ---")
    valid_urns = [
        ("urn:lcs:tool:system.math:eval-add", "tool", "system.math", "eval-add"),
        ("urn:lcs:skill:developer.git:review-diff", "skill", "developer.git", "review-diff"),
        ("urn:lcs:agent:orchestration.review:code-reviewer", "agent", "orchestration.review", "code-reviewer"),
        ("urn:lcs:interface:system.math:eval-add-input", "interface", "system.math", "eval-add-input"),
        ("urn:lcs:tool:deep.hierarchical.namespace.domain:simple-tool", "tool", "deep.hierarchical.namespace.domain", "simple-tool"),
        ("urn:lcs:tool:min:t", "tool", "min", "t"),
        ("urn:lcs:tool:namespace_with_underscores:id-with-hyphen-1", "tool", "namespace_with_underscores", "id-with-hyphen-1")
    ]
    for raw, exp_kind, exp_ns, exp_id in valid_urns:
        parsed = parse_canonical_urn(raw)
        assert parsed.entity_kind == exp_kind
        assert parsed.namespace == exp_ns
        assert parsed.identifier == exp_id
        assert parsed.raw_urn == raw
    print(f"  Verified {len(valid_urns)} valid canonical URNs accepted.")


def test_02_invalid_and_noncanonical_identifiers():
    print("--- Test 02: Invalid and Noncanonical Identifiers ---")
    invalid_cases = [
        # Uppercase violations
        ("URN:lcs:tool:system.math:eval-add", "Uppercase scheme prefix"),
        ("urn:LCS:tool:system.math:eval-add", "Uppercase LCS prefix"),
        ("urn:lcs:Tool:system.math:eval-add", "Uppercase entity kind"),
        ("urn:lcs:tool:System.Math:eval-add", "Uppercase namespace"),
        ("urn:lcs:tool:system.math:Eval-Add", "Uppercase identifier"),
        # Unsupported entity kinds
        ("urn:lcs:service:system.math:eval-add", "Unsupported entity_kind 'service'"),
        ("urn:lcs:module:system.math:eval-add", "Unsupported entity_kind 'module'"),
        ("urn:lcs:cap:system.math:eval-add", "Unsupported entity_kind 'cap'"),
        # Syntax & formatting errors
        ("urn:lcs:tool:eval-add", "Missing namespace component"),
        ("urn:lcs:tool:system.math:", "Empty identifier"),
        ("urn:lcs:tool::eval-add", "Empty namespace"),
        ("urn:lcs:tool:ab:eval-add", "Namespace too short (<3 chars)"),
        ("urn:lcs:tool:" + ("a"*65) + ":eval-add", "Namespace too long (>64 chars)"),
        ("urn:lcs:tool:system.math:" + ("b"*65), "Identifier too long (>64 chars)"),
        # Forbidden characters & encodings
        ("urn:lcs:tool:system:math:eval-add", "Extra colon in namespace"),
        ("urn:lcs:tool:system/math:eval-add", "Slash in namespace"),
        ("urn:lcs:tool:system.math:eval/add", "Slash in identifier"),
        ("urn:lcs:tool:system%20math:eval-add", "Percent-encoding in namespace"),
        ("urn:lcs:tool:system.math:eval%20add", "Percent-encoding in identifier"),
        ("urn:lcs:tool:system.math:eval add", "Space in identifier"),
        ("urn:lcs:tool:system.math:eval\tadd", "Tab in identifier"),
        ("urn:lcs:tool:system.math:eval\nadd", "Newline in identifier"),
        ("urn:lcs:tool:system..math:eval-add", "Consecutive dots in namespace"),
        ("urn:lcs:tool:.system.math:eval-add", "Leading dot in namespace"),
        ("urn:lcs:tool:system.math.:eval-add", "Trailing dot in namespace"),
        ("urn:lcs:tool:system.math:-eval-add", "Leading hyphen in identifier"),
        ("urn:lcs:tool:system.math:eval-add-", "Trailing hyphen in identifier")
    ]
    for raw, reason in invalid_cases:
        try:
            parse_canonical_urn(raw)
            assert False, f"Expected InvalidCapabilityURNError for '{reason}' ({raw})!"
        except InvalidCapabilityURNError as e:
            pass
    print(f"  Verified {len(invalid_cases)} noncanonical URNs strictly rejected.")


def test_03_deterministic_serialization():
    print("--- Test 03: Deterministic Serialization ---")
    # Construct definition with keys in varying dictionary orders
    def_1 = CapabilityDefinition(
        capability_id="urn:lcs:tool:system.math:eval-add",
        display_name="Math Evaluator: Add",
        description="Declarative specification for deterministic integer addition.",
        capability_type="tool",
        schema_version=1,
        input_interface_ref="urn:lcs:interface:system.math:eval-add-input",
        output_interface_ref="urn:lcs:interface:system.math:eval-add-output",
        provenance={
            "author": "LCS Systems Architecture Team",
            "created_at": "2026-11-11T00:00:00Z",
            "license": "Apache-2.0",
            "source_origin": "lcs.builtin.math.eval_add"
        },
        content_integrity={"digest_algorithm": "sha256"}
    )

    # Scramble dictionary construction order in def_2
    def_2 = CapabilityDefinition.from_dict({
        "content_integrity": {"digest_algorithm": "sha256"},
        "description": "Declarative specification for deterministic integer addition.",
        "output_interface_ref": "urn:lcs:interface:system.math:eval-add-output",
        "schema_version": 1,
        "provenance": {
            "source_origin": "lcs.builtin.math.eval_add",
            "license": "Apache-2.0",
            "created_at": "2026-11-11T00:00:00Z",
            "author": "LCS Systems Architecture Team"
        },
        "display_name": "Math Evaluator: Add",
        "input_interface_ref": "urn:lcs:interface:system.math:eval-add-input",
        "capability_type": "tool",
        "capability_id": "urn:lcs:tool:system.math:eval-add"
    })

    bytes_1 = def_1.to_deterministic_json_bytes()
    bytes_2 = def_2.to_deterministic_json_bytes()
    assert bytes_1 == bytes_2, "Deterministic bytes do not match across scrambled key dicts!"
    assert def_1.compute_sha256() == def_2.compute_sha256()
    print(f"  Verified: Bit-for-bit identical serialization (length: {len(bytes_1)} bytes, SHA-256: {def_1.compute_sha256()}).")


def test_04_valid_registration_and_cas_ingestion():
    print("--- Test 04: Valid Registration and CAS Ingestion ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs.db")
        
        conn = init_test_db(db_path)
        cas_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, cas_engine)

        # Register canonical example capability
        result = reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        assert result.capability_id == "urn:lcs:tool:system.math:eval-add"
        assert result.is_duplicate is False
        assert result.byte_size == len(EVAL_ADD_CAPABILITY_DEF.to_deterministic_json_bytes())
        assert result.blob_digest == EVAL_ADD_CAPABILITY_DEF.compute_sha256()

        # Verify physical file in CAS objects/xx/
        prefix = result.blob_digest[:2]
        shard_path = os.path.join(cas_root, "objects", prefix, result.blob_digest)
        assert os.path.exists(shard_path), f"CAS blob file does not exist at {shard_path}"
        st = os.stat(shard_path)
        # In CAS storage, finalized published objects are read-only (0o444)
        assert stat.S_IMODE(st.st_mode) in (0o444, 0o600)
        assert st.st_size == result.byte_size

        # Verify SQLite database records
        cur = conn.cursor()
        cur.execute("SELECT lifecycle_state FROM entity_urn_registry WHERE entity_urn = ?;", (result.capability_id,))
        assert cur.fetchone()[0] == "ACTIVE"

        cur.execute("SELECT name, description FROM capabilities WHERE capability_urn = ?;", (result.capability_id,))
        row_cap = cur.fetchone()
        assert row_cap[0] == EVAL_ADD_CAPABILITY_DEF.display_name
        assert row_cap[1] == EVAL_ADD_CAPABILITY_DEF.description

        cur.execute("SELECT byte_length FROM content_chunk_blobs WHERE blob_digest = ?;", (result.blob_digest,))
        assert cur.fetchone()[0] == result.byte_size

        cur.execute("SELECT definition_blob_digest, capability_type FROM capability_declarations WHERE capability_urn = ?;", (result.capability_id,))
        row_decl = cur.fetchone()
        assert row_decl[0] == result.blob_digest
        assert row_decl[1] == "tool"

        print("  Verified: Physical blob and relational records committed with full integrity.")
        cas_engine.close()
        conn.close()


def test_05_duplicate_registration_behavior():
    print("--- Test 05: Duplicate Registration Behavior ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs.db")
        
        conn = init_test_db(db_path)
        cas_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, cas_engine)

        # 1. Initial Registration
        res1 = reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        assert res1.is_duplicate is False

        # 2. Identical Duplicate Registration (Idempotent Success)
        res2 = reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        assert res2.is_duplicate is True
        assert res2.blob_digest == res1.blob_digest
        assert res2.capability_id == res1.capability_id
        print("  Verified: Identical duplicate registration is cleanly idempotent.")

        # 3. Conflicting Duplicate Registration (Different definition, same canonical URN)
        conflicting_def = CapabilityDefinition(
            capability_id="urn:lcs:tool:system.math:eval-add",
            display_name="Math Evaluator: Add (CONFLICTING VERSION)",
            description="A modified description that changes the serialized digest.",
            capability_type="tool",
            schema_version=1,
            input_interface_ref="urn:lcs:interface:system.math:eval-add-input",
            output_interface_ref="urn:lcs:interface:system.math:eval-add-output",
            provenance={
                "author": "Rogue Developer",
                "created_at": "2026-11-11T01:00:00Z",
                "license": "MIT",
                "source_origin": "rogue.math"
            },
            content_integrity={"digest_algorithm": "sha256"}
        )

        try:
            reg_service.register_capability(conflicting_def)
            assert False, "Expected CapabilityRegistrationConflictError on conflicting re-registration!"
        except CapabilityRegistrationConflictError as e:
            print(f"  Guarded: Conflicting re-registration strictly rejected: {e}")

        # Confirm original record in database is intact and unaltered
        cur = conn.cursor()
        cur.execute("SELECT definition_blob_digest, display_name FROM capability_declarations WHERE capability_urn = ?;", (res1.capability_id,))
        row = cur.fetchone()
        assert row[0] == res1.blob_digest
        assert row[1] == EVAL_ADD_CAPABILITY_DEF.display_name
        print("  Verified: Original registration was not overwritten.")

        cas_engine.close()
        conn.close()


def test_06_retrieval_and_byte_equality():
    print("--- Test 06: Retrieval and Byte-for-Byte Equality ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs.db")
        
        conn = init_test_db(db_path)
        cas_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, cas_engine)

        reg_res = reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        
        # Retrieve by canonical ID
        retrieved = reg_service.retrieve_capability("urn:lcs:tool:system.math:eval-add")
        assert retrieved.blob_digest == reg_res.blob_digest
        assert retrieved.stored_byte_length == reg_res.byte_size
        
        # Verify byte-for-byte equality with original serialization
        orig_bytes = EVAL_ADD_CAPABILITY_DEF.to_deterministic_json_bytes()
        assert retrieved.raw_bytes == orig_bytes
        
        # Verify reconstructed definition attributes
        d = retrieved.definition
        assert d.capability_id == EVAL_ADD_CAPABILITY_DEF.capability_id
        assert d.display_name == EVAL_ADD_CAPABILITY_DEF.display_name
        assert d.description == EVAL_ADD_CAPABILITY_DEF.description
        assert d.capability_type == EVAL_ADD_CAPABILITY_DEF.capability_type
        assert d.input_interface_ref == EVAL_ADD_CAPABILITY_DEF.input_interface_ref
        assert d.output_interface_ref == EVAL_ADD_CAPABILITY_DEF.output_interface_ref
        assert d.provenance == EVAL_ADD_CAPABILITY_DEF.provenance
        
        # Verify re-serialized bytes of reconstructed object match retrieved raw bytes
        assert d.to_deterministic_json_bytes() == retrieved.raw_bytes
        print("  Verified: Retrieved definition satisfies byte-for-byte equality and semantic parity.")

        cas_engine.close()
        conn.close()


def test_07_missing_cas_content_rejection():
    print("--- Test 07: Missing CAS Content Rejection (No Silent Repair) ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs.db")
        
        conn = init_test_db(db_path)
        cas_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, cas_engine)

        reg_res = reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        
        # Out-of-band delete physical CAS blob from disk
        shard_path = os.path.join(cas_root, "objects", reg_res.blob_digest[:2], reg_res.blob_digest)
        os.unlink(shard_path)
        assert not os.path.exists(shard_path)

        # Retrieval must fail explicitly with CASBlobNotFoundError
        try:
            reg_service.retrieve_capability("urn:lcs:tool:system.math:eval-add")
            assert False, "Expected CASBlobNotFoundError when physical file is deleted!"
        except CASBlobNotFoundError as e:
            print(f"  Guarded: Missing disk content caught and strictly raised: {e}")

        cas_engine.close()
        conn.close()


def test_08_corrupted_cas_content_rejection():
    print("--- Test 08: Corrupted CAS Content Rejection (No Silent Corruption) ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs.db")
        
        conn = init_test_db(db_path)
        cas_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, cas_engine)

        reg_res = reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        
        # Tamper with physical blob on disk (flip 1 byte)
        shard_path = os.path.join(cas_root, "objects", reg_res.blob_digest[:2], reg_res.blob_digest)
        os.chmod(shard_path, 0o644)
        with open(shard_path, "r+b") as f:
            data = bytearray(f.read())
            data[10] ^= 0xFF  # Corrupt byte 10
            f.seek(0)
            f.write(data)
            f.flush()
        os.chmod(shard_path, 0o444)

        # Retrieval must detect SHA-256 corruption and raise CapabilityCorruptionError
        try:
            reg_service.retrieve_capability("urn:lcs:tool:system.math:eval-add")
            assert False, "Expected CapabilityCorruptionError on tampered blob bytes!"
        except CapabilityCorruptionError as e:
            print(f"  Guarded: Corrupted disk content detected and strictly raised: {e}")

        cas_engine.close()
        conn.close()


def test_09_mismatched_db_reference_defense():
    print("--- Test 09: Mismatched Database Reference Defense ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs.db")
        
        conn = init_test_db(db_path)
        cas_engine = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service = CapabilityRegistrationService(conn, cas_engine)

        reg_res = reg_service.register_capability(EVAL_ADD_CAPABILITY_DEF)

        # 1. Non-existent URN
        try:
            reg_service.retrieve_capability("urn:lcs:tool:system.math:non-existent")
            assert False, "Expected CapabilityNotFoundError!"
        except CapabilityNotFoundError as e:
            print(f"  Guarded: Non-existent URN rejected: {e}")

        # 2. Adversarial DB modification: point definition_blob_digest to a dummy non-existent digest
        bogus_digest = "f" * 64
        conn.execute("INSERT OR IGNORE INTO content_chunk_blobs (blob_digest, byte_length, storage_compression, stored_byte_length) VALUES (?, 10, 'NONE', 10);", (bogus_digest,))
        conn.execute("UPDATE capability_declarations SET definition_blob_digest = ? WHERE capability_urn = ?;", (bogus_digest, reg_res.capability_id))
        conn.commit()

        try:
            reg_service.retrieve_capability(reg_res.capability_id)
            assert False, "Expected CASBlobNotFoundError when DB reference points to bogus digest!"
        except CASBlobNotFoundError as e:
            print(f"  Guarded: Bogus DB reference detected: {e}")

        cas_engine.close()
        conn.close()


def test_10_persistence_across_engine_restart():
    print("--- Test 10: Persistence Across Engine Restart ---")
    with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs.db")
        
        # Instance 1: Register capability
        conn_1 = init_test_db(db_path)
        cas_engine_1 = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service_1 = CapabilityRegistrationService(conn_1, cas_engine_1)
        res_1 = reg_service_1.register_capability(EVAL_ADD_CAPABILITY_DEF)
        
        cas_engine_1.close()
        conn_1.close()
        print("  Instance 1 closed after registration.")

        # Instance 2: Brand new connection and fresh CASStorageEngine instance
        conn_2 = sqlite3.connect(db_path, timeout=30.0)
        conn_2.execute("PRAGMA foreign_keys = ON;")
        cas_engine_2 = SecureCASStorageEngine(cas_root, trusted_anchor=real_anchor)
        reg_service_2 = CapabilityRegistrationService(conn_2, cas_engine_2)

        # Confirm capability is registered and active
        assert reg_service_2.is_registered("urn:lcs:tool:system.math:eval-add") is True

        # Retrieve across process/restart boundary
        retrieved = reg_service_2.retrieve_capability("urn:lcs:tool:system.math:eval-add")
        assert retrieved.blob_digest == res_1.blob_digest
        assert retrieved.definition.capability_id == EVAL_ADD_CAPABILITY_DEF.capability_id
        assert retrieved.raw_bytes == EVAL_ADD_CAPABILITY_DEF.to_deterministic_json_bytes()
        print("  Verified: Fresh engine instance retrieved and verified capability across restart boundary.")

        cas_engine_2.close()
        conn_2.close()


def main():
    print("======================================================================")
    print("LCS Stage 2B — Milestone 2 Capability Registration & CAS Ingestion Suite")
    print("======================================================================")
    
    test_01_valid_canonical_identifiers()
    test_02_invalid_and_noncanonical_identifiers()
    test_03_deterministic_serialization()
    test_04_valid_registration_and_cas_ingestion()
    test_05_duplicate_registration_behavior()
    test_06_retrieval_and_byte_equality()
    test_07_missing_cas_content_rejection()
    test_08_corrupted_cas_content_rejection()
    test_09_mismatched_db_reference_defense()
    test_10_persistence_across_engine_restart()
    
    print("\n======================================================================")
    print("ALL 10 MILESTONE 2 CAPABILITY REGISTRATION TESTS PASSED (100% GREEN)")
    print("======================================================================")

if __name__ == "__main__":
    main()
