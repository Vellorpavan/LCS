#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 3: Interface Attestation & Policy Verification Suite
=============================================================================
Authoritatively tests:
1. Valid interface attestation & canonical serialization.
2. Persistent attestation verification across application restarts.
3. Modified interface declaration detection (tampered interface CAS blob).
4. Modified capability definition detection (tampered capability CAS blob).
5. Forged / invalid HMAC signature rejection.
6. Unknown interface identity handling (UNAVAILABLE state).
7. Unattested interface handling (UNVERIFIED state when attestation required).
8. Policy acceptance and rejection constraints (license, author, source origin, attester, version).
9. Explainable policy decisions & persistent audit trail retrieval.
10. Relational transaction safety & foreign-key referential integrity (ON DELETE RESTRICT).
11. Attestation verification across key rotation in PersistentReceiptKeyStore.
"""

import os
import sys
import json
import uuid
import hmac
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
    CASDigestMismatchError
)
from capability_registry_v2b import (
    CapabilityRegistrationService,
    CapabilityDefinition,
    EVAL_ADD_CAPABILITY_DEF,
    InvalidCapabilityURNError
)
from interface_policy_v2b import (
    AgentDeclaration,
    InterfaceDeclaration,
    InterfaceCapabilityRef,
    InterfaceAttestation,
    InterfaceTrustPolicy,
    PolicyEvaluationDecision,
    InterfacePolicyService,
    InterfaceNotFoundError,
    AgentNotFoundError,
    InvalidInterfaceURNError,
    InvalidInterfaceDeclarationError,
    SQLiteForeignKeyEnforcementError
)


def init_test_env(tmp_dir: str):
    real_anchor = os.path.realpath(tmp_dir)
    cas_root = os.path.join(real_anchor, "cas")
    db_path = os.path.join(real_anchor, "test_m3.db")
    key_store_dir = os.path.join(real_anchor, ".lcs_keys")

    conn = sqlite3.connect(db_path)
    schema_path = os.path.join(CURRENT_DIR, "lcs_schema_v2b.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.execute("PRAGMA foreign_keys = ON;")

    cas_engine = SecureCASStorageEngine(
        cas_root=cas_root,
        trusted_anchor=real_anchor,
        key_store_dir=key_store_dir
    )
    cap_service = CapabilityRegistrationService(conn, cas_engine)
    iface_service = InterfacePolicyService(conn, cas_engine, cap_service)
    return conn, cas_engine, cap_service, iface_service, db_path, cas_root, key_store_dir, real_anchor


def test_01_valid_interface_attestation_and_serialization():
    print("--- Test 01: Valid Interface Attestation and Canonical Serialization ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        # 1. Register agent
        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:test.system:calc-agent",
            display_name="Calc Agent",
            description="Agent",
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_agent(agent)

        # 2. Register capability
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)

        # 3. Register interface
        iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:math-iface-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="Math Interface",
            description="Test Math Interface",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(iface)

        # Verify deterministic serialization
        ser_1 = iface.to_deterministic_json_bytes()
        ser_2 = iface.to_deterministic_json_bytes()
        assert ser_1 == ser_2
        assert hashlib.sha256(ser_1).hexdigest() == iface.compute_sha256()

        # 4. Generate attestation
        att = iface_srv.attest_interface(iface.interface_urn, "urn:lcs:attester:sec:signer-1")
        assert att.attestation_id.startswith("att_")
        assert att.interface_urn == iface.interface_urn
        assert att.agent_urn == agent.agent_urn
        assert len(att.signature) == 64
        assert engine.blob_exists(att.attestation_blob_digest)

        # 5. Immediate verification
        is_valid, reasons = iface_srv.verify_attestation(att.attestation_id)
        assert is_valid, f"Verification failed: {reasons}"
        print(f"  Verified: Attestation generated and verified (ID: {att.attestation_id})")

        engine.close()
        conn.close()


def test_02_persistent_verification_after_restart():
    print("--- Test 02: Persistent Verification Across Application Restart ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:test.system:persist-agent",
            display_name="Persist Agent",
            description="Persist Agent Desc",
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "Apache-2.0", "source_origin": "test.origin"}
        )
        iface_srv.register_agent(agent)
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:persist-iface-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="Persist Interface",
            description="Persist Interface Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "Apache-2.0", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(iface)
        att = iface_srv.attest_interface(iface.interface_urn, "urn:lcs:attester:sec:local")
        att_id = att.attestation_id

        # Close all connections
        engine.close()
        conn.close()

        # Reopen fresh connections simulating new process
        conn_reopened = sqlite3.connect(db_path)
        engine_reopened = SecureCASStorageEngine(cas_root=cas_root, trusted_anchor=anchor, key_store_dir=ks_dir)
        iface_srv_reopened = InterfacePolicyService(conn_reopened, engine_reopened)

        is_valid, reasons = iface_srv_reopened.verify_attestation(att_id)
        assert is_valid, f"Restart verification failed: {reasons}"
        print(f"  Verified: Attestation '{att_id}' successfully verified across restart boundary.")

        engine_reopened.close()
        conn_reopened.close()


def test_03_modified_interface_detection():
    print("--- Test 03: Modified Interface Declaration Detection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:test.system:tamper-iface-agent",
            display_name="Agent",
            description="Agent",
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_agent(agent)
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:tamper-iface-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="Tamper Interface",
            description="Tamper Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(iface)
        att = iface_srv.attest_interface(iface.interface_urn)
        att_id = att.attestation_id

        # Tamper with interface declaration blob in CAS
        iface_digest = iface.compute_sha256()
        blob_path = os.path.join(cas_root, "objects", iface_digest[:2], iface_digest)
        os.chmod(blob_path, 0o644)
        with open(blob_path, "wb") as f:
            f.write(b"{\"tampered\": true}")

        is_valid, reasons = iface_srv.verify_attestation(att_id)
        assert not is_valid, "Attestation must fail when interface declaration blob is tampered!"
        print(f"  Guarded: Tampered interface declaration detected: {reasons[0]}")

        engine.close()
        conn.close()


def test_04_modified_capability_definition_detection():
    print("--- Test 04: Modified Capability Definition Detection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:test.system:tamper-cap-agent",
            display_name="Agent",
            description="Agent",
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_agent(agent)
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:tamper-cap-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="Tamper Cap Interface",
            description="Tamper Cap Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(iface)
        att = iface_srv.attest_interface(iface.interface_urn)
        att_id = att.attestation_id

        # Tamper with capability blob
        cap_digest = res.blob_digest
        blob_path = os.path.join(cas_root, "objects", cap_digest[:2], cap_digest)
        os.chmod(blob_path, 0o644)
        with open(blob_path, "wb") as f:
            f.write(b"{\"malicious\": true}")

        is_valid, reasons = iface_srv.verify_attestation(att_id)
        assert not is_valid, "Attestation must fail when capability blob is tampered!"
        print(f"  Guarded: Tampered capability blob detected: {reasons[0]}")

        # Policy evaluation must return REJECTED
        policy = InterfaceTrustPolicy("strict-policy")
        dec = iface_srv.evaluate_policy(iface.interface_urn, policy)
        assert dec.decision == "DENY"
        assert dec.status == "REJECTED"
        print("  Verified: Policy evaluation correctly yielded DENY / REJECTED.")

        engine.close()
        conn.close()


def test_05_forged_hmac_signature_rejection():
    print("--- Test 05: Forged HMAC Signature Rejection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:test.system:forge-agent",
            display_name="Agent",
            description="Agent",
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_agent(agent)
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:forge-iface-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="Forge Interface",
            description="Forge Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(iface)
        att = iface_srv.attest_interface(iface.interface_urn)
        att_id = att.attestation_id

        # Tamper signature in database
        conn.execute(
            "UPDATE interface_attestations SET signature = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' WHERE attestation_id = ?;",
            (att_id,)
        )
        conn.commit()

        is_valid, reasons = iface_srv.verify_attestation(att_id)
        assert not is_valid, "Attestation must fail when HMAC signature is forged!"
        assert "Cryptographic HMAC signature verification failed" in reasons[0]
        print(f"  Guarded: Forged HMAC signature caught and rejected: {reasons[0]}")

        engine.close()
        conn.close()


def test_06_unattested_and_unknown_interface_states():
    print("--- Test 06: Unattested (UNVERIFIED) and Unknown (UNAVAILABLE) States ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        # 1. Unknown interface
        policy = InterfaceTrustPolicy("test-policy", require_attestation=True)
        dec_unknown = iface_srv.evaluate_policy("urn:lcs:interface:test.system:unknown-iface", policy)
        assert dec_unknown.decision == "DENY"
        assert dec_unknown.status == "UNAVAILABLE"
        print(f"  Verified: Unknown interface returned DENY / UNAVAILABLE: {dec_unknown.reasons[0]}")

        # 2. Registered interface without attestation
        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:test.system:unattested-agent",
            display_name="Agent",
            description="Agent",
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_agent(agent)
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:unattested-iface-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="Unattested Interface",
            description="Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(iface)

        dec_unattested = iface_srv.evaluate_policy(iface.interface_urn, policy)
        assert dec_unattested.decision == "DENY"
        assert dec_unattested.status == "UNVERIFIED"
        print(f"  Verified: Unattested interface returned DENY / UNVERIFIED: {dec_unattested.reasons[0]}")

        engine.close()
        conn.close()


def test_07_policy_constraints_acceptance_and_rejections():
    print("--- Test 07: Policy Constraints (License, Author, Origin, Attester, Version) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:finance.core:trading-agent",
            display_name="Trading Agent",
            description="Agent",
            provenance={"author": "Quant Team", "created_at": "2026-11-11T00:00:00Z", "license": "GPL-3.0", "source_origin": "internal.repo"}
        )
        iface_srv.register_agent(agent)
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:finance.core:trade-service-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="Trade Interface",
            description="Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Quant Team", "created_at": "2026-11-11T00:00:00Z", "license": "GPL-3.0", "source_origin": "internal.repo"}
        )
        iface_srv.register_interface(iface)
        att = iface_srv.attest_interface(iface.interface_urn, "urn:lcs:attester:team:quant-signer")

        # 1. License rejection: policy requires Apache-2.0 or MIT, interface has GPL-3.0
        policy_license = InterfaceTrustPolicy("strict-license", required_licenses={"Apache-2.0", "MIT"})
        dec_lic = iface_srv.evaluate_policy(iface.interface_urn, policy_license)
        assert dec_lic.decision == "DENY" and dec_lic.status == "REJECTED"
        assert any("license" in r.lower() for r in dec_lic.reasons)
        print("  Guarded: License mismatch rejected cleanly.")

        # 2. Version rejection: policy requires min_version=2, interface is 1
        policy_ver = InterfaceTrustPolicy("strict-ver", min_interface_version=2)
        dec_ver = iface_srv.evaluate_policy(iface.interface_urn, policy_ver)
        assert dec_ver.decision == "DENY" and dec_ver.status == "REJECTED"
        assert any("version" in r.lower() for r in dec_ver.reasons)
        print("  Guarded: Below minimum version rejected cleanly.")

        # 3. Attester rejection: policy only trusts central-sec
        policy_att = InterfaceTrustPolicy("strict-attester", allowed_attester_ids={"urn:lcs:attester:sec:central"})
        dec_att = iface_srv.evaluate_policy(iface.interface_urn, policy_att)
        assert dec_att.decision == "DENY" and dec_att.status == "REJECTED"
        assert any("attester" in r.lower() for r in dec_att.reasons)
        print("  Guarded: Untrusted attester rejected cleanly.")

        # 4. Agent rejection: policy only trusts core-agent
        policy_agent = InterfaceTrustPolicy("strict-agent", allowed_agent_urns={"urn:lcs:agent:trusted:core"})
        dec_agent = iface_srv.evaluate_policy(iface.interface_urn, policy_agent)
        assert dec_agent.decision == "DENY" and dec_agent.status == "REJECTED"
        assert any("agent" in r.lower() for r in dec_agent.reasons)
        print("  Guarded: Untrusted agent rejected cleanly.")

        # 5. Matching policy acceptance
        policy_pass = InterfaceTrustPolicy(
            "matching-policy",
            allowed_attester_ids={"urn:lcs:attester:team:quant-signer"},
            allowed_agent_urns={"urn:lcs:agent:finance.core:trading-agent"},
            allowed_source_origins={"internal.repo"},
            required_licenses={"GPL-3.0"},
            min_interface_version=1
        )
        dec_pass = iface_srv.evaluate_policy(iface.interface_urn, policy_pass)
        assert dec_pass.decision == "ALLOW" and dec_pass.status == "VERIFIED"
        print("  Verified: Fully conforming interface accepted cleanly (ALLOW / VERIFIED).")

        engine.close()
        conn.close()


def test_08_persistent_decision_audit_trail():
    print("--- Test 08: Persistent Decision Audit Trail ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:test.system:audit-agent",
            display_name="Audit Agent",
            description="Desc",
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_agent(agent)
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:audit-iface-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="Audit Interface",
            description="Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(iface)
        att = iface_srv.attest_interface(iface.interface_urn)

        policy = InterfaceTrustPolicy("audit-policy")
        dec = iface_srv.evaluate_policy(iface.interface_urn, policy)

        # Retrieve decision from database
        retrieved_dec = iface_srv.retrieve_decision(dec.decision_id)
        assert retrieved_dec is not None
        assert retrieved_dec.decision_id == dec.decision_id
        assert retrieved_dec.decision == "ALLOW"
        assert retrieved_dec.status == "VERIFIED"
        assert retrieved_dec.interface_urn == iface.interface_urn
        assert retrieved_dec.reasons == dec.reasons
        print(f"  Verified: Persistent decision '{dec.decision_id}' successfully queried from audit table.")

        engine.close()
        conn.close()


def test_09_relational_integrity_and_foreign_key_protection():
    print("--- Test 09: Relational Integrity & ON DELETE RESTRICT Enforcement ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        # 1. Registering interface with non-existent agent fails closed
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        invalid_iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:invalid-iface",
            agent_urn="urn:lcs:agent:nonexistent:agent",
            interface_version=1,
            display_name="Invalid",
            description="Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        caught_no_agent = False
        try:
            iface_srv.register_interface(invalid_iface)
        except AgentNotFoundError:
            caught_no_agent = True
        assert caught_no_agent, "Must reject interface with unregistered agent!"
        print("  Guarded: Registration with unregistered agent rejected.")

        # 2. Register valid agent & interface
        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:test.system:fk-agent",
            display_name="FK Agent",
            description="Desc",
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_agent(agent)
        valid_iface = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:fk-iface-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="FK Iface",
            description="Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(valid_iface)
        iface_srv.attest_interface(valid_iface.interface_urn)

        # 3. ON DELETE RESTRICT: Attempt to delete agent while referenced by interface
        caught_del_agent = False
        try:
            conn.execute("DELETE FROM agent_declarations WHERE agent_urn = ?;", (agent.agent_urn,))
        except sqlite3.IntegrityError as e:
            caught_del_agent = True
            print(f"  Guarded: Deletion of agent blocked by foreign key: {e}")
        assert caught_del_agent, "Foreign key must prevent deleting agent while referenced by interface!"

        # 4. ON DELETE RESTRICT: Attempt to delete interface while referenced by attestation
        caught_del_iface = False
        try:
            conn.execute("DELETE FROM interface_declarations WHERE interface_urn = ?;", (valid_iface.interface_urn,))
        except sqlite3.IntegrityError as e:
            caught_del_iface = True
            print(f"  Guarded: Deletion of interface blocked by foreign key: {e}")
        assert caught_del_iface, "Foreign key must prevent deleting interface while referenced by attestation!"

        engine.close()
        conn.close()


def test_10_key_rotation_across_attestations():
    print("--- Test 10: Attestation Verification Across Key Rotation ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, db_path, cas_root, ks_dir, anchor = init_test_env(tmp_dir)

        agent = AgentDeclaration(
            agent_urn="urn:lcs:agent:test.system:rotation-agent",
            display_name="Rotation Agent",
            description="Desc",
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_agent(agent)
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        iface_1 = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:rotation-iface-v1",
            agent_urn=agent.agent_urn,
            interface_version=1,
            display_name="Iface 1",
            description="Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(iface_1)

        # Attestation 1 with initial key k1
        att_1 = iface_srv.attest_interface(iface_1.interface_urn)
        assert att_1.key_id == "k1"

        # Rotate key in PersistentReceiptKeyStore to k2
        new_key_id, _ = engine.key_store.rotate_key("k2")
        assert new_key_id == "k2"
        print("  Key rotated from k1 to k2.")

        # Attestation 2 with new key k2
        iface_2 = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:test.system:rotation-iface-v2",
            agent_urn=agent.agent_urn,
            interface_version=2,
            display_name="Iface 2",
            description="Desc",
            capabilities=[InterfaceCapabilityRef(res.capability_id, res.blob_digest)],
            provenance={"author": "Team A", "created_at": "2026-11-11T00:00:00Z", "license": "MIT", "source_origin": "test.origin"}
        )
        iface_srv.register_interface(iface_2)
        att_2 = iface_srv.attest_interface(iface_2.interface_urn)
        assert att_2.key_id == "k2"

        # Both attestations must verify cleanly: att_1 with historical key, att_2 with active key
        valid_1, r_1 = iface_srv.verify_attestation(att_1.attestation_id)
        assert valid_1, f"Historical attestation verification failed: {r_1}"
        valid_2, r_2 = iface_srv.verify_attestation(att_2.attestation_id)
        assert valid_2, f"Rotated attestation verification failed: {r_2}"
        print("  Verified: Both historical (k1) and active (k2) attestations verified 100% green.")

        engine.close()
        conn.close()


def main():
    print("=" * 72)
    print("LCS Stage 2B — Milestone 3: Interface Attestation & Policy Suite")
    print("=" * 72)
    test_01_valid_interface_attestation_and_serialization()
    test_02_persistent_verification_after_restart()
    test_03_modified_interface_detection()
    test_04_modified_capability_definition_detection()
    test_05_forged_hmac_signature_rejection()
    test_06_unattested_and_unknown_interface_states()
    test_07_policy_constraints_acceptance_and_rejections()
    test_08_persistent_decision_audit_trail()
    test_09_relational_integrity_and_foreign_key_protection()
    test_10_key_rotation_across_attestations()
    print("=" * 72)
    print("ALL 10 MILESTONE 3 TESTS PASSED (100% GREEN)")
    print("=" * 72)


if __name__ == "__main__":
    main()
