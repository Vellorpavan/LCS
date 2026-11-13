#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 3: Runnable Vertical Slice Demonstration
================================================================
Demonstrates the complete end-to-end lifecycle of Interface Attestation & Policy:
Step 1: Create a representative agent declaration.
Step 2: Associate it with an existing M2 capability definition.
Step 3: Generate an interface attestation using PersistentReceiptKeyStore.
Step 4: Persist the attestation in SQLite and CAS.
Step 5: Restart the application (simulate fresh process/engine boundary).
Step 6: Verify the attestation across the restart boundary.
Step 7: Evaluate the interface against configured trust policy (Decision: ALLOW, Status: VERIFIED).
Step 8: Simulate adversarial modification of a capability definition blob.
Step 9: Confirm that the previous attestation fails validation (Decision: DENY, Status: REJECTED).
Step 10: Return a structured explanation of the policy decision and audit record.
"""

import os
import sys
import json
import sqlite3
import tempfile
from typing import Dict, Any

# Ensure local scratch directory is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from cas_storage_engine_v2b import SecureCASStorageEngine
from capability_registry_v2b import (
    CapabilityRegistrationService,
    CapabilityDefinition,
    EVAL_ADD_CAPABILITY_DEF
)
from interface_policy_v2b import (
    AgentDeclaration,
    InterfaceDeclaration,
    InterfaceCapabilityRef,
    InterfaceTrustPolicy,
    InterfacePolicyService
)


def run_vertical_slice_demo() -> Dict[str, Any]:
    print("=" * 76)
    print("LCS STAGE 2B — MILESTONE 3: RUNNABLE VERTICAL SLICE DEMONSTRATION")
    print("=" * 76)

    demo_results = {}

    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs_v2b_m3.db")
        key_store_dir = os.path.join(real_anchor, ".lcs_keys")

        # --------------------------------------------------------------------
        # Phase 1: Setup & Registration
        # --------------------------------------------------------------------
        print("\n[PHASE 1: REGISTRATION & ATTESTATION]")
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

        # Step 1: Create a representative agent declaration
        print("  Step 1: Creating agent declaration...")
        agent_decl = AgentDeclaration(
            agent_urn="urn:lcs:agent:assistant.core:calculator-agent",
            display_name="Core Mathematical Assistant Agent",
            description="Agent providing verified arithmetic capabilities.",
            provenance={
                "author": "LCS Systems Team",
                "created_at": "2026-11-11T00:00:00Z",
                "license": "Apache-2.0",
                "source_origin": "lcs.agent.math"
            }
        )
        iface_service.register_agent(agent_decl)
        print(f"    Agent registered: {agent_decl.agent_urn}")

        # Step 2: Register M2 capability definition and associate with interface
        print("  Step 2: Registering capability definition & associating with interface...")
        reg_result = cap_service.register_capability(EVAL_ADD_CAPABILITY_DEF)
        cap_urn = reg_result.capability_id
        cap_digest = reg_result.blob_digest
        print(f"    Capability registered: {cap_urn} (digest: {cap_digest[:16]}...)")

        interface_decl = InterfaceDeclaration(
            interface_urn="urn:lcs:interface:agent.assistant:math-service-v1",
            agent_urn=agent_decl.agent_urn,
            interface_version=1,
            display_name="Mathematical Operations Interface v1",
            description="Exposes verified declarative addition operations.",
            capabilities=[
                InterfaceCapabilityRef(
                    capability_urn=cap_urn,
                    expected_definition_digest=cap_digest
                )
            ],
            provenance={
                "author": "LCS Systems Team",
                "created_at": "2026-11-11T00:00:00Z",
                "license": "Apache-2.0",
                "source_origin": "lcs.interface.math"
            }
        )
        iface_service.register_interface(interface_decl)
        print(f"    Interface registered: {interface_decl.interface_urn} (v{interface_decl.interface_version})")

        # Step 3: Generate an interface attestation
        print("  Step 3: Generating cryptographic interface attestation...")
        attestation = iface_service.attest_interface(
            interface_urn=interface_decl.interface_urn,
            attester_id="urn:lcs:attester:security:local-authority"
        )
        print(f"    Attestation ID: {attestation.attestation_id}")
        print(f"    Key ID used: {attestation.key_id}")
        print(f"    HMAC Signature: {attestation.signature[:24]}...")

        # Step 4: Persist the attestation (already completed in attest_interface)
        print("  Step 4: Attestation persisted to SQLite & CAS storage.")

        # --------------------------------------------------------------------
        # Phase 2: Application Restart & Baseline Verification
        # --------------------------------------------------------------------
        print("\n[PHASE 2: APPLICATION RESTART & POLICY EVALUATION]")
        # Step 5: Restart the application or use a fresh process
        print("  Step 5: Simulating application restart (closing instances & opening fresh)...")
        cas_engine.close()
        conn.close()

        # Reopen fresh connections
        conn_restarted = sqlite3.connect(db_path)
        cas_engine_restarted = SecureCASStorageEngine(
            cas_root=cas_root,
            trusted_anchor=real_anchor,
            key_store_dir=key_store_dir
        )
        iface_service_restarted = InterfacePolicyService(conn_restarted, cas_engine_restarted)

        # Step 6: Verify the attestation
        print("  Step 6: Verifying attestation across restart boundary...")
        is_valid, verif_reasons = iface_service_restarted.verify_attestation(attestation.attestation_id)
        assert is_valid, f"Attestation verification failed after restart: {verif_reasons}"
        print("    Attestation verified successfully! Reasons:")
        for r in verif_reasons:
            print(f"      - {r}")

        # Step 7: Evaluate the interface against policy
        print("  Step 7: Evaluating interface against configured trust policy...")
        trust_policy = InterfaceTrustPolicy(
            policy_name="production-secure-math-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            allowed_agent_urns={"urn:lcs:agent:assistant.core:calculator-agent"},
            allowed_source_origins={"lcs.interface.math"},
            required_licenses={"Apache-2.0", "MIT"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        decision_baseline = iface_service_restarted.evaluate_policy(
            interface_urn=interface_decl.interface_urn,
            policy=trust_policy
        )
        print(f"    Policy Decision: {decision_baseline.decision}")
        print(f"    Policy Status:   {decision_baseline.status}")
        assert decision_baseline.decision == "ALLOW"
        assert decision_baseline.status == "VERIFIED"
        demo_results["baseline_decision"] = decision_baseline.to_dict()

        # --------------------------------------------------------------------
        # Phase 3: Adversarial Tampering & Detection
        # --------------------------------------------------------------------
        print("\n[PHASE 3: ADVERSARIAL TAMPERING & DETECTION]")
        # Step 8: Modify a capability definition or its digest on disk
        print("  Step 8: Simulating unauthorized mutation of capability definition in CAS...")
        cap_blob_path = os.path.join(cas_root, "objects", cap_digest[:2], cap_digest)
        os.chmod(cap_blob_path, 0o644)
        with open(cap_blob_path, "wb") as f:
            f.write(b"{\"tampered\": true, \"payload\": \"malicious_modification\"}")
        print(f"    Overwrote physical blob '{cap_digest[:16]}...' with tampered content.")

        # Step 9: Confirm that the previous attestation no longer validates
        print("  Step 9: Re-verifying attestation and re-evaluating policy...")
        is_valid_tampered, tampered_verif_reasons = iface_service_restarted.verify_attestation(attestation.attestation_id)
        assert not is_valid_tampered, "Attestation MUST fail verification after blob tampering!"
        print(f"    Attestation invalidation confirmed: {tampered_verif_reasons}")

        decision_tampered = iface_service_restarted.evaluate_policy(
            interface_urn=interface_decl.interface_urn,
            policy=trust_policy
        )
        print(f"    Policy Decision: {decision_tampered.decision}")
        print(f"    Policy Status:   {decision_tampered.status}")
        assert decision_tampered.decision == "DENY"
        assert decision_tampered.status == "REJECTED"
        demo_results["tampered_decision"] = decision_tampered.to_dict()

        # Step 10: Return a structured explanation of the result
        print("\n[PHASE 4: STRUCTURED EXPLANATION & AUDIT TRAIL]")
        print("  Step 10: Structured explanation of policy decisions:")
        print(json.dumps(demo_results, indent=2))

        cas_engine_restarted.close()
        conn_restarted.close()

    print("\n" + "=" * 76)
    print("VERTICAL SLICE DEMONSTRATION COMPLETE: ALL 10 STEPS VERIFIED 100% GREEN")
    print("=" * 76)
    return demo_results


if __name__ == "__main__":
    run_vertical_slice_demo()
