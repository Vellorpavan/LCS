#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 4: Capability Discovery & MCP Working Demonstration
============================================================================
Demonstrates the full 8-step flow:
1. Start local MCP test server fixture running JSON-RPC 2.0 over stdio.
2. Discover available tools using tools/list across pagination boundaries.
3. Normalize MCP tool schemas into canonical LCS CapabilityDefinitions.
4. Register discovered capabilities in LCS CAS and relational storage (M2).
5. Apply M3 cryptographic attestation and explainable policy evaluation.
6. Index registered capabilities into SQLite FTS5 discovery engine.
7. Execute query: 'Find a capability that can read PDF documents'.
8. Return grounded results displaying provenance and verified trust status.
"""

import os
import sys
import json
import sqlite3
import tempfile
from typing import Dict, Any

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from cas_storage_engine_v2b import SecureCASStorageEngine
from capability_registry_v2b import CapabilityRegistrationService
from interface_policy_v2b import (
    InterfacePolicyService,
    InterfaceTrustPolicy
)
from capability_discovery_v2b import (
    CapabilityDiscoveryPipeline,
    DiscoveryIndexService
)


def run_m4_working_demonstration() -> Dict[str, Any]:
    print("=" * 76)
    print("LCS STAGE 2B — MILESTONE 4: CAPABILITY DISCOVERY & MCP DEMONSTRATION")
    print("=" * 76)

    demo_results = {}

    with tempfile.TemporaryDirectory() as tmp_dir:
        real_anchor = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_anchor, "cas")
        db_path = os.path.join(real_anchor, "lcs_v2b_m4.db")
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
        index_service = DiscoveryIndexService(conn)

        pipeline = CapabilityDiscoveryPipeline(
            conn=conn,
            cas_engine=cas_engine,
            cap_service=cap_service,
            iface_service=iface_service,
            index_service=index_service
        )

        # --------------------------------------------------------------------
        # Step 1: Start local MCP test server fixture
        # --------------------------------------------------------------------
        print("\n[STEP 1: LOCAL MCP SERVER LAUNCH]")
        server_script = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
        server_cmd = [sys.executable, server_script]
        server_name = "local-document-tools"
        print(f"  Target server: {server_name}")
        print(f"  Command line:  {' '.join(server_cmd)}")

        # Configure M3 trust policy for discovered tools
        trust_policy = InterfaceTrustPolicy(
            policy_name="mcp-discovered-tools-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        # --------------------------------------------------------------------
        # Steps 2-6: Discover, Normalize, Register, Attest, and Index
        # --------------------------------------------------------------------
        print("\n[STEPS 2-6: DISCOVERY, NORMALIZATION, REGISTRATION & ATTESTATION]")
        print("  Discovering tools via JSON-RPC 2.0 tools/list...")
        summary = pipeline.discover_and_register_mcp_server(
            command=server_cmd,
            server_name=server_name,
            trust_policy=trust_policy
        )

        print(f"  Discovered tools count: {len(summary.discovered_tools)}")
        for tool in summary.discovered_tools:
            print(f"    - Raw Tool: {tool.raw_name:24} -> Canonical: {tool.canonical_urn}")

        print(f"  Associated Interface:   {summary.interface_urn}")
        print(f"  Cryptographic Attestation ID: {summary.attestation_id}")
        print(f"  Policy Decision:        {summary.policy_decision.decision}")
        print(f"  Policy Trust Status:    {summary.policy_decision.status}")
        for r in summary.policy_decision.reasons:
            print(f"    * {r}")

        demo_results["discovery_summary"] = summary.to_dict()

        # --------------------------------------------------------------------
        # Steps 7-8: Grounded FTS5 Search
        # --------------------------------------------------------------------
        print("\n[STEPS 7-8: GROUNDED CAPABILITY DISCOVERY & SEARCH]")
        user_query = "Find a capability that can read PDF documents."
        print(f"  User Query: \"{user_query}\"")

        search_results = index_service.search(user_query)
        print(f"  Found {len(search_results)} grounded matching capability/capabilities:")

        formatted_results = []
        for res in search_results:
            res_dict = res.to_dict()
            formatted_results.append(res_dict)
            print("\n  --------------------------------------------------------")
            print(f"  URN:          {res.capability_urn}")
            print(f"  Name:         {res.name}")
            print(f"  Description:  {res.description}")
            print(f"  Category:     {res.category}")
            print(f"  Trust Status: {res.trust_status}")
            print(f"  Origin:       {res.provenance_origin}")
            print(f"  Rank:         {res.rank:.4f}")
            print("  --------------------------------------------------------")

        demo_results["user_query"] = user_query
        demo_results["search_results"] = formatted_results

        # Verification assertion: read_pdf_document MUST be discovered, registered, and verified
        assert len(search_results) >= 1
        top_match = search_results[0]
        assert "read-pdf-document" in top_match.capability_urn
        assert top_match.trust_status == "VERIFIED"

        cas_engine.close()
        conn.close()

    print("\n" + "=" * 76)
    print("DEMONSTRATION COMPLETE: ALL 8 PHASES EXECUTED 100% GREEN")
    print("=" * 76)
    return demo_results


if __name__ == "__main__":
    results = run_m4_working_demonstration()
    print("\nFinal Demonstration Output JSON:")
    print(json.dumps(results, indent=2))
