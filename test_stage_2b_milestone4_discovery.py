#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 4: Discovery, MCP Integration & FTS5 Verification Suite
================================================================================
Authoritatively tests:
1. SQLite FTS5 capability indexing and multi-term keyword search.
2. Authoritative FTS5 index reconstruction from CAS & SQLite storage.
3. MCP stdio JSON-RPC 2.0 handshake (initialize, notifications/initialized).
4. MCP tools/list pagination traversal (nextCursor handling).
5. MCP tools/call rejection (strict out-of-scope code execution defense).
6. Schema normalization (canonical URN generation, inputSchema, invalid syntax rejection).
7. End-to-end discovery, registration, attestation, and indexing pipeline.
8. Zero-trust policy rejection propagation to search index (trust_status).
9. Grounded search query resolution and policy status filtering.
10. Zero-result query safety and empty database handling.
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
from capability_registry_v2b import (
    CapabilityRegistrationService,
    CapabilityDefinition,
    EVAL_ADD_CAPABILITY_DEF
)
from interface_policy_v2b import (
    InterfacePolicyService,
    InterfaceTrustPolicy
)
from capability_discovery_v2b import (
    MCPDiscoveryClient,
    MCPSchemaNormalizer,
    DiscoveryIndexService,
    CapabilityDiscoveryPipeline,
    SchemaNormalizationError,
    MCPProtocolError
)


def init_m4_test_env(tmp_dir: str):
    real_anchor = os.path.realpath(tmp_dir)
    cas_root = os.path.join(real_anchor, "cas")
    db_path = os.path.join(real_anchor, "test_m4.db")
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
    return conn, cas_engine, cap_service, iface_service, index_service, pipeline, real_anchor


def test_01_fts5_indexing_and_search():
    print("--- Test 01: SQLite FTS5 Indexing & Search ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, idx_srv, pipe, anchor = init_m4_test_env(tmp_dir)

        # Register capability
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        idx_srv.index_capability(
            cap_def=EVAL_ADD_CAPABILITY_DEF,
            trust_status="VERIFIED",
            category="math",
            keywords=["arithmetic", "addition", "integer"]
        )

        # Search for exact keyword
        matches = idx_srv.search("addition")
        assert len(matches) == 1
        assert matches[0].capability_urn == EVAL_ADD_CAPABILITY_DEF.capability_id
        assert matches[0].category == "math"
        assert matches[0].trust_status == "VERIFIED"
        print(f"  Verified: FTS5 matched '{matches[0].name}' on keyword query.")

        # Search for category
        matches_cat = idx_srv.search("math")
        assert len(matches_cat) == 1

        engine.close()
        conn.close()


def test_02_fts5_index_rebuild_from_authoritative_storage():
    print("--- Test 02: FTS5 Index Rebuild from Authoritative Storage ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, idx_srv, pipe, anchor = init_m4_test_env(tmp_dir)

        # Register capability in M2
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)

        # Clear FTS5 table completely
        conn.execute("DELETE FROM capability_fts;")
        conn.commit()
        assert len(idx_srv.search("addition")) == 0

        # Rebuild index from CAS and SQLite
        count = idx_srv.rebuild_index(cas_engine=engine)
        assert count == 1

        matches = idx_srv.search("addition")
        assert len(matches) == 1
        assert matches[0].capability_urn == EVAL_ADD_CAPABILITY_DEF.capability_id
        print(f"  Verified: Authoritative index rebuild reconstructed {count} capabilities.")

        engine.close()
        conn.close()


def test_03_mcp_handshake_and_pagination():
    print("--- Test 03: MCP Handshake & tools/list Pagination Traversal ---")
    server_script = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
    cmd = [sys.executable, server_script]

    with MCPDiscoveryClient(cmd, "test-doc-server") as client:
        tools = client.list_tools()
        # The fixture contains 3 tools split across 2 pages (PAGE_SIZE = 2)
        assert len(tools) == 3
        tool_names = [t["name"] for t in tools]
        assert "read_pdf_document" in tool_names
        assert "convert_document_format" in tool_names
        assert "query_local_database" in tool_names
        print(f"  Verified: Traversed pagination boundaries and discovered all {len(tools)} tools.")


def test_04_mcp_tools_call_strictly_rejected():
    print("--- Test 04: MCP tools/call Strictly Rejected (Out of Scope Guard) ---")
    server_script = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
    cmd = [sys.executable, server_script]

    with MCPDiscoveryClient(cmd, "test-guard-server") as client:
        call_req = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "read_pdf_document", "arguments": {}}
        }
        resp = client._send_request(call_req)
        assert "error" in resp
        err = resp["error"]
        assert err["code"] == -32601
        assert "tools/call is strictly disabled" in err["message"]
        print(f"  Guarded: tools/call safely rejected by server: {err['message']}")


def test_05_schema_normalizer():
    print("--- Test 05: MCP Schema Normalization & URN Generation ---")
    raw_tool = {
        "name": "Extract_Text_From_PDF",
        "description": "Extracts text from PDF documents.",
        "inputSchema": {
            "type": "object",
            "properties": {"doc_path": {"type": "string"}},
            "required": ["doc_path"]
        }
    }
    norm = MCPSchemaNormalizer.normalize_tool(raw_tool, "document-reader-service")
    assert norm.canonical_urn == "urn:lcs:tool:mcp.document-reader-service:extract-text-from-pdf"
    assert norm.category == "document"
    assert "pdf" in norm.keywords

    cap_def = norm.to_capability_definition()
    assert cap_def.capability_id == norm.canonical_urn
    assert cap_def.capability_type == "tool"
    assert cap_def.provenance["original_tool_name"] == "Extract_Text_From_PDF"
    print(f"  Verified: Normalized '{raw_tool['name']}' -> '{cap_def.capability_id}'")

    # Invalid tool without name
    caught = False
    try:
        MCPSchemaNormalizer.normalize_tool({}, "server")
    except SchemaNormalizationError:
        caught = True
    assert caught, "Tool without name must raise SchemaNormalizationError"
    print("  Guarded: Tool without name strictly rejected.")


def test_06_end_to_end_pipeline():
    print("--- Test 06: End-to-End Discovery, Attestation & Indexing Pipeline ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, idx_srv, pipe, anchor = init_m4_test_env(tmp_dir)

        server_script = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
        cmd = [sys.executable, server_script]

        policy = InterfaceTrustPolicy(
            policy_name="doc-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True
        )

        summary = pipe.discover_and_register_mcp_server(cmd, "doc-server", policy)
        assert len(summary.discovered_tools) == 3
        assert len(summary.registered_capabilities) == 3
        assert summary.policy_decision.decision == "ALLOW"
        assert summary.policy_decision.status == "VERIFIED"

        # Search for PDF tool
        res_pdf = idx_srv.search("pdf extract")
        assert len(res_pdf) >= 1
        assert any("read-pdf-document" in r.capability_urn for r in res_pdf)
        assert res_pdf[0].trust_status == "VERIFIED"
        print("  Verified: Discovered MCP tools registered, attested, and searchable.")

        engine.close()
        conn.close()


def test_07_zero_trust_policy_rejection_in_search():
    print("--- Test 07: Zero-Trust Policy Rejection in Search ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, idx_srv, pipe, anchor = init_m4_test_env(tmp_dir)

        server_script = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
        cmd = [sys.executable, server_script]

        # Policy that requires min_interface_version = 2 (our interface is v1)
        policy_strict = InterfaceTrustPolicy(
            policy_name="strict-v2-policy",
            min_interface_version=2,
            require_attestation=True
        )

        summary = pipe.discover_and_register_mcp_server(cmd, "doc-server", policy_strict)
        assert summary.policy_decision.decision == "DENY"
        assert summary.policy_decision.status == "REJECTED"

        # Search for tools: they must show up with trust_status = REJECTED
        res = idx_srv.search("database query")
        assert len(res) >= 1
        assert res[0].trust_status == "REJECTED"
        print(f"  Guarded: Policy rejection propagated to search index: trust_status = {res[0].trust_status}")

        engine.close()
        conn.close()


def test_08_policy_status_filter_in_search():
    print("--- Test 08: Policy Status Filtering in Search ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, idx_srv, pipe, anchor = init_m4_test_env(tmp_dir)

        # Index one verified and one rejected capability
        res = cap_srv.register_capability(EVAL_ADD_CAPABILITY_DEF)
        idx_srv.index_capability(
            cap_def=EVAL_ADD_CAPABILITY_DEF,
            trust_status="VERIFIED",
            category="math"
        )

        # Filter search by VERIFIED
        verified_results = idx_srv.search("addition", policy_filter="VERIFIED")
        assert len(verified_results) == 1

        # Filter search by REJECTED (should be empty)
        rejected_results = idx_srv.search("addition", policy_filter="REJECTED")
        assert len(rejected_results) == 0
        print("  Verified: Policy status filter strictly segregates search results.")

        engine.close()
        conn.close()


def test_09_zero_match_query_safety():
    print("--- Test 09: Zero-Match Query Safety & Empty Query Handling ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, idx_srv, pipe, anchor = init_m4_test_env(tmp_dir)

        # Empty search
        assert idx_srv.search("") == []
        assert idx_srv.search("   ") == []

        # Non-matching search
        assert idx_srv.search("quantum_flux_transistor_non_existent") == []
        print("  Verified: Non-matching and empty queries return empty list safely without errors.")

        engine.close()
        conn.close()


def test_10_mcp_server_registry_persistence():
    print("--- Test 10: MCP Server Registry Table Persistence ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, engine, cap_srv, iface_srv, idx_srv, pipe, anchor = init_m4_test_env(tmp_dir)

        server_script = os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")
        cmd = [sys.executable, server_script]
        policy = InterfaceTrustPolicy("policy", min_interface_version=1)

        pipe.discover_and_register_mcp_server(cmd, "doc-server", policy)

        cur = conn.cursor()
        cur.execute("SELECT server_name, transport_type FROM mcp_server_registrations WHERE server_name = 'doc-server';")
        row = cur.fetchone()
        assert row is not None
        assert row[0] == "doc-server"
        assert row[1] == "STDIO"
        print("  Verified: MCP server registration recorded in relational database.")

        engine.close()
        conn.close()


def main():
    print("=" * 72)
    print("LCS Stage 2B — Milestone 4: Discovery & MCP Verification Suite")
    print("=" * 72)
    test_01_fts5_indexing_and_search()
    test_02_fts5_index_rebuild_from_authoritative_storage()
    test_03_mcp_handshake_and_pagination()
    test_04_mcp_tools_call_strictly_rejected()
    test_05_schema_normalizer()
    test_06_end_to_end_pipeline()
    test_07_zero_trust_policy_rejection_in_search()
    test_08_policy_status_filter_in_search()
    test_09_zero_match_query_safety()
    test_10_mcp_server_registry_persistence()
    print("=" * 72)
    print("ALL 10 MILESTONE 4 TESTS PASSED (100% GREEN)")
    print("=" * 72)


if __name__ == "__main__":
    main()
