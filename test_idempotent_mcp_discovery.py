#!/usr/bin/env python3
"""
LCS — Idempotent MCP Discovery Verification Suite
=================================================
Verifies that discovering the same unchanged MCP server multiple times
succeeds safely without creating duplicate agents, interfaces, capabilities,
or unnecessary attestations, while preserving original creation timestamps
and strictly rejecting genuine provenance conflicts.

Tests:
  1. Triple Discovery Idempotency & Count Invariance (Runs 1, 2, 3)
  2. Timestamp Preservation Across Agent, Interface & Capabilities
  3. Rejection of Genuine Agent Provenance Conflict (author, license, origin)
  4. Rejection of Genuine Interface Definition Conflict (capabilities, provenance)
  5. Attestation Verification After Repeated Discovery Across Engine Restarts
  6. FTS5 Index Consistency Across Repeated Discoveries
"""

import os
import sys
import json
import sqlite3
import tempfile
import time
from typing import Dict, Any

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from cas_storage_engine_v2b import SecureCASStorageEngine
from capability_registry_v2b import CapabilityRegistrationService, CapabilityDefinition
from interface_policy_v2b import (
    InterfacePolicyService,
    AgentDeclaration,
    InterfaceDeclaration,
    InterfaceCapabilityRef,
    InterfaceTrustPolicy,
    InterfacePolicyError
)
from capability_discovery_v2b import (
    CapabilityDiscoveryPipeline,
    DiscoveryIndexService
)


def init_isolated_env(tmp_dir: str):
    real_anchor = os.path.realpath(tmp_dir)
    cas_root = os.path.join(real_anchor, "cas")
    db_path = os.path.join(real_anchor, "lcs_test.db")
    key_store_dir = os.path.join(real_anchor, "keys")

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")

    # Apply all 4 migrations
    for schema_file in ("lcs_schema_v2b.sql", "lcs_schema_m3_migration.sql", "lcs_schema_m4_migration.sql", "lcs_schema_m5_sqlite_compat.sql"):
        p = os.path.join(CURRENT_DIR, schema_file)
        with open(p, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.commit()

    cas_engine = SecureCASStorageEngine(
        cas_root=cas_root,
        trusted_anchor=real_anchor,
        key_store_dir=key_store_dir
    )
    cap_srv = CapabilityRegistrationService(conn, cas_engine)
    iface_srv = InterfacePolicyService(conn, cas_engine, cap_srv)
    idx_srv = DiscoveryIndexService(conn)
    pipe = CapabilityDiscoveryPipeline(
        conn=conn,
        cas_engine=cas_engine,
        cap_service=cap_srv,
        iface_service=iface_srv,
        index_service=idx_srv
    )
    return conn, cas_engine, cap_srv, iface_srv, idx_srv, pipe, db_path, cas_root, key_store_dir, real_anchor


def get_system_counts(conn: sqlite3.Connection, cas_root: str) -> Dict[str, int]:
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM capabilities;")
    cap_count = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM agent_declarations;")
    agent_count = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM interface_declarations;")
    iface_count = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM interface_attestations;")
    attest_count = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM capability_fts;")
    fts_count = cur.fetchone()[0]

    objects_dir = os.path.join(cas_root, "objects")
    cas_count = 0
    if os.path.exists(objects_dir):
        for _, _, files in os.walk(objects_dir):
            cas_count += len(files)

    return {
        "capabilities": cap_count,
        "agents": agent_count,
        "interfaces": iface_count,
        "attestations": attest_count,
        "fts_indexed": fts_count,
        "cas_objects": cas_count
    }


def test_01_triple_discovery_idempotency_and_counts():
    print("--- Test 01: Triple Discovery Idempotency & Count Invariance (Runs 1, 2, 3) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, cas_engine, cap_srv, iface_srv, idx_srv, pipe, db_path, cas_root, ks_dir, anchor = init_isolated_env(tmp_dir)
        try:
            server_cmd = [sys.executable, os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")]
            server_name = "test-doc-tools"
            policy = InterfaceTrustPolicy(
                policy_name="test-policy",
                allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
                min_interface_version=1,
                require_attestation=True
            )

            # Discovery Run 1 (Initial)
            s1 = pipe.discover_and_register_mcp_server(command=server_cmd, server_name=server_name, trust_policy=policy)
            assert len(s1.discovered_tools) == 3
            assert s1.policy_decision.decision == "ALLOW"
            assert s1.policy_decision.status == "VERIFIED"
            counts1 = get_system_counts(conn, cas_root)
            print(f"  Run 1 Counts: {counts1}")

            # Sleep briefly to ensure clock ticks forward
            time.sleep(1.0)

            # Discovery Run 2 (Repeated)
            s2 = pipe.discover_and_register_mcp_server(command=server_cmd, server_name=server_name, trust_policy=policy)
            assert len(s2.discovered_tools) == 3
            assert s2.policy_decision.decision == "ALLOW"
            assert s2.policy_decision.status == "VERIFIED"
            counts2 = get_system_counts(conn, cas_root)
            print(f"  Run 2 Counts: {counts2}")

            time.sleep(1.0)

            # Discovery Run 3 (Repeated Again)
            s3 = pipe.discover_and_register_mcp_server(command=server_cmd, server_name=server_name, trust_policy=policy)
            assert len(s3.discovered_tools) == 3
            assert s3.policy_decision.decision == "ALLOW"
            assert s3.policy_decision.status == "VERIFIED"
            counts3 = get_system_counts(conn, cas_root)
            print(f"  Run 3 Counts: {counts3}")

            # Assert counts remain identical across all 3 runs
            assert counts1 == counts2 == counts3, f"Count drift detected! Run1: {counts1}, Run2: {counts2}, Run3: {counts3}"
            assert s1.attestation_id == s2.attestation_id == s3.attestation_id, (
                f"Attestation ID changed! s1={s1.attestation_id}, s2={s2.attestation_id}, s3={s3.attestation_id}"
            )
            print("  Verified: Triple discovery completed with 100% count invariance and zero duplicate records.")
        finally:
            try:
                cas_engine.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


def test_02_preservation_of_original_timestamps():
    print("--- Test 02: Timestamp Preservation Across Agent, Interface & Capabilities ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, cas_engine, cap_srv, iface_srv, idx_srv, pipe, db_path, cas_root, ks_dir, anchor = init_isolated_env(tmp_dir)
        try:
            server_cmd = [sys.executable, os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")]
            server_name = "test-doc-tools"
            policy = InterfaceTrustPolicy(
                policy_name="test-policy",
                allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
                min_interface_version=1
            )

            s1 = pipe.discover_and_register_mcp_server(server_cmd, server_name, policy)

            # Record original timestamps from DB
            cur = conn.cursor()
            cur.execute("SELECT provenance_json FROM agent_declarations WHERE agent_urn = ?;", (s1.agent_urn,))
            agent_prov1 = json.loads(cur.fetchone()[0])
            agent_ts1 = agent_prov1["created_at"]

            cur.execute("SELECT declaration_blob_digest FROM interface_declarations WHERE interface_urn = ?;", (s1.interface_urn,))
            iface_dig1 = cur.fetchone()[0]
            iface_data1 = json.loads(cas_engine.read_blob(iface_dig1).decode("utf-8"))
            iface_ts1 = iface_data1["provenance"]["created_at"]

            cap_urn = "urn:lcs:tool:mcp.test-doc-tools:read-pdf-document"
            cur.execute("SELECT definition_blob_digest FROM capability_declarations WHERE capability_urn = ?;", (cap_urn,))
            cap_dig1 = cur.fetchone()[0]
            cap_data1 = json.loads(cas_engine.read_blob(cap_dig1).decode("utf-8"))
            cap_ts1 = cap_data1["provenance"]["created_at"]

            # Advance clock and re-discover
            time.sleep(1.1)
            s2 = pipe.discover_and_register_mcp_server(server_cmd, server_name, policy)

            # Fetch timestamps after second discovery
            cur.execute("SELECT provenance_json FROM agent_declarations WHERE agent_urn = ?;", (s2.agent_urn,))
            agent_prov2 = json.loads(cur.fetchone()[0])
            agent_ts2 = agent_prov2["created_at"]

            cur.execute("SELECT declaration_blob_digest FROM interface_declarations WHERE interface_urn = ?;", (s2.interface_urn,))
            iface_dig2 = cur.fetchone()[0]
            iface_data2 = json.loads(cas_engine.read_blob(iface_dig2).decode("utf-8"))
            iface_ts2 = iface_data2["provenance"]["created_at"]

            cur.execute("SELECT definition_blob_digest FROM capability_declarations WHERE capability_urn = ?;", (cap_urn,))
            cap_dig2 = cur.fetchone()[0]
            cap_data2 = json.loads(cas_engine.read_blob(cap_dig2).decode("utf-8"))
            cap_ts2 = cap_data2["provenance"]["created_at"]

            assert agent_ts1 == agent_ts2, f"Agent created_at drifted: {agent_ts1} != {agent_ts2}"
            assert iface_ts1 == iface_ts2, f"Interface created_at drifted: {iface_ts1} != {iface_ts2}"
            assert cap_ts1 == cap_ts2, f"Capability created_at drifted: {cap_ts1} != {cap_ts2}"
            assert iface_dig1 == iface_dig2, f"Interface definition digest changed: {iface_dig1} != {iface_dig2}"
            assert cap_dig1 == cap_dig2, f"Capability definition digest changed: {cap_dig1} != {cap_dig2}"
            print(f"  Verified: Original creation timestamps preserved exactly (Agent: {agent_ts1}, Iface: {iface_ts1}, Cap: {cap_ts1}).")
        finally:
            try:
                cas_engine.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


def test_03_rejection_of_genuine_agent_provenance_conflict():
    print("--- Test 03: Rejection of Genuine Agent Provenance Conflict ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, cas_engine, cap_srv, iface_srv, idx_srv, pipe, db_path, cas_root, ks_dir, anchor = init_isolated_env(tmp_dir)
        try:
            agent_1 = AgentDeclaration(
                agent_urn="urn:lcs:agent:security.dept:scanner",
                display_name="Security Scanner Agent",
                description="Performs vulnerability scanning",
                provenance={
                    "author": "Security Engineering",
                    "created_at": "2026-01-01T00:00:00Z",
                    "license": "Apache-2.0",
                    "source_origin": "https://sec.corp/scanner"
                }
            )
            iface_srv.register_agent(agent_1)

            # 1. Idempotent re-registration with same stable attributes but new timestamp
            agent_same = AgentDeclaration(
                agent_urn="urn:lcs:agent:security.dept:scanner",
                display_name="Security Scanner Agent",
                description="Performs vulnerability scanning",
                provenance={
                    "author": "Security Engineering",
                    "created_at": "2026-02-02T12:00:00Z",  # New timestamp
                    "license": "Apache-2.0",
                    "source_origin": "https://sec.corp/scanner"
                }
            )
            res_same = iface_srv.register_agent(agent_same)
            assert res_same.provenance["created_at"] == "2026-01-01T00:00:00Z"
            print("  Verified: Idempotent agent re-registration succeeded and preserved original timestamp.")

            # 2. Conflict: Author changed
            agent_diff_author = AgentDeclaration(
                agent_urn="urn:lcs:agent:security.dept:scanner",
                display_name="Security Scanner Agent",
                description="Performs vulnerability scanning",
                provenance={
                    "author": "Rogue Entity",  # Changed!
                    "created_at": "2026-02-02T12:00:00Z",
                    "license": "Apache-2.0",
                    "source_origin": "https://sec.corp/scanner"
                }
            )
            try:
                iface_srv.register_agent(agent_diff_author)
                assert False, "Failed to reject conflicting agent author"
            except InterfacePolicyError as e:
                assert "already registered with different provenance" in str(e)
                print(f"  Guarded: Conflicting agent author strictly rejected: {e}")

            # 3. Conflict: License changed
            agent_diff_license = AgentDeclaration(
                agent_urn="urn:lcs:agent:security.dept:scanner",
                display_name="Security Scanner Agent",
                description="Performs vulnerability scanning",
                provenance={
                    "author": "Security Engineering",
                    "created_at": "2026-02-02T12:00:00Z",
                    "license": "GPL-3.0",  # Changed!
                    "source_origin": "https://sec.corp/scanner"
                }
            )
            try:
                iface_srv.register_agent(agent_diff_license)
                assert False, "Failed to reject conflicting agent license"
            except InterfacePolicyError as e:
                assert "already registered with different provenance" in str(e)
                print(f"  Guarded: Conflicting agent license strictly rejected: {e}")

            # 4. Conflict: Display name changed
            agent_diff_name = AgentDeclaration(
                agent_urn="urn:lcs:agent:security.dept:scanner",
                display_name="Malicious Phishing Agent",  # Changed!
                description="Performs vulnerability scanning",
                provenance={
                    "author": "Security Engineering",
                    "created_at": "2026-02-02T12:00:00Z",
                    "license": "Apache-2.0",
                    "source_origin": "https://sec.corp/scanner"
                }
            )
            try:
                iface_srv.register_agent(agent_diff_name)
                assert False, "Failed to reject conflicting agent display name"
            except InterfacePolicyError as e:
                assert "already registered with different provenance" in str(e)
                print(f"  Guarded: Conflicting agent display name strictly rejected: {e}")
        finally:
            try:
                cas_engine.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


def test_04_rejection_of_genuine_interface_conflict():
    print("--- Test 04: Rejection of Genuine Interface Definition Conflict ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, cas_engine, cap_srv, iface_srv, idx_srv, pipe, db_path, cas_root, ks_dir, anchor = init_isolated_env(tmp_dir)
        try:
            # Register Agent and 2 Capabilities
            agent = AgentDeclaration(
                agent_urn="urn:lcs:agent:test.tools:server",
                display_name="Test Server",
                description="Server",
                provenance={"author": "Team A", "created_at": "2026-01-01T00:00:00Z", "license": "MIT", "source_origin": "test"}
            )
            iface_srv.register_agent(agent)

            cap_def_1 = CapabilityDefinition(
                capability_id="urn:lcs:tool:test.tools:tool-one",
                display_name="Tool One",
                description="First tool",
                capability_type="tool",
                schema_version=1,
                input_interface_ref="urn:lcs:interface:schema:tool-one-in",
                output_interface_ref="urn:lcs:interface:schema:tool-one-out",
                provenance={"author": "Team A", "created_at": "2026-01-01T00:00:00Z", "license": "MIT", "source_origin": "test"}
            )
            res1 = cap_srv.register_capability(cap_def_1)

            cap_def_2 = CapabilityDefinition(
                capability_id="urn:lcs:tool:test.tools:tool-two",
                display_name="Tool Two",
                description="Second tool",
                capability_type="tool",
                schema_version=1,
                input_interface_ref="urn:lcs:interface:schema:tool-two-in",
                output_interface_ref="urn:lcs:interface:schema:tool-two-out",
                provenance={"author": "Team A", "created_at": "2026-01-01T00:00:00Z", "license": "MIT", "source_origin": "test"}
            )
            res2 = cap_srv.register_capability(cap_def_2)

            # Register interface binding Tool One
            iface_1 = InterfaceDeclaration(
                interface_urn="urn:lcs:interface:test.tools:interface-v1",
                agent_urn=agent.agent_urn,
                interface_version=1,
                display_name="Toolset Interface",
                description="Interface description",
                capabilities=[InterfaceCapabilityRef(res1.capability_id, res1.blob_digest)],
                provenance={"author": "Team A", "created_at": "2026-01-01T00:00:00Z", "license": "MIT", "source_origin": "test"}
            )
            iface_srv.register_interface(iface_1)

            # 1. Idempotent re-registration of exact same interface with different created_at
            iface_same = InterfaceDeclaration(
                interface_urn="urn:lcs:interface:test.tools:interface-v1",
                agent_urn=agent.agent_urn,
                interface_version=1,
                display_name="Toolset Interface",
                description="Interface description",
                capabilities=[InterfaceCapabilityRef(res1.capability_id, res1.blob_digest)],
                provenance={"author": "Team A", "created_at": "2026-03-03T00:00:00Z", "license": "MIT", "source_origin": "test"}
            )
            res_same = iface_srv.register_interface(iface_same)
            assert res_same.provenance["created_at"] == "2026-01-01T00:00:00Z"
            print("  Verified: Idempotent interface re-registration succeeded and preserved original timestamp.")

            # 2. Conflict: Bound capability changed (binding Tool Two instead of Tool One)
            iface_diff_caps = InterfaceDeclaration(
                interface_urn="urn:lcs:interface:test.tools:interface-v1",
                agent_urn=agent.agent_urn,
                interface_version=1,
                display_name="Toolset Interface",
                description="Interface description",
                capabilities=[InterfaceCapabilityRef(res2.capability_id, res2.blob_digest)],  # Changed!
                provenance={"author": "Team A", "created_at": "2026-01-01T00:00:00Z", "license": "MIT", "source_origin": "test"}
            )
            try:
                iface_srv.register_interface(iface_diff_caps)
                assert False, "Failed to reject interface with conflicting capability bindings"
            except InterfacePolicyError as e:
                assert "different definition digest" in str(e)
                print(f"  Guarded: Conflicting capability bindings strictly rejected: {e}")

            # 3. Conflict: Author changed
            iface_diff_author = InterfaceDeclaration(
                interface_urn="urn:lcs:interface:test.tools:interface-v1",
                agent_urn=agent.agent_urn,
                interface_version=1,
                display_name="Toolset Interface",
                description="Interface description",
                capabilities=[InterfaceCapabilityRef(res1.capability_id, res1.blob_digest)],
                provenance={"author": "Rogue Team", "created_at": "2026-01-01T00:00:00Z", "license": "MIT", "source_origin": "test"}
            )
            try:
                iface_srv.register_interface(iface_diff_author)
                assert False, "Failed to reject interface with conflicting author"
            except InterfacePolicyError as e:
                assert "different definition digest" in str(e)
                print(f"  Guarded: Conflicting interface author strictly rejected: {e}")
        finally:
            try:
                cas_engine.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


def test_05_attestation_verification_after_repeated_discovery():
    print("--- Test 05: Attestation Verification After Repeated Discovery Across Engine Restarts ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, cas_engine, cap_srv, iface_srv, idx_srv, pipe, db_path, cas_root, ks_dir, anchor = init_isolated_env(tmp_dir)
        conn_restarted = None
        cas_restarted = None
        try:
            server_cmd = [sys.executable, os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")]
            server_name = "test-doc-tools"
            policy = InterfaceTrustPolicy(
                policy_name="test-policy",
                allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
                min_interface_version=1
            )

            # Run discovery multiple times
            s1 = pipe.discover_and_register_mcp_server(server_cmd, server_name, policy)
            s2 = pipe.discover_and_register_mcp_server(server_cmd, server_name, policy)
            s3 = pipe.discover_and_register_mcp_server(server_cmd, server_name, policy)

            att_id = s1.attestation_id

            # Verify attestation with live service
            valid, reasons = iface_srv.verify_attestation(att_id)
            assert valid, f"Live attestation verification failed: {reasons}"
            print(f"  Verified: Attestation '{att_id}' valid after 3 discovery runs.")

            # Simulate engine restart: close and re-open fresh connection and engine
            cas_engine.close()
            conn.close()
            conn = None
            cas_engine = None

            conn_restarted = sqlite3.connect(db_path)
            conn_restarted.execute("PRAGMA foreign_keys = ON;")
            cas_restarted = SecureCASStorageEngine(cas_root=cas_root, trusted_anchor=anchor, key_store_dir=ks_dir)
            iface_restarted = InterfacePolicyService(conn_restarted, cas_restarted)

            valid_restarted, reasons_restarted = iface_restarted.verify_attestation(att_id)
            assert valid_restarted, f"Restarted attestation verification failed: {reasons_restarted}"
            print(f"  Verified: Attestation '{att_id}' remains 100% valid after restart.")

            # Evaluate policy on restarted instance
            dec = iface_restarted.evaluate_policy(s1.interface_urn, policy)
            assert dec.decision == "ALLOW"
            assert dec.status == "VERIFIED"
            print("  Verified: Policy evaluation returns ALLOW / VERIFIED on restarted instance.")
        finally:
            if cas_engine is not None:
                try: cas_engine.close()
                except Exception: pass
            if conn is not None:
                try: conn.close()
                except Exception: pass
            if cas_restarted is not None:
                try: cas_restarted.close()
                except Exception: pass
            if conn_restarted is not None:
                try: conn_restarted.close()
                except Exception: pass


def test_06_search_integrity_across_repeated_discovery():
    print("--- Test 06: FTS5 Index Consistency Across Repeated Discoveries ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        conn, cas_engine, cap_srv, iface_srv, idx_srv, pipe, db_path, cas_root, ks_dir, anchor = init_isolated_env(tmp_dir)
        try:
            server_cmd = [sys.executable, os.path.join(CURRENT_DIR, "mcp_test_server_fixture.py")]
            server_name = "test-doc-tools"
            policy = InterfaceTrustPolicy(
                policy_name="test-policy",
                allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
                min_interface_version=1
            )

            # Discovery 1
            pipe.discover_and_register_mcp_server(server_cmd, server_name, policy)
            res1 = idx_srv.search("PDF extract")
            assert len(res1) >= 1
            assert res1[0].trust_status == "VERIFIED"

            # Discovery 2 & 3
            pipe.discover_and_register_mcp_server(server_cmd, server_name, policy)
            pipe.discover_and_register_mcp_server(server_cmd, server_name, policy)

            res3 = idx_srv.search("PDF extract")
            assert len(res3) == len(res1), f"Search results count changed! {len(res1)} -> {len(res3)}"
            assert res3[0].capability_urn == res1[0].capability_urn
            assert res3[0].trust_status == "VERIFIED"

            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM capability_fts;")
            fts_total = cur.fetchone()[0]
            assert fts_total == 3, f"Expected 3 FTS rows, got {fts_total}"
            print(f"  Verified: FTS5 index contains exactly {fts_total} capabilities with zero duplicates.")
        finally:
            try:
                cas_engine.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


if __name__ == "__main__":
    tests = [
        test_01_triple_discovery_idempotency_and_counts,
        test_02_preservation_of_original_timestamps,
        test_03_rejection_of_genuine_agent_provenance_conflict,
        test_04_rejection_of_genuine_interface_conflict,
        test_05_attestation_verification_after_repeated_discovery,
        test_06_search_integrity_across_repeated_discovery,
    ]
    print("=" * 76)
    print("LCS IDEMPOTENT MCP DISCOVERY VERIFICATION SUITE")
    print("=" * 76)
    for t in tests:
        t()
    print("=" * 76)
    print(f"ALL {len(tests)} IDEMPOTENT DISCOVERY TESTS PASSED (100% GREEN)")
    print("=" * 76)

