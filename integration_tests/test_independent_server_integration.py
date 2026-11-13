#!/usr/bin/env python3
"""
LCS — Independent MCP Server Integration Test Suite
===================================================
Tests discovery, zero-trust verification, FTS5 search, inspection,
repeated discovery idempotency, and timeout behavior against an independent
local MCP server running as a subprocess over standard I/O.
"""

import os
import sys
import json
import time
import sqlite3
import tempfile
import shutil
import pytest

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from capability_discovery_v2b import (
    MCPDiscoveryClient,
    MCPTimeoutError,
    CapabilityDiscoveryPipeline
)
from cas_storage_engine_v2b import SecureCASStorageEngine
from capability_registry_v2b import CapabilityRegistrationService
from interface_policy_v2b import InterfacePolicyService, InterfaceTrustPolicy

SERVER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "independent_mcp_server.py")


@pytest.fixture
def lcs_isolated_env():
    """Sets up an isolated LCS environment with dedicated CAS, SQLite DB, and keys."""
    temp_dir = tempfile.mkdtemp(prefix="lcs_independent_mcp_test_")
    real_temp = os.path.realpath(temp_dir)
    db_path = os.path.join(real_temp, "lcs.db")
    cas_dir = os.path.join(real_temp, "cas")
    key_dir = os.path.join(real_temp, "keys")
    os.makedirs(key_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    schema_path = os.path.join(_PARENT, "lcs_schema_v2b.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.commit()

    cas_engine = SecureCASStorageEngine(
        cas_root=cas_dir,
        trusted_anchor=real_temp,
        key_store_dir=key_dir
    )
    cap_service = CapabilityRegistrationService(conn, cas_engine)
    iface_service = InterfacePolicyService(conn, cas_engine, cap_service)
    pipeline = CapabilityDiscoveryPipeline(conn, cas_engine, cap_service, iface_service)

    yield {
        "conn": conn,
        "cas_engine": cas_engine,
        "pipeline": pipeline,
        "temp_dir": real_temp
    }

    conn.close()
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_independent_server_stdio_handshake_and_tools_list():
    """Verify that the independent server negotiates initialize and returns 3 tools."""
    cmd = [sys.executable, SERVER_SCRIPT]
    with MCPDiscoveryClient(cmd, "independent-geo-metrics", timeout=5.0) as client:
        tools = client.list_tools()
        assert len(tools) == 3
        tool_names = [t["name"] for t in tools]
        assert "calculate_polygon_area" in tool_names
        assert "compute_haversine_distance" in tool_names
        assert "find_bounding_envelope" in tool_names


def test_independent_server_tools_call_rejected():
    """Verify that tools/call is explicitly denied by the independent server."""
    cmd = [sys.executable, SERVER_SCRIPT]
    with MCPDiscoveryClient(cmd, "independent-geo-metrics", timeout=5.0) as client:
        req = {
            "jsonrpc": "2.0",
            "id": 999,
            "method": "tools/call",
            "params": {"name": "calculate_polygon_area", "arguments": {}}
        }
        resp = client._send_request(req)
        assert "error" in resp
        assert resp["error"]["code"] == -32601
        assert "tools/call is strictly prohibited" in resp["error"]["message"]


def test_end_to_end_discovery_registration_and_attestation(lcs_isolated_env):
    """Verify end-to-end discovery, registration, attestation, and FTS indexing."""
    pipeline = lcs_isolated_env["pipeline"]
    conn = lcs_isolated_env["conn"]
    policy = InterfaceTrustPolicy(
        policy_name="geo-policy",
        allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
        min_interface_version=1,
        require_attestation=True,
        require_all_capabilities_verified=True
    )

    cmd = [sys.executable, SERVER_SCRIPT]
    summary = pipeline.discover_and_register_mcp_server(
        command=cmd,
        server_name="independent-geo-metrics",
        trust_policy=policy,
        timeout=5.0
    )

    assert summary.server_name == "independent-geo-metrics"
    assert summary.agent_urn == "urn:lcs:agent:mcp.independent-geo-metrics:host"
    assert summary.interface_urn == "urn:lcs:interface:mcp.independent-geo-metrics:tools-v1"
    assert len(summary.discovered_tools) == 3
    assert len(summary.registered_capabilities) == 3
    assert summary.policy_decision.status == "VERIFIED"
    assert summary.policy_decision.decision == "ALLOW"

    expected_urns = {
        "urn:lcs:tool:mcp.independent-geo-metrics:calculate-polygon-area",
        "urn:lcs:tool:mcp.independent-geo-metrics:compute-haversine-distance",
        "urn:lcs:tool:mcp.independent-geo-metrics:find-bounding-envelope"
    }
    assert set(summary.registered_capabilities) == expected_urns


def test_distinct_search_queries_for_each_tool(lcs_isolated_env):
    """Verify keyword queries distinctly resolve each of the three registered capabilities."""
    pipeline = lcs_isolated_env["pipeline"]
    policy = InterfaceTrustPolicy(
        policy_name="geo-policy",
        allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
        min_interface_version=1,
        require_attestation=True,
        require_all_capabilities_verified=True
    )
    cmd = [sys.executable, SERVER_SCRIPT]
    pipeline.discover_and_register_mcp_server(cmd, "independent-geo-metrics", policy)

    index_service = pipeline.index_service

    # Query 1: polygon -> calculate_polygon_area
    results_polygon = index_service.search("polygon")
    assert len(results_polygon) == 1
    assert results_polygon[0].capability_urn == "urn:lcs:tool:mcp.independent-geo-metrics:calculate-polygon-area"
    assert results_polygon[0].trust_status == "VERIFIED"

    # Query 2: haversine -> compute_haversine_distance
    results_haversine = index_service.search("haversine")
    assert len(results_haversine) == 1
    assert results_haversine[0].capability_urn == "urn:lcs:tool:mcp.independent-geo-metrics:compute-haversine-distance"
    assert results_haversine[0].trust_status == "VERIFIED"

    # Query 3: bounding -> find_bounding_envelope
    results_bounding = index_service.search("bounding")
    assert len(results_bounding) == 1
    assert results_bounding[0].capability_urn == "urn:lcs:tool:mcp.independent-geo-metrics:find-bounding-envelope"
    assert results_bounding[0].trust_status == "VERIFIED"


def test_repeated_discovery_idempotency(lcs_isolated_env):
    """Verify repeated discovery produces zero duplicate declarations, attestations, or CAS blobs."""
    pipeline = lcs_isolated_env["pipeline"]
    conn = lcs_isolated_env["conn"]
    cas_engine = lcs_isolated_env["cas_engine"]
    policy = InterfaceTrustPolicy(
        policy_name="geo-policy",
        allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
        min_interface_version=1,
        require_attestation=True,
        require_all_capabilities_verified=True
    )
    cmd = [sys.executable, SERVER_SCRIPT]

    # Run 1
    sum1 = pipeline.discover_and_register_mcp_server(cmd, "independent-geo-metrics", policy)

    # Count records after run 1
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM agent_declarations;")
    agent_count_1 = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM interface_declarations;")
    iface_count_1 = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM interface_attestations;")
    attest_count_1 = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM capability_declarations;")
    cap_count_1 = cur.fetchone()[0]

    cas_objects_dir = os.path.join(lcs_isolated_env["temp_dir"], "cas", "objects")
    cas_blobs_1 = sum(len(files) for _, _, files in os.walk(cas_objects_dir))

    # Run 2
    sum2 = pipeline.discover_and_register_mcp_server(cmd, "independent-geo-metrics", policy)

    # Run 3
    sum3 = pipeline.discover_and_register_mcp_server(cmd, "independent-geo-metrics", policy)

    # Verify identical identities and attestation reuse
    assert sum1.agent_urn == sum2.agent_urn == sum3.agent_urn
    assert sum1.interface_urn == sum2.interface_urn == sum3.interface_urn
    assert sum1.attestation_id == sum2.attestation_id == sum3.attestation_id
    assert sum1.registered_capabilities == sum2.registered_capabilities == sum3.registered_capabilities

    # Verify record counts are exactly identical
    cur.execute("SELECT count(*) FROM agent_declarations;")
    assert cur.fetchone()[0] == agent_count_1 == 1
    cur.execute("SELECT count(*) FROM interface_declarations;")
    assert cur.fetchone()[0] == iface_count_1 == 1
    cur.execute("SELECT count(*) FROM interface_attestations;")
    assert cur.fetchone()[0] == attest_count_1 == 1
    cur.execute("SELECT count(*) FROM capability_declarations;")
    assert cur.fetchone()[0] == cap_count_1 == 3

    cas_blobs_3 = sum(len(files) for _, _, files in os.walk(cas_objects_dir))
    assert cas_blobs_3 == cas_blobs_1


def test_server_timeout_and_process_cleanup():
    """Verify that slow/hanging independent server triggers MCPTimeoutError and cleanly terminates child process."""
    cmd = [sys.executable, SERVER_SCRIPT, "--delay", "3.0"]
    client = MCPDiscoveryClient(cmd, "independent-geo-metrics", timeout=0.4)

    with pytest.raises(MCPTimeoutError) as exc_info:
        client.connect()

    err = str(exc_info.value)
    assert "timed out after 0.4s" in err
    assert client.process is None

