#!/usr/bin/env python3
"""
LCS — Independent MCP SDK Compatibility Integration Test Suite
==============================================================
Validates interoperability with the official Python MCP SDK (`mcp` package,
`FastMCP` architecture) running as an independent subprocess over stdio.

Tests:
1. Official MCP SDK handshake compatibility.
2. Tool discovery and schema normalization.
3. Capability registration, interface binding, and cryptographic attestation.
4. Triple-discovery idempotency and zero duplicate storage.
5. Timeout enforcement and child process cleanup.
6. Strict prohibition of tool execution (tools/call rejected).
7. Distinct FTS5 keyword discovery for SDK-exposed capabilities.
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

SERVER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_sdk_server.py")


@pytest.fixture
def isolated_lcs_env():
    """Provides an isolated LCS environment with dedicated SQLite DB and CAS."""
    temp_dir = tempfile.mkdtemp(prefix="lcs_mcp_sdk_compat_test_")
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


def test_01_mcp_sdk_handshake_compatibility():
    """Verify that the official Python MCP SDK server negotiates initialize handshake cleanly."""
    cmd = [sys.executable, SERVER_SCRIPT]
    with MCPDiscoveryClient(cmd, "official-mcp-sdk-analytics", timeout=5.0) as client:
        tools = client.list_tools()
        assert len(tools) == 3
        names = [t["name"] for t in tools]
        assert "calculate_statistical_variance" in names
        assert "parse_semver_expression" in names
        assert "inspect_http_header_security" in names


def test_02_mcp_sdk_tool_discovery_and_schema_normalization(isolated_lcs_env):
    """Verify schema normalization handles Pydantic/FastMCP generated schemas."""
    pipeline = isolated_lcs_env["pipeline"]
    policy = InterfaceTrustPolicy(
        policy_name="sdk-compat-policy",
        allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
        min_interface_version=1,
        require_attestation=True,
        require_all_capabilities_verified=True
    )
    cmd = [sys.executable, SERVER_SCRIPT]
    summary = pipeline.discover_and_register_mcp_server(
        command=cmd,
        server_name="official-mcp-sdk-analytics",
        trust_policy=policy,
        timeout=5.0
    )

    assert len(summary.discovered_tools) == 3
    for tool in summary.discovered_tools:
        assert tool.canonical_urn.startswith("urn:lcs:tool:mcp.official-mcp-sdk-analytics:")
        assert tool.category in ("math", "utility", "network", "document")
        assert tool.input_schema.get("type") == "object"
        assert len(tool.keywords) > 0


def test_03_mcp_sdk_capability_registration_and_attestation(isolated_lcs_env):
    """Verify end-to-end registration, CAS storage, and cryptographic attestation."""
    pipeline = isolated_lcs_env["pipeline"]
    conn = isolated_lcs_env["conn"]
    policy = InterfaceTrustPolicy(
        policy_name="sdk-compat-policy",
        allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
        min_interface_version=1,
        require_attestation=True,
        require_all_capabilities_verified=True
    )
    cmd = [sys.executable, SERVER_SCRIPT]
    summary = pipeline.discover_and_register_mcp_server(
        command=cmd,
        server_name="official-mcp-sdk-analytics",
        trust_policy=policy,
        timeout=5.0
    )

    assert summary.policy_decision.status == "VERIFIED"
    assert summary.policy_decision.decision == "ALLOW"
    assert summary.attestation_id.startswith("att_")

    expected_urns = {
        "urn:lcs:tool:mcp.official-mcp-sdk-analytics:calculate-statistical-variance",
        "urn:lcs:tool:mcp.official-mcp-sdk-analytics:parse-semver-expression",
        "urn:lcs:tool:mcp.official-mcp-sdk-analytics:inspect-http-header-security"
    }
    assert set(summary.registered_capabilities) == expected_urns

    # Verify CAS persistence of capability definitions
    cas_engine = isolated_lcs_env["cas_engine"]
    cur = conn.cursor()
    for urn in expected_urns:
        cur.execute("SELECT definition_blob_digest FROM capability_declarations WHERE capability_urn = ?;", (urn,))
        row = cur.fetchone()
        assert row is not None
        digest = row[0]
        assert cas_engine.blob_exists(digest)


def test_04_mcp_sdk_repeated_discovery_idempotency(isolated_lcs_env):
    """Verify three consecutive discovery passes against official MCP SDK produce zero duplicates."""
    pipeline = isolated_lcs_env["pipeline"]
    conn = isolated_lcs_env["conn"]
    cas_objects_dir = os.path.join(isolated_lcs_env["temp_dir"], "cas", "objects")
    policy = InterfaceTrustPolicy(
        policy_name="sdk-compat-policy",
        allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
        min_interface_version=1,
        require_attestation=True,
        require_all_capabilities_verified=True
    )
    cmd = [sys.executable, SERVER_SCRIPT]

    # Pass 1
    sum1 = pipeline.discover_and_register_mcp_server(cmd, "official-mcp-sdk-analytics", policy)
    cur = conn.cursor()
    cur.execute("SELECT count(*) FROM agent_declarations;")
    agents_1 = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM interface_declarations;")
    ifaces_1 = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM interface_attestations;")
    attests_1 = cur.fetchone()[0]
    cur.execute("SELECT count(*) FROM capability_declarations;")
    caps_1 = cur.fetchone()[0]
    blobs_1 = sum(len(files) for _, _, files in os.walk(cas_objects_dir))

    # Pass 2
    sum2 = pipeline.discover_and_register_mcp_server(cmd, "official-mcp-sdk-analytics", policy)

    # Pass 3
    sum3 = pipeline.discover_and_register_mcp_server(cmd, "official-mcp-sdk-analytics", policy)

    # Invariants
    assert sum1.agent_urn == sum2.agent_urn == sum3.agent_urn
    assert sum1.interface_urn == sum2.interface_urn == sum3.interface_urn
    assert sum1.attestation_id == sum2.attestation_id == sum3.attestation_id
    assert sum1.registered_capabilities == sum2.registered_capabilities == sum3.registered_capabilities

    cur.execute("SELECT count(*) FROM agent_declarations;")
    assert cur.fetchone()[0] == agents_1 == 1
    cur.execute("SELECT count(*) FROM interface_declarations;")
    assert cur.fetchone()[0] == ifaces_1 == 1
    cur.execute("SELECT count(*) FROM interface_attestations;")
    assert cur.fetchone()[0] == attests_1 == 1
    cur.execute("SELECT count(*) FROM capability_declarations;")
    assert cur.fetchone()[0] == caps_1 == 3

    blobs_3 = sum(len(files) for _, _, files in os.walk(cas_objects_dir))
    assert blobs_3 == blobs_1


def test_05_mcp_sdk_timeout_and_process_cleanup():
    """Verify timeout terminates the official MCP SDK server process without orphan processes."""
    cmd = [sys.executable, SERVER_SCRIPT, "--delay", "3.0"]
    client = MCPDiscoveryClient(cmd, "official-mcp-sdk-analytics", timeout=0.4)

    with pytest.raises(MCPTimeoutError) as exc_info:
        client.connect()

    err = str(exc_info.value)
    assert "timed out after 0.4s" in err
    assert client.process is None


def test_06_mcp_sdk_tools_call_prohibited():
    """Verify tool execution (tools/call) is strictly disabled and throws PermissionError."""
    cmd = [sys.executable, SERVER_SCRIPT]
    with MCPDiscoveryClient(cmd, "official-mcp-sdk-analytics", timeout=5.0) as client:
        req = {
            "jsonrpc": "2.0",
            "id": 888,
            "method": "tools/call",
            "params": {"name": "calculate_statistical_variance", "arguments": {"samples": [1.0, 2.0]}}
        }
        resp = client._send_request(req)
        # FastMCP surfaces tool handler exceptions as JSON-RPC errors or error payloads
        assert "error" in resp or resp.get("result", {}).get("isError") is True
        error_text = json.dumps(resp)
        assert "strictly prohibited" in error_text or "Tool execution" in error_text or "-32603" in error_text


def test_07_mcp_sdk_distinct_fts_searches(isolated_lcs_env):
    """Verify distinct keyword queries correctly match each official SDK tool."""
    pipeline = isolated_lcs_env["pipeline"]
    policy = InterfaceTrustPolicy(
        policy_name="sdk-compat-policy",
        allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
        min_interface_version=1,
        require_attestation=True,
        require_all_capabilities_verified=True
    )
    cmd = [sys.executable, SERVER_SCRIPT]
    pipeline.discover_and_register_mcp_server(cmd, "official-mcp-sdk-analytics", policy)

    index_service = pipeline.index_service

    # Search for variance
    res_var = index_service.search("variance")
    assert len(res_var) == 1
    assert res_var[0].capability_urn == "urn:lcs:tool:mcp.official-mcp-sdk-analytics:calculate-statistical-variance"

    # Search for semver
    res_semver = index_service.search("semver")
    assert len(res_semver) == 1
    assert res_semver[0].capability_urn == "urn:lcs:tool:mcp.official-mcp-sdk-analytics:parse-semver-expression"

    # Search for header
    res_header = index_service.search("header")
    assert len(res_header) == 1
    assert res_header[0].capability_urn == "urn:lcs:tool:mcp.official-mcp-sdk-analytics:inspect-http-header-security"

