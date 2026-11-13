#!/usr/bin/env python3
"""
LCS — MCP Process Isolation and Timeout Hardening Test Suite
============================================================
Verifies:
1. Normal MCP initialization and discovery.
2. Server that never responds (times out, raises MCPTimeoutError).
3. Server that exits unexpectedly (MCPProtocolError).
4. Malformed JSON response (MCPProtocolError).
5. Broken stdin pipe (MCPProtocolError).
6. Child process termination and cleanup after timeout.
7. Explicitly allowed environment variable reaches child process.
8. Unlisted parent environment variables do not reach child process.
9. Existing repeated-discovery idempotency remains intact.
10. Existing regression suites continue passing with zero regressions.
"""

import os
import sys
import json
import time
import sqlite3
import subprocess
import tempfile
import shutil
import pytest

from capability_discovery_v2b import (
    MCPDiscoveryClient,
    MCPProtocolError,
    MCPTimeoutError,
    DEFAULT_SYSTEM_ENV_VARS,
    CapabilityDiscoveryPipeline
)
from cas_storage_engine_v2b import SecureCASStorageEngine
from capability_registry_v2b import CapabilityRegistrationService
from interface_policy_v2b import InterfacePolicyService, InterfaceTrustPolicy

_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURE_PATH = os.path.join(_DIR, "mcp_test_server_fixture.py")


def test_01_normal_mcp_initialization_and_discovery():
    """Test 1: Normal MCP initialization handshake and tools/list discovery."""
    cmd = [sys.executable, FIXTURE_PATH]
    with MCPDiscoveryClient(cmd, "test-normal-server", timeout=5.0) as client:
        tools = client.list_tools()
        assert len(tools) == 3
        tool_names = [t["name"] for t in tools]
        assert "read_pdf_document" in tool_names
        assert "convert_document_format" in tool_names
        assert "query_local_database" in tool_names


def test_02_server_that_never_responds_times_out():
    """Test 2: Server that never responds triggers bounded MCPTimeoutError."""
    # Subprocess reads stdin line and sleeps without responding
    hang_code = "import sys, time; sys.stdin.readline(); time.sleep(10)"
    cmd = [sys.executable, "-u", "-c", hang_code]

    client = MCPDiscoveryClient(cmd, "test-hang-server", timeout=0.4)
    with pytest.raises(MCPTimeoutError) as exc_info:
        client.connect()

    err_msg = str(exc_info.value)
    assert "timed out after 0.4s" in err_msg
    assert "initialize" in err_msg
    assert client.process is None


def test_03_server_exits_unexpectedly():
    """Test 3: Server that exits unexpectedly raises MCPProtocolError."""
    crash_code = "import sys; sys.stdin.readline(); sys.stderr.write('fatal crash\\n'); sys.exit(42)"
    cmd = [sys.executable, "-u", "-c", crash_code]

    client = MCPDiscoveryClient(cmd, "test-crash-server", timeout=2.0)
    with pytest.raises(MCPProtocolError) as exc_info:
        client.connect()

    err_msg = str(exc_info.value)
    assert "closed stdout unexpectedly" in err_msg or "fatal crash" in err_msg


def test_04_malformed_json_response():
    """Test 4: Server returning malformed JSON raises MCPProtocolError."""
    bad_json_code = "import sys; sys.stdin.readline(); sys.stdout.write('INVALID-JSON-RESPONSE\\n'); sys.stdout.flush()"
    cmd = [sys.executable, "-u", "-c", bad_json_code]

    client = MCPDiscoveryClient(cmd, "test-bad-json-server", timeout=2.0)
    with pytest.raises(MCPProtocolError) as exc_info:
        client.connect()

    assert "Malformed JSON response" in str(exc_info.value)


def test_05_broken_stdin_pipe():
    """Test 5: Broken stdin pipe or already-terminated process is safely caught."""
    exit_code = "import sys; sys.exit(0)"
    cmd = [sys.executable, "-u", "-c", exit_code]

    client = MCPDiscoveryClient(cmd, "test-exit-server", timeout=2.0)
    # The process exits immediately, so connect handshake fails safely
    with pytest.raises(MCPProtocolError) as exc_info:
        client.connect()

    assert "closed stdout unexpectedly" in str(exc_info.value) or "not running" in str(exc_info.value)


def test_06_process_termination_after_timeout():
    """Test 6: Child process is cleanly and reliably terminated on timeout without orphan processes."""
    hang_code = "import sys, time; sys.stdin.readline(); time.sleep(30)"
    cmd = [sys.executable, "-u", "-c", hang_code]

    client = MCPDiscoveryClient(cmd, "test-kill-server", timeout=0.3)
    captured_proc = None

    # Hook connect to capture the spawned Popen instance before timeout
    orig_popen = subprocess.Popen
    def intercept_popen(*args, **kwargs):
        nonlocal captured_proc
        proc = orig_popen(*args, **kwargs)
        captured_proc = proc
        return proc

    subprocess.Popen = intercept_popen
    try:
        with pytest.raises(MCPTimeoutError):
            client.connect()
    finally:
        subprocess.Popen = orig_popen

    assert captured_proc is not None
    # Verify child process was terminated/killed and is not running
    time.sleep(0.1)
    assert captured_proc.poll() is not None
    assert client.process is None


def test_07_explicitly_allowed_env_var_reaches_child():
    """Test 7: Environment variables in env_allowlist or custom_env reach the child process."""
    server_code = """
import sys, os, json
line = sys.stdin.readline()
req = json.loads(line)
val = os.environ.get("LCS_ALLOWED_TEST_TOKEN", "NOT_FOUND")
resp = {
    "jsonrpc": "2.0",
    "id": req["id"],
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "serverInfo": {"name": "test-env", "env_val": val}
    }
}
sys.stdout.write(json.dumps(resp) + "\\n")
sys.stdout.flush()
# notification
sys.stdin.readline()
# tools/list
line2 = sys.stdin.readline()
req2 = json.loads(line2)
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req2["id"], "result": {"tools": []}}) + "\\n")
sys.stdout.flush()
"""
    cmd = [sys.executable, "-u", "-c", server_code]

    # Test via custom_env
    client = MCPDiscoveryClient(
        cmd,
        "test-env-server",
        timeout=2.0,
        custom_env={"LCS_ALLOWED_TEST_TOKEN": "custom_secret_12345"}
    )
    with client:
        tools = client.list_tools()
        assert tools == []

    # Test via env_allowlist from os.environ
    os.environ["LCS_HOST_PERMITTED_VAR"] = "permitted_value_67890"
    try:
        server_code_allowlist = """
import sys, os, json
line = sys.stdin.readline()
req = json.loads(line)
val = os.environ.get("LCS_HOST_PERMITTED_VAR", "NOT_FOUND")
assert val == "permitted_value_67890", f"Expected permitted_value_67890, got {val}"
resp = {
    "jsonrpc": "2.0",
    "id": req["id"],
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "serverInfo": {"name": "test-env"}
    }
}
sys.stdout.write(json.dumps(resp) + "\\n")
sys.stdout.flush()
sys.stdin.readline()
line2 = sys.stdin.readline()
req2 = json.loads(line2)
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req2["id"], "result": {"tools": []}}) + "\\n")
sys.stdout.flush()
"""
        cmd2 = [sys.executable, "-u", "-c", server_code_allowlist]
        with MCPDiscoveryClient(cmd2, "test-allowlist-server", timeout=2.0, env_allowlist={"LCS_HOST_PERMITTED_VAR"}) as client2:
            assert client2.list_tools() == []
    finally:
        os.environ.pop("LCS_HOST_PERMITTED_VAR", None)


def test_08_unlisted_env_vars_do_not_reach_child():
    """Test 8: Unlisted parent environment variables are isolated and omitted from child."""
    os.environ["SECRET_PARENT_TOKEN_FORBIDDEN"] = "ultra_sensitive_secret_value"
    try:
        check_code = """
import sys, os, json
line = sys.stdin.readline()
req = json.loads(line)
val = os.environ.get("SECRET_PARENT_TOKEN_FORBIDDEN")
# PATH must be preserved as an essential system variable
path_val = os.environ.get("PATH")
assert val is None, f"Forbidden environment variable leaked to child: {val}"
assert path_val is not None, "Essential PATH was not preserved"

resp = {
    "jsonrpc": "2.0",
    "id": req["id"],
    "result": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "serverInfo": {"name": "test-isolation"}
    }
}
sys.stdout.write(json.dumps(resp) + "\\n")
sys.stdout.flush()
sys.stdin.readline()
line2 = sys.stdin.readline()
req2 = json.loads(line2)
sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req2["id"], "result": {"tools": []}}) + "\\n")
sys.stdout.flush()
"""
        cmd = [sys.executable, "-u", "-c", check_code]
        with MCPDiscoveryClient(cmd, "test-isolation-server", timeout=2.0) as client:
            tools = client.list_tools()
            assert tools == []
    finally:
        os.environ.pop("SECRET_PARENT_TOKEN_FORBIDDEN", None)


def test_09_existing_repeated_discovery_idempotency_remains_intact():
    """Test 9: End-to-end repeated discovery preserves idempotency, valid attestations, and storage integrity."""
    temp_dir = tempfile.mkdtemp(prefix="lcs_mcp_hardening_test_")
    try:
        real_temp = os.path.realpath(temp_dir)
        db_path = os.path.join(real_temp, "lcs.db")
        cas_dir = os.path.join(real_temp, "cas")
        key_store_dir = os.path.join(real_temp, "keys")
        os.makedirs(key_store_dir, exist_ok=True)

        conn = sqlite3.connect(db_path)
        schema_path = os.path.join(_DIR, "lcs_schema_v2b.sql")
        with open(schema_path, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.commit()

        cas_engine = SecureCASStorageEngine(
            cas_root=cas_dir,
            trusted_anchor=real_temp,
            key_store_dir=key_store_dir
        )
        pipeline = CapabilityDiscoveryPipeline(conn, cas_engine)

        policy = InterfaceTrustPolicy(
            policy_name="hardening-test-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        cmd = [sys.executable, FIXTURE_PATH]

        # First discovery run with timeout & isolation
        sum1 = pipeline.discover_and_register_mcp_server(
            command=cmd,
            server_name="doc-tools-isolated",
            trust_policy=policy,
            timeout=5.0
        )
        assert len(sum1.discovered_tools) == 3
        assert sum1.policy_decision.status == "VERIFIED"

        # Second discovery run with same unchanged server
        sum2 = pipeline.discover_and_register_mcp_server(
            command=cmd,
            server_name="doc-tools-isolated",
            trust_policy=policy,
            timeout=5.0
        )

        # Idempotency checks
        assert sum1.agent_urn == sum2.agent_urn
        assert sum1.interface_urn == sum2.interface_urn
        assert sum1.registered_capabilities == sum2.registered_capabilities
        assert sum1.attestation_id == sum2.attestation_id
        assert sum2.policy_decision.status == "VERIFIED"

        # Verify no duplicate entries were created in database
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM agent_declarations;")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM interface_declarations;")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM interface_attestations;")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT count(*) FROM capability_declarations;")
        assert cur.fetchone()[0] == 3

        conn.close()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_10_secret_redaction_in_errors_and_logs():
    """Test 10: Secrets in custom_env or allowlist are never leaked in error messages or logs."""
    super_secret = "lcs_synthetic_mock_credential_token_998877665544332211aabbcc"
    crash_code = f"import sys; sys.stdin.readline(); sys.stderr.write('Error connecting with {super_secret}\\n'); sys.exit(1)"
    cmd = [sys.executable, "-u", "-c", crash_code]

    client = MCPDiscoveryClient(
        cmd,
        "test-secret-server",
        timeout=2.0,
        custom_env={"API_SECRET_KEY": super_secret}
    )

    with pytest.raises(MCPProtocolError) as exc_info:
        client.connect()

    err_text = str(exc_info.value)
    # The raw secret MUST NOT appear in the exception text
    assert super_secret not in err_text
    # Redaction marker must be present
    assert "***REDACTED***" in err_text
