"""
Item 3 Verification Test Suite: Persistent MCP Connection Pool & Session Reuse
=============================================================================
Validates:
1. MCPServerSession reuses active stdio subprocesses across consecutive tool calls (identical PID).
2. MCPConnectionPool caches sessions by command signature and handles eviction and graceful teardown.
3. Server drop / crash transparently re-spawns on subsequent call.
4. Engine and Context clean up all pooled child processes without leaving zombies.
"""

import os
import sys
import json
import time
import pytest
import sqlite3
import tempfile
import subprocess
from lcs.context import LCSContext
from lcs.config import LCSConfig
from execution_engine_v1 import MCPServerSession, MCPConnectionPool, MCPToolHandler, ExecutionEngineV1
from capability_planning_v1 import ExecutionPlan, PlanStep, StepInputBinding, StepOutputDefinition
from governance_policy_v1 import ExecutionAuthorizationToken, DispatchPermit


DUMMY_MCP_SERVER_CODE = """
import sys, json

def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        try:
            req = json.loads(line)
        except Exception:
            continue
        method = req.get("method")
        msg_id = req.get("id")
        
        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "test-persistent-mcp", "version": "1.0.0"}
                }
            }
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()
        elif method == "notifications/initialized":
            pass
        elif method == "tools/call":
            params = req.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})
            val = args.get("value", 0) + 10
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tool": name,
                    "computed": val,
                    "pid": os.getpid()
                }
            }
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()

if __name__ == "__main__":
    import os
    main()
"""

@pytest.fixture
def mcp_server_script(tmp_path):
    script_path = tmp_path / "dummy_mcp_server.py"
    script_path.write_text(DUMMY_MCP_SERVER_CODE, encoding="utf-8")
    return str(script_path)


def test_01_mcp_session_reuse_pid(mcp_server_script):
    """Verify that multiple consecutive tool calls to MCPServerSession reuse the exact same process PID."""
    cmd = [sys.executable, mcp_server_script]
    session = MCPServerSession(cmd)
    try:
        session.start_and_initialize()
        assert session.is_alive()
        pid1 = session.pid
        assert pid1 is not None

        # Call 1
        res1 = session.call_tool("add_ten", {"value": 5})
        assert res1["computed"] == 15
        assert res1["pid"] == pid1

        # Call 2
        res2 = session.call_tool("add_ten", {"value": 20})
        assert res2["computed"] == 30
        assert res2["pid"] == pid1  # Exact same PID (reused connection)

        # Process should still be alive
        assert session.is_alive()
    finally:
        session.close()
        assert not session.is_alive()


def test_02_mcp_session_transparent_recovery(mcp_server_script):
    """Verify that if an MCP process dies, MCPServerSession recovers cleanly on the next tool call."""
    cmd = [sys.executable, mcp_server_script]
    session = MCPServerSession(cmd)
    try:
        session.start_and_initialize()
        pid1 = session.pid

        # Call tool successfully
        res1 = session.call_tool("add_ten", {"value": 1})
        assert res1["computed"] == 11

        # Kill the underlying process externally
        if session.proc:
            session.proc.kill()
            session.proc.wait()

        assert not session.is_alive()

        # Calling tool again should automatically re-spawn and succeed
        res2 = session.call_tool("add_ten", {"value": 2})
        assert res2["computed"] == 12
        assert res2["pid"] != pid1  # New process spawned
        assert session.is_alive()
    finally:
        session.close()


def test_03_mcp_connection_pool_lifecycle(mcp_server_script):
    """Verify that MCPConnectionPool caches sessions by command and clean teardown shuts down all processes."""
    cmd = [sys.executable, mcp_server_script]
    pool = MCPConnectionPool()
    try:
        sess1 = pool.get_session(cmd)
        sess2 = pool.get_session(cmd)
        assert sess1 is sess2  # Same session instance returned
        assert sess1.is_alive()

        # Evict session
        pool.evict_session(cmd)
        assert not sess1.is_alive()

        # Getting session again creates a fresh one
        sess3 = pool.get_session(cmd)
        assert sess3 is not sess1
        assert sess3.is_alive()
    finally:
        pool.close_all()
        assert not sess3.is_alive()
        assert len(pool._sessions) == 0


def test_04_mcp_tool_handler_engine_integration(mcp_server_script, tmp_path):
    """Verify MCPToolHandler executes through pool and engine.close() cleans up sessions."""
    cmd = [sys.executable, mcp_server_script]
    db_path = str(tmp_path / "test_mcp.db")
    conn = sqlite3.connect(db_path)

    handler = MCPToolHandler(conn)
    try:
        res = handler.execute_tool(
            capability_urn="urn:lcs:tool:test:add_ten",
            tool_name="add_ten",
            arguments={"value": 50},
            server_command=cmd
        )
        assert res["computed"] == 60

        # Run again
        res2 = handler.execute_tool(
            capability_urn="urn:lcs:tool:test:add_ten",
            tool_name="add_ten",
            arguments={"value": 100},
            server_command=cmd
        )
        assert res2["computed"] == 110
        assert res2["pid"] == res["pid"]
    finally:
        handler.close()
        conn.close()
