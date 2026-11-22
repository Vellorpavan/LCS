"""
Test Suite for LCS Environment Adapters & Live Verification Engine (Phase 1B)
=============================================================================
Verifies:
1. AdapterFeature bitmask manipulation and assert_feature() fail-closed behavior.
2. OperationalStatus 7-state enum.
3. GenericPOSIXAdapter discovery, security checks, and feature constraints.
4. ClaudeCodeAdapter detection, MCP discovery, command registration, and AGENT_DELEGATION rejection.
5. OpenCodeAdapter detection, MCP discovery, and command registration.
6. AntigravityAdapter detection, full capability discovery, and subagent delegation.
7. LiveProbeEngine live stdio probes (successful JSON-RPC, crash, 2.0s timeout & orphan cleanup).
8. AdapterRegistry precedence resolution and active adapter detection.
9. ActivationIntegrityVerifier hash-on-activation verification and tampering detection.
"""

import os
import sys
import json
import time
import shutil
import sqlite3
import tempfile
import pytest
from pathlib import Path

from lcs.adapters.base import (
    AdapterFeature,
    EnvironmentKind,
    OperationalStatus,
    CapabilityRoot,
    ResourceProbeResult,
    AdapterReachabilityReport,
    MCPConfigEntry,
    SubagentHandle,
    AdapterError,
    UnsupportedAdapterFeatureError,
    EnvironmentUnreachableError,
    PathTraversalSecurityError,
    ProbeTimeoutError,
    ContentIntegrityMismatchError,
    AdapterRegistry
)
from lcs.adapters.generic import GenericPOSIXAdapter
from lcs.adapters.claude_code import ClaudeCodeAdapter
from lcs.adapters.opencode import OpenCodeAdapter
from lcs.adapters.antigravity import AntigravityAdapter
from lcs.adapters.probes import LiveProbeEngine
from lcs.adapters.activation_verifier import ActivationIntegrityVerifier


# =====================================================================
# 1. AdapterFeature Bitmask & OperationalStatus Tests
# =====================================================================

def test_adapter_feature_bitmask():
    features = AdapterFeature.SKILL_DISCOVERY | AdapterFeature.MCP_TOOL_INVOCATION
    assert AdapterFeature.SKILL_DISCOVERY in features
    assert AdapterFeature.MCP_TOOL_INVOCATION in features
    assert AdapterFeature.AGENT_DELEGATION not in features

    # Test combination with other flags
    combined = features | AdapterFeature.AGENT_DELEGATION
    assert AdapterFeature.AGENT_DELEGATION in combined
    assert AdapterFeature.SLASH_COMMAND_REGISTRATION not in combined


def test_operational_status_enumeration():
    expected_states = {
        "UNCHECKED",
        "REACHABLE",
        "CONNECTED",
        "AVAILABLE",
        "DEGRADED",
        "DISCONNECTED",
        "UNREACHABLE",
        "REVOKED"
    }
    actual_states = {s.value for s in OperationalStatus}
    assert expected_states == actual_states


# =====================================================================
# 2. GenericPOSIXAdapter Tests
# =====================================================================

def test_generic_posix_adapter_features_and_rejections():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = GenericPOSIXAdapter(workspace_root=tmpdir)
        assert adapter.kind == EnvironmentKind.GENERIC_POSIX
        assert adapter.has_feature(AdapterFeature.SKILL_DISCOVERY)
        assert adapter.has_feature(AdapterFeature.INTERACTIVE_TTY_CONSENT)
        assert not adapter.has_feature(AdapterFeature.AGENT_DELEGATION)
        assert not adapter.has_feature(AdapterFeature.SLASH_COMMAND_REGISTRATION)

        # Assert fail-closed on unsupported feature
        with pytest.raises(UnsupportedAdapterFeatureError) as exc_info:
            adapter.assert_feature(AdapterFeature.AGENT_DELEGATION)
        assert "AGENT_DELEGATION" in str(exc_info.value)

        with pytest.raises(UnsupportedAdapterFeatureError):
            adapter.spawn_subagent("dummy-task")

        with pytest.raises(UnsupportedAdapterFeatureError):
            adapter.register_slash_command("call-me", "lcs")


def test_generic_posix_adapter_skill_discovery():
    with tempfile.TemporaryDirectory() as tmpdir:
        skills_dir = os.path.join(tmpdir, ".agents", "skills", "test-skill")
        os.makedirs(skills_dir, exist_ok=True)
        skill_file = os.path.join(skills_dir, "SKILL.md")
        with open(skill_file, "w", encoding="utf-8") as f:
            f.write("# Test Skill\\nContent")

        adapter = GenericPOSIXAdapter(workspace_root=tmpdir)
        roots = adapter.discover_capability_roots()
        root_paths = [os.path.realpath(r.path) for r in roots]
        assert os.path.realpath(os.path.join(tmpdir, ".agents", "skills")) in root_paths

        # Test exact byte reading
        content = adapter.read_skill_exact_bytes(skill_file)
        assert b"# Test Skill" in content

        # Test path traversal prevention
        outside_file = os.path.abspath(os.path.join(tmpdir, "..", "outside.txt"))
        with pytest.raises(PathTraversalSecurityError):
            adapter.read_skill_exact_bytes(outside_file)


# =====================================================================
# 3. ClaudeCodeAdapter Tests
# =====================================================================

def test_claude_code_adapter_detection_and_features():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = GenericPOSIXAdapter(workspace_root=tmpdir)
        claude_adapter = ClaudeCodeAdapter(workspace_root=tmpdir)

        # Initially inactive without .claude or CLAUDE.md
        old_env = os.environ.pop("CLAUDE_CODE_ENTRYPOINT", None)
        try:
            assert not claude_adapter.detect_active()

            # Create CLAUDE.md
            claude_md = os.path.join(tmpdir, "CLAUDE.md")
            with open(claude_md, "w") as f:
                f.write("# Project Instructions")
            assert claude_adapter.detect_active()

            # Rejects AGENT_DELEGATION strictly
            assert not claude_adapter.has_feature(AdapterFeature.AGENT_DELEGATION)
            with pytest.raises(UnsupportedAdapterFeatureError):
                claude_adapter.spawn_subagent("researcher")

            # Supports slash command registration and MCP config discovery
            assert claude_adapter.has_feature(AdapterFeature.SLASH_COMMAND_REGISTRATION)
            assert claude_adapter.has_feature(AdapterFeature.MCP_CONFIG_DISCOVERY)
            assert claude_adapter.has_feature(AdapterFeature.COMMAND_DISCOVERY)
        finally:
            if old_env:
                os.environ["CLAUDE_CODE_ENTRYPOINT"] = old_env


def test_claude_code_adapter_command_registration_and_mcp():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = ClaudeCodeAdapter(workspace_root=tmpdir)

        # Register slash command
        reg_result = adapter.register_slash_command("call-me", "Execute LCS capability intelligence")
        assert reg_result["command"] == "call-me"
        command_file = Path(reg_result["target_file"])
        assert command_file.exists()
        content = command_file.read_text(encoding="utf-8")
        assert "call-me" in content
        assert "LCS" in content

        # Test MCP config discovery
        claude_json = Path(tmpdir) / ".claude.json"
        claude_json.write_text(json.dumps({
            "mcpServers": {
                "sqlite-srv": {
                    "command": "python3",
                    "args": ["-m", "sqlite_mcp"]
                }
            }
        }), encoding="utf-8")

        mcp_configs = adapter.discover_mcp_configurations()
        assert len(mcp_configs) >= 1
        srv = next(c for c in mcp_configs if c.server_name == "sqlite-srv")
        assert srv.command == "python3"
        assert srv.args == ["-m", "sqlite_mcp"]


# =====================================================================
# 4. OpenCodeAdapter Tests
# =====================================================================

def test_opencode_adapter_detection_and_command():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = OpenCodeAdapter(workspace_root=tmpdir)
        assert not adapter.detect_active()

        # Create opencode.json
        cfg_file = Path(tmpdir) / "opencode.json"
        cfg_file.write_text(json.dumps({
            "mcpServers": {
                "local-mcp": {
                    "command": "node",
                    "args": ["server.js"]
                }
            }
        }), encoding="utf-8")
        assert adapter.detect_active()

        # MCP discovery
        mcp_configs = adapter.discover_mcp_configurations()
        assert len(mcp_configs) == 1
        assert mcp_configs[0].server_name == "local-mcp"

        # Slash command registration
        reg = adapter.register_slash_command("call-me", "LCS invocation")
        assert reg["command"] == "/call-me"
        assert Path(reg["macro_file"]).exists()

        # Check that opencode.json was updated
        updated_cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
        assert "/call-me" in updated_cfg.get("commands", {})


# =====================================================================
# 5. AntigravityAdapter Tests
# =====================================================================

def test_antigravity_adapter_capabilities_and_subagent():
    with tempfile.TemporaryDirectory() as tmpdir:
        adapter = AntigravityAdapter(workspace_root=tmpdir)
        assert adapter.has_feature(AdapterFeature.AGENT_DELEGATION)
        assert adapter.has_feature(AdapterFeature.SKILL_DISCOVERY)
        assert adapter.has_feature(AdapterFeature.MCP_CONFIG_DISCOVERY)
        assert adapter.has_feature(AdapterFeature.EXECUTION_TRACE_STREAMING)

        # Subagent delegation
        handle = adapter.spawn_subagent(
            role="Codebase Auditor",
            prompt="Audit adapter interface",
            type_name="researcher"
        )
        assert isinstance(handle, SubagentHandle)
        assert handle.role == "Codebase Auditor"
        assert handle.conversation_id.startswith("subagent-")
        assert handle.status == "ACTIVE"

        # Discovery roots with mock directories
        mock_agents_skills = Path(tmpdir) / ".agents" / "skills"
        mock_agents_skills.mkdir(parents=True)
        roots = adapter.discover_capability_roots()
        root_paths = [os.path.realpath(r.path) for r in roots]
        assert os.path.realpath(str(mock_agents_skills)) in root_paths


# =====================================================================
# 6. LiveProbeEngine Tests (Active JSON-RPC, Crash, 2.0s Timeout)
# =====================================================================

def test_live_probe_engine_roots_and_binaries():
    with tempfile.TemporaryDirectory() as tmpdir:
        valid_dir = os.path.join(tmpdir, "valid_root")
        os.makedirs(valid_dir)
        invalid_dir = os.path.join(tmpdir, "non_existent")

        res_valid = LiveProbeEngine.probe_skill_root(valid_dir, tmpdir)
        assert res_valid.status == OperationalStatus.AVAILABLE
        assert res_valid.error_message is None

        res_invalid = LiveProbeEngine.probe_skill_root(invalid_dir, tmpdir)
        assert res_invalid.status == OperationalStatus.UNREACHABLE
        assert "does not exist" in res_invalid.error_message

        # Probe binary
        res_bin = LiveProbeEngine.probe_binary(sys.executable)
        assert res_bin.status == OperationalStatus.AVAILABLE

        res_missing_bin = LiveProbeEngine.probe_binary("non_existent_binary_xyz123")
        assert res_missing_bin.status == OperationalStatus.UNREACHABLE


def test_live_probe_engine_mcp_successful_ping():
    # Echo responder script in Python: reads initialize JSON-RPC and replies
    server_script = (
        "import sys, json\n"
        "line = sys.stdin.readline()\n"
        "req = json.loads(line)\n"
        "res = {'jsonrpc': '2.0', 'id': req.get('id', 1), 'result': {'serverInfo': {'name': 'test-mcp', 'version': '1.0'}}}\n"
        "sys.stdout.write(json.dumps(res) + '\\n')\n"
        "sys.stdout.flush()\n"
    )
    result = LiveProbeEngine.probe_mcp_server(
        server_name="mock-fast-server",
        command=sys.executable,
        args=["-c", server_script],
        timeout_seconds=2.0
    )
    assert result.status in (OperationalStatus.CONNECTED, OperationalStatus.AVAILABLE)
    assert result.error_message is None
    assert result.response_latency_ms > 0
    assert result.metadata.get("server_info", {}).get("name") == "test-mcp"


def test_live_probe_engine_mcp_crash():
    # Process exits immediately with non-zero exit code
    crash_script = "import sys; sys.exit(42)"
    result = LiveProbeEngine.probe_mcp_server(
        server_name="mock-crash-server",
        command=sys.executable,
        args=["-c", crash_script],
        timeout_seconds=2.0
    )
    assert result.status == OperationalStatus.DISCONNECTED
    assert "exited with code 42" in result.error_message


def test_live_probe_engine_mcp_timeout_and_orphan_cleanup():
    # Process sleeps for 10 seconds, exceeding 2.0s probe timeout
    sleep_script = "import time, sys; sys.stdin.readline(); time.sleep(10)"
    t0 = time.time()
    result = LiveProbeEngine.probe_mcp_server(
        server_name="mock-slow-server",
        command=sys.executable,
        args=["-c", sleep_script],
        timeout_seconds=1.0  # shortened to 1.0s for quick test execution
    )
    duration = time.time() - t0

    assert result.status == OperationalStatus.UNREACHABLE
    assert "timed out after 1.0s" in result.error_message
    assert duration < 2.5, "Probe must abort within timeout window and terminate child process"


# =====================================================================
# 7. AdapterRegistry Precedence & Fallback Tests
# =====================================================================

def test_adapter_registry_fallback_to_generic():
    with tempfile.TemporaryDirectory() as tmpdir:
        registry = AdapterRegistry()
        registry.register(ClaudeCodeAdapter(workspace_root=tmpdir))
        registry.register(OpenCodeAdapter(workspace_root=tmpdir))
        registry.register(GenericPOSIXAdapter(workspace_root=tmpdir))

        # With empty dir, detect_active() falls back to GenericPOSIXAdapter
        active = registry.detect_active()
        assert active.kind == EnvironmentKind.GENERIC_POSIX


def test_adapter_registry_precedence():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Shared skills also exist in Claude projects.
        (Path(tmpdir) / ".agents").mkdir()
        (Path(tmpdir) / "CLAUDE.md").write_text("# Claude")

        registry = AdapterRegistry()
        registry.register(ClaudeCodeAdapter(workspace_root=tmpdir))
        registry.register(AntigravityAdapter(workspace_root=tmpdir))
        registry.register(GenericPOSIXAdapter(workspace_root=tmpdir))

        # Only the Claude marker identifies a specific host.
        active = registry.detect_active()
        assert active.kind == EnvironmentKind.CLAUDE_CODE


# =====================================================================
# 8. ActivationIntegrityVerifier Hash-On-Activation Tests
# =====================================================================

def test_activation_integrity_verifier_success_and_tampering():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_lcs.db")
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # Create minimal table schema
        cur.execute("""
            CREATE TABLE physical_source_instances (
                instance_id TEXT PRIMARY KEY,
                capability_urn TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                sha256_digest TEXT NOT NULL,
                status TEXT NOT NULL
            );
        """)

        # Create target skill file
        skill_path = os.path.join(tmpdir, "SKILL.md")
        content = b"# Authentic Skill Content\\nversion: 1"
        with open(skill_path, "wb") as f:
            f.write(content)

        import hashlib
        digest = hashlib.sha256(content).hexdigest()

        urn = "skill:local:test-activation"
        cur.execute("""
            INSERT INTO physical_source_instances (
                instance_id, capability_urn, file_path, file_size, sha256_digest, status
            ) VALUES (?, ?, ?, ?, ?, 'ACTIVE');
        """, ("inst-01", urn, skill_path, len(content), digest))
        conn.commit()

        verifier = ActivationIntegrityVerifier(conn)

        # 1. Verification succeeds when file matches digest
        res = verifier.verify_capability_activation(urn)
        assert res["verified"] is True
        assert res["sha256"] == digest

        # 2. Tampering: Modify file content on disk without updating DB
        tampered_content = b"# TAMPERED Skill Content\\nversion: 2"
        with open(skill_path, "wb") as f:
            f.write(tampered_content)

        # Verification must fail-closed with ContentIntegrityMismatchError
        with pytest.raises(ContentIntegrityMismatchError) as exc_info:
            verifier.verify_capability_activation(urn)
        assert "Integrity mismatch" in str(exc_info.value)

        conn.close()
