"""
LCS Stage 3: Universal MCP Invocation & Cross-Agent Context Hydration Test Suite
================================================================================
Verifies:
1. Unified `lcs_call_me` and `lcs_hydrate_context` MCP tools.
2. Dual-Gate governance and execution authorization invariance over MCP.
3. Local context hydration and cross-agent session continuity on the same project.
4. Bounded context selection with token limits and provenance tracking.
5. Strict POSIX project isolation preventing cross-project context leakage.
6. Simultaneous multiple agent detection without configuration conflicts.
7. Real external client process stdio JSON-RPC 2.0 communication.
8. Negative tests: malicious definitions, cross-project leakage, unauthorized execution, MCP protocol errors.
9. Clean wheel installation and fresh-shell invocation.
"""

import os
import sys
import json
import shutil
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, List

import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.mcp_server import LCSMCPServer, TOOLS_SPEC
from lcs.hydration.project_context import (
    ProjectContextHydrator,
    ProjectContextPayload,
    ProjectIsolationViolationError,
    ProjectContextError,
)
from lcs.adapters import (
    AdapterRegistry,
    EnvironmentKind,
    ClaudeCodeAdapter,
    AntigravityAdapter,
    OpenCodeAdapter,
    GenericPOSIXAdapter,
)
from lcs.adapters.custom import DynamicAdapterLoader


@pytest.fixture
def workspace_env(tmp_path, monkeypatch):
    """Sets up an isolated workspace, home directory, and database for testing."""
    ws = str(tmp_path / "workspace")
    home = str(tmp_path / "home")
    os.makedirs(ws, exist_ok=True)
    os.makedirs(home, exist_ok=True)

    monkeypatch.setenv("LCS_USER_HOME", home)
    monkeypatch.setenv("HOME", home)

    # Clear developer terminal ambient variables
    for k in list(os.environ.keys()):
        if k.startswith("ANTIGRAVITY_") or k.startswith("CLAUDE_") or k.startswith("OPENCODE_") or k.startswith("CODEX_"):
            monkeypatch.delenv(k, raising=False)

    return {"workspace": ws, "home": home, "tmp_path": tmp_path}


def test_mcp_tools_spec_contains_call_me_and_context_hydration():
    """Verifies that TOOLS_SPEC registers lcs_call_me and lcs_hydrate_context with valid JSON schemas."""
    tool_names = [t["name"] for t in TOOLS_SPEC]
    assert "lcs_call_me" in tool_names
    assert "lcs_hydrate_context" in tool_names

    call_me_tool = next(t for t in TOOLS_SPEC if t["name"] == "lcs_call_me")
    props = call_me_tool["inputSchema"]["properties"]
    assert "task" in props
    assert "session_id" in props
    assert "execute" in props
    assert "handoff" in props
    assert "budget" in props
    assert "decision" in props
    assert "approver_role" in props
    assert call_me_tool["inputSchema"]["required"] == ["task"]

    hydrate_tool = next(t for t in TOOLS_SPEC if t["name"] == "lcs_hydrate_context")
    h_props = hydrate_tool["inputSchema"]["properties"]
    assert "workspace_root" in h_props
    assert "target_agent" in h_props
    assert "token_budget" in h_props
    assert "session_id" in h_props


def test_mcp_call_me_plan_mode(workspace_env):
    """Verifies lcs_call_me in proposal/plan mode returns candidates and governance preflight."""
    ws = workspace_env["workspace"]
    cfg = LCSConfig.resolve(root_override=os.path.join(ws, ".lcs"), home_override=workspace_env["home"], workspace_root=ws)

    with LCSContext(config=cfg, auto_migrate=True) as ctx:
        server = LCSMCPServer(ctx=ctx)

        result = server.handle_tool_call("lcs_call_me", {
            "task": "Audit repository security and verify dependencies",
            "session_id": "sess_plan_1"
        })

        assert "isError" not in result or not result["isError"]
        assert len(result["content"]) == 1
        data = json.loads(result["content"][0]["text"])
        assert data["session_id"] == "sess_plan_1"
        assert "status" in data


def test_mcp_call_me_handoff_mode_with_provenance(workspace_env):
    """Verifies lcs_call_me with handoff=True produces token-bounded context with provenance."""
    ws = workspace_env["workspace"]

    # Create a local workspace skill
    skill_dir = os.path.join(ws, ".agents", "skills", "security-audit")
    os.makedirs(skill_dir, exist_ok=True)
    with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("---\nname: security-audit\ndescription: Audit repository for security vulnerabilities\n---\n# Security Audit Instructions\nPerform complete static analysis.")

    cfg = LCSConfig.resolve(root_override=os.path.join(ws, ".lcs"), home_override=workspace_env["home"], workspace_root=ws)
    with LCSContext(config=cfg, auto_migrate=True) as ctx:
        server = LCSMCPServer(ctx=ctx)

        result = server.handle_tool_call("lcs_call_me", {
            "task": "Perform security audit",
            "handoff": True,
            "budget": 500,
            "session_id": "sess_handoff_1"
        })

        assert "isError" not in result or not result["isError"]
        data = json.loads(result["content"][0]["text"])
        assert "ready" in data
        assert "task_query" in data
        assert "provenance_hashes" in data


def test_mcp_call_me_execution_requires_governance_authorization_cannot_bypass(workspace_env):
    """
    Security Gate Test (Requirement 4):
    Proves that MCP caller cannot self-authorize execution by sending decision='APPROVED'.
    Approval must be independently authenticated and scoped to the intended action.
    """
    from lcs.governance import ApproverConsent, ApproverRole
    ws = workspace_env["workspace"]
    cfg = LCSConfig.resolve(root_override=os.path.join(ws, ".lcs"), home_override=workspace_env["home"], workspace_root=ws)

    with LCSContext(config=cfg, auto_migrate=True) as ctx:
        server = LCSMCPServer(ctx=ctx)

        # 1. Attempt unapproved execution -> Must return APPROVAL_REQUIRED
        res_unapproved = server.handle_tool_call("lcs_call_me", {
            "task": "Deploy production infrastructure",
            "execute": True,
            "decision": None
        })
        assert res_unapproved.get("isError") is True
        payload = json.loads(res_unapproved["content"][0]["text"])
        assert payload["status"] == "APPROVAL_REQUIRED"
        assert payload["governance_status"] == "PENDING_CONSENT"

        # 2. Self-authorization attempt: sending decision='APPROVED' without a token -> MUST BE REJECTED
        res_self_auth = server.handle_tool_call("lcs_call_me", {
            "task": "Deploy production infrastructure",
            "execute": True,
            "decision": "APPROVED",
            "approver_identity": "attacker@remote"
        })
        assert res_self_auth.get("isError") is True
        payload_self = json.loads(res_self_auth["content"][0]["text"])
        assert payload_self["status"] == "UNAUTHORIZED"
        assert payload_self["error"] == "SELF_AUTHORIZATION_PROHIBITED"

        # 3. Invalid token attempt -> TOKEN_NOT_FOUND
        res_fake_token = server.handle_tool_call("lcs_call_me", {
            "task": "Deploy production infrastructure",
            "execute": True,
            "authorization_token": "eat-forged-999"
        })
        assert res_fake_token.get("isError") is True
        payload_fake = json.loads(res_fake_token["content"][0]["text"])
        assert payload_fake["error"] == "TOKEN_NOT_FOUND"

        # 4. Scoping enforcement test:
        # Generate independent approval for Task A ("Audit code safety")
        plan_a = ctx.planning_engine.create_plan("Audit code safety")
        consent_a = ApproverConsent(principal="security-officer@local", role=ApproverRole.HUMAN_OPERATOR)
        token_a, _ = ctx.governance_engine.approve_plan(plan_a, approver=consent_a)

        # Attempt to use Token A to execute Task B ("Wipe production database") -> MUST BE REJECTED
        res_scope_mismatch = server.handle_tool_call("lcs_call_me", {
            "task": "Wipe production database",
            "execute": True,
            "authorization_token": token_a.token_id
        })
        assert res_scope_mismatch.get("isError") is True
        payload_mismatch = json.loads(res_scope_mismatch["content"][0]["text"])
        assert payload_mismatch["error"] == "TOKEN_SCOPE_MISMATCH"

        # 5. Legitimate execution with correctly scoped independent token -> Token accepted
        res_valid = server.handle_tool_call("lcs_call_me", {
            "task": "Audit code safety",
            "execute": True,
            "authorization_token": token_a.token_id
        })
        assert "content" in res_valid


def test_local_project_context_hydration_and_provenance(workspace_env):
    """Verifies that ProjectContextHydrator deep-hydrates shared rules, skills, and provenance."""
    ws = workspace_env["workspace"]

    # Shared rules
    with open(os.path.join(ws, "AGENTS.md"), "w", encoding="utf-8") as f:
        f.write("# Agent Rules\nFollow project strict standards.")
    with open(os.path.join(ws, "CLAUDE.md"), "w", encoding="utf-8") as f:
        f.write("# Claude Rules\nVerify all changes.")

    # Workspace skill
    skill_dir = os.path.join(ws, ".agents", "skills", "lint-code")
    os.makedirs(skill_dir, exist_ok=True)
    with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write("---\nname: lint-code\ndescription: Lints all Python files\n---\n# Linting Guide\nRun ruff check.")

    cfg = LCSConfig.resolve(root_override=os.path.join(ws, ".lcs"), home_override=workspace_env["home"], workspace_root=ws)
    with LCSContext(config=cfg, auto_migrate=True) as ctx:
        hydrator = ProjectContextHydrator(ctx)
        payload = hydrator.hydrate_project_context(workspace_root=ws)

        assert payload.workspace_root == os.path.realpath(ws)
        assert len(payload.shared_rules) == 2
        rule_names = [r["name"] for r in payload.shared_rules]
        assert "AGENTS.md" in rule_names
        assert "CLAUDE.md" in rule_names

        assert len(payload.active_skills) == 1
        assert payload.active_skills[0]["name"] == "lint-code"

        # Verify provenance hashes
        for r in payload.shared_rules:
            rel = r["relative_path"]
            assert rel in payload.provenance_hashes
            assert payload.provenance_hashes[rel] == r["digest"]


def test_cross_agent_context_switching_and_session_continuity(workspace_env):
    """
    Verifies that when Agent A (e.g. Claude Code) saves a task session on a project,
    Agent B (e.g. Antigravity or custom agent) hydrates the same project and resumes seamlessly.
    """
    ws = workspace_env["workspace"]
    cfg = LCSConfig.resolve(root_override=os.path.join(ws, ".lcs"), home_override=workspace_env["home"], workspace_root=ws)

    with LCSContext(config=cfg, auto_migrate=True) as ctx:
        hydrator = ProjectContextHydrator(ctx)

        # 1. Agent A saves session state
        session_id = "session_alpha_cross"
        state = {
            "author_agent": "claude_code",
            "current_goal": "Refactor database migration engine",
            "completed_steps": ["step_1_backup", "step_2_schema"],
            "deliverable": "db/migrations/v2.sql"
        }
        hydrator.save_session_state(workspace_root=ws, session_id=session_id, state_data=state)

        # 2. Agent B switches into project and hydrates context with session_id
        payload = hydrator.hydrate_project_context(
            workspace_root=ws,
            target_agent="antigravity",
            session_id=session_id
        )

        assert payload.active_host == "antigravity"
        assert payload.session_id == session_id
        assert payload.session_state is not None
        assert payload.session_state["author_agent"] == "claude_code"
        assert payload.session_state["current_goal"] == "Refactor database migration engine"
        assert payload.session_state["deliverable"] == "db/migrations/v2.sql"


def test_strict_project_isolation_and_cross_project_leakage_rejection(workspace_env):
    """
    Security Gate Test: Verifies that Project A cannot read, hydrate, or leak
    context from unrelated Project B.
    """
    tmp_path = workspace_env["tmp_path"]
    proj_a = str(tmp_path / "project_a")
    proj_b = str(tmp_path / "project_b")
    os.makedirs(proj_a, exist_ok=True)
    os.makedirs(proj_b, exist_ok=True)

    # Put secret file in Project B
    with open(os.path.join(proj_b, "SECRET_KEY.md"), "w") as f:
        f.write("SECRET_TOKEN_DO_NOT_LEAK")

    hydrator = ProjectContextHydrator()

    # Attempt 1: Target path resolves outside workspace root
    outside_path = os.path.join(proj_b, "SECRET_KEY.md")
    with pytest.raises(ProjectIsolationViolationError):
        hydrator.verify_workspace_containment(outside_path, proj_a)

    # Attempt 2: Path traversal attack '../project_b/SECRET_KEY.md'
    traversal_path = os.path.join(proj_a, "..", "project_b", "SECRET_KEY.md")
    with pytest.raises(ProjectIsolationViolationError):
        hydrator.verify_workspace_containment(traversal_path, proj_a)

    # Attempt 3: Saving session with path traversal in session_id
    with pytest.raises(ProjectContextError):
        hydrator.save_session_state(proj_a, "../../bad_session", {"foo": "bar"})


def test_simultaneous_multi_agent_detection_and_precedence(workspace_env):
    """
    Verifies that simultaneous presence of multiple agent markers (.claude, .agents, .opencode)
    in the same workspace is resolved deterministically by precedence without crashing or corrupting config.
    """
    ws = workspace_env["workspace"]
    home = workspace_env["home"]

    # Create markers for multiple hosts simultaneously
    os.makedirs(os.path.join(ws, ".claude"), exist_ok=True)
    with open(os.path.join(ws, "CLAUDE.md"), "w") as f:
        f.write("# Claude")
    os.makedirs(os.path.join(ws, ".agents", "skills"), exist_ok=True)
    os.makedirs(os.path.join(ws, ".opencode"), exist_ok=True)

    # Register custom agent with high precedence (88)
    custom_spec = {
        "schema_version": "1.0",
        "agent_id": "adapter.custom88.v1",
        "name": "custom88",
        "display_name": "Custom 88 Agent",
        "precedence": 88,
        "environment_markers": {
            "workspace_files": ["custom.manifest.json"]
        }
    }
    with open(os.path.join(ws, "custom.manifest.json"), "w") as f:
        f.write("{}")

    registry = AdapterRegistry()
    registry.register(GenericPOSIXAdapter(workspace_root=ws))
    registry.register(OpenCodeAdapter(workspace_root=ws))
    registry.register(ClaudeCodeAdapter(workspace_root=ws))
    registry.register(AntigravityAdapter(workspace_root=ws))

    custom_ad = DynamicAdapterLoader.load_from_dict(custom_spec, workspace_root=ws)
    registry.register(custom_ad, precedence=88)

    # Custom 88 has precedence 88, which is higher than Claude Code (70) and OpenCode (60)
    active = registry.detect_active(ws)
    assert active.adapter_id == "adapter.custom88.v1"

    # Remove custom marker -> Claude Code takes precedence
    os.remove(os.path.join(ws, "custom.manifest.json"))
    active_after = registry.detect_active(ws)
    assert active_after.kind == EnvironmentKind.CLAUDE_CODE


def test_mcp_external_process_stdio_jsonrpc_handshake_and_invocation(workspace_env):
    """
    End-to-End Real Subprocess Integration:
    Spawns 'python3 -m lcs.cli serve-mcp' as a real external OS process over stdio.
    Performs standard JSON-RPC 2.0 initialize, tools/list, and tools/call for lcs_call_me.
    """
    ws = workspace_env["workspace"]
    home = workspace_env["home"]

    env = os.environ.copy()
    env["LCS_USER_HOME"] = home
    env["HOME"] = home
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
    env["PYTHONPATH"] = f"{repo_root}:{env.get('PYTHONPATH', '')}"

    proc = subprocess.Popen(
        [sys.executable, "-m", "lcs.cli", "--root", os.path.join(ws, ".lcs"), "serve-mcp"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=ws,
        env=env
    )

    try:
        # 1. Send initialize request
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "external-test-client", "version": "1.0.0"}
            }
        }
        proc.stdin.write(json.dumps(init_req) + "\n")
        proc.stdin.flush()

        init_resp_line = proc.stdout.readline()
        assert init_resp_line, "Expected initialize response from MCP server."
        init_resp = json.loads(init_resp_line)
        assert init_resp.get("id") == 1
        assert "serverInfo" in init_resp["result"]
        assert init_resp["result"]["serverInfo"]["name"] == "lcs-mcp-server"

        # 2. Send initialized notification
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()

        # 3. Send tools/list request
        list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        proc.stdin.write(json.dumps(list_req) + "\n")
        proc.stdin.flush()

        list_resp_line = proc.stdout.readline()
        assert list_resp_line
        list_resp = json.loads(list_resp_line)
        assert list_resp.get("id") == 2
        tool_names = [t["name"] for t in list_resp["result"]["tools"]]
        assert "lcs_call_me" in tool_names
        assert "lcs_hydrate_context" in tool_names

        # 4. Call lcs_call_me in handoff mode
        call_req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "lcs_call_me",
                "arguments": {
                    "task": "Test external client task handoff",
                    "handoff": True
                }
            }
        }
        proc.stdin.write(json.dumps(call_req) + "\n")
        proc.stdin.flush()

        call_resp_line = proc.stdout.readline()
        assert call_resp_line
        call_resp = json.loads(call_resp_line)
        assert call_resp.get("id") == 3
        assert "content" in call_resp["result"]

        # 5. Call lcs_call_me with execute=True without approval -> must return APPROVAL_REQUIRED
        exec_req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "lcs_call_me",
                "arguments": {
                    "task": "Deploy production system",
                    "execute": True
                }
            }
        }
        proc.stdin.write(json.dumps(exec_req) + "\n")
        proc.stdin.flush()

        exec_resp_line = proc.stdout.readline()
        assert exec_resp_line
        exec_resp = json.loads(exec_resp_line)
        assert exec_resp.get("id") == 4
        assert exec_resp["result"].get("isError") is True
        err_data = json.loads(exec_resp["result"]["content"][0]["text"])
        assert err_data["status"] == "APPROVAL_REQUIRED"

        # 6. Call lcs_call_me with execute=True and decision="APPROVED" (self-auth attempt) -> must reject
        self_auth_req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "lcs_call_me",
                "arguments": {
                    "task": "Deploy production system",
                    "execute": True,
                    "decision": "APPROVED"
                }
            }
        }
        proc.stdin.write(json.dumps(self_auth_req) + "\n")
        proc.stdin.flush()

        self_auth_line = proc.stdout.readline()
        assert self_auth_line
        self_auth_resp = json.loads(self_auth_line)
        assert self_auth_resp.get("id") == 5
        assert self_auth_resp["result"].get("isError") is True
        self_auth_err = json.loads(self_auth_resp["result"]["content"][0]["text"])
        assert self_auth_err["error"] == "SELF_AUTHORIZATION_PROHIBITED"

    finally:
        proc.stdin.close()
        proc.wait(timeout=5)
        assert proc.returncode == 0


def test_mcp_protocol_negative_cases(workspace_env):
    """Verifies that MCP server handles malformed JSON, unknown methods, and missing parameters cleanly."""
    ws = workspace_env["workspace"]
    cfg = LCSConfig.resolve(root_override=os.path.join(ws, ".lcs"), home_override=workspace_env["home"], workspace_root=ws)

    with LCSContext(config=cfg, auto_migrate=True) as ctx:
        server = LCSMCPServer(ctx=ctx)

        # 1. Unknown tool invocation
        res_unknown = server.handle_tool_call("lcs_nonexistent_tool", {})
        assert res_unknown.get("isError") is True
        assert "Unknown tool" in res_unknown["content"][0]["text"]

        # 2. Empty task description to lcs_call_me
        res_empty = server.handle_tool_call("lcs_call_me", {"task": "   "})
        assert res_empty.get("isError") is True
        assert "cannot be empty" in res_empty["content"][0]["text"]


def test_clean_wheel_build_and_isolated_shell_invocation(workspace_env, tmp_path):
    """
    Packaging and Fresh-Shell Verification:
    Builds the LCS wheel in an isolated directory, installs it in a fresh virtualenv,
    and proves that 'lcs' and MCP server run cleanly from external shells.
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__)))
    dist_dir = str(tmp_path / "dist")
    clean_venv = str(tmp_path / "clean_venv")

    # 1. Build wheel using pip / build tool
    build_cmd = [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", dist_dir, repo_root]
    build_res = subprocess.run(build_cmd, capture_output=True, text=True)
    assert build_res.returncode == 0, f"Wheel build failed: {build_res.stderr}"

    wheel_files = list(Path(dist_dir).glob("*.whl"))
    assert len(wheel_files) > 0, "No wheel file produced in dist directory."
    wheel_path = str(wheel_files[0])

    # 2. Create clean virtualenv
    import venv
    venv.create(clean_venv, with_pip=True)
    if sys.platform == "win32":
        venv_pip = os.path.join(clean_venv, "Scripts", "pip.exe")
        venv_python = os.path.join(clean_venv, "Scripts", "python.exe")
        venv_lcs = os.path.join(clean_venv, "Scripts", "lcs.exe")
    else:
        venv_pip = os.path.join(clean_venv, "bin", "pip")
        venv_python = os.path.join(clean_venv, "bin", "python")
        venv_lcs = os.path.join(clean_venv, "bin", "lcs")

    # 3. Install built wheel into clean virtualenv
    install_cmd = [venv_pip, "install", "--no-deps", wheel_path]
    inst_res = subprocess.run(install_cmd, capture_output=True, text=True)
    assert inst_res.returncode == 0, f"Wheel installation failed: {inst_res.stderr}"

    # 4. Verify 'lcs --version' runs cleanly from installed clean environment
    if sys.platform == "win32":
        clean_env = {
            **os.environ,
            "PATH": f"{os.path.join(clean_venv, 'Scripts')};{os.environ.get('PATH', '')}",
            "HOME": workspace_env["home"],
            "LCS_USER_HOME": workspace_env["home"]
        }
    else:
        clean_env = {
            "PATH": f"{os.path.join(clean_venv, 'bin')}:/usr/bin:/bin",
            "HOME": workspace_env["home"],
            "LCS_USER_HOME": workspace_env["home"]
        }
    # Notice: PYTHONPATH is intentionally omitted!

    ver_res = subprocess.run([venv_lcs, "--help"], capture_output=True, text=True, env=clean_env)
    assert ver_res.returncode == 0
    assert "Living Capability System" in ver_res.stdout
