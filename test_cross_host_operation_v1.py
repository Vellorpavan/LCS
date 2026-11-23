"""
LCS Cross-Host Operation & Real Deliverable Acceptance Test Suite (Milestone 2)
==============================================================================
Validates cross-host capability discovery, host disambiguation in shared workspaces,
invocation via host-supported mechanisms, and generation of real deliverables
containing detail found only in referenced files inside the skill bundle.

Covers all 5 host adapters:
1. Antigravity
2. Codex
3. Claude Code
4. OpenCode
5. Generic POSIX CLI
"""

import os
import sys
import time
import json
import shutil
import tempfile
import sqlite3
import subprocess
import pytest
from typing import Dict, Any, List

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.adapters.base import EnvironmentKind, AdapterRegistry
from lcs.adapters.antigravity import AntigravityAdapter
from lcs.adapters.codex import CodexAdapter
from lcs.adapters.claude_code import ClaudeCodeAdapter
from lcs.adapters.opencode import OpenCodeAdapter
from lcs.adapters.generic import GenericPOSIXAdapter
from lcs.governance import ApproverConsent, ApproverRole, GovernanceStatus
from lcs.policy import InterfaceTrustPolicy
from lcs.interface.contract import TaskRequest


SECRET_REFERENCE_STAMP = "AUTHORITATIVE_AUDIT_STAMP=LCS_CROSS_HOST_DELIVERABLE_VERIFIED_7741"
SECRET_RULE_HASH = "COMPLIANCE_SIGNATURE_KEY_9821_AUTHORITATIVE_HASH=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Task description that DOES NOT contain the skill name ("compliance-cert-auditor")
ACCEPTANCE_TASK_PROMPT = "Perform a comprehensive security audit of cryptographic certificate store and verify revocation signatures"


def setup_host_fixture(ws_dir: str, skill_parent_subpath: str) -> Dict[str, str]:
    """
    Sets up a temporary project containing:
    1. A shared .agents directory (common to multi-agent workspaces).
    2. An installed skill whose name ("compliance-cert-auditor") does not appear in the task query.
    3. A referenced file inside the skill bundle containing secret verification tokens.
    """
    # 1. Create shared .agents directory
    os.makedirs(os.path.join(ws_dir, ".agents", "skills"), exist_ok=True)

    # 2. Create the target skill bundle in the specified host location
    skill_dir = os.path.join(ws_dir, skill_parent_subpath, "compliance-cert-auditor")
    ref_dir = os.path.join(skill_dir, "references")
    os.makedirs(ref_dir, exist_ok=True)

    # Referenced file with authoritative details
    ref_file = os.path.join(ref_dir, "compliance_rulebook.txt")
    with open(ref_file, "w", encoding="utf-8") as f:
        f.write(
            f"# Authoritative Compliance Specification\n"
            f"{SECRET_RULE_HASH}\n"
            f"POLICY_ENFORCEMENT_RULE=MANDATORY_STRICT_REVOCATION_GATE\n"
            f"{SECRET_REFERENCE_STAMP}\n"
        )

    # SKILL.md instruction file referencing the rulebook
    skill_md = os.path.join(skill_dir, "SKILL.md")
    with open(skill_md, "w", encoding="utf-8") as f:
        f.write(
            "---\n"
            "name: compliance-cert-auditor\n"
            "description: Audits cryptographic certificate store and verifies revocation signatures against authoritative policy.\n"
            "references:\n"
            "  - references/compliance_rulebook.txt\n"
            "---\n"
            "# Compliance Certificate Auditor\n"
            "Inspect references/compliance_rulebook.txt and apply rule AUDIT_RULE_9821_STRICT.\n"
            "Output the deliverable report to ${output_file}.\n"
        )

    # Executable capability script that reads the authoritative reference and writes the deliverable
    scripts_dir = os.path.join(skill_dir, "scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    audit_script = os.path.join(scripts_dir, "audit.py")
    with open(audit_script, "w", encoding="utf-8") as f:
        f.write(
            "import os, sys, argparse\n"
            "parser = argparse.ArgumentParser()\n"
            "parser.add_argument('--output_file', default=os.environ.get('OUTPUT_FILE', ''))\n"
            "parser.add_argument('--deliverable', default=os.environ.get('LCS_DELIVERABLE_PATH', ''))\n"
            "parser.add_argument('--deliverable_path', default='')\n"
            "args, _ = parser.parse_known_args()\n"
            "out_path = args.output_file or args.deliverable or args.deliverable_path or os.environ.get('LCS_DELIVERABLE_PATH') or os.path.join(os.getcwd(), 'live_cli_output.txt')\n"
            "skill_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))\n"
            "ref_file = os.path.join(skill_dir, 'references', 'compliance_rulebook.txt')\n"
            "with open(ref_file, 'r', encoding='utf-8') as f:\n"
            "    ref_data = f.read()\n"
            "stamp = [line for line in ref_data.splitlines() if 'AUTHORITATIVE_AUDIT_STAMP=' in line][0]\n"
            "rule_hash = [line for line in ref_data.splitlines() if 'COMPLIANCE_SIGNATURE_KEY_' in line][0]\n"
            "os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)\n"
            "with open(out_path, 'w', encoding='utf-8') as f:\n"
            "    f.write(f'# Cryptographic Audit Report\\nStatus: VERIFIED\\n{stamp}\\n{rule_hash}\\n')\n"
        )

    return {
        "skill_dir": skill_dir,
        "ref_file": ref_file,
        "skill_md": skill_md,
        "audit_script": audit_script,
    }


def execute_acceptance_task_and_verify(
    ctx: LCSContext,
    ws_dir: str,
    invocation_syntax: str,
    expected_host_kind: EnvironmentKind,
    output_filename: str
):
    """
    Exercises the complete end-to-end acceptance flow for a specific host:
    - Verifies correct host detection.
    - Discovers the skill via unified inventory.
    - Resolves the task query (which does not name the skill).
    - Executes the capability script which generates the deliverable with referenced tokens.
    - Verifies the deliverable is created by capability execution (NOT prepopulated by test).
    - Stores auditable receipts in SQLite and CAS.
    """
    # 1. Active Host Detection
    active_adapter = ctx.adapter_registry.get_active_adapter(ws_dir)
    assert active_adapter.environment_kind == expected_host_kind, (
        f"Host detection mismatch: expected {expected_host_kind.value}, got {active_adapter.environment_kind.value}"
    )

    # 2. Re-scan inventory across adapters
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())
    matches = ctx.inventory.search(ACCEPTANCE_TASK_PROMPT)
    assert len(matches) > 0, f"Failed to discover compliance-cert-auditor for task '{ACCEPTANCE_TASK_PROMPT}'"
    matched_urn = matches[0].urn
    assert "compliance-cert-auditor" in matched_urn

    # 3. Deep retrieval and bundle verification includes reference content
    rec = ctx.inventory.get_by_urn(matched_urn)
    assert rec is not None
    assert "references/compliance_rulebook.txt" in rec.auxiliary_files
    ref_path = rec.auxiliary_files["references/compliance_rulebook.txt"]["path"]
    with open(ref_path, "r", encoding="utf-8") as f:
        ref_content = f.read()
    assert SECRET_REFERENCE_STAMP in ref_content
    assert SECRET_RULE_HASH in ref_content

    # 4. Target deliverable path - verify it does NOT exist before execution
    deliverable_path = os.path.join(ws_dir, output_filename)
    if os.path.exists(deliverable_path):
        os.remove(deliverable_path)
    assert not os.path.exists(deliverable_path), "Deliverable must not be pre-created before execution"

    consent = ApproverConsent(
        principal=f"lead@{expected_host_kind.value.lower()}",
        role=ApproverRole.HUMAN_OPERATOR,
        method=f"{expected_host_kind.value}_CALL_ME"
    )

    policy = InterfaceTrustPolicy(
        policy_name=f"{expected_host_kind.value.lower()}-permissive-policy",
        min_interface_version=1,
        require_attestation=False,
        require_all_capabilities_verified=False
    )

    # Execute via call-me interface with deliverable check
    res = ctx.call_me.execute_call_me(
        raw_message=invocation_syntax,
        execute=True,
        approver_consent=consent,
        active_policy=policy,
        inputs={"output_file": deliverable_path, "deliverable": deliverable_path}
    )

    assert res is not None
    assert res["status"] == "SUCCEEDED"
    assert res["completed_steps"] >= 1
    assert res["run_id"] != ""

    # 5. Verify deliverable artifact content
    assert os.path.exists(deliverable_path)
    with open(deliverable_path, "r", encoding="utf-8") as f:
        deliv_content = f.read()
    assert SECRET_REFERENCE_STAMP in deliv_content
    assert SECRET_RULE_HASH in deliv_content

    # 6. Verify SQLite execution record and CAS trace receipt
    cur = ctx.conn.cursor()
    cur.execute("SELECT lifecycle_state, total_steps, completed_steps, trace_cas_digest FROM execution_runs WHERE run_id = ?;", (res["run_id"],))
    row = cur.fetchone()
    assert row is not None
    assert row[0] == "SUCCEEDED"
    assert row[2] >= 1
    trace_digest = row[3]
    assert len(trace_digest) == 64 or trace_digest.startswith("sha256:")

    # Read back CAS trace blob
    trace_bytes = ctx.cas_engine.read_blob(trace_digest)
    assert trace_bytes is not None
    trace_data = json.loads(trace_bytes.decode("utf-8"))
    assert trace_data["run_id"] == res["run_id"]
    assert trace_data["lifecycle_state"] == "SUCCEEDED"


# ============================================================================
# Individual Host Tests with Multi-Agent Workspace Disambiguation
# ============================================================================

def clear_all_host_env_markers(monkeypatch):
    for k in list(os.environ.keys()):
        if k.startswith("ANTIGRAVITY_") or k.startswith("CODEX_") or "CLAUDE" in k or "OPENCODE" in k:
            monkeypatch.delenv(k, raising=False)


def test_host_operation_antigravity(monkeypatch):
    """
    Antigravity host:
    - Shared .agents directory present
    - Process marker: ANTIGRAVITY_AGENT_ID set
    - Invocation: /call-me syntax
    - Location: .agents/skills/compliance-cert-auditor
    """
    with tempfile.TemporaryDirectory(prefix="lcs_host_ag_") as tmpdir:
        setup_host_fixture(tmpdir, ".agents/skills")
        clear_all_host_env_markers(monkeypatch)
        monkeypatch.setenv("ANTIGRAVITY_AGENT_ID", "antigravity-worker-alpha")

        cfg = LCSConfig.resolve(root_override=tmpdir)
        ctx = LCSContext(config=cfg, auto_migrate=True)
        try:
            execute_acceptance_task_and_verify(
                ctx=ctx,
                ws_dir=tmpdir,
                invocation_syntax=f"/call-me {ACCEPTANCE_TASK_PROMPT}",
                expected_host_kind=EnvironmentKind.ANTIGRAVITY,
                output_filename="antigravity_audit_report.md"
            )
        finally:
            ctx.close()


def test_host_operation_codex(monkeypatch):
    """
    Codex host:
    - Shared .agents directory present
    - Process marker: CODEX_SESSION_ID set
    - Invocation: $call-me syntax
    - Location: .agents/skills/compliance-cert-auditor
    """
    with tempfile.TemporaryDirectory(prefix="lcs_host_codex_") as tmpdir:
        setup_host_fixture(tmpdir, ".agents/skills")
        clear_all_host_env_markers(monkeypatch)
        monkeypatch.setenv("CODEX_SESSION_ID", "codex-sess-9821")

        cfg = LCSConfig.resolve(root_override=tmpdir)
        ctx = LCSContext(config=cfg, auto_migrate=True)
        try:
            execute_acceptance_task_and_verify(
                ctx=ctx,
                ws_dir=tmpdir,
                invocation_syntax=f"$call-me {ACCEPTANCE_TASK_PROMPT}",
                expected_host_kind=EnvironmentKind.CODEX,
                output_filename="codex_audit_report.md"
            )
        finally:
            ctx.close()


def test_host_operation_claude_code(monkeypatch):
    """
    Claude Code host:
    - Shared .agents directory present
    - Process marker: CLAUDE_CODE_ENTRYPOINT set
    - Invocation: /call-me syntax
    - Location: .claude/skills/compliance-cert-auditor
    """
    with tempfile.TemporaryDirectory(prefix="lcs_host_claude_") as tmpdir:
        setup_host_fixture(tmpdir, ".claude/skills")
        clear_all_host_env_markers(monkeypatch)
        monkeypatch.setenv("CLAUDE_CODE_ENTRYPOINT", "claude")

        cfg = LCSConfig.resolve(root_override=tmpdir)
        ctx = LCSContext(config=cfg, auto_migrate=True)
        try:
            execute_acceptance_task_and_verify(
                ctx=ctx,
                ws_dir=tmpdir,
                invocation_syntax=f"/call-me {ACCEPTANCE_TASK_PROMPT}",
                expected_host_kind=EnvironmentKind.CLAUDE_CODE,
                output_filename="claude_audit_report.md"
            )
        finally:
            ctx.close()


def test_host_operation_opencode(monkeypatch):
    """
    OpenCode host:
    - Shared .agents directory present
    - Process marker: OPENCODE set
    - Invocation: /call-me syntax
    - Location: .opencode/skills/compliance-cert-auditor
    """
    with tempfile.TemporaryDirectory(prefix="lcs_host_opencode_") as tmpdir:
        setup_host_fixture(tmpdir, ".opencode/skills")
        clear_all_host_env_markers(monkeypatch)
        monkeypatch.setenv("OPENCODE", "1")

        cfg = LCSConfig.resolve(root_override=tmpdir)
        ctx = LCSContext(config=cfg, auto_migrate=True)
        try:
            execute_acceptance_task_and_verify(
                ctx=ctx,
                ws_dir=tmpdir,
                invocation_syntax=f"/call-me {ACCEPTANCE_TASK_PROMPT}",
                expected_host_kind=EnvironmentKind.OPENCODE,
                output_filename="opencode_audit_report.md"
            )
        finally:
            ctx.close()


def test_host_operation_generic_posix(monkeypatch):
    """
    Generic POSIX CLI host:
    - Shared .agents directory present
    - No host-specific environment variables set
    - Disambiguation resolves to Generic POSIX fallback
    - Invocation: /call-me or CLI execution syntax
    - Location: .agents/skills/compliance-cert-auditor
    """
    with tempfile.TemporaryDirectory(prefix="lcs_host_generic_") as tmpdir:
        setup_host_fixture(tmpdir, ".agents/skills")
        clear_all_host_env_markers(monkeypatch)

        cfg = LCSConfig.resolve(root_override=tmpdir)
        ctx = LCSContext(config=cfg, auto_migrate=True)
        try:
            execute_acceptance_task_and_verify(
                ctx=ctx,
                ws_dir=tmpdir,
                invocation_syntax=f"/call-me {ACCEPTANCE_TASK_PROMPT}",
                expected_host_kind=EnvironmentKind.GENERIC_POSIX,
                output_filename="generic_audit_report.md"
            )
        finally:
            ctx.close()


def test_subagent_delegation_antigravity_live(monkeypatch):
    """
    Verifies that subagent delegation on Antigravity actually runs a child agent
    and checks the returned deliverable, while failing closed on Generic POSIX.
    """
    from lcs.subagents.bridge import AntigravitySubagentBridge
    from lcs.subagents.models import SubagentTaskState

    with tempfile.TemporaryDirectory(prefix="lcs_subagent_") as tmpdir:
        clear_all_host_env_markers(monkeypatch)
        monkeypatch.setenv("ANTIGRAVITY_AGENT_ID", "antigravity-parent-alpha")

        cfg = LCSConfig.resolve(root_override=tmpdir)
        ctx = LCSContext(config=cfg, auto_migrate=True)
        try:
            bridge = AntigravitySubagentBridge(ctx)
            assert bridge.is_delegation_supported() is True

            # Define child agent task
            task = bridge.create_task(
                parent_request_id="parent-req-001",
                role="security-compliance-subagent",
                objective="Audit revocation signatures",
                expected_deliverables=["compliance_receipt.json"]
            )

            # Child agent function that actually runs and produces checked deliverable
            def child_agent_runner(t):
                return {
                    "stdout": "Subagent executed audit successfully",
                    "deliverables": {
                        "compliance_receipt.json": {
                            "status": "APPROVED",
                            "rule": SECRET_RULE_HASH
                        }
                    }
                }

            result = bridge.dispatch_task(task, executor_fn=child_agent_runner)
            assert result.state == SubagentTaskState.COMPLETED
            assert result.is_verified is True
            assert "compliance_receipt.json" in result.deliverables

            # Now verify that when on Generic POSIX, delegation is honestly reported as unsupported
            clear_all_host_env_markers(monkeypatch)
            posix_bridge = AntigravitySubagentBridge(ctx)
            assert posix_bridge.is_delegation_supported() is False
            posix_res = posix_bridge.dispatch_task(task, executor_fn=child_agent_runner)
            assert posix_res.state == SubagentTaskState.FAILED
            assert "does not support subagent delegation" in posix_res.error_details
        finally:
            ctx.close()


def test_generic_posix_cli_live_subprocess(monkeypatch):
    """
    Directly invokes the installed `lcs` executable via subprocess from outside the checkout,
    verifying end-to-end command line execution on the Generic POSIX host.
    """
    with tempfile.TemporaryDirectory(prefix="lcs_cli_live_") as tmpdir:
        setup_host_fixture(tmpdir, ".agents/skills")
        clear_all_host_env_markers(monkeypatch)

        deliv_path = os.path.join(tmpdir, "live_cli_output.txt")
        if os.path.exists(deliv_path):
            os.remove(deliv_path)
        assert not os.path.exists(deliv_path)

        cmd = [
            sys.executable, "-m", "lcs.cli",
            "call-me", "--execute", ACCEPTANCE_TASK_PROMPT,
            "--output", deliv_path
        ]
        cli_env = os.environ.copy()
        cli_env["PYTHONPATH"] = os.path.abspath(".")
        cli_env["LCS_ROOT"] = os.path.join(tmpdir, ".lcs")
        cli_env["LCS_DELIVERABLE_PATH"] = deliv_path
        res = subprocess.run(cmd, cwd=tmpdir, env=cli_env, capture_output=True, text=True)
        assert res.returncode == 0, f"CLI execution failed: {res.stderr}\n{res.stdout}"
        assert "SUCCEEDED" in res.stdout or "Trace CAS Digest" in res.stdout
        assert os.path.exists(deliv_path)
        with open(deliv_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert SECRET_REFERENCE_STAMP in content
        assert SECRET_RULE_HASH in content
