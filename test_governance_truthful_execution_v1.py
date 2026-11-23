"""
LCS Governance, Truthful Execution & Public Path Enforcement Test Suite (Milestone 2)
=====================================================================================
Comprehensive verification of dual-gate governance authorization, single-use token
lifecycle, deliverable artifact truthfulness, multi-step failure unwinding, and public
execution path enforcement across:
1. CLI execution path (lcs execute / lcs run)
2. API submit / call_me entrypoint
3. MCP tool execution (lcs_execute)
"""

import os
import sys
import io
import time
import json
import shutil
import tempfile
import sqlite3
import pytest
from typing import Dict, Any, List

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.governance import (
    ApproverConsent,
    ApproverRole,
    GovernanceStatus,
    GovernanceRejectedError,
    TokenAlreadyConsumedError,
    PlanIntegrityTamperedError,
    TokenRevokedError,
)
from lcs.planning import (
    ExecutionPlan,
    PlanStep,
    StepInputBinding,
    StepOutputDefinition,
    BindingSourceType,
)
from lcs.execution import (
    ExecutionLifecycleState,
    StepExecutionStatus,
    StepExecutionError,
    PreflightVerificationError,
)
from lcs.policy import InterfaceTrustPolicy
from lcs.mcp_server import LCSMCPServer


@pytest.fixture
def gov_env():
    raw_dir = tempfile.mkdtemp(prefix="lcs_gov_exec_")
    real_dir = os.path.realpath(raw_dir)
    ws_dir = os.path.join(real_dir, "workspace")
    os.makedirs(ws_dir, exist_ok=True)

    cfg = LCSConfig.resolve(root_override=ws_dir)
    ctx = LCSContext(config=cfg, auto_migrate=True)

    yield {
        "ctx": ctx,
        "root": real_dir,
        "workspace": ws_dir,
    }

    ctx.close()
    shutil.rmtree(real_dir, ignore_errors=True)


def create_test_skill(ws_dir: str, name: str, instructions: str) -> str:
    skill_dir = os.path.join(ws_dir, ".agents", "skills", name)
    os.makedirs(skill_dir, exist_ok=True)
    skill_md = os.path.join(skill_dir, "SKILL.md")
    with open(skill_md, "w", encoding="utf-8") as f:
        f.write(
            f"---\n"
            f"name: {name}\n"
            f"description: Test skill {name}\n"
            f"---\n"
            f"# {name}\n"
            f"{instructions}\n"
        )
    return skill_md


# ============================================================================
# Gate 1 & Gate 2 Authorization Invariants
# ============================================================================

def test_01_discovery_and_text_never_grants_authorization(gov_env):
    """
    Gate 1: Discovery, parameter resolution, and skill text alone NEVER grant execution authorization.
    An unapproved plan has status PENDING_APPROVAL and zero dispatch permits.
    """
    ctx: LCSContext = gov_env["ctx"]
    ws = gov_env["workspace"]
    create_test_skill(ws, "unauthorized-worker", "Instructions.")
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    # Task submitted through call-me API without execute=True
    resp = ctx.call_me.execute_call_me("/call-me run unauthorized worker", execute=False)
    assert resp is not None
    assert resp.status == "ACCEPTED"
    assert resp.governance_status == "PENDING_APPROVAL"
    # No execution run or token was minted
    cur = ctx.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM execution_runs;")
    assert cur.fetchone()[0] == 0
    cur.execute("SELECT COUNT(*) FROM governance_dispatch_permits;")
    assert cur.fetchone()[0] == 0


def test_02_missing_or_denied_approval_halts_dispatch(gov_env):
    """
    Gate 2: Missing or denied operator consent halts dispatch closed.
    Zero execution steps are performed.
    """
    ctx: LCSContext = gov_env["ctx"]
    ws = gov_env["workspace"]
    create_test_skill(ws, "denied-worker", "Instructions.")
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    # Attempt execution with approver_consent=None
    res = ctx.call_me.execute_call_me(
        "/call-me run denied worker",
        execute=True,
        approver_consent=None
    )
    assert res is not None
    assert res["status"] == "REJECTED"
    assert "Explicit operator consent is required" in res["message"]
    assert res["completed_steps"] == 0

    # Verify zero execution records in DB
    cur = ctx.conn.cursor()
    cur.execute("SELECT COUNT(*) FROM execution_runs;")
    assert cur.fetchone()[0] == 0


def test_03_altered_plan_fails_closed(gov_env):
    """
    An altered plan between approval and dispatch fails closed with PlanIntegrityTamperedError.
    Token is marked REVOKED.
    """
    ctx: LCSContext = gov_env["ctx"]
    ws = gov_env["workspace"]
    create_test_skill(ws, "tamper-check", "Instructions.")
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    step = PlanStep(
        step_id="step-tamper",
        step_index=1,
        capability_urn="urn:lcs:skill:antigravity:tamper-check",
        display_name="Tamper Check",
        sub_goal="Test tampering",
        selection_reason="Test",
        input_bindings={},
        output_definitions={"result": StepOutputDefinition("result", "string")}
    )
    plan = ExecutionPlan(
        plan_id="plan-tamper-01",
        request_query="tamper check",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step],
        dag_edges=[],
        execution_order=["step-tamper"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Test plan"
    )

    consent = ApproverConsent(principal="admin@local", role=ApproverRole.HUMAN_OPERATOR, method="TEST")
    policy = InterfaceTrustPolicy(policy_name="test-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)

    token, eval_res = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)
    assert token is not None
    assert eval_res.status == GovernanceStatus.APPROVED

    # Tamper with the plan before execution by altering a step's capability
    plan.steps[0].capability_urn = "urn:lcs:skill:antigravity:tampered-malicious-cap"

    # Execution should fail closed
    with pytest.raises(PreflightVerificationError) as exc_info:
        ctx.execution_engine.execute_plan(plan=plan, token=token)

    assert "integrity" in str(exc_info.value).lower() or "tamper" in str(exc_info.value).lower()

    # Token must now be REVOKED in database
    cur = ctx.conn.cursor()
    cur.execute("SELECT state FROM governance_tokens WHERE jti = ?;", (token.token_id,))
    assert cur.fetchone()[0] == "REVOKED"


def test_04_replayed_token_fails_closed(gov_env):
    """
    A single-use EAT token cannot be replayed. Second execution fails closed with TokenAlreadyConsumedError.
    """
    ctx: LCSContext = gov_env["ctx"]
    ws = gov_env["workspace"]
    create_test_skill(ws, "replay-check", "Instructions.")
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    step = PlanStep(
        step_id="step-replay",
        step_index=1,
        capability_urn="urn:lcs:skill:antigravity:replay-check",
        display_name="Replay Check",
        sub_goal="Test replay",
        selection_reason="Test",
        input_bindings={},
        output_definitions={"result": StepOutputDefinition("result", "string")}
    )
    plan = ExecutionPlan(
        plan_id="plan-replay-01",
        request_query="replay check",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step],
        dag_edges=[],
        execution_order=["step-replay"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Test plan"
    )

    consent = ApproverConsent(principal="admin@local", role=ApproverRole.HUMAN_OPERATOR, method="TEST")
    policy = InterfaceTrustPolicy(policy_name="test-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)

    token, _ = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)

    # First execution succeeds
    res1 = ctx.execution_engine.execute_plan(plan=plan, token=token)
    assert res1.lifecycle_state == ExecutionLifecycleState.SUCCEEDED

    # Second execution using same consumed token must fail closed
    with pytest.raises(PreflightVerificationError) as exc_info:
        ctx.execution_engine.execute_plan(plan=plan, token=token)

    assert "already been consumed" in str(exc_info.value).lower() or "token_already_consumed" in str(exc_info.value).lower()


# ============================================================================
# Truthful Deliverable Verification & Failure Handling
# ============================================================================

def test_05_missing_deliverable_reported_as_failed(gov_env):
    """
    Truthful Execution: If a capability declares a deliverable artifact but fails to create it,
    the skill execution handler must report the step as FAILED.
    """
    ctx: LCSContext = gov_env["ctx"]
    ws = gov_env["workspace"]
    create_test_skill(ws, "deliverable-generator", "Instructions.")
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    missing_deliv_path = os.path.join(ws, "non_existent_report.pdf")

    step = PlanStep(
        step_id="step-deliv-missing",
        step_index=1,
        capability_urn="urn:lcs:skill:antigravity:deliverable-generator",
        display_name="Deliverable Generator",
        sub_goal="Create report",
        selection_reason="Test",
        input_bindings={"deliverable": StepInputBinding("deliverable", "string", False, bound_value=missing_deliv_path)},
        output_definitions={"result": StepOutputDefinition("result", "string")}
    )
    plan = ExecutionPlan(
        plan_id="plan-deliv-01",
        request_query="create deliverable report",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step],
        dag_edges=[],
        execution_order=["step-deliv-missing"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Test plan"
    )

    consent = ApproverConsent(principal="admin@local", role=ApproverRole.HUMAN_OPERATOR, method="TEST")
    policy = InterfaceTrustPolicy(policy_name="test-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    token, _ = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)

    res = ctx.execution_engine.execute_plan(plan=plan, token=token)
    assert res.lifecycle_state == ExecutionLifecycleState.FAILED
    assert res.completed_steps == 0
    assert len(res.step_records) >= 1
    assert res.step_records[0].status == StepExecutionStatus.FAILED
    assert "Requested deliverable artifact was not created" in (res.step_records[0].error_details or "")


def test_06_mid_plan_failure_marks_subsequent_steps_skipped(gov_env):
    """
    A multi-step plan that fails mid-execution must:
    - Mark the failing step as FAILED.
    - Mark all subsequent steps as SKIPPED (never COMPLETED).
    - Distinguish capabilities that ran, failed, and were skipped in execution receipts.
    """
    ctx: LCSContext = gov_env["ctx"]
    ws = gov_env["workspace"]
    create_test_skill(ws, "step-1-worker", "Instructions.")
    create_test_skill(ws, "step-2-worker", "Instructions.")
    create_test_skill(ws, "step-3-worker", "Instructions.")
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    # Step 1: Normal success
    s1 = PlanStep(
        step_id="step-1",
        step_index=1,
        capability_urn="urn:lcs:skill:antigravity:step-1-worker",
        display_name="Step 1",
        sub_goal="Goal 1",
        selection_reason="Test",
        input_bindings={},
        output_definitions={"result": StepOutputDefinition("result", "string")}
    )

    # Step 2: Configured to fail via missing deliverable
    missing_file = os.path.join(ws, "does_not_exist.txt")
    s2 = PlanStep(
        step_id="step-2",
        step_index=2,
        capability_urn="urn:lcs:skill:antigravity:step-2-worker",
        display_name="Step 2",
        sub_goal="Goal 2",
        selection_reason="Test",
        input_bindings={"deliverable_file": StepInputBinding("deliverable_file", "string", False, bound_value=missing_file)},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=["step-1"]
    )

    # Step 3: Subsequent step that must be skipped
    s3 = PlanStep(
        step_id="step-3",
        step_index=3,
        capability_urn="urn:lcs:skill:antigravity:step-3-worker",
        display_name="Step 3",
        sub_goal="Goal 3",
        selection_reason="Test",
        input_bindings={},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=["step-2"]
    )

    plan = ExecutionPlan(
        plan_id="plan-multistep-fail",
        request_query="multistep failure test",
        plan_type="MULTI_CAPABILITY",
        status="PLAN_READY",
        steps=[s1, s2, s3],
        dag_edges=[],
        execution_order=["step-1", "step-2", "step-3"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Test plan"
    )

    consent = ApproverConsent(principal="admin@local", role=ApproverRole.HUMAN_OPERATOR, method="TEST")
    policy = InterfaceTrustPolicy(policy_name="test-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    token, _ = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)

    res = ctx.execution_engine.execute_plan(plan=plan, token=token)

    assert res.lifecycle_state == ExecutionLifecycleState.FAILED
    assert res.completed_steps == 1
    assert res.total_steps == 3

    statuses = {s.step_id: s.status for s in res.step_records}
    assert statuses["step-1"] in (StepExecutionStatus.COMPLETED, StepExecutionStatus.COMPENSATED)
    assert statuses["step-2"] == StepExecutionStatus.FAILED
    assert statuses["step-3"] == StepExecutionStatus.SKIPPED

    # In database
    cur = ctx.conn.cursor()
    cur.execute("SELECT step_id, status FROM execution_step_records WHERE run_id = ? ORDER BY step_index ASC;", (res.run_id,))
    db_rows = dict(cur.fetchall())
    assert db_rows["step-2"] == "FAILED"
    assert db_rows["step-3"] == "SKIPPED"


# ============================================================================
# Public Execution Paths: CLI, API, MCP
# ============================================================================

def test_07_public_path_mcp_tool_execution(gov_env):
    """
    Exercises MCP tool path (lcs_execute):
    - Valid token executes successfully.
    - Missing token returns isError=True.
    - Replayed token returns isError=True.
    """
    ctx: LCSContext = gov_env["ctx"]
    ws = gov_env["workspace"]
    create_test_skill(ws, "mcp-executable", "Instructions.")
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    step = PlanStep(
        step_id="step-mcp-01",
        step_index=1,
        capability_urn="urn:lcs:skill:antigravity:mcp-executable",
        display_name="MCP Executable",
        sub_goal="Test MCP execution",
        selection_reason="Test",
        input_bindings={},
        output_definitions={"result": StepOutputDefinition("result", "string")}
    )
    plan = ExecutionPlan(
        plan_id="plan-mcp-01",
        request_query="mcp test",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step],
        dag_edges=[],
        execution_order=["step-mcp-01"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Test MCP plan"
    )

    consent = ApproverConsent(principal="admin@local", role=ApproverRole.HUMAN_OPERATOR, method="TEST")
    policy = InterfaceTrustPolicy(policy_name="test-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    token, _ = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)

    server = LCSMCPServer(ctx)

    # 1. Valid execution via MCP tool call
    res_mcp = server.handle_tool_call("lcs_execute", {
        "plan_json": plan.to_dict(),
        "token_id": token.token_id
    })
    assert "isError" not in res_mcp or res_mcp.get("isError") is False
    mcp_out = json.loads(res_mcp["content"][0]["text"])
    assert mcp_out["lifecycle_state"] == "SUCCEEDED"
    assert mcp_out["completed_steps"] == 1

    # 2. Replay via MCP tool call fails closed
    replay_mcp = server.handle_tool_call("lcs_execute", {
        "plan_json": plan.to_dict(),
        "token_id": token.token_id
    })
    assert replay_mcp.get("isError") is True or "consumed" in replay_mcp["content"][0]["text"].lower() or "failed" in replay_mcp["content"][0]["text"].lower()

    # 3. Missing token via MCP tool call fails closed
    missing_mcp = server.handle_tool_call("lcs_execute", {
        "plan_json": plan.to_dict(),
        "token_id": "non-existent-token-id"
    })
    assert missing_mcp.get("isError") is True
    assert "not found" in missing_mcp["content"][0]["text"].lower()
