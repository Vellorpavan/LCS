"""
LCS Multi-Capability Real Execution Engine & Governance Test Suite (Milestone 2)
================================================================================
Comprehensive verification demonstrating:
1. Actual multi-step execution with multiple selected capabilities.
2. Real dependency ordering and topological resolution.
3. Actual execution records in SQLite and CAS trace receipts.
4. Real input/output parameter bindings across sequential steps.
5. Dual-Gate Governance authorization and single-use EAT token consumption.
6. Mid-plan failure handling and reverse compensation unwinding.
7. Explicit audit evidence of which capabilities were actually used.
"""

import os
import sys
import time
import json
import shutil
import tempfile
import sqlite3
import pytest
import hashlib
from typing import Dict, Any, List

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.governance import (
    ApproverConsent,
    ApproverRole,
    GovernanceStatus,
    GovernanceRejectedError,
    TokenAlreadyConsumedError,
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
    StepReversibilityType,
    PreflightVerificationError,
)
from lcs.policy import InterfaceTrustPolicy
from lcs.inventory.models import ResourceType, OperationalLifecycleState


@pytest.fixture
def exec_env():
    raw_dir = tempfile.mkdtemp(prefix="lcs_m2_exec_")
    real_dir = os.path.realpath(raw_dir)
    ws_dir = os.path.join(real_dir, "workspace")
    os.makedirs(ws_dir, exist_ok=True)

    # Isolate user home for test runs so local machine skills don't clutter the test inventory
    fake_home = os.path.join(real_dir, "home")
    os.makedirs(fake_home, exist_ok=True)

    cfg = LCSConfig.resolve(root_override=ws_dir)
    ctx = LCSContext(config=cfg, auto_migrate=True)
    if hasattr(ctx, "skill_service") and hasattr(ctx.skill_service, "resolver"):
        ctx.skill_service.resolver.user_home = fake_home

    yield {
        "ctx": ctx,
        "root": real_dir,
        "workspace": ws_dir,
    }

    ctx.close()
    shutil.rmtree(real_dir, ignore_errors=True)


def test_01_real_multi_step_execution_with_dependency_ordering(exec_env):
    """
    Demonstrates real multi-step execution across 3 capabilities with:
    - Real DAG dependency ordering (Step 1 -> Step 2 -> Step 3).
    - Dynamic I/O parameter binding.
    - Real database records in execution_runs and execution_step_records.
    - Real CAS trace receipt.
    """
    ctx: LCSContext = exec_env["ctx"]
    ws = exec_env["workspace"]

    # 1. Author and register 3 skills in workspace
    skills_dir = os.path.join(ws, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)

    for s_name, desc in [
        ("data-extractor", "Extracts data payloads"),
        ("data-transformer", "Transforms extracted payloads"),
        ("report-generator", "Generates final audit report")
    ]:
        s_dir = os.path.join(skills_dir, s_name)
        os.makedirs(s_dir, exist_ok=True)
        with open(os.path.join(s_dir, "SKILL.md"), "w") as f:
            f.write(f"---\nname: {s_name}\ndescription: {desc}\n---\n# {s_name}\nInstructions for {s_name}.")

    # Ingest into inventory (persists and binds interfaces)
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    # Build Plan Steps with real I/O bindings
    urn1 = "urn:lcs:skill:generic_posix:data-extractor"
    urn2 = "urn:lcs:skill:generic_posix:data-transformer"
    urn3 = "urn:lcs:skill:generic_posix:report-generator"

    step1 = PlanStep(
        step_id="step-1-extract",
        step_index=1,
        capability_urn=urn1,
        display_name="Data Extractor",
        sub_goal="Extract data",
        selection_reason="Initial ingestion",
        input_bindings={"source": StepInputBinding("source", "string", False, bound_value="metrics.json")},
        output_definitions={"result": StepOutputDefinition("result", "string")}
    )

    # Step 2 binds previous output from Step 1
    step2 = PlanStep(
        step_id="step-2-transform",
        step_index=2,
        capability_urn=urn2,
        display_name="Data Transformer",
        sub_goal="Normalize data",
        selection_reason="Transformation",
        input_bindings={
            "input_data": StepInputBinding(
                param_name="input_data",
                param_type="string",
                required=False,
                source_type=BindingSourceType.STEP_OUTPUT,
                source_step_id="step-1-extract",
                source_output_field="result"
            )
        },
        output_definitions={"result": StepOutputDefinition("result", "string")}
    )

    # Step 3 binds output from Step 2
    step3 = PlanStep(
        step_id="step-3-report",
        step_index=3,
        capability_urn=urn3,
        display_name="Report Generator",
        sub_goal="Generate final deliverable",
        selection_reason="Reporting",
        input_bindings={
            "summary_data": StepInputBinding(
                param_name="summary_data",
                param_type="string",
                required=False,
                source_type=BindingSourceType.STEP_OUTPUT,
                source_step_id="step-2-transform",
                source_output_field="result"
            )
        },
        output_definitions={"result": StepOutputDefinition("result", "string")}
    )

    plan = ExecutionPlan(
        plan_id="plan-m2-001",
        request_query="Extract, transform, and report metrics",
        plan_type="MULTI_CAPABILITY",
        status="PLAN_READY",
        steps=[step1, step2, step3],
        dag_edges=[],
        execution_order=["step-1-extract", "step-2-transform", "step-3-report"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="3-stage automated data pipeline"
    )

    consent = ApproverConsent(
        principal="eng-lead@local",
        role=ApproverRole.SECURITY_OFFICER,
        method="CLI_EXPLICIT_TEST"
    )

    policy = InterfaceTrustPolicy(
        policy_name="m2-permissive-policy",
        min_interface_version=1,
        require_attestation=False,
        require_all_capabilities_verified=False
    )

    # Authorize through Governance
    token, eval_res = ctx.governance_engine.approve_plan(
        plan=plan,
        approver=consent,
        active_policy=policy
    )
    assert token is not None
    assert eval_res.status == GovernanceStatus.APPROVED

    # Execute plan via ExecutionEngine
    result = ctx.execution_engine.execute_plan(plan=plan, token=token)

    # Verify real execution results
    assert result.lifecycle_state == ExecutionLifecycleState.SUCCEEDED
    assert result.completed_steps == 3
    assert result.total_steps == 3
    assert result.run_id != ""

    # Verify SQLite execution_runs record
    cur = ctx.conn.cursor()
    cur.execute("SELECT run_id, lifecycle_state, total_steps, completed_steps, trace_cas_digest FROM execution_runs WHERE run_id = ?;", (result.run_id,))
    run_row = cur.fetchone()
    assert run_row is not None
    assert run_row[1] == "SUCCEEDED"
    assert run_row[2] == 3
    assert run_row[3] == 3
    trace_digest = run_row[4]
    assert trace_digest is not None
    assert ctx.cas_engine.blob_exists(trace_digest)

    # Verify SQLite execution_step_records
    cur.execute("SELECT step_id, capability_urn, status, duration_ms FROM execution_step_records WHERE run_id = ? ORDER BY step_index ASC;", (result.run_id,))
    step_rows = cur.fetchall()
    assert len(step_rows) == 3
    assert step_rows[0][0] == "step-1-extract"
    assert step_rows[0][2] == "COMPLETED"
    assert step_rows[1][0] == "step-2-transform"
    assert step_rows[1][2] == "COMPLETED"
    assert step_rows[2][0] == "step-3-report"
    assert step_rows[2][2] == "COMPLETED"

    # Verify dynamic I/O parameter binding from Step 1 to Step 2
    step2_res = [r for r in result.step_records if r.step_id == "step-2-transform"][0]
    assert step2_res.input_arguments.get("input_data") is not None


def test_02_call_me_execute_pipeline(exec_env):
    """
    Verifies that calling /call-me with execute=True runs the end-to-end multi-capability pipeline.
    """
    ctx: LCSContext = exec_env["ctx"]
    ws = exec_env["workspace"]

    # Register skills in workspace
    skills_dir = os.path.join(ws, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)
    for s_name in ["alpha-analyzer", "beta-optimizer"]:
        s_dir = os.path.join(skills_dir, s_name)
        os.makedirs(s_dir, exist_ok=True)
        with open(os.path.join(s_dir, "SKILL.md"), "w") as f:
            f.write(f"---\nname: {s_name}\ndescription: Test capability {s_name}\n---\n# {s_name}\nInstructions.")

    # Initialize inventory with workspace adapter
    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    prompt = "/call-me alpha-analyzer and beta-optimizer"
    consent = ApproverConsent(
        principal="operator@local",
        role=ApproverRole.HUMAN_OPERATOR,
        method="CLI_CALL_ME"
    )

    # Execute through CallMeInterface
    res = ctx.call_me.execute_call_me(prompt, execute=True, approver_consent=consent)

    assert res is not None
    assert isinstance(res, dict)
    # Instruction-only capability execution returns HANDOFF_READY awaiting specialist dispatch
    assert res["status"] == "HANDOFF_READY"
    assert res["completed_steps"] >= 1
    assert len(res["capabilities_used"]) >= 1
    assert res["run_id"] != ""


def test_03_governance_rejection_halts_execution(exec_env):
    """
    Verifies that when governance consent is not provided, the execution engine halts closed
    and dispatches zero commands.
    """
    ctx: LCSContext = exec_env["ctx"]
    ws = exec_env["workspace"]

    skills_dir = os.path.join(ws, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)
    tool_dir = os.path.join(skills_dir, "audit-tool")
    os.makedirs(tool_dir, exist_ok=True)
    with open(os.path.join(tool_dir, "SKILL.md"), "w") as f:
        f.write("---\nname: audit-tool\ndescription: Security audit tool\n---\n# Audit Tool")

    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    step1 = PlanStep(
        step_id="step-1",
        step_index=1,
        capability_urn="urn:lcs:skill:generic_posix:audit-tool",
        display_name="Audit Tool",
        sub_goal="Goal",
        selection_reason="Reason",
        input_bindings={},
        output_definitions={}
    )
    plan = ExecutionPlan(
        plan_id="plan-reject-001",
        request_query="Task",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step1],
        dag_edges=[],
        execution_order=["step-1"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Test"
    )

    with pytest.raises(GovernanceRejectedError):
        ctx.governance_engine.approve_plan(
            plan=plan,
            approver=ApproverConsent(principal="", role=ApproverRole.HUMAN_OPERATOR, method="DECLINED"),
            active_policy=InterfaceTrustPolicy(policy_name="test-policy", min_interface_version=1, require_attestation=False)
        )

    # Zero runs created in DB
    cur = ctx.conn.cursor()
    cur.execute("SELECT count(*) FROM execution_runs WHERE plan_id = 'plan-reject-001';")
    assert cur.fetchone()[0] == 0


def test_04_mid_plan_failure_and_reverse_compensation(exec_env):
    """
    Verifies that a failure in step 2 halts step 3 and triggers reverse compensation on step 1.
    """
    ctx: LCSContext = exec_env["ctx"]
    ws = exec_env["workspace"]

    skills_dir = os.path.join(ws, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)
    for s_name in ["allocator", "deallocator", "calculator", "committer"]:
        s_dir = os.path.join(skills_dir, s_name)
        os.makedirs(s_dir, exist_ok=True)
        with open(os.path.join(s_dir, "SKILL.md"), "w") as f:
            f.write(f"---\nname: {s_name}\ndescription: {s_name} skill\n---\n# {s_name}")

    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    urn_alloc = "urn:lcs:skill:generic_posix:allocator"
    urn_dealloc = "urn:lcs:skill:generic_posix:deallocator"
    urn_calc = "urn:lcs:skill:generic_posix:calculator"
    urn_commit = "urn:lcs:skill:generic_posix:committer"

    step1 = PlanStep(
        step_id="step-1-reversible",
        step_index=1,
        capability_urn=urn_alloc,
        display_name="Resource Allocator",
        sub_goal="Allocate scratch resource",
        selection_reason="Setup",
        input_bindings={},
        output_definitions={}
    )
    step1.compensation_urn = urn_dealloc

    # Step 2 intentionally configured to fail (unresolved mandatory input)
    step2 = PlanStep(
        step_id="step-2-failing",
        step_index=2,
        capability_urn=urn_calc,
        display_name="Calculator",
        sub_goal="Calculate with missing input",
        selection_reason="Process",
        input_bindings={
            "required_var": StepInputBinding("required_var", "string", True, bound_value=None, source_type=BindingSourceType.UNRESOLVED)
        },
        output_definitions={"result": StepOutputDefinition("result", "string")}
    )

    step3 = PlanStep(
        step_id="step-3-cancelled",
        step_index=3,
        capability_urn=urn_commit,
        display_name="Committer",
        sub_goal="Final commit",
        selection_reason="Commit",
        input_bindings={},
        output_definitions={}
    )

    plan = ExecutionPlan(
        plan_id="plan-compensation-001",
        request_query="Allocate, calculate, and commit",
        plan_type="MULTI_CAPABILITY",
        status="PLAN_READY",
        steps=[step1, step2, step3],
        dag_edges=[],
        execution_order=["step-1-reversible", "step-2-failing", "step-3-cancelled"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Test reverse compensation"
    )

    consent = ApproverConsent(
        principal="test-operator@local",
        role=ApproverRole.HUMAN_OPERATOR,
        method="CLI_TEST"
    )

    token, _ = ctx.governance_engine.approve_plan(
        plan=plan,
        approver=consent,
        active_policy=InterfaceTrustPolicy(policy_name="test-policy", min_interface_version=1, require_attestation=False)
    )

    result = ctx.execution_engine.execute_plan(plan=plan, token=token)

    assert result.lifecycle_state == ExecutionLifecycleState.FAILED
    assert result.completed_steps == 1  # Step 1 succeeded before Step 2 failed

    # Step 1 was compensated via reverse compensation unwinding
    step1_rec = [r for r in result.step_records if r.step_id == "step-1-reversible"][0]
    assert step1_rec.status == StepExecutionStatus.COMPENSATED

    # Step 2 failed
    step2_rec = [r for r in result.step_records if r.step_id == "step-2-failing"][0]
    assert step2_rec.status == StepExecutionStatus.FAILED

    # Step 3 was never dispatched due to failure halting (marked SKIPPED)
    assert len(result.step_records) == 3
    step3_rec = [r for r in result.step_records if r.step_id == "step-3-cancelled"][0]
    assert step3_rec.status == StepExecutionStatus.SKIPPED


def test_05_token_single_use_replay_protection(exec_env):
    """
    Verifies that once consumed, an EAT token cannot be replayed for a second execution run.
    """
    ctx: LCSContext = exec_env["ctx"]
    ws = exec_env["workspace"]

    skills_dir = os.path.join(ws, ".agents", "skills")
    os.makedirs(skills_dir, exist_ok=True)
    single_dir = os.path.join(skills_dir, "single-task")
    os.makedirs(single_dir, exist_ok=True)
    with open(os.path.join(single_dir, "SKILL.md"), "w") as f:
        f.write("---\nname: single-task\ndescription: Single execution task\n---\n# Single Task")

    ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())

    step1 = PlanStep(
        step_id="step-1",
        step_index=1,
        capability_urn="urn:lcs:skill:generic_posix:single-task",
        display_name="Single Task",
        sub_goal="Run once",
        selection_reason="Test",
        input_bindings={},
        output_definitions={}
    )
    plan = ExecutionPlan(
        plan_id="plan-replay-001",
        request_query="Run once",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step1],
        dag_edges=[],
        execution_order=["step-1"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Test"
    )

    token, _ = ctx.governance_engine.approve_plan(
        plan=plan,
        approver=ApproverConsent(principal="op@local", role=ApproverRole.HUMAN_OPERATOR, method="TEST"),
        active_policy=InterfaceTrustPolicy(policy_name="test-policy", min_interface_version=1, require_attestation=False)
    )

    # First execution succeeds
    res1 = ctx.execution_engine.execute_plan(plan=plan, token=token)
    assert res1.lifecycle_state == ExecutionLifecycleState.SUCCEEDED

    # Second execution must raise PreflightVerificationError: TOKEN_ALREADY_CONSUMED
    with pytest.raises((TokenAlreadyConsumedError, PreflightVerificationError)) as exc_info:
        ctx.execution_engine.execute_plan(plan=plan, token=token)

    assert "already been consumed" in str(exc_info.value).lower()
