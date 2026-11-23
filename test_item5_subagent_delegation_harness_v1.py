"""
Item 5 Verification Test Suite: Real Multi-Agent Subagent Delegation Harness
===========================================================================
Validates:
1. Structured parent-child task creation and parameter handoff.
2. Real child worker subprocess delegation in Generic POSIX environment.
3. Transcript loop bounds enforcement (halting runaway iterations).
4. Multi-tier deliverable verification via AgentVerificationGate.
5. Honest fail-closed behavior when host environment lacks delegation support.
6. Full ExecutionEngineV1 integration for urn:lcs:agent:... capabilities.
"""

import os
import sys
import time
import pytest
import tempfile
from lcs.context import LCSContext
from lcs.config import LCSConfig
from lcs.subagents.models import SubagentTaskState, SubagentTask, SubagentExecutionResult
from lcs.subagents.bridge import AntigravitySubagentBridge
from execution_engine_v1 import ExecutionEngineV1
from capability_planning_v1 import ExecutionPlan, PlanStep, StepInputBinding, StepOutputDefinition
from governance_policy_v1 import (
    ExecutionAuthorizationToken,
    ApproverConsent,
    ApproverRole,
    InterfaceTrustPolicy
)


@pytest.fixture
def lcs_setup(tmp_path, monkeypatch):
    root_dir = str(tmp_path / "workspace")
    os.makedirs(root_dir, exist_ok=True)
    monkeypatch.setenv("ANTIGRAVITY_AGENT_ID", "antigravity-worker-alpha")
    cfg = LCSConfig.resolve(root_override=root_dir)
    ctx = LCSContext(config=cfg)
    yield ctx
    ctx.close()


def test_01_subagent_bridge_task_creation(lcs_setup):
    """Verify structured parent-child task creation and parameter tracking."""
    ctx = lcs_setup
    bridge = AntigravitySubagentBridge(ctx)

    task = bridge.create_task(
        parent_request_id="parent-req-001",
        role="code-reviewer",
        objective="Review security of auth module",
        inputs={"module": "auth.py", "max_iterations": 10},
        constraints=["read_only"],
        expected_deliverables=["review_notes.md"]
    )

    assert task.child_task_id.startswith("subtask-")
    assert task.role == "code-reviewer"
    assert task.objective == "Review security of auth module"
    assert task.child_task_id in bridge.tasks


def test_02_generic_posix_child_worker_delegation(lcs_setup):
    """Verify real worker subprocess execution on Generic POSIX adapter."""
    ctx = lcs_setup
    bridge = AntigravitySubagentBridge(ctx)

    task = bridge.create_task(
        parent_request_id="parent-req-002",
        role="syntax-checker",
        objective="Analyze syntax of source files",
        inputs={"file": "main.py"},
        expected_deliverables=[]
    )

    res = bridge.dispatch_task(task)
    assert res.state == SubagentTaskState.COMPLETED
    assert res.is_verified is True
    assert "syntax-checker" in res.stdout_summary
    assert res.child_task_id in bridge.results


def test_03_transcript_loop_bounds_enforcement(lcs_setup):
    """Verify that exceeding transcript loop bounds (max_iterations) immediately halts execution."""
    ctx = lcs_setup
    bridge = AntigravitySubagentBridge(ctx)

    task = bridge.create_task(
        parent_request_id="parent-req-003",
        role="looping-agent",
        objective="Run in loops",
        inputs={"iteration_count": 55, "max_iterations": 50}
    )

    res = bridge.dispatch_task(task)
    assert res.state == SubagentTaskState.FAILED
    assert res.is_verified is False
    assert "Transcript loop bounds exceeded" in str(res.error_details)


def test_04_missing_deliverable_fails_verification(lcs_setup):
    """Verify that if expected deliverable is missing, verification fails closed."""
    ctx = lcs_setup
    bridge = AntigravitySubagentBridge(ctx)

    # Missing deliverable that child worker doesn't return and doesn't exist on disk
    task = bridge.create_task(
        parent_request_id="parent-req-004",
        role="report-generator",
        objective="Generate report",
        inputs={},
        expected_deliverables=["/nonexistent/missing_report.pdf"]
    )

    res = bridge.dispatch_task(task)
    assert res.state == SubagentTaskState.FAILED
    assert "Missing declared deliverables" in str(res.error_details)


def test_05_unsupported_environment_fails_closed(lcs_setup):
    """Verify that when delegation feature flag is disabled, delegation fails closed honestly."""
    ctx = lcs_setup
    # Explicitly disable subagent bridge feature flag
    bridge = AntigravitySubagentBridge(ctx, feature_flag=False)

    task = bridge.create_task(
        parent_request_id="parent-req-005",
        role="worker",
        objective="Do work"
    )

    res = bridge.dispatch_task(task)
    assert res.state == SubagentTaskState.FAILED
    assert res.is_verified is False
    assert "does not support subagent delegation" in str(res.error_details)


def test_06_execution_engine_agent_capability_dispatch(lcs_setup):
    """Verify end-to-end ExecutionEngineV1 dispatch of urn:lcs:agent:... capabilities."""
    ctx = lcs_setup

    step = PlanStep(
        step_id="step-agent-01",
        step_index=1,
        capability_urn="urn:lcs:agent:code-optimizer",
        display_name="Code Optimizer Agent",
        sub_goal="Optimize memory usage",
        selection_reason="Agent capability",
        input_bindings={"target": StepInputBinding("target", "string", False, bound_value="pipeline.py")},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=[]
    )

    plan = ExecutionPlan(
        plan_id="plan-agent-01",
        request_query="Optimize code with specialist agent",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step],
        dag_edges=[],
        execution_order=["step-agent-01"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Agent dispatch test"
    )

    from lcs.inventory.models import UnifiedResourceRecord, ResourceType, ProvenanceRecord
    import hashlib
    raw_content = "Code optimizer agent"
    content_hash = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
    rec = UnifiedResourceRecord(
        urn=step.capability_urn,
        name="code-optimizer",
        resource_type=ResourceType.AGENT,
        display_name="Code Optimizer Agent",
        description="Code optimizer agent description",
        raw_content=raw_content,
        raw_content_digest=content_hash,
        provenance=ProvenanceRecord(
            origin_host="generic_posix",
            precedence_tier="WORKSPACE",
            source_path="optimizer.py",
            resolved_path="optimizer.py",
            content_hash=content_hash
        )
    )
    ctx.inventory._persist_and_bind_capability(rec)

    consent = ApproverConsent("lead@local", ApproverRole.SECURITY_OFFICER, "CLI_EXPLICIT_TEST")
    policy = InterfaceTrustPolicy("test-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    token, _ = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)

    res = ctx.execution_engine.execute_plan(plan, token)
    assert res.lifecycle_state.value == "SUCCEEDED"
    assert res.completed_steps == 1
    out = res.outputs["step-agent-01"]
    assert "code-optimizer" in str(out)
    assert out.get("verification", {}).get("is_verified") is True
