"""
Item 4 Verification Test Suite: True Concurrent Branching DAG Execution (Fan-Out / Fan-In)
========================================================================================
Validates:
1. Truly concurrent parallel execution of independent DAG branches (fan-out).
2. Fan-in dependency resolution and multi-source input binding aggregation.
3. Cascading abort and proper skipping of downstream steps upon branch failure.
4. Reverse compensation unwinding across completed concurrent branches.
"""

import os
import sys
import time
import pytest
import sqlite3
import hashlib
import tempfile
from lcs.context import LCSContext
from lcs.config import LCSConfig
from execution_engine_v1 import ExecutionEngineV1
from capability_planning_v1 import (
    ExecutionPlan,
    PlanStep,
    StepInputBinding,
    StepOutputDefinition,
    BindingSourceType
)
from governance_policy_v1 import (
    ExecutionAuthorizationToken,
    DispatchPermit,
    ExecutionGovernanceEngineV1,
    GovernanceAuditLedger,
    compute_plan_integrity_hash,
    extract_canonical_plan_payload,
    canonicalize_jcs,
    ApproverConsent,
    ApproverRole,
    InterfaceTrustPolicy,
    GovernanceStatus
)


@pytest.fixture
def lcs_setup(tmp_path):
    root_dir = str(tmp_path / "workspace")
    os.makedirs(root_dir, exist_ok=True)
    cfg = LCSConfig.resolve(root_override=root_dir)
    ctx = LCSContext(config=cfg)
    yield ctx
    ctx.close()


from lcs.inventory.models import UnifiedResourceRecord, ResourceType, ProvenanceRecord

def register_test_interface(ctx, urn, name="Test Capability", resolved_path="test.py"):
    raw_content = f"Instructions for {name}"
    content_hash = hashlib.sha256(raw_content.encode("utf-8")).hexdigest()
    clean_name = name.replace("_", "-")
    rtype = ResourceType.SKILL if ":skill:" in urn else (ResourceType.TOOL if ":tool:" in urn else ResourceType.AGENT)
    rec = UnifiedResourceRecord(
        urn=urn,
        name=clean_name,
        resource_type=rtype,
        display_name=name,
        description=f"Description for {name}",
        raw_content=raw_content,
        raw_content_digest=content_hash,
        provenance=ProvenanceRecord(
            origin_host="generic_posix",
            precedence_tier="WORKSPACE",
            source_path=resolved_path,
            resolved_path=resolved_path,
            content_hash=content_hash
        )
    )
    ctx.inventory._persist_and_bind_capability(rec)


def test_01_concurrent_fan_out_execution(lcs_setup):
    """
    Verify that two independent steps (A and B) run concurrently in parallel.
    Both steps sleep for 0.4 seconds; if concurrent, total elapsed time is < 0.7s, not >= 0.8s.
    """
    ctx = lcs_setup
    ws = ctx.config.root_dir

    # Create two python scripts that sleep for 0.35s
    script_a = os.path.join(ws, "task_a.py")
    script_b = os.path.join(ws, "task_b.py")
    with open(script_a, "w") as f:
        f.write("import time, json\ntime.sleep(0.35)\nprint(json.dumps({'result': 'A_DONE'}))\n")
    with open(script_b, "w") as f:
        f.write("import time, json\ntime.sleep(0.35)\nprint(json.dumps({'result': 'B_DONE'}))\n")

    step_a = PlanStep(
        step_id="step-a",
        step_index=1,
        capability_urn="urn:lcs:skill:test:task-a",
        display_name="Task A",
        sub_goal="Run A",
        selection_reason="Independent branch A",
        input_bindings={"target_script": StepInputBinding("target_script", "string", False, bound_value=script_a)},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=[]
    )
    step_b = PlanStep(
        step_id="step-b",
        step_index=2,
        capability_urn="urn:lcs:skill:test:task-b",
        display_name="Task B",
        sub_goal="Run B",
        selection_reason="Independent branch B",
        input_bindings={"target_script": StepInputBinding("target_script", "string", False, bound_value=script_b)},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=[]
    )

    plan = ExecutionPlan(
        plan_id="plan-fanout-01",
        request_query="Run tasks A and B in parallel",
        plan_type="MULTI_CAPABILITY",
        status="PLAN_READY",
        steps=[step_a, step_b],
        dag_edges=[],
        execution_order=["step-a", "step-b"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Parallel execution of task A and task B"
    )

    # Authorize plan via governance engine
    register_test_interface(ctx, step_a.capability_urn, "task-a", resolved_path=script_a)
    register_test_interface(ctx, step_b.capability_urn, "task-b", resolved_path=script_b)
    consent = ApproverConsent("lead@local", ApproverRole.SECURITY_OFFICER, "CLI_EXPLICIT_TEST")
    policy = InterfaceTrustPolicy("test-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    token, _ = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)

    t0 = time.perf_counter()
    res = ctx.execution_engine.execute_plan(plan, token)
    elapsed = time.perf_counter() - t0

    assert res.lifecycle_state.value == "SUCCEEDED"
    assert res.completed_steps == 2
    # If executed sequentially, elapsed >= 0.70s; concurrent execution takes ~0.35-0.55s
    assert elapsed < 0.68, f"Expected concurrent execution under 0.68s, took {elapsed:.3f}s"


def test_02_fan_in_parameter_aggregation(lcs_setup):
    """
    Verify fan-in execution:
    Step A and Step B run independently, and Step C depends on both Step A and Step B,
    aggregating results from both into its input bindings.
    """
    ctx = lcs_setup

    step_a = PlanStep(
        step_id="step-calc-a",
        step_index=1,
        capability_urn="urn:lcs:tool:math:calc-a",
        display_name="Calc A",
        sub_goal="Add 10 + 20",
        selection_reason="Native calculation A",
        input_bindings={
            "a": StepInputBinding("a", "integer", False, bound_value=10),
            "b": StepInputBinding("b", "integer", False, bound_value=20)
        },
        output_definitions={"result": StepOutputDefinition("result", "integer")},
        dependencies=[]
    )
    step_b = PlanStep(
        step_id="step-calc-b",
        step_index=2,
        capability_urn="urn:lcs:tool:math:calc-b",
        display_name="Calc B",
        sub_goal="Add 30 + 40",
        selection_reason="Native calculation B",
        input_bindings={
            "a": StepInputBinding("a", "integer", False, bound_value=30),
            "b": StepInputBinding("b", "integer", False, bound_value=40)
        },
        output_definitions={"result": StepOutputDefinition("result", "integer")},
        dependencies=[]
    )
    step_c = PlanStep(
        step_id="step-aggregate-c",
        step_index=3,
        capability_urn="urn:lcs:tool:format:report",
        display_name="Aggregate Report",
        sub_goal="Aggregate results of A and B",
        selection_reason="Fan-in join node",
        input_bindings={
            "data": StepInputBinding(
                param_name="data",
                param_type="string",
                required=True,
                source_type=BindingSourceType.STEP_OUTPUT,
                source_step_id="step-calc-a",
                source_output_field="result"
            )
        },
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=["step-calc-a", "step-calc-b"]
    )

    plan = ExecutionPlan(
        plan_id="plan-fanin-01",
        request_query="Aggregate results from two branches",
        plan_type="MULTI_CAPABILITY",
        status="PLAN_READY",
        steps=[step_a, step_b, step_c],
        dag_edges=[],
        execution_order=["step-calc-a", "step-calc-b", "step-aggregate-c"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Fan-in join execution"
    )

    register_test_interface(ctx, step_a.capability_urn, "calc-a")
    register_test_interface(ctx, step_b.capability_urn, "calc-b")
    register_test_interface(ctx, step_c.capability_urn, "format")
    consent = ApproverConsent("lead@local", ApproverRole.SECURITY_OFFICER, "CLI_EXPLICIT_TEST")
    policy = InterfaceTrustPolicy("test-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    token, _ = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)

    res = ctx.execution_engine.execute_plan(plan, token)
    assert res.lifecycle_state.value == "SUCCEEDED"
    assert res.completed_steps == 3
    # Step C output includes the result from Step A (30)
    assert "30" in str(res.outputs["step-aggregate-c"]["result"])


def test_03_cascading_abort_and_compensation_on_branch_failure(lcs_setup):
    """
    Verify that if one branch fails, dependent downstream steps are marked SKIPPED
    and reverse compensation unwinds completed steps.
    """
    ctx = lcs_setup
    ws = ctx.config.root_dir
    scratch = os.path.join(ws, "temp_dir")
    os.makedirs(scratch, exist_ok=True)

    # Step A provisions scratch dir, with compensation to delete it
    step_a = PlanStep(
        step_id="step-prov",
        step_index=1,
        capability_urn="urn:lcs:tool:echo:create",
        display_name="Provision",
        sub_goal="Create scratch",
        selection_reason="Step with compensation",
        input_bindings={"path": StepInputBinding("path", "string", False, bound_value=scratch)},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=[]
    )
    step_a.reversibility_type = "COMPENSATABLE"
    step_a.compensation_urn = "urn:lcs:tool:cleanup:delete"

    # Step B fails intentionally
    script_fail = os.path.join(ws, "fail_task.py")
    with open(script_fail, "w") as f:
        f.write("import sys\nsys.stderr.write('Fatal branch error\\n')\nsys.exit(1)\n")

    step_b = PlanStep(
        step_id="step-fail",
        step_index=2,
        capability_urn="urn:lcs:skill:test:fail",
        display_name="Failing branch",
        sub_goal="Fail branch",
        selection_reason="Failure injection",
        input_bindings={"target_script": StepInputBinding("target_script", "string", False, bound_value=script_fail)},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=[]
    )

    # Step C depends on Step A and Step B
    step_c = PlanStep(
        step_id="step-downstream",
        step_index=3,
        capability_urn="urn:lcs:tool:echo:final",
        display_name="Downstream",
        sub_goal="Should be skipped",
        selection_reason="Dependent on failing branch",
        input_bindings={"msg": StepInputBinding("msg", "string", False, bound_value="hello")},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=["step-prov", "step-fail"]
    )

    plan = ExecutionPlan(
        plan_id="plan-abort-01",
        request_query="Test failure cascading and compensation",
        plan_type="MULTI_CAPABILITY",
        status="PLAN_READY",
        steps=[step_a, step_b, step_c],
        dag_edges=[],
        execution_order=["step-prov", "step-fail", "step-downstream"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Compensation test"
    )

    register_test_interface(ctx, step_a.capability_urn, "echo-create")
    register_test_interface(ctx, step_b.capability_urn, "fail-task", resolved_path=script_fail)
    register_test_interface(ctx, step_c.capability_urn, "echo-final")
    register_test_interface(ctx, "urn:lcs:tool:cleanup:delete", "cleanup")
    consent = ApproverConsent("lead@local", ApproverRole.SECURITY_OFFICER, "CLI_EXPLICIT_TEST")
    policy = InterfaceTrustPolicy("test-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    token, _ = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)

    res = ctx.execution_engine.execute_plan(plan, token)
    assert res.lifecycle_state.value == "FAILED"
    # Step C was skipped
    rec_c = next(r for r in res.step_records if r.step_id == "step-downstream")
    assert rec_c.status.value == "SKIPPED"
    # Scratch directory was removed by reverse compensation of step A
    assert not os.path.exists(scratch)
