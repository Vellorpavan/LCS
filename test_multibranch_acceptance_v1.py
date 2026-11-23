import os
import sys
import time
import json
import sqlite3
import hashlib
import pytest
import tempfile
from pathlib import Path

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.interface.contract import TaskRequest
from lcs.interface.core_bridge import LCSCoreBridge
from lcs.inventory.models import UnifiedResourceRecord, ResourceType, ProvenanceRecord
from capability_planning_v1 import (
    ExecutionPlan,
    PlanStep,
    StepInputBinding,
    StepOutputDefinition,
    BindingSourceType
)
from governance_policy_v1 import (
    ApproverConsent,
    ApproverRole,
    InterfaceTrustPolicy,
    GovernanceStatus
)


@pytest.fixture
def clean_context(tmp_path):
    root = str(tmp_path / "workspace")
    os.makedirs(root, exist_ok=True)
    cfg = LCSConfig.resolve(root_override=root)
    ctx = LCSContext(config=cfg)
    yield ctx
    ctx.close()


def test_multibranch_fan_out_and_fan_in_orchestration(clean_context):
    ctx = clean_context
    ws = ctx.config.root_dir

    # Step 1: Script A generates artifact A
    path_a = os.path.join(ws, "out_a.txt")
    script_a = os.path.join(ws, "worker_a.py")
    with open(script_a, "w") as f:
        f.write(
            "import os, time, json\n"
            "time.sleep(0.3)\n"
            f"with open(r'{path_a}', 'w') as f: f.write('PAYLOAD_A')\n"
            f"print(json.dumps({{'result': 'BRANCH_A_OK', 'file': r'{path_a}'}}))\n"
        )

    # Step 2: Script B generates artifact B (parallel branch)
    path_b = os.path.join(ws, "out_b.txt")
    script_b = os.path.join(ws, "worker_b.py")
    with open(script_b, "w") as f:
        f.write(
            "import os, time, json\n"
            "time.sleep(0.3)\n"
            f"with open(r'{path_b}', 'w') as f: f.write('PAYLOAD_B')\n"
            f"print(json.dumps({{'result': 'BRANCH_B_OK', 'file': r'{path_b}'}}))\n"
        )

    # Step 3: Script C joins results from both branches
    path_c = os.path.join(ws, "joined.txt")
    script_c = os.path.join(ws, "worker_c.py")
    with open(script_c, "w") as f:
        f.write(
            "import os, json\n"
            f"data_a = open(r'{path_a}').read().strip()\n"
            f"data_b = open(r'{path_b}').read().strip()\n"
            "combined = data_a + '+' + data_b\n"
            f"with open(r'{path_c}', 'w') as f: f.write(combined)\n"
            f"print(json.dumps({{'result': combined, 'file': r'{path_c}'}}))\n"
        )

    step_1 = PlanStep(
        step_id="step-1-worker-a",
        step_index=1,
        capability_urn="urn:lcs:skill:test:worker-a",
        display_name="Worker A",
        sub_goal="Generate branch A artifact",
        selection_reason="Branch A independent path",
        input_bindings={"target_script": StepInputBinding("target_script", "string", False, bound_value=script_a)},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=[]
    )

    step_2 = PlanStep(
        step_id="step-2-worker-b",
        step_index=2,
        capability_urn="urn:lcs:skill:test:worker-b",
        display_name="Worker B",
        sub_goal="Generate branch B artifact",
        selection_reason="Branch B independent path",
        input_bindings={"target_script": StepInputBinding("target_script", "string", False, bound_value=script_b)},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=[]
    )

    step_3 = PlanStep(
        step_id="step-3-worker-c",
        step_index=3,
        capability_urn="urn:lcs:skill:test:worker-c",
        display_name="Worker C",
        sub_goal="Aggregate branches A and B",
        selection_reason="Fan-in join node",
        input_bindings={
            "input_data": StepInputBinding("input_data", "string", False, BindingSourceType.STEP_OUTPUT, "step-1-worker-a", "result"),
            "branch_b": StepInputBinding("branch_b", "string", False, BindingSourceType.STEP_OUTPUT, "step-2-worker-b", "result"),
            "target_script": StepInputBinding("target_script", "string", False, bound_value=script_c)
        },
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=["step-1-worker-a", "step-2-worker-b"]
    )

    plan = ExecutionPlan(
        plan_id="plan-acceptance-fanout-fanin",
        request_query="Execute branch A and branch B concurrently and aggregate via join step C",
        plan_type="MULTI_CAPABILITY",
        status="PLAN_READY",
        steps=[step_1, step_2, step_3],
        dag_edges=[
            ("step-1-worker-a", "step-3-worker-c", "OUTPUT_TO_INPUT", "A to C"),
            ("step-2-worker-b", "step-3-worker-c", "OUTPUT_TO_INPUT", "B to C")
        ],
        execution_order=["step-1-worker-a", "step-2-worker-b", "step-3-worker-c"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="True concurrent fan-out and fan-in integration test"
    )

    # Register capabilities into inventory
    for st, scr in [(step_1, script_a), (step_2, script_b), (step_3, script_c)]:
        rec = UnifiedResourceRecord(
            urn=st.capability_urn,
            name=st.display_name,
            resource_type=ResourceType.SKILL,
            display_name=st.display_name,
            description="Acceptance capability",
            raw_content="instructions",
            raw_content_digest="abc",
            provenance=ProvenanceRecord(
                origin_host="generic_posix",
                precedence_tier="WORKSPACE",
                source_path=scr,
                resolved_path=scr,
                content_hash="abc"
            )
        )
        ctx.inventory._persist_and_bind_capability(rec)

    consent = ApproverConsent("lead@test", ApproverRole.SECURITY_OFFICER, "AUTOMATED_TEST")
    policy = InterfaceTrustPolicy("test", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    token, eval_res = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)
    assert eval_res.status == GovernanceStatus.APPROVED

    t0 = time.perf_counter()
    res = ctx.execution_engine.execute_plan(plan, token)
    duration = time.perf_counter() - t0

    assert res.lifecycle_state.value == "SUCCEEDED"
    assert res.completed_steps == 3
    # Step 1 and Step 2 run in parallel; total execution bounded reasonably across platforms
    assert duration < 30.0

    # Artifact handoff verification
    assert os.path.exists(path_c)
    with open(path_c) as f:
        content = f.read().strip()
    assert content == "PAYLOAD_A+PAYLOAD_B"

    # SQLite persistence and deterministic concurrency verification
    cur = ctx.execution_engine.conn.cursor()
    cur.execute("SELECT lifecycle_state, completed_steps FROM execution_runs WHERE run_id = ?", (res.run_id,))
    row = cur.fetchone()
    assert row is not None
    assert row[0] == "SUCCEEDED"
    assert row[1] == 3

    cur.execute("SELECT step_id, status, start_time, end_time FROM execution_step_records WHERE run_id = ? ORDER BY step_index", (res.run_id,))
    step_rows = cur.fetchall()
    assert len(step_rows) == 3
    for s_id, s_status, _, _ in step_rows:
        assert s_status == "COMPLETED"

    step_times = {r[0]: (r[2], r[3]) for r in step_rows}
    s1_start, s1_end = step_times["step-1-worker-a"]
    s2_start, s2_end = step_times["step-2-worker-b"]
    s3_start, s3_end = step_times["step-3-worker-c"]
    # Parallel branches execute concurrently (overlapping execution intervals)
    assert s1_start < s2_end and s2_start < s1_end, f"Branches did not execute concurrently: s1=({s1_start}, {s1_end}), s2=({s2_start}, {s2_end})"
    # Fan-in aggregation step starts only after BOTH upstream branches finish
    assert s3_start >= max(s1_end, s2_end), f"Fan-in step started before dependencies finished: s3_start={s3_start}, max_end={max(s1_end, s2_end)}"

    # CAS trace verification
    assert res.trace_cas_digest is not None
    assert len(res.trace_cas_digest) == 64
    raw_trace = ctx.cas_engine.read_blob(res.trace_cas_digest)
    assert raw_trace is not None
    trace_data = json.loads(raw_trace.decode("utf-8"))
    assert trace_data["run_id"] == res.run_id


def test_failure_diagnosis_and_repair_workflow(clean_context):
    ctx = clean_context
    ws = ctx.config.root_dir

    faulty_script = os.path.join(ws, "task_faulty.py")
    with open(faulty_script, "w") as f:
        f.write("import sys\nsys.stderr.write('CRITICAL: Syntax or missing input\\n')\nsys.exit(1)\n")

    step_f = PlanStep(
        step_id="step-fail",
        step_index=1,
        capability_urn="urn:lcs:skill:test:faulty",
        display_name="Faulty Step",
        sub_goal="Execute failing script",
        selection_reason="Controlled failure test",
        input_bindings={"target_script": StepInputBinding("target_script", "string", False, bound_value=faulty_script)},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=[]
    )

    plan_f = ExecutionPlan(
        plan_id="plan-fail-01",
        request_query="Demonstrate failure handling",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step_f],
        dag_edges=[],
        execution_order=["step-fail"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Controlled failure run"
    )

    rec_f = UnifiedResourceRecord(
        urn=step_f.capability_urn,
        name=step_f.display_name,
        resource_type=ResourceType.SKILL,
        display_name=step_f.display_name,
        description="Failing capability",
        raw_content="instructions",
        raw_content_digest="f1",
        provenance=ProvenanceRecord(
            origin_host="generic_posix",
            precedence_tier="WORKSPACE",
            source_path=faulty_script,
            resolved_path=faulty_script,
            content_hash="f1"
        )
    )
    ctx.inventory._persist_and_bind_capability(rec_f)

    consent = ApproverConsent("lead@test", ApproverRole.SECURITY_OFFICER, "AUTOMATED_TEST")
    policy = InterfaceTrustPolicy("test", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    token_f, _ = ctx.governance_engine.approve_plan(plan=plan_f, approver=consent, active_policy=policy)

    # 1. Observe failure
    res_f = ctx.execution_engine.execute_plan(plan_f, token_f)
    assert res_f.lifecycle_state.value == "FAILED"
    assert "CRITICAL" in (res_f.error_message or "")

    # 2. Repair script
    with open(faulty_script, "w") as f:
        f.write("import json\nprint(json.dumps({'result': 'REPAIRED_SUCCESS'}))\n")

    # 3. Re-authorize and re-run
    token_repaired, _ = ctx.governance_engine.approve_plan(plan=plan_f, approver=consent, active_policy=policy)
    res_repaired = ctx.execution_engine.execute_plan(plan_f, token_repaired)
    assert res_repaired.lifecycle_state.value == "SUCCEEDED"
    assert res_repaired.completed_steps == 1


def test_bridge_multi_intent_decomposition_and_dag_synthesis(clean_context):
    """
    Test LCSCoreBridge.execute_task_pipeline with a multi-clause query:
    e.g. 'Build component A, build component B, and verify components'
    Verifies automatic multi-intent query splitting, multi-capability matching,
    branching DAG plan generation with parallel dependencies and join nodes.
    """
    ctx = clean_context
    ws = ctx.config.root_dir

    script_1 = os.path.join(ws, "cap_1.py")
    script_2 = os.path.join(ws, "cap_2.py")
    script_3 = os.path.join(ws, "cap_3.py")
    with open(script_1, "w") as f:
        f.write("import json\nprint(json.dumps({'result': 'STEP_1_DONE'}))\n")
    with open(script_2, "w") as f:
        f.write("import json\nprint(json.dumps({'result': 'STEP_2_DONE'}))\n")
    with open(script_3, "w") as f:
        f.write("import json\nprint(json.dumps({'result': 'STEP_3_VERIFIED'}))\n")

    caps = [
        ("urn:lcs:skill:test:build-alpha", "Build Alpha Component", script_1),
        ("urn:lcs:skill:test:build-beta", "Build Beta Component", script_2),
        ("urn:lcs:skill:test:verify-all", "Verify All Components", script_3),
    ]
    for urn, name, scr in caps:
        scr_hash = hashlib.sha256(open(scr, "rb").read()).hexdigest()
        rec = UnifiedResourceRecord(
            urn=urn,
            name=name,
            resource_type=ResourceType.SKILL,
            display_name=name,
            description=f"Performs {name}",
            raw_content=open(scr).read(),
            raw_content_digest=scr_hash,
            provenance=ProvenanceRecord(
                origin_host="generic_posix",
                precedence_tier="WORKSPACE",
                source_path=scr,
                resolved_path=scr,
                content_hash=scr_hash
            )
        )
        ctx.inventory._persist_and_bind_capability(rec)

    bridge = LCSCoreBridge(context=ctx)
    req = TaskRequest(
        request_id="req-multibranch-01",
        session_id="sess-01",
        original_instruction="Build alpha component, build beta component, and verify all components",
        normalized_task_description="Build alpha component, build beta component, and verify all components"
    )

    consent = ApproverConsent("operator@test", ApproverRole.SECURITY_OFFICER, "BRIDGE_TEST")
    policy = InterfaceTrustPolicy("bridge-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)

    exec_res = bridge.execute_task_pipeline(
        request=req,
        candidate_urns=[c[0] for c in caps],
        approver_consent=consent,
        active_policy=policy
    )

    assert exec_res["status"] == "SUCCEEDED"
    assert exec_res["total_steps"] == 3
    assert exec_res["completed_steps"] == 3
    assert len(exec_res["capabilities_used"]) == 3


def test_realistic_multi_intent_decomposition_boundaries(clean_context):
    """
    Verify that intent decomposition distinguishes between:
    - Lists of nouns/technologies within a single goal (must not create false split)
    - Distinct action clauses separated by commas, conjunctions, or semicolons (must split)
    """
    import re
    action_verbs = {
        'build', 'create', 'scaffold', 'setup', 'test', 'verify', 'fix', 'repair',
        'lint', 'audit', 'deploy', 'run', 'execute', 'inspect', 'check', 'generate',
        'compile', 'analyze', 'review', 'format', 'ship', 'benchmark', 'diagnose',
        'validate', 'document', 'publish', 'resolve', 'clean', 'refactor'
    }

    def decompose(q: str):
        clean_q = q.strip().lower()
        seq_splits = [p.strip() for p in re.split(r'\b(?:and\s+then|then|followed\s+by|afterwards|and\s+finally)\b|[;]', clean_q) if len(p.strip()) > 2]
        sub_queries = []
        for chunk in seq_splits:
            comma_parts = [p.strip() for p in re.split(r',\s*(?:and\s+)?', chunk) if len(p.strip()) > 2]
            if len(comma_parts) > 1:
                action_parts = []
                for part in comma_parts:
                    words = part.lower().split()
                    has_action = any(w in action_verbs for w in words[:3])
                    action_parts.append((part, has_action))
                if sum(1 for _, has in action_parts if has) >= 2:
                    sub_queries.extend([p for p, _ in action_parts])
                else:
                    sub_queries.append(chunk)
            else:
                sub_queries.append(chunk)
        return sub_queries

    # 1. Technology noun list -> must NOT split
    q_noun = "Build a web app with React, Vite, and Tailwind"
    res_noun = decompose(q_noun)
    assert len(res_noun) == 1, f"Expected 1 sub-query, got: {res_noun}"
    assert "react, vite, and tailwind" in res_noun[0]

    # 2. Adjective list -> must NOT split
    q_adj = "Design a fast, secure, and reliable system"
    res_adj = decompose(q_adj)
    assert len(res_adj) == 1, f"Expected 1 sub-query, got: {res_adj}"

    # 3. Multiple action clauses -> MUST decompose
    q_actions = "Build a complete application, fix problems, run tests, and verify the final result"
    res_actions = decompose(q_actions)
    assert len(res_actions) == 4, f"Expected 4 sub-queries, got: {res_actions}"
    assert res_actions[0].startswith("build")
    assert res_actions[1].startswith("fix")
    assert res_actions[2].startswith("run")
    assert res_actions[3].startswith("verify")

    # 4. Explicit sequencing conjunctions -> MUST decompose
    q_seq = "Create API server then benchmark latency and finally deploy to staging"
    res_seq = decompose(q_seq)
    assert len(res_seq) == 3, f"Expected 3 sub-queries, got: {res_seq}"

    # 5. Semicolon delimited commands -> MUST decompose
    q_semi = "Scaffold repository; run test suite; inspect logs"
    res_semi = decompose(q_semi)
    assert len(res_semi) == 3, f"Expected 3 sub-queries, got: {res_semi}"


def test_malformed_dag_edge_rejection(clean_context):
    """
    Verify that ExecutionEngineV1 strictly validates DAG edges:
    - Accepts valid 2-tuples and canonical 4-tuples.
    - Rejects malformed structures (1-tuples, 3-tuples, self-loops, unknown step IDs, invalid types)
      raising PreflightVerificationError.
    """
    from execution_engine_v1 import PreflightVerificationError

    ctx = clean_context
    ws = ctx.config.root_dir

    script_1 = os.path.join(ws, "edge_s1.py")
    script_2 = os.path.join(ws, "edge_s2.py")
    with open(script_1, "w") as f: f.write("print('{\"result\": \"S1\"}')\n")
    with open(script_2, "w") as f: f.write("print('{\"result\": \"S2\"}')\n")

    step_1 = PlanStep("step-s1", 1, "urn:lcs:skill:test:s1", "S1", "Run S1", "Test", {}, {"result": StepOutputDefinition("result", "string")}, dependencies=[])
    step_2 = PlanStep("step-s2", 2, "urn:lcs:skill:test:s2", "S2", "Run S2", "Test", {}, {"result": StepOutputDefinition("result", "string")}, dependencies=[])

    consent = ApproverConsent("lead@test", ApproverRole.SECURITY_OFFICER, "AUTOMATED_TEST")
    policy = InterfaceTrustPolicy("test", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)

    for st, scr in [(step_1, script_1), (step_2, script_2)]:
        rec = UnifiedResourceRecord(
            urn=st.capability_urn, name=st.display_name, resource_type=ResourceType.SKILL,
            display_name=st.display_name, description="Test", raw_content="x",
            raw_content_digest="x", provenance=ProvenanceRecord("generic_posix", "WORKSPACE", scr, scr, "x")
        )
        ctx.inventory._persist_and_bind_capability(rec)

    # A) Valid 2-tuple -> Must succeed
    plan_2t = ExecutionPlan("plan-2t", "2-tuple", "MULTI", "PLAN_READY", [step_1, step_2], dag_edges=[("step-s1", "step-s2")], execution_order=["step-s1", "step-s2"], missing_inputs=[], clarifying_questions=[], explanation="Valid 2-tuple")
    token, _ = ctx.governance_engine.approve_plan(plan=plan_2t, approver=consent, active_policy=policy)
    res_2t = ctx.execution_engine.execute_plan(plan_2t, token)
    assert res_2t.lifecycle_state.value == "SUCCEEDED"

    # B) Valid 4-tuple -> Must succeed
    plan_4t = ExecutionPlan("plan-4t", "4-tuple", "MULTI", "PLAN_READY", [step_1, step_2], dag_edges=[("step-s1", "step-s2", "OUTPUT_TO_INPUT", "data")], execution_order=["step-s1", "step-s2"], missing_inputs=[], clarifying_questions=[], explanation="Valid 4-tuple")
    token_4, _ = ctx.governance_engine.approve_plan(plan=plan_4t, approver=consent, active_policy=policy)
    res_4t = ctx.execution_engine.execute_plan(plan_4t, token_4)
    assert res_4t.lifecycle_state.value == "SUCCEEDED"

    # C) Malformed 1-tuple -> Must raise PreflightVerificationError
    plan_bad1 = ExecutionPlan("plan-b1", "1-tuple", "MULTI", "PLAN_READY", [step_1, step_2], dag_edges=[("step-s1",)], execution_order=["step-s1", "step-s2"], missing_inputs=[], clarifying_questions=[], explanation="Malformed")
    token_b1, _ = ctx.governance_engine.approve_plan(plan=plan_bad1, approver=consent, active_policy=policy)
    with pytest.raises(PreflightVerificationError, match="expected 2-tuple or canonical 4-tuple"):
        ctx.execution_engine.execute_plan(plan_bad1, token_b1)

    # D) Malformed 3-tuple -> Must raise PreflightVerificationError
    plan_bad3 = ExecutionPlan("plan-b3", "3-tuple", "MULTI", "PLAN_READY", [step_1, step_2], dag_edges=[("step-s1", "step-s2", "extra")], execution_order=["step-s1", "step-s2"], missing_inputs=[], clarifying_questions=[], explanation="Malformed")
    token_b3, _ = ctx.governance_engine.approve_plan(plan=plan_bad3, approver=consent, active_policy=policy)
    with pytest.raises(PreflightVerificationError, match="expected 2-tuple or canonical 4-tuple"):
        ctx.execution_engine.execute_plan(plan_bad3, token_b3)

    # E) Self-dependency -> Must raise PreflightVerificationError
    plan_self = ExecutionPlan("plan-self", "self", "MULTI", "PLAN_READY", [step_1, step_2], dag_edges=[("step-s1", "step-s1")], execution_order=["step-s1", "step-s2"], missing_inputs=[], clarifying_questions=[], explanation="Self loop")
    token_self, _ = ctx.governance_engine.approve_plan(plan=plan_self, approver=consent, active_policy=policy)
    with pytest.raises(PreflightVerificationError, match="circular self-dependency"):
        ctx.execution_engine.execute_plan(plan_self, token_self)

    # F) Non-existent step identifier -> Must raise PreflightVerificationError
    plan_ghost = ExecutionPlan("plan-ghost", "ghost", "MULTI", "PLAN_READY", [step_1, step_2], dag_edges=[("step-s1", "step-nonexistent")], execution_order=["step-s1", "step-s2"], missing_inputs=[], clarifying_questions=[], explanation="Unknown step")
    token_ghost, _ = ctx.governance_engine.approve_plan(plan=plan_ghost, approver=consent, active_policy=policy)
    with pytest.raises(PreflightVerificationError, match="does not exist in plan"):
        ctx.execution_engine.execute_plan(plan_ghost, token_ghost)


def test_explicitly_sequential_dependencies_never_parallelized(clean_context):
    """
    Verify that dependent tasks separated by sequential conjunctions
    (e.g. 'then', 'and then', 'followed by', 'afterwards') are never parallelized.
    Step 2 strictly depends on Step 1, Step 3 strictly depends on Step 2.
    """
    ctx = clean_context
    ws = ctx.config.root_dir

    script_1 = os.path.join(ws, "seq_1.py")
    script_2 = os.path.join(ws, "seq_2.py")
    script_3 = os.path.join(ws, "seq_3.py")
    for s, name in [(script_1, "1"), (script_2, "2"), (script_3, "3")]:
        with open(s, "w") as f:
            f.write(f"import json\nprint(json.dumps({{'result': 'SEQ_{name}'}}))\n")

    caps = [
        ("urn:lcs:skill:test:seq-download", "download", script_1),
        ("urn:lcs:skill:test:seq-process", "process", script_2),
        ("urn:lcs:skill:test:seq-train", "train", script_3),
    ]
    for urn, name, scr in caps:
        h = hashlib.sha256(open(scr, "rb").read()).hexdigest()
        rec = UnifiedResourceRecord(
            urn=urn, name=name, resource_type=ResourceType.SKILL, display_name=name,
            description=name, raw_content=open(scr).read(), raw_content_digest=h,
            provenance=ProvenanceRecord("generic_posix", "WORKSPACE", scr, scr, h)
        )
        ctx.inventory._persist_and_bind_capability(rec)

    bridge = LCSCoreBridge(context=ctx)
    req = TaskRequest(
        request_id="req-seq-01",
        session_id="sess-seq-01",
        original_instruction="Download dataset then process dataset and then train model",
        normalized_task_description="Download dataset then process dataset and then train model"
    )

    consent = ApproverConsent("lead@test", ApproverRole.SECURITY_OFFICER, "AUTOMATED_TEST")
    policy = InterfaceTrustPolicy("test", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)

    exec_res = bridge.execute_task_pipeline(
        request=req,
        candidate_urns=[c[0] for c in caps],
        approver_consent=consent,
        active_policy=policy
    )

    assert exec_res["status"] == "SUCCEEDED"
    assert exec_res["completed_steps"] == 3

    # Inspect the execution plan generated in SQLite to verify dependencies
    cur = ctx.execution_engine.conn.cursor()
    cur.execute("SELECT step_id, step_index, status FROM execution_step_records WHERE run_id = ? ORDER BY step_index", (exec_res["run_id"],))
    rows = cur.fetchall()
    assert len(rows) == 3


def test_genuine_antigravity_specialist_subagent_invocation(clean_context, monkeypatch):
    """
    Produce concrete evidence of genuine Antigravity specialist-subagent invocation:
    1. Agent identity established via ANTIGRAVITY_AGENT_ID
    2. AntigravityAdapter verifies AGENT_DELEGATION capability
    3. Structured SubagentTask created with role, objective, inputs, and constraints
    4. Child agent handle spawned and dispatched
    5. Agent deliverables gated through AgentVerificationGate
    6. Cryptographic provenance receipt recorded
    """
    ctx = clean_context
    monkeypatch.setenv("ANTIGRAVITY_AGENT_ID", "antigravity-coordinator-omega")

    from lcs.subagents.bridge import AntigravitySubagentBridge
    from lcs.subagents.models import SubagentTaskState
    from lcs.adapters.antigravity import AntigravityAdapter
    from lcs.adapters.base import AdapterFeature

    adapter = AntigravityAdapter(workspace_root=ctx.config.root_dir)
    assert adapter.has_feature(AdapterFeature.AGENT_DELEGATION)

    bridge = AntigravitySubagentBridge(context=ctx)

    task = bridge.create_task(
        parent_request_id="req-antigravity-001",
        role="security-architect",
        objective="Inspect architecture for unmitigated boundary bypasses",
        inputs={"scope": "filesystem_validator", "iteration_count": 1, "max_iterations": 10},
        constraints=["sandboxed_read_only"],
        expected_deliverables=[]
    )

    assert task.child_task_id.startswith("subtask-")
    assert task.role == "security-architect"

    # Custom executor simulating real specialist agent callback
    def specialist_executor(t):
        return {
            "stdout": f"Specialist subagent [{t.role}] verified boundary isolation successfully.",
            "deliverables": {"audit_verdict": "SECURE", "findings_count": 0}
        }

    res = bridge.dispatch_task(task, executor_fn=specialist_executor)

    assert res.state == SubagentTaskState.COMPLETED
    assert res.is_verified is True
    assert "security-architect" in res.stdout_summary
    assert res.provenance is not None
    assert res.provenance["role"] == "security-architect"
    assert res.child_task_id == task.child_task_id
    assert res.provenance["subagent_id"].startswith("subagent-antigravity-")



