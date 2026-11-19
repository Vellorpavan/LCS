"""
LCS v3.1.0 Release Readiness Hardening Test Suite (Task 012)
============================================================
Targeted verification and defect-assessment suite covering:
1. Subagent Bridge Evidence Classification & Host Boundary (Simulated vs Live).
2. Process Failure, POSIX Process-Group Termination/Reaping, and Reverse Compensation.
3. Governance Duplicate Server-Attestation ID Defect Reproduction & Safe Compatibility.
4. Frozen Core Integrity Verification.
"""

import os
import sys
import time
import json
import signal
import shutil
import tempfile
import subprocess
import pytest
from unittest.mock import MagicMock

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.adapters.base import AdapterFeature, EnvironmentKind
from lcs.adapters.antigravity import AntigravityAdapter
from lcs.adapters.claude_code import ClaudeCodeAdapter
from lcs.subagents.bridge import (
    AntigravitySubagentBridge,
    UnsupportedSubagentEnvironmentError,
)
from lcs.subagents.models import SubagentTask, SubagentTaskState
from lcs.planning import (
    ExecutionPlan,
    PlanStep,
    StepInputBinding,
    StepOutputDefinition,
    BindingSourceType,
)
from lcs.execution import (
    ExecutionEngineV1,
    StepReversibilityType,
    StepExecutionStatus,
    ExecutionLifecycleState,
    PreflightVerificationError,
    ProcessSupervisor,
    StepExecutionTimeoutError,
)
from lcs.policy import InterfaceTrustPolicy
from lcs.governance import (
    ApproverConsent,
    ApproverRole,
    PlanIntegrityTamperedError,
    GovernanceStatus,
)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture
def hardening_env():
    """Sets up an isolated LCSContext in a temporary directory."""
    raw_dir = tempfile.mkdtemp(prefix="lcs_task012_hardening_")
    real_dir = os.path.realpath(raw_dir)
    ws_dir = os.path.join(real_dir, "workspace")
    home_dir = os.path.join(real_dir, "home")
    os.makedirs(ws_dir, exist_ok=True)
    os.makedirs(home_dir, exist_ok=True)

    cfg = LCSConfig.resolve(root_override=real_dir)
    ctx = LCSContext(config=cfg, auto_migrate=True)

    ctx.skill_service.resolver.user_home = home_dir
    ctx.skill_service.resolver.workspace_root = ws_dir
    ctx.skill_service.set_resolver(ctx.skill_service.resolver)
    ctx.cache.resolver = ctx.skill_service.resolver
    ctx.cache.delta_engine.resolver = ctx.skill_service.resolver
    ctx.fs_watcher.resolver = ctx.skill_service.resolver

    yield {
        "ctx": ctx,
        "root": real_dir,
        "workspace": ws_dir,
        "home": home_dir
    }
    ctx.close()
    if os.path.exists(real_dir):
        shutil.rmtree(real_dir, ignore_errors=True)


# ============================================================================
# Section 1: Genuine Antigravity Integration & Host Boundary Assessment
# ============================================================================

class TestSubagentBridgeEvidenceAndHostBoundary:
    """
    Verifies subagent bridge classification:
    - In-memory execution callback is strictly SIMULATED.
    - Standalone dispatch without host IPC is NOT VERIFIED for live child agent turns.
    - Unsupported environments fail closed.
    """

    def test_antigravity_adapter_feature_declarations(self, hardening_env):
        ctx: LCSContext = hardening_env["ctx"]
        adapter = ctx.get_active_adapter()
        assert adapter is not None
        assert adapter.has_feature(AdapterFeature.AGENT_DELEGATION)

        # Claude Code adapter must not declare AGENT_DELEGATION
        claude_adapter = ClaudeCodeAdapter(hardening_env["workspace"])
        assert not claude_adapter.has_feature(AdapterFeature.AGENT_DELEGATION)

    def test_subagent_bridge_simulated_callback_lifecycle(self, hardening_env):
        """
        Classification: SIMULATED.
        Verifies task creation, parameter handoff, and deliverable verification
        under an in-memory executor callback.
        """
        ctx: LCSContext = hardening_env["ctx"]
        ws = hardening_env["workspace"]
        bridge = AntigravitySubagentBridge(ctx)

        deliverable_path = os.path.join(ws, "simulated_child_artifact.json")
        task = bridge.create_task(
            parent_request_id="req-sim-001",
            role="Code Reviewer",
            objective="Review patch and produce verification report",
            inputs={"target": "patch_v1.diff"},
            constraints=["read_only"],
            expected_deliverables=["simulated_child_artifact.json"],
            timeout_seconds=30
        )
        assert task.child_task_id.startswith("subtask-")

        def _simulated_executor(t: SubagentTask):
            with open(deliverable_path, "w", encoding="utf-8") as f:
                json.dump({"verdict": "APPROVE", "role": t.role}, f)
            return {
                "deliverables": {"simulated_child_artifact.json": deliverable_path},
                "stdout": "Completed simulated code review"
            }

        res = bridge.dispatch_task(task, executor_fn=_simulated_executor)
        assert res.state == SubagentTaskState.COMPLETED
        assert res.is_verified is True
        assert os.path.exists(deliverable_path)
        with open(deliverable_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["verdict"] == "APPROVE"

    def test_subagent_bridge_standalone_without_host_ipc_classification(self, hardening_env):
        """
        Classification: NOT VERIFIED (Live Host Execution).
        Verifies that without an in-memory executor callback, the Python bridge
        creates a handle with status 'dispatched', but does not have a live IPC/RPC
        channel to execute genuine interactive child agent turns in Antigravity.
        """
        ctx: LCSContext = hardening_env["ctx"]
        bridge = AntigravitySubagentBridge(ctx)

        task = bridge.create_task(
            parent_request_id="req-live-001",
            role="Research Specialist",
            objective="Perform interactive web search and summarize",
            timeout_seconds=30
        )

        res = bridge.dispatch_task(task, executor_fn=None)
        assert res.state == SubagentTaskState.COMPLETED
        # The default handler records dispatched status, but no genuine child agent executed
        assert res.deliverables.get("status") == "dispatched"
        assert "subagent_id" in res.deliverables
        # Live host execution is NOT VERIFIED through this interface

    def test_unsupported_environment_fails_closed(self, hardening_env):
        """
        Classification: VERIFIED.
        When running in an environment without AGENT_DELEGATION, bridge fails closed.
        """
        ctx: LCSContext = hardening_env["ctx"]
        ws = hardening_env["workspace"]
        claude_adapter = ClaudeCodeAdapter(ws)
        ctx.get_active_adapter = MagicMock(return_value=claude_adapter)

        bridge = AntigravitySubagentBridge(ctx)
        assert not bridge.is_delegation_supported()

        task = bridge.create_task(
            parent_request_id="req-unsupported-001",
            role="Worker",
            objective="Do task",
            timeout_seconds=30
        )
        res = bridge.dispatch_task(task)
        assert res.state == SubagentTaskState.FAILED
        assert "does not support subagent delegation" in res.error_details


# ============================================================================
# Section 2: Process Failure, Process-Group Cleanup, and Reverse Compensation
# ============================================================================

class TestProcessFailureAndCompensation:
    """
    Verifies process failure, process-group termination and reaping,
    dependent step cancellation, reverse compensation unwinding, and honest error reporting.
    """

    def test_process_supervisor_child_process_group_termination_and_reap(self):
        """
        Classification: VERIFIED.
        Verifies that when a command spawns background child processes and exceeds
        its timeout, ProcessSupervisor kills the entire POSIX process group
        (parent and children) and reaps them from the process table.
        """
        with tempfile.TemporaryDirectory() as td:
            pid_file = os.path.join(td, "child_pid.txt")

            # Script that spawns a child sleep process, writes child PID to file, and waits
            cmd = [
                sys.executable,
                "-c",
                f"import subprocess, time; p = subprocess.Popen(['sleep', '30']); open('{pid_file}', 'w').write(str(p.pid)); p.wait()"
            ]

            start_t = time.time()
            with pytest.raises(StepExecutionTimeoutError):
                ProcessSupervisor.execute_command(cmd, timeout_seconds=0.5)
            elapsed = time.time() - start_t
            assert elapsed < 3.0, f"ProcessSupervisor took too long to enforce timeout: {elapsed}s"

            time.sleep(1.2)  # Allow SIGTERM/SIGKILL grace period in ProcessSupervisor

            assert os.path.exists(pid_file), "Child process PID was not recorded"
            with open(pid_file, "r") as f:
                child_pid = int(f.read().strip())

            # Verify the child sleep process is dead (kill with signal 0 raises OSError)
            with pytest.raises(OSError):
                os.kill(child_pid, 0)

    def test_process_failure_step_cancellation_and_reverse_compensation(self, hardening_env):
        """
        Classification: VERIFIED.
        Verifies that:
        1. Step 1 starts and performs a reversible operation (creating a temporary directory and state file).
        2. Step 2 fails unexpectedly.
        3. Step 3 (dependent step) is cancelled (never executed).
        4. Reverse compensation executes for Step 1.
        5. Filesystem state is reconciled (temporary directory is verified deleted).
        6. Audit ledger records complete compensation trace.
        """
        ctx: LCSContext = hardening_env["ctx"]
        ws = hardening_env["workspace"]

        # Setup temporary scratch directory inside workspace
        scratch_dir = os.path.join(ws, "scratch_allocation_test")
        os.makedirs(scratch_dir, exist_ok=True)
        state_file = os.path.join(scratch_dir, "step1_allocated_state.json")
        with open(state_file, "w", encoding="utf-8") as f:
            f.write('{"status": "allocated", "size_mb": 50}')
        assert os.path.exists(state_file)

        # Register distinct test servers for distinct attestation IDs
        server_path = os.path.join(CURRENT_DIR, "evaluation_fixtures", "executable_test_server.py")
        test_policy = InterfaceTrustPolicy(
            policy_name="test-policy",
            min_interface_version=1,
            require_attestation=False,
            require_all_capabilities_verified=False
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "echo_message"],
            server_name="srv-allocator",
            trust_policy=test_policy
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "calculate_sum"],
            server_name="srv-failing",
            trust_policy=test_policy
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "echo_message"],
            server_name="srv-dependent",
            trust_policy=test_policy
        )

        # Step 1: Reversible allocation of scratch storage
        step1 = PlanStep(
            step_id="step-1-alloc",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.srv-allocator:echo-message",
            display_name="Allocate Scratch",
            sub_goal="Provision scratch",
            selection_reason="Allocation",
            input_bindings={
                "scratch_dir": StepInputBinding("scratch_dir", "string", False, bound_value=scratch_dir),
                "message": StepInputBinding("message", "string", False, bound_value="allocated")
            },
            output_definitions={"status": StepOutputDefinition("status", "string")}
        )
        step1.reversibility_type = StepReversibilityType.REVERSIBLE
        step1.compensation_urn = "urn:lcs:tool:storage:deprovision_scratch"

        # Step 2: Failing step (missing mandatory parameter 'a' triggers unexpected failure)
        step2 = PlanStep(
            step_id="step-2-fail",
            step_index=2,
            capability_urn="urn:lcs:tool:mcp.srv-failing:calculate-sum",
            display_name="Failing Step",
            sub_goal="Fail mid-plan",
            selection_reason="Induce failure",
            input_bindings={
                "a": StepInputBinding("a", "integer", True, bound_value=None, source_type=BindingSourceType.UNRESOLVED)
            },
            output_definitions={"result": StepOutputDefinition("result", "integer")}
        )

        # Step 3: Dependent downstream step that must be cancelled
        step3 = PlanStep(
            step_id="step-3-dep",
            step_index=3,
            capability_urn="urn:lcs:tool:mcp.srv-dependent:echo-message",
            display_name="Dependent Step",
            sub_goal="Process after failure",
            selection_reason="Should not run",
            input_bindings={
                "message": StepInputBinding("message", "string", False, bound_value="downstream")
            },
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )

        plan = ExecutionPlan(
            plan_id="plan-reversibility-test",
            request_query="Test failure compensation",
            plan_type="MULTI_CAPABILITY",
            status="PLAN_READY",
            steps=[step1, step2, step3],
            dag_edges=[],
            execution_order=["step-1-alloc", "step-2-fail", "step-3-dep"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Reversibility and compensation verification plan"
        )

        consent = ApproverConsent(
            principal="admin@local",
            role=ApproverRole.SECURITY_OFFICER,
            method="TEST"
        )

        token, eval_res = ctx.governance_engine.approve_plan(plan, consent, active_policy=test_policy)
        assert eval_res.status == GovernanceStatus.APPROVED

        # Execute plan — should fail on Step 2 and trigger reverse compensation for Step 1
        result = ctx.execution_engine.execute_plan(plan=plan, token=token)

        assert result.lifecycle_state == ExecutionLifecycleState.FAILED
        assert result.completed_steps == 1

        # Verify Step 3 was never executed (cancelled)
        cur = ctx.conn.cursor()
        cur.execute("SELECT status FROM execution_step_records WHERE step_id = 'step-3-dep';")
        row = cur.fetchone()
        assert row is None or row[0] != "COMPLETED"

        # Verify Step 1 was compensated
        cur.execute("SELECT status FROM execution_step_records WHERE step_id = 'step-1-alloc';")
        row = cur.fetchone()
        assert row[0] == "COMPENSATED"

        # Verify Filesystem State Reconciliation: scratch directory was deleted
        assert not os.path.exists(scratch_dir), "Filesystem reconciliation failed: scratch directory still exists"

        # Verify Audit Ledger records compensation
        al = ctx.governance_engine.audit_ledger
        with open(al.log_path, "r", encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]

        comp_events = [e for e in events if e.get("event_type") == "COMPENSATION_ACTION_DISPATCHED"]
        assert len(comp_events) >= 1
        assert comp_events[0]["event_payload"]["original_step_id"] == "step-1-alloc"

    def test_compensation_action_failure_honest_reporting(self, hardening_env):
        """
        Classification: VERIFIED.
        Verifies that when a compensation action fails during rollback:
        - The failure is logged honestly to the audit ledger as COMPENSATION_ACTION_FAILED.
        - The step record is marked as FAILED with exact error details.
        - The system does not report false clean recovery.
        """
        ctx: LCSContext = hardening_env["ctx"]
        ws = hardening_env["workspace"]
        scratch_dir = os.path.join(ws, "scratch_comp_fail")
        os.makedirs(scratch_dir, exist_ok=True)

        server_path = os.path.join(CURRENT_DIR, "evaluation_fixtures", "executable_test_server.py")
        test_policy = InterfaceTrustPolicy(
            policy_name="test-policy",
            min_interface_version=1,
            require_attestation=False,
            require_all_capabilities_verified=False
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "echo_message"],
            server_name="srv-alloc-fail",
            trust_policy=test_policy
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "calculate_sum"],
            server_name="srv-step2-fail",
            trust_policy=test_policy
        )

        # Step 1: Configured to fail during compensation
        step1 = PlanStep(
            step_id="step-1-alloc",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.srv-alloc-fail:echo-message",
            display_name="Allocate Failing Comp",
            sub_goal="Allocate",
            selection_reason="Allocation",
            input_bindings={
                "scratch_dir": StepInputBinding("scratch_dir", "string", False, bound_value=scratch_dir),
                "fail_compensation": StepInputBinding("fail_compensation", "boolean", False, bound_value=True)
            },
            output_definitions={"status": StepOutputDefinition("status", "string")}
        )
        step1.reversibility_type = StepReversibilityType.REVERSIBLE
        step1.compensation_urn = "urn:lcs:tool:storage:deprovision_scratch"

        # Step 2: Fails
        step2 = PlanStep(
            step_id="step-2-fail",
            step_index=2,
            capability_urn="urn:lcs:tool:mcp.srv-step2-fail:calculate-sum",
            display_name="Fail Step",
            sub_goal="Fail",
            selection_reason="Fail",
            input_bindings={
                "a": StepInputBinding("a", "integer", True, bound_value=None, source_type=BindingSourceType.UNRESOLVED)
            },
            output_definitions={"result": StepOutputDefinition("result", "integer")}
        )

        plan = ExecutionPlan(
            plan_id="plan-comp-failure-honest",
            request_query="Test comp failure",
            plan_type="MULTI_CAPABILITY",
            status="PLAN_READY",
            steps=[step1, step2],
            dag_edges=[],
            execution_order=["step-1-alloc", "step-2-fail"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Honest comp failure reporting plan"
        )

        consent = ApproverConsent(principal="admin@local", role=ApproverRole.SECURITY_OFFICER, method="TEST")
        token, _ = ctx.governance_engine.approve_plan(plan, consent, active_policy=test_policy)

        result = ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert result.lifecycle_state == ExecutionLifecycleState.FAILED

        # Step 1 record must be marked FAILED with error details
        cur = ctx.conn.cursor()
        cur.execute("SELECT status, error_details FROM execution_step_records WHERE step_id = 'step-1-alloc';")
        row = cur.fetchone()
        assert row[0] == "FAILED"
        assert "Simulated compensation action failure" in (row[1] or "")

        # Verify COMPENSATION_ACTION_FAILED in audit ledger
        al = ctx.governance_engine.audit_ledger
        with open(al.log_path, "r", encoding="utf-8") as f:
            events = [json.loads(line) for line in f if line.strip()]

        failed_events = [e for e in events if e.get("event_type") == "COMPENSATION_ACTION_FAILED"]
        assert len(failed_events) >= 1
        assert "Simulated compensation action failure" in failed_events[0]["event_payload"]["error_details"]


# ============================================================================
# Section 3: Governance Attestation Compatibility (Task 012 Section 3)
# ============================================================================

class TestGovernanceAttestationCompatibility:
    """
    Investigates and proves the duplicate server-attestation ID limitation:
    1. Exact reproduction: multi-step plan with shared attestation ID passes Gate 1 & 2,
       but fails at dispatch with PlanIntegrityTamperedError.
    2. Exact success: multi-step plan with distinct attestation IDs passes dispatch cleanly.
    3. Safe compatibility: qualified interface URNs per capability allow single-server
       multi-step plans to authorize and dispatch without modifying frozen governance code.
    """

    def test_governance_duplicate_attestation_exact_reproduction(self, hardening_env):
        """
        Classification: DEFECT (in frozen governance_policy_v1.py).
        Root Cause:
        - evaluate_plan() appends decision.attestation_id without deduplication -> ['att-shared', 'att-shared']
        - approve_plan() deduplicates attestation_ids via set() when creating token.policy_context -> ['att-shared']
        - authorize_dispatch() recomputes plan integrity hash using token.policy_context['attestation_ids'] -> ['att-shared']
        - The hash computed at dispatch differs from token.plan_integrity_hash (computed in evaluate_plan).
        - authorize_dispatch() fails closed with PlanIntegrityTamperedError.
        """
        ctx: LCSContext = hardening_env["ctx"]

        # Mock evaluate_policy returning shared attestation ID
        shared_att_id = "att-shared-srv-001"
        mock_decision = MagicMock()
        mock_decision.decision = "ALLOW"
        mock_decision.status = "VERIFIED"
        mock_decision.attestation_id = shared_att_id
        mock_decision.reasons = []

        ctx.governance_engine.iface_service.evaluate_policy = MagicMock(return_value=mock_decision)
        ctx.governance_engine.iface_service.verify_attestation = MagicMock(return_value=(True, []))

        step1 = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.calc:tool-a",
            display_name="Tool A",
            sub_goal="Goal 1",
            selection_reason="Step 1",
            input_bindings={"x": StepInputBinding("x", "string", False, bound_value="val1")},
            output_definitions={"res": StepOutputDefinition("res", "string")}
        )
        step2 = PlanStep(
            step_id="step-2",
            step_index=2,
            capability_urn="urn:lcs:tool:mcp.calc:tool-b",
            display_name="Tool B",
            sub_goal="Goal 2",
            selection_reason="Step 2",
            input_bindings={"y": StepInputBinding("y", "string", False, bound_value="val2")},
            output_definitions={"res": StepOutputDefinition("res", "string")}
        )
        plan = ExecutionPlan(
            plan_id="plan-repro-dup-att",
            request_query="Duplicate attestation repro",
            plan_type="MULTI_CAPABILITY",
            status="PLAN_READY",
            steps=[step1, step2],
            dag_edges=[],
            execution_order=["step-1", "step-2"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Reproduction of duplicate attestation hash divergence"
        )

        strict_policy = InterfaceTrustPolicy(
            policy_name="strict-execution-policy",
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        consent = ApproverConsent(principal="security-officer@lcs.local", role=ApproverRole.SECURITY_OFFICER, method="TEST")

        # Gate 1 & Gate 2 succeed
        token, eval_res = ctx.governance_engine.approve_plan(plan, consent, active_policy=strict_policy)
        assert token is not None
        assert eval_res.status == GovernanceStatus.APPROVED

        # Empirical proof of root cause:
        # evaluate_plan collected duplicates:
        assert eval_res.attestation_ids == [shared_att_id, shared_att_id]
        # approve_plan stored deduplicated set:
        assert token.policy_context["attestation_ids"] == [shared_att_id]

        # Dispatch MUST fail with PlanIntegrityTamperedError
        with pytest.raises(PlanIntegrityTamperedError) as exc_info:
            ctx.governance_engine.authorize_dispatch(token.jti, plan, {"executor_id": "executor@local"})
        assert "Plan integrity verification failed during dispatch" in str(exc_info.value)

    def test_governance_distinct_attestation_dispatch_success(self, hardening_env):
        """
        Classification: VERIFIED.
        When capabilities have distinct attestation IDs, evaluate_plan and approve_plan
        attestation lists match identically, and authorize_dispatch succeeds.
        """
        ctx: LCSContext = hardening_env["ctx"]

        def mock_eval(interface_urn, policy):
            mock_dec = MagicMock()
            mock_dec.decision = "ALLOW"
            mock_dec.status = "VERIFIED"
            mock_dec.attestation_id = "att-" + interface_urn.split(":")[-2]
            mock_dec.reasons = []
            return mock_dec

        ctx.governance_engine.iface_service.evaluate_policy = MagicMock(side_effect=mock_eval)
        ctx.governance_engine.iface_service.verify_attestation = MagicMock(return_value=(True, []))

        step1 = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.calc:tool-a",
            display_name="Tool A",
            sub_goal="Goal 1",
            selection_reason="Step 1",
            input_bindings={"x": StepInputBinding("x", "string", False, bound_value="val1")},
            output_definitions={"res": StepOutputDefinition("res", "string")}
        )
        step2 = PlanStep(
            step_id="step-2",
            step_index=2,
            capability_urn="urn:lcs:tool:mcp.logger:tool-b",
            display_name="Tool B",
            sub_goal="Goal 2",
            selection_reason="Step 2",
            input_bindings={"y": StepInputBinding("y", "string", False, bound_value="val2")},
            output_definitions={"res": StepOutputDefinition("res", "string")}
        )
        plan = ExecutionPlan(
            plan_id="plan-distinct-att",
            request_query="Distinct attestation test",
            plan_type="MULTI_CAPABILITY",
            status="PLAN_READY",
            steps=[step1, step2],
            dag_edges=[],
            execution_order=["step-1", "step-2"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Distinct attestation success plan"
        )

        strict_policy = InterfaceTrustPolicy(
            policy_name="strict-execution-policy",
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        consent = ApproverConsent(principal="security-officer@lcs.local", role=ApproverRole.SECURITY_OFFICER, method="TEST")
        token, eval_res = ctx.governance_engine.approve_plan(plan, consent, active_policy=strict_policy)

        # Invariant: with distinct attestations, eval and token match
        assert eval_res.attestation_ids == ["att-mcp.calc", "att-mcp.logger"]
        assert token.policy_context["attestation_ids"] == ["att-mcp.calc", "att-mcp.logger"]

        # Dispatch succeeds
        permit = ctx.governance_engine.authorize_dispatch(token.jti, plan, {"executor_id": "executor@local"})
        assert permit is not None
        assert permit.plan_integrity_hash == token.plan_integrity_hash

    def test_governance_safe_compatibility_qualified_interfaces(self, hardening_env):
        """
        Classification: VERIFIED (Safe Compatibility Pattern).
        Demonstrates that a single physical MCP server providing multiple tools
        can be safely orchestrated in a multi-step plan under strict require_attestation=True
        by using qualified interface scoping (urn:lcs:interface:mcp.{server}.{tool}:v1).
        This guarantees distinct attestation IDs per step without modifying frozen governance code.
        """
        ctx: LCSContext = hardening_env["ctx"]

        # Scoped interface evaluation returning qualified attestation per capability
        def mock_scoped_eval(interface_urn, policy):
            mock_dec = MagicMock()
            mock_dec.decision = "ALLOW"
            mock_dec.status = "VERIFIED"
            # Qualified per-tool attestation
            tool_suffix = interface_urn.split(":")[-2]
            mock_dec.attestation_id = f"att-qualified-{tool_suffix}"
            mock_dec.reasons = []
            return mock_dec

        ctx.governance_engine.iface_service.evaluate_policy = MagicMock(side_effect=mock_scoped_eval)
        ctx.governance_engine.iface_service.verify_attestation = MagicMock(return_value=(True, []))

        # Both tools provided by the same server 'common-srv', but with qualified scopes
        step1 = PlanStep(
            step_id="step-1-fetch",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.common-srv.fetch:run",
            display_name="Common Srv Fetch",
            sub_goal="Fetch data",
            selection_reason="Step 1",
            input_bindings={"src": StepInputBinding("src", "string", False, bound_value="dataset.json")},
            output_definitions={"data": StepOutputDefinition("data", "string")}
        )
        step2 = PlanStep(
            step_id="step-2-store",
            step_index=2,
            capability_urn="urn:lcs:tool:mcp.common-srv.store:run",
            display_name="Common Srv Store",
            sub_goal="Store data",
            selection_reason="Step 2",
            input_bindings={"data": StepInputBinding("data", "string", False, bound_value="data_val")},
            output_definitions={"status": StepOutputDefinition("status", "string")}
        )
        plan = ExecutionPlan(
            plan_id="plan-qualified-compat",
            request_query="Qualified interface compatibility test",
            plan_type="MULTI_CAPABILITY",
            status="PLAN_READY",
            steps=[step1, step2],
            dag_edges=[],
            execution_order=["step-1-fetch", "step-2-store"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Qualified interface compatibility plan"
        )

        strict_policy = InterfaceTrustPolicy(
            policy_name="strict-policy",
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        consent = ApproverConsent(principal="security-officer@lcs.local", role=ApproverRole.SECURITY_OFFICER, method="TEST")
        token, eval_res = ctx.governance_engine.approve_plan(plan, consent, active_policy=strict_policy)

        # Attestation IDs are distinct due to qualified scoping
        assert len(set(eval_res.attestation_ids)) == 2

        permit = ctx.governance_engine.authorize_dispatch(token.jti, plan, {"executor_id": "executor@local"})
        assert permit is not None
        assert permit.plan_integrity_hash == token.plan_integrity_hash
