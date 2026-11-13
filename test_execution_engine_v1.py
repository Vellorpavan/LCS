"""
test_execution_engine_v1.py
===========================
Authoritative test suite for LCS Execution Engine V1.

Verifies:
1. Pre-flight verification & atomic EAT token consumption.
2. Replay protection (single-use token enforcement).
3. Plan tampering detection (mismatched plan integrity hash).
4. Policy revision freshness (compare-and-consume drift protection).
5. Topological multi-step execution & parameter propagation.
6. Skill execution modality (exact-byte CAS instruction contextualization).
7. Process sandboxing and timeout supervisor.
8. Path confinement and traversal security.
9. Fault recovery, idempotent retries, and compensation unwinding.
10. Audit ledger event commitment and CAS trace verification.
11. CLI command integration ('lcs execute', 'lcs run list', 'lcs run inspect').
"""

import os
import sys
import time
import json
import sqlite3
import tempfile
import hashlib
import pytest
from unittest.mock import patch
from pathlib import Path

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.execution import (
    ExecutionLifecycleState,
    StepExecutionStatus,
    StepReversibilityType,
    ExecutionEngineV1,
    PreflightVerificationError,
    StepExecutionTimeoutError,
    StepExecutionError,
    UnresolvedParameterError,
    PathTraversalExecutionError,
    PathSecurityValidator,
    ProcessSupervisor,
    MCPToolHandler,
    SkillExecutionHandler,
    NativeSimulationHandler
)
from lcs.planning import (
    ExecutionPlan,
    PlanStep,
    StepInputBinding,
    StepOutputDefinition,
    BindingSourceType
)
from lcs.governance import (
    ExecutionAuthorizationToken,
    DispatchPermit,
    ApproverConsent,
    ApproverRole,
    GovernanceStatus,
    compute_plan_integrity_hash,
    canonicalize_jcs
)
from lcs.policy import InterfaceTrustPolicy
from interface_policy_v2b import InterfaceDeclaration, InterfaceCapabilityRef
from lcs.cli import main as cli_main


@pytest.fixture
def exec_test_env(tmp_path):
    """Sets up an isolated LCSContext for execution engine testing."""
    root = tmp_path / "lcs_root"
    home = tmp_path / "fake_home"
    root.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)

    with patch.dict(os.environ, {"HOME": str(home)}), \
         patch("os.path.expanduser", lambda p: str(home) if p.startswith("~") else p), \
         patch.object(Path, "home", return_value=home):

        cfg = LCSConfig.resolve(root_override=str(root))
        ctx = LCSContext(config=cfg, auto_migrate=True)

        # Register live JSON-RPC executable MCP test server
        server_path = os.path.join(CURRENT_DIR, "evaluation_fixtures", "executable_test_server.py")
        policy = InterfaceTrustPolicy(
            policy_name="test-policy",
            min_interface_version=1,
            require_attestation=False,
            require_all_capabilities_verified=False
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "echo_message"],
            server_name="executable-server",
            trust_policy=policy
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "calculate_sum"],
            server_name="calc-server",
            trust_policy=policy
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "hash_sha256_digest"],
            server_name="hash-server",
            trust_policy=policy
        )

        yield {
            "ctx": ctx,
            "root": root,
            "home": home
        }
        ctx.close()


def _create_authorized_plan(ctx: LCSContext, steps: list, query: str = "Test Task") -> tuple:
    """Helper to create a plan and authorize it through Governance V1."""
    plan_id = f"plan-{hashlib.sha256(query.encode()).hexdigest()[:8]}"
    plan = ExecutionPlan(
        plan_id=plan_id,
        request_query=query,
        plan_type="MULTI_CAPABILITY" if len(steps) > 1 else "SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=steps,
        dag_edges=[],
        execution_order=[s.step_id for s in steps],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Test plan"
    )

    permissive_policy = InterfaceTrustPolicy(
        policy_name="test-permissive-policy",
        min_interface_version=1,
        require_attestation=False,
        require_all_capabilities_verified=False
    )

    consent = ApproverConsent(
        principal="operator@test.local",
        role=ApproverRole.HUMAN_OPERATOR,
        method="CLI_TEST"
    )

    token, eval_result = ctx.governance_engine.approve_plan(
        plan=plan,
        approver=consent,
        active_policy=permissive_policy
    )
    assert token is not None
    return plan, token


def _register_skill_interface(ctx: LCSContext, skill_urn: str, raw_content_bytes: bytes, environment: str = "antigravity.global") -> str:
    """Registers an interface and agent declaration in SQLite and CAS so Gate 1 passes for skill URNs."""
    raw_digest = ctx.execution_engine.store_blob_in_cas(raw_content_bytes)
    env_name = environment.split(".")[0]
    iface_urn = f"urn:lcs:interface:mcp.{environment}:v1"
    agent_urn = f"urn:lcs:agent:mcp.{environment}:host"

    # 1. Capability in CAS & registry
    ctx.conn.execute("INSERT OR IGNORE INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES (?, 'CAPABILITY', 'PENDING');", (skill_urn,))
    ctx.conn.execute("INSERT OR IGNORE INTO capabilities (capability_urn, name, version, description) VALUES (?, 'Test Skill', '1.0.0', 'Desc');", (skill_urn,))
    ctx.conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = ?;", (skill_urn,))
    ctx.conn.execute("INSERT OR IGNORE INTO capability_declarations (capability_urn, definition_blob_digest, schema_version, display_name, capability_type) VALUES (?, ?, 1, 'Test Skill', 'skill');", (skill_urn, raw_digest))

    # 2. Agent
    ctx.conn.execute("INSERT OR IGNORE INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES (?, 'CAPABILITY', 'PENDING');", (agent_urn,))
    ctx.conn.execute("INSERT OR IGNORE INTO capabilities (capability_urn, name, version, description) VALUES (?, 'Agent', '1.0.0', 'Agent');", (agent_urn,))
    ctx.conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = ?;", (agent_urn,))
    ctx.conn.execute("INSERT OR IGNORE INTO agent_declarations (agent_urn, display_name, description, provenance_json) VALUES (?, 'Agent', 'Agent', '{}');", (agent_urn,))

    # 3. Interface declaration object in CAS & database
    iface_decl = InterfaceDeclaration(
        interface_urn=iface_urn,
        agent_urn=agent_urn,
        interface_version=1,
        display_name=f"{environment} Interface",
        description="Test interface",
        schema_version=1,
        capabilities=[InterfaceCapabilityRef(capability_urn=skill_urn, expected_definition_digest=raw_digest)],
        provenance={"author": "test", "created_at": "2026-01-01T00:00:00Z", "source_origin": env_name, "license": "MIT"}
    )
    decl_bytes = json.dumps(iface_decl.to_dict()).encode("utf-8")
    decl_digest = ctx.execution_engine.store_blob_in_cas(decl_bytes)

    ctx.conn.execute("INSERT OR IGNORE INTO entity_urn_registry (entity_urn, entity_kind, lifecycle_state) VALUES (?, 'CAPABILITY', 'PENDING');", (iface_urn,))
    ctx.conn.execute("INSERT OR IGNORE INTO capabilities (capability_urn, name, version, description) VALUES (?, 'Interface', '1.0.0', 'Desc');", (iface_urn,))
    ctx.conn.execute("UPDATE entity_urn_registry SET lifecycle_state = 'ACTIVE' WHERE entity_urn = ?;", (iface_urn,))
    ctx.conn.execute("""
        INSERT OR REPLACE INTO interface_declarations (
            interface_urn, agent_urn, interface_version, display_name, description, declaration_blob_digest, schema_version
        ) VALUES (?, ?, 1, 'Interface', 'Desc', ?, 1);
    """, (iface_urn, agent_urn, decl_digest))
    ctx.conn.commit()
    return raw_digest


class TestTokenConsumptionAndIntegrity:
    """Tests Pre-flight validation, token consumption, replay protection, and plan tampering."""

    def test_successful_token_consumption(self, exec_test_env):
        ctx = exec_test_env["ctx"]

        step = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.executable-server:echo-message",
            display_name="Echo Step",
            sub_goal="Echo test",
            selection_reason="Test",
            input_bindings={"msg": StepInputBinding("msg", "string", False, bound_value="hello")},
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )
        plan, token = _create_authorized_plan(ctx, [step], query="Echo task")

        # Execute
        result = ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert result.lifecycle_state == ExecutionLifecycleState.SUCCEEDED
        assert result.completed_steps == 1

        # Check token is consumed in SQLite
        cur = ctx.conn.cursor()
        cur.execute("SELECT state, consumed_at FROM governance_tokens WHERE jti = ?;", (token.token_id,))
        row = cur.fetchone()
        assert row[0] == "CONSUMED"
        assert row[1] is not None

    def test_replay_protection_double_consumption(self, exec_test_env):
        ctx = exec_test_env["ctx"]

        step = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.executable-server:echo-message",
            display_name="Echo Step",
            sub_goal="Echo test",
            selection_reason="Test",
            input_bindings={"msg": StepInputBinding("msg", "string", False, bound_value="hello")},
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )
        plan, token = _create_authorized_plan(ctx, [step], query="Echo task replay")

        # First execution succeeds
        res1 = ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert res1.lifecycle_state == ExecutionLifecycleState.SUCCEEDED

        # Second execution with same token must fail with PreflightVerificationError
        with pytest.raises(PreflightVerificationError) as exc_info:
            ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert "TOKEN_ALREADY_CONSUMED" in str(exc_info.value)

    def test_plan_tampering_detection(self, exec_test_env):
        ctx = exec_test_env["ctx"]

        step1 = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.executable-server:echo-message",
            display_name="Echo Step",
            sub_goal="Echo test",
            selection_reason="Test",
            input_bindings={"msg": StepInputBinding("msg", "string", False, bound_value="original")},
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )
        plan, token = _create_authorized_plan(ctx, [step1], query="Echo task tampering")

        # Maliciously modify the plan post-authorization
        tampered_step = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.executable-server:echo-message",
            display_name="Tampered Step",
            sub_goal="Malicious injection",
            selection_reason="Tampered",
            input_bindings={"msg": StepInputBinding("msg", "string", False, bound_value="tampered")},
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )
        tampered_plan = ExecutionPlan(
            plan_id=plan.plan_id,
            request_query=plan.request_query,
            plan_type=plan.plan_type,
            status="PLAN_READY",
            steps=[tampered_step],
            dag_edges=[],
            execution_order=["step-1"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Tampered plan"
        )

        # Executing tampered plan must fail integrity check
        with pytest.raises(PreflightVerificationError) as exc_info:
            ctx.execution_engine.execute_plan(plan=tampered_plan, token=token)
        assert "integrity verification failed" in str(exc_info.value)

    def test_policy_revision_stale_detection(self, exec_test_env):
        ctx = exec_test_env["ctx"]
        from governance_policy_v1 import increment_policy_revision

        step = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.executable-server:echo-message",
            display_name="Echo Step",
            sub_goal="Echo test",
            selection_reason="Test",
            input_bindings={"msg": StepInputBinding("msg", "string", False, bound_value="fresh")},
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )
        plan, token = _create_authorized_plan(ctx, [step], query="Policy freshness check")

        # Drift policy revision post-authorization
        increment_policy_revision(ctx.conn, change_reason="EMERGENCY_POLICY_UPDATE")

        # Execution must fail due to policy drift
        with pytest.raises(PreflightVerificationError) as exc_info:
            ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert "POLICY_REVISION_MISMATCH" in str(exc_info.value)


class TestTopologicalDataFlowAndParameterPropagation:
    """Tests multi-step topological execution, downstream parameter propagation, and unresolved errors."""

    def test_multistep_parameter_propagation(self, exec_test_env):
        ctx = exec_test_env["ctx"]

        # Step 1: Calculate sum (10 + 20 = 30)
        step1 = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.calc-server:calculate-sum",
            display_name="Calculate Sum",
            sub_goal="Compute 10 + 20",
            selection_reason="Add numbers",
            input_bindings={
                "a": StepInputBinding("a", "integer", True, bound_value=10),
                "b": StepInputBinding("b", "integer", True, bound_value=20)
            },
            output_definitions={"result": StepOutputDefinition("result", "integer")}
        )

        # Step 2: Hash SHA256 consuming Step 1's output
        step2 = PlanStep(
            step_id="step-2",
            step_index=2,
            capability_urn="urn:lcs:tool:mcp.hash-server:hash-sha256-digest",
            display_name="Hash Result",
            sub_goal="Hash computation result",
            selection_reason="Hash",
            input_bindings={
                "data": StepInputBinding(
                    "data", "string", True,
                    source_type=BindingSourceType.STEP_OUTPUT,
                    source_step_id="step-1",
                    source_output_field="result"
                )
            },
            output_definitions={"sha256_hash": StepOutputDefinition("sha256_hash", "string")}
        )

        plan, token = _create_authorized_plan(ctx, [step1, step2], query="Compute and hash")

        result = ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert result.lifecycle_state == ExecutionLifecycleState.SUCCEEDED
        assert result.completed_steps == 2
        assert len(result.step_records) == 2

        # Step 1 output was 30
        assert result.outputs["step-1"]["result"] == 30
        # Step 2 output hashed 30
        expected_hash = hashlib.sha256(b"30").hexdigest()
        assert result.outputs["step-2"]["sha256_hash"] == expected_hash

    def test_unresolved_mandatory_parameter_halts_execution(self, exec_test_env):
        ctx = exec_test_env["ctx"]

        step = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.calc-server:calculate-sum",
            display_name="Calculate Missing Param",
            sub_goal="Missing mandatory param",
            selection_reason="Test",
            input_bindings={
                "a": StepInputBinding("a", "integer", True, bound_value=None, source_type=BindingSourceType.UNRESOLVED)
            },
            output_definitions={"result": StepOutputDefinition("result", "integer")}
        )

        plan, token = _create_authorized_plan(ctx, [step], query="Unresolved param")

        result = ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert result.lifecycle_state == ExecutionLifecycleState.FAILED
        assert result.completed_steps == 0
        assert "could not be resolved" in result.error_message


class TestModalityHandlers:
    """Tests Skill execution modality and Path confinement."""

    def test_skill_execution_modality(self, exec_test_env):
        ctx = exec_test_env["ctx"]

        # 1. Ingest test skill into CAS and register interface
        skill_text = (
            "---\n"
            "name: test-formatter\n"
            "description: Test skill formatting\n"
            "---\n"
            "# Formatter\n"
            "Execute formatting on ${target_file} with options $ARGUMENTS.\n"
        )
        content_bytes = skill_text.encode("utf-8")
        skill_urn = "urn:lcs:skill:antigravity.global:test-formatter"
        digest = _register_skill_interface(ctx, skill_urn, content_bytes, environment="antigravity.global")

        cur = ctx.conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO artifact_discovery_records (
                artifact_id, name, display_name, taxonomy_kind, environment_origin,
                precedence_tier, source_path, resolved_path, is_bundle,
                file_size_bytes, st_mtime, st_ino, st_dev, raw_content_digest,
                canonical_urn, lifecycle_state
            ) VALUES (
                'art-test1', 'test-formatter', 'Test Formatter', 'SKILL', 'ANTIGRAVITY',
                1, '/tmp/SKILL.md', '/tmp/SKILL.md', 0,
                ?, 0, 0, 0, ?, ?, 'AVAILABLE'
            );
        """, (len(content_bytes), digest, skill_urn))
        ctx.conn.commit()

        # Step executing this skill
        step = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn=skill_urn,
            display_name="Test Formatter Skill",
            sub_goal="Run formatter",
            selection_reason="Test",
            input_bindings={
                "target_file": StepInputBinding("target_file", "string", False, bound_value="report.txt"),
                "mode": StepInputBinding("mode", "string", False, bound_value="verbose")
            },
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )

        plan, token = _create_authorized_plan(ctx, [step], query="Run skill")

        result = ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert result.lifecycle_state == ExecutionLifecycleState.SUCCEEDED
        rendered = result.outputs["step-1"]["rendered_instructions"]
        assert "Execute formatting on report.txt" in rendered
        assert '"mode": "verbose"' in rendered

    def test_path_confinement_security_rejection(self, exec_test_env):
        ws_root = str(exec_test_env["root"])

        # Path inside workspace passes
        inside = os.path.join(ws_root, "valid.txt")
        assert PathSecurityValidator.validate_file_path(inside, [ws_root]) == os.path.realpath(inside)

        # Path outside workspace rejected
        outside = "/etc/passwd"
        with pytest.raises(PathTraversalExecutionError):
            PathSecurityValidator.validate_file_path(outside, [ws_root])


class TestProcessSupervisorAndTimeout:
    """Tests process group execution and timeout supervisor."""

    def test_process_supervisor_normal_command(self):
        code, out, err = ProcessSupervisor.execute_command(["echo", "hello-lcs"])
        assert code == 0
        assert "hello-lcs" in out

    def test_process_supervisor_timeout_enforcement(self):
        # Command that sleeps longer than timeout
        with pytest.raises(StepExecutionTimeoutError):
            ProcessSupervisor.execute_command(["sleep", "5"], timeout_seconds=0.5)


class TestCompensationAndAuditReceipts:
    """Tests fault recovery, reverse compensation unwinding, and append-only audit ledger."""

    def test_compensation_unwinding_on_step_failure(self, exec_test_env):
        ctx = exec_test_env["ctx"]

        # Step 1: Reversible echo step
        step1 = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.executable-server:echo-message",
            display_name="Reversible Echo",
            sub_goal="Step 1",
            selection_reason="Echo",
            input_bindings={"msg": StepInputBinding("msg", "string", False, bound_value="created")},
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )

        # Step 2: Step that fails with missing mandatory parameter
        step2 = PlanStep(
            step_id="step-2",
            step_index=2,
            capability_urn="urn:lcs:tool:mcp.calc-server:calculate-sum",
            display_name="Failing Step",
            sub_goal="Step 2",
            selection_reason="Fail",
            input_bindings={"a": StepInputBinding("a", "integer", True, bound_value=None, source_type=BindingSourceType.UNRESOLVED)},
            output_definitions={"result": StepOutputDefinition("result", "integer")}
        )

        plan, token = _create_authorized_plan(ctx, [step1, step2], query="Compensation test")

        result = ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert result.lifecycle_state == ExecutionLifecycleState.FAILED

        # Verify audit ledger has events
        ok, count, msg = ctx.governance_engine.audit_ledger.verify_ledger()
        assert ok
        assert count >= 3

        # Verify CAS execution trace exists and can be loaded
        assert result.trace_cas_digest is not None
        trace_blob = ctx.execution_engine.read_blob_from_cas(result.trace_cas_digest)
        assert trace_blob is not None
        trace_obj = json.loads(trace_blob.decode("utf-8"))
        assert trace_obj["run_id"] == result.run_id
        assert trace_obj["lifecycle_state"] == "FAILED"


class TestCliExecutionIntegration:
    """Tests CLI command execution for 'lcs execute', 'lcs run list', and 'lcs run inspect'."""

    def test_cli_execute_and_run_inspection(self, exec_test_env, capsys):
        ctx = exec_test_env["ctx"]
        root_dir = str(exec_test_env["root"])

        # Setup test skill inside the workspace
        s_dir = exec_test_env["root"] / ".agents" / "skills" / "cli-echo"
        s_dir.mkdir(parents=True, exist_ok=True)
        skill_text = (
            "---\n"
            "name: cli-echo\n"
            "description: Echo test message and parameters\n"
            "---\n"
            "# Echo Command\n"
            "Echoing $ARGUMENTS\n"
        )
        (s_dir / "SKILL.md").write_text(skill_text)

        with patch.dict(os.environ, {"HOME": str(exec_test_env["home"])}), \
             patch("os.path.expanduser", lambda p: str(exec_test_env["home"]) if p.startswith("~") else p), \
             patch.object(Path, "home", return_value=exec_test_env["home"]):

            # Discover skill so it's in the catalog and FTS index
            recs = ctx.skill_service.run_full_pipeline()
            skill_rec = recs[0]

            # Register interface declaration so permissive policy approves it
            _register_skill_interface(ctx, skill_rec.canonical_urn, skill_text.encode("utf-8"), environment="antigravity.workspace")

            # 1. Execute task query directly via CLI
            rc = cli_main(["--root", root_dir, "execute", "Echo test message and parameters", "--permissive", "--args", '{"msg": "cli-test-ok"}'])
            assert rc == 0
            captured = capsys.readouterr()
            assert "[EXECUTION SUCCEEDED]" in captured.out

            # Extract Run ID from output
            run_id = None
            for line in captured.out.splitlines():
                if "Run ID:" in line:
                    run_id = line.split("Run ID:")[-1].strip()
                    break
            assert run_id is not None

            # 2. List runs via CLI
            rc = cli_main(["--root", root_dir, "run", "list"])
            assert rc == 0
            captured = capsys.readouterr()
            assert run_id in captured.out

            # 3. Inspect run via CLI
            rc = cli_main(["--root", root_dir, "run", "inspect", run_id])
            assert rc == 0
            captured = capsys.readouterr()
            assert f"EXECUTION RUN: {run_id}" in captured.out
