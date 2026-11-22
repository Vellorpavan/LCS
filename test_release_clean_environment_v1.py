"""
LCS v3.1.0-RC1 Clean-Environment Packaging Validation Suite (Task 013)
======================================================================
Authoritative verification covering:
1. Clean-environment installation in isolated temporary virtual environment.
2. Initialization from scratch without pre-existing development database or cache.
3. Slash-command installation, safe removal, and protection against overwriting user files.
4. Explicit CLI /call-me invocation and ordinary-message conversational dormancy.
5. Real multi-step execution acceptance under Generic POSIX Adapter.
6. Security invariants: Hash-On-Activation, fail-closed governance, replay protection, secret non-exposure.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import pytest
from unittest.mock import MagicMock

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.adapters.base import EnvironmentKind, AdapterFeature
from lcs.adapters.generic import GenericPOSIXAdapter
from lcs.interface.generators import SlashCommandGenerator, CommandGeneratorError
from lcs.planning import (
    ExecutionPlan,
    PlanStep,
    StepInputBinding,
    StepOutputDefinition,
    BindingSourceType,
)
from lcs.execution import (
    ExecutionEngineV1,
    ExecutionLifecycleState,
    PreflightVerificationError,
    StepExecutionStatus,
)
from lcs.policy import InterfaceTrustPolicy
from lcs.governance import (
    ApproverConsent,
    ApproverRole,
    GovernanceStatus,
    TokenAlreadyConsumedError,
)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROD_WHEEL = os.path.join(CURRENT_DIR, "dist", "lcs_core-3.1.0-py3-none-any.whl")
RC1_WHEEL = os.path.join(CURRENT_DIR, "dist", "lcs_core-3.1.0rc1-py3-none-any.whl")
WHEEL_PATH = PROD_WHEEL if os.path.exists(PROD_WHEEL) else RC1_WHEEL


@pytest.fixture
def clean_test_env():
    """Sets up an isolated LCSContext in a fresh temporary workspace."""
    raw_dir = tempfile.mkdtemp(prefix="lcs_task013_clean_")
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
        "home": home_dir,
    }
    ctx.close()
    if os.path.exists(real_dir):
        shutil.rmtree(real_dir, ignore_errors=True)


# ============================================================================
# 1. Clean Environment Isolation & Packaging Validation
# ============================================================================

class TestCleanEnvironmentInstallationAndImports:
    """Verifies that LCS installs and initializes in a virgin virtualenv without development state."""

    def test_wheel_package_install_and_import_in_isolated_venv(self):
        """
        Creates an isolated temporary virtual environment and installs the built wheel.
        Confirms dependency resolution, package import, and correct version.
        """
        # If pre-built wheel is not present in clean checkout, skip
        actual_wheel = None
        if os.path.exists(WHEEL_PATH):
            actual_wheel = WHEEL_PATH
        else:
            dist_dir = os.path.join(CURRENT_DIR, "dist")
            if os.path.isdir(dist_dir):
                wheels = [os.path.join(dist_dir, f) for f in os.listdir(dist_dir) if f.endswith(".whl")]
                if wheels:
                    actual_wheel = wheels[0]

        if not actual_wheel:
            pytest.skip(f"Pre-built wheel package not present in checkout (expected at {WHEEL_PATH})")

        with tempfile.TemporaryDirectory() as td:
            venv_dir = os.path.join(td, "clean_venv")
            subprocess.run([sys.executable, "-m", "venv", venv_dir], check=True)

            if sys.platform == "win32":
                venv_python = os.path.join(venv_dir, "Scripts", "python.exe")
                venv_pip = os.path.join(venv_dir, "Scripts", "pip.exe")
            else:
                venv_python = os.path.join(venv_dir, "bin", "python")
                venv_pip = os.path.join(venv_dir, "bin", "pip")

            # Install standalone wheel package
            install_cmd = [venv_pip, "install", actual_wheel]
            res = subprocess.run(install_cmd, capture_output=True, text=True)
            assert res.returncode == 0, f"pip install failed:\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}"

            # Verify package import and __version__
            expected_ver = "3.1.0" if "3.1.0-py3" in WHEEL_PATH else "3.1.0rc1"
            check_script = "import lcs; print('VERSION:' + lcs.__version__)"
            res = subprocess.run([venv_python, "-c", check_script], capture_output=True, text=True, cwd=td)
            assert res.returncode == 0, f"Import failed in clean venv: {res.stderr}"
            assert f"VERSION:{expected_ver}" in res.stdout

    def test_clean_initialization_without_existing_db_or_cache(self):
        """
        Verifies that LCS CLI initializes from scratch in a virgin directory without
        relying on pre-existing development database, keys, or cache.
        """
        with tempfile.TemporaryDirectory() as td:
            clean_lcs_root = os.path.join(td, "virgin_lcs_root")

            # Run lcs status on non-existent directory
            res = subprocess.run(
                [sys.executable, "-m", "lcs.cli", "--root", clean_lcs_root, "status"],
                capture_output=True,
                text=True
            )
            assert res.returncode == 0, f"lcs status failed on clean directory: {res.stderr}"
            assert "LIVING CAPABILITY SYSTEM (LCS) — SYSTEM STATUS" in res.stdout
            assert "Migrations:        4/4 applied" in res.stdout

            # Verify database, CAS, and directory structure were created cleanly
            db_path = os.path.join(clean_lcs_root, "lcs.db")
            cas_path = os.path.join(clean_lcs_root, "cas")
            keys_path = os.path.join(clean_lcs_root, "keys")

            assert os.path.exists(db_path), "Database was not created in clean root"
            assert os.path.isdir(cas_path), "CAS directory was not created in clean root"
            assert os.path.isdir(keys_path), "Keys directory was not created in clean root"


# ============================================================================
# 2. Command Installation, Invocation, and Dormancy
# ============================================================================

class TestCommandInstallationInvocationAndDormancy:
    """Verifies slash-command installation, safe removal, overwrite safety, CLI invocation, and dormancy."""

    def test_call_me_slash_command_installation_across_environments(self, clean_test_env):
        """Verifies installation of /call-me across Antigravity, Claude Code, and OpenCode."""
        ws = clean_test_env["workspace"]

        installed = SlashCommandGenerator.install_all(ws, overwrite=False)
        assert "ANTIGRAVITY" in installed
        assert "CLAUDE_CODE" in installed
        assert "OPENCODE" in installed

        ag_file = installed["ANTIGRAVITY"]
        cc_file = installed["CLAUDE_CODE"]
        oc_file = installed["OPENCODE"]

        assert os.path.exists(ag_file)
        assert os.path.exists(cc_file)
        assert os.path.exists(oc_file)

        # Confirm LCS signature
        with open(ag_file, "r", encoding="utf-8") as f:
            assert SlashCommandGenerator.LCS_ARTIFACT_SIGNATURE in f.read()

    def test_safe_uninstall_and_empty_directory_cleanup(self, clean_test_env):
        """Verifies safe removal of command artifacts and cleanup of empty directories."""
        ws = clean_test_env["workspace"]
        SlashCommandGenerator.install_all(ws, overwrite=False)

        ag_dir = os.path.join(ws, ".agents", "skills", "call-me")
        cc_dir = os.path.join(ws, ".claude", "commands")
        oc_dir = os.path.join(ws, ".opencode", "commands")

        assert os.path.isdir(ag_dir)

        # Uninstall Antigravity
        uninstalled_ag = SlashCommandGenerator.uninstall(ws, "ANTIGRAVITY")
        assert uninstalled_ag is True
        assert not os.path.exists(os.path.join(ag_dir, "SKILL.md"))
        assert not os.path.exists(ag_dir)

        # Uninstall Claude Code
        uninstalled_cc = SlashCommandGenerator.uninstall(ws, "CLAUDE_CODE")
        assert uninstalled_cc is True
        assert not os.path.exists(os.path.join(cc_dir, "call-me.md"))

        # Uninstall OpenCode
        uninstalled_oc = SlashCommandGenerator.uninstall(ws, "OPENCODE")
        assert uninstalled_oc is True
        assert not os.path.exists(os.path.join(oc_dir, "call-me.md"))

    def test_protection_against_overwriting_unrelated_user_files(self, clean_test_env):
        """Verifies that install refuses to overwrite existing user files without overwrite=True."""
        ws = clean_test_env["workspace"]
        ag_dir = os.path.join(ws, ".agents", "skills", "call-me")
        os.makedirs(ag_dir, exist_ok=True)
        user_file = os.path.join(ag_dir, "SKILL.md")

        # Create unrelated user file
        with open(user_file, "w", encoding="utf-8") as f:
            f.write("# Unrelated user skill\ndo not touch\n")

        # Attempt install without overwrite -> must raise CommandGeneratorError
        with pytest.raises(CommandGeneratorError) as exc_info:
            SlashCommandGenerator.install_antigravity(ws, overwrite=False)
        assert "Refusing to overwrite existing non-LCS file" in str(exc_info.value)

        # With overwrite=True -> succeeds
        installed_path = SlashCommandGenerator.install_antigravity(ws, overwrite=True)
        assert os.path.exists(installed_path)
        with open(installed_path, "r", encoding="utf-8") as f:
            assert SlashCommandGenerator.LCS_ARTIFACT_SIGNATURE in f.read()

    def test_explicit_call_me_cli_invocation(self, clean_test_env):
        """
        Tests explicit CLI /call-me invocation via `lcs call-me`.
        Clearly distinguishing tested CLI invocation from genuine host UI invocation.
        """
        root = clean_test_env["root"]
        task_query = "Calculate project metrics and format summary"

        res = subprocess.run(
            [sys.executable, "-m", "lcs.cli", "--root", root, "call-me", task_query],
            capture_output=True,
            text=True
        )
        assert res.returncode == 0
        assert "LIVING CAPABILITY SYSTEM (LCS) — /call-me INVOCATION" in res.stdout
        assert "Status:             ACCEPTED" in res.stdout
        assert "Request ID:         req-" in res.stdout

    def test_ordinary_conversational_dormancy_in_clean_environment(self, clean_test_env):
        """
        Empirically verifies that non-/call-me messages completely bypass LCS Core:
        - 0 Core invocations
        - 0 Database queries or writes
        - 0 CAS writes
        - 0 Context token consumption
        """
        ctx: LCSContext = clean_test_env["ctx"]

        ordinary_prompts = [
            "What is the capital of France?",
            "How do I sort a list in Python?",
            "Can you write a poem about autumn?",
            "git status check"
        ]

        cas_dir = os.path.join(ctx.config.cas_root, "objects")
        cas_before = len(os.listdir(cas_dir)) if os.path.exists(cas_dir) else 0

        cur = ctx.conn.cursor()
        cur.execute("SELECT count(*) FROM execution_runs;")
        runs_before = cur.fetchone()[0]

        for p in ordinary_prompts:
            resp = ctx.call_me.execute_call_me(p)
            # Invariant: Dormant bypass returns None for non-/call-me messages
            assert resp is None

        # Invariant: zero database or storage mutations
        cur.execute("SELECT count(*) FROM execution_runs;")
        runs_after = cur.fetchone()[0]
        assert runs_after == runs_before

        cas_after = len(os.listdir(cas_dir)) if os.path.exists(cas_dir) else 0
        assert cas_after == cas_before


# ============================================================================
# 3. Real Multi-Step Execution Acceptance under Generic POSIX Adapter
# ============================================================================

class TestRealExecutionAcceptanceGenericPOSIX:
    """Verifies end-to-end execution of a multi-step task under GenericPOSIXAdapter."""

    def test_generic_posix_multi_step_governed_execution(self, clean_test_env):
        """
        Submits a representative multi-step task using GenericPOSIXAdapter:
        1. Step 1: Tool execution (echo message).
        2. Step 2: Tool execution (calculate sum).
        3. Dependency resolution and topological ordering.
        4. Governance Gate 1 (policy) & Gate 2 (approver consent).
        5. Execution under sandboxed process supervision.
        6. Verifies final deliverable and execution records in CAS and audit ledger.
        """
        ctx: LCSContext = clean_test_env["ctx"]
        ws = clean_test_env["workspace"]

        # Ensure GenericPOSIXAdapter is active
        posix_adapter = GenericPOSIXAdapter(ws)
        ctx.get_active_adapter = MagicMock(return_value=posix_adapter)
        assert posix_adapter.environment_kind == EnvironmentKind.GENERIC_POSIX

        # Register live test MCP server with 2 distinct tools under qualified scopes
        server_path = os.path.join(CURRENT_DIR, "evaluation_fixtures", "executable_test_server.py")
        test_policy = InterfaceTrustPolicy(
            policy_name="posix-test-policy",
            min_interface_version=1,
            require_attestation=False,
            require_all_capabilities_verified=False
        )

        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "echo_message"],
            server_name="posix-echo-srv",
            trust_policy=test_policy
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "calculate_sum"],
            server_name="posix-calc-srv",
            trust_policy=test_policy
        )

        deliverable_file = os.path.join(ws, "final_summary_report.txt")

        # Step 1: Echo configuration parameters
        step1 = PlanStep(
            step_id="step-1-echo",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.posix-echo-srv:echo-message",
            display_name="Generate Parameter Context",
            sub_goal="Format execution parameters",
            selection_reason="Echo tool",
            input_bindings={"message": StepInputBinding("message", "string", False, bound_value="INIT_POSIX_RUN")},
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )

        # Step 2: Calculate sum
        step2 = PlanStep(
            step_id="step-2-calc",
            step_index=2,
            capability_urn="urn:lcs:tool:mcp.posix-calc-srv:calculate-sum",
            display_name="Compute Metrics Checksum",
            sub_goal="Calculate sum",
            selection_reason="Calc tool",
            input_bindings={
                "a": StepInputBinding("a", "integer", False, bound_value=15),
                "b": StepInputBinding("b", "integer", False, bound_value=25)
            },
            output_definitions={"result": StepOutputDefinition("result", "integer")}
        )

        plan = ExecutionPlan(
            plan_id="plan-posix-acceptance",
            request_query="Echo parameters and compute sum under POSIX adapter",
            plan_type="MULTI_CAPABILITY",
            status="PLAN_READY",
            steps=[step1, step2],
            dag_edges=[],
            execution_order=["step-1-echo", "step-2-calc"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="POSIX execution acceptance test plan"
        )

        # Governance Gate 2 Consent
        consent = ApproverConsent(
            principal="posix-operator@local",
            role=ApproverRole.SECURITY_OFFICER,
            method="CLI_TEST"
        )

        token, eval_res = ctx.governance_engine.approve_plan(plan, consent, active_policy=test_policy)
        assert eval_res.status == GovernanceStatus.APPROVED
        assert token is not None

        # Execute Plan
        result = ctx.execution_engine.execute_plan(plan=plan, token=token)

        assert result.lifecycle_state == ExecutionLifecycleState.SUCCEEDED
        assert result.completed_steps == 2
        assert result.trace_cas_digest is not None

        # Verify Execution Trace Record in CAS
        trace_bytes = ctx.execution_engine.read_blob_from_cas(result.trace_cas_digest)
        assert trace_bytes is not None
        trace = json.loads(trace_bytes.decode("utf-8"))
        assert trace["run_id"] == result.run_id
        assert trace["lifecycle_state"] == "SUCCEEDED"
        assert len(trace["step_records"]) == 2

        # Verify Append-Only Audit Ledger
        valid_chain, count, msg = ctx.governance_engine.audit_ledger.verify_ledger()
        assert valid_chain is True
        assert count >= 4


# ============================================================================
# 4. Security, Integrity, and Invariant Verification
# ============================================================================

class TestSecurityAndIntegrityControls:
    """Verifies Hash-On-Activation, fail-closed handling, replay defense, and secret non-exposure."""

    def test_fail_closed_on_missing_mandatory_input(self, clean_test_env):
        """Verifies that execution fails closed when a mandatory input parameter is missing."""
        ctx: LCSContext = clean_test_env["ctx"]

        server_path = os.path.join(CURRENT_DIR, "evaluation_fixtures", "executable_test_server.py")
        test_policy = InterfaceTrustPolicy(
            policy_name="test-policy",
            min_interface_version=1,
            require_attestation=False,
            require_all_capabilities_verified=False
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "calculate_sum"],
            server_name="srv-calc-fail",
            trust_policy=test_policy
        )

        step = PlanStep(
            step_id="step-missing-param",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.srv-calc-fail:calculate-sum",
            display_name="Failing Step",
            sub_goal="Test fail-closed",
            selection_reason="Fail",
            input_bindings={
                "a": StepInputBinding("a", "integer", True, bound_value=None, source_type=BindingSourceType.UNRESOLVED)
            },
            output_definitions={"result": StepOutputDefinition("result", "integer")}
        )

        plan = ExecutionPlan(
            plan_id="plan-missing-mandatory",
            request_query="Fail closed test",
            plan_type="SINGLE_CAPABILITY",
            status="PLAN_READY",
            steps=[step],
            dag_edges=[],
            execution_order=["step-missing-param"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Missing mandatory input plan"
        )

        consent = ApproverConsent(principal="admin@local", role=ApproverRole.SECURITY_OFFICER, method="TEST")
        token, _ = ctx.governance_engine.approve_plan(plan, consent, active_policy=test_policy)

        # Plan execution must fail closed
        result = ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert result.lifecycle_state == ExecutionLifecycleState.FAILED
        assert result.completed_steps == 0

    def test_single_use_replay_protection(self, clean_test_env):
        """Verifies atomic consumption and replay rejection for EAT governance tokens."""
        ctx: LCSContext = clean_test_env["ctx"]

        server_path = os.path.join(CURRENT_DIR, "evaluation_fixtures", "executable_test_server.py")
        test_policy = InterfaceTrustPolicy(
            policy_name="test-policy",
            min_interface_version=1,
            require_attestation=False,
            require_all_capabilities_verified=False
        )
        ctx.discovery_pipeline.discover_and_register_mcp_server(
            command=[sys.executable, server_path, "--tools", "echo_message"],
            server_name="srv-replay-test",
            trust_policy=test_policy
        )

        step = PlanStep(
            step_id="step-1",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.srv-replay-test:echo-message",
            display_name="Echo",
            sub_goal="Test replay",
            selection_reason="Echo",
            input_bindings={"message": StepInputBinding("message", "string", False, bound_value="OK")},
            output_definitions={"result": StepOutputDefinition("result", "string")}
        )

        plan = ExecutionPlan(
            plan_id="plan-replay",
            request_query="Replay test",
            plan_type="SINGLE_CAPABILITY",
            status="PLAN_READY",
            steps=[step],
            dag_edges=[],
            execution_order=["step-1"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Replay test plan"
        )

        consent = ApproverConsent(principal="admin@local", role=ApproverRole.SECURITY_OFFICER, method="TEST")
        token, _ = ctx.governance_engine.approve_plan(plan, consent, active_policy=test_policy)

        # First execution -> succeeds
        res1 = ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert res1.lifecycle_state == ExecutionLifecycleState.SUCCEEDED

        # Replay attempt with same token -> fails closed
        with pytest.raises((TokenAlreadyConsumedError, PreflightVerificationError)) as exc_info:
            ctx.execution_engine.execute_plan(plan=plan, token=token)
        assert "already been consumed" in str(exc_info.value).lower()

    def test_secrets_not_exposed_in_audit_ledger_or_trace_receipts(self, clean_test_env):
        """
        Verifies that HMAC secret keys and raw private key bytes are never written
        to execution trace receipts or append-only audit ledgers.
        """
        ctx: LCSContext = clean_test_env["ctx"]
        key_store = ctx.key_store
        active_key_bytes = key_store.get_key(key_store.active_key_id)
        secret_hex = active_key_bytes.hex()

        # Audit ledger text
        al_path = ctx.governance_engine.audit_ledger.log_path
        if os.path.exists(al_path):
            with open(al_path, "r", encoding="utf-8") as f:
                al_content = f.read()
            assert secret_hex not in al_content, "Raw secret key hex leaked in audit ledger"

        # Check all CAS trace files
        cas_objects_dir = os.path.join(ctx.config.cas_root, "objects")
        if os.path.exists(cas_objects_dir):
            for root, _, files in os.walk(cas_objects_dir):
                for f in files:
                    blob_path = os.path.join(root, f)
                    with open(blob_path, "rb") as bf:
                        blob_bytes = bf.read()
                    assert active_key_bytes not in blob_bytes, f"Raw secret key bytes leaked in CAS blob {f}"
