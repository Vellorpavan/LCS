#!/usr/bin/env python3
"""
LCS End-to-End Integration Verification Suite (V3.0.0)
======================================================
Authoritative end-to-end integration tests verifying the complete vertical
pipeline across all LCS subsystems:
  1. Discovery & CAS exact-byte storage (Skill & MCP)
  2. Semantic profiling & parameter understanding
  3. Natural language retrieval & FTS5 candidate ranking
  4. Multi-capability DAG plan synthesis & data flow binding
  5. Dual-gated execution governance (Gate 1 policy & Gate 2 approver consent)
  6. Token issuance, replay protection, and plan integrity hashing (RFC 8785)
  7. Runtime execution engine dispatch across skill & MCP modality handlers
  8. Append-only cryptographic audit logging and CAS trace storage
"""

import os
import sys
import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.skills import (
    EnvironmentOrigin,
    SkillLifecycleState,
    DiscoveryRootResolver
)
from lcs.governance import (
    ApproverConsent,
    ApproverRole,
    GovernanceStatus
)
from lcs.execution import (
    ExecutionLifecycleState,
    StepExecutionStatus,
    PreflightVerificationError
)
from lcs.cli import main as cli_main


@pytest.fixture
def e2e_env(tmp_path):
    """Sets up an isolated LCS environment with custom workspace and discovery roots."""
    root = tmp_path / "lcs_root"
    fake_home = tmp_path / "home"
    ws = tmp_path / "workspace"
    root.mkdir(parents=True, exist_ok=True)
    fake_home.mkdir(parents=True, exist_ok=True)
    ws.mkdir(parents=True, exist_ok=True)

    # Set up sample skills in workspace
    skill_dir = ws / ".agents" / "skills" / "data-formatter"
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: data-formatter\n"
        "description: Formats input text into a standardized uppercase output\n"
        "parameters:\n"
        "  input_text:\n"
        "    type: string\n"
        "    required: false\n"
        "    description: The text to format\n"
        "---\n"
        "# Data Formatter\n"
        "Format input text: {{input_text}}\n"
    )

    cfg = LCSConfig.resolve(root_override=str(root))
    ctx = LCSContext(config=cfg, auto_migrate=True)
    resolver = DiscoveryRootResolver(workspace_root=str(ws), home_dir=str(fake_home))
    ctx.skill_service.set_resolver(resolver)

    yield {
        "ctx": ctx,
        "root": root,
        "ws": ws,
        "home": fake_home,
        "resolver": resolver
    }

    ctx.close()


class TestEndToEndPipeline:
    """Verifies complete end-to-end integration across all LCS subsystems."""

    def test_01_skill_discovery_to_governed_execution(self, e2e_env):
        """
        Tests complete vertical slice:
        Skill Discovery -> Ingestion -> Profiling -> Catalog/FTS5 -> Retrieval ->
        Plan Generation -> Gate 1 Check -> Gate 2 Consent -> Token Issuance ->
        Process Execution -> CAS Trace -> Audit Ledger.
        """
        ctx = e2e_env["ctx"]

        # 1. Run discovery pipeline
        records = ctx.skill_service.run_full_pipeline()
        assert len(records) >= 1
        skill_rec = next(r for r in records if r.name == "data-formatter")
        assert skill_rec.lifecycle_state == SkillLifecycleState.AVAILABLE
        assert skill_rec.raw_content_digest is not None
        assert ctx.cas_engine.blob_exists(skill_rec.raw_content_digest)

        # 2. Unified Retrieval
        candidates = ctx.retrieval_coordinator.retrieve("format input text")
        assert len(candidates) >= 1
        top_cand = candidates[0]
        assert "data-formatter" in top_cand.capability_urn

        # 3. Create Multi-Capability DAG Plan
        plan = ctx.planning_engine.create_plan("format input text")
        assert plan.status in ("PLAN_READY", "PLAN_INCOMPLETE")
        assert len(plan.steps) == 1
        step = plan.steps[0]
        assert step.capability_urn == skill_rec.canonical_urn

        # 4. Governance Gate 1 (Capability Trust & Policy Evaluation)
        eval_res = ctx.governance_engine.evaluate_plan(plan)
        assert eval_res.status == GovernanceStatus.PENDING
        assert eval_res.gate_1_status == "VERIFIED"
        assert len(eval_res.reasons) == 0

        # 5. Governance Gate 2 (Approver Consent & Authorization)
        consent = ApproverConsent(
            principal="admin-security",
            role=ApproverRole.SECURITY_OFFICER,
            method="CLI_SIGNATURE"
        )
        token, final_eval = ctx.governance_engine.approve_plan(plan, consent)
        assert token is not None
        assert token.token_id.startswith("eat-")
        assert final_eval.status == GovernanceStatus.APPROVED

        # 6. Runtime Execution via ExecutionEngineV1
        run_res = ctx.execution_engine.execute_plan(plan, token)
        assert run_res.lifecycle_state == ExecutionLifecycleState.SUCCEEDED
        assert run_res.total_steps == 1
        assert run_res.completed_steps == 1
        assert run_res.trace_cas_digest is not None
        assert ctx.cas_engine.blob_exists(run_res.trace_cas_digest)

        # 7. Verify step execution record
        srec = run_res.step_records[0]
        assert srec.status == StepExecutionStatus.COMPLETED
        assert srec.capability_urn == skill_rec.canonical_urn
        assert srec.output_result["status"] == "SUCCESS"
        assert "rendered_instructions" in srec.output_result

        # 8. Verify Execution Run persistence
        persisted_run = ctx.execution_engine.get_run(run_res.run_id)
        assert persisted_run is not None
        assert persisted_run["lifecycle_state"] == "SUCCEEDED"

        # 9. Verify Audit Ledger integrity
        is_valid, count, msg = ctx.governance_engine.audit_ledger.verify_ledger()
        assert is_valid is True
        assert count > 0

    def test_02_tampered_plan_blocked_at_runtime(self, e2e_env):
        """Verifies that tampering with a plan after governance approval halts execution."""
        ctx = e2e_env["ctx"]

        # Run discovery & plan
        ctx.skill_service.run_full_pipeline()
        plan = ctx.planning_engine.create_plan("format input text")
        consent = ApproverConsent(principal="admin", role=ApproverRole.SECURITY_OFFICER)
        token, _ = ctx.governance_engine.approve_plan(plan, consent)

        # Tamper with plan
        plan.steps[0].capability_urn = "urn:lcs:skill:antigravity.workspace:malicious-skill"

        with pytest.raises(PreflightVerificationError) as exc_info:
            ctx.execution_engine.execute_plan(plan, token)
        assert "Plan integrity verification failed" in str(exc_info.value)

    def test_03_token_replay_rejected(self, e2e_env):
        """Verifies that an execution authorization token cannot be consumed twice."""
        ctx = e2e_env["ctx"]

        ctx.skill_service.run_full_pipeline()
        plan = ctx.planning_engine.create_plan("format input text")
        consent = ApproverConsent(principal="admin", role=ApproverRole.SECURITY_OFFICER)
        token, _ = ctx.governance_engine.approve_plan(plan, consent)

        # First execution succeeds
        res1 = ctx.execution_engine.execute_plan(plan, token)
        assert res1.lifecycle_state == ExecutionLifecycleState.SUCCEEDED

        # Second execution with same token must fail
        with pytest.raises(PreflightVerificationError) as exc_info:
            ctx.execution_engine.execute_plan(plan, token)
        assert "TOKEN_ALREADY_CONSUMED" in str(exc_info.value)

    def test_04_cli_end_to_end_integration(self, e2e_env, capsys):
        """Verifies CLI commands for status, skills, planning, and run inspection."""
        root_dir = str(e2e_env["root"])

        # Patch environment so CLI discovery uses the test fixture roots
        with patch.dict(os.environ, {"HOME": str(e2e_env["home"])}), \
             patch("os.path.expanduser", lambda p: str(e2e_env["home"]) if p.startswith("~") else p), \
             patch.object(Path, "home", return_value=e2e_env["home"]):

            # 1. Run discovery via CLI
            ret = cli_main(["--root", root_dir, "skill", "discover"])
            assert ret == 0

            # 2. List skills via CLI
            ret = cli_main(["--root", root_dir, "skill", "list"])
            assert ret == 0

            # 3. Search skills via CLI
            ret = cli_main(["--root", root_dir, "skill", "search", "format"])
            assert ret == 0

            # 4. Inspect skill via CLI
            records = e2e_env["ctx"].skill_service.list_artifacts()
            if records:
                urn = records[0]["canonical_urn"]
                ret = cli_main(["--root", root_dir, "skill", "inspect", urn])
                assert ret == 0

    def test_05_multi_skill_dag_execution(self, e2e_env):
        """Verifies multi-skill plan synthesis, governance, and execution."""
        ctx = e2e_env["ctx"]
        ws = e2e_env["ws"]

        # Add second skill
        s2_dir = ws / ".agents" / "skills" / "summary-reporter"
        s2_dir.mkdir(parents=True, exist_ok=True)
        (s2_dir / "SKILL.md").write_text(
            "---\n"
            "name: summary-reporter\n"
            "description: Generates a summary report from formatted data\n"
            "parameters:\n"
            "  report_title:\n"
            "    type: string\n"
            "    required: false\n"
            "---\n"
            "# Summary Reporter\n"
            "Generate report: {{report_title}}\n"
        )

        records = ctx.skill_service.run_full_pipeline()
        assert len(records) >= 2

        # Create multi-capability plan
        plan = ctx.planning_engine.create_plan("format input text then generate a summary report")
        assert len(plan.steps) >= 1

        consent = ApproverConsent(principal="admin-security", role=ApproverRole.SECURITY_OFFICER)
        token, final_eval = ctx.governance_engine.approve_plan(plan, consent)
        assert final_eval.status == GovernanceStatus.APPROVED

        run_res = ctx.execution_engine.execute_plan(plan, token)
        assert run_res.lifecycle_state == ExecutionLifecycleState.SUCCEEDED
        assert run_res.completed_steps == len(plan.steps)
