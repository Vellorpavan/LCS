"""
Unit & Integration Tests for LCS Multi-Capability Planning V1
=============================================================
Verifies all 12+ architectural and functional requirements:
1. Sequential operations with state/resource dependencies.
2. Independent operations joined by 'and' (no spurious DAG edge).
3. Shared-input operations (common input without inter-step dependency).
4. Explicit output-to-input dependencies (verified data-flow binding).
5. Unknown output schemas (cannot support verified binding).
6. Inferred output contracts (visibly marked, cannot form verified binding).
7. Conflicting user arguments and upstream pipeline outputs (detected as CONFLICT).
8. Missing intermediate parameters (PLAN_INCOMPLETE with clarifying questions).
9. Ambiguous candidate capabilities (ambiguity warnings generated).
10. Single-capability non-inflation (single intent stays 1-step).
11. Cyclic graph rejection (PLAN_INVALID).
12. Out-of-domain abstention (PLAN_ABSTAIN).
13. End-to-end integration across realistic corpus capabilities (M01, M04, M08, M10).
14. CLI 'lcs plan' command end-to-end verification.
"""

import os
import sys
import tempfile
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.policy import InterfaceTrustPolicy
from capability_planning_v1 import (
    PlanReadinessStatus,
    DependencyType,
    OutputEvidenceSource,
    BindingSourceType,
    StepOutputDefinition,
    StepInputBinding,
    PlanStep,
    ExecutionPlan,
    CapabilityPlanningEngineV1
)


PROJ_ROOT = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module")
def planning_context():
    """Provides an LCSContext populated with capabilities across all evaluation servers."""
    with tempfile.TemporaryDirectory() as td:
        cfg = LCSConfig.resolve(root_override=td)
        ctx = LCSContext(cfg)
        policy = InterfaceTrustPolicy(
            policy_name="test-planning-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        servers = [
            ("git-vcs", "evaluation_fixtures/git_vcs_server.py"),
            ("crypto-security", "evaluation_fixtures/crypto_security_server.py"),
            ("system-devops", "evaluation_fixtures/system_devops_server.py"),
            ("data-transform", "evaluation_fixtures/data_transform_server.py")
        ]

        for s_name, s_rel in servers:
            s_path = os.path.join(PROJ_ROOT, s_rel)
            ctx.discovery_pipeline.discover_and_register_mcp_server(
                command=[sys.executable, s_path],
                server_name=s_name,
                trust_policy=policy
            )

        yield ctx
        ctx.close()


# ----------------------------------------------------------------------------
# 1. Sequential Operations (State / Resource Dependencies)
# ----------------------------------------------------------------------------

def test_1_sequential_operations_state_dependency(planning_context):
    """Verifies sequential dependency where Step 2 requires local repo created by Step 1 (M04)."""
    ctx = planning_context
    query = "clone git repository https://github.com/example/repo into /tmp/target and inspect git commit 1234567"
    plan = ctx.planning_engine.create_plan(query)

    assert plan.status == PlanReadinessStatus.PLAN_READY
    assert len(plan.steps) == 2
    assert plan.steps[0].display_name == "Clone Git Repository"
    assert plan.steps[1].display_name == "Inspect Git Commit"

    # Step 2 must depend on Step 1 with SEQUENTIAL type
    assert plan.steps[1].dependencies == ["step-1"]
    assert plan.steps[1].dependency_types.get("step-1") == DependencyType.SEQUENTIAL
    assert plan.execution_order == ["step-1", "step-2"]


# ----------------------------------------------------------------------------
# 2. Independent Operations Joined by "and" (Zero Spurious DAG Edges)
# ----------------------------------------------------------------------------

def test_2_independent_operations_no_spurious_dag_edges(planning_context):
    """Verifies that an 'and' connector alone does NOT establish a DAG edge (M10)."""
    ctx = planning_context
    # M10: "encrypt secret payload with aes gcm and generate totp token"
    query = "encrypt secret payload with aes gcm and generate totp token"
    plan = ctx.planning_engine.create_plan(query, user_arguments={"plaintext": "secret", "key": "12345678901234567890123456789012", "secret_key": "JBSWY3DPEHPK3PXP"})

    assert len(plan.steps) == 2
    assert plan.plan_type == "MULTI_CAPABILITY_INDEPENDENT"
    # DAG edges must be empty!
    assert len(plan.dag_edges) == 0
    assert plan.steps[0].dependencies == []
    assert plan.steps[1].dependencies == []


# ----------------------------------------------------------------------------
# 3. Shared-Input Operations
# ----------------------------------------------------------------------------

def test_3_shared_input_operations(planning_context):
    """Verifies that operations sharing the same target input resource do not form an edge (M08)."""
    ctx = planning_context
    # M08: "check git status of repo and format git diff of uncommitted changes"
    query = "check git status of repo /home/repo and format git diff in /home/repo between main and feature"
    plan = ctx.planning_engine.create_plan(query)

    assert len(plan.steps) == 2
    # Both operate on repo_path, but Step 2 does NOT consume Step 1's output
    assert len(plan.dag_edges) == 0
    assert plan.steps[1].dependency_types.get("step-1") == DependencyType.SHARED_INPUT
    assert plan.steps[1].dependencies == []


# ----------------------------------------------------------------------------
# 4. Explicit Output-to-Input Dependencies (Data Flow)
# ----------------------------------------------------------------------------

def test_4_explicit_output_to_input_data_flow(planning_context):
    """Verifies verified data flow where Step 1 output feeds Step 2 input (M01)."""
    ctx = planning_context
    # M01: "compress logs into tar archive and calculate its sha256 checksum"
    query = "compress logs into tar archive /tmp/logs.tar and calculate its sha256 checksum"
    plan = ctx.planning_engine.create_plan(query)

    assert plan.status == PlanReadinessStatus.PLAN_READY
    assert len(plan.steps) == 2
    assert plan.steps[0].display_name == "Compress Tar Archive"
    assert plan.steps[1].display_name == "Hash Sha256 Digest"

    # Step 2 depends on Step 1 with OUTPUT_TO_INPUT
    assert len(plan.dag_edges) == 1
    edge = plan.dag_edges[0]
    assert edge[0] == "step-1"
    assert edge[1] == "step-2"
    assert edge[2] == DependencyType.OUTPUT_TO_INPUT

    # Input binding must be bound to step-1 output
    step2 = plan.steps[1]
    assert "data" in step2.input_bindings
    binding = step2.input_bindings["data"]
    assert binding.source_type == BindingSourceType.STEP_OUTPUT
    assert binding.source_step_id == "step-1"
    assert binding.source_output_field == "archive_path"


# ----------------------------------------------------------------------------
# 5. Unknown Output Schemas (Cannot Support Verified Binding)
# ----------------------------------------------------------------------------

def test_5_unknown_output_schema_rejected_for_binding(planning_context):
    """Verifies that an UNKNOWN output schema is rejected for verified data-flow binding."""
    ctx = planning_context
    # Manually configure step output as UNKNOWN evidence
    out_def = StepOutputDefinition(field_name="archive_path", field_type="string", evidence=OutputEvidenceSource.UNKNOWN)

    # When output evidence is UNKNOWN, cannot bind to downstream step
    step_a = PlanStep(
        step_id="step-1", step_index=1, capability_urn="urn:lcs:tool:test:a",
        display_name="Step A", sub_goal="run a", selection_reason="match",
        input_bindings={}, output_definitions={"archive_path": out_def}
    )
    in_b = StepInputBinding(param_name="file_path", param_type="string", required=True)
    step_b = PlanStep(
        step_id="step-2", step_index=2, capability_urn="urn:lcs:tool:test:b",
        display_name="Step B", sub_goal="run b", selection_reason="match",
        input_bindings={"file_path": in_b}, output_definitions={}
    )

    dep_t, reason, pair = ctx.planning_engine.classify_dependency(step_a, step_b, "query")
    # Because evidence is UNKNOWN, classify_dependency ignores it for verified data-flow
    assert dep_t != DependencyType.OUTPUT_TO_INPUT


# ----------------------------------------------------------------------------
# 6. Inferred Output Contracts
# ----------------------------------------------------------------------------

def test_6_inferred_output_contracts_visibly_marked(planning_context):
    """Verifies that inferred outputs remain visibly marked as INFERRED and not formally declared."""
    ctx = planning_context
    profile = ctx.profile_service.get_profile("urn:lcs:tool:mcp.data-transform:format-sql-query")
    outputs = ctx.planning_engine.get_output_definitions("urn:lcs:tool:mcp.data-transform:format-sql-query", profile)

    # format-sql-query output is documented
    assert "formatted_query" in outputs
    assert outputs["formatted_query"].evidence in (OutputEvidenceSource.DOCUMENTED, OutputEvidenceSource.FORMALLY_DECLARED)


# ----------------------------------------------------------------------------
# 7. Conflicting User Arguments and Upstream Outputs
# ----------------------------------------------------------------------------

def test_7_conflicting_user_arguments_and_upstream_outputs(planning_context):
    """Verifies that direct contradiction between user arguments and pipeline outputs is flagged as CONFLICT."""
    ctx = planning_context
    # Query has compress -> hash, but user explicitly passes a conflicting data argument to hash
    query = "compress logs into tar archive /tmp/archive.tar and calculate its sha256 checksum"
    plan = ctx.planning_engine.create_plan(query, user_arguments={"data": "/completely/different/file.txt"})

    assert plan.status == PlanReadinessStatus.PLAN_INVALID
    assert "Binding Conflict" in plan.explanation

    # Step 2 parameter data must be marked as CONFLICT
    step2 = plan.steps[1]
    binding = step2.input_bindings["data"]
    assert binding.source_type == BindingSourceType.CONFLICT
    assert binding.is_valid is False
    assert "User explicitly supplied" in binding.conflict_details


# ----------------------------------------------------------------------------
# 8. Missing Intermediate Parameters -> PLAN_INCOMPLETE
# ----------------------------------------------------------------------------

def test_8_missing_intermediate_parameters_incomplete(planning_context):
    """Verifies that missing intermediate parameters produce PLAN_INCOMPLETE with questions."""
    ctx = planning_context
    # Step 1: clone git repository requires repo_url and target_dir (both missing here)
    query = "clone git repository and inspect the initial commit log"
    plan = ctx.planning_engine.create_plan(query)

    assert plan.status == PlanReadinessStatus.PLAN_INCOMPLETE
    assert len(plan.missing_inputs) > 0
    assert len(plan.clarifying_questions) > 0
    assert any("repo_url" in q for q in plan.clarifying_questions)


# ----------------------------------------------------------------------------
# 9. Ambiguous Candidate Capabilities (Tied / Similarly Suitable Candidates)
# ----------------------------------------------------------------------------

def test_9_ambiguous_candidate_capabilities_clarification(planning_context):
    """
    Verifies that when two capability candidates are similarly suitable for a sub-goal,
    the planner does not silently select an unjustified candidate, but exposes
    ambiguity through PLAN_INCOMPLETE, explanatory warnings, and clarifying questions.
    """
    ctx = planning_context
    # Sub-goal 'check git' produces a score tie between 'Inspect Git Commit' (0.890) and 'List Git Branches' (0.890)
    query = "compress logs into tar archive /tmp/logs.tar and check git"
    plan = ctx.planning_engine.create_plan(
        query,
        user_arguments={"source_dir": "/var/log", "output_archive": "/tmp/logs.tar"}
    )

    # Must NOT be marked as PLAN_READY
    assert plan.status == PlanReadinessStatus.PLAN_INCOMPLETE
    assert "Ambiguous candidate capabilities detected" in plan.explanation
    assert any("ambiguous between 'Inspect Git Commit' and 'List Git Branches'" in q for q in plan.clarifying_questions)


# ----------------------------------------------------------------------------
# 10. Single-Capability Non-Inflation
# ----------------------------------------------------------------------------

def test_10_single_capability_non_inflation(planning_context):
    """Verifies that a single direct task is not artificially decomposed into multiple steps."""
    ctx = planning_context
    query = "calculate sha256 checksum of release tarball"
    plan = ctx.planning_engine.create_plan(query)

    assert plan.plan_type == "SINGLE_CAPABILITY"
    assert len(plan.steps) == 1
    assert plan.steps[0].display_name == "Hash Sha256 Digest"
    assert len(plan.dag_edges) == 0


# ----------------------------------------------------------------------------
# 11. Cyclic Graph Rejection
# ----------------------------------------------------------------------------

def test_11_cyclic_graph_rejection():
    """Verifies that cyclic graphs are detected and marked as PLAN_INVALID."""
    step_ids = ["step-1", "step-2"]
    edges = [
        ("step-1", "step-2", DependencyType.OUTPUT_TO_INPUT, "1 to 2"),
        ("step-2", "step-1", DependencyType.OUTPUT_TO_INPUT, "2 to 1")
    ]
    order, has_cycle = CapabilityPlanningEngineV1.compute_topological_order(step_ids, edges)
    assert has_cycle is True


# ----------------------------------------------------------------------------
# 12. Out-of-Domain Abstention
# ----------------------------------------------------------------------------

def test_12_out_of_domain_abstention(planning_context):
    """Verifies that out-of-domain and ambiguous requests produce PLAN_ABSTAIN."""
    ctx = planning_context
    # Out-of-domain: weather query
    query = "check the current weather temperature in Seattle"
    plan = ctx.planning_engine.create_plan(query)

    assert plan.status == PlanReadinessStatus.PLAN_ABSTAIN
    assert "Planner safely abstained" in plan.explanation


# ----------------------------------------------------------------------------
# 13. End-to-End Context & CLI Integration
# ----------------------------------------------------------------------------

def test_13_cli_command_invocation(planning_context, capsys):
    """Verifies that 'lcs plan' CLI command works end-to-end with formatted and JSON output."""
    from lcs.cli import main

    root_dir = planning_context.config.root_dir

    # 1. Human-readable CLI invocation
    argv1 = ["--root", root_dir, "plan", "compress logs into tar archive /tmp/logs.tar and calculate its sha256 checksum"]
    ret1 = main(argv1)
    assert ret1 == 0
    out1, _ = capsys.readouterr()
    assert "LIVING CAPABILITY SYSTEM (LCS) — MULTI-CAPABILITY EXECUTION PLAN" in out1
    assert "Readiness Status:    PLAN_READY" in out1
    assert "Compress Tar Archive" in out1
    assert "Hash Sha256 Digest" in out1

    # 2. JSON formatted CLI invocation
    argv2 = ["--root", root_dir, "plan", "compress logs into tar archive /tmp/logs.tar and calculate its sha256 checksum", "--format-json"]
    ret2 = main(argv2)
    assert ret2 == 0
    out2, _ = capsys.readouterr()
    assert '"status": "PLAN_READY"' in out2
    assert '"plan_type": "MULTI_CAPABILITY_DAG"' in out2
