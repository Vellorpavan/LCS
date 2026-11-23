"""
LCS Phase 2B Capability Utilization & Execution Readiness Acceptance Test Suite
==============================================================================
Validates:
1. Complete, provenance-preserving instruction hydration (no AI summaries)
2. Auxiliary asset loading (scripts, templates, references)
3. Dependency graph construction and deterministic topological resolution
4. Circular dependency detection (CircularDependencyError)
5. Missing dependency handling (mandatory fail-closed vs optional warning)
6. Merkle bundle invalidation upon leaf file modification
7. Hash-On-Activation fail-closed on tampered root or auxiliary leaf
8. Resource-specific multi-tier verification gates:
   - Skills (completeness, frontmatter)
   - Scripts (exit code 0, stderr audit, declared output files)
   - MCP tools (JSON-RPC 2.0, isError False, CAS trace)
   - Subagents (terminal state, transcript audit, deliverables)
   - Templates (placeholders, rendered output)
9. Antigravity subagent bridge:
   - Governed dispatch, parent-child ID tracking, deliverable verification
   - Missing deliverable failure
   - Feature flag gating & unsupported environment honesty
10. Governance preservation: Preparation does not execute without Gate 2 EAT token
"""

import os
import json
import time
import shutil
import tempfile
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.hydration import (
    HydrationEngine,
    HydrationError,
    ResourceUtilizationState,
)
from lcs.dependencies import (
    ResourceType,
    DependencyType,
    DependencyNode,
    DependencyGraph,
    DependencyResolver,
    CircularDependencyError,
    MissingDependencyError,
)
from lcs.verification import (
    VerificationState,
    EvidenceTier,
    UnifiedResourceVerifier,
)
from lcs.subagents import (
    AntigravitySubagentBridge,
    SubagentTask,
    SubagentTaskState,
    UnsupportedSubagentEnvironmentError,
)
from lcs.interface.contract import TaskRequest
from lcs.adapters import ContentIntegrityMismatchError


@pytest.fixture
def utilization_env(monkeypatch):
    """Sets up an isolated LCSContext in a real temporary workspace."""
    monkeypatch.setenv("ANTIGRAVITY_AGENT", "1")
    raw_dir = tempfile.mkdtemp(prefix="lcs_utilization_test_")
    real_dir = os.path.realpath(raw_dir)

    cfg = LCSConfig.resolve(root_override=real_dir)
    ctx = LCSContext(config=cfg, auto_migrate=True)

    # Strictly isolate discovery roots
    ctx.skill_service.resolver.user_home = real_dir
    ctx.skill_service.resolver.workspace_root = real_dir
    ctx.skill_service.set_resolver(ctx.skill_service.resolver)
    ctx.cache.resolver = ctx.skill_service.resolver
    ctx.cache.delta_engine.resolver = ctx.skill_service.resolver
    ctx.fs_watcher.resolver = ctx.skill_service.resolver

    yield ctx, real_dir

    ctx.close()
    shutil.rmtree(real_dir, ignore_errors=True)


def test_01_complete_instruction_hydration_with_provenance(utilization_env):
    """
    Verifies that capability hydration retrieves the complete raw instructions from CAS/disk,
    loads auxiliary assets, preserves provenance, and NEVER substitutes AI summaries.
    """
    ctx, ws = utilization_env

    # 1. Create a bundle skill with auxiliary files
    skill_dir = os.path.join(ws, ".agents", "skills", "deployer")
    os.makedirs(os.path.join(skill_dir, "scripts"), exist_ok=True)
    os.makedirs(os.path.join(skill_dir, "templates"), exist_ok=True)

    instruction_text = """---
name: deployer
description: Staging deployment orchestration skill
dependencies:
  - helper_tool
---
# Deployer Playbook
Execute deployment using [script](scripts/deploy.py) and [template](templates/config.j2).
"""
    with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8", newline="") as f:
        f.write(instruction_text)

    with open(os.path.join(skill_dir, "scripts", "deploy.py"), "w", encoding="utf-8") as f:
        f.write("print('Deploying cluster...')\n")

    with open(os.path.join(skill_dir, "templates", "config.j2"), "w", encoding="utf-8") as f:
        f.write("cluster_name: {{ cluster_name }}\n")

    # 2. Run discovery & indexing
    records = ctx.skill_service.run_full_pipeline()
    assert len(records) >= 1
    urn = records[0].canonical_urn

    # 3. Hydrate capability
    hydrated = ctx.hydration_engine.hydrate_capability(urn)

    assert hydrated.capability_urn == urn
    assert hydrated.name == "deployer"
    assert hydrated.raw_instructions == instruction_text
    assert not hydrated.raw_instructions.startswith("[AI Generated Summary]")
    assert hydrated.instruction_digest == records[0].raw_content_digest
    assert hydrated.is_bundle is True

    # Verify auxiliary files loaded
    assert "scripts/deploy.py" in hydrated.auxiliary_files
    assert "templates/config.j2" in hydrated.auxiliary_files
    aux_script = hydrated.get_auxiliary_file("scripts/deploy.py")
    assert aux_script is not None
    assert "print('Deploying cluster...')" in aux_script.content_text

    # Verify provenance
    assert hydrated.provenance["origin_environment"].lower() == "antigravity"
    assert hydrated.provenance["raw_byte_length"] == len(instruction_text.encode("utf-8"))


def test_02_dependency_graph_and_deterministic_topological_resolution():
    """
    Verifies that DependencyGraph resolves dependencies in deterministic topological order
    (dependencies execute before dependents) with lexicographical tie-breaking.
    """
    graph = DependencyGraph()

    # Define nodes: A depends on B and C; B depends on D; C depends on D
    graph.add_node(DependencyNode(resource_id="A", resource_type=ResourceType.SKILL))
    graph.add_node(DependencyNode(resource_id="B", resource_type=ResourceType.SCRIPT))
    graph.add_node(DependencyNode(resource_id="C", resource_type=ResourceType.TEMPLATE))
    graph.add_node(DependencyNode(resource_id="D", resource_type=ResourceType.MCP_TOOL))

    graph.add_dependency("A", "B", DependencyType.MANDATORY)
    graph.add_dependency("A", "C", DependencyType.MANDATORY)
    graph.add_dependency("B", "D", DependencyType.MANDATORY)
    graph.add_dependency("C", "D", DependencyType.MANDATORY)

    order = graph.resolve_order()

    # D has 0 dependencies -> must run first
    # B and C depend only on D -> run next in deterministic sorted order: B, then C
    # A depends on B and C -> must run last
    assert order == ["D", "B", "C", "A"]


def test_03_circular_dependency_detection_fails_closed():
    """
    Verifies that circular dependencies (A -> B -> C -> A) are detected and fail closed.
    """
    graph = DependencyGraph()
    graph.add_node(DependencyNode(resource_id="node_a", resource_type=ResourceType.SKILL))
    graph.add_node(DependencyNode(resource_id="node_b", resource_type=ResourceType.SKILL))
    graph.add_node(DependencyNode(resource_id="node_c", resource_type=ResourceType.SKILL))

    graph.add_dependency("node_a", "node_b", DependencyType.MANDATORY)
    graph.add_dependency("node_b", "node_c", DependencyType.MANDATORY)
    graph.add_dependency("node_c", "node_a", DependencyType.MANDATORY)

    with pytest.raises(CircularDependencyError) as exc_info:
        graph.resolve_order()

    assert "Circular dependency cycle detected" in str(exc_info.value)
    assert "node_a" in str(exc_info.value)
    assert "node_b" in str(exc_info.value)


def test_04_missing_dependencies_mandatory_vs_optional():
    """
    Verifies that missing mandatory dependencies fail closed with MissingDependencyError,
    while missing optional dependencies do not prevent validation.
    """
    graph = DependencyGraph()
    graph.add_node(DependencyNode(resource_id="root_task", resource_type=ResourceType.WORKFLOW))

    # Mandatory dependency on missing resource
    graph.add_dependency("root_task", "missing_mandatory_tool", DependencyType.MANDATORY)

    with pytest.raises(MissingDependencyError) as exc_info:
        graph.resolve_order()
    assert "missing_mandatory_tool" in str(exc_info.value)

    # Now replace with optional dependency
    graph2 = DependencyGraph()
    graph2.add_node(DependencyNode(resource_id="root_task", resource_type=ResourceType.WORKFLOW))
    graph2.add_dependency("root_task", "missing_optional_telemetry", DependencyType.OPTIONAL)

    # Optional missing dependency allows validation to pass
    graph2.validate()
    # Topological order of registered nodes succeeds
    assert graph2.resolve_order() == ["root_task"]


def test_05_merkle_bundle_invalidation_upon_leaf_modification(utilization_env):
    """
    Verifies that modifying an auxiliary leaf file inside a bundle alters its Merkle
    manifest digest and causes Hash-On-Activation to fail closed.
    """
    ctx, ws = utilization_env

    # 1. Create a bundle skill
    skill_dir = os.path.join(ws, ".agents", "skills", "builder")
    os.makedirs(os.path.join(skill_dir, "scripts"), exist_ok=True)

    with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8", newline="") as f:
        f.write("# Builder Skill\nRuns build script.\n")

    script_path = os.path.join(skill_dir, "scripts", "build.sh")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write("#!/bin/bash\necho 'Compiling...'\n")

    # 2. Index bundle
    records = ctx.skill_service.run_full_pipeline()
    assert len(records) >= 1
    urn = records[0].canonical_urn
    initial_bundle_digest = records[0].bundle_manifest_digest
    assert initial_bundle_digest is not None

    # 3. Activation check passes
    status = ctx.activation_verifier.verify_capability_activation(urn)
    assert status.actual_digest == initial_bundle_digest

    # 4. Modify leaf script file on disk
    time.sleep(0.02)
    with open(script_path, "w", encoding="utf-8") as f:
        f.write("#!/bin/bash\necho 'MALICIOUS MODIFICATION'\n")

    # 5. Activation check MUST fail closed with ContentIntegrityMismatchError
    with pytest.raises(ContentIntegrityMismatchError):
        ctx.activation_verifier.verify_capability_activation(urn)


def test_06_skill_verification_gate():
    """Verifies Skill multi-tier verification gate."""
    verifier = UnifiedResourceVerifier()

    # Pass: Complete hydrated capability
    mock_cap = type("MockCap", (), {
        "capability_urn": "urn:lcs:skill:test:alpha",
        "instruction_digest": "a" * 64,
        "raw_instructions": "# Alpha Skill\nComplete instructions without summary.",
        "missing_dependencies": []
    })()

    res_pass = verifier.verify_resource("SKILL", {"hydrated_capability": mock_cap})
    assert res_pass.is_verified is True
    assert res_pass.state == VerificationState.VERIFIED

    # Fail: Missing mandatory dependency
    mock_cap_fail = type("MockCap", (), {
        "capability_urn": "urn:lcs:skill:test:broken",
        "instruction_digest": "b" * 64,
        "raw_instructions": "# Broken Skill",
        "missing_dependencies": ["mandatory_db_tool"]
    })()

    res_fail = verifier.verify_resource("SKILL", {"hydrated_capability": mock_cap_fail})
    assert res_fail.is_verified is False
    assert res_fail.state == VerificationState.FAILED
    assert "mandatory_db_tool" in res_fail.error_details


def test_07_script_verification_gate(tmp_path):
    """
    Verifies Script multi-tier verification:
    - Fails if exit_code != 0
    - Fails if fatal exception in stderr despite exit code 0
    - Fails if declared output file is missing or empty
    - Passes only when all tiers succeed
    """
    verifier = UnifiedResourceVerifier()
    script_file = tmp_path / "run.py"
    script_file.write_text("print('ok')")

    out_file = tmp_path / "result.json"
    out_file.write_text('{"status": "ok"}')

    # Case 1: Pass
    res_pass = verifier.verify_resource("SCRIPT", {
        "resource_id": "script-1",
        "script_path": str(script_file),
        "exit_code": 0,
        "stderr": "",
        "declared_output_files": [str(out_file)]
    })
    assert res_pass.is_verified is True

    # Case 2: Fail on non-zero exit code
    res_exit_fail = verifier.verify_resource("SCRIPT", {
        "resource_id": "script-2",
        "script_path": str(script_file),
        "exit_code": 1,
        "stderr": "General error"
    })
    assert res_exit_fail.is_verified is False

    # Case 3: 'Exit 0 Fallacy' - exits 0 but stderr has fatal traceback
    res_traceback_fail = verifier.verify_resource("SCRIPT", {
        "resource_id": "script-3",
        "script_path": str(script_file),
        "exit_code": 0,
        "stderr": "Traceback (most recent call last):\n  File 'x.py', line 1\nZeroDivisionError: division by zero",
        "declared_output_files": [str(out_file)]
    })
    assert res_traceback_fail.is_verified is False
    assert "Stderr clean of fatal tracebacks" in res_traceback_fail.error_details

    # Case 4: Declared output file missing
    res_missing_out = verifier.verify_resource("SCRIPT", {
        "resource_id": "script-4",
        "script_path": str(script_file),
        "exit_code": 0,
        "stderr": "",
        "declared_output_files": [str(tmp_path / "nonexistent.json")]
    })
    assert res_missing_out.is_verified is False


def test_08_mcp_tool_verification_gate():
    """
    Verifies MCP Tool verification gate:
    - Protocol JSON-RPC 2.0 success
    - isError == False
    - CAS trace recorded
    - Required schema keys satisfied
    """
    verifier = UnifiedResourceVerifier()

    # Case 1: Pass
    res_pass = verifier.verify_resource("MCP_TOOL", {
        "resource_id": "tool-read",
        "tool_response": {"content": [{"type": "text", "text": "File data"}], "isError": False},
        "cas_trace_digest": "c" * 64,
        "required_output_keys": ["content"]
    })
    assert res_pass.is_verified is True
    assert res_pass.cas_trace_digest == "c" * 64

    # Case 2: Fail on isError: True inside 200 wrapper
    res_err_flag = verifier.verify_resource("MCP_TOOL", {
        "resource_id": "tool-rate-limit",
        "tool_response": {"isError": True, "error": "Rate limit exceeded"},
        "cas_trace_digest": "c" * 64
    })
    assert res_err_flag.is_verified is False
    assert "isError flag is false" in res_err_flag.error_details

    # Case 3: Fail on missing CAS trace digest
    res_no_cas = verifier.verify_resource("MCP_TOOL", {
        "resource_id": "tool-no-cas",
        "tool_response": {"content": "ok", "isError": False},
        "cas_trace_digest": None
    })
    assert res_no_cas.is_verified is False


def test_09_template_verification_gate():
    """Verifies Template multi-tier verification gate."""
    verifier = UnifiedResourceVerifier()

    # Pass: Rendered text clean
    res_pass = verifier.verify_resource("TEMPLATE", {
        "resource_id": "tmpl-1",
        "rendered_text": "cluster_name: prod-east-1\nreplicas: 3\n"
    })
    assert res_pass.is_verified is True

    # Fail: Unrendered {{ placeholder }} remains in output
    res_fail = verifier.verify_resource("TEMPLATE", {
        "resource_id": "tmpl-2",
        "rendered_text": "cluster_name: {{ cluster_name }}\nreplicas: 3\n"
    })
    assert res_fail.is_verified is False
    assert "Zero unrendered template placeholders" in res_fail.error_details


def test_10_antigravity_subagent_bridge_governed_delegation(utilization_env):
    """
    Verifies Antigravity subagent bridge:
    - Structured task dispatch with parent and child IDs
    - Delivery of declared deliverables
    - Verification of child results
    """
    ctx, ws = utilization_env

    bridge = AntigravitySubagentBridge(ctx, feature_flag=True)
    task = bridge.create_task(
        parent_request_id="req-root-123",
        role="Code Auditor",
        objective="Inspect code for security vulnerabilities",
        expected_deliverables=["audit_report.json"]
    )

    assert task.parent_request_id == "req-root-123"
    assert task.child_task_id.startswith("subtask-")

    # Mock successful execution function producing expected deliverables
    def mock_executor(subtask):
        return {
            "deliverables": {"audit_report.json": {"vulnerabilities_found": 0}},
            "stdout": "Audited 12 files without vulnerabilities."
        }

    result = bridge.dispatch_task(task, executor_fn=mock_executor)

    assert result.state == SubagentTaskState.COMPLETED
    assert result.is_verified is True
    assert "audit_report.json" in result.deliverables
    assert result.parent_request_id == "req-root-123"


def test_11_antigravity_subagent_bridge_fails_on_missing_deliverable(utilization_env):
    """
    Verifies that if a child subagent finishes but does not produce the declared deliverable,
    the bridge marks the execution FAILED.
    """
    ctx, ws = utilization_env

    bridge = AntigravitySubagentBridge(ctx, feature_flag=True)
    task = bridge.create_task(
        parent_request_id="req-root-456",
        role="Build Worker",
        objective="Compile binary",
        expected_deliverables=["dist/app.bin"]
    )

    def mock_failing_executor(subtask):
        # Exits without declared deliverable
        return {"deliverables": {}, "stdout": "Compilation completed but output missing."}

    result = bridge.dispatch_task(task, executor_fn=mock_failing_executor)

    assert result.state == SubagentTaskState.FAILED
    assert result.is_verified is False
    assert "Missing declared deliverables" in result.error_details


def test_12_subagent_bridge_unsupported_environment_honesty(utilization_env):
    """
    Verifies that when delegation is attempted on an environment lacking AGENT_DELEGATION,
    or with feature flag disabled, it fails safely and reports honestly.
    """
    ctx, ws = utilization_env

    # 1. Feature flag disabled
    disabled_bridge = AntigravitySubagentBridge(ctx, feature_flag=False)
    task = disabled_bridge.create_task(
        parent_request_id="req-root-789",
        role="Worker",
        objective="Test delegation"
    )

    res = disabled_bridge.dispatch_task(task)
    assert res.state == SubagentTaskState.FAILED
    assert res.is_verified is False
    assert "does not support subagent delegation" in res.error_details


def test_13_core_bridge_execution_readiness_pipeline(utilization_env):
    """
    Verifies the end-to-end Phase 2B capability utilization pipeline in LCSCoreBridge:
    - Discovery -> Deep Hydration -> Dependency Resolution -> Hash-On-Activation -> Execution Preparation
    - Invariant: Zero unapproved execution runs created prior to Gate 2.
    """
    ctx, ws = utilization_env

    # 1. Create a skill
    skill_dir = os.path.join(ws, ".agents", "skills", "validator")
    os.makedirs(skill_dir, exist_ok=True)
    with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8", newline="") as f:
        f.write("# Validator Skill\nValidates system health.\n")

    records = ctx.skill_service.run_full_pipeline()
    assert len(records) >= 1
    urn = records[0].canonical_urn

    # 2. Prepare execution plan via core bridge
    req = TaskRequest.create(raw_instruction="Validate system health", environment="ANTIGRAVITY")
    plan = ctx.call_me.bridge.prepare_execution_plan(req, [urn])

    assert plan["request_id"] == req.request_id
    assert plan["governance_status"] == "PREPARED_PENDING_GATE_2"
    assert plan["hydrated_count"] == 1
    assert plan["verified_integrity_count"] == 1
    assert urn in plan["execution_order"]

    # 3. Invariant check: Execution engine has ZERO runs (no un-governed execution)
    assert ctx.execution_engine.list_runs() == []
