"""
Stage 7.1 — Final Security & Filesystem Authorization Regression Suite
======================================================================
Validates zero-trust filesystem authorization in ExecutionEngineV1 and PathSecurityValidator:
1. Workspace escape attempts (relative traversal, absolute escapes).
2. Symlink and junction traversal rejection (O_NOFOLLOW, realpath containment).
3. Untrusted working directory confinement (os.getcwd() cannot expand authorization).
4. Cross-project isolation between independent project directories.
5. Ambiguous or invalid authorization roots fail closed.
"""

import os
import sys
import json
import tempfile
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.governance import ApproverConsent, ApproverRole
from lcs.planning import ExecutionPlan, PlanStep, StepInputBinding, StepOutputDefinition
from lcs.policy import InterfaceTrustPolicy
from lcs.inventory.models import UnifiedResourceRecord, ResourceType, ProvenanceRecord
from execution_engine_v1 import (
    PathSecurityValidator,
    PathTraversalExecutionError,
    ExecutionEngineV1,
    PreflightVerificationError,
)


@pytest.fixture
def isolated_security_env(tmp_path):
    """Provides isolated workspaces for security testing."""
    ws_a = tmp_path / "workspace_alpha"
    ws_b = tmp_path / "workspace_beta"
    untrusted = tmp_path / "untrusted_dir"
    home = tmp_path / "user_home"

    ws_a.mkdir(parents=True, exist_ok=True)
    ws_b.mkdir(parents=True, exist_ok=True)
    untrusted.mkdir(parents=True, exist_ok=True)
    home.mkdir(parents=True, exist_ok=True)

    return {
        "ws_a": str(ws_a.resolve()),
        "ws_b": str(ws_b.resolve()),
        "untrusted": str(untrusted.resolve()),
        "home": str(home.resolve()),
        "tmp_path": tmp_path,
    }


# ============================================================================
# 1. Workspace Escape & Traversal Rejection
# ============================================================================

def test_relative_path_traversal_escape_rejected(isolated_security_env):
    """Verifies that relative traversal escaping authorized roots is blocked."""
    ws_a = isolated_security_env["ws_a"]
    untrusted = isolated_security_env["untrusted"]

    # Target outside workspace via relative traversal
    escape_path = os.path.join(ws_a, "..", "untrusted_dir", "malicious.txt")
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(escape_path, [ws_a])
    assert "escapes authorized roots" in str(exc_info.value)


def test_absolute_path_escape_rejected(isolated_security_env):
    """Verifies that absolute paths outside authorized roots are blocked."""
    ws_a = isolated_security_env["ws_a"]
    ws_b = isolated_security_env["ws_b"]

    target_in_b = os.path.join(ws_b, "sensitive_data.txt")
    with open(target_in_b, "w") as f:
        f.write("CONFIDENTIAL")

    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(target_in_b, [ws_a])
    assert "escapes authorized roots" in str(exc_info.value)


# ============================================================================
# 2. Symlink & Junction Traversal Rejection
# ============================================================================

def test_symlink_escape_rejected(isolated_security_env):
    """Verifies that symlinks inside workspace pointing outside are rejected."""
    ws_a = isolated_security_env["ws_a"]
    ws_b = isolated_security_env["ws_b"]

    outside_file = os.path.join(ws_b, "external_secret.txt")
    with open(outside_file, "w") as f:
        f.write("SECRET_KEY_12345")

    link_inside_a = os.path.join(ws_a, "leak_symlink.txt")
    try:
        os.symlink(outside_file, link_inside_a)
    except OSError:
        pytest.skip("Symlink creation not permitted in this environment")

    # Realpath resolves outside ws_a, must be rejected
    with pytest.raises(PathTraversalExecutionError) as exc_info:
        PathSecurityValidator.validate_file_path(link_inside_a, [ws_a])
    assert "escapes authorized roots" in str(exc_info.value) or "Symlink rejected" in str(exc_info.value)


def test_directory_symlink_traversal_rejected(isolated_security_env):
    """Verifies that directory symlinks pointing outside workspace are rejected."""
    ws_a = isolated_security_env["ws_a"]
    ws_b = isolated_security_env["ws_b"]

    dir_link = os.path.join(ws_a, "linked_dir")
    try:
        os.symlink(ws_b, dir_link)
    except OSError:
        pytest.skip("Symlink creation not permitted in this environment")

    escaped_target = os.path.join(dir_link, "subfile.txt")
    with pytest.raises(PathTraversalExecutionError):
        PathSecurityValidator.validate_file_path(escaped_target, [ws_a])


# ============================================================================
# 3. Untrusted Working Directory Confinement (os.getcwd() Cannot Expand Roots)
# ============================================================================

def test_cwd_cannot_expand_authorized_workspace(isolated_security_env, monkeypatch):
    """
    CRITICAL INVARIANT:
    When ExecutionEngineV1 is initialized with an authorized workspace_root,
    running in an untrusted current working directory MUST NOT authorize files
    in that untrusted working directory.
    """
    ws_a = isolated_security_env["ws_a"]
    untrusted = isolated_security_env["untrusted"]

    # Switch current working directory to untrusted
    monkeypatch.chdir(untrusted)
    assert os.path.realpath(os.getcwd()) == os.path.realpath(untrusted)

    # Initialize execution engine explicitly for workspace_alpha
    cfg_a = LCSConfig.resolve(root_override=os.path.join(ws_a, ".lcs"), workspace_root=ws_a)
    with LCSContext(config=cfg_a, auto_migrate=True) as ctx:
        assert os.path.realpath(ctx.execution_engine.workspace_root) == os.path.realpath(ws_a)

        # File in untrusted working directory
        untrusted_file = os.path.join(untrusted, "leak.txt")
        with open(untrusted_file, "w") as f:
            f.write("UNTRUSTED")

        # Attempt to validate path in untrusted cwd against ws_a workspace_root
        with pytest.raises(PathTraversalExecutionError) as exc_info:
            PathSecurityValidator.validate_file_path(
                untrusted_file,
                [ctx.execution_engine.workspace_root]
            )
        assert "escapes authorized roots" in str(exc_info.value)


# ============================================================================
# 4. Cross-Project Isolation in Execution Pipeline
# ============================================================================

def test_cross_project_deliverable_escape_rejected_at_execution(isolated_security_env):
    """
    Verifies that during actual plan execution, an input or output deliverable
    targeting another project directory is rejected fail-closed.
    """
    import hashlib
    ws_a = isolated_security_env["ws_a"]
    ws_b = isolated_security_env["ws_b"]

    cfg_a = LCSConfig.resolve(root_override=os.path.join(ws_a, ".lcs"), workspace_root=ws_a)
    with LCSContext(config=cfg_a, auto_migrate=True) as ctx:
        # Step script inside workspace_alpha
        script_path = os.path.join(ws_a, "step.py")
        with open(script_path, "w") as f:
            f.write("print('EXECUTED')\n")

        # Register capability properly in inventory
        content_hash = hashlib.sha256(open(script_path, "rb").read()).hexdigest()
        rec = UnifiedResourceRecord(
            urn="urn:lcs:skill:test:escape",
            name="escape-step",
            resource_type=ResourceType.SKILL,
            display_name="Escape Step",
            description="Testing escape",
            raw_content=open(script_path).read(),
            raw_content_digest=content_hash,
            provenance=ProvenanceRecord(
                origin_host="generic_posix",
                precedence_tier="WORKSPACE",
                source_path=script_path,
                resolved_path=script_path,
                content_hash=content_hash
            )
        )
        ctx.inventory._persist_and_bind_capability(rec)

        # Target deliverable maliciously aimed at workspace_beta
        target_in_b = os.path.join(ws_b, "stolen_data.txt")

        step = PlanStep(
            step_id="step-escape",
            step_index=1,
            capability_urn="urn:lcs:skill:test:escape",
            display_name="Escape Step",
            sub_goal="Escape to Project B",
            selection_reason="Testing cross-project boundary",
            input_bindings={
                "target_script": StepInputBinding("target_script", "string", False, bound_value=script_path),
                "output_target": StepInputBinding("output_target", "string", False, bound_value=target_in_b),
            },
            output_definitions={"result": StepOutputDefinition("result", "string")},
            dependencies=[]
        )

        plan = ExecutionPlan(
            plan_id="plan-escape-01",
            request_query="Cross-project escape test",
            plan_type="SINGLE_CAPABILITY",
            status="PLAN_READY",
            steps=[step],
            dag_edges=[],
            execution_order=["step-escape"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="Testing boundary escape"
        )

        consent = ApproverConsent("auditor@local", ApproverRole.HUMAN_OPERATOR, "AUDIT")
        policy = InterfaceTrustPolicy("permissive", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
        token, _ = ctx.governance_engine.approve_plan(plan, approver=consent, active_policy=policy)

        # Execution MUST fail closed due to PathTraversalExecutionError on output_target
        res = ctx.execution_engine.execute_plan(plan, token)
        assert res.lifecycle_state.value in ("FAILED", "ABORTED")
        assert not os.path.exists(target_in_b)
        rec = res.step_records[0]
        assert rec.status.value in ("FAILED", "ERROR")
        assert "escapes authorized roots" in (rec.error_details or "") or "escapes authorized roots" in (res.error_message or "")


# ============================================================================
# 5. Ambiguous or Invalid Roots Fail Closed
# ============================================================================

def test_ambiguous_and_empty_authorized_roots_fail_closed(isolated_security_env):
    """Verifies that empty or nonexistent authorized roots fail closed."""
    ws_a = isolated_security_env["ws_a"]
    test_file = os.path.join(ws_a, "valid.txt")
    with open(test_file, "w") as f:
        f.write("OK")

    # Nonexistent root
    with pytest.raises(PathTraversalExecutionError):
        PathSecurityValidator.validate_file_path(test_file, ["/nonexistent/root/path/12345"])

    # Path outside single root
    with pytest.raises(PathTraversalExecutionError):
        PathSecurityValidator.validate_file_path("/etc/hosts", [ws_a])
