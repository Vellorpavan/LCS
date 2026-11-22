"""
Test Suite for LCS Stage 2B — Execution Governance V1
=====================================================
Verifies all 14 architectural verification areas defined in the approved specification:
  1. Gate 1 Policy Rejection (unverified or policy-denied capability blocked)
  2. Dual-Gate Enforcement (user consent cannot bypass Gate 1; approver denial rejected)
  3. Dual-Gate Success (verified policy + explicit consent issues valid EAT)
  4. Plan Integrity Hashing (single-bit plan tampering invalidates token)
  5. Deterministic RFC 8785 JCS Canonicalization (verifies test vectors & byte reproducibility)
  6. Token Verification, Atomic Consumption & Single-Use DispatchPermit
  7. Token TTL Expiration (expired token transitions to TOKEN_EXPIRED)
  8. Trust Freshness Revalidation, Policy Revision Drift & Storage Topology
  9. Filesystem Path Confinement & Traversal Defense
 10. Network Origin Gating & SSRF Defense
 11. Step Quota Ceiling (exceeding max_steps rejected)
 12. Irreversible Action Gating & Warnings
 13. Hash-Chained Append-Only Audit Ledger, Preimage Integrity & Crash Recovery
 14. Zero-Execution Invariant (zero tool calls, zero subprocesses, zero network calls)
 15. Concurrency & Cross-Connection Serialization
 16. CLI 'lcs approve' and 'lcs audit-log verify' End-to-End Commands
"""

import os
import sys
import json
import time
import uuid
import hmac
import hashlib
import sqlite3
import tempfile
import threading
from unittest.mock import patch
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.policy import InterfaceTrustPolicy
from lcs.governance import (
    canonicalize_jcs,
    compute_plan_integrity_hash,
    extract_canonical_plan_payload,
    GovernanceStatus,
    ApproverRole,
    ApproverConsent,
    PolicyRevision,
    ExecutionAuthorizationToken,
    DispatchPermit,
    GovernanceEvaluationResult,
    GovernanceError,
    GovernanceBlockedError,
    GovernanceRejectedError,
    PlanIntegrityTamperedError,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    TokenRevokedError,
    DispatchPermitAlreadyUsedError,
    DispatchPermitExpiredError,
    DispatchPermitInvalidError,
    PolicyRevisionMismatchError,
    AttestationRevokedError,
    PermissionViolationError,
    UnsupportedStorageTopologyError,
    AuditChainIntegrityError,
    AuditLogTailTruncatedError,
    AuditDirectorySyncError,
    ensure_governance_schema,
    check_storage_topology,
    get_current_policy_revision,
    increment_policy_revision,
    evaluate_resource_boundaries,
    GovernanceAuditLedger,
    ExecutionGovernanceEngineV1
)
from capability_planning_v1 import (
    ExecutionPlan,
    PlanStep,
    StepInputBinding,
    StepOutputDefinition
)


PROJ_ROOT = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module")
def governance_fixture():
    """Populates an LCSContext with realistic discovered capabilities for testing."""
    with tempfile.TemporaryDirectory() as td:
        root_dir = os.path.realpath(td)
        cfg = LCSConfig.resolve(root_override=root_dir)
        ctx = LCSContext(cfg)

        policy = InterfaceTrustPolicy(
            policy_name="production-strict-v2",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        servers = [
            ("git-vcs", "evaluation_fixtures/git_vcs_server.py"),
            ("system-devops", "evaluation_fixtures/system_devops_server.py"),
            ("crypto-security", "evaluation_fixtures/crypto_security_server.py")
        ]

        for srv_name, rel_path in servers:
            full_path = os.path.join(PROJ_ROOT, rel_path)
            ctx.discovery_pipeline.discover_and_register_mcp_server(
                command=[sys.executable, full_path],
                server_name=srv_name,
                trust_policy=policy
            )

        yield ctx
        ctx.close()


def _create_sample_plan(plan_id="plan-sample-01", query="compress logs and calculate sha256"):
    step1 = PlanStep(
        step_id="step-1",
        step_index=1,
        capability_urn="urn:lcs:tool:mcp.system-devops:compress-tar-archive",
        display_name="Compress Tar Archive",
        sub_goal="compress logs",
        selection_reason="matches compression",
        input_bindings={
            "compression": StepInputBinding("compression", "string", False, "SCHEMA_DEFAULT", bound_value="gz"),
            "output_archive": StepInputBinding("output_archive", "string", True, "USER_SUPPLIED", bound_value="/tmp/logs.tar"),
            "source_dir": StepInputBinding("source_dir", "string", True, "USER_SUPPLIED", bound_value="/tmp/logs")
        },
        output_definitions={
            "archive_path": StepOutputDefinition("archive_path", "string", "DOCUMENTED")
        },
        readiness="READY"
    )
    step2 = PlanStep(
        step_id="step-2",
        step_index=2,
        capability_urn="urn:lcs:tool:mcp.crypto-security:hash-sha256-digest",
        display_name="Hash Sha256 Digest",
        sub_goal="calculate sha256",
        selection_reason="matches hashing",
        input_bindings={
            "data": StepInputBinding("data", "string", True, "STEP_OUTPUT", source_step_id="step-1", source_output_field="archive_path", bound_value="${step-1.archive_path}")
        },
        output_definitions={
            "sha256_hash": StepOutputDefinition("sha256_hash", "string", "DOCUMENTED")
        },
        dependencies=["step-1"],
        dependency_types={"step-1": "OUTPUT_TO_INPUT"},
        readiness="READY"
    )
    return ExecutionPlan(
        plan_id=plan_id,
        request_query=query,
        plan_type="MULTI_CAPABILITY_DAG",
        status="PLAN_READY",
        steps=[step1, step2],
        dag_edges=[("step-1", "step-2", "OUTPUT_TO_INPUT", "data flows to hash")],
        execution_order=["step-1", "step-2"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="2-step pipeline"
    )


# ============================================================================
# 1. Gate 1 Policy Rejection Test
# ============================================================================

def test_01_gate_1_policy_rejection(governance_fixture):
    ctx = governance_fixture
    # Create plan containing untrusted capability
    untrusted_step = PlanStep(
        step_id="step-bad",
        step_index=1,
        capability_urn="urn:lcs:tool:mcp.rogue-server:arbitrary-exec",
        display_name="Rogue Arbitrary Exec",
        sub_goal="execute rogue code",
        selection_reason="malicious",
        input_bindings={"cmd": StepInputBinding("cmd", "string", True, "USER_SUPPLIED", bound_value="rm -rf /")},
        output_definitions={},
        readiness="READY"
    )
    bad_plan = ExecutionPlan(
        plan_id="plan-bad-01",
        request_query="run rogue code",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[untrusted_step],
        dag_edges=[],
        execution_order=["step-bad"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="untrusted tool"
    )

    eval_result = ctx.governance_engine.evaluate_plan(bad_plan)
    assert eval_result.status == GovernanceStatus.BLOCKED
    assert eval_result.gate_1_status == "REJECTED"
    assert any("rejected by policy" in r or "error" in r for r in eval_result.reasons)

    # Approver approval MUST NOT bypass Gate 1
    consent = ApproverConsent(principal="admin@local")
    with pytest.raises(GovernanceBlockedError) as exc_info:
        ctx.governance_engine.approve_plan(bad_plan, approver=consent)
    assert "GOVERNANCE_BLOCKED" in str(exc_info.value)


# ============================================================================
# 2. Dual-Gate Enforcement Test
# ============================================================================

def test_02_dual_gate_enforcement(governance_fixture):
    ctx = governance_fixture
    plan = _create_sample_plan("plan-dual-gate-02")

    # Gate 1 passes
    eval_result = ctx.governance_engine.evaluate_plan(plan)
    assert eval_result.gate_1_status == "VERIFIED"

    # Approver declines (empty principal / no consent)
    with pytest.raises(GovernanceRejectedError):
        ctx.governance_engine.approve_plan(plan, approver=ApproverConsent(principal=""))


# ============================================================================
# 3. Dual-Gate Success Test
# ============================================================================

def test_03_dual_gate_success(governance_fixture):
    ctx = governance_fixture
    plan = _create_sample_plan("plan-dual-gate-03")

    consent = ApproverConsent(
        principal="human-operator@local",
        role=ApproverRole.HUMAN_OPERATOR,
        method="CLI_INTERACTIVE_CONFIRMATION"
    )
    token, eval_result = ctx.governance_engine.approve_plan(plan, approver=consent)

    assert eval_result.status == GovernanceStatus.APPROVED
    assert eval_result.gate_1_status == "VERIFIED"
    assert eval_result.gate_2_status == "APPROVED"
    assert token.token_id.startswith("eat-")
    assert token.plan_integrity_hash == eval_result.plan_integrity_hash
    assert token.iss == "urn:lcs:governance:v1"
    assert token.aud == "urn:lcs:executor:v1"
    assert token.signature != ""

    # Token verifies cleanly
    assert ctx.governance_engine.verify_token(token, plan) is True


# ============================================================================
# 4. Plan Integrity Hashing Test (Anti-Tampering)
# ============================================================================

def test_04_plan_integrity_tampering_detection(governance_fixture):
    ctx = governance_fixture
    plan = _create_sample_plan("plan-tamper-04")
    consent = ApproverConsent(principal="human-operator@local")
    token, _ = ctx.governance_engine.approve_plan(plan, approver=consent)

    # 1. Tamper with parameter binding value
    plan.steps[0].input_bindings["output_archive"].bound_value = "/etc/shadow"
    with pytest.raises(PlanIntegrityTamperedError):
        ctx.governance_engine.verify_token(token, plan)

    # Restore and tamper with step order
    plan.steps[0].input_bindings["output_archive"].bound_value = "/tmp/logs.tar"
    plan.execution_order = ["step-2", "step-1"]
    with pytest.raises(PlanIntegrityTamperedError):
        ctx.governance_engine.verify_token(token, plan)


# ============================================================================
# 5. Deterministic RFC 8785 JCS Canonicalization Test
# ============================================================================

def test_05_deterministic_rfc8785_canonicalization():
    # Test Section 6.2 verified test vector
    plan_payload = {
        "schema_version": "lcs.plan.canonical.v1",
        "plan_id": "plan-eb07f834",
        "plan_type": "MULTI_CAPABILITY_DAG",
        "steps": [
            {
                "step_id": "step-1",
                "step_index": 1,
                "capability_urn": "urn:lcs:tool:mcp.system-devops:compress-tar-archive",
                "display_name": "Compress Tar Archive",
                "input_bindings": {
                    "compression": {"source": "SCHEMA_DEFAULT", "value": "gz"},
                    "output_archive": {"source": "USER_SUPPLIED", "value": "/tmp/logs.tar"},
                    "source_dir": {"source": "USER_SUPPLIED", "value": "/tmp/logs"}
                },
                "output_definitions": {
                    "archive_path": {"evidence": "DOCUMENTED", "type": "string"}
                }
            },
            {
                "step_id": "step-2",
                "step_index": 2,
                "capability_urn": "urn:lcs:tool:mcp.crypto-security:hash-sha256-digest",
                "display_name": "Hash Sha256 Digest",
                "input_bindings": {
                    "data": {"source": "STEP_OUTPUT", "value": "${step-1.archive_path}"}
                },
                "output_definitions": {
                    "sha256_hash": {"evidence": "DOCUMENTED", "type": "string"}
                }
            }
        ],
        "dag_edges": [
            ["step-1", "step-2", "OUTPUT_TO_INPUT"]
        ],
        "execution_order": ["step-1", "step-2"],
        "resource_grants": [
            {"category": "FILESYSTEM", "access": "READ", "target": "/tmp/logs"},
            {"category": "FILESYSTEM", "access": "WRITE", "target": "/tmp/logs.tar"}
        ],
        "limits": {
            "max_steps": 2,
            "step_timeout_seconds": 30,
            "total_timeout_seconds": 180
        },
        "policy_context": {
            "policy_name": "production-strict-v2",
            "attestation_ids": [
                "urn:lcs:attestation:2026-11:sys-devops",
                "urn:lcs:attestation:2026-11:crypto-sec"
            ]
        }
    }

    canon_bytes = canonicalize_jcs(plan_payload)
    plan_digest = hashlib.sha256(canon_bytes).hexdigest()
    assert plan_digest == "5ca291f6d493504121864374df6a9f389f5542ab1e4541549a66bf6c092a1e82"

    # Test Section 10.2 audit preimage verified test vector
    preimage = {
        "cas_blob_reference": "sha256:9f8e7d6c5b4a0123456789abcdef0123456789abcdef0123456789abcdef",
        "event_id": "evt-7a8b9c0d",
        "event_payload": {
            "approver": "human-operator@local",
            "gate_1_status": "VERIFIED",
            "gate_2_status": "APPROVED",
            "resource_grants_count": 2
        },
        "event_type": "PLAN_AUTHORIZATION_GRANTED",
        "plan_id": "plan-eb07f834",
        "plan_integrity_hash": "5ca291f6d493504121864374df6a9f389f5542ab1e4541549a66bf6c092a1e82",
        "prev_record_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "sequence_number": 42,
        "timestamp": "2026-11-12T13:45:00Z",
        "token_id": "eat-8f4b21a9c3e7"
    }
    audit_digest = hashlib.sha256(canonicalize_jcs(preimage)).hexdigest()
    assert audit_digest == "7dbae66a95632ca70660771e345666f3e1debc1b594f33b57933dad8f824ebe4"

    # Rejection of NaN/Infinity
    with pytest.raises(ValueError):
        canonicalize_jcs({"bad": float("nan")})
    with pytest.raises(ValueError):
        canonicalize_jcs({"bad": float("inf")})


# ============================================================================
# 6. Token Verification, Atomic Consumption & Single-Use DispatchPermit Test
# ============================================================================

def test_06_token_consumption_and_single_use_permit(governance_fixture):
    ctx = governance_fixture
    plan = _create_sample_plan("plan-dispatch-06")
    consent = ApproverConsent(principal="human-operator@local")
    token, _ = ctx.governance_engine.approve_plan(plan, approver=consent)

    executor_id = {"executor_id": "worker-1", "channel": "unix:///tmp/executor.sock"}

    # First dispatch succeeds
    permit = ctx.governance_engine.authorize_dispatch(token.token_id, plan, executor_id)
    assert permit.permit_id.startswith("prm-")
    assert permit.state == "ISSUED"

    # Second dispatch with same token MUST be rejected (TOKEN_ALREADY_CONSUMED)
    with pytest.raises(TokenAlreadyConsumedError):
        ctx.governance_engine.authorize_dispatch(token.token_id, plan, executor_id)

    # First permit acceptance succeeds
    acceptance = ctx.governance_engine.accept_dispatch_permit(permit.permit_id, plan_integrity_hash=token.plan_integrity_hash)
    assert acceptance["status"] == "ACCEPTED"

    # Second acceptance of the same permit MUST be rejected (DISPATCH_PERMIT_ALREADY_USED)
    with pytest.raises(DispatchPermitAlreadyUsedError):
        ctx.governance_engine.accept_dispatch_permit(permit.permit_id, plan_integrity_hash=token.plan_integrity_hash)


# ============================================================================
# 7. Token TTL Expiration Test
# ============================================================================

def test_07_token_ttl_expiration(governance_fixture):
    ctx = governance_fixture
    plan = _create_sample_plan("plan-ttl-07")
    consent = ApproverConsent(principal="human-operator@local")
    # Issue token with 1 second TTL
    token, _ = ctx.governance_engine.approve_plan(plan, approver=consent, ttl_seconds=1)

    # Wait for TTL to expire
    time.sleep(1.2)

    with pytest.raises(TokenExpiredError):
        ctx.governance_engine.authorize_dispatch(token.token_id, plan, {"executor_id": "w1"})


# ============================================================================
# 8. Trust Freshness Revalidation, Policy Revision Drift & Storage Topology
# ============================================================================

def test_08_trust_freshness_revision_drift_and_storage_topology(governance_fixture):
    ctx = governance_fixture
    plan = _create_sample_plan("plan-drift-08")
    consent = ApproverConsent(principal="human-operator@local")
    token, _ = ctx.governance_engine.approve_plan(plan, approver=consent)

    # Simulate administrative policy mutation that increments policy revision
    increment_policy_revision(ctx.conn, change_reason="REVOKE_TEST_ATTESTATION")

    # Authorize dispatch must detect revision drift and fail closed!
    with pytest.raises(PolicyRevisionMismatchError) as exc_info:
        ctx.governance_engine.authorize_dispatch(token.token_id, plan, {"executor_id": "w1"})
    assert "POLICY_REVISION_MISMATCH_AT_DISPATCH" in str(exc_info.value)

    # Token must now be marked REVOKED in database
    cur = ctx.conn.cursor()
    cur.execute("SELECT state, revocation_reason FROM governance_tokens WHERE jti = ?;", (token.token_id,))
    row = cur.fetchone()
    assert row[0] == "REVOKED"
    assert row[1] == "POLICY_REVISION_DRIFT"

    # Test separate-database topology fail-closed enforcement
    with tempfile.NamedTemporaryFile(suffix=".db") as separate_db:
        conn_sep = sqlite3.connect(separate_db.name)
        with pytest.raises(UnsupportedStorageTopologyError):
            check_storage_topology(ctx.conn, conn_sep)
        conn_sep.close()


# ============================================================================
# 9. Filesystem Path Confinement & Traversal Defense Test
# ============================================================================

def test_09_filesystem_path_confinement_and_traversal():
    step = PlanStep(
        step_id="step-trav",
        step_index=1,
        capability_urn="urn:lcs:tool:mcp.system:read-file",
        display_name="Read File",
        sub_goal="read file",
        selection_reason="file",
        input_bindings={
            "file_path": StepInputBinding("file_path", "string", True, "USER_SUPPLIED", bound_value="/var/data/../../etc/passwd")
        },
        output_definitions={},
        readiness="READY"
    )
    plan = ExecutionPlan(
        plan_id="plan-trav-09",
        request_query="read passwd",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step],
        dag_edges=[],
        execution_order=["step-trav"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="traversal test"
    )

    with tempfile.TemporaryDirectory() as td:
        boundary_root = os.path.realpath(td)
        grants, warnings, violations = evaluate_resource_boundaries(plan, boundary_root=boundary_root)
        assert len(violations) > 0
        assert any("Path traversal" in v or "resolves outside boundary root" in v for v in violations)


# ============================================================================
# 10. Network Origin Gating & SSRF Defense Test
# ============================================================================

def test_10_network_origin_ssrf_defense():
    for blocked_url in ["http://127.0.0.1:8080/admin", "http://169.254.169.254/latest/meta-data", "http://localhost/secret"]:
        step = PlanStep(
            step_id="step-ssrf",
            step_index=1,
            capability_urn="urn:lcs:tool:mcp.net:fetch-url",
            display_name="Fetch URL",
            sub_goal="fetch",
            selection_reason="net",
            input_bindings={
                "url": StepInputBinding("url", "string", True, "USER_SUPPLIED", bound_value=blocked_url)
            },
            output_definitions={},
            readiness="READY"
        )
        plan = ExecutionPlan(
            plan_id="plan-ssrf-10",
            request_query="fetch",
            plan_type="SINGLE_CAPABILITY",
            status="PLAN_READY",
            steps=[step],
            dag_edges=[],
            execution_order=["step-ssrf"],
            missing_inputs=[],
            clarifying_questions=[],
            explanation="ssrf test"
        )
        _, _, violations = evaluate_resource_boundaries(plan)
        assert len(violations) > 0
        assert any("SSRF violation" in v for v in violations)


# ============================================================================
# 11. Step Quota Ceiling Test
# ============================================================================

def test_11_step_quota_ceiling():
    # Construct plan exceeding max 10 steps
    steps = [
        PlanStep(
            step_id=f"step-{i}",
            step_index=i,
            capability_urn="urn:lcs:tool:mcp.test:noop",
            display_name=f"Noop {i}",
            sub_goal=f"noop {i}",
            selection_reason="noop",
            input_bindings={},
            output_definitions={},
            readiness="READY"
        )
        for i in range(1, 15)
    ]
    plan = ExecutionPlan(
        plan_id="plan-quota-11",
        request_query="many steps",
        plan_type="MULTI_CAPABILITY_DAG",
        status="PLAN_READY",
        steps=steps,
        dag_edges=[],
        execution_order=[s.step_id for s in steps],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="quota test"
    )
    _, _, violations = evaluate_resource_boundaries(plan, max_steps_ceiling=10)
    assert len(violations) > 0
    assert any("exceeds maximum governance quota ceiling" in v for v in violations)


# ============================================================================
# 12. Irreversible Action Gating & Warnings Test
# ============================================================================

def test_12_irreversible_action_warnings(governance_fixture):
    ctx = governance_fixture
    del_step = PlanStep(
        step_id="step-del",
        step_index=1,
        capability_urn="urn:lcs:tool:mcp.system-devops:delete-directory-tree",
        display_name="Delete Directory Tree",
        sub_goal="delete temp logs",
        selection_reason="cleanup",
        input_bindings={"target_dir": StepInputBinding("target_dir", "string", True, "USER_SUPPLIED", bound_value="/tmp/test_dir")},
        output_definitions={},
        readiness="READY"
    )
    plan = ExecutionPlan(
        plan_id="plan-del-12",
        request_query="delete temp logs",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[del_step],
        dag_edges=[],
        execution_order=["step-del"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="deletion"
    )

    eval_result = ctx.governance_engine.evaluate_plan(plan)
    assert any("Irreversible mutation warning" in w for w in eval_result.warnings)


# ============================================================================
# 13. Hash-Chained Audit Ledger, Preimage Integrity, Directory Sync & Crash Recovery
# ============================================================================

def test_13_audit_ledger_preimage_sync_and_crash_recovery(governance_fixture):
    ctx = governance_fixture
    with tempfile.TemporaryDirectory() as td:
        ledger = GovernanceAuditLedger(audit_dir=td, key_store=ctx.key_store)

        # 1. Verify genesis ledger
        ok, count, msg = ledger.verify_ledger()
        assert ok is True
        assert count == 0

        # 2. Append events and verify hash chaining
        rec1 = ledger.append_event("PLAN_SUBMITTED", "plan-test-1", "hash-1", "eat-1", {"meta": "data 1"})
        rec2 = ledger.append_event("PLAN_APPROVED", "plan-test-1", "hash-1", "eat-1", {"meta": "data 2"})

        assert rec1["sequence_number"] == 1
        assert rec2["sequence_number"] == 2
        assert rec2["prev_record_hash"] == rec1["record_hash"]

        # 3. Verify ledger
        ok, total_count, _ = ledger.verify_ledger()
        assert ok is True
        assert total_count == 2

        # 4. Tail Truncation Detection
        # Manually delete last line of log
        with open(ledger.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        with open(ledger.log_path, "w", encoding="utf-8") as f:
            f.writelines(lines[:-1])

        with pytest.raises(AuditLogTailTruncatedError):
            ledger.verify_ledger()

        # Restore lines
        with open(ledger.log_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # 5. Crash Recovery Simulation
        # Simulate a crash where record 3 was fsynced to log file, but anchor update was interrupted
        rec3_preimage = {
            "sequence_number": 3,
            "event_id": "evt-crashed-03",
            "prev_record_hash": rec2["record_hash"],
            "timestamp": "2026-11-12T14:00:00Z",
            "event_type": "PLAN_DISPATCHED",
            "plan_id": "plan-test-1",
            "plan_integrity_hash": "hash-1",
            "token_id": "eat-1",
            "event_payload": {"crashed": True},
            "cas_blob_reference": "sha256:11223344"
        }
        rec3_bytes = canonicalize_jcs(rec3_preimage)
        rec3_hash = hashlib.sha256(rec3_bytes).hexdigest()
        rec3_stored = dict(rec3_preimage)
        rec3_stored["record_hash"] = rec3_hash

        # Append valid record 3 directly to log file (unanchored!)
        with open(ledger.log_path, "ab") as f:
            f.write(canonicalize_jcs(rec3_stored) + b"\n")
            # Also append trailing corrupt partial bytes
            f.write(b'{"corrupted_torn_write":')

        # Execute Crash Recovery
        forward_rolled, truncated_bytes = ledger.recover()
        assert forward_rolled == 1  # Forward-rolled record 3
        assert truncated_bytes > 0   # Truncated trailing torn bytes

        # Verify ledger is now fully consistent at sequence 3
        ok, count, _ = ledger.verify_ledger()
        assert ok is True
        assert count == 3


# ============================================================================
# 14. Zero-Execution Invariant Test
# ============================================================================

def test_14_zero_execution_invariant(governance_fixture):
    ctx = governance_fixture
    plan = _create_sample_plan("plan-zero-exec-14")
    consent = ApproverConsent(principal="human-operator@local")

    # Mock subprocess.Popen, socket, and any execution tools
    with patch("subprocess.Popen") as mock_popen, \
         patch("subprocess.run") as mock_run, \
         patch("socket.socket") as mock_socket:

        # Run evaluation, approval, token verification, and dispatch
        eval_result = ctx.governance_engine.evaluate_plan(plan)
        token, _ = ctx.governance_engine.approve_plan(plan, approver=consent)
        assert ctx.governance_engine.verify_token(token, plan) is True
        permit = ctx.governance_engine.authorize_dispatch(token.token_id, plan, {"executor_id": "test"})
        assert permit is not None

        # Assert ZERO execution calls occurred
        assert mock_popen.call_count == 0
        assert mock_run.call_count == 0
        assert mock_socket.call_count == 0


# ============================================================================
# 15. Concurrency and Multi-Connection Serialization Test
# ============================================================================

def test_15_concurrency_and_multi_connection_serialization(governance_fixture):
    ctx = governance_fixture
    plan = _create_sample_plan("plan-concurrent-15")
    consent = ApproverConsent(principal="human-operator@local")
    token, _ = ctx.governance_engine.approve_plan(plan, approver=consent)

    results = []
    errors = []

    def try_dispatch(worker_id):
        # Open separate connection to the same SQLite database
        conn_worker = sqlite3.connect(ctx.config.db_path, timeout=10.0)
        try:
            from lcs.registry import CapabilityRegistrationService
            from lcs.policy import InterfacePolicyService
            from lcs.profile import CapabilityProfileService
            cap_svc = CapabilityRegistrationService(conn_worker, ctx.cas_engine)
            iface_svc = InterfacePolicyService(conn_worker, ctx.cas_engine, cap_svc)
            prof_svc = CapabilityProfileService(conn_worker, ctx.cas_engine)
            gov_worker = ExecutionGovernanceEngineV1(
                conn=conn_worker,
                cas_engine=ctx.cas_engine,
                iface_service=iface_svc,
                profile_service=prof_svc,
                key_store=ctx.key_store,
                audit_dir=ctx.governance_engine.audit_ledger.audit_dir
            )
            permit = gov_worker.authorize_dispatch(token.token_id, plan, {"executor_id": f"worker-{worker_id}"})
            results.append(permit)
        except Exception as e:
            errors.append(e)
        finally:
            conn_worker.close()

    # Launch 5 concurrent threads competing to consume the same token
    threads = [threading.Thread(target=try_dispatch, args=(i,)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly ONE dispatch must succeed; all other 4 must fail closed with TokenAlreadyConsumedError!
    assert len(results) == 1
    assert len(errors) == 4
    for err in errors:
        assert isinstance(err, TokenAlreadyConsumedError) or "already been consumed" in str(err)


# ============================================================================
# 16. CLI 'lcs approve' and 'lcs audit-log verify' End-to-End Test
# ============================================================================

def test_16_cli_commands_integration(governance_fixture):
    from lcs.cli import main

    ctx = governance_fixture

    # Test audit-log verify via CLI
    code = main(["--root", ctx.config.root_dir, "audit-log", "verify"])
    assert code == 0

    # Test approve command via CLI with --yes flag
    code = main([
        "--root", ctx.config.root_dir,
        "approve", "compress logs and calculate sha256",
        "--yes",
        "--approver", "cli-test@local"
    ])
    assert code == 0
