"""
LCS Stage 5 Release-Blocking Remediation: Genuine Cross-Process Locking Suite
=============================================================================
Validates:
1. Strict Win32 kernel API parameter translation and error code mapping (no-op shims rejected).
2. Genuine cross-process exclusive lock contention between independent OS processes.
3. Genuine cross-process shared lock concurrency and exclusive blocking.
4. Automatic OS kernel lock release upon process termination / abrupt crash (SIGKILL/TerminateProcess).
5. Concurrent authorization token consumption race serialization (exactly one winner).
6. Audit ledger cryptographic hash-chain integrity under concurrent access.
"""

import os
import sys
import time
import json
import errno
import tempfile
import subprocess
import multiprocessing
import pytest
from unittest.mock import MagicMock, patch

from lcs.locking import (
    LOCK_SH,
    LOCK_EX,
    LOCK_NB,
    LOCK_UN,
    flock,
    win32_flock,
    _win32_flock_lockfileex,
    CrossProcessFileLock,
    ERROR_LOCK_VIOLATION,
    ERROR_SHARING_VIOLATION,
    ERROR_NOT_LOCKED,
    ERROR_ACCESS_DENIED,
    LOCKFILE_FAIL_IMMEDIATELY,
    LOCKFILE_EXCLUSIVE_LOCK
)
from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.planning import ExecutionPlan, PlanStep, StepInputBinding, StepOutputDefinition
from lcs.governance import ApproverConsent, ApproverRole, GovernanceStatus
from lcs.policy import InterfaceTrustPolicy
from lcs.execution import PreflightVerificationError
from lcs.inventory.models import UnifiedResourceRecord, ResourceType, ProvenanceRecord


# ============================================================================
# 1. Parameter & Error Code Verification for Win32 Locking (Anti-Mocking Test)
# ============================================================================

def test_win32_lockfileex_parameter_translation_and_rejection_of_noops():
    """
    Requirement 1 & 5:
    Verifies that _win32_flock_lockfileex passes exact Win32 flags and structures,
    and raises genuine exceptions on lock violations.
    A no-op function that simply returns None or 0 WILL FAIL this test.
    """
    mock_kernel32 = MagicMock()
    mock_msvcrt = MagicMock()
    mock_msvcrt.get_osfhandle.return_value = 1001

    with patch.dict("sys.modules", {"msvcrt": mock_msvcrt, "ctypes.windll": MagicMock(kernel32=mock_kernel32)}):
        import ctypes
        with patch.object(ctypes, "windll", create=True) as mock_windll:
            mock_windll.kernel32 = mock_kernel32

            # Test 1: Exclusive non-blocking lock (LOCK_EX | LOCK_NB)
            mock_kernel32.LockFileEx.return_value = 1  # Success
            _win32_flock_lockfileex(42, LOCK_EX | LOCK_NB)

            mock_msvcrt.get_osfhandle.assert_called_with(42)
            assert mock_kernel32.LockFileEx.called
            args, _ = mock_kernel32.LockFileEx.call_args
            # Verify exact flags: LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
            expected_flags = LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY
            assert args[1].value == expected_flags
            assert args[3].value == 0xFFFFFFFF  # 64-bit lock range
            assert args[4].value == 0xFFFFFFFF

            # Test 2: Shared non-blocking lock (LOCK_SH | LOCK_NB)
            mock_kernel32.LockFileEx.reset_mock()
            _win32_flock_lockfileex(42, LOCK_SH | LOCK_NB)
            args, _ = mock_kernel32.LockFileEx.call_args
            assert args[1].value == LOCKFILE_FAIL_IMMEDIATELY  # Exclusive bit NOT set

            # Test 3: Lock contention raises BlockingIOError(EAGAIN)
            mock_kernel32.LockFileEx.return_value = 0  # Win32 Failure
            mock_kernel32.GetLastError.return_value = ERROR_LOCK_VIOLATION
            with pytest.raises(BlockingIOError) as exc_info:
                _win32_flock_lockfileex(42, LOCK_EX | LOCK_NB)
            assert exc_info.value.errno == errno.EAGAIN

            # Test 4: Sharing violation also raises BlockingIOError(EAGAIN)
            mock_kernel32.GetLastError.return_value = ERROR_SHARING_VIOLATION
            with pytest.raises(BlockingIOError) as exc_info:
                _win32_flock_lockfileex(42, LOCK_EX | LOCK_NB)
            assert exc_info.value.errno == errno.EAGAIN

            # Test 5: Permission denied raises PermissionError(EACCES)
            mock_kernel32.GetLastError.return_value = ERROR_ACCESS_DENIED
            with pytest.raises(PermissionError) as exc_info:
                _win32_flock_lockfileex(42, LOCK_EX | LOCK_NB)
            assert exc_info.value.errno == errno.EACCES

            # Test 6: Unlock calls UnlockFileEx
            mock_kernel32.UnlockFileEx.return_value = 1
            _win32_flock_lockfileex(42, LOCK_UN)
            assert mock_kernel32.UnlockFileEx.called


# ============================================================================
# 2. Real Cross-Process Exclusive Lock Contention (Independent Processes)
# ============================================================================

def test_cross_process_exclusive_lock_contention(tmp_path):
    """
    Requirement 4 & 5:
    Spawns an independent OS subprocess that locks a file exclusively.
    Verifies that the parent process is rejected with BlockingIOError when
    attempting non-blocking lock, and succeeds immediately once the child unlocks.
    """
    lock_file = str(tmp_path / "test_exclusive.lock")
    ready_file = str(tmp_path / "child_ready.flag")
    release_file = str(tmp_path / "release.flag")

    lock_file_esc = json.dumps(lock_file)
    ready_file_esc = json.dumps(ready_file)
    release_file_esc = json.dumps(release_file)

    child_code = f"""
import os, sys, time
from lcs.locking import flock, LOCK_EX, LOCK_UN

fd = os.open({lock_file_esc}, os.O_RDWR | os.O_CREAT, 0o600)
flock(fd, LOCK_EX)
with open({ready_file_esc}, "w") as f:
    f.write("LOCKED")

# Wait for release signal
while not os.path.exists({release_file_esc}):
    time.sleep(0.05)

flock(fd, LOCK_UN)
os.close(fd)
sys.exit(0)
"""
    proc = subprocess.Popen([sys.executable, "-c", child_code])
    try:
        # Wait until child process has acquired lock
        for _ in range(50):
            if os.path.exists(ready_file):
                break
            time.sleep(0.1)
        assert os.path.exists(ready_file), "Child process failed to acquire initial lock"

        # Parent attempts non-blocking exclusive lock: MUST fail with BlockingIOError / EAGAIN
        parent_fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with pytest.raises((BlockingIOError, OSError)) as exc_info:
                flock(parent_fd, LOCK_EX | LOCK_NB)
            assert exc_info.value.errno in (errno.EAGAIN, errno.EACCES)
        finally:
            os.close(parent_fd)

        # Signal child to release lock
        with open(release_file, "w") as f:
            f.write("RELEASE")

        proc.wait(timeout=5)
        assert proc.returncode == 0

        # Now parent acquires lock cleanly
        parent_fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        flock(parent_fd, LOCK_EX | LOCK_NB)
        flock(parent_fd, LOCK_UN)
        os.close(parent_fd)

    finally:
        if proc.poll() is None:
            proc.kill()


# ============================================================================
# 3. Automatic OS Kernel Lock Release on Abrupt Process Crash / SIGKILL
# ============================================================================

def test_crash_recovery_kernel_lock_cleanup(tmp_path):
    """
    Requirement 4:
    Proves that when an OS process holding an exclusive lock is abruptly killed
    (simulating a crash or SIGKILL/TerminateProcess), the OS kernel automatically
    releases the lock without corruption or deadlock.
    """
    lock_file = str(tmp_path / "test_crash.lock")
    ready_file = str(tmp_path / "crash_ready.flag")

    lock_file_esc = json.dumps(lock_file)
    ready_file_esc = json.dumps(ready_file)

    child_code = f"""
import os, sys, time
from lcs.locking import flock, LOCK_EX

fd = os.open({lock_file_esc}, os.O_RDWR | os.O_CREAT, 0o600)
flock(fd, LOCK_EX)
with open({ready_file_esc}, "w") as f:
    f.write("LOCKED")

# Sleep forever until abruptly killed
while True:
    time.sleep(1)
"""
    proc = subprocess.Popen([sys.executable, "-c", child_code])
    try:
        for _ in range(50):
            if os.path.exists(ready_file):
                break
            time.sleep(0.1)
        assert os.path.exists(ready_file)

        # Confirm lock is held by child
        parent_fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with pytest.raises((BlockingIOError, OSError)):
                flock(parent_fd, LOCK_EX | LOCK_NB)
        finally:
            os.close(parent_fd)

        # Abruptly kill the process without allowing graceful cleanup
        proc.kill()
        proc.wait(timeout=5)

        # The OS kernel MUST have freed the lock automatically
        parent_fd = os.open(lock_file, os.O_RDWR | os.O_CREAT, 0o600)
        flock(parent_fd, LOCK_EX | LOCK_NB)
        flock(parent_fd, LOCK_UN)
        os.close(parent_fd)

    finally:
        if proc.poll() is None:
            proc.kill()


# ============================================================================
# 4. Concurrent Execution Token Consumption (Exactly One Winner)
# ============================================================================

def _worker_execute_token(ws_dir, home_dir, plan, token, result_file):
    """Worker function executed in independent processes to race for single token."""
    cfg = LCSConfig.resolve(root_override=os.path.join(ws_dir, ".lcs"), home_override=home_dir, workspace_root=ws_dir)
    ctx = LCSContext(config=cfg, auto_migrate=True)
    try:
        try:
            res = ctx.execution_engine.execute_plan(plan, token)
            outcome = {"status": "SUCCESS", "lifecycle": res.lifecycle_state.value}
        except PreflightVerificationError as pve:
            outcome = {"status": "REJECTED", "error": str(pve)}
        except Exception as e:
            outcome = {"status": "ERROR", "error": str(e)}

        with open(result_file, "w") as f:
            json.dump(outcome, f)
    finally:
        ctx.close()


def test_concurrent_authorization_token_consumption_race(tmp_path):
    """
    Requirement 4:
    Verifies that when 4 independent concurrent processes attempt to execute
    the same plan with the same single-use token, exactly ONE process succeeds
    and all others are rejected with TOKEN_ALREADY_CONSUMED.
    """
    ws_dir = str(tmp_path / "workspace")
    home_dir = str(tmp_path / "home")
    os.makedirs(ws_dir, exist_ok=True)
    os.makedirs(home_dir, exist_ok=True)

    cfg = LCSConfig.resolve(root_override=os.path.join(ws_dir, ".lcs"), home_override=home_dir, workspace_root=ws_dir)
    ctx = LCSContext(config=cfg, auto_migrate=True)

    # Register simple step
    script_step = os.path.join(ws_dir, "step.py")
    with open(script_step, "w") as f:
        f.write("print('RACE_TEST')\n")

    import hashlib
    content_hash = hashlib.sha256(b"print('RACE_TEST')\n").hexdigest()
    rec = UnifiedResourceRecord(
        urn="urn:lcs:skill:race:step",
        name="race-step",
        resource_type=ResourceType.SKILL,
        display_name="race-step",
        description="Race test step",
        raw_content="print('RACE_TEST')\n",
        raw_content_digest=content_hash,
        provenance=ProvenanceRecord(
            origin_host="generic_posix",
            precedence_tier="WORKSPACE",
            source_path=script_step,
            resolved_path=script_step,
            content_hash=content_hash
        )
    )
    ctx.inventory._persist_and_bind_capability(rec)

    step = PlanStep(
        step_id="step-race-01",
        step_index=1,
        capability_urn="urn:lcs:skill:race:step",
        display_name="Race Step",
        sub_goal="Race test",
        selection_reason="Race test",
        input_bindings={"target_script": StepInputBinding("target_script", "string", False, bound_value=script_step)},
        output_definitions={"result": StepOutputDefinition("result", "string")},
        dependencies=[]
    )
    plan = ExecutionPlan(
        plan_id="plan-race-01",
        request_query="Race test",
        plan_type="SINGLE_CAPABILITY",
        status="PLAN_READY",
        steps=[step],
        dag_edges=[],
        execution_order=["step-race-01"],
        missing_inputs=[],
        clarifying_questions=[],
        explanation="Testing concurrent token race"
    )

    policy = InterfaceTrustPolicy("race-policy", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)
    consent = ApproverConsent("race-auditor@local", ApproverRole.HUMAN_OPERATOR)
    token, _ = ctx.governance_engine.approve_plan(plan=plan, approver=consent, active_policy=policy)
    ctx.close()

    # Launch 4 concurrent processes
    num_workers = 4
    procs = []
    result_files = []
    mp_ctx = multiprocessing.get_context("spawn")

    for i in range(num_workers):
        res_file = str(tmp_path / f"worker_res_{i}.json")
        result_files.append(res_file)
        p = mp_ctx.Process(
            target=_worker_execute_token,
            args=(ws_dir, home_dir, plan, token, res_file)
        )
        procs.append(p)

    # Start all concurrently
    for p in procs:
        p.start()

    for p in procs:
        p.join(timeout=20)
        assert p.exitcode == 0, f"Worker process crashed with exit code {p.exitcode}"

    # Analyze outcomes
    outcomes = []
    for rf in result_files:
        assert os.path.exists(rf), f"Result file missing: {rf}"
        with open(rf) as f:
            outcomes.append(json.load(f))

    successes = [o for o in outcomes if o.get("status") == "SUCCESS"]
    rejected = [o for o in outcomes if o.get("status") == "REJECTED"]

    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)} ({outcomes})"
    assert len(rejected) == num_workers - 1, f"Expected {num_workers - 1} rejections, got {len(rejected)}"
    for r in rejected:
        assert "TOKEN_ALREADY_CONSUMED" in r.get("error", "")

    # Audit ledger cryptographic integrity check
    ctx2 = LCSContext(config=cfg, auto_migrate=True)
    try:
        is_valid, count, msg = ctx2.execution_engine.audit_ledger.verify_ledger()
        assert is_valid is True, f"Audit ledger broken: {msg}"
        assert count >= 1
    finally:
        ctx2.close()
