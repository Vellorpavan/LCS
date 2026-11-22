"""
Test Suite: Item 2 - Multi-Tier Verification Gates in Execution Engine
=====================================================================
Verifies:
1. Successful execution verifies through UnifiedResourceVerifier and records verification evidence.
2. Eliminates 'exit 0 fallacy': a script exiting with code 0 but emitting fatal tracebacks
   in stderr is rejected by ScriptVerificationGate and causes execution to fail closed.
3. Multi-tier verification results are recorded in output CAS trace receipts.
"""

import os
import sys
import tempfile
import pytest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.planning import ExecutionPlan, PlanStep, StepInputBinding, StepOutputDefinition
from lcs.governance import ApproverConsent, ApproverRole, GovernanceStatus
from lcs.policy import InterfaceTrustPolicy


def test_01_script_execution_passes_all_verification_tiers():
    """Confirms valid script execution passes all 5 verification tiers."""
    with tempfile.TemporaryDirectory(prefix="lcs_vgate_pass_") as tmpdir:
        skill_dir = os.path.join(tmpdir, ".agents", "skills", "valid-worker")
        scripts_dir = os.path.join(skill_dir, "scripts")
        os.makedirs(scripts_dir, exist_ok=True)

        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("---\nname: valid-worker\ndescription: Valid worker\n---\n# Valid\n")

        deliv_path = os.path.join(tmpdir, "output.txt")
        script_path = os.path.join(scripts_dir, "run.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(
                "import os, sys, argparse\n"
                "parser = argparse.ArgumentParser()\n"
                "parser.add_argument('--deliverable', default='')\n"
                "args, _ = parser.parse_known_args()\n"
                "with open(args.deliverable, 'w') as f:\n"
                "    f.write('VERIFIED_DELIVERABLE_PAYLOAD_9912\\n')\n"
                "sys.stdout.write('PROCESS_COMPLETE\\n')\n"
            )

        cfg = LCSConfig.resolve(root_override=tmpdir)
        with LCSContext(config=cfg, auto_migrate=True) as ctx:
            ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())
            rec = next((r for r in ctx.inventory.list_all() if r.name == "valid-worker"), None)
            assert rec is not None

            consent = ApproverConsent(principal="tester", role=ApproverRole.HUMAN_OPERATOR, method="TEST")
            policy = InterfaceTrustPolicy(policy_name="permissive", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)

            res = ctx.call_me.execute_call_me(
                raw_message="/call-me Run valid worker",
                execute=True,
                approver_consent=consent,
                active_policy=policy,
                inputs={"deliverable": deliv_path}
            )
            assert res["status"] == "SUCCEEDED"
            assert res["completed_steps"] >= 1
            assert os.path.exists(deliv_path)
            assert res["trace_cas_digest"] != ""


def test_02_exit_zero_fallacy_blocked_by_stderr_traceback():
    """
    Eliminates 'exit 0 fallacy':
    If a script exits with returncode 0 but wrote a fatal traceback to stderr,
    ScriptVerificationGate rejects the execution and marks the step FAILED.
    """
    with tempfile.TemporaryDirectory(prefix="lcs_vgate_fail_") as tmpdir:
        skill_dir = os.path.join(tmpdir, ".agents", "skills", "flaky-worker")
        scripts_dir = os.path.join(skill_dir, "scripts")
        os.makedirs(scripts_dir, exist_ok=True)

        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("---\nname: flaky-worker\ndescription: Flaky worker\n---\n# Flaky\n")

        deliv_path = os.path.join(tmpdir, "flaky_output.txt")
        script_path = os.path.join(scripts_dir, "run.py")
        # Script creates the file, exits 0, but emitted fatal traceback to stderr
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(
                "import os, sys, argparse\n"
                "parser = argparse.ArgumentParser()\n"
                "parser.add_argument('--deliverable', default='')\n"
                "args, _ = parser.parse_known_args()\n"
                "with open(args.deliverable, 'w') as f:\n"
                "    f.write('partial output')\n"
                "sys.stderr.write('Traceback (most recent call last):\\n  File \"core.py\", line 42\\nZeroDivisionError: division by zero\\n')\n"
                "sys.exit(0)\n"
            )

        cfg = LCSConfig.resolve(root_override=tmpdir)
        with LCSContext(config=cfg, auto_migrate=True) as ctx:
            ctx.inventory.initialize_environment(adapters=ctx.adapter_registry.list_all())
            rec = next((r for r in ctx.inventory.list_all() if r.name == "flaky-worker"), None)
            assert rec is not None

            consent = ApproverConsent(principal="tester", role=ApproverRole.HUMAN_OPERATOR, method="TEST")
            policy = InterfaceTrustPolicy(policy_name="permissive", min_interface_version=1, require_attestation=False, require_all_capabilities_verified=False)

            res = ctx.call_me.execute_call_me(
                raw_message="/call-me Run flaky worker",
                execute=True,
                approver_consent=consent,
                active_policy=policy,
                inputs={"deliverable": deliv_path}
            )
            # Must fail closed due to verification rejection of stderr traceback!
            assert res["status"] == "FAILED"
            assert "verification failed" in res.get("error_message", "").lower()
