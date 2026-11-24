"""
Call Me — Stage 2 Host Integration & Deliverable Verification Test Suite
=======================================================================
Verifies:
1. Host slash-command artifact generation containing closed-loop protocol.
2. Deliverable verification governance checks:
   - Unauthorized binaries (e.g. rm, bash, curl) are rejected.
   - Escaping argument paths (e.g. ../../) are rejected.
   - Authorized binaries (python3, pytest) within workspace boundaries pass.
3. Closed-loop flow from plan_call_me -> deliverable creation -> verify_deliverables.
4. Failure states when required files or tests fail.
"""

import os
import sys
import shutil
import tempfile
import unittest

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.interface.core_bridge import ApproverConsent
from lcs.interface.generators import SlashCommandGenerator
from lcs.verification.gates import DeliverableVerificationGate, VerificationState


class TestCallMeStage2HostIntegration(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="call_me_stage2_test_")
        self.workspace = os.path.join(self.test_dir, "workspace")
        os.makedirs(self.workspace, exist_ok=True)
        cfg = LCSConfig.resolve(root_override=self.workspace)
        self.ctx = LCSContext(config=cfg)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_slash_command_template_contains_closed_loop_protocol(self):
        template = SlashCommandGenerator.ANTIGRAVITY_SKILL_TEMPLATE
        self.assertIn("call-me-plan", template)
        self.assertIn("call-me-verify", template)
        self.assertIn("execution_waves", template)
        self.assertIn("invoke_subagent", template)
        self.assertIn("Phase 1: Request Structured Plan", template)
        self.assertIn("Phase 2: Closed-Loop Execution by Waves", template)
        self.assertIn("Phase 3: Deliverable & Test Verification Gate", template)
        self.assertIn("Phase 4: Truthful Outcome Reporting", template)

    def test_governance_rejects_unauthorized_verification_binary(self):
        gate = DeliverableVerificationGate()
        fpath = os.path.join(self.workspace, "app.py")
        with open(fpath, "w") as f:
            f.write("print('hello')\n")

        # Attempt to run unauthorized command 'sh' or 'rm'
        res = gate.verify({
            "run_id": "test-sec-binary",
            "workspace_root": self.workspace,
            "expected_files": ["app.py"],
            "verification_commands": ["rm -rf /tmp/test"]
        })
        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)
        failed_ev = [e for e in res.evidence_records if not e.passed]
        self.assertTrue(any("governance" in e.criterion.lower() or "unauthorized" in str(e.details).lower() for e in failed_ev))

    def test_governance_rejects_escaping_argument_in_verification_command(self):
        gate = DeliverableVerificationGate()
        fpath = os.path.join(self.workspace, "app.py")
        with open(fpath, "w") as f:
            f.write("print('hello')\n")

        # Attempt path traversal in argument
        res = gate.verify({
            "run_id": "test-sec-arg",
            "workspace_root": self.workspace,
            "expected_files": ["app.py"],
            "verification_commands": ["python3 -m unittest ../../../outside_test.py"]
        })
        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)

    def test_closed_loop_plan_and_verify_success(self):
        plan_packet = self.ctx.call_me.plan_call_me(
            raw_message="Build a Python telemetry service",
            workspace_root=self.workspace
        )
        self.assertEqual(plan_packet["status"], "PLAN_READY")
        self.assertIn("execution_waves", plan_packet)
        self.assertGreater(len(plan_packet["execution_waves"]), 0)

        # Create expected deliverables
        main_py = os.path.join(self.workspace, "main.py")
        test_py = os.path.join(self.workspace, "test_telemetry.py")
        with open(main_py, "w") as f:
            f.write("# Telemetry service\ndef health(): return {'status': 'healthy'}\n")
        with open(test_py, "w") as f:
            f.write("import unittest\nfrom main import health\n\nclass TestHealth(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(health()['status'], 'healthy')\n\nif __name__ == '__main__': unittest.main()\n")

        verify_res = self.ctx.call_me.verify_deliverables(
            run_id=plan_packet["request_id"],
            expected_files=["main.py", "test_telemetry.py"],
            verification_commands=["python3 -m unittest test_telemetry.py"],
            workspace_root=self.workspace
        )
        self.assertTrue(verify_res["is_verified"])
        self.assertEqual(verify_res["verification_state"], "VERIFIED")

    def test_closed_loop_verify_fails_on_failing_unit_test(self):
        main_py = os.path.join(self.workspace, "main.py")
        test_py = os.path.join(self.workspace, "test_telemetry.py")
        with open(main_py, "w") as f:
            f.write("def health(): return {'status': 'unhealthy'}\n")
        with open(test_py, "w") as f:
            f.write("import unittest\nfrom main import health\n\nclass TestHealth(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(health()['status'], 'healthy')\n\nif __name__ == '__main__': unittest.main()\n")

        verify_res = self.ctx.call_me.verify_deliverables(
            run_id="req-failing-test",
            expected_files=["main.py", "test_telemetry.py"],
            verification_commands=["python3 -m unittest test_telemetry.py"],
            workspace_root=self.workspace
        )
        self.assertFalse(verify_res["is_verified"])
        self.assertEqual(verify_res["verification_state"], "FAILED")


if __name__ == "__main__":
    unittest.main()
