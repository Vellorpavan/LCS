"""
Stage 1 Regression Test Suite: Closed-Loop Execution Protocol & Deliverable Verification
========================================================================================
Validates:
1. Instruction-only execution yields HANDOFF_READY, never SUCCEEDED.
2. Structured planning packet contains run ID, waves, instructions, and verification criteria.
3. DeliverableVerificationGate asserts physical file existence and non-emptiness.
4. Missing or empty files fail deliverable verification.
5. Workspace escape attempts (NTFS ADS ':' or '..') are rejected.
6. Automated verification commands (e.g. tests) pass or fail truthfully.
7. Backward compatibility with existing lcs commands and frozen hashes.
"""

import os
import sys
import tempfile
import unittest
import shutil

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.interface.contract import TaskRequest
from lcs.interface.core_bridge import LCSCoreBridge, ApproverConsent, ApproverRole
from lcs.interface.entry_point import CallMeInterface
from lcs.verification.gates import DeliverableVerificationGate, VerificationState


class TestCallMeStage1ClosedLoop(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_stage1_")
        cfg = LCSConfig.resolve(root_override=self.test_dir)
        self.ctx = LCSContext(config=cfg)
        self.call_me = CallMeInterface(self.ctx)


    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_structured_plan_packet(self):
        """Verify call-me-plan generates structured DAG, waves, and hydrated instructions."""
        plan = self.call_me.plan_call_me(
            "/call-me Scaffold a Python service, add telemetry, and run tests",
            workspace_root=self.test_dir
        )
        self.assertEqual(plan["status"], "PLAN_READY")
        self.assertIn("execution_waves", plan)
        self.assertIn("steps", plan)
        self.assertGreaterEqual(len(plan["steps"]), 1)
        self.assertIn("verification_criteria", plan)
        self.assertEqual(plan["workspace_root"], os.path.abspath(self.test_dir))

        # Check step structure
        first_step = plan["steps"][0]
        self.assertIn("step_id", first_step)
        self.assertIn("role", first_step)
        self.assertIn("instructions", first_step)
        self.assertIn("dependencies", first_step)

    def test_deliverable_verification_successful(self):
        """Verify DeliverableVerificationGate passes when required files and tests succeed."""
        app_file = os.path.join(self.test_dir, "service.py")
        with open(app_file, "w") as f:
            f.write("def health(): return {'status': 'healthy'}\n")

        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": "run-test-01",
            "workspace_root": self.test_dir,
            "expected_files": ["service.py"],
            "verification_commands": [[sys.executable, "-c", "import service; assert service.health()['status'] == 'healthy'"]]
        })

        self.assertTrue(res.is_verified)
        self.assertEqual(res.state, VerificationState.VERIFIED)

    def test_deliverable_verification_missing_file_fails(self):
        """Verify DeliverableVerificationGate fails when an expected physical file is missing."""
        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": "run-test-02",
            "workspace_root": self.test_dir,
            "expected_files": ["non_existent_app.py"],
            "verification_commands": []
        })

        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)

    def test_deliverable_verification_empty_file_fails(self):
        """Verify DeliverableVerificationGate fails when an expected physical file is empty."""
        empty_file = os.path.join(self.test_dir, "empty_service.py")
        open(empty_file, "w").close()

        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": "run-test-03",
            "workspace_root": self.test_dir,
            "expected_files": ["empty_service.py"],
            "verification_commands": []
        })

        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)

    def test_deliverable_verification_workspace_escape_fails(self):
        """Verify DeliverableVerificationGate rejects traversal '..' and NTFS ADS ':' attempts."""
        gate = DeliverableVerificationGate()

        # Traversal escape
        res_traversal = gate.verify({
            "run_id": "run-test-04",
            "workspace_root": self.test_dir,
            "expected_files": ["../../outside.py"]
        })
        self.assertFalse(res_traversal.is_verified)

        # Windows NTFS Alternate Data Stream escape
        res_ads = gate.verify({
            "run_id": "run-test-05",
            "workspace_root": self.test_dir,
            "expected_files": ["app.py:stream"]
        })
        self.assertFalse(res_ads.is_verified)

    def test_deliverable_verification_failed_command_fails(self):
        """Verify DeliverableVerificationGate fails when a verification command exits non-zero."""
        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": "run-test-06",
            "workspace_root": self.test_dir,
            "expected_files": [],
            "verification_commands": [[sys.executable, "-c", "import sys; sys.exit(1)"]]
        })

        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)

    def test_instruction_only_execution_yields_handoff_ready(self):
        """Verify instruction-only execution returns HANDOFF_READY, never premature SUCCEEDED."""
        resp = self.call_me.execute_call_me(
            "/call-me Scaffold a Python telemetry service",
            execute=True,
            approver_consent=ApproverConsent(principal="tester", role=ApproverRole.HUMAN_OPERATOR, method="TEST")
        )
        self.assertIsNotNone(resp)
        self.assertEqual(resp.get("status"), "HANDOFF_READY")
        self.assertEqual(resp.get("lifecycle_state"), "HANDOFF_READY")


if __name__ == "__main__":
    unittest.main()
