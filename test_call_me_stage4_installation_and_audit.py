"""
Call Me — Stage 4 Installation and Audit Persistence Test Suite
==============================================================
Verifies:
1. Persistent verification in SQLite and CAS surviving process/context restart.
2. Fabricated / un-planned run ID rejection.
3. Failed deliverable verification persistence with truthful FAILED state.
4. Cryptographic binding of deliverable artifact SHA-256 digests.
5. install.sh, install.ps1, and uninstall.sh script presence, permissions, and structure.
"""

import os
import sys
import shutil
import tempfile
import unittest
import sqlite3

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.verification.persistence import VerificationAuditStore


class TestCallMeStage4InstallationAndAudit(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="call_me_stage4_test_")
        self.workspace = os.path.join(self.test_dir, "workspace")
        os.makedirs(self.workspace, exist_ok=True)
        self.cfg = LCSConfig.resolve(root_override=self.workspace)
        self.ctx = LCSContext(config=self.cfg)

    def tearDown(self):
        if hasattr(self, "ctx") and self.ctx:
            self.ctx.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_installer_scripts_structure_and_permissions(self):
        repo_dir = os.path.dirname(os.path.abspath(__file__))
        install_sh = os.path.join(repo_dir, "install.sh")
        install_ps1 = os.path.join(repo_dir, "install.ps1")
        uninstall_sh = os.path.join(repo_dir, "uninstall.sh")

        # 1. install.sh
        self.assertTrue(os.path.isfile(install_sh), "install.sh must exist")
        self.assertTrue(os.access(install_sh, os.X_OK), "install.sh must be executable")
        with open(install_sh, "r", encoding="utf-8") as f:
            content_sh = f.read()
        self.assertIn("PYTHON_CANDIDATES", content_sh)
        self.assertIn("call-me", content_sh)
        self.assertIn("lcs", content_sh)
        self.assertIn("venv", content_sh)
        self.assertIn("setup --repair", content_sh)

        # 2. install.ps1
        self.assertTrue(os.path.isfile(install_ps1), "install.ps1 must exist")
        with open(install_ps1, "r", encoding="utf-8") as f:
            content_ps1 = f.read()
        self.assertIn("call-me.cmd", content_ps1)
        self.assertIn("lcs.cmd", content_ps1)
        self.assertIn("setup --repair", content_ps1)

        # 3. uninstall.sh
        self.assertTrue(os.path.isfile(uninstall_sh), "uninstall.sh must exist")
        self.assertTrue(os.access(uninstall_sh, os.X_OK), "uninstall.sh must be executable")
        with open(uninstall_sh, "r", encoding="utf-8") as f:
            content_un = f.read()
        self.assertIn("uninstall-command", content_un)
        self.assertIn("--purge", content_un)

    def test_persistent_verification_survives_restart_and_retrieves_by_run_id(self):
        # 1. Plan task (registers authentic run_id)
        plan_packet = self.ctx.call_me.plan_call_me(
            raw_message="Build a Python telemetry service",
            workspace_root=self.workspace
        )
        run_id = plan_packet["request_id"]
        self.assertTrue(VerificationAuditStore.is_run_registered(self.ctx.conn, run_id))

        # 2. Create physical deliverables
        main_py = os.path.join(self.workspace, "main.py")
        test_py = os.path.join(self.workspace, "test_telemetry.py")
        with open(main_py, "w") as f:
            f.write("# Telemetry service\ndef health(): return {'status': 'healthy'}\n")
        with open(test_py, "w") as f:
            f.write("import unittest\nfrom main import health\n\nclass TestHealth(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(health()['status'], 'healthy')\n\nif __name__ == '__main__': unittest.main()\n")

        # 3. Verify deliverables
        res = self.ctx.call_me.verify_deliverables(
            run_id=run_id,
            expected_files=["main.py", "test_telemetry.py"],
            verification_commands=["python3 -m unittest test_telemetry.py"],
            workspace_root=self.workspace
        )
        self.assertTrue(res["is_verified"])
        self.assertEqual(res["verification_state"], "VERIFIED")
        self.assertIsNotNone(res["cas_receipt_digest"])

        # 4. Simulate process restart: close context and open fresh context
        self.ctx.close()
        fresh_ctx = LCSContext(config=self.cfg)
        try:
            persisted = fresh_ctx.call_me.get_verification_receipt(run_id)
            self.assertIsNotNone(persisted, "Persisted receipt must survive process restart")
            self.assertEqual(persisted["run_id"], run_id)
            self.assertTrue(persisted["is_verified"])
            self.assertEqual(persisted["verification_state"], "VERIFIED")
            self.assertIn("main.py", persisted["file_digests"])
            self.assertIn("test_telemetry.py", persisted["file_digests"])
            self.assertEqual(persisted["cas_receipt_digest"], res["cas_receipt_digest"])
        finally:
            fresh_ctx.close()

    def test_fabricated_run_id_rejected_and_persisted_as_failed(self):
        # Create physical deliverable but use unregistered/fabricated run ID
        main_py = os.path.join(self.workspace, "main.py")
        with open(main_py, "w") as f:
            f.write("print('hello')\n")

        fabricated_id = "req-fabricated-unregistered-9999"
        self.assertFalse(VerificationAuditStore.is_run_registered(self.ctx.conn, fabricated_id))

        res = self.ctx.call_me.verify_deliverables(
            run_id=fabricated_id,
            expected_files=["main.py"],
            workspace_root=self.workspace
        )
        self.assertFalse(res["is_verified"])
        self.assertEqual(res["verification_state"], "FAILED")

        # Confirm failure was durably persisted
        persisted = self.ctx.call_me.get_verification_receipt(fabricated_id)
        self.assertIsNotNone(persisted)
        self.assertFalse(persisted["is_verified"])
        self.assertEqual(persisted["verification_state"], "FAILED")
        self.assertTrue(any("fabricated" in str(e["details"]).lower() for e in persisted["evidence"]))

    def test_failed_tests_persist_truthfully(self):
        # Plan valid run
        plan = self.ctx.call_me.plan_call_me(
            raw_message="Build a service",
            workspace_root=self.workspace
        )
        run_id = plan["request_id"]

        # Create failing test
        main_py = os.path.join(self.workspace, "main.py")
        test_py = os.path.join(self.workspace, "test_telemetry.py")
        with open(main_py, "w") as f:
            f.write("def health(): return 500\n")
        with open(test_py, "w") as f:
            f.write("import unittest\nfrom main import health\n\nclass TestFail(unittest.TestCase):\n    def test_fail(self):\n        self.assertEqual(health(), 200)\n\nif __name__ == '__main__': unittest.main()\n")

        res = self.ctx.call_me.verify_deliverables(
            run_id=run_id,
            expected_files=["main.py", "test_telemetry.py"],
            verification_commands=["python3 -m unittest test_telemetry.py"],
            workspace_root=self.workspace
        )
        self.assertFalse(res["is_verified"])
        self.assertEqual(res["verification_state"], "FAILED")

        persisted = self.ctx.call_me.get_verification_receipt(run_id)
        self.assertIsNotNone(persisted)
        self.assertFalse(persisted["is_verified"])
        self.assertEqual(persisted["verification_state"], "FAILED")


if __name__ == "__main__":
    unittest.main()
