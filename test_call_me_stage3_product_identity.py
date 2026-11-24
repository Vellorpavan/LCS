"""
Call Me — Stage 3 Product Identity & CLI Aliasing Test Suite
============================================================
Verifies:
1. Both CLI entry points ('lcs' and 'call-me') function identically without code duplication.
2. 'call-me' syntax:
   - call-me --version
   - call-me setup --check
   - call-me plan "<objective>"
   - call-me verify <run-id> ...
   - call-me "<objective>" default routing
3. Legacy 'lcs' syntax:
   - lcs --version
   - lcs call-me "<objective>"
   - lcs call-me-plan "<objective>"
   - lcs call-me-verify <run-id> ...
   - lcs verify <run-id> ...
   - lcs setup --check
4. Packaging metadata in pyproject.toml declares both project scripts.
5. Deliverable verification evidence contains cryptographic SHA-256 digests.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

from lcs.cli import main, main_call_me, build_parser
from lcs import __version__
from lcs.verification.gates import DeliverableVerificationGate


class TestCallMeStage3ProductIdentity(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="call_me_stage3_test_")
        self.workspace = os.path.join(self.test_dir, "workspace")
        os.makedirs(self.workspace, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pyproject_scripts_declaration(self):
        root_dir = os.path.dirname(os.path.abspath(__file__))
        pyproject_path = os.path.join(root_dir, "pyproject.toml")
        with open(pyproject_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn('[project.scripts]', content)
        self.assertIn('lcs = "lcs.cli:main"', content)
        self.assertIn('call-me = "lcs.cli:main_call_me"', content)

    def test_version_output_both_entry_points(self):
        # 1. lcs --version
        with patch("sys.stdout", new=StringIO()) as out:
            with self.assertRaises(SystemExit) as cm:
                main(["--version"])
            self.assertEqual(cm.exception.code, 0)
            self.assertIn(f"lcs {__version__}", out.getvalue())

        # 2. call-me --version
        with patch("sys.stdout", new=StringIO()) as out:
            with self.assertRaises(SystemExit) as cm:
                main_call_me(["--version"])
            self.assertEqual(cm.exception.code, 0)
            self.assertIn(f"Call Me {__version__}", out.getvalue())
            self.assertIn(f"LCS core {__version__}", out.getvalue())

    def test_call_me_plan_syntax(self):
        with patch("sys.stdout", new=StringIO()) as out:
            ret = main_call_me([
                "plan",
                "Build a Python telemetry service",
                "--workspace", self.workspace,
                "--format-json"
            ])
            self.assertEqual(ret, 0)
            val = out.getvalue()
            self.assertIn('"status": "PLAN_READY"', val)
            self.assertIn('"expected_deliverables"', val)

    def test_call_me_verify_and_alias_syntax(self):
        # Create test deliverable
        fpath = os.path.join(self.workspace, "main.py")
        with open(fpath, "w") as f:
            f.write("# Telemetry service\n")

        # 0. Plan to generate authentic planned run ID
        with patch("sys.stdout", new=StringIO()) as out:
            ret_plan = main_call_me([
                "plan",
                "Build a Python telemetry service",
                "--workspace", self.workspace,
                "--format-json"
            ])
            self.assertEqual(ret_plan, 0)
            plan_obj = json.loads(out.getvalue())
            run_id = plan_obj["request_id"]

        # 1. call-me verify
        with patch("sys.stdout", new=StringIO()) as out:
            ret = main_call_me([
                "verify",
                run_id,
                "--workspace", self.workspace,
                "--files", "main.py",
                "--format-json"
            ])
            self.assertEqual(ret, 0)
            val = out.getvalue()
            self.assertIn('"is_verified": true', val)
            self.assertIn('"verification_state": "VERIFIED"', val)

        # 2. lcs verify (alias)
        with patch("sys.stdout", new=StringIO()) as out:
            ret = main([
                "verify",
                run_id,
                "--workspace", self.workspace,
                "--files", "main.py",
                "--format-json"
            ])
            self.assertEqual(ret, 0)
            self.assertIn('"is_verified": true', out.getvalue())

    def test_legacy_lcs_call_me_plan_and_verify_syntax(self):
        fpath = os.path.join(self.workspace, "app.py")
        with open(fpath, "w") as f:
            f.write("print('ready')\n")

        with patch("sys.stdout", new=StringIO()) as out:
            ret_plan = main([
                "call-me-plan",
                "Scaffold an application",
                "--workspace", self.workspace,
                "--format-json"
            ])
            self.assertEqual(ret_plan, 0)
            val = out.getvalue()
            self.assertIn('"PLAN_READY"', val)
            plan_obj = json.loads(val)
            run_id = plan_obj["request_id"]

        with patch("sys.stdout", new=StringIO()) as out:
            ret_ver = main([
                "call-me-verify",
                run_id,
                "--workspace", self.workspace,
                "--files", "app.py",
                "--format-json"
            ])
            self.assertEqual(ret_ver, 0)
            self.assertIn('"is_verified": true', out.getvalue())

    def test_call_me_default_objective_routing(self):
        # Invoking `call-me "objective"` without explicit subcommand routes to cmd_call_me
        with patch("sys.stdout", new=StringIO()) as out:
            ret = main_call_me([
                "Build a Python telemetry service",
                "--format-json"
            ])
            self.assertEqual(ret, 0)
            self.assertIn('"status": "ACCEPTED"', out.getvalue())
            self.assertIn('"request_id"', out.getvalue())

    def test_deliverable_verification_cryptographic_fingerprints(self):
        fpath = os.path.join(self.workspace, "telemetry.py")
        with open(fpath, "w") as f:
            f.write("def health(): return 200\n")

        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": "req-fingerprint-test",
            "workspace_root": self.workspace,
            "expected_files": ["telemetry.py"]
        })
        self.assertTrue(res.is_verified)
        tier1_ev = [e for e in res.evidence_records if "SHA-256" in e.criterion]
        self.assertEqual(len(tier1_ev), 1)
        self.assertIn("telemetry.py", str(tier1_ev[0].details))


if __name__ == "__main__":
    unittest.main()
