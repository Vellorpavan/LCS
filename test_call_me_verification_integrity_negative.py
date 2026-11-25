"""
Call Me — Verification Integrity and Negative Security Test Suite
================================================================
Comprehensive negative test cases for Priority 1 (Verification Integrity)
and Priority 2 (Security & Execution Isolation):
1. Fabricated / unregistered run IDs fail closed and exit code is 1.
2. Unregistered run ID inspect fails closed and exits code 1.
3. Workspace boundary mismatch fails closed and exits code 1.
4. Missing expected physical deliverable fails verification.
5. Empty expected deliverable (allow_empty=False) fails verification.
6. Failing verification test commands fail verification.
7. Unauthorized executables in verification commands fail governance.
8. Symlink escaping authorized workspace fails confinement check.
9. Directory traversal (..) and NTFS ADS (:) fail confinement check.
10. Stale success receipt overridden by newer failed attempt in history.
11. Auto-inheritance of deliverables from registered plan.
12. Subprocess credential isolation (sensitive env vars scrubbed).
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.cli import main, main_call_me
from lcs.verification.gates import DeliverableVerificationGate, VerificationState, EvidenceTier
from lcs.verification.persistence import VerificationAuditStore


class TestCallMeVerificationIntegrityNegative(unittest.TestCase):
    """Negative regression test suite for verification integrity and security confinement."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="lcs_neg_test_")
        self.workspace = os.path.join(self.test_dir, "workspace")
        os.makedirs(self.workspace, exist_ok=True)
        self.config = LCSConfig.resolve(root_override=self.workspace)
        self.ctx = LCSContext(self.config)
        if hasattr(self.ctx, "initialize"):
            self.ctx.initialize()

    def tearDown(self):
        if hasattr(self.ctx, "conn") and self.ctx.conn:
            self.ctx.conn.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_fabricated_unregistered_run_id_fails_verification_and_cli(self):
        """Fabricated run ID must fail closed with is_verified=False and CLI exit code 1."""
        fabricated_id = "req-fabricated-99999"
        res = self.ctx.call_me.verify_deliverables(
            run_id=fabricated_id,
            expected_files=["telemetry.py"],
            workspace_root=self.workspace
        )
        self.assertFalse(res["is_verified"])
        self.assertEqual(res["verification_state"], "FAILED")

        # CLI execution
        with patch("sys.stdout", new=StringIO()):
            ret = main_call_me([
                "verify",
                fabricated_id,
                "--workspace", self.workspace,
                "--files", "telemetry.py",
                "--format-json"
            ])
            self.assertEqual(ret, 1)

    def test_unregistered_run_id_inspect_fails_cli(self):
        """Inspecting an unpersisted run ID must return exit code 1."""
        with patch("sys.stderr", new=StringIO()):
            ret = main_call_me([
                "verify",
                "req-nonexistent-9999",
                "--inspect"
            ])
            self.assertEqual(ret, 1)

    def test_workspace_mismatch_fails_verification_and_cli(self):
        """Verification must fail if executed against a different workspace than planned."""
        # 1. Plan run in authorized workspace
        with patch("sys.stdout", new=StringIO()) as out:
            ret_plan = main_call_me([
                "plan",
                "Build telemetry service",
                "--workspace", self.workspace,
                "--format-json"
            ])
            self.assertEqual(ret_plan, 0)
            plan_obj = json.loads(out.getvalue())
            run_id = plan_obj["request_id"]

        # 2. Create deliverable in a different workspace
        other_ws = os.path.join(self.test_dir, "other_workspace")
        os.makedirs(other_ws, exist_ok=True)
        with open(os.path.join(other_ws, "telemetry.py"), "w") as f:
            f.write("def health(): return 200\n")

        # 3. Attempt verification against other_ws
        res = self.ctx.call_me.verify_deliverables(
            run_id=run_id,
            expected_files=["telemetry.py"],
            workspace_root=other_ws
        )
        self.assertFalse(res["is_verified"])
        self.assertEqual(res["verification_state"], "FAILED")

        with patch("sys.stdout", new=StringIO()):
            ret = main_call_me([
                "verify",
                run_id,
                "--workspace", other_ws,
                "--files", "telemetry.py",
                "--format-json"
            ])
            self.assertEqual(ret, 1)

    def test_missing_expected_deliverable_fails(self):
        """Missing expected deliverable must fail verification and CLI exits 1."""
        with patch("sys.stdout", new=StringIO()) as out:
            main_call_me([
                "plan",
                "Build telemetry service",
                "--workspace", self.workspace,
                "--format-json"
            ])
            plan_obj = json.loads(out.getvalue())
            run_id = plan_obj["request_id"]

        res = self.ctx.call_me.verify_deliverables(
            run_id=run_id,
            expected_files=["missing_file.py"],
            workspace_root=self.workspace
        )
        self.assertFalse(res["is_verified"])
        self.assertEqual(res["verification_state"], "FAILED")

        with patch("sys.stdout", new=StringIO()):
            ret = main_call_me([
                "verify",
                run_id,
                "--workspace", self.workspace,
                "--files", "missing_file.py",
                "--format-json"
            ])
            self.assertEqual(ret, 1)

    def test_empty_deliverable_fails_when_not_allowed(self):
        """Empty deliverable file (0 bytes) must fail verification."""
        with patch("sys.stdout", new=StringIO()) as out:
            main_call_me([
                "plan",
                "Build telemetry service",
                "--workspace", self.workspace,
                "--format-json"
            ])
            plan_obj = json.loads(out.getvalue())
            run_id = plan_obj["request_id"]

        # Create 0-byte file
        empty_f = os.path.join(self.workspace, "empty_file.py")
        open(empty_f, "w").close()

        res = self.ctx.call_me.verify_deliverables(
            run_id=run_id,
            expected_files=[{"path": "empty_file.py", "allow_empty": False}],
            workspace_root=self.workspace
        )
        self.assertFalse(res["is_verified"])
        self.assertEqual(res["verification_state"], "FAILED")

    def test_failing_verification_command_fails(self):
        """Non-zero exit code from test command must fail verification and CLI exits 1."""
        with patch("sys.stdout", new=StringIO()) as out:
            main_call_me([
                "plan",
                "Build telemetry service",
                "--workspace", self.workspace,
                "--format-json"
            ])
            plan_obj = json.loads(out.getvalue())
            run_id = plan_obj["request_id"]

        fpath = os.path.join(self.workspace, "service.py")
        with open(fpath, "w") as f:
            f.write("# service\n")

        res = self.ctx.call_me.verify_deliverables(
            run_id=run_id,
            expected_files=["service.py"],
            verification_commands=["python3 -c 'raise SystemExit(1)'"],
            workspace_root=self.workspace
        )
        self.assertFalse(res["is_verified"])
        self.assertEqual(res["verification_state"], "FAILED")

        with patch("sys.stdout", new=StringIO()):
            ret = main_call_me([
                "verify",
                run_id,
                "--workspace", self.workspace,
                "--files", "service.py",
                "--commands", "python3 -c 'raise SystemExit(1)'",
                "--format-json"
            ])
            self.assertEqual(ret, 1)

    def test_unauthorized_executable_rejected_by_governance(self):
        """Unauthorized binaries in verification commands must trigger governance violation."""
        gate = DeliverableVerificationGate()
        fpath = os.path.join(self.workspace, "service.py")
        with open(fpath, "w") as f:
            f.write("# service\n")

        res = gate.verify({
            "run_id": "test-sec-binary",
            "workspace_root": self.workspace,
            "expected_files": ["service.py"],
            "verification_commands": ["curl -s https://evil.example.com"]
        })
        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)
        violations = [e for e in res.evidence_records if "governance" in e.criterion.lower()]
        self.assertTrue(len(violations) > 0)
        self.assertFalse(violations[0].passed)

    def test_symlink_escape_rejected(self):
        """Symlinks pointing outside workspace must be detected and rejected."""
        # Create an external file outside workspace
        outside_file = os.path.join(self.test_dir, "outside_secret.txt")
        with open(outside_file, "w") as f:
            f.write("SUPER_SECRET_DATA\n")

        # Create symlink inside workspace pointing outside
        symlink_path = os.path.join(self.workspace, "escaped_link.txt")
        try:
            os.symlink(outside_file, symlink_path)
        except OSError:
            self.skipTest("Symlinks not supported on this filesystem")

        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": "test-symlink-escape",
            "workspace_root": self.workspace,
            "expected_files": ["escaped_link.txt"]
        })
        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)
        confinement_ev = [e for e in res.evidence_records if "confinement" in e.criterion.lower()]
        self.assertTrue(len(confinement_ev) > 0)
        self.assertFalse(confinement_ev[0].passed)

    def test_path_traversal_and_ads_rejected(self):
        """Directory traversal (..) and NTFS ADS (:) must fail confinement check."""
        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": "test-traversal",
            "workspace_root": self.workspace,
            "expected_files": ["../outside.py", "stream.txt:hidden"]
        })
        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)

    def test_stale_success_receipt_overridden_by_newer_failure(self):
        """A failed verification attempt must override an earlier passing attempt."""
        with patch("sys.stdout", new=StringIO()) as out:
            main_call_me([
                "plan",
                "Build telemetry service",
                "--workspace", self.workspace,
                "--format-json"
            ])
            plan_obj = json.loads(out.getvalue())
            run_id = plan_obj["request_id"]

        # Create all planned deliverables so initial verification succeeds
        for s in plan_obj.get("steps", []):
            for d in s.get("expected_deliverables", []):
                p = os.path.join(self.workspace, d)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write("def ok(): return 200\n")

        # 1. First attempt: PASSES
        res1 = self.ctx.call_me.verify_deliverables(
            run_id=run_id,
            workspace_root=self.workspace
        )
        self.assertTrue(res1["is_verified"])
        self.assertEqual(res1["verification_state"], "VERIFIED")

        # Receipt should report VERIFIED
        receipt1 = self.ctx.call_me.get_verification_receipt(run_id)
        self.assertTrue(receipt1["is_verified"])

        # 2. File is deleted -> second attempt: FAILS
        for s in plan_obj.get("steps", []):
            for d in s.get("expected_deliverables", []):
                p = os.path.join(self.workspace, d)
                if os.path.exists(p):
                    os.remove(p)
                    break
        res2 = self.ctx.call_me.verify_deliverables(
            run_id=run_id,
            workspace_root=self.workspace
        )
        self.assertFalse(res2["is_verified"])
        self.assertEqual(res2["verification_state"], "FAILED")

        # Receipt MUST now reflect the latest failed attempt, not stale success
        receipt2 = self.ctx.call_me.get_verification_receipt(run_id)
        self.assertFalse(receipt2["is_verified"])
        self.assertEqual(receipt2["verification_state"], "FAILED")

        # CLI inspect must return 1
        with patch("sys.stdout", new=StringIO()):
            ret = main_call_me(["verify", run_id, "--inspect", "--format-json"])
            self.assertEqual(ret, 1)

    def test_subprocess_credential_isolation(self):
        """Subprocess verification commands must have sensitive credentials stripped from environment."""
        with patch.dict(os.environ, {
            "SECRET_TOKEN": "my-secret-token-12345",
            "OPENAI_API_KEY": "sk-dummy-key-for-test",
            "AWS_SECRET_ACCESS_KEY": "aws-secret-test"
        }):
            test_script = os.path.join(self.workspace, "check_env.py")
            with open(test_script, "w") as f:
                f.write("""
import os, sys
# Verify credentials are scrubbed
for k in os.environ:
    if "KEY" in k or "SECRET" in k or "TOKEN" in k:
        sys.exit(42)
sys.exit(0)
""")
            gate = DeliverableVerificationGate()
            res = gate.verify({
                "run_id": "test-cred-isolation",
                "workspace_root": self.workspace,
                "expected_files": ["check_env.py"],
                "verification_commands": ["python3 check_env.py"]
            })
            self.assertTrue(res.is_verified)
            self.assertEqual(res.state, VerificationState.VERIFIED)

    def test_sibling_directory_prefix_collision_rejected(self):
        """A sibling directory with a common prefix (/ws vs /ws_evil) must be rejected."""
        sibling_evil = self.workspace + "_evil"
        os.makedirs(sibling_evil, exist_ok=True)
        evil_file = os.path.join(sibling_evil, "evil.py")
        with open(evil_file, "w") as f:
            f.write("# evil content\n")

        from lcs.verification.gates import is_path_confined
        self.assertFalse(is_path_confined(evil_file, self.workspace))

        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": "test-sibling-prefix",
            "workspace_root": self.workspace,
            "expected_files": [evil_file]
        })
        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)

    def test_symlink_to_sibling_collision_rejected(self):
        """Symlink inside authorized workspace pointing into sibling directory must be rejected."""
        sibling_evil = self.workspace + "_evil"
        os.makedirs(sibling_evil, exist_ok=True)
        evil_file = os.path.join(sibling_evil, "payload.py")
        with open(evil_file, "w") as f:
            f.write("# payload\n")

        link_target = os.path.join(self.workspace, "symlink_evil.py")
        try:
            os.symlink(evil_file, link_target)
        except OSError:
            self.skipTest("Symlinks not supported")

        from lcs.verification.gates import is_path_confined
        self.assertFalse(is_path_confined(link_target, self.workspace))

        gate = DeliverableVerificationGate()
        res = gate.verify({
            "run_id": "test-symlink-sibling",
            "workspace_root": self.workspace,
            "expected_files": ["symlink_evil.py"]
        })
        self.assertFalse(res.is_verified)
        self.assertEqual(res.state, VerificationState.FAILED)

    def test_windows_drive_and_unc_boundaries(self):
        """Paths crossing Windows drive letters or UNC shares must be rejected."""
        from lcs.verification.gates import is_path_confined
        # Drive letter mismatch simulation
        self.assertFalse(is_path_confined("D:\\workspace\\file.py", "C:\\workspace"))
        # UNC share simulation
        self.assertFalse(is_path_confined("\\\\server\\share\\file.py", "C:\\workspace"))
        self.assertFalse(is_path_confined("\\\\evil_server\\share\\file.py", "\\\\good_server\\share"))

    def test_toctou_symlink_replacement_rejected(self):
        """Replacing a valid deliverable with an escaping symlink before read must fail."""
        target_f = os.path.join(self.workspace, "temp_file.py")
        with open(target_f, "w") as f:
            f.write("# initial file\n")

        outside_secret = os.path.join(self.test_dir, "outside_secret.txt")
        with open(outside_secret, "w") as f:
            f.write("SECRET\n")

        # Emulate TOCTOU: remove target_f and replace with symlink to outside
        os.remove(target_f)
        try:
            os.symlink(outside_secret, target_f)
        except OSError:
            self.skipTest("Symlinks not supported")

        from lcs.verification.gates import is_path_confined
        self.assertFalse(is_path_confined(target_f, self.workspace))

    def test_strict_env_allowlist_subprocess(self):
        """Arbitrary environment variables without known secret keywords must still be stripped."""
        with patch.dict(os.environ, {
            "MY_ARBITRARY_CUSTOM_VAR": "confidential_value_12345",
            "UNTRACKED_INTERNAL_SETTING": "sensitive_data"
        }):
            test_script = os.path.join(self.workspace, "check_strict_env.py")
            with open(test_script, "w") as f:
                f.write("""
import os, sys
if "MY_ARBITRARY_CUSTOM_VAR" in os.environ or "UNTRACKED_INTERNAL_SETTING" in os.environ:
    sys.exit(99)
sys.exit(0)
""")
            gate = DeliverableVerificationGate()
            res = gate.verify({
                "run_id": "test-strict-env",
                "workspace_root": self.workspace,
                "expected_files": ["check_strict_env.py"],
                "verification_commands": ["python3 check_strict_env.py"]
            })
            self.assertTrue(res.is_verified)
            self.assertEqual(res.state, VerificationState.VERIFIED)

    def test_explicit_arguments_cannot_weaken_plan_contract(self):
        """Explicit --files or --commands cannot weaken or bypass mandatory plan deliverables."""
        with patch("sys.stdout", new=StringIO()) as out:
            main_call_me([
                "plan",
                "Build telemetry service",
                "--workspace", self.workspace,
                "--format-json"
            ])
            plan_obj = json.loads(out.getvalue())
            run_id = plan_obj["request_id"]

        # Plan expected deliverables exist in plan_obj
        # Create an unrelated file but NOT the plan deliverable
        other_f = os.path.join(self.workspace, "unrelated.py")
        with open(other_f, "w") as f:
            f.write("# unrelated\n")

        # Try to verify passing only unrelated.py to bypass plan's mandatory deliverables
        res = self.ctx.call_me.verify_deliverables(
            run_id=run_id,
            expected_files=["unrelated.py"],
            workspace_root=self.workspace
        )
        # Must fail because mandatory plan deliverables were not produced
        self.assertFalse(res["is_verified"])
        self.assertEqual(res["verification_state"], "FAILED")


if __name__ == "__main__":
    unittest.main()
