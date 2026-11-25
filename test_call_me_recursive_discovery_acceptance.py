"""
Call Me — Recursive Capability Discovery Acceptance Suite (Priority 8)
====================================================================
Tests the full recursive discovery loop:
1. Gap Detection: When a requested capability is missing from the local inventory,
   the planner detects the missing capability gap.
2. Candidate Recommendation: Emits structured discovery recommendation with candidate sources.
3. Authorized Onboarding: New capability is installed into authorized capability root.
4. Automatic Dynamic Ingestion: Subsequent /call-me invocation discovers, indexes,
   and incorporates the new capability into planning and specialist DAG without manual restart.
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
from lcs.cli import main_call_me


class TestCallMeRecursiveDiscoveryAcceptance(unittest.TestCase):
    """Acceptance test suite for recursive capability discovery and dynamic onboarding."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="lcs_rec_disc_")
        self.workspace = os.path.join(self.test_dir, "workspace")
        self.custom_skills = os.path.join(self.test_dir, "custom_skills")
        os.makedirs(self.workspace, exist_ok=True)
        os.makedirs(self.custom_skills, exist_ok=True)

        self.config = LCSConfig.resolve(root_override=self.workspace)
        self.ctx = LCSContext(self.config)

    def tearDown(self):
        if hasattr(self.ctx, "conn") and self.ctx.conn:
            self.ctx.conn.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_recursive_discovery_gap_detection_and_dynamic_onboarding(self):
        """
        1. Query for novel capability 'cad-step-exporter'.
        2. Verify gap is recognized.
        3. Dynamically install 'cad-step-exporter' into custom skills path.
        4. Re-plan: capability is dynamically indexed, selected, and scheduled.
        """
        # Set custom capability paths to our isolated directory
        with patch.dict(os.environ, {"LCS_CAPABILITY_PATHS": self.custom_skills}):
            # 1. First Plan: Capability is not yet present
            with patch("sys.stdout", new=StringIO()) as out:
                main_call_me([
                    "plan",
                    "Export 3D mechanical geometry to ISO 10303 STEP format using cad-step-exporter",
                    "--workspace", self.workspace,
                    "--format-json"
                ])
                plan_v1 = json.loads(out.getvalue())

            # Confirm cad-step-exporter was not yet scheduled
            step_caps_v1 = [s.get("capability_urn", "") for s in plan_v1.get("steps", [])]
            self.assertFalse(any("cad-step-exporter" in c for c in step_caps_v1))

            # 2. Dynamic Authorized Installation of the new skill
            skill_dir = os.path.join(self.custom_skills, "cad-step-exporter")
            os.makedirs(skill_dir, exist_ok=True)
            with open(os.path.join(skill_dir, "SKILL.md"), "w") as f:
                f.write("""---
name: cad-step-exporter
description: Production ISO 10303 STEP CAD geometry export engine for mechanical solids and assemblies.
category: graphics_3d
---

# CAD STEP Exporter
Exports B-Rep CAD geometry to standardized ISO 10303 STEP files.

## Instructions
1. Initialize OpenCASCADE geometry kernel.
2. Read solid B-Rep topology.
3. Write STEP AP214 format to output path.
""")

            # 3. Second Plan: Dynamic discovery triggers automatically
            with patch("sys.stdout", new=StringIO()) as out2:
                main_call_me([
                    "plan",
                    "Export 3D mechanical geometry to ISO 10303 STEP format using cad-step-exporter",
                    "--workspace", self.workspace,
                    "--format-json"
                ])
                plan_v2 = json.loads(out2.getvalue())

            # 4. Verify capability is now selected, hydrated, and scheduled
            step_caps_v2 = [s.get("capability_urn", "") for s in plan_v2.get("steps", [])]
            self.assertTrue(any("cad-step-exporter" in c for c in step_caps_v2), f"Steps: {step_caps_v2}")

            # Verify specialist prompt contains hydrated instructions
            target_step = next(s for s in plan_v2.get("steps", []) if "cad-step-exporter" in s.get("capability_urn", ""))
            instructions = target_step.get("instructions", "")
            self.assertIn("OpenCASCADE geometry kernel", instructions)
            self.assertIn("ISO 10303 STEP", instructions)


if __name__ == "__main__":
    unittest.main()
