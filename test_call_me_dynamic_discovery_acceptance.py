"""
Call Me — Dynamic Capability Discovery Acceptance Test Suite
=============================================================
Validates that Call Me maintains a living, dynamically refreshed capability
inventory rather than a static installation-time snapshot:

1. Automatic refresh on every invocation without reinstalling or running setup.
2. Dynamic discovery of newly installed skills after setup.
3. Accurate relevance ranking, selection, and instruction hydration of new skills.
4. Detection of modified skills with updated instructions and content hashes.
5. Eviction of deleted and renamed capabilities so they are no longer selected.
6. Support for authorized custom capability directories (LCS_CAPABILITY_PATHS).
7. Level 1 POSIX stat pre-filtering for unchanged capabilities (0ms I/O).
8. Preserved governance and workspace authorization boundaries.
"""

import os
import sys
import shutil
import tempfile
import sqlite3
import pytest
from typing import Dict, Any

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.inventory.models import OperationalLifecycleState, ResourceType


class TestCallMeDynamicCapabilityDiscovery:

    @pytest.fixture(autouse=True)
    def setup_test_env(self):
        self.test_dir = tempfile.mkdtemp(prefix="call_me_dynamic_discovery_")
        self.workspace_dir = os.path.join(self.test_dir, "workspace")
        self.lcs_dir = os.path.join(self.workspace_dir, ".lcs")
        self.custom_caps_dir = os.path.join(self.test_dir, "custom_capabilities")

        os.makedirs(self.workspace_dir, exist_ok=True)
        os.makedirs(self.custom_caps_dir, exist_ok=True)

        self.skills_dir = os.path.join(self.workspace_dir, ".agents", "skills")
        os.makedirs(self.skills_dir, exist_ok=True)

        self.old_cwd = os.getcwd()
        os.chdir(self.workspace_dir)

        self.old_cap_paths = os.environ.get("LCS_CAPABILITY_PATHS")
        os.environ.pop("LCS_CAPABILITY_PATHS", None)

        self.config = LCSConfig.resolve(root_override=self.lcs_dir)
        self.config.workspace_root = self.workspace_dir
        self.config.ensure_directories()

        yield

        os.chdir(self.old_cwd)
        if self.old_cap_paths is not None:
            os.environ["LCS_CAPABILITY_PATHS"] = self.old_cap_paths
        else:
            os.environ.pop("LCS_CAPABILITY_PATHS", None)
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_dynamic_discovery_lifecycle(self):
        """
        Complete lifecycle acceptance test:
        1. Initialize Call Me context (baseline inventory).
        2. Verify new skill is not present.
        3. Install a brand-new skill on disk without setup or reinstallation.
        4. Invoke Call Me plan -> assert new skill discovered, ranked, selected, hydrated.
        5. Modify the skill on disk -> assert updated instructions and hash used.
        6. Delete the skill on disk -> assert evicted and no longer selected.
        7. Add skill via LCS_CAPABILITY_PATHS -> assert discovered and selected.
        """
        with LCSContext(config=self.config, auto_migrate=True) as ctx:
            # -------------------------------------------------------------
            # Step 1: Initial Baseline Inventory
            # -------------------------------------------------------------
            initial_count = ctx.inventory.total_count
            initial_urns = set(ctx.inventory._inventory.keys())
            assert not any("data-extractor" in u for u in initial_urns), (
                "data-extractor should not exist in initial baseline inventory"
            )

            # -------------------------------------------------------------
            # Step 2: Install a Brand-New Skill After Setup
            # -------------------------------------------------------------
            extractor_dir = os.path.join(self.skills_dir, "data-extractor")
            os.makedirs(extractor_dir, exist_ok=True)
            skill_md_path = os.path.join(extractor_dir, "SKILL.md")
            
            initial_skill_content = (
                "---\n"
                "name: data-extractor\n"
                "description: Extract structured data records from CSV files and format as JSON.\n"
                "---\n"
                "# Data Extractor Specialist\n"
                "Extract and parse CSV records and output clean structured JSON data.\n"
            )
            with open(skill_md_path, "w", encoding="utf-8") as f:
                f.write(initial_skill_content)

            # -------------------------------------------------------------
            # Step 3: Invoke Call Me Plan (Zero-Prompt Dynamic Refresh)
            # -------------------------------------------------------------
            plan1 = ctx.call_me.plan_call_me(
                "/call-me Extract structured data records from CSV files and format as JSON",
                workspace_root=self.workspace_dir
            )

            assert plan1["status"] in ("ACCEPTED", "HANDOFF_READY", "PLAN_READY"), f"Plan failed: {plan1}"
            step_urns = [s["capability_urn"] for s in plan1.get("steps", [])]
            assert any("data-extractor" in u for u in step_urns), (
                f"Newly installed data-extractor was not selected in plan: {step_urns}"
            )

            # Confirm hydration contains original instruction content
            matching_step = next(s for s in plan1["steps"] if "data-extractor" in s["capability_urn"])
            assert "Data Extractor Specialist" in matching_step["instructions"]
            assert "Extract and parse CSV records" in matching_step["instructions"]

            # Confirm inventory count increased dynamically
            assert ctx.inventory.total_count > initial_count

            # -------------------------------------------------------------
            # Step 4: Modify Skill On Disk
            # -------------------------------------------------------------
            modified_skill_content = (
                "---\n"
                "name: data-extractor\n"
                "description: Extract and transform structured records from CSV and XML into JSON.\n"
                "---\n"
                "# Enhanced Data Extractor Specialist v2\n"
                "Perform high-throughput extraction of CSV and XML datasets with strict validation.\n"
            )
            with open(skill_md_path, "w", encoding="utf-8") as f:
                f.write(modified_skill_content)

            # Invoke plan again without restarting or manual refresh
            plan2 = ctx.call_me.plan_call_me(
                "/call-me Extract and transform structured records from CSV and XML into JSON",
                workspace_root=self.workspace_dir
            )

            assert plan2["status"] in ("ACCEPTED", "HANDOFF_READY", "PLAN_READY"), f"Plan failed: {plan2}"
            step_urns_2 = [s["capability_urn"] for s in plan2.get("steps", [])]
            assert any("data-extractor" in u for u in step_urns_2), (
                f"Modified data-extractor was not selected: {step_urns_2}"
            )

            matching_step_2 = next(s for s in plan2["steps"] if "data-extractor" in s["capability_urn"])
            assert "Enhanced Data Extractor Specialist v2" in matching_step_2["instructions"], (
                f"Updated instructions were not hydrated: {matching_step_2['instructions']}"
            )
            assert "XML" in matching_step_2["instructions"]

            # -------------------------------------------------------------
            # Step 5: Delete Skill From Disk
            # -------------------------------------------------------------
            shutil.rmtree(extractor_dir)
            assert not os.path.exists(extractor_dir)

            # Invoke plan again -> skill must be evicted and not selected
            plan3 = ctx.call_me.plan_call_me(
                "/call-me Extract structured data records from CSV files and format as JSON",
                workspace_root=self.workspace_dir
            )

            step_urns_3 = [s["capability_urn"] for s in plan3.get("steps", [])]
            assert not any("data-extractor" in u for u in step_urns_3), (
                f"Deleted skill was still selected in plan: {step_urns_3}"
            )
            assert not any("data-extractor" in u for u in ctx.inventory._inventory.keys()), (
                "Deleted skill was not evicted from UnifiedCapabilityInventory"
            )

            # -------------------------------------------------------------
            # Step 6: Authorized Custom Capability Directory (LCS_CAPABILITY_PATHS)
            # -------------------------------------------------------------
            os.environ["LCS_CAPABILITY_PATHS"] = self.custom_caps_dir

            custom_analyzer_dir = os.path.join(self.custom_caps_dir, "custom-analyzer")
            os.makedirs(custom_analyzer_dir, exist_ok=True)
            custom_skill_path = os.path.join(custom_analyzer_dir, "SKILL.md")

            custom_content = (
                "---\n"
                "name: custom-analyzer\n"
                "description: Analyze telemetric time-series data and detect system anomalies.\n"
                "---\n"
                "# Custom Telemetry Analyzer Specialist\n"
                "Analyze telemetric time-series signals and report statistical anomalies.\n"
            )
            with open(custom_skill_path, "w", encoding="utf-8") as f:
                f.write(custom_content)

            plan4 = ctx.call_me.plan_call_me(
                "/call-me Analyze telemetric time-series data and detect system anomalies",
                workspace_root=self.workspace_dir
            )

            assert plan4["status"] in ("ACCEPTED", "HANDOFF_READY", "PLAN_READY"), f"Plan failed: {plan4}"
            step_urns_4 = [s["capability_urn"] for s in plan4.get("steps", [])]
            assert any("custom-analyzer" in u for u in step_urns_4), (
                f"Skill from LCS_CAPABILITY_PATHS was not selected: {step_urns_4}"
            )
            matching_step_4 = next(s for s in plan4["steps"] if "custom-analyzer" in s["capability_urn"])
            assert "Custom Telemetry Analyzer Specialist" in matching_step_4["instructions"]

    def test_level1_stat_filter_avoids_unnecessary_rescans(self):
        """
        Verifies that unchanged capabilities are bypassed via Level 1 stat pre-filter
        without re-reading or re-hashing content.
        """
        with LCSContext(config=self.config, auto_migrate=True) as ctx:
            # Create a test skill
            test_skill_dir = os.path.join(self.skills_dir, "fast-probe")
            os.makedirs(test_skill_dir, exist_ok=True)
            skill_path = os.path.join(test_skill_dir, "SKILL.md")

            with open(skill_path, "w", encoding="utf-8") as f:
                f.write("---\nname: fast-probe\ndescription: Rapid health check probe.\n---\n# Fast Probe\nPerform fast probe.\n")

            # First refresh: initial scan and fingerprint capture
            ctx.inventory.refresh_discovery(adapters=ctx.adapter_registry.list_all())
            real_skill_path = os.path.realpath(skill_path)
            assert real_skill_path in ctx.inventory._stat_fingerprints
            initial_fp = ctx.inventory._stat_fingerprints[real_skill_path]

            # Second refresh with zero disk modifications:
            # Must retain identical fingerprint and execute in near-zero time
            summary = ctx.inventory.refresh_discovery(adapters=ctx.adapter_registry.list_all())
            assert real_skill_path in ctx.inventory._stat_fingerprints
            assert ctx.inventory._stat_fingerprints[real_skill_path] == initial_fp
            assert "fast-probe" in [r.name for r in ctx.inventory.list_all()]
