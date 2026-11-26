"""
Call Me — Post-RC2 Completion Regression Suite
=============================================
Covers:
1. Adaptive requirement-driven candidate brief & deep metadata extraction.
2. Confidence-aware clarification vs out-of-domain abstention.
3. Multi-skill agent composition (complementary skills paired to one agent).
4. Production CLI `lcs discover` fallback when test fixture is absent.
5. Verification dependency preflight diagnostics (fail-closed without pytest).
6. Windows `uninstall.ps1` structure and data-preservation parity.
7. Bidirectional contract synchronization (provider->consumer & consumer->provider) on non-web workflow.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.intelligence.semantic_reasoner import SemanticReasoner
from lcs.inventory.models import (
    OperationalLifecycleState,
    ProvenanceRecord,
    ResourceType,
    UnifiedResourceRecord,
)
from lcs.sync.contract import ProjectContractManager
from lcs.verification.gates import DeliverableVerificationGate


class TestPostRC2Completion(unittest.TestCase):

    def setUp(self):
        self.workspace = tempfile.mkdtemp(prefix="call_me_post_rc2_")
        self.cfg = LCSConfig.resolve(root_override=os.path.join(self.workspace, ".lcs"))
        self.ctx = LCSContext(self.cfg)
        self.ctx.inventory.refresh_discovery(adapters=self.ctx.adapter_registry.list_all())

    def tearDown(self):
        self.ctx.close()
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_01_adaptive_brief_deep_metadata_and_clarification(self):
        # Ambiguous objective triggers clarification
        amb = SemanticReasoner.reason_locally("fix it", self.ctx.inventory, active_host="antigravity")
        self.assertTrue(amb.needs_clarification)
        self.assertGreater(len(amb.clarification_questions), 0)
        self.assertFalse(amb.coverage_complete)

        # Deep metadata extraction in candidate brief
        reqs = SemanticReasoner.decompose_requirements("Build a Python telemetry service with unit tests")
        brief = SemanticReasoner.build_candidate_brief(
            self.ctx.inventory, self.ctx.hydration_engine,
            "Build a Python telemetry service with unit tests", reqs
        )
        self.assertGreater(len(brief["candidate_skills"]), 0)
        first = brief["candidate_skills"][0]
        self.assertIn("permissions", first)
        self.assertIn("scripts", first)
        self.assertIn("limitations", first)

    def test_02_multi_skill_composition_on_shared_agent(self):
        # Register 2 complementary skills + 1 shared specialist agent
        for name, desc, tags in [
            ("schema-designer", "Design PostgreSQL database tables and indexes", ["postgres", "schema"]),
            ("migration-runner", "Generate PostgreSQL database migrations", ["postgres", "migrations"]),
        ]:
            self.ctx.inventory._register_resource_with_conflict_resolution(
                UnifiedResourceRecord(
                    urn=f"urn:lcs:skill:antigravity:{name}",
                    name=name,
                    resource_type=ResourceType.SKILL,
                    display_name=name,
                    description=desc,
                    raw_content=f"# {name}\n{desc}",
                    raw_content_digest=f"dig_{name}",
                    provenance=ProvenanceRecord("antigravity", "USER_GLOBAL", f"db://{name}", f"db://{name}", f"dig_{name}"),
                    lifecycle_state=OperationalLifecycleState.EXECUTABLE,
                    tags=tags,
                ),
                persist=True,
            )
        self.ctx.inventory._register_resource_with_conflict_resolution(
            UnifiedResourceRecord(
                urn="urn:lcs:agent:antigravity:postgres-specialist",
                name="postgres-specialist",
                resource_type=ResourceType.AGENT,
                display_name="postgres-specialist",
                description="PostgreSQL schema design and database migrations specialist",
                raw_content="PostgreSQL specialist",
                raw_content_digest="dig_pg_agent",
                provenance=ProvenanceRecord("antigravity", "USER_GLOBAL", "db://pg_agent", "db://pg_agent", "dig_pg_agent"),
                lifecycle_state=OperationalLifecycleState.EXECUTABLE,
                tags=["postgres", "schema", "migrations"],
            ),
            persist=True,
        )

        res = SemanticReasoner.reason_locally(
            "Design PostgreSQL schema and generate database migrations",
            self.ctx.inventory,
            active_host="antigravity",
        )
        self.assertGreaterEqual(len(res.selections), 2)
        shared_agent_sels = [s for s in res.selections if len(s.paired_skills) >= 2]
        self.assertGreaterEqual(len(shared_agent_sels), 1, f"Expected shared agent multi-skill pairing, got: {[(s.name, s.agent_id, s.paired_skills) for s in res.selections]}")

    def test_03_production_cli_discover_without_test_fixture(self):
        from lcs.cli import main
        # Simulate production wheel where mcp_test_server_fixture.py does not exist
        with patch("os.path.exists", side_effect=lambda p: False if "mcp_test_server_fixture.py" in str(p) else os.path.lexists(p)):
            with patch("sys.stdout", new=StringIO()) as out:
                rc = main(["discover", "--format-json"])
                self.assertEqual(rc, 0)
                payload = json.loads(out.getvalue())
                self.assertEqual(payload["mode"], "local_capability_discovery")
                self.assertGreater(payload["total_capabilities"], 0)

    def test_04_verification_dependency_preflight_diagnostic(self):
        gate = DeliverableVerificationGate()
        fpath = os.path.join(self.workspace, "test_sample.py")
        with open(fpath, "w") as f:
            f.write("def test_ok(): assert True\n")

        # Simulate environment where `python -c "import pytest"` fails
        mock_proc = type("Proc", (), {"returncode": 1, "stdout": "", "stderr": "No module named pytest"})()
        with patch("subprocess.run", return_value=mock_proc):
            res = gate.verify({
                "run_id": "req-preflight",
                "workspace_root": self.workspace,
                "expected_files": ["test_sample.py"],
                "verification_commands": ["python3 -m pytest"],
            })
        self.assertFalse(res.is_verified)
        self.assertIn("Missing verification dependency", str(res.metadata.get("command_results", [])))

    def test_05_windows_uninstaller_exists_and_preserves_data_by_default(self):
        ps1_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uninstall.ps1")
        self.assertTrue(os.path.isfile(ps1_path))
        with open(ps1_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("[switch]$Purge", content)
        self.assertIn("uninstall-command --global", content)
        self.assertIn("call-me.cmd", content)
        self.assertIn("preserved", content)

    def test_06_bidirectional_sync_non_web_workflow(self):
        mgr = ProjectContractManager(self.workspace)
        mgr.register_component("stream_collector", "Telemetry Specialist", ["collector.py"])
        mgr.register_component("anomaly_detector", "Analytics Specialist", ["detector.py"], dependencies=["stream_collector"])
        mgr.declare_interface("metric_stream", "stream_collector", ["anomaly_detector"], {"fields": ["ts", "cpu"]})

        # Consumer -> Provider reverse change request
        chg = mgr.request_interface_change(
            "metric_stream",
            requested_schema_patch={"add_field": "host_region"},
            consumer_role="Analytics Specialist",
            reason="Anomaly detector needs region grouping",
        )
        self.assertEqual(chg["status"], "PENDING_PROVIDER_REVIEW")

        # Provider updates interface -> invalidates consumer
        mut = mgr.update_interface(
            "metric_stream",
            {"fields": ["ts", "cpu", "host_region"]},
            actor_role="Telemetry Specialist",
        )
        self.assertIn("anomaly_detector", mut["affected_components"])
        self.assertEqual(len(mgr.get_stale_components()), 1)

        # Consumer adapts with evidence
        mgr.mark_component_adapted(
            "anomaly_detector",
            actor_role="Analytics Specialist",
            invocation_id="subagent-nonweb-001",
            adaptation_evidence={"updated": "detector.py", "contract_version": mut["contract_version"]},
            require_evidence=True,
        )
        self.assertEqual(len(mgr.get_stale_components()), 0)


if __name__ == "__main__":
    unittest.main()
