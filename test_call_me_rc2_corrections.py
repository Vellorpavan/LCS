"""
Call Me — RC2 Corrections Regression & Negative Test Suite
=========================================================
Verifies:
1. Generalized requirement-to-capability coverage & unrelated capability rejection.
2. Host-assisted semantic reasoning validation gate (rejects hallucinated/unjustified URNs).
3. Existing installed agent selection & multi-skill pairing.
4. Functional verification distinction: source files alone cannot pass when tests are required.
5. Stale contract component blocking & adaptation evidence enforcement.
"""

import json
import os
import shutil
import tempfile
import unittest

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


class TestCallMeRC2Corrections(unittest.TestCase):

    def setUp(self):
        self.workspace = tempfile.mkdtemp(prefix="call_me_rc2_test_")
        self.cfg = LCSConfig.resolve()
        self.ctx = LCSContext(self.cfg)
        self.ctx.inventory.refresh_discovery(adapters=self.ctx.adapter_registry.list_all())
        self._ensure_portable_test_catalog()

    def _ensure_portable_test_catalog(self):
        """Ensure portable test skills/agents exist on clean CI runners without user-local plugins."""
        existing_names = {r.name.lower() for r in self.ctx.inventory.list_all()}
        portable_records = [
            ("urn:lcs:skill:antigravity:fastapi-patterns", "fastapi-patterns", ResourceType.SKILL, "FastAPI backend patterns, Pydantic v2 schemas, REST APIs", ["fastapi", "backend", "python", "api"]),
            ("urn:lcs:skill:antigravity:dashboard-builder", "dashboard-builder", ResourceType.SKILL, "Build operational HTML monitoring dashboards", ["dashboard", "html", "frontend"]),
            ("urn:lcs:skill:antigravity:python-testing", "python-testing", ResourceType.SKILL, "Python testing strategies using pytest and integration suites", ["python", "pytest", "testing"]),
            ("urn:lcs:skill:antigravity:jira-integration", "jira-integration", ResourceType.SKILL, "Retrieve Jira tickets and post Jira issue updates", ["jira", "tickets"]),
            ("urn:lcs:skill:antigravity:postgres-patterns", "postgres-patterns", ResourceType.SKILL, "PostgreSQL database schema design, indexing, and queries", ["postgres", "postgresql", "sql", "schema"]),
            ("urn:lcs:skill:antigravity:database-migrations", "database-migrations", ResourceType.SKILL, "Database schema migrations and rollbacks", ["database", "migrations", "sql"]),
            ("urn:lcs:skill:antigravity:go-test", "go-test", ResourceType.SKILL, "Idiomatic Go table-driven unit tests", ["go", "golang", "testing"]),
            ("urn:lcs:agent:antigravity:fastapi-reviewer", "fastapi-reviewer", ResourceType.AGENT, "FastAPI backend specialist and reviewer", ["fastapi", "backend", "python"]),
            ("urn:lcs:agent:antigravity:python-reviewer", "python-reviewer", ResourceType.AGENT, "Python specialist and pytest reviewer", ["python", "pytest", "telemetry"]),
            ("urn:lcs:agent:antigravity:database-reviewer", "database-reviewer", ResourceType.AGENT, "PostgreSQL database schema and migration specialist", ["postgres", "database", "sql"]),
        ]
        for urn, name, rtype, desc, tags in portable_records:
            if name.lower() not in existing_names:
                rec = UnifiedResourceRecord(
                    urn=urn,
                    name=name,
                    resource_type=rtype,
                    display_name=name,
                    description=desc,
                    raw_content=f"# {name}\n{desc}\n",
                    raw_content_digest=f"digest_{name}",
                    provenance=ProvenanceRecord("antigravity", "USER_GLOBAL", f"db://{name}", f"db://{name}", f"digest_{name}"),
                    lifecycle_state=OperationalLifecycleState.EXECUTABLE,
                    tags=tags,
                )
                self.ctx.inventory._register_resource_with_conflict_resolution(rec, persist=False)

    def tearDown(self):
        self.ctx.close()
        shutil.rmtree(self.workspace, ignore_errors=True)

    def test_01_telemetry_objective_coverage_rejects_jira_and_includes_testing_and_html(self):
        obj = "Build a Python telemetry service with FastAPI backend, HTML dashboard frontend, and pytest integration suite"
        plan = self.ctx.call_me.plan_call_me(raw_message=obj, workspace_root=self.workspace)
        self.assertEqual(plan["status"], "PLAN_READY")

        step_names = [s["display_name"].lower() for s in plan["steps"]]
        self.assertNotIn("jira-integration", step_names, "Irrelevant jira-integration must not be selected")
        self.assertTrue(
            any("test" in n or "tdd" in n for n in step_names),
            f"Testing capability must be selected for pytest integration suite, got: {step_names}"
        )

        expected_files = plan["verification_criteria"]["expected_files"]
        self.assertIn("dashboard.html", expected_files)
        self.assertIn("test_service.py", expected_files)
        cmds = plan["verification_criteria"]["verification_commands"]
        self.assertTrue(any("pytest" in c or "test_service.py" in c for c in cmds))

        # Check existing installed agent selection
        agents = [s.get("agent_id") for s in plan["steps"] if s.get("agent_id")]
        self.assertGreater(len(agents), 0, "Installed specialist agents should be selected")

    def test_02_unrelated_domain_objective_coverage(self):
        obj = "Design a PostgreSQL schema for e-commerce orders with unit tests"
        plan = self.ctx.call_me.plan_call_me(raw_message=obj, workspace_root=self.workspace)
        self.assertEqual(plan["status"], "PLAN_READY")

        step_names = [s["display_name"].lower() for s in plan["steps"]]
        self.assertTrue(any("postgres" in n or "database" in n for n in step_names))
        self.assertNotIn("go-test", step_names, "Language-mismatched go-test must not be selected")
        self.assertTrue(len(plan["verification_criteria"]["verification_commands"]) > 0)

    def test_03_missing_capability_gap_detected(self):
        obj = "Calibrate quantum flux capacitor warp matrix"
        res = SemanticReasoner.reason_locally(obj, self.ctx.inventory, active_host="antigravity")
        self.assertGreater(len(res.gaps), 0, "Unsupported requirement should be reported as a capability gap")
        self.assertFalse(res.coverage_complete)

    def test_04_host_reasoning_validation_rejects_hallucinated_and_unjustified_urns(self):
        obj = "Build a Python FastAPI service with pytest tests"
        reqs = SemanticReasoner.decompose_requirements(obj)
        host_decision = {
            "selected_capabilities": [
                {
                    "urn": "urn:lcs:skill:nonexistent:hallucinated-skill",
                    "covers_requirements": [reqs[0].id],
                    "justification": "Hallucinated skill"
                },
                {
                    "urn": "jira-integration",
                    "covers_requirements": [reqs[0].id],
                    "justification": "Unrelated Jira skill"
                },
                {
                    "urn": "fastapi-patterns",
                    "covers_requirements": [reqs[0].id],
                    "agent_id": "fastapi-reviewer",
                    "justification": "Matches FastAPI backend requirement"
                },
            ],
            "missing_capabilities": []
        }
        validated = SemanticReasoner.validate_and_build_from_host_decision(
            objective=obj,
            requirements=reqs,
            host_decision=host_decision,
            inventory=self.ctx.inventory,
            active_host="antigravity",
            host_model="TestHostModel"
        )
        selected_names = [s.name for s in validated.selections]
        self.assertIn("fastapi-patterns", selected_names)
        self.assertNotIn("hallucinated-skill", selected_names)
        self.assertNotIn("jira-integration", selected_names)
        self.assertGreaterEqual(len(validated.validation_errors), 2)
        fastapi_sel = next(s for s in validated.selections if s.name == "fastapi-patterns")
        self.assertEqual(fastapi_sel.agent_id, "fastapi-reviewer")

    def test_05_source_files_alone_cannot_satisfy_project_requiring_tests(self):
        # Plan a project that requires tests
        plan = self.ctx.call_me.plan_call_me(
            raw_message="Build a Python telemetry service with pytest tests",
            workspace_root=self.workspace
        )
        run_id = plan["request_id"]
        # Create all expected files as dummy source files (WITHOUT a passing test_service.py)
        for fname in plan["verification_criteria"]["expected_files"]:
            fpath = os.path.join(self.workspace, fname)
            with open(fpath, "w") as f:
                if fname == "test_service.py":
                    # Failing test
                    f.write("def test_fail():\n    assert False, 'incomplete implementation'\n")
                else:
                    f.write("# stub\n")

        res = self.ctx.call_me.verify_deliverables(run_id=run_id, workspace_root=self.workspace)
        self.assertTrue(res["artifact_verified"], "Physical files exist and are non-empty")
        self.assertFalse(res["functional_verified"], "Failing test must prevent functional verification")
        self.assertFalse(res["is_verified"], "Source files alone with failing test must not verify")
        self.assertEqual(res["verification_state"], "FAILED")
        self.assertTrue(len(res["command_results"]) > 0)
        self.assertNotEqual(res["command_results"][0]["exit_code"], 0)

    def test_06_stale_contract_blocks_verification_and_requires_adaptation_evidence(self):
        plan = self.ctx.call_me.plan_call_me(
            raw_message="Build a Python telemetry service with pytest tests",
            workspace_root=self.workspace
        )
        run_id = plan["request_id"]
        for fname in plan["verification_criteria"]["expected_files"]:
            fpath = os.path.join(self.workspace, fname)
            with open(fpath, "w") as f:
                if fname == "test_service.py":
                    f.write("def test_ok():\n    assert True\n")
                else:
                    f.write("# valid module\n")

        mgr = ProjectContractManager(self.workspace)
        comps = list(mgr.contract["components"].keys())
        self.assertGreaterEqual(len(comps), 2)
        mgr.declare_interface(
            "api_contract",
            provider_component=comps[0],
            consumer_components=[comps[1]],
            schema_spec={"v": 1}
        )
        mgr.update_interface("api_contract", {"v": 2}, actor_role=comps[0])
        self.assertGreater(len(mgr.get_stale_components()), 0)

        # Verification must fail while component is NEEDS_UPDATE
        res = self.ctx.call_me.verify_deliverables(run_id=run_id, workspace_root=self.workspace)
        self.assertFalse(res["is_verified"])
        self.assertTrue(any("stale" in e["criterion"].lower() or "stale" in str(e["details"]).lower() for e in res["evidence"]))

        # Marking ACTIVE with require_evidence=True must fail without invocation_id & evidence
        with self.assertRaises(ValueError):
            mgr.mark_component_adapted(comps[1], actor_role="specialist", require_evidence=True)

        # Providing valid invocation_id and adaptation_evidence succeeds and unblocks verification
        mgr.mark_component_adapted(
            comps[1],
            actor_role="specialist",
            invocation_id="subagent-adapt-123",
            adaptation_evidence={"updated_files": [comps[1]], "contract_version": mgr.version},
            require_evidence=True,
        )
        res_ok = self.ctx.call_me.verify_deliverables(run_id=run_id, workspace_root=self.workspace)
        self.assertTrue(res_ok["is_verified"])
        self.assertTrue(res_ok["functional_verified"])
        self.assertEqual(res_ok["command_results"][0]["exit_code"], 0)


if __name__ == "__main__":
    unittest.main()
