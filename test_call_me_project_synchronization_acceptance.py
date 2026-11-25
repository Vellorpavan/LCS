"""
Call Me — Shared Project State & Synchronization Acceptance Suite (Priority 7)
=============================================================================
Tests versioned project contracts, component ownership, automated change propagation,
conflict detection, and real end-to-end frontend/backend adaptation:
1. Scenario A: Real Frontend/Backend App with Deliberate Schema Mutation:
   - Backend service declares API contract (v1).
   - Frontend dashboard consumes API contract.
   - Initial integration test passes.
   - Deliberate schema mutation on API contract (v2).
   - Frontend component is automatically flagged as NEEDS_UPDATE.
   - Concurrent write on stale base version raises ConcurrentContractConflictError.
   - Frontend specialist adapts dashboard to v2 contract.
   - Component marked adapted.
   - End-to-end integration test passes under v2 contract.
2. Scenario B: Non-Frontend/Backend Pipeline (Telemetry + Health Monitor):
   - Telemetry provider updates event payload structure.
   - Health monitor consumer automatically detected as stale and adapted.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import subprocess
from io import StringIO
from unittest.mock import patch

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.sync.contract import ProjectContractManager, ConcurrentContractConflictError
from lcs.verification.gates import DeliverableVerificationGate, VerificationState


class TestCallMeProjectSynchronizationAcceptance(unittest.TestCase):
    """Acceptance test suite for shared project state, contracts, and synchronization."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="lcs_sync_test_")
        self.workspace = os.path.join(self.test_dir, "workspace")
        os.makedirs(self.workspace, exist_ok=True)
        self.config = LCSConfig.resolve(root_override=self.workspace)
        self.ctx = LCSContext(self.config)

    def tearDown(self):
        if hasattr(self.ctx, "conn") and self.ctx.conn:
            self.ctx.conn.close()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_frontend_backend_deliberate_contract_mutation_and_adaptation(self):
        """
        Full lifecycle: Backend API contract v1 -> Frontend consumption ->
        Deliberate API contract mutation v2 -> Automated invalidation ->
        Conflict prevention -> Frontend adaptation -> Verified passing integration test.
        """
        mgr = ProjectContractManager(self.workspace)
        self.assertEqual(mgr.version, 1)

        # 1. Register Components and Ownership
        mgr.register_component(
            name="backend_api",
            owner_role="Backend Specialist",
            files=["backend.py"]
        )
        mgr.register_component(
            name="frontend_ui",
            owner_role="Frontend Specialist",
            files=["frontend.py"],
            dependencies=["telemetry_api_v1"]
        )

        # 2. Declare Interface Contract v1
        api_schema_v1 = {
            "endpoint": "/api/v1/metrics",
            "method": "GET",
            "response": {
                "status": "string",
                "cpu_usage": "float",
                "memory_mb": "integer"
            }
        }
        mgr.declare_interface(
            interface_name="telemetry_api",
            provider_component="backend_api",
            consumer_components=["frontend_ui"],
            schema_spec=api_schema_v1
        )

        # 3. Create initial implementation files (v1 contract)
        backend_code_v1 = """
class BackendAPI:
    def get_metrics(self):
        return {"status": "ok", "cpu_usage": 14.5, "memory_mb": 512}
"""
        frontend_code_v1 = """
from backend import BackendAPI

class FrontendDashboard:
    def __init__(self, api):
        self.api = api

    def render_summary(self):
        data = self.api.get_metrics()
        return f"Status: {data['status']}, CPU: {data['cpu_usage']}%, Mem: {data['memory_mb']}MB"
"""
        test_code_v1 = """
import unittest
from backend import BackendAPI
from frontend import FrontendDashboard

class TestIntegrationV1(unittest.TestCase):
    def test_dashboard_renders_metrics(self):
        api = BackendAPI()
        ui = FrontendDashboard(api)
        summary = ui.render_summary()
        self.assertEqual(summary, "Status: ok, CPU: 14.5%, Mem: 512MB")

if __name__ == "__main__":
    unittest.main()
"""
        with open(os.path.join(self.workspace, "backend.py"), "w") as f:
            f.write(backend_code_v1)
        with open(os.path.join(self.workspace, "frontend.py"), "w") as f:
            f.write(frontend_code_v1)
        with open(os.path.join(self.workspace, "test_integration.py"), "w") as f:
            f.write(test_code_v1)

        # Run initial integration test (v1)
        proc_v1 = subprocess.run([sys.executable, "test_integration.py"], cwd=self.workspace, capture_output=True, text=True)
        self.assertEqual(proc_v1.returncode, 0, f"V1 integration test failed: {proc_v1.stderr}")

        # 4. DELIBERATE CONTRACT MUTATION (v2)
        # Backend specialist modifies schema: changes payload format and endpoint
        api_schema_v2 = {
            "endpoint": "/api/v2/telemetry",
            "method": "GET",
            "response": {
                "system": {
                    "health_status": "string",
                    "cpu_pct": "float"
                },
                "memory_bytes": "integer"
            }
        }
        res_mutation = mgr.update_interface(
            interface_name="telemetry_api",
            new_schema_spec=api_schema_v2,
            actor_role="Backend Specialist"
        )

        self.assertEqual(res_mutation["contract_version"], 2)
        self.assertTrue(res_mutation["schema_mutated"])
        self.assertIn("frontend_ui", res_mutation["affected_components"])

        # 5. Verify Automatic Change Propagation
        stale_comps = mgr.get_stale_components()
        self.assertEqual(len(stale_comps), 1)
        self.assertEqual(stale_comps[0]["name"], "frontend_ui")
        self.assertEqual(stale_comps[0]["status"], "NEEDS_UPDATE")
        self.assertIn("mutated at contract version 2", stale_comps[0]["stale_reason"])

        # 6. Concurrency & Conflict Protection:
        # If frontend attempts to write on base_version 1 while marked NEEDS_UPDATE, raise conflict
        with self.assertRaises(ConcurrentContractConflictError):
            mgr.safe_write_file(
                component_name="frontend_ui",
                rel_path="frontend.py",
                content="# Unaware edit\n",
                base_version=1,
                actor_role="Frontend Specialist"
            )

        # 7. Update Backend to v2
        backend_code_v2 = """
class BackendAPI:
    def get_telemetry(self):
        return {
            "system": {
                "health_status": "healthy",
                "cpu_pct": 18.2
            },
            "memory_bytes": 1073741824
        }
"""
        mgr.safe_write_file(
            component_name="backend_api",
            rel_path="backend.py",
            content=backend_code_v2,
            base_version=2,
            actor_role="Backend Specialist"
        )

        # If we run the old frontend against new backend, it would fail due to KeyError
        # 8. Frontend Specialist Adapts to v2 Schema
        frontend_code_v2 = """
from backend import BackendAPI

class FrontendDashboard:
    def __init__(self, api):
        self.api = api

    def render_summary(self):
        data = self.api.get_telemetry()
        sys_info = data["system"]
        mem_mb = data["memory_bytes"] // (1024 * 1024)
        return f"Status: {sys_info['health_status']}, CPU: {sys_info['cpu_pct']}%, Mem: {mem_mb}MB"
"""
        # Mark adaptation complete
        mgr.mark_component_adapted("frontend_ui", actor_role="Frontend Specialist")
        self.assertEqual(len(mgr.get_stale_components()), 0)

        # Now write adapted frontend code
        mgr.safe_write_file(
            component_name="frontend_ui",
            rel_path="frontend.py",
            content=frontend_code_v2,
            base_version=2,
            actor_role="Frontend Specialist"
        )

        # 9. Updated v2 Integration Test
        test_code_v2 = """
import unittest
from backend import BackendAPI
from frontend import FrontendDashboard

class TestIntegrationV2(unittest.TestCase):
    def test_dashboard_renders_metrics_v2(self):
        api = BackendAPI()
        ui = FrontendDashboard(api)
        summary = ui.render_summary()
        self.assertEqual(summary, "Status: healthy, CPU: 18.2%, Mem: 1024MB")

if __name__ == "__main__":
    unittest.main()
"""
        with open(os.path.join(self.workspace, "test_integration.py"), "w") as f:
            f.write(test_code_v2)

        # 10. Run End-to-End Integration Verification Gate
        gate = DeliverableVerificationGate()
        res_gate = gate.verify({
            "run_id": "run-sync-v2-acceptance",
            "workspace_root": self.workspace,
            "expected_files": ["backend.py", "frontend.py", "test_integration.py"],
            "verification_commands": [f"{sys.executable} -m unittest test_integration.py"]
        })

        self.assertTrue(res_gate.is_verified)
        self.assertEqual(res_gate.state, VerificationState.VERIFIED)

    def test_non_frontend_pipeline_stream_contract_synchronization(self):
        """
        Scenario B: Telemetry Stream Collector -> Health Evaluator pipeline.
        Demonstrates non-frontend/backend component contract change propagation.
        """
        mgr = ProjectContractManager(self.workspace)

        mgr.register_component("collector", "Telemetry Specialist", ["collector.py"])
        mgr.register_component("evaluator", "Monitor Specialist", ["evaluator.py"])

        initial_schema = {"stream_format": "csv", "fields": ["timestamp", "temperature"]}
        mgr.declare_interface("stream_contract", "collector", ["evaluator"], initial_schema)

        # Mutate to structured JSON event stream
        new_schema = {
            "stream_format": "json_lines",
            "fields": ["ts_epoch_ms", "sensor_readings", "alert_level"]
        }
        res = mgr.update_interface("stream_contract", new_schema, actor_role="Telemetry Specialist")
        self.assertTrue(res["schema_mutated"])
        self.assertIn("evaluator", res["affected_components"])

        stale = mgr.get_stale_components()
        self.assertTrue(any(c["name"] == "evaluator" for c in stale))

        # Evaluator adapts
        mgr.mark_component_adapted("evaluator", actor_role="Monitor Specialist")
        self.assertEqual(len(mgr.get_stale_components()), 0)

    def test_reverse_direction_change_request_from_consumer(self):
        """
        Reverse-direction schema evolution: Consumer requests an interface extension,
        upstream provider reviews and accepts the requested patch, monotonic version increments,
        and both components synchronize.
        """
        mgr = ProjectContractManager(self.workspace)
        mgr.register_component("backend_service", "Backend Specialist", ["service.py"])
        mgr.register_component("analytics_consumer", "Analytics Specialist", ["analytics.py"])

        initial_schema = {
            "endpoint": "/events",
            "payload": {"event_type": "string", "count": "integer"}
        }
        mgr.declare_interface("event_feed", "backend_service", ["analytics_consumer"], initial_schema)

        # Reverse request: Analytics consumer needs latency percentile fields
        req_patch = {
            "endpoint": "/events",
            "payload": {
                "event_type": "string",
                "count": "integer",
                "p95_latency_ms": "float",
                "p99_latency_ms": "float"
            }
        }
        change_req = mgr.request_interface_change(
            interface_name="event_feed",
            requested_schema_patch=req_patch,
            consumer_role="Analytics Specialist",
            reason="Required for P99 SLA telemetry alerting"
        )
        self.assertEqual(change_req["status"], "PENDING_PROVIDER_REVIEW")
        self.assertEqual(change_req["provider_component"], "backend_service")

        # Provider reviews and applies the requested change
        res = mgr.update_interface(
            interface_name="event_feed",
            new_schema_spec=req_patch,
            actor_role="Backend Specialist"
        )
        self.assertTrue(res["schema_mutated"])
        self.assertIn("analytics_consumer", res["affected_components"])

        # Analytics adapts to the new schema it requested
        mgr.mark_component_adapted("analytics_consumer", actor_role="Analytics Specialist")
        self.assertEqual(len(mgr.get_stale_components()), 0)

    def test_user_style_call_me_plan_wires_contract_and_specialists(self):
        """
        Tests that user-style /call-me plan automatically initializes ProjectContractManager,
        binds specialist ownership to the planned DAG steps, and embeds project contract.
        """
        plan = self.ctx.call_me.plan_call_me(
            raw_message="Build a Python telemetry service, assemble it, and run tests",
            workspace_root=self.workspace
        )
        self.assertEqual(plan["status"], "PLAN_READY")
        self.assertIn("project_contract", plan)
        contract_info = plan["project_contract"]
        self.assertIsNotNone(contract_info)
        self.assertIn("contract_id", contract_info)
        self.assertTrue(contract_info["version"] >= 1)
        self.assertTrue(len(contract_info["components"]) >= 2)

        # Verify contract file physically exists inside .lcs
        contract_file = os.path.join(self.workspace, ".lcs", "project_contract.json")
        self.assertTrue(os.path.isfile(contract_file))
        with open(contract_file, "r") as f:
            data = json.load(f)
        self.assertEqual(data["contract_id"], contract_info["contract_id"])


if __name__ == "__main__":
    unittest.main()
