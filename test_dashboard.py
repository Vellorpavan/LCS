#!/usr/bin/env python3
"""
Unit and API Tests for LCS Web Dashboard
========================================
Tests the DashboardRequestHandler HTTP endpoints:
  - GET / (HTML delivery)
  - GET /api/status
  - GET /api/search
  - GET /api/plan
  - GET /api/runs
"""

import os
import sys
import json
import pytest
import threading
from http.server import HTTPServer
import urllib.request

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.dashboard import DashboardRequestHandler


@pytest.fixture
def dashboard_server(tmp_path):
    root = tmp_path / "lcs_root"
    cfg = LCSConfig.resolve(root_override=str(root))
    ctx = LCSContext(config=cfg, auto_migrate=True)

    handler = lambda *args, **kwargs: DashboardRequestHandler(*args, ctx=ctx, **kwargs)
    server = HTTPServer(("127.0.0.1", 0), handler)
    port = server.server_port

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    server.server_close()
    ctx.close()


class TestDashboardServer:
    """Verifies dashboard HTTP server and API endpoints."""

    def test_get_dashboard_html(self, dashboard_server):
        """Verifies GET / returns valid HTML5 dashboard."""
        req = urllib.request.urlopen(dashboard_server + "/")
        assert req.status == 200
        assert "text/html" in req.headers.get("Content-Type")
        body = req.read().decode("utf-8")
        assert "Living Capability System Telemetry" in body
        assert "LCS v3.0" in body

    def test_api_status(self, dashboard_server):
        """Verifies GET /api/status returns live system metrics."""
        req = urllib.request.urlopen(dashboard_server + "/api/status")
        assert req.status == 200
        data = json.loads(req.read().decode("utf-8"))
        assert "capabilities_count" in data
        assert "cas_objects_count" in data
        assert "interfaces_count" in data

    def test_api_search(self, dashboard_server):
        """Verifies GET /api/search returns results list."""
        req = urllib.request.urlopen(dashboard_server + "/api/search")
        assert req.status == 200
        data = json.loads(req.read().decode("utf-8"))
        assert "results" in data

    def test_api_plan(self, dashboard_server):
        """Verifies GET /api/plan synthesizes a plan."""
        req = urllib.request.urlopen(dashboard_server + "/api/plan?intent=sample+task")
        assert req.status == 200
        data = json.loads(req.read().decode("utf-8"))
        assert "plan_id" in data
        assert "status" in data

    def test_api_runs(self, dashboard_server):
        """Verifies GET /api/runs returns historical execution runs."""
        req = urllib.request.urlopen(dashboard_server + "/api/runs")
        assert req.status == 200
        data = json.loads(req.read().decode("utf-8"))
        assert "runs" in data
