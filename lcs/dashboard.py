#!/usr/bin/env python3
"""
LCS Web Telemetry & Capability Dashboard
========================================
Lightweight, zero-external-dependency web dashboard providing real-time telemetry,
interactive capability exploration, visual DAG plan simulation, and execution run receipts.

Endpoints:
  - GET /                 : Interactive HTML5 / CSS / Vanilla JS telemetry dashboard
  - GET /api/status       : Real-time system health, CAS storage, and registry metrics
  - GET /api/capabilities : List registered capabilities and skills
  - GET /api/search?q=... : Full-text search and precedence-ranked candidate scoring
  - GET /api/plan?intent= : Multi-capability DAG execution plan synthesis
  - GET /api/runs         : Historical execution runs and audit receipts
"""

import os
import sys
import json
import logging
import threading
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional
import webbrowser

from .config import LCSConfig
from .context import LCSContext

logger = logging.getLogger("lcs.dashboard")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>LCS Telemetry & Capability Dashboard</title>
  <style>
    :root {
      --bg: #090a0f;
      --card-bg: #12151f;
      --card-border: #1e2436;
      --accent: #00f0ff;
      --accent-glow: rgba(0, 240, 255, 0.15);
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.5;
      padding: 24px;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .logo-badge {
      background: var(--accent);
      color: #000;
      font-weight: 800;
      font-size: 14px;
      padding: 4px 8px;
      border-radius: 4px;
      font-family: var(--font-mono);
    }
    h1 { font-size: 20px; font-weight: 700; }
    .status-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
      color: var(--success);
      font-family: var(--font-mono);
      background: rgba(16, 185, 129, 0.1);
      padding: 4px 12px;
      border-radius: 999px;
      border: 1px solid rgba(16, 185, 129, 0.2);
    }
    .dot {
      width: 8px;
      height: 8px;
      background: var(--success);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--success);
    }
    .grid-kpis {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 16px;
    }
    .kpi-title {
      font-size: 12px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 6px;
    }
    .kpi-value {
      font-size: 24px;
      font-weight: 700;
      font-family: var(--font-mono);
      color: var(--accent);
    }
    .kpi-sub {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 4px;
    }
    .tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 8px;
    }
    .tab-btn {
      background: transparent;
      color: var(--text-muted);
      border: 1px solid transparent;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.2s;
    }
    .tab-btn:hover { color: var(--text); background: rgba(255,255,255,0.03); }
    .tab-btn.active {
      color: var(--accent);
      background: var(--card-bg);
      border-color: var(--card-border);
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    .search-box {
      display: flex;
      gap: 12px;
      margin-bottom: 20px;
    }
    input[type="text"] {
      flex: 1;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 10px 16px;
      border-radius: 6px;
      font-size: 14px;
      outline: none;
    }
    input[type="text"]:focus {
      border-color: var(--accent);
      box-shadow: 0 0 10px var(--accent-glow);
    }
    button.action-btn {
      background: var(--accent);
      color: #000;
      border: none;
      padding: 10px 20px;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      overflow: hidden;
    }
    th, td {
      padding: 12px 16px;
      text-align: left;
      font-size: 13px;
      border-bottom: 1px solid var(--card-border);
    }
    th {
      background: rgba(255,255,255,0.02);
      color: var(--text-muted);
      font-weight: 600;
      font-size: 12px;
      text-transform: uppercase;
    }
    td.mono { font-family: var(--font-mono); font-size: 12px; }
    .tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      font-family: var(--font-mono);
    }
    .tag-verified { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    .tag-trusted { background: rgba(0, 240, 255, 0.2); color: var(--accent); }
    .tag-succeeded { background: rgba(16, 185, 129, 0.2); color: var(--success); }
    .tag-failed { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
    pre {
      background: #050608;
      border: 1px solid var(--card-border);
      padding: 16px;
      border-radius: 6px;
      font-family: var(--font-mono);
      font-size: 12px;
      overflow-x: auto;
      color: #e5e7eb;
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span class="logo-badge">LCS v3.0</span>
      <h1>Living Capability System Telemetry</h1>
    </div>
    <div class="status-badge">
      <span class="dot"></span>
      <span>SYSTEM OPERATIONAL</span>
    </div>
  </header>

  <div class="grid-kpis" id="kpis">
    <div class="kpi-card">
      <div class="kpi-title">Capabilities</div>
      <div class="kpi-value" id="kpi-caps">-</div>
      <div class="kpi-sub" id="kpi-caps-sub">Registered tools & skills</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">CAS Blobs</div>
      <div class="kpi-value" id="kpi-blobs">-</div>
      <div class="kpi-sub" id="kpi-blobs-size">Exact-byte volume</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Interface Policies</div>
      <div class="kpi-value" id="kpi-ifaces">-</div>
      <div class="kpi-sub">Attested zero-trust interfaces</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-title">Execution Runs</div>
      <div class="kpi-value" id="kpi-runs">-</div>
      <div class="kpi-sub">Historical audit receipts</div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('search')">Capabilities & Search</button>
    <button class="tab-btn" onclick="switchTab('plan')">DAG Plan Simulator</button>
    <button class="tab-btn" onclick="switchTab('runs')">Execution Runs</button>
  </div>

  <!-- Search Tab -->
  <div class="tab-content active" id="tab-search">
    <div class="search-box">
      <input type="text" id="search-input" placeholder="Search capabilities or skills by keyword (e.g. 'transform', 'pdf', 'document')..." onkeydown="if(event.key==='Enter') doSearch()">
      <button class="action-btn" onclick="doSearch()">Search</button>
    </div>
    <table id="search-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Taxonomy</th>
          <th>Category</th>
          <th>Status</th>
          <th>URN</th>
        </tr>
      </thead>
      <tbody id="search-body">
        <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading registered capabilities...</td></tr>
      </tbody>
    </table>
  </div>

  <!-- Plan Tab -->
  <div class="tab-content" id="tab-plan">
    <div class="search-box">
      <input type="text" id="plan-input" placeholder="Type plain English intent (e.g. 'text transform with operation uppercase')..." onkeydown="if(event.key==='Enter') doPlan()">
      <button class="action-btn" onclick="doPlan()">Synthesize DAG Plan</button>
    </div>
    <div id="plan-output" style="display: none;">
      <pre id="plan-json"></pre>
    </div>
  </div>

  <!-- Runs Tab -->
  <div class="tab-content" id="tab-runs">
    <table id="runs-table">
      <thead>
        <tr>
          <th>Run ID</th>
          <th>Plan ID</th>
          <th>Status</th>
          <th>Steps</th>
          <th>Duration</th>
          <th>Trace CAS Digest</th>
        </tr>
      </thead>
      <tbody id="runs-body">
        <tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Loading execution runs...</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    function switchTab(name) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('tab-' + name).classList.add('active');
      if (name === 'runs') loadRuns();
    }

    async function loadStatus() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        document.getElementById('kpi-caps').textContent = data.capabilities_count;
        document.getElementById('kpi-blobs').textContent = data.cas_objects_count;
        document.getElementById('kpi-blobs-size').textContent = (data.cas_volume_bytes / (1024*1024)).toFixed(1) + ' MB stored';
        document.getElementById('kpi-ifaces').textContent = data.interfaces_count;
        document.getElementById('kpi-runs').textContent = data.runs_count;
      } catch (e) {
        console.error(e);
      }
    }

    async function doSearch() {
      const q = document.getElementById('search-input').value.trim();
      const tbody = document.getElementById('search-body');
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Searching...</td></tr>';
      try {
        const res = await fetch('/api/search?q=' + encodeURIComponent(q));
        const data = await res.json();
        if (!data.results || data.results.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No capabilities matched your query.</td></tr>';
          return;
        }
        tbody.innerHTML = data.results.map(r => `
          <tr>
            <td><strong>${r.name || r.display_name}</strong></td>
            <td><span class="tag tag-trusted">${r.taxonomy_kind || 'TOOL'}</span></td>
            <td>${r.category || '-'}</td>
            <td><span class="tag ${r.trust_status === 'VERIFIED' ? 'tag-verified' : 'tag-trusted'}">${r.trust_status || 'TRUSTED'}</span></td>
            <td class="mono">${r.capability_urn}</td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" style="color: var(--danger);">Search error: ' + e + '</td></tr>';
      }
    }

    async function doPlan() {
      const intent = document.getElementById('plan-input').value.trim();
      if (!intent) return;
      const outDiv = document.getElementById('plan-output');
      const jsonPre = document.getElementById('plan-json');
      outDiv.style.display = 'block';
      jsonPre.textContent = 'Synthesizing DAG execution plan...';
      try {
        const res = await fetch('/api/plan?intent=' + encodeURIComponent(intent));
        const data = await res.json();
        jsonPre.textContent = JSON.stringify(data, null, 2);
      } catch (e) {
        jsonPre.textContent = 'Planning error: ' + e;
      }
    }

    async function loadRuns() {
      const tbody = document.getElementById('runs-body');
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Loading runs...</td></tr>';
      try {
        const res = await fetch('/api/runs');
        const data = await res.json();
        if (!data.runs || data.runs.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No execution runs recorded yet.</td></tr>';
          return;
        }
        tbody.innerHTML = data.runs.map(r => `
          <tr>
            <td class="mono"><strong>${r.run_id}</strong></td>
            <td class="mono">${r.plan_id}</td>
            <td><span class="tag ${r.lifecycle_state === 'SUCCEEDED' ? 'tag-succeeded' : 'tag-failed'}">${r.lifecycle_state}</span></td>
            <td>${r.completed_steps} / ${r.total_steps}</td>
            <td class="mono">${r.duration_ms ? r.duration_ms.toFixed(1) + 'ms' : '-'}</td>
            <td class="mono">${r.trace_cas_digest ? r.trace_cas_digest.substring(0, 16) + '...' : '-'}</td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" style="color: var(--danger);">Failed to load runs: ' + e + '</td></tr>';
      }
    }

    loadStatus();
    doSearch();
  </script>
</body>
</html>
"""


class DashboardRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for the dashboard and REST API."""

    def __init__(self, *args, ctx: Optional[LCSContext] = None, **kwargs):
        self.ctx = ctx
        super().__init__(*args, **kwargs)

    @property
    def active_ctx(self) -> LCSContext:
        """Returns a thread-safe LCSContext instance for the handling thread."""
        if not hasattr(self.server, "_lcs_local"):
            self.server._lcs_local = threading.local()
        local_data = self.server._lcs_local
        if not hasattr(local_data, "ctx") or local_data.ctx is None:
            local_data.ctx = LCSContext(config=self.ctx.config, auto_migrate=False)
        return local_data.ctx

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        params = urllib.parse.parse_qs(parsed_url.query)

        if path == "/" or path == "/index.html":
            self._send_html(DASHBOARD_HTML)
        elif path == "/api/status":
            self._handle_api_status()
        elif path == "/api/search":
            q = params.get("q", [""])[0]
            self._handle_api_search(q)
        elif path == "/api/plan":
            intent = params.get("intent", [""])[0]
            self._handle_api_plan(intent)
        elif path == "/api/runs":
            self._handle_api_runs()
        else:
            self._send_json({"error": "Not Found"}, status=404)

    def _handle_api_status(self) -> None:
        ctx = self.active_ctx
        cur = ctx.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM capabilities;")
        caps_cnt = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM interface_declarations;")
        iface_cnt = cur.fetchone()[0]

        runs = ctx.execution_engine.list_runs(limit=100)
        runs_cnt = len(runs)

        cas_count = 0
        cas_bytes = 0
        objects_dir = os.path.join(ctx.config.cas_root, "objects")
        if os.path.exists(objects_dir):
            for root_p, _, files in os.walk(objects_dir):
                for fn in files:
                    cas_count += 1
                    try:
                        cas_bytes += os.path.getsize(os.path.join(root_p, fn))
                    except OSError:
                        pass

        data = {
            "capabilities_count": caps_cnt,
            "interfaces_count": iface_cnt,
            "runs_count": runs_cnt,
            "cas_objects_count": cas_count,
            "cas_volume_bytes": cas_bytes
        }
        self._send_json(data)

    def _handle_api_search(self, query: str) -> None:
        ctx = self.active_ctx
        if not query:
            cur = ctx.conn.cursor()
            cur.execute("""
                SELECT capability_urn, display_name, capability_type, 'VERIFIED' as trust_status
                FROM capability_declarations
                LIMIT 50;
            """)
            rows = cur.fetchall()
            results = [{
                "capability_urn": r[0],
                "name": r[1],
                "taxonomy_kind": r[2].upper(),
                "trust_status": r[3]
            } for r in rows]
            self._send_json({"query": "", "results": results})
            return

        candidates = ctx.retrieval_coordinator.retrieve(query=query, limit=20)
        results = [c.to_dict() for c in candidates]
        self._send_json({"query": query, "results": results})

    def _handle_api_plan(self, intent: str) -> None:
        if not intent:
            self._send_json({"error": "Intent parameter is required"}, status=400)
            return
        plan = self.active_ctx.planning_engine.create_plan(intent)
        self._send_json(plan.to_dict())

    def _handle_api_runs(self) -> None:
        runs = self.active_ctx.execution_engine.list_runs(limit=50)
        self._send_json({"runs": runs})

    def _send_html(self, html: str, status: int = 200) -> None:
        content = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, data: Any, status: int = 200) -> None:
        content = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args) -> None:
        """Suppresses default noisy stdout HTTP access logging."""
        pass


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = False,
    ctx: Optional[LCSContext] = None
) -> None:
    """Runs the LCS telemetry dashboard HTTP server."""
    context = ctx or LCSContext(auto_migrate=True)
    handler = lambda *args, **kwargs: DashboardRequestHandler(*args, ctx=context, **kwargs)
    server = HTTPServer((host, port), handler)
    url = f"http://{host}:{port}"
    print(f"\n========================================================================")
    print(f" LIVING CAPABILITY SYSTEM (LCS) — TELEMETRY DASHBOARD")
    print(f"========================================================================")
    print(f"  Dashboard URL: {url}")
    print(f"  REST API:      {url}/api/status")
    print(f"  Press Ctrl+C to stop the dashboard server.")
    print(f"========================================================================\n")

    if open_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard server...")
    finally:
        server.server_close()
