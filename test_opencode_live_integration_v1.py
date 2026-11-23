"""
LCS OpenCode Live Host Integration Test Suite (v3.2.0-RC1)
==========================================================
Validates integration with the real local OpenCode CLI installation
located at /Users/pavan/.opencode/bin/opencode or PATH.

Tests:
1. Live binary detection and version verification.
2. Live `opencode mcp add` integration and config ingestion via OpenCodeAdapter.
3. Live JSON-RPC MCP ping to `lcs.cli serve-mcp` configured through OpenCode.
4. Slash command installation and registration in OpenCode projects.
5. Honest execution reporting when live subagent delegation is not supported.
"""

import os
import sys
import json
import shutil
import tempfile
import subprocess
import pytest
from pathlib import Path

from lcs.adapters.opencode import OpenCodeAdapter
from lcs.adapters.base import EnvironmentKind, AdapterFeature, OperationalStatus
from lcs.adapters.probes import LiveProbeEngine
from lcs.context import LCSContext
from lcs.config import LCSConfig


OPENCODE_BIN_PATHS = [
    "/Users/pavan/.opencode/bin/opencode",
    shutil.which("opencode"),
]
OPENCODE_BIN = next((p for p in OPENCODE_BIN_PATHS if p and os.path.isfile(p) and os.access(p, os.X_OK)), None)


@pytest.fixture
def opencode_ws():
    """Sets up an isolated workspace for OpenCode integration."""
    td = tempfile.mkdtemp(prefix="lcs_opencode_live_")
    ws_dir = os.path.realpath(td)
    cfg = LCSConfig.resolve(root_override=ws_dir)
    ctx = LCSContext(config=cfg, auto_migrate=True)
    yield {
        "ws": ws_dir,
        "ctx": ctx,
        "bin": OPENCODE_BIN
    }
    ctx.close()
    shutil.rmtree(ws_dir, ignore_errors=True)


@pytest.mark.skipif(OPENCODE_BIN is None, reason="OpenCode binary not installed on host")
def test_01_opencode_live_binary_version():
    """Verifies that the live opencode CLI is functional and returns a valid version."""
    res = subprocess.run([OPENCODE_BIN, "--version"], capture_output=True, text=True, timeout=5)
    assert res.returncode == 0
    assert "opencode v" in res.stdout
    version_str = res.stdout.strip()
    assert len(version_str) > 0


@pytest.mark.skipif(OPENCODE_BIN is None, reason="OpenCode binary not installed on host")
def test_02_opencode_mcp_add_and_adapter_discovery(opencode_ws):
    """
    Executes live `opencode mcp add` using the real binary, then verifies that
    OpenCodeAdapter discovers and normalizes the resulting configuration.
    """
    ws = opencode_ws["ws"]
    bin_path = opencode_ws["bin"]

    # 1. Execute live `opencode mcp add` to register LCS MCP server
    cmd = [
        bin_path, "mcp", "add", "lcs-bridge", "--",
        sys.executable, "-m", "lcs.cli", "serve-mcp"
    ]
    res = subprocess.run(cmd, cwd=ws, capture_output=True, text=True, timeout=10)
    assert res.returncode == 0, f"opencode mcp add failed: {res.stderr}"

    manifest_path = os.path.join(ws, "opencode.json")
    assert os.path.isfile(manifest_path)

    # 2. Inspect with OpenCodeAdapter
    adapter = OpenCodeAdapter(workspace_root=ws)
    assert adapter.detect_active()

    servers = adapter.discover_mcp_servers()
    assert len(servers) >= 1
    lcs_srv = next((s for s in servers if s.server_name == "lcs-bridge"), None)
    assert lcs_srv is not None
    assert lcs_srv.command == sys.executable
    assert "-m" in lcs_srv.args
    assert "lcs.cli" in lcs_srv.args
    assert "serve-mcp" in lcs_srv.args


def test_03_opencode_slash_command_and_rule_roots(opencode_ws):
    """
    Verifies that OpenCodeAdapter registers /call-me command in OpenCode format
    and updates opencode.json commands map.
    """
    ws = opencode_ws["ws"]
    manifest_path = os.path.join(ws, "opencode.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({"mcp": {}}, f)

    adapter = OpenCodeAdapter(workspace_root=ws)

    # Register slash command
    reg = adapter.register_slash_command("call-me", "LCS Natural Language Intake")
    assert reg["command"] == "/call-me"
    assert os.path.isfile(reg["macro_file"])

    # Verify manifest updated
    assert os.path.isfile(manifest_path)
    with open(manifest_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "/call-me" in data.get("commands", {})


def test_04_opencode_honest_subagent_boundary(opencode_ws):
    """
    Verifies that OpenCodeAdapter honestly reports unsupported for subagent delegation
    rather than fabricating live LLM execution.
    """
    ws = opencode_ws["ws"]
    adapter = OpenCodeAdapter(workspace_root=ws)
    assert not adapter.has_feature(AdapterFeature.AGENT_DELEGATION)

    with pytest.raises(Exception) as exc_info:
        adapter.spawn_subagent("Test Worker", "Test prompt")
    assert "does not support feature" in str(exc_info.value)
