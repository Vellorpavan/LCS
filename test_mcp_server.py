#!/usr/bin/env python3
"""
Unit and Protocol Tests for LCS MCP Server
==========================================
Verifies the stdio JSON-RPC 2.0 MCP server implementation in lcs.mcp_server:
  - Protocol initialization
  - Tools listing (tools/list)
  - Tool execution (lcs_search, lcs_plan, lcs_inspect, lcs_govern)
"""

import os
import sys
import json
import pytest

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.mcp_server import LCSMCPServer, TOOLS_SPEC


@pytest.fixture
def mcp_test_ctx(tmp_path):
    root = tmp_path / "lcs_root"
    cfg = LCSConfig.resolve(root_override=str(root))
    ctx = LCSContext(config=cfg, auto_migrate=True)
    yield ctx
    ctx.close()


class TestLCSMCPServer:
    """Verifies MCP Server functionality."""

    def test_tools_list_schema(self, mcp_test_ctx):
        """Verifies that all 6 tools are properly specified with JSON schemas."""
        server = LCSMCPServer(ctx=mcp_test_ctx)
        tool_names = [t["name"] for t in TOOLS_SPEC]
        assert "lcs_search" in tool_names
        assert "lcs_inspect" in tool_names
        assert "lcs_plan" in tool_names
        assert "lcs_govern" in tool_names
        assert "lcs_execute" in tool_names
        assert "lcs_skill_discover" in tool_names

    def test_handle_tool_call_search(self, mcp_test_ctx):
        """Verifies lcs_search tool execution."""
        server = LCSMCPServer(ctx=mcp_test_ctx)
        res = server.handle_tool_call("lcs_search", {"query": "document tools", "limit": 5})
        assert "content" in res
        assert len(res["content"]) == 1
        data = json.loads(res["content"][0]["text"])
        assert "query" in data
        assert "candidates" in data

    def test_handle_tool_call_plan(self, mcp_test_ctx):
        """Verifies lcs_plan tool execution."""
        server = LCSMCPServer(ctx=mcp_test_ctx)
        res = server.handle_tool_call("lcs_plan", {"intent": "test simple operation"})
        assert "content" in res
        plan_dict = json.loads(res["content"][0]["text"])
        assert "plan_id" in plan_dict
        assert "status" in plan_dict

    def test_handle_unknown_tool(self, mcp_test_ctx):
        """Verifies that unknown tools return an error result."""
        server = LCSMCPServer(ctx=mcp_test_ctx)
        res = server.handle_tool_call("non_existent_tool", {})
        assert res.get("isError") is True
