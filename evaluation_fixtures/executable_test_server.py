#!/usr/bin/env python3
"""
LCS Evaluation Fixture — Executable Test MCP Server
===================================================
Standard JSON-RPC 2.0 MCP server running over stdio for runtime execution testing.
Handles initialize, tools/list, and tools/call.
"""

import sys
import json
import hashlib
from typing import Dict, Any, List

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "hash_sha256_digest",
        "description": "Computes cryptographic SHA-256 digest of input text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {"type": "string", "description": "Text payload to hash"}
            },
            "required": ["data"]
        }
    },
    {
        "name": "calculate_sum",
        "description": "Calculates the sum of two integers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "integer", "description": "First integer"},
                "b": {"type": "integer", "description": "Second integer"}
            },
            "required": ["a", "b"]
        }
    },
    {
        "name": "echo_message",
        "description": "Echoes back the input message.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "msg": {"type": "string", "description": "Message to echo"}
            },
            "required": ["msg"]
        }
    }
]


def send_response(resp: Dict[str, Any]) -> None:
    line = json.dumps(resp) + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()


def main():
    tools = TOOLS
    if "--tools" in sys.argv:
        idx = sys.argv.index("--tools")
        if idx + 1 < len(sys.argv):
            allowed = set(sys.argv[idx + 1].split(","))
            tools = [t for t in TOOLS if t["name"] in allowed or t["name"].replace("_", "-") in allowed]

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if req_id is None:
            continue

        if method == "initialize":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "executable-test-server", "version": "1.0.0"}
                }
            })
        elif method == "tools/list":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools}
            })
        elif method == "tools/call":
            raw_tool_name = params.get("name", "")
            tool_name = raw_tool_name.replace("-", "_")
            arguments = params.get("arguments", {})

            if tool_name == "hash_sha256_digest":
                raw_data = str(arguments.get("data", "")).encode("utf-8")
                digest = hashlib.sha256(raw_data).hexdigest()
                send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": digest}],
                        "sha256_hash": digest,
                        "isError": False
                    }
                })
            elif tool_name == "calculate_sum":
                a = int(arguments.get("a", 0))
                b = int(arguments.get("b", 0))
                sum_val = a + b
                send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": str(sum_val)}],
                        "result": sum_val,
                        "isError": False
                    }
                })
            elif tool_name == "echo_message":
                msg = str(arguments.get("msg", ""))
                send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": msg}],
                        "result": msg,
                        "isError": False
                    }
                })
            else:
                send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Tool '{tool_name}' not found"}
                })
        else:
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method {method} not supported"}
            })


if __name__ == "__main__":
    main()
