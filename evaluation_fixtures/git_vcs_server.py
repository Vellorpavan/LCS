#!/usr/bin/env python3
"""
LCS Evaluation Fixture — Git & Version Control Tools MCP Server
===============================================================
Standard JSON-RPC 2.0 MCP server running over stdio for retrieval generalization testing.
Exposes 7 Git and revision control tools.
Strictly disallows tools/call execution.
"""

import sys
import json
from typing import Dict, Any, List

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "inspect_git_commit",
        "description": "Reads commit metadata, author, timestamp, and diff statistics for a git revision hash.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Filesystem path to local git repository"},
                "commit_hash": {"type": "string", "description": "Full or abbreviated SHA-1 commit hash"}
            },
            "required": ["repo_path", "commit_hash"]
        }
    },
    {
        "name": "list_git_branches",
        "description": "Lists local and remote branches in a git repository with tracking status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Path to git repository root"},
                "include_remote": {"type": "boolean", "default": True}
            },
            "required": ["repo_path"]
        }
    },
    {
        "name": "format_git_diff",
        "description": "Formats unified diff output with syntax highlighting markers between git tree revisions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Path to git repository root"},
                "revision_a": {"type": "string", "description": "Base revision or branch"},
                "revision_b": {"type": "string", "description": "Target revision or branch"}
            },
            "required": ["repo_path", "revision_a", "revision_b"]
        }
    },
    {
        "name": "parse_git_status",
        "description": "Parses git working tree status into modified, untracked, and staged file lists.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Path to git repository root"}
            },
            "required": ["repo_path"]
        }
    },
    {
        "name": "clone_git_repository",
        "description": "Clones a remote git repository from URL into a target directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_url": {"type": "string", "description": "Remote git URL (HTTPS or SSH)"},
                "target_dir": {"type": "string", "description": "Destination directory path"},
                "depth": {"type": "integer", "description": "Shallow clone depth", "default": 0}
            },
            "required": ["repo_url", "target_dir"]
        }
    },
    {
        "name": "verify_pgp_signature",
        "description": "Verifies PGP signatures on git commits and signed tags.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Path to git repository root"},
                "commit_hash": {"type": "string", "description": "Commit or tag object hash to verify"}
            },
            "required": ["repo_path", "commit_hash"]
        }
    },
    {
        "name": "extract_git_blame",
        "description": "Extracts line-by-line commit attribution and author info for a source file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "Path to git repository root"},
                "file_path": {"type": "string", "description": "Relative file path inside the repository"}
            },
            "required": ["repo_path", "file_path"]
        }
    }
]


def send_response(resp: Dict[str, Any]) -> None:
    line = json.dumps(resp) + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()


def main():
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
                    "serverInfo": {"name": "git-vcs-tools", "version": "1.0.0"}
                }
            })
        elif method == "tools/list":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": TOOLS}
            })
        elif method == "tools/call":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": "Tool execution prohibited by LCS security policy"}
            })
        else:
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method {method} not supported"}
            })


if __name__ == "__main__":
    main()

