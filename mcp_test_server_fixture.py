#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 4: Compatible Local MCP Server Fixture
==============================================================
Standard JSON-RPC 2.0 Model Context Protocol (MCP) server running over stdio.
Supports:
- initialize handshake
- notifications/initialized
- tools/list with pagination (nextCursor)
- Explicitly rejects tools/call (code execution is out of scope)
"""

import sys
import json
from typing import Dict, Any, List

TOOLS_DATABASE: List[Dict[str, Any]] = [
    {
        "name": "read_pdf_document",
        "description": "Extracts text, metadata, structured tables, and page content from PDF documents.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the PDF file on the local filesystem."
                },
                "extract_tables": {
                    "type": "boolean",
                    "description": "Whether to extract tabular data into structured arrays."
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "convert_document_format",
        "description": "Converts text, markdown, and docx documents into standardized PDF or plaintext formats.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_path": {"type": "string"},
                "target_format": {"type": "string", "enum": ["pdf", "txt", "html"]}
            },
            "required": ["source_path", "target_format"]
        }
    },
    {
        "name": "query_local_database",
        "description": "Executes read-only analytical SQL queries against local SQLite relational databases.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "SELECT query to execute"}
            },
            "required": ["query"]
        }
    }
]

PAGE_SIZE = 2


def handle_request(req: Dict[str, Any]) -> None:
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    # Handle notifications (no id)
    if req_id is None:
        if method == "notifications/initialized":
            # Handshake complete
            pass
        return

    # Handle standard requests
    if method == "initialize":
        resp = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {"listChanged": True}
                },
                "serverInfo": {
                    "name": "local-document-tools",
                    "version": "1.0.0"
                }
            }
        }
        send_response(resp)
        return

    elif method == "tools/list":
        cursor = params.get("cursor")
        if not cursor:
            # First page
            page_tools = TOOLS_DATABASE[:PAGE_SIZE]
            next_cursor = "page_2" if len(TOOLS_DATABASE) > PAGE_SIZE else None
        elif cursor == "page_2":
            # Second page
            page_tools = TOOLS_DATABASE[PAGE_SIZE:]
            next_cursor = None
        else:
            page_tools = []
            next_cursor = None

        resp = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": page_tools,
                "nextCursor": next_cursor
            }
        }
        send_response(resp)
        return

    elif method == "tools/call":
        # Explicit scope boundary: code execution strictly disabled
        err_resp = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": "Method not allowed: tools/call is strictly disabled in LCS discovery phase"
            }
        }
        send_response(err_resp)
        return

    else:
        err_resp = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method '{method}' not found"
            }
        }
        send_response(err_resp)


def send_response(resp: Dict[str, Any]) -> None:
    line = json.dumps(resp, separators=(",", ":")) + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()


def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            handle_request(req)
        except Exception as e:
            sys.stderr.write(f"Error handling MCP request: {e}\n")
            sys.stderr.flush()


if __name__ == "__main__":
    main()
