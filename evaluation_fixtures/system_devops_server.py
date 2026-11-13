#!/usr/bin/env python3
"""
LCS Evaluation Fixture — System & DevOps Tools MCP Server
=========================================================
Standard JSON-RPC 2.0 MCP server running over stdio for retrieval generalization testing.
Exposes 8 system, network, and operational tools.
Strictly disallows tools/call execution.
"""

import sys
import json
from typing import Dict, Any, List

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "ping_network_host",
        "description": "Sends ICMP echo requests to verify remote host reachability and round-trip latency.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target hostname or IP address to ping"},
                "count": {"type": "integer", "default": 4},
                "timeout": {"type": "number", "default": 5.0}
            },
            "required": ["host"]
        }
    },
    {
        "name": "query_dns_records",
        "description": "Queries DNS nameservers for A, AAAA, MX, CNAME, or TXT resource records.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Fully qualified domain name to resolve"},
                "record_type": {"type": "string", "enum": ["A", "AAAA", "MX", "CNAME", "TXT", "NS"], "default": "A"},
                "nameserver": {"type": "string", "description": "Custom nameserver IP address", "default": "8.8.8.8"}
            },
            "required": ["domain"]
        }
    },
    {
        "name": "inspect_process_metrics",
        "description": "Retrieves CPU, memory, and thread utilization metrics for running system process IDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process identifier on local operating system"}
            },
            "required": ["pid"]
        }
    },
    {
        "name": "tail_system_log",
        "description": "Streams and filters recent log lines from local syslog or journalctl files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_path": {"type": "string", "description": "Filesystem path to log file"},
                "lines": {"type": "integer", "default": 100},
                "filter_regex": {"type": "string", "description": "Optional regular expression filter"}
            },
            "required": ["log_path"]
        }
    },
    {
        "name": "validate_yaml_syntax",
        "description": "Validates syntax and parses hierarchical structure of YAML configuration manifests.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "yaml_content": {"type": "string", "description": "Raw YAML string to parse and validate"}
            },
            "required": ["yaml_content"]
        }
    },
    {
        "name": "format_json_document",
        "description": "Formats and pretty-prints raw unformatted JSON text strings with configurable indentation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "json_text": {"type": "string", "description": "Raw unformatted JSON string"},
                "indent": {"type": "integer", "default": 2}
            },
            "required": ["json_text"]
        }
    },
    {
        "name": "calculate_disk_usage",
        "description": "Calculates recursive disk usage in bytes across directory hierarchy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "directory_path": {"type": "string", "description": "Root path to scan for disk usage"}
            },
            "required": ["directory_path"]
        }
    },
    {
        "name": "compress_tar_archive",
        "description": "Compresses a directory of filesystem objects into a tar.gz or tar.bz2 archive.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_dir": {"type": "string", "description": "Source directory path to archive"},
                "output_archive": {"type": "string", "description": "Target archive file path"},
                "compression": {"type": "string", "enum": ["gz", "bz2", "xz"], "default": "gz"}
            },
            "required": ["source_dir", "output_archive"]
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
                    "serverInfo": {"name": "system-devops-tools", "version": "1.0.0"}
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

