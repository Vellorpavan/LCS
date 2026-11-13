#!/usr/bin/env python3
"""
LCS Evaluation Fixture — Data Transform & Analytics Tools MCP Server
====================================================================
Standard JSON-RPC 2.0 MCP server running over stdio for retrieval generalization testing.
Exposes 8 data transformation, parsing, and formatting tools.
Strictly disallows tools/call execution.
"""

import sys
import json
from typing import Dict, Any, List

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "parse_csv_records",
        "description": "Parses comma-separated value tabular files into structured dictionaries with header detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Filesystem path to CSV file"},
                "delimiter": {"type": "string", "default": ","},
                "has_header": {"type": "boolean", "default": True}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "format_sql_query",
        "description": "Formats and indents raw SQL query text according to ANSI or dialect styling standards.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "raw_sql": {"type": "string", "description": "Raw unformatted SQL string"},
                "dialect": {"type": "string", "enum": ["ansi", "postgres", "mysql", "sqlite"], "default": "ansi"}
            },
            "required": ["raw_sql"]
        }
    },
    {
        "name": "convert_timezone",
        "description": "Converts ISO 8601 timestamps between IANA timezones with DST adjustment.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "timestamp_iso": {"type": "string", "description": "ISO 8601 timestamp string"},
                "source_tz": {"type": "string", "description": "Source IANA timezone name (e.g. UTC)"},
                "target_tz": {"type": "string", "description": "Target IANA timezone name (e.g. America/New_York)"}
            },
            "required": ["timestamp_iso", "target_tz"]
        }
    },
    {
        "name": "calculate_percentile_rank",
        "description": "Calculates nearest-rank and interpolated percentiles across numerical distributions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "values": {
                    "type": "array",
                    "items": {"type": "number"},
                    "description": "List of numeric values"
                },
                "percentile": {"type": "number", "description": "Percentile between 0 and 100", "default": 95.0}
            },
            "required": ["values"]
        }
    },
    {
        "name": "clean_html_markup",
        "description": "Strips dangerous HTML tags and scripts, returning sanitized text content.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "raw_html": {"type": "string", "description": "Raw HTML string to sanitize"},
                "allowed_tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["p", "b", "i", "a"]
                }
            },
            "required": ["raw_html"]
        }
    },
    {
        "name": "extract_regex_matches",
        "description": "Extracts all regex pattern matches, capture groups, and offsets from input text.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Input text to search"},
                "pattern": {"type": "string", "description": "Regular expression pattern string"}
            },
            "required": ["text", "pattern"]
        }
    },
    {
        "name": "validate_ip_address",
        "description": "Validates IPv4 and IPv6 network addresses, returning CIDR and subnet metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip_string": {"type": "string", "description": "IP address or CIDR notation"}
            },
            "required": ["ip_string"]
        }
    },
    {
        "name": "convert_currency_amount",
        "description": "Converts monetary quantities between international currency codes using fixed exchange tables.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount": {"type": "number", "description": "Monetary quantity to convert"},
                "from_currency": {"type": "string", "description": "Three-letter ISO 4217 code"},
                "to_currency": {"type": "string", "description": "Three-letter ISO 4217 code"}
            },
            "required": ["amount", "from_currency", "to_currency"]
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
                    "serverInfo": {"name": "data-transform-tools", "version": "1.0.0"}
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

