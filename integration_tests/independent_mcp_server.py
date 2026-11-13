#!/usr/bin/env python3
"""
Standalone Independent MCP Server for LCS Integration Testing
=============================================================
Communicates exclusively over standard I/O via JSON-RPC 2.0.
Exposes 3 harmless spatial analysis tools with distinct schemas.
Strictly disallows tool execution (tools/call is rejected).
"""

import sys
import os
import json
import time
import argparse
from typing import Dict, Any, List

SERVER_NAME = "independent-geo-metrics"
PROTOCOL_VERSION = "2024-11-05"
SIMULATED_DELAY = 0.0

INDEPENDENT_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "calculate_polygon_area",
        "description": "Calculates the two-dimensional Cartesian or geodesic surface area of arbitrary polygonal coordinates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "coordinates": {
                    "type": "array",
                    "description": "List of (x, y) or (lon, lat) vertex coordinate pairs.",
                    "items": {
                        "type": "array",
                        "items": {"type": "number"},
                        "minItems": 2,
                        "maxItems": 2
                    }
                },
                "geodesic": {
                    "type": "boolean",
                    "description": "Whether to calculate area across ellipsoidal surface.",
                    "default": False
                }
            },
            "required": ["coordinates"]
        }
    },
    {
        "name": "compute_haversine_distance",
        "description": "Computes the great-circle arc distance between two geographic coordinates on a spherical datum in kilometers or miles.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "latitude_start": {"type": "number", "description": "Starting waypoint latitude in degrees."},
                "longitude_start": {"type": "number", "description": "Starting waypoint longitude in degrees."},
                "latitude_end": {"type": "number", "description": "Ending waypoint latitude in degrees."},
                "longitude_end": {"type": "number", "description": "Ending waypoint longitude in degrees."},
                "units": {"type": "string", "enum": ["km", "miles", "meters"], "default": "km"}
            },
            "required": ["latitude_start", "longitude_start", "latitude_end", "longitude_end"]
        }
    },
    {
        "name": "find_bounding_envelope",
        "description": "Extracts minimum bounding rectangle envelope coordinates and geometric centroid for spatial features.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "feature_id": {"type": "string", "description": "Unique identifier of the spatial feature."},
                "precision_digits": {"type": "integer", "description": "Decimal precision for envelope bounding box.", "default": 6}
            },
            "required": ["feature_id"]
        }
    }
]


def send_response(resp: Dict[str, Any]) -> None:
    if SIMULATED_DELAY > 0:
        time.sleep(SIMULATED_DELAY)
    line = json.dumps(resp) + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()


def handle_request(req: Dict[str, Any]) -> None:
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params", {})

    # Notification handling (no response sent)
    if req_id is None:
        return

    if method == "initialize":
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False}
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": "1.0.0"
                }
            }
        })
    elif method == "tools/list":
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": INDEPENDENT_TOOLS
            }
        })
    elif method == "tools/call":
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": "Execution denied: tools/call is strictly prohibited by security policy."
            }
        })
    else:
        send_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not supported: {method}"
            }
        })


def main() -> None:
    global SIMULATED_DELAY
    parser = argparse.ArgumentParser(description="Standalone Independent MCP Server")
    parser.add_argument("--delay", type=float, default=0.0, help="Simulate latency in seconds before responding")
    args, _ = parser.parse_known_args()
    SIMULATED_DELAY = args.delay

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            handle_request(req)
        except json.JSONDecodeError:
            send_response({
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "Parse error: invalid JSON"
                }
            })


if __name__ == "__main__":
    main()
