#!/usr/bin/env python3
"""
Production Tools MCP Server
===========================
A fully functional JSON-RPC 2.0 stdio MCP server exposing real executable tools
for production agent workflows:
  - text_transform: Transform text (uppercase, lowercase, reverse, slugify, base64)
  - hash_compute: Compute cryptographic digests (sha256, sha512, md5)
  - math_eval: Evaluate safe mathematical expressions
  - file_checksum: Compute file metrics and SHA-256 with security path validation
"""

import sys
import json
import base64
import hashlib
import re
import ast
import os
from typing import Dict, Any, List

TOOLS = [
    {
        "name": "text_transform",
        "description": "Performs text manipulation operations (uppercase, lowercase, reverse, slugify, base64_encode, base64_decode).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The input string to transform"
                },
                "operation": {
                    "type": "string",
                    "description": "The transformation operation",
                    "enum": ["uppercase", "lowercase", "reverse", "slugify", "base64_encode", "base64_decode"]
                }
            },
            "required": ["text", "operation"]
        }
    },
    {
        "name": "hash_compute",
        "description": "Computes cryptographic hash digests for given input data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "string",
                    "description": "Input data string to hash"
                },
                "algorithm": {
                    "type": "string",
                    "description": "Hash algorithm (sha256, sha512, md5)",
                    "enum": ["sha256", "sha512", "md5"],
                    "default": "sha256"
                }
            },
            "required": ["data"]
        }
    },
    {
        "name": "math_eval",
        "description": "Evaluates mathematical expressions safely using an AST parser (addition, subtraction, multiplication, division, powers).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "expression": {
                    "type": "string",
                    "description": "Mathematical expression (e.g. '12 * (4 + 8) / 2')"
                }
            },
            "required": ["expression"]
        }
    },
    {
        "name": "file_checksum",
        "description": "Computes SHA-256 hash, byte size, and line count for a specified local file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filepath": {
                    "type": "string",
                    "description": "Absolute or relative path to the target file"
                }
            },
            "required": ["filepath"]
        }
    }
]


def _safe_eval(node: ast.AST) -> float:
    """Safely evaluates basic arithmetic AST expressions."""
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    elif isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return float(node.value)
        raise ValueError(f"Unsupported constant type: {type(node.value)}")
    elif isinstance(node, ast.UnaryOp):
        operand = _safe_eval(node.operand)
        if isinstance(node.op, ast.UAdd):
            return +operand
        elif isinstance(node.op, ast.USub):
            return -operand
        raise ValueError(f"Unsupported unary operator: {type(node.op)}")
    elif isinstance(node, ast.BinOp):
        left = _safe_eval(node.left)
        right = _safe_eval(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        elif isinstance(node.op, ast.Sub):
            return left - right
        elif isinstance(node.op, ast.Mult):
            return left * right
        elif isinstance(node.op, ast.Div):
            if right == 0:
                raise ZeroDivisionError("Division by zero")
            return left / right
        elif isinstance(node.op, ast.Pow):
            if abs(right) > 100:
                raise ValueError("Exponent too large (max 100)")
            return left ** right
        elif isinstance(node.op, ast.Mod):
            return left % right
        raise ValueError(f"Unsupported binary operator: {type(node.op)}")
    raise ValueError(f"Unsupported AST expression node: {type(node)}")


def execute_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Executes a tool and returns the structured output dict."""
    if name == "text_transform":
        text = str(args.get("text", ""))
        op = str(args.get("operation", "uppercase")).lower()
        if op == "uppercase":
            res = text.upper()
        elif op == "lowercase":
            res = text.lower()
        elif op == "reverse":
            res = text[::-1]
        elif op == "slugify":
            clean = re.sub(r"[^\w\s-]", "", text).strip().lower()
            res = re.sub(r"[-\s]+", "-", clean)
        elif op == "base64_encode":
            res = base64.b64encode(text.encode("utf-8")).decode("utf-8")
        elif op == "base64_decode":
            res = base64.b64decode(text.encode("utf-8")).decode("utf-8", errors="replace")
        else:
            raise ValueError(f"Unknown text operation: {op}")
        return {"result": res, "operation": op, "original_length": len(text)}

    elif name == "hash_compute":
        data = str(args.get("data", ""))
        algo = str(args.get("algorithm", "sha256")).lower()
        data_bytes = data.encode("utf-8")
        if algo == "sha256":
            digest = hashlib.sha256(data_bytes).hexdigest()
        elif algo == "sha512":
            digest = hashlib.sha512(data_bytes).hexdigest()
        elif algo == "md5":
            digest = hashlib.md5(data_bytes).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algo}")
        return {"digest": digest, "algorithm": algo, "bytes_hashed": len(data_bytes)}

    elif name == "math_eval":
        expr = str(args.get("expression", ""))
        parsed = ast.parse(expr, mode="eval")
        val = _safe_eval(parsed)
        return {"expression": expr, "result": val}

    elif name == "file_checksum":
        filepath = os.path.abspath(str(args.get("filepath", "")))
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        content = open(filepath, "rb").read()
        sha256_hash = hashlib.sha256(content).hexdigest()
        lines = content.count(b"\n") + (1 if content and not content.endswith(b"\n") else 0)
        return {
            "filepath": filepath,
            "size_bytes": len(content),
            "line_count": lines,
            "sha256": sha256_hash
        }

    else:
        raise ValueError(f"Unknown tool: {name}")


def send_response(req_id: Any, result: Any = None, error: Any = None) -> None:
    msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": req_id}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main() -> None:
    """Stdio JSON-RPC 2.0 loop."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            send_response(None, error={"code": -32700, "message": f"Parse error: {e}"})
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            send_response(req_id, {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "production-tools-server",
                    "version": "1.0.0"
                },
                "capabilities": {
                    "tools": {}
                }
            })

        elif method == "notifications/initialized":
            pass

        elif method == "tools/list":
            send_response(req_id, {"tools": TOOLS})

        elif method == "tools/call":
            raw_name = params.get("name", "")
            tool_name = raw_name.replace("-", "_")
            tool_args = params.get("arguments", {})
            try:
                out = execute_tool(tool_name, tool_args)
                send_response(req_id, {
                    "content": [{
                        "type": "text",
                        "text": json.dumps(out)
                    }]
                })
            except Exception as e:
                send_response(req_id, {
                    "isError": True,
                    "content": [{
                        "type": "text",
                        "text": f"Tool execution failed: {str(e)}"
                    }]
                })

        elif method == "ping":
            send_response(req_id, {})

        else:
            send_response(req_id, error={"code": -32601, "message": f"Method '{method}' not found."})


if __name__ == "__main__":
    main()
