#!/usr/bin/env python3
"""
LCS Model Context Protocol (MCP) Server
=======================================
Exposes the Living Capability System (LCS) as a standard JSON-RPC 2.0 stdio
MCP server for integration with external AI agent environments (Google Antigravity,
Claude Code, Cursor, Windsurf, OpenCode).

Tools Exposed:
  - lcs_search: Natural language search across registered capabilities and skills.
  - lcs_inspect: Inspect full capability definition, parameters, and CAS blob digest.
  - lcs_plan: Synthesize an acyclic DAG execution plan from user intent.
  - lcs_govern: Evaluate Gate 1 zero-trust policy and interface attestations for a plan.
  - lcs_execute: Execute an approved plan with a signed authorization token.
  - lcs_skill_discover: Run multi-environment discovery across authorized roots.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from .config import LCSConfig
from .context import LCSContext
from .skills import ArtifactTaxonomyKind, EnvironmentOrigin
from .governance import ApproverConsent, ApproverRole, GovernanceStatus
from .execution import ExecutionLifecycleState

logger = logging.getLogger("lcs.mcp")

TOOLS_SPEC = [
    {
        "name": "lcs_search",
        "description": "Search registered capabilities and skills using natural language, FTS5 keywords, and precedence ranking.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language query describing the desired capability or tool"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default 10)",
                    "default": 10
                },
                "taxonomy": {
                    "type": "string",
                    "description": "Optional taxonomy filter: SKILL, COMMAND, RULE, AGENT_INSTRUCTION, AGENT_CONFIGURATION",
                    "enum": ["SKILL", "COMMAND", "RULE", "AGENT_INSTRUCTION", "AGENT_CONFIGURATION"]
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "lcs_inspect",
        "description": "Inspect full relational metadata, semantic parameter profiles, and CAS definition digest for a capability URN.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "capability_urn": {
                    "type": "string",
                    "description": "Canonical URN (e.g. urn:lcs:skill:antigravity.workspace:my-skill)"
                }
            },
            "required": ["capability_urn"]
        }
    },
    {
        "name": "lcs_plan",
        "description": "Synthesize an acyclic DAG execution plan from plain English intent with upstream-to-downstream parameter binding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "intent": {
                    "type": "string",
                    "description": "Plain English description of what needs to be executed"
                }
            },
            "required": ["intent"]
        }
    },
    {
        "name": "lcs_govern",
        "description": "Evaluate Gate 1 zero-trust policy and interface HMAC attestations for an execution plan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "plan_json": {
                    "type": "string",
                    "description": "Serialized JSON string of the execution plan"
                }
            },
            "required": ["plan_json"]
        }
    },
    {
        "name": "lcs_execute",
        "description": "Execute a governed plan in the sandboxed runtime using a signed Execution Authorization Token (EAT).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "plan_json": {
                    "type": "string",
                    "description": "Serialized JSON string of the execution plan"
                },
                "token_id": {
                    "type": "string",
                    "description": "Cryptographically signed Execution Authorization Token ID (eat-...)"
                }
            },
            "required": ["plan_json", "token_id"]
        }
    },
    {
        "name": "lcs_skill_discover",
        "description": "Trigger discovery across authorized workspace, global, and plugin skills directories.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "environment": {
                    "type": "string",
                    "description": "Optional environment filter: GOOGLE_ANTIGRAVITY, CLAUDE_CODE, OPENCODE",
                    "enum": ["GOOGLE_ANTIGRAVITY", "CLAUDE_CODE", "OPENCODE"]
                }
            }
        }
    }
]


class LCSMCPServer:
    """Stdio JSON-RPC 2.0 MCP server for LCS."""

    def __init__(self, ctx: Optional[LCSContext] = None):
        self.ctx = ctx or LCSContext(auto_migrate=True)

    def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches an MCP tool call to the matching LCS service."""
        try:
            if name == "lcs_search":
                query = arguments.get("query", "")
                limit = int(arguments.get("limit", 10))
                tax_str = arguments.get("taxonomy")
                tax_kind = [ArtifactTaxonomyKind(tax_str)] if tax_str else None

                candidates = self.ctx.retrieval_coordinator.retrieve(
                    query=query,
                    limit=limit,
                    taxonomy_kinds=tax_kind
                )
                results = [c.to_dict() for c in candidates]
                return {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({"query": query, "count": len(results), "candidates": results}, indent=2)
                    }]
                }

            elif name == "lcs_inspect":
                urn = arguments.get("capability_urn", "")
                cap = self.ctx.cap_service.retrieve_capability(urn)
                prof = None
                try:
                    prof = self.ctx.profile_service.get_profile(urn)
                except Exception:
                    pass

                info = {
                    "capability_urn": cap.capability_urn,
                    "name": cap.name,
                    "version": cap.version,
                    "description": cap.description,
                    "blob_digest": cap.blob_digest,
                    "profile": prof.to_dict() if prof else None
                }
                return {
                    "content": [{"type": "text", "text": json.dumps(info, indent=2)}]
                }

            elif name == "lcs_plan":
                intent = arguments.get("intent", "")
                plan = self.ctx.planning_engine.create_plan(intent)
                return {
                    "content": [{"type": "text", "text": json.dumps(plan.to_dict(), indent=2)}]
                }

            elif name == "lcs_govern":
                plan_json = arguments.get("plan_json", "{}")
                plan_data = json.loads(plan_json) if isinstance(plan_json, str) else plan_json
                from lcs.planning import ExecutionPlan
                plan = ExecutionPlan.from_dict(plan_data)
                eval_res = self.ctx.governance_engine.evaluate_plan(plan)
                out = {
                    "status": eval_res.status.value,
                    "gate_1_status": eval_res.gate_1_status,
                    "gate_2_status": eval_res.gate_2_status,
                    "plan_integrity_hash": eval_res.plan_integrity_hash,
                    "reasons": eval_res.reasons,
                    "warnings": eval_res.warnings,
                    "presentation_text": eval_res.presentation_text
                }
                return {
                    "content": [{"type": "text", "text": json.dumps(out, indent=2)}]
                }

            elif name == "lcs_execute":
                plan_json = arguments.get("plan_json", "{}")
                token_id = arguments.get("token_id", "")
                plan_data = json.loads(plan_json) if isinstance(plan_json, str) else plan_json
                from lcs.planning import ExecutionPlan
                plan = ExecutionPlan.from_dict(plan_data)

                # Fetch token from governance engine
                cur = self.ctx.conn.cursor()
                cur.execute("SELECT token_id, plan_id, plan_integrity_hash, policy_revision_id, issued_at, expires_at, signature FROM eat_tokens WHERE token_id = ?;", (token_id,))
                row = cur.fetchone()
                if not row:
                    return {
                        "isError": True,
                        "content": [{"type": "text", "text": f"Execution Authorization Token '{token_id}' not found."}]
                    }

                from lcs.governance import ExecutionAuthorizationToken
                token = ExecutionAuthorizationToken(
                    token_id=row[0],
                    plan_id=row[1],
                    plan_integrity_hash=row[2],
                    policy_revision_id=row[3],
                    issued_at=row[4],
                    expires_at=row[5],
                    signature=row[6]
                )

                run_res = self.ctx.execution_engine.execute_plan(plan, token)
                return {
                    "content": [{"type": "text", "text": json.dumps(run_res.to_dict(), indent=2)}]
                }

            elif name == "lcs_skill_discover":
                env_str = arguments.get("environment")
                env = EnvironmentOrigin[env_str] if env_str else None
                records = self.ctx.skill_service.run_full_pipeline(environment=env)
                recs_summary = [
                    {
                        "name": r.name,
                        "canonical_urn": r.canonical_urn,
                        "taxonomy_kind": r.taxonomy_kind.value,
                        "environment_origin": r.environment_origin.value,
                        "lifecycle_state": r.lifecycle_state.value
                    }
                    for r in records
                ]
                return {
                    "content": [{
                        "type": "text",
                        "text": json.dumps({"count": len(records), "artifacts": recs_summary}, indent=2)
                    }]
                }

            else:
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Unknown tool: {name}"}]
                }

        except Exception as e:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"Error executing tool '{name}': {str(e)}"}]
            }

    def run_stdio(self) -> None:
        """Runs the JSON-RPC 2.0 stdio event loop."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            try:
                request = json.loads(line)
            except json.JSONDecodeError as e:
                self._send_error(None, -32700, f"Parse error: {str(e)}")
                continue

            req_id = request.get("id")
            method = request.get("method")
            params = request.get("params", {})

            if method == "initialize":
                self._send_response(req_id, {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "lcs-mcp-server",
                        "version": "3.0.0"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                })

            elif method == "notifications/initialized":
                pass  # Client acknowledged initialization

            elif method == "tools/list":
                self._send_response(req_id, {
                    "tools": TOOLS_SPEC
                })

            elif method == "tools/call":
                tool_name = params.get("name", "")
                arguments = params.get("arguments", {})
                result = self.handle_tool_call(tool_name, arguments)
                self._send_response(req_id, result)

            elif method == "ping":
                self._send_response(req_id, {})

            else:
                self._send_error(req_id, -32601, f"Method '{method}' not found.")

    def _send_response(self, req_id: Any, result: Any) -> None:
        """Sends a JSON-RPC 2.0 success response to stdout."""
        msg = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result
        }
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    def _send_error(self, req_id: Any, code: int, message: str) -> None:
        """Sends a JSON-RPC 2.0 error response to stdout."""
        msg = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": message
            }
        }
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()


def run_mcp_server(ctx: Optional[LCSContext] = None) -> int:
    """CLI entry point to run LCS as an MCP server."""
    server = LCSMCPServer(ctx=ctx)
    server.run_stdio()
    return 0
