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
from . import __version__

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
    },
    {
        "name": "lcs_call_me",
        "description": "Unified natural language entry point for Living Capability System (LCS). Discovers capabilities, plans, evaluates governance, executes multi-step workflows, or returns token-optimized skill instructions for the host agent.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "description": "Natural language task or capability instruction"
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional persistent session identifier"
                },
                "execute": {
                    "type": "boolean",
                    "description": "Whether to authorize and execute the workflow through the governed execution pipeline (default: false)",
                    "default": False
                },
                "handoff": {
                    "type": "boolean",
                    "description": "Whether to return token-optimized skill instructions and dependencies for direct host execution (default: false)",
                    "default": False
                },
                "budget": {
                    "type": "integer",
                    "description": "Estimated token budget limit for context hydration"
                },
                "authorization_token": {
                    "type": "string",
                    "description": "Independently authenticated Execution Authorization Token ID (eat-...) scoped to the intended task"
                },
                "token_id": {
                    "type": "string",
                    "description": "Alias for authorization_token"
                },
                "inputs": {
                    "type": "object",
                    "description": "Optional key-value parameters or structured inputs for the task"
                },
                "deliverables": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional expected deliverable file paths"
                },
                "approver_role": {
                    "type": "string",
                    "description": "Role of the approver (e.g. HUMAN_OPERATOR, AUTOMATED_AGENT)",
                    "enum": ["HUMAN_OPERATOR", "AUTOMATED_AGENT"]
                },
                "approver_identity": {
                    "type": "string",
                    "description": "Principal identity authorizing execution"
                },
                "decision": {
                    "type": "string",
                    "description": "Explicit approver decision ('APPROVED' or 'REJECTED')",
                    "enum": ["APPROVED", "REJECTED"]
                }
            },
            "required": ["task"]
        }
    },
    {
        "name": "lcs_hydrate_context",
        "description": "Hydrate local project context, ambient rules, host-specific instructions, skills, and session continuity for cross-agent switching.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_root": {
                    "type": "string",
                    "description": "Target workspace root directory (default: current workspace)"
                },
                "target_agent": {
                    "type": "string",
                    "description": "Optional target agent adapter name (e.g. claude_code, antigravity, opencode, codex)"
                },
                "token_budget": {
                    "type": "integer",
                    "description": "Optional maximum token budget limit for context hydration"
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional session identifier for continuity state"
                }
            }
        }
    }
]


def _deserialize_execution_plan(plan_data: Any) -> Any:
    from lcs.planning import ExecutionPlan, PlanStep, StepInputBinding, StepOutputDefinition, BindingSourceType
    if isinstance(plan_data, ExecutionPlan):
        return plan_data
    if isinstance(plan_data, str):
        plan_data = json.loads(plan_data)

    steps = []
    for s in plan_data.get("steps", []):
        if isinstance(s, PlanStep):
            steps.append(s)
            continue
        bindings = {}
        for b_name, b_val in s.get("input_bindings", {}).items():
            if isinstance(b_val, StepInputBinding):
                bindings[b_name] = b_val
            elif isinstance(b_val, dict):
                src_val = b_val.get("source_type") or b_val.get("source") or "USER_SUPPLIED"
                src_enum = BindingSourceType(src_val) if hasattr(BindingSourceType, str(src_val)) or src_val in [e.value for e in BindingSourceType] else BindingSourceType.USER_SUPPLIED
                bindings[b_name] = StepInputBinding(
                    param_name=b_val.get("param_name", b_name),
                    param_type=b_val.get("param_type", "string"),
                    required=b_val.get("required", False),
                    bound_value=b_val.get("bound_value") or b_val.get("value"),
                    source_type=src_enum,
                    source_step_id=b_val.get("source_step_id"),
                    source_output_field=b_val.get("source_output_field")
                )
            else:
                bindings[b_name] = StepInputBinding(param_name=b_name, param_type="string", required=False, bound_value=b_val)

        outputs = {}
        for o_name, o_val in s.get("output_definitions", {}).items():
            if isinstance(o_val, StepOutputDefinition):
                outputs[o_name] = o_val
            elif isinstance(o_val, dict):
                outputs[o_name] = StepOutputDefinition(
                    field_name=o_val.get("field_name", o_name),
                    field_type=o_val.get("field_type") or o_val.get("type") or "string"
                )
            else:
                outputs[o_name] = StepOutputDefinition(field_name=o_name, field_type="string")

        steps.append(PlanStep(
            step_id=s["step_id"],
            step_index=s.get("step_index", len(steps) + 1),
            capability_urn=s["capability_urn"],
            display_name=s.get("display_name", s["capability_urn"]),
            sub_goal=s.get("sub_goal", ""),
            selection_reason=s.get("selection_reason", ""),
            input_bindings=bindings,
            output_definitions=outputs
        ))

    return ExecutionPlan(
        plan_id=plan_data["plan_id"],
        request_query=plan_data.get("request_query", ""),
        plan_type=plan_data.get("plan_type", "SINGLE_CAPABILITY"),
        status=plan_data.get("status", "PLAN_READY"),
        steps=steps,
        dag_edges=plan_data.get("dag_edges", []),
        execution_order=plan_data.get("execution_order", [st.step_id for st in steps]),
        missing_inputs=plan_data.get("missing_inputs", []),
        clarifying_questions=plan_data.get("clarifying_questions", []),
        explanation=plan_data.get("explanation", "")
    )


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
                plan = _deserialize_execution_plan(plan_json)
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
                plan = _deserialize_execution_plan(plan_json)

                # Fetch token from governance engine
                cur = self.ctx.conn.cursor()
                cur.execute("""
                    SELECT jti, plan_id, plan_integrity_hash, policy_revision_id,
                           state, approver_json, policy_context_json, constraints_json,
                           issued_at, expires_at, signature
                    FROM governance_tokens WHERE jti = ?;
                """, (token_id,))
                row = cur.fetchone()
                if not row:
                    return {
                        "isError": True,
                        "content": [{"type": "text", "text": f"Execution Authorization Token '{token_id}' not found."}]
                    }

                from lcs.governance import ExecutionAuthorizationToken
                token = ExecutionAuthorizationToken(
                    token_id=row[0],
                    jti=row[0],
                    iss="lcs-governance",
                    aud="lcs-runtime",
                    iat=row[8],
                    nbf=row[8],
                    exp=row[9],
                    plan_id=row[1],
                    plan_integrity_hash=row[2],
                    key_id="default",
                    approver=json.loads(row[5]) if row[5] else {},
                    constraints=json.loads(row[7]) if row[7] else {},
                    policy_context=json.loads(row[6]) if row[6] else {},
                    signature=row[10] or ""
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

            elif name == "lcs_call_me":
                task = arguments.get("task", "")
                if not isinstance(task, str) or not task.strip():
                    return {
                        "isError": True,
                        "content": [{"type": "text", "text": "Task instruction cannot be empty."}]
                    }
                task = task.strip()

                session_id = arguments.get("session_id")
                do_execute = bool(arguments.get("execute", False))
                do_handoff = bool(arguments.get("handoff", False))
                budget = arguments.get("budget")
                inputs = arguments.get("inputs")
                deliverables = arguments.get("deliverables")
                decision = arguments.get("decision")
                approver_role_str = arguments.get("approver_role", "HUMAN_OPERATOR")
                approver_identity = arguments.get("approver_identity", "mcp-client@local")

                # 1. Handoff mode: token-optimized instructions and dependencies
                if do_handoff:
                    if self.ctx.inventory.total_count == 0 and hasattr(self.ctx, "adapter_registry"):
                        self.ctx.inventory.initialize_environment(adapters=self.ctx.adapter_registry.list_all())

                    from lcs.inventory.models import ResourceType
                    matches = (record for record in self.ctx.inventory.search(
                        task, limit=2, resource_types=[ResourceType.SKILL]
                    ) if record.name != "call-me")
                    primary = next(matches, None)

                    active_adapter = self.ctx.get_active_adapter()
                    host_str = active_adapter.kind.value if hasattr(active_adapter.kind, "value") else str(active_adapter.kind)

                    if primary is None:
                        handoff_payload = {
                            "ready": False,
                            "host": host_str,
                            "block_reason": f"Zero registered capabilities matched task '{task}'.",
                            "missing_required": [],
                            "instructions": "",
                            "dependencies": {},
                            "task_query": task,
                            "primary_urn": None,
                            "estimated_tokens": 0,
                            "token_metric": "ESTIMATE",
                            "budget_limit": budget,
                            "budget_exceeded": False,
                            "omitted_references": [],
                            "provenance_hashes": {}
                        }
                        return {
                            "content": [{"type": "text", "text": json.dumps(handoff_payload, indent=2)}]
                        }

                    retrieval = self.ctx.deep_retriever.retrieve_deep(primary.urn, active_environment=host_str)
                    payload = self.ctx.deep_retriever.optimize_context_transfer(
                        task_query=task,
                        retrieval_result=retrieval,
                        token_budget=budget
                    )

                    required = {primary.urn}
                    stack = [primary]
                    by_identity = {
                        identity: record
                        for record in retrieval.resolved_dependencies
                        for identity in (record.name, record.urn)
                    }
                    while stack:
                        for edge in stack.pop().declared_dependencies:
                            dep = by_identity.get(edge.get("name"))
                            if edge.get("mandatory", True) and dep and dep.urn not in required:
                                required.add(dep.urn)
                                stack.append(dep)

                    missing = [record.name for record in retrieval.resolved_dependencies
                               if record.urn in required and record.name not in payload.dependency_snippets]
                    all_missing = sorted(set(retrieval.missing_dependencies + missing))
                    ready = retrieval.is_executable and not all_missing and not payload.budget_exceeded

                    block_reason = None
                    if not ready:
                        if not retrieval.is_executable or all_missing:
                            block_reason = f"Missing or inaccessible required resources: {all_missing}"
                        elif payload.budget_exceeded:
                            block_reason = f"Token budget exceeded: estimated {payload.estimated_tokens} tokens exceeds budget limit of {payload.token_budget_limit}"

                    handoff_data = {
                        "ready": ready,
                        "host": host_str,
                        "block_reason": block_reason,
                        "missing_required": all_missing,
                        "instructions": payload.instructions_text if ready else "",
                        "dependencies": payload.dependency_snippets if ready else {},
                        "task_query": payload.task_query,
                        "primary_urn": payload.primary_urn,
                        "estimated_tokens": payload.estimated_tokens,
                        "token_metric": "ESTIMATE",
                        "budget_limit": payload.token_budget_limit,
                        "budget_exceeded": payload.budget_exceeded,
                        "omitted_references": payload.omitted_references,
                        "provenance_hashes": payload.provenance_hashes
                    }

                    # Session persistence for cross-agent continuity
                    if session_id and hasattr(self.ctx, "project_context_hydrator"):
                        try:
                            ws = getattr(self.ctx.inventory, "workspace_root", os.getcwd())
                            self.ctx.project_context_hydrator.save_session_state(
                                workspace_root=ws,
                                session_id=session_id,
                                state_data={"task": task, "primary_urn": payload.primary_urn, "ready": ready}
                            )
                        except Exception as e:
                            logger.debug(f"Session state save note: {e}")

                    return {
                        "content": [{"type": "text", "text": json.dumps(handoff_data, indent=2)}]
                    }

                # 2. Execution mode: Enforce Independent Governance Authorization & Scoping
                elif do_execute:
                    token_id = arguments.get("authorization_token") or arguments.get("token_id")

                    # Requirement 4: MCP caller cannot self-authorize execution by sending decision="APPROVED"
                    if not token_id:
                        if arguments.get("decision") == "APPROVED":
                            return {
                                "isError": True,
                                "content": [{
                                    "type": "text",
                                    "text": json.dumps({
                                        "status": "UNAUTHORIZED",
                                        "error": "SELF_AUTHORIZATION_PROHIBITED",
                                        "message": "MCP caller cannot self-authorize execution by sending decision='APPROVED'. An independently authenticated authorization token (authorization_token) scoped to the intended action is required.",
                                        "governance_status": "REJECTED"
                                    }, indent=2)
                                }]
                            }

                        resp = self.ctx.call_me.execute_call_me(
                            raw_message=f"/call-me {task}",
                            session_id=session_id,
                            inputs=inputs,
                            deliverables=deliverables,
                            execute=False
                        )
                        return {
                            "isError": True,
                            "content": [{
                                "type": "text",
                                "text": json.dumps({
                                    "status": "APPROVAL_REQUIRED",
                                    "message": "Execution requires independent authorization. Review the plan and obtain an authorization token before executing.",
                                    "governance_status": "PENDING_CONSENT",
                                    "request_id": resp.request_id if resp else None,
                                    "candidate_count": resp.candidate_count if resp else 0,
                                    "candidate_urns": resp.candidate_urns if resp else []
                                }, indent=2)
                            }]
                        }

                    # Fetch and verify token from governance store
                    cur = self.ctx.conn.cursor()
                    cur.execute("""
                        SELECT jti, plan_id, plan_integrity_hash, policy_revision_id,
                               state, approver_json, policy_context_json, constraints_json,
                               issued_at, expires_at, signature
                        FROM governance_tokens WHERE jti = ?;
                    """, (token_id,))
                    row = cur.fetchone()
                    if not row:
                        return {
                            "isError": True,
                            "content": [{
                                "type": "text",
                                "text": json.dumps({
                                    "status": "UNAUTHORIZED",
                                    "error": "TOKEN_NOT_FOUND",
                                    "message": f"Execution Authorization Token '{token_id}' not found in governance store."
                                }, indent=2)
                            }]
                        }

                    token_state = row[4]
                    expires_at = row[9]
                    now_ts = datetime.now(timezone.utc).timestamp()
                    if token_state not in ("ISSUED", "ACTIVE"):
                        return {
                            "isError": True,
                            "content": [{
                                "type": "text",
                                "text": json.dumps({
                                    "status": "UNAUTHORIZED",
                                    "error": "TOKEN_INVALID_STATE",
                                    "message": f"Execution Authorization Token is in state '{token_state}', not active."
                                }, indent=2)
                            }]
                        }
                    
                    is_expired = False
                    if expires_at is not None:
                        try:
                            is_expired = float(expires_at) < now_ts
                        except (ValueError, TypeError):
                            is_expired = str(expires_at) < datetime.now(timezone.utc).isoformat()

                    if is_expired:
                        return {
                            "isError": True,
                            "content": [{
                                "type": "text",
                                "text": json.dumps({
                                    "status": "UNAUTHORIZED",
                                    "error": "TOKEN_EXPIRED",
                                    "message": f"Execution Authorization Token expired at {expires_at}."
                                }, indent=2)
                            }]
                        }

                    # Synthesize current task plan to verify scoping
                    task_plan = self.ctx.planning_engine.create_plan(task, user_arguments=inputs)
                    eval_res = self.ctx.governance_engine.evaluate_plan(task_plan)
                    expected_hash = eval_res.plan_integrity_hash
                    token_plan_hash = row[2]

                    if token_plan_hash != expected_hash:
                        return {
                            "isError": True,
                            "content": [{
                                "type": "text",
                                "text": json.dumps({
                                    "status": "UNAUTHORIZED",
                                    "error": "TOKEN_SCOPE_MISMATCH",
                                    "message": f"Token is not scoped to this task. Token plan hash '{token_plan_hash[:16]}...' does not match intended action hash '{expected_hash[:16]}...'.",
                                    "governance_status": "REJECTED"
                                }, indent=2)
                            }]
                        }

                    approver_info = json.loads(row[5]) if row[5] else {}
                    approver_principal = approver_info.get("principal") or "independent-operator"
                    approver_role_val = approver_info.get("role") or "HUMAN_OPERATOR"
                    try:
                        role_enum = ApproverRole[approver_role_val] if hasattr(ApproverRole, approver_role_val) else ApproverRole.HUMAN_OPERATOR
                    except Exception:
                        role_enum = ApproverRole.HUMAN_OPERATOR

                    consent = ApproverConsent(
                        principal=approver_principal,
                        role=role_enum,
                        method="INDEPENDENT_AUTHENTICATED_TOKEN"
                    )

                    exec_res = self.ctx.call_me.execute_call_me(
                        raw_message=f"/call-me {task}",
                        session_id=session_id,
                        inputs=inputs,
                        deliverables=deliverables,
                        execute=True,
                        approver_consent=consent
                    )

                    if isinstance(exec_res, dict):
                        is_err = exec_res.get("status") in ("FAILED", "REJECTED", "ERROR")
                        return {
                            "isError": is_err,
                            "content": [{"type": "text", "text": json.dumps(exec_res, indent=2)}]
                        }
                    else:
                        out_dict = exec_res.to_dict() if hasattr(exec_res, "to_dict") else {"result": str(exec_res)}
                        return {
                            "content": [{"type": "text", "text": json.dumps(out_dict, indent=2)}]
                        }

                # 3. Plan / Proposal mode: Submit task for candidate matching and preflight
                else:
                    resp = self.ctx.call_me.execute_call_me(
                        raw_message=f"/call-me {task}",
                        session_id=session_id,
                        inputs=inputs,
                        deliverables=deliverables,
                        execute=False
                    )
                    out = resp.to_dict() if resp and hasattr(resp, "to_dict") else {"status": "UNKNOWN"}
                    return {
                        "content": [{"type": "text", "text": json.dumps(out, indent=2)}]
                    }

            elif name == "lcs_hydrate_context":
                ws = arguments.get("workspace_root") or getattr(self.ctx.inventory, "workspace_root", os.getcwd())
                target_agent = arguments.get("target_agent")
                budget = arguments.get("token_budget")
                session_id = arguments.get("session_id")

                payload = self.ctx.project_context_hydrator.hydrate_project_context(
                    workspace_root=ws,
                    target_agent=target_agent,
                    token_budget=budget,
                    session_id=session_id
                )
                return {
                    "content": [{"type": "text", "text": json.dumps(payload.to_dict(), indent=2)}]
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
                        "version": __version__
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

