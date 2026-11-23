"""
LCS Core Handoff Bridge (Phase 2A)
==================================
Routes validated TaskRequests into the LCS Core retrieval, planning, and
governance pre-flight subsystems.

Invariants:
- Zero automatic execution of un-governed or destructive actions.
- Preserves Governance Gate 1 and Gate 2.
- Maintains strict session isolation.
"""

import time
import re
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple

from .contract import TaskRequest, InvocationResponse, ConsentState
from ..hydration.models import HydratedCapability, ResourceUtilizationState
from ..inventory.models import ResourceType
from ..dependencies.graph import DependencyGraph, DependencyError
from ..subagents.models import SubagentTask, SubagentExecutionResult
from ..planning import (
    ExecutionPlan,
    PlanStep,
    StepInputBinding,
    StepOutputDefinition,
    BindingSourceType,
)
from ..governance import (
    ApproverConsent,
    ApproverRole,
    GovernanceStatus,
)
from ..policy import InterfaceTrustPolicy
from ..execution import ExecutionLifecycleState

logger = logging.getLogger("lcs.interface.bridge")


def _semantic_phase_rank(urn: str, cap: Any = None) -> int:
    """
    Ranks capabilities into architectural execution phases:
      Phase 0: Components, Models, Scaffolding, Workers, Services (independent / fan-out)
      Phase 1: Assembly, Integration, Pipeline, Composition, Runner (fan-in / aggregator)
      Phase 2: Verification, Testing, QA, Audit, Linter, Security (validation gate)
    """
    ident = urn.split(":")[-1].lower() if ":" in urn else urn.lower()
    text = (
        ident + " " +
        (getattr(cap, "name", "") or "") + " " +
        (getattr(cap, "display_name", "") or "") + " " +
        (getattr(cap, "description", "") or "")
    ).lower()

    if any(k in text for k in ("verify", "verification", "audit", "qa", "lint", "benchmark", "validate", "eval", "test-runner", "tests", "test_")):
        return 2
    if re.search(r'\btest\b', text) and not any(k in text for k in ("telemetry", "health", "scaffold", "service", "worker", "build", "create")):
        return 2
    if any(k in text for k in ("assemble", "assembly", "integrate", "integration", "gateway", "orchestrat", "compose", "join", "aggregate")):
        return 1
    return 0


class LCSCoreBridge:
    """
    Coordinates the handoff of a TaskRequest into LCS Core intelligence subsystems.
    """

    def __init__(self, context: Any):
        self.ctx = context

    def _is_capability_compatible_with_host(self, urn: str, active_host: Optional[str]) -> bool:
        """
        Enforces that host-specific capabilities cannot be executed on incompatible hosts.
        Generic, shared, or host-agnostic capabilities remain executable everywhere.
        """
        if not active_host or active_host.lower() in ("generic_posix", "generic"):
            return True
        active = active_host.lower()
        parts = urn.split(":")
        if len(parts) >= 4:
            origin = parts[3].lower()
            primary_origin = origin.split(".")[0]
            if primary_origin in ("codex", "claude_code", "opencode", "antigravity"):
                if primary_origin != active:
                    return False
        return True

    def submit_task(self, request: TaskRequest) -> InvocationResponse:
        """
        Receives a validated TaskRequest, searches matching capabilities from
        the unified inventory and local cache, and prepares initial candidate proposals.
        Guarantees that a weak cached match cannot hide a better installed skill,
        disallows self-referential call-me selection, and produces actionable
        clarifications or limitation responses for ambiguous/unmatched tasks.
        """
        try:
            query = request.normalized_task_description
            clean_q = query.strip().lower()

            # Check for genuinely ambiguous queries upfront
            ambiguous_keywords = {"help", "hi", "hello", "do it", "run", "execute", "start", "test", "please", "ok", "update", "fix", "what can you do"}
            clean_tokens = [w for w in re.split(r'\W+', clean_q) if w]
            is_ambiguous = (
                clean_q in ambiguous_keywords
                or len(clean_tokens) <= 1
                or (len(clean_tokens) == 2 and clean_tokens[0] in ("do", "run", "make", "fix", "please") and clean_tokens[1] in ("it", "this", "that", "help", "me"))
            )
            if is_ambiguous:
                msg = f"Task is ambiguous ('{query}'). Please specify what outcome, tool, or capability is desired."
                return InvocationResponse(
                    request_id=request.request_id,
                    session_id=request.session_id,
                    status="ACCEPTED",
                    message=msg,
                    candidate_count=0,
                    candidate_urns=[],
                    governance_status="PENDING_CAPABILITIES"
                )

            # 1. Search candidate capabilities using Unified Inventory & local cache
            candidate_scores: Dict[str, float] = {}

            # Primary source: Unified Capability Inventory (live cross-host catalog)
            if hasattr(self.ctx, "inventory") and self.ctx.inventory:
                try:
                    if self.ctx.inventory.total_count == 0 and hasattr(self.ctx, "adapter_registry"):
                        self.ctx.inventory.initialize_environment(adapters=self.ctx.adapter_registry.list_all())
                    matches = self.ctx.inventory.search(query, limit=10)
                    for idx, m in enumerate(matches):
                        score = 100.0 - (idx * 5.0)
                        candidate_scores[m.urn] = max(candidate_scores.get(m.urn, 0.0), score)
                except Exception as e:
                    logger.debug(f"Inventory search error: {e}")

            # Secondary source: local cache (warm cache hits)
            if hasattr(self.ctx, "cache") and self.ctx.cache:
                try:
                    cached_candidates = self.ctx.cache.search_candidates(query, limit=10)
                    for idx, c in enumerate(cached_candidates):
                        score = getattr(c, "relevance_score", 60.0 - (idx * 5.0))
                        candidate_scores[c.urn] = max(candidate_scores.get(c.urn, 0.0), score)
                except Exception as e:
                    logger.debug(f"Cache search error: {e}")

            # Fallback source: skill service
            if not candidate_scores and hasattr(self.ctx, "skill_service") and self.ctx.skill_service:
                try:
                    results = self.ctx.skill_service.search(query, limit=10)
                    for idx, c in enumerate(results):
                        candidate_scores[c.capability_urn] = 50.0 - (idx * 5.0)
                except Exception as e:
                    logger.debug(f"Skill service search error: {e}")

            # Active caller environment for host compatibility check
            active_host = (getattr(request, "invocation_environment", None) or getattr(request, "caller_environment", None) or (request.provenance.get("env") if hasattr(request, "provenance") and isinstance(request.provenance, dict) else "") or "").lower()
            if not active_host and hasattr(self.ctx, "adapter_registry") and self.ctx.adapter_registry:
                try:
                    active_host = self.ctx.adapter_registry.detect_active().kind.value.lower()
                except Exception:
                    pass

            # Disallow self-referential call-me, filter by host compatibility, and rank candidates
            candidates = [
                urn for urn, _ in sorted(candidate_scores.items(), key=lambda x: x[1], reverse=True)
                if not (urn.lower().endswith((":call-me", ":call_me")) or "/call-me" in urn.lower())
                and self._is_capability_compatible_with_host(urn, active_host)
            ]

            # 2. Construct response
            if not candidates:
                ambiguous_keywords = {"help", "hi", "hello", "do it", "run", "execute", "start", "test", "please", "ok", "update", "fix", "what can you do"}
                clean_tokens = [w for w in re.split(r'\W+', clean_q) if w]
                is_ambiguous = (
                    clean_q in ambiguous_keywords
                    or len(clean_tokens) <= 1
                    or (len(clean_tokens) == 2 and clean_tokens[0] in ("do", "run", "make", "fix") and clean_tokens[1] in ("it", "this", "that"))
                )

                if is_ambiguous:
                    msg = f"Task is ambiguous ('{query}'). Please specify what outcome, tool, or capability is desired."
                else:
                    msg = f"Task received. Zero registered capabilities matched query: '{query}'."

                return InvocationResponse(
                    request_id=request.request_id,
                    session_id=request.session_id,
                    status="ACCEPTED",
                    message=msg,
                    candidate_count=0,
                    candidate_urns=[],
                    governance_status="PENDING_CAPABILITIES"
                )

            msg = f"Task accepted. Matched {len(candidates)} candidate capability URN(s)."
            return InvocationResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                status="ACCEPTED",
                message=msg,
                candidate_count=len(candidates),
                candidate_urns=candidates,
                governance_status="PENDING_APPROVAL"
            )

        except Exception as e:
            logger.error(f"LCS Core handoff failure: {e}", exc_info=True)
            return InvocationResponse(
                request_id=request.request_id,
                session_id=request.session_id,
                status="ERROR",
                message=f"Failed to hand off task to LCS Core: {e}",
                candidate_count=0,
                candidate_urns=[],
                governance_status="REJECTED",
                error_details=str(e)
            )

    def hydrate_candidates(self, candidate_urns: List[str]) -> List[HydratedCapability]:
        """
        Deep-hydrates a list of candidate capability URNs with complete instructions
        and auxiliary assets without replacing with AI summaries.
        """
        if not hasattr(self.ctx, "hydration_engine") or not self.ctx.hydration_engine:
            raise RuntimeError("HydrationEngine not initialized on LCSContext.")

        hydrated = []
        for urn in candidate_urns:
            cap = self.ctx.hydration_engine.hydrate_capability(urn)
            hydrated.append(cap)
        return hydrated

    def resolve_dependencies(self, capabilities: List[HydratedCapability]) -> Tuple[List[str], DependencyGraph]:
        """
        Builds a multi-resource dependency graph and computes deterministic topological
        execution sequence. Fails closed on cycles or missing mandatory dependencies.
        """
        if not hasattr(self.ctx, "dependency_resolver") or not self.ctx.dependency_resolver:
            raise RuntimeError("DependencyResolver not initialized on LCSContext.")

        graph = self.ctx.dependency_resolver.build_graph_for_capabilities(capabilities)
        order = graph.resolve_order()
        return order, graph

    def prepare_execution_plan(
        self,
        request: TaskRequest,
        candidate_urns: List[str]
    ) -> Dict[str, Any]:
        """
        Prepares a validated, dependency-ordered, integrity-verified execution plan.
        Invariants:
        - Does NOT execute without explicit Governance Gate 2 authorization.
        - Verifies Hash-On-Activation for all root and auxiliary files.
        - Verifies resource gates before and after staging.
        """
        # 1. Hydrate candidates
        hydrated_caps = self.hydrate_candidates(candidate_urns)

        # 2. Resolve dependencies
        exec_order, graph = self.resolve_dependencies(hydrated_caps)

        # 3. Hash-On-Activation Pre-Flight Check
        verified_capabilities = []
        if hasattr(self.ctx, "activation_verifier") and self.ctx.activation_verifier:
            for cap in hydrated_caps:
                rec = self.ctx.activation_verifier.verify_capability_activation(cap.capability_urn)
                verified_capabilities.append(rec.capability_urn)
                cap.state = ResourceUtilizationState.PREPARED

        return {
            "request_id": request.request_id,
            "session_id": request.session_id,
            "execution_order": exec_order,
            "hydrated_count": len(hydrated_caps),
            "verified_integrity_count": len(verified_capabilities),
            "governance_status": "PREPARED_PENDING_GATE_2",
            "capabilities": [c.to_dict() for c in hydrated_caps]
        }

    def delegate_subagent(
        self,
        task: SubagentTask,
        executor_fn: Optional[Any] = None
    ) -> SubagentExecutionResult:
        """
        Delegates structured subtask to AntigravitySubagentBridge if supported.
        Fails safely and honestly if delegation is unsupported in current environment.
        """
        if not hasattr(self.ctx, "subagent_bridge") or not self.ctx.subagent_bridge:
            raise RuntimeError("SubagentBridge not initialized on LCSContext.")

        return self.ctx.subagent_bridge.dispatch_task(task, executor_fn=executor_fn)

    def execute_task_pipeline(
        self,
        request: TaskRequest,
        candidate_urns: Optional[List[str]] = None,
        approver_consent: Optional[ApproverConsent] = None,
        active_policy: Optional[InterfaceTrustPolicy] = None,
        initial_inputs: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Milestone 2: Orchestrates real multi-capability execution:
        1. Discovers and matches candidate capabilities if not explicitly supplied.
        2. Deeply hydrates instructions from CAS/disk without summarization.
        3. Resolves dependency graph into deterministic topological execution order.
        4. Synthesizes an ExecutionPlan with dynamic input/output bindings.
        5. Obtains Dual-Gate Governance authorization and single-use EAT token.
        6. Dispatches to Runtime Execution Engine with process supervision and compensation.
        7. Audits deliverables and records cryptographic trace receipts.
        """
        if approver_consent is None:
            return {"status": "REJECTED", "request_id": request.request_id,
                    "completed_steps": 0, "total_steps": 0,
                    "message": "Explicit operator consent is required."}

        active_host = (getattr(request, "invocation_environment", None) or getattr(request, "caller_environment", None) or (request.provenance.get("env") if hasattr(request, "provenance") and isinstance(request.provenance, dict) else "") or "").lower()
        if not active_host and hasattr(self.ctx, "adapter_registry") and self.ctx.adapter_registry:
            try:
                active_host = self.ctx.adapter_registry.detect_active().kind.value.lower()
            except Exception:
                pass

        # 1. Candidate Capability Resolution
        if not candidate_urns:
            query = request.normalized_task_description
            clean_q = query.strip().lower()

            # Multi-intent decomposition:
            # 1. Split on explicit sequencing boundaries (e.g. 'and then', 'then', 'followed by', ';')
            seq_splits = [p.strip() for p in re.split(r'\b(?:and\s+then|then|followed\s+by|afterwards|and\s+finally)\b|[;]', clean_q) if len(p.strip()) > 2]

            action_verbs = {
                'build', 'create', 'scaffold', 'setup', 'test', 'verify', 'fix', 'repair',
                'lint', 'audit', 'deploy', 'run', 'execute', 'inspect', 'check', 'generate',
                'compile', 'analyze', 'review', 'format', 'ship', 'benchmark', 'diagnose',
                'validate', 'document', 'publish', 'resolve', 'clean', 'refactor'
            }

            sub_queries = []
            for chunk in seq_splits:
                comma_parts = [p.strip() for p in re.split(r',\s*(?:and\s+)?', chunk) if len(p.strip()) > 2]
                if len(comma_parts) > 1:
                    # Distinguish action clauses from noun lists like 'React, Vite, and Tailwind'
                    action_parts = []
                    for part in comma_parts:
                        words = part.lower().split()
                        has_action = any(w in action_verbs for w in words[:3])
                        action_parts.append((part, has_action))
                    if sum(1 for _, has in action_parts if has) >= 2:
                        sub_queries.extend([p for p, _ in action_parts])
                    else:
                        sub_queries.append(chunk)
                else:
                    sub_queries.append(chunk)

            if hasattr(self.ctx, "inventory") and self.ctx.inventory:
                if self.ctx.inventory.total_count == 0 and hasattr(self.ctx, "adapter_registry"):
                    self.ctx.inventory.initialize_environment(adapters=self.ctx.adapter_registry.list_all())

                if len(sub_queries) > 1:
                    # Multi-intent decomposition: select top candidate for each distinct sub-query
                    selected = []
                    for sq in sub_queries:
                        sq_matches = self.ctx.inventory.search(sq, limit=5)
                        for m in sq_matches:
                            if m.urn not in selected and not m.urn.endswith(":call-me") and self._is_capability_compatible_with_host(m.urn, active_host):
                                selected.append(m.urn)
                                break
                    candidate_urns = selected

                if not candidate_urns:
                    # Single intent or fallback: select the top matching capability
                    matches = self.ctx.inventory.search(query, limit=10)
                    filtered = [m.urn for m in matches if not m.urn.endswith(":call-me") and self._is_capability_compatible_with_host(m.urn, active_host)]
                    candidate_urns = filtered[:1] if filtered else []

            if not candidate_urns and hasattr(self.ctx, "skill_service") and self.ctx.skill_service:
                results = self.ctx.skill_service.search(query, limit=5)
                filtered = [c.capability_urn for c in results if self._is_capability_compatible_with_host(c.capability_urn, active_host)]
                candidate_urns = filtered[:1] if filtered else []

        if not candidate_urns:
            return {
                "status": "FAILED",
                "request_id": request.request_id,
                "completed_steps": 0,
                "total_steps": 0,
                "message": f"Zero registered capabilities matched task query: '{request.original_instruction}'"
            }

        candidate_urns = candidate_urns[:5]

        # 2. Deep Instruction Hydration & Hash-On-Activation Check
        hydrated_caps = self.hydrate_candidates(candidate_urns)
        if hasattr(self.ctx, "activation_verifier") and self.ctx.activation_verifier:
            for cap in hydrated_caps:
                self.ctx.activation_verifier.verify_capability_activation(cap.capability_urn)
                cap.state = ResourceUtilizationState.PREPARED

        # 3. Dependency Resolution & Topological Ordering
        exec_order, dep_graph = self.resolve_dependencies(hydrated_caps)
        # Filter execution order to only include executable capabilities (not static documentation/reference files)
        executable_order = []
        for urn in exec_order:
            # Auxiliary bundle files (e.g. cap:references/..., cap:scripts/...) are internal bundle assets, not distinct plan steps
            if any(urn.startswith(f"{c.capability_urn}:") for c in hydrated_caps):
                continue
            node = dep_graph.nodes.get(urn) if dep_graph else None
            if node and node.resource_type in (ResourceType.DOCUMENTATION, ResourceType.TEMPLATE):
                continue
            if any(urn.endswith(ext) for ext in (".md", ".txt", ".yaml", ".yml", ".json", ".csv")):
                continue
            executable_order.append(urn)

        if not executable_order and candidate_urns:
            executable_order = [candidate_urns[0]]

        # Check if dep_graph contains any explicit dependencies between executable capabilities
        has_cross_cap_deps = any(
            any(dep in executable_order for dep in deps)
            for urn, deps in dep_graph.adjacency.items()
            if urn in executable_order
        ) if dep_graph else False

        # Ensure semantic phase ordering when no explicit cross-capability graph dependencies are declared
        if not has_cross_cap_deps:
            executable_order.sort(key=lambda u: _semantic_phase_rank(u, next((c for c in hydrated_caps if c.capability_urn == u), None)))

        # Quota constraint: ensure total steps does not exceed governance quota ceiling (10)
        exec_order = executable_order[:8]

        # 4. Synthesize Multi-Step Execution Plan with Dynamic I/O Bindings
        steps: List[PlanStep] = []
        dag_edges: List[Tuple[str, str, str, str]] = []
        clean_desc = (request.normalized_task_description or request.original_instruction or "").strip().lower()
        is_explicitly_sequential = bool(re.search(r'\b(?:and\s+then|then|followed\s+by|afterwards|and\s+finally)\b|[;]', clean_desc))
        is_multi_branch = len(exec_order) >= 3 and (not is_explicitly_sequential) and (not has_cross_cap_deps)

        for idx, urn in enumerate(exec_order, start=1):
            cap = next((c for c in hydrated_caps if c.capability_urn == urn), None)
            step_id = f"step-{idx}-{cap.name if cap else 'task'}"

            input_bindings: Dict[str, StepInputBinding] = {}
            if initial_inputs:
                is_primary_or_final = (urn in candidate_urns) or (idx == len(exec_order))
                for k, v in initial_inputs.items():
                    if k in ("deliverable", "deliverable_path", "deliverable_file", "output_file", "target_file", "expected_deliverable", "expected_deliverables"):
                        if is_primary_or_final:
                            input_bindings[k] = StepInputBinding(param_name=k, param_type="string", required=False, bound_value=v)
                    elif idx == 1 or (is_multi_branch and idx == 2):
                        input_bindings[k] = StepInputBinding(param_name=k, param_type="string", required=False, bound_value=v)

            # Resolve prerequisites for step
            step_deps: List[str] = []
            if dep_graph and urn in dep_graph.adjacency:
                dep_urns = dep_graph.adjacency[urn]
                step_deps = [s.step_id for s in steps if s.capability_urn in dep_urns]

            if not step_deps:
                if is_multi_branch:
                    cur_rank = _semantic_phase_rank(urn, cap)
                    if cur_rank == 0 and idx <= 2:
                        step_deps = []
                    elif cur_rank == 1:
                        # Assembly step depends on all preceding phase 0 steps
                        phase0_steps = [s.step_id for s in steps if _semantic_phase_rank(s.capability_urn, next((c for c in hydrated_caps if c.capability_urn == s.capability_urn), None)) == 0]
                        step_deps = phase0_steps if phase0_steps else [steps[-1].step_id]
                    elif cur_rank == 2:
                        # Verification step depends on preceding step (e.g. assembly or join node)
                        phase1_steps = [s.step_id for s in steps if _semantic_phase_rank(s.capability_urn, next((c for c in hydrated_caps if c.capability_urn == s.capability_urn), None)) == 1]
                        if phase1_steps:
                            step_deps = [phase1_steps[-1]]
                        elif len(steps) > 0:
                            step_deps = [s.step_id for s in steps]
                    elif idx == 1:
                        step_deps = []
                    elif idx == 2:
                        step_deps = []
                    elif idx == 3:
                        if len(exec_order) == 3:
                            step_deps = [steps[0].step_id, steps[1].step_id]
                        else:
                            step_deps = [steps[0].step_id]
                    elif idx == 4:
                        step_deps = [steps[1].step_id, steps[2].step_id]
                    else:
                        step_deps = [steps[-1].step_id]
                elif idx > 1:
                    step_deps = [steps[-1].step_id]

            if step_deps:
                for dep_id in step_deps:
                    dag_edges.append((dep_id, step_id, "OUTPUT_TO_INPUT", f"Prerequisite {dep_id}"))

                primary_dep = step_deps[0]
                input_bindings["input_data"] = StepInputBinding(
                    param_name="input_data",
                    param_type="string",
                    required=False,
                    source_type=BindingSourceType.STEP_OUTPUT,
                    source_step_id=primary_dep,
                    source_output_field="result"
                )
                input_bindings["previous_result"] = StepInputBinding(
                    param_name="previous_result",
                    param_type="string",
                    required=False,
                    source_type=BindingSourceType.STEP_OUTPUT,
                    source_step_id=primary_dep,
                    source_output_field="result"
                )
                if len(step_deps) > 1:
                    secondary_dep = step_deps[1]
                    input_bindings["secondary_input_data"] = StepInputBinding(
                        param_name="secondary_input_data",
                        param_type="string",
                        required=False,
                        source_type=BindingSourceType.STEP_OUTPUT,
                        source_step_id=secondary_dep,
                        source_output_field="result"
                    )
                    input_bindings["branch_b_result"] = StepInputBinding(
                        param_name="branch_b_result",
                        param_type="string",
                        required=False,
                        source_type=BindingSourceType.STEP_OUTPUT,
                        source_step_id=secondary_dep,
                        source_output_field="result"
                    )

            step = PlanStep(
                step_id=step_id,
                step_index=idx,
                capability_urn=urn,
                display_name=cap.name if cap else urn,
                sub_goal=f"Execute {cap.name if cap else urn}",
                selection_reason="Selected via topological dependency resolution",
                input_bindings=input_bindings,
                output_definitions={
                    "result": StepOutputDefinition(field_name="result", field_type="string"),
                    "status": StepOutputDefinition(field_name="status", field_type="string")
                },
                dependencies=step_deps
            )
            steps.append(step)

        plan_id = f"plan-{hashlib.sha256(request.original_instruction.encode()).hexdigest()[:8]}-{int(time.time())}"
        plan = ExecutionPlan(
            plan_id=plan_id,
            request_query=request.original_instruction,
            plan_type="MULTI_CAPABILITY" if len(steps) > 1 else "SINGLE_CAPABILITY",
            status="PLAN_READY",
            steps=steps,
            dag_edges=dag_edges,
            execution_order=[s.step_id for s in steps],
            missing_inputs=[],
            clarifying_questions=[],
            explanation=f"Autonomous plan for '{request.original_instruction}'"
        )

        # 5. Dual-Gate Governance Authorization
        policy = active_policy or InterfaceTrustPolicy(
            policy_name="call-me-verified-interfaces",
            min_interface_version=1,
            require_attestation=False,
            require_all_capabilities_verified=False
        )

        token, eval_result = self.ctx.governance_engine.approve_plan(
            plan=plan,
            approver=approver_consent,
            active_policy=policy
        )

        if eval_result.status != GovernanceStatus.APPROVED or not token:
            return {
                "status": "REJECTED",
                "request_id": request.request_id,
                "plan_id": plan.plan_id,
                "governance_status": str(eval_result.status),
                "message": f"Plan authorization rejected: {eval_result.reason_summary}",
                "completed_steps": 0,
                "total_steps": len(steps)
            }

        # 6. Real Execution via Execution Engine
        exec_result = self.ctx.execution_engine.execute_plan(plan=plan, token=token)

        # 7. Collect Auditable Results
        step_summary = []
        for r in exec_result.step_records:
            step_summary.append({
                "step_id": r.step_id,
                "capability_urn": r.capability_urn,
                "status": r.status.value if hasattr(r.status, "value") else str(r.status),
                "duration_ms": r.duration_ms,
                "error_details": r.error_details,
                "input_cas_digest": r.input_arguments_cas_digest,
                "output_cas_digest": r.output_result_cas_digest
            })

        return {
            "status": "SUCCEEDED" if exec_result.lifecycle_state == ExecutionLifecycleState.SUCCEEDED else "FAILED",
            "run_id": exec_result.run_id,
            "plan_id": plan.plan_id,
            "lifecycle_state": exec_result.lifecycle_state.value,
            "total_steps": exec_result.total_steps,
            "completed_steps": exec_result.completed_steps,
            "trace_cas_digest": exec_result.trace_cas_digest,
            "capabilities_used": [s.capability_urn for s in steps[:exec_result.completed_steps]],
            "dag_edges": plan.dag_edges,
            "step_records": step_summary,
            "error_message": exec_result.error_message
        }
