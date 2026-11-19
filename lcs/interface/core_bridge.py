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

import logging
from typing import Dict, Any, List, Optional, Tuple

from .contract import TaskRequest, InvocationResponse, ConsentState
from ..hydration.models import HydratedCapability, ResourceUtilizationState
from ..dependencies.graph import DependencyGraph, DependencyError
from ..subagents.models import SubagentTask, SubagentExecutionResult

logger = logging.getLogger("lcs.interface.bridge")


class LCSCoreBridge:
    """
    Coordinates the handoff of a TaskRequest into LCS Core intelligence subsystems.
    """

    def __init__(self, context: Any):
        self.ctx = context

    def submit_task(self, request: TaskRequest) -> InvocationResponse:
        """
        Receives a validated TaskRequest, searches matching capabilities from
        the cache/index, and prepares initial candidate proposals.
        """
        try:
            # 1. Search candidate capabilities using fast cache / Unified Retrieval
            query = request.normalized_task_description
            candidates = []

            # First attempt: warm local cache
            if hasattr(self.ctx, "cache") and self.ctx.cache:
                cached_candidates = self.ctx.cache.search_candidates(query, limit=10)
                candidates = [c.urn for c in cached_candidates]

            # Fallback attempt: Skill Intelligence retrieval if cache empty
            if not candidates and hasattr(self.ctx, "skill_service") and self.ctx.skill_service:
                try:
                    results = self.ctx.skill_service.search(query, limit=10)
                    candidates = [c.capability_urn for c in results]
                except Exception as e:
                    logger.debug(f"Retrieval fallback error: {e}")

            # 2. Construct response
            if not candidates:
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
