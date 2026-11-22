"""
LCS Deep Capability Retrieval & Context Transfer Optimizer
==========================================================
Coordinates deep capability retrieval, transitive dependency resolution,
host compatibility verification, and token-budget-aware context optimization.

Key Principles:
1. Zero summarization of authoritative instructions.
2. Deep transitive dependency resolution.
3. Explicit reporting of missing or inaccessible resources.
4. Token-budget optimization: Delivers task-relevant instructions without context bloat.
5. Never injects the entire capability catalog into the LLM context.
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Set, Tuple

from .models import (
    ResourceType,
    OperationalLifecycleState,
    UnifiedResourceRecord,
    DeepRetrievalResult,
    ContextTransferPayload,
    ExecutionRequirement,
)
from .inventory import UnifiedCapabilityInventory

logger = logging.getLogger("lcs.inventory.retrieval")


class DeepCapabilityRetriever:
    """
    Orchestrates deep capability retrieval, dependency resolution, and context transfer packaging.
    """

    def __init__(self, inventory: UnifiedCapabilityInventory, policy_service: Optional[Any] = None):
        self.inventory = inventory
        self.policy_service = policy_service

    def retrieve_deep(
        self,
        capability_urn_or_name: str,
        active_environment: str = "generic_posix"
    ) -> DeepRetrievalResult:
        """
        Deeply retrieves a primary capability, resolves transitive dependencies,
        verifies host compatibility, and checks physical accessibility.
        """
        # 1. Resolve Primary Capability
        primary = self.inventory.get_by_urn(capability_urn_or_name)
        if not primary:
            # Search by name
            matches = self.inventory.search(capability_urn_or_name, limit=1)
            if matches:
                primary = matches[0]

        if not primary:
            raise KeyError(f"Capability '{capability_urn_or_name}' not found in unified inventory.")

        # 2. Check Host Compatibility
        compat_passed, compat_notes = self._check_host_compatibility(primary, active_environment)

        # 3. Resolve Transitive Dependencies & Check Auxiliary Assets
        resolved_deps: List[UnifiedResourceRecord] = []
        missing_deps: List[str] = []
        inaccessible: List[Dict[str, str]] = []

        # Check physical accessibility of declared auxiliary and referenced files
        if primary.auxiliary_files:
            for rel_path, file_info in primary.auxiliary_files.items():
                f_path = file_info.get("path")
                if not f_path or not os.path.exists(f_path):
                    inaccessible.append({
                        "urn": primary.urn,
                        "name": rel_path,
                        "reason": f"Referenced asset file missing on disk: '{rel_path}'"
                    })
                    missing_deps.append(rel_path)
                elif not os.access(f_path, os.R_OK):
                    inaccessible.append({
                        "urn": primary.urn,
                        "name": rel_path,
                        "reason": f"Referenced asset file has no read permissions: '{rel_path}'"
                    })
                    missing_deps.append(rel_path)

        visited: Set[str] = {primary.urn}
        queue: List[Dict[str, Any]] = list(primary.declared_dependencies)

        while queue:
            dep = queue.pop(0)
            dep_name = dep.get("name")
            is_mandatory = dep.get("mandatory", True)

            if not dep_name:
                continue

            # Find matching resource
            dep_rec = self.inventory.get_by_urn(dep_name)
            if not dep_rec:
                dep_rec = next((record for record in self.inventory.list_all()
                                if record.name == dep_name), None)

            if not dep_rec:
                if is_mandatory:
                    missing_deps.append(dep_name)
                continue

            if dep_rec.urn in visited:
                continue
            visited.add(dep_rec.urn)

            # Check physical accessibility
            if dep_rec.lifecycle_state == OperationalLifecycleState.UNAVAILABLE:
                inaccessible.append({
                    "urn": dep_rec.urn,
                    "name": dep_rec.name,
                    "reason": "Physical path inaccessible or missing on disk"
                })
                if is_mandatory:
                    missing_deps.append(dep_rec.name)
            else:
                resolved_deps.append(dep_rec)
                # Enqueue child dependencies
                for child_dep in dep_rec.declared_dependencies:
                    if child_dep.get("name") not in visited:
                        queue.append(child_dep)

        is_executable = (len(missing_deps) == 0) and compat_passed

        return DeepRetrievalResult(
            primary_resource=primary,
            resolved_dependencies=resolved_deps,
            missing_dependencies=missing_deps,
            inaccessible_resources=inaccessible,
            compatibility_passed=compat_passed,
            compatibility_notes=compat_notes,
            is_executable=is_executable,
            execution_requirements=primary.execution_requirements
        )

    def optimize_context_transfer(
        self,
        task_query: str,
        retrieval_result: DeepRetrievalResult,
        token_budget: Optional[int] = None
    ) -> ContextTransferPayload:
        """
        Builds a token-efficient ContextTransferPayload tailored to the task.
        Guarantees that original primary instructions are preserved.
        Selects supporting dependencies and execution guidance within the token budget.
        """
        primary = retrieval_result.primary_resource

        # 1. Base Primary Instructions (Authoritative)
        instructions = primary.raw_content

        # 2. Extract Execution Guidance
        guidance_lines = [
            f"# Capability Execution Context: {primary.display_name} ({primary.urn})",
            f"- Resource Type: {primary.resource_type.value}",
            f"- Origin Environment: {primary.provenance.origin_host}",
            f"- Runtime Requirements: {primary.execution_requirements.runtime_environment} (binaries: {', '.join(primary.execution_requirements.required_binaries) or 'none'})",
        ]
        if primary.security_flags:
            guidance_lines.append(f"- Security Notice: Audit flagged potential patterns: {', '.join(primary.security_flags)}")
        guidance = "\n".join(guidance_lines)

        # 3. Dependency Snippets
        dep_snippets: Dict[str, str] = {}
        omitted_refs: List[str] = []
        prov_hashes: Dict[str, str] = {primary.urn: primary.raw_content_digest}

        # Calculate base tokens
        base_text = guidance + "\n\n" + instructions
        current_tokens = ContextTransferPayload.estimate_tokens(base_text)
        budget_exceeded = False

        if token_budget is not None and current_tokens > token_budget:
            budget_exceeded = True

        # Include resolved dependencies if budget permits
        for dep in retrieval_result.resolved_dependencies:
            prov_hashes[dep.urn] = dep.raw_content_digest
            dep_text = f"### Dependency: {dep.display_name} ({dep.urn})\n{dep.raw_content}"
            dep_tokens = ContextTransferPayload.estimate_tokens(dep_text)

            if token_budget is not None:
                if current_tokens + dep_tokens <= token_budget:
                    dep_snippets[dep.name] = dep_text
                    current_tokens += dep_tokens
                else:
                    omitted_refs.append(f"{dep.name} (exceeded token budget by {dep_tokens} tokens)")
            else:
                dep_snippets[dep.name] = dep_text
                current_tokens += dep_tokens

        # Include readable referenced auxiliary files in dependency_snippets
        if primary.auxiliary_files:
            for rel_path, file_info in sorted(primary.auxiliary_files.items()):
                f_path = file_info.get("path")
                if f_path and os.path.exists(f_path) and os.access(f_path, os.R_OK):
                    try:
                        with open(f_path, "r", encoding="utf-8", errors="replace") as f:
                            ref_content = f.read()
                        ref_snippet = f"### Referenced Asset: {rel_path}\n{ref_content}"
                        ref_tokens = ContextTransferPayload.estimate_tokens(ref_snippet)
                        if token_budget is not None and current_tokens + ref_tokens > token_budget:
                            omitted_refs.append(f"{rel_path} (exceeded token budget by {ref_tokens} tokens)")
                            budget_exceeded = True
                        else:
                            dep_snippets[rel_path] = ref_snippet
                            current_tokens += ref_tokens
                    except Exception as e:
                        omitted_refs.append(f"{rel_path} (read error: {e})")

        # Also list auxiliary files summary if available
        if primary.auxiliary_files:
            aux_summary = "\n".join([f"- {k} ({v.get('kind', 'FILE')}, {v.get('size_bytes', 0)} bytes)" for k, v in list(primary.auxiliary_files.items())[:10]])
            guidance += f"\n\n### Available Auxiliary Assets:\n{aux_summary}"

        return ContextTransferPayload(
            task_query=task_query,
            primary_urn=primary.urn,
            instructions_text=instructions,
            dependency_snippets=dep_snippets,
            execution_guidance=guidance,
            estimated_tokens=current_tokens,
            token_budget_limit=token_budget,
            budget_exceeded=budget_exceeded,
            omitted_references=omitted_refs,
            provenance_hashes=prov_hashes
        )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _check_host_compatibility(
        self,
        record: UnifiedResourceRecord,
        active_environment: str
    ) -> Tuple[bool, List[str]]:
        notes = []
        origin = record.provenance.origin_host.lower()
        active = active_environment.lower()

        # If origin is generic_posix or host agnostic, always compatible
        if origin in ("generic_posix", "generic", "any"):
            return True, ["Host-agnostic capability."]

        # Check environment-specific restrictions
        if record.resource_type == ResourceType.AGENT and active == "generic_posix":
            notes.append("Subagent delegation may not be supported on Generic POSIX host.")
            return False, notes

        if origin != active and origin not in ("mcp", "agent_runtime"):
            notes.append(f"Capability was created for '{origin}' but executing under '{active}'. Compatibility heuristics active.")

        return True, notes
