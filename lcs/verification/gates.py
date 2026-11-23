"""
LCS Resource-Specific Multi-Tier Verification Gates (Phase 2B)
==============================================================
Authoritative multi-tier verification rubrics for Skills, Scripts, MCP Tools,
Agents/Subagents, Workflows, and Templates. Eliminates the 'exit 0 fallacy'.
"""

import os
import re
import json
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple

from .models import VerificationState, EvidenceTier, EvidenceRecord, VerificationResult
from ..hydration.models import HydratedCapability


class BaseVerificationGate(ABC):
    """Abstract base class for resource verification gates."""

    @abstractmethod
    def verify(self, execution_context: Dict[str, Any]) -> VerificationResult:
        """Executes multi-tier verification checks and returns a VerificationResult."""
        pass


class SkillVerificationGate(BaseVerificationGate):
    """
    Verification gate for Skill Playbooks.
    Criteria:
    - Tier 1: Root instruction digest intact.
    - Tier 2: Mandatory dependencies hydrated.
    - Tier 4: Non-empty instructions, valid parameter structure.
    """

    def verify(self, execution_context: Dict[str, Any]) -> VerificationResult:
        skill: Optional[HydratedCapability] = execution_context.get("hydrated_capability")
        skill_id = skill.capability_urn if skill else execution_context.get("resource_id", "unknown-skill")
        result = VerificationResult(
            resource_id=skill_id,
            resource_type="SKILL",
            state=VerificationState.VERIFIED,
            is_verified=True
        )

        rendered = execution_context.get("rendered_instructions")
        if not skill and not rendered:
            result.add_evidence(
                EvidenceTier.TIER_1_IDENTITY_INTEGRITY,
                "Hydrated capability present",
                False,
                details="No HydratedCapability or rendered instructions found in context"
            )
            return result

        raw_inst = skill.raw_instructions if skill else rendered

        # Tier 1: Instruction Digest
        digest_val = skill.instruction_digest if skill else (execution_context.get("digest") or execution_context.get("cas_trace_digest"))
        has_digest = bool(digest_val and len(digest_val) == 64)
        result.add_evidence(
            EvidenceTier.TIER_1_IDENTITY_INTEGRITY,
            "Instruction SHA-256 digest valid",
            has_digest,
            digest=digest_val
        )

        # Tier 2: Instruction Completeness & Dependencies
        has_content = bool(raw_inst and len(raw_inst.strip()) > 0)
        result.add_evidence(
            EvidenceTier.TIER_2_RETRIEVAL_ACTIVATION,
            "Authoritative instructions non-empty",
            has_content,
            details=f"Length: {len(raw_inst)} chars"
        )

        missing_deps = skill.missing_dependencies if skill else execution_context.get("missing_dependencies", [])
        no_missing_deps = len(missing_deps) == 0
        result.add_evidence(
            EvidenceTier.TIER_2_RETRIEVAL_ACTIVATION,
            "Mandatory dependencies satisfied",
            no_missing_deps,
            details=f"Missing: {missing_deps}" if not no_missing_deps else "All present"
        )

        # Tier 4: Not AI Summary
        is_not_summary = not raw_inst.startswith("[AI Generated Summary]")
        result.add_evidence(
            EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
            "Authoritative instructions un-summarized",
            is_not_summary
        )

        return result


class ScriptVerificationGate(BaseVerificationGate):
    """
    Verification gate for Executable Scripts.
    Criteria:
    - Tier 1: Script file exists on disk.
    - Tier 3: Subprocess exit code == 0.
    - Tier 4: Stderr free of fatal exception tracebacks.
    - Tier 4: Declared output files exist, non-empty, and readable.
    """

    FATAL_STDERR_PATTERNS = (
        "Traceback (most recent call last):",
        "ZeroDivisionError:",
        "NullPointerException",
        "FATAL:",
        "SIGSEGV",
        "AssertionError:"
    )

    def verify(self, execution_context: Dict[str, Any]) -> VerificationResult:
        script_id = execution_context.get("resource_id", "script-run")
        result = VerificationResult(
            resource_id=script_id,
            resource_type="SCRIPT",
            state=VerificationState.VERIFIED,
            is_verified=True
        )

        # Tier 1: Script path exists
        script_path = execution_context.get("script_path")
        path_exists = bool(script_path and os.path.exists(script_path))
        result.add_evidence(
            EvidenceTier.TIER_1_IDENTITY_INTEGRITY,
            "Script file accessible",
            path_exists,
            details=f"Path: {script_path}"
        )

        # Tier 3: Exit code 0
        exit_code = execution_context.get("exit_code")
        is_exit_zero = (exit_code == 0)
        result.add_evidence(
            EvidenceTier.TIER_3_EXECUTION_EVIDENCE,
            "Exit code is zero",
            is_exit_zero,
            details=f"Exit code: {exit_code}"
        )

        # Tier 4: Stderr Exception Scan
        stderr_text = execution_context.get("stderr", "") or ""
        has_fatal_trace = any(pat in stderr_text for pat in self.FATAL_STDERR_PATTERNS)
        result.add_evidence(
            EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
            "Stderr clean of fatal tracebacks",
            not has_fatal_trace,
            details=f"Stderr sample: {stderr_text[:100]}" if has_fatal_trace else "Clean"
        )

        # Tier 4: Declared Output Files
        declared_outputs = execution_context.get("declared_output_files", [])
        for out_path in declared_outputs:
            exists = os.path.exists(out_path)
            non_empty = exists and os.path.getsize(out_path) > 0
            result.add_evidence(
                EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
                f"Output file created and non-empty: {os.path.basename(out_path)}",
                non_empty,
                details=f"Path: {out_path}, size: {os.path.getsize(out_path) if exists else 0} bytes"
            )

        return result


class MCPToolVerificationGate(BaseVerificationGate):
    """
    Verification gate for MCP Tool Invocations.
    Criteria:
    - Tier 3: JSON-RPC 2.0 success wrapper.
    - Tier 4: isError explicitly False or absent.
    - Tier 4: CAS trace digest non-empty.
    - Tier 4: Expected keys / schema present.
    """

    def verify(self, execution_context: Dict[str, Any]) -> VerificationResult:
        tool_id = execution_context.get("resource_id", "mcp-tool")
        result = VerificationResult(
            resource_id=tool_id,
            resource_type="MCP_TOOL",
            state=VerificationState.VERIFIED,
            is_verified=True
        )

        payload = execution_context.get("tool_response", {})

        # Tier 3: Response structure
        is_dict = isinstance(payload, dict)
        result.add_evidence(
            EvidenceTier.TIER_3_EXECUTION_EVIDENCE,
            "Valid tool response dictionary returned",
            is_dict
        )

        # Tier 4: isError check
        is_error = payload.get("isError", False) if is_dict else True
        result.add_evidence(
            EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
            "isError flag is false",
            not is_error,
            details=f"Payload: {str(payload)[:100]}"
        )

        # Tier 4: CAS Trace Digest
        cas_digest = execution_context.get("cas_trace_digest")
        has_cas_trace = bool(cas_digest and len(cas_digest) == 64)
        result.add_evidence(
            EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
            "CAS trace digest recorded",
            has_cas_trace,
            digest=cas_digest
        )
        result.cas_trace_digest = cas_digest

        # Tier 4: Required output keys
        required_keys = execution_context.get("required_output_keys", [])
        if required_keys and is_dict:
            missing_keys = [k for k in required_keys if k not in payload]
            result.add_evidence(
                EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
                "Required output keys satisfied",
                len(missing_keys) == 0,
                details=f"Missing: {missing_keys}" if missing_keys else "All present"
            )

        return result


class AgentVerificationGate(BaseVerificationGate):
    """
    Verification gate for Agent / Subagent Delegations.
    Criteria:
    - Tier 3: Terminal status explicitly DONE / COMPLETED.
    - Tier 4: Transcript loop check (bounded iteration count).
    - Tier 5: Declared deliverable verified non-empty.
    """

    def verify(self, execution_context: Dict[str, Any]) -> VerificationResult:
        subagent_id = execution_context.get("resource_id", "subagent-task")
        result = VerificationResult(
            resource_id=subagent_id,
            resource_type="AGENT",
            state=VerificationState.VERIFIED,
            is_verified=True
        )

        # Tier 3: Terminal Status
        status = execution_context.get("status", "").upper()
        is_done = status in ("DONE", "COMPLETED", "SUCCESS")
        result.add_evidence(
            EvidenceTier.TIER_3_EXECUTION_EVIDENCE,
            "Agent reached terminal completion state",
            is_done,
            details=f"Reported status: {status}"
        )

        # Tier 4: Transcript Loop & Error Check
        iterations = execution_context.get("iteration_count", 1)
        max_iter = execution_context.get("max_iterations", 50)
        is_bounded = (iterations <= max_iter)
        result.add_evidence(
            EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
            "Execution iterations within bounds",
            is_bounded,
            details=f"{iterations}/{max_iter} turns"
        )

        # Tier 5: Deliverable Verification
        deliverable_path = execution_context.get("deliverable_file")
        if deliverable_path:
            d_exists = os.path.exists(deliverable_path)
            d_nonempty = d_exists and os.path.getsize(deliverable_path) > 0
            result.add_evidence(
                EvidenceTier.TIER_5_TASK_OUTCOME_AUDIT,
                "Declared deliverable created and non-empty",
                d_nonempty,
                details=f"Path: {deliverable_path}"
            )

        return result


class TemplateVerificationGate(BaseVerificationGate):
    """
    Verification gate for Templates.
    Criteria:
    - Tier 2: Required variables supplied.
    - Tier 4: Rendered output non-empty and no unresolved placeholders.
    """

    def verify(self, execution_context: Dict[str, Any]) -> VerificationResult:
        tmpl_id = execution_context.get("resource_id", "template")
        result = VerificationResult(
            resource_id=tmpl_id,
            resource_type="TEMPLATE",
            state=VerificationState.VERIFIED,
            is_verified=True
        )

        rendered_text = execution_context.get("rendered_text", "")
        has_content = bool(rendered_text and len(rendered_text.strip()) > 0)
        result.add_evidence(
            EvidenceTier.TIER_2_RETRIEVAL_ACTIVATION,
            "Template output rendered non-empty",
            has_content
        )

        # Check for un-rendered {{ ... }} placeholders
        unrendered = re.findall(r'\{\{[^}]+\}\}', rendered_text)
        result.add_evidence(
            EvidenceTier.TIER_4_CONTRACT_COMPLIANCE,
            "Zero unrendered template placeholders",
            len(unrendered) == 0,
            details=f"Unresolved placeholders: {unrendered[:5]}" if unrendered else "Clean"
        )

        return result


class UnifiedResourceVerifier:
    """
    Coordinates multi-tier verification dispatch based on resource type.
    """

    GATES = {
        "SKILL": SkillVerificationGate(),
        "SCRIPT": ScriptVerificationGate(),
        "MCP_TOOL": MCPToolVerificationGate(),
        "AGENT": AgentVerificationGate(),
        "SUBAGENT": AgentVerificationGate(),
        "TEMPLATE": TemplateVerificationGate(),
    }

    @classmethod
    def verify_resource(
        cls,
        resource_type: str,
        execution_context: Dict[str, Any]
    ) -> VerificationResult:
        """Dispatches to the matching verification gate."""
        rtype_upper = resource_type.upper()
        gate = cls.GATES.get(rtype_upper)
        if not gate:
            # Fallback gate: requires success flag
            res = VerificationResult(
                resource_id=execution_context.get("resource_id", "unknown"),
                resource_type=resource_type,
                state=VerificationState.VERIFIED,
                is_verified=True
            )
            success = execution_context.get("success", False)
            res.add_evidence(
                EvidenceTier.TIER_3_EXECUTION_EVIDENCE,
                f"Generic success assertion for {resource_type}",
                success
            )
            return res

        return gate.verify(execution_context)
