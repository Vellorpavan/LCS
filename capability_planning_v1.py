#!/usr/bin/env python3
"""
LCS Stage 2B — Multi-Capability Planning V1
===========================================
Constructs explainable, dependency-aware execution plans for complex requests
requiring multiple living capabilities.

Architecture Layer:
  Directly above Capability Retrieval V1.1 and Capability Parameter Understanding V1.
  Decomposes compound requests into sub-goals, retrieves candidate capabilities,
  analyzes 4-tier dependencies (Independent, Shared-Input, Sequential, Output-to-Input),
  enforces strict output contract evidence (Declared/Documented vs Inferred/Unknown),
  binds parameters with conflict detection, and generates verifiable execution plans.

Strict Security & Execution Boundaries:
  - ZERO Tool Execution (tools/call disabled).
  - ZERO Subprocess Execution or arbitrary code execution.
  - ZERO automatic filesystem modifications.
  - Fully deterministic, explainable, and testable.
"""

import os
import re
import sys
import json
import uuid
import time
from typing import Dict, Any, List, Optional, Tuple, Set, Union

from capability_profile_v2b import (
    EvidenceSource,
    ProfileField,
    ParameterProfile,
    CapabilitySemanticProfile,
    CapabilityProfileService
)
from capability_retrieval_v1_1 import (
    CapabilityRetrievalEngineV11,
    ProcessedQueryV11,
    QueryProcessorV11,
    RetrievalResultV11,
    ScoredCandidateV11
)
from capability_parameter_v1 import (
    ParameterUnderstandingEngineV1,
    ParameterRequirement,
    MappedParameter,
    ParameterReadinessStatus,
    MappingMethod
)


# ----------------------------------------------------------------------------
# Enums and Constants
# ----------------------------------------------------------------------------

class PlanReadinessStatus:
    PLAN_READY = "PLAN_READY"              # All steps valid, acyclic DAG, all required inputs satisfied by evidence
    PLAN_INCOMPLETE = "PLAN_INCOMPLETE"    # Steps identified, but missing required user inputs or unverified outputs
    PLAN_INVALID = "PLAN_INVALID"          # Schema violations, cyclic dependencies, type mismatches, or binding conflicts
    PLAN_ABSTAIN = "PLAN_ABSTAIN"          # Out-of-domain, ambiguous request, or capabilities unavailable in LCS


class DependencyType:
    INDEPENDENT = "INDEPENDENT"            # Steps share neither data nor resources (concurrent/unordered)
    SHARED_INPUT = "SHARED_INPUT"          # Steps consume identical input/resource without inter-step dependency
    SEQUENTIAL = "SEQUENTIAL"              # Step B requires state/resource established by Step A
    OUTPUT_TO_INPUT = "OUTPUT_TO_INPUT"    # Step B consumes declared/documented output produced by Step A


class OutputEvidenceSource:
    FORMALLY_DECLARED = "FORMALLY_DECLARED"  # Parsed from formal JSON/Pydantic outputSchema
    DOCUMENTED = "DOCUMENTED"                # Authoritative tool documentation with explicit return semantics
    INFERRED = "INFERRED"                    # Derived from naming heuristics or tool category
    UNKNOWN = "UNKNOWN"                      # Undeclared or unavailable in evidence records


class BindingSourceType:
    USER_SUPPLIED = "USER_SUPPLIED"          # Explicitly provided by user in prompt
    STEP_OUTPUT = "STEP_OUTPUT"              # Derived from validated upstream step output
    SCHEMA_DEFAULT = "SCHEMA_DEFAULT"        # Satisfied by capability schema default
    UNRESOLVED = "UNRESOLVED"                # Missing required parameter
    CONFLICT = "CONFLICT"                    # Direct contradiction between user argument and upstream output


# Documented output specifications for canonical LCS corpus tools (evidence: DOCUMENTED)
DOCUMENTED_CAPABILITY_OUTPUTS: Dict[str, List[Dict[str, Any]]] = {
    "compress-tar-archive": [
        {"field_name": "archive_path", "field_type": "string", "description": "Absolute filesystem path to created tar archive"}
    ],
    "hash-sha256-digest": [
        {"field_name": "sha256_hash", "field_type": "string", "description": "Hexadecimal SHA-256 digest string"}
    ],
    "clone-git-repository": [
        {"field_name": "target_dir", "field_type": "string", "description": "Local repository destination path"},
        {"field_name": "repo_path", "field_type": "string", "description": "Cloned git working tree path"}
    ],
    "format-sql-query": [
        {"field_name": "formatted_query", "field_type": "string", "description": "Indented and normalized SQL query string"}
    ],
    "parse-csv-records": [
        {"field_name": "records_text", "field_type": "string", "description": "Extracted text or tabular representation from CSV"}
    ],
    "format-certificate-pem": [
        {"field_name": "pem_string", "field_type": "string", "description": "Base64 PEM-formatted certificate string"}
    ],
    "read-pdf-document": [
        {"field_name": "document_text", "field_type": "string", "description": "Extracted plain text content of PDF document"}
    ],
    "find-bounding-envelope": [
        {"field_name": "polygon", "field_type": "string", "description": "Bounding polygon coordinates representation"}
    ],
    "validate-ip-address": [
        {"field_name": "normalized_ip", "field_type": "string", "description": "Canonical normalized IP address string"}
    ],
    "encrypt-aes-gcm": [
        {"field_name": "ciphertext", "field_type": "string", "description": "Encrypted ciphertext string"}
    ],
    "generate-totp-token": [
        {"field_name": "totp_token", "field_type": "string", "description": "6-digit time-based one-time password"}
    ]
}


# ----------------------------------------------------------------------------
# Data Models: StepOutputDefinition, StepInputBinding, PlanStep, ExecutionPlan
# ----------------------------------------------------------------------------

class StepOutputDefinition:
    """Formal definition of an output produced by a capability in a plan step."""
    def __init__(
        self,
        field_name: str,
        field_type: str,
        evidence: str = OutputEvidenceSource.UNKNOWN,
        description: Optional[str] = None,
        notes: str = ""
    ):
        self.field_name = field_name
        self.field_type = field_type or "any"
        self.evidence = evidence
        self.description = description
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_name": self.field_name,
            "field_type": self.field_type,
            "evidence": self.evidence,
            "description": self.description,
            "notes": self.notes
        }


class StepInputBinding:
    """Formal parameter binding for an operation within an execution plan."""
    def __init__(
        self,
        param_name: str,
        param_type: str,
        required: bool,
        source_type: str = BindingSourceType.UNRESOLVED,
        source_step_id: Optional[str] = None,
        source_output_field: Optional[str] = None,
        bound_value: Any = None,
        is_valid: bool = True,
        conflict_details: Optional[str] = None,
        validation_error: Optional[str] = None
    ):
        self.param_name = param_name
        self.param_type = param_type
        self.required = required
        self.source_type = source_type
        self.source_step_id = source_step_id
        self.source_output_field = source_output_field
        self.bound_value = bound_value
        self.is_valid = is_valid
        self.conflict_details = conflict_details
        self.validation_error = validation_error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param_name": self.param_name,
            "param_type": self.param_type,
            "required": self.required,
            "source_type": self.source_type,
            "source_step_id": self.source_step_id,
            "source_output_field": self.source_output_field,
            "bound_value": self.bound_value,
            "is_valid": self.is_valid,
            "conflict_details": self.conflict_details,
            "validation_error": self.validation_error
        }


class PlanStep:
    """An individual operation within a multi-capability execution plan."""
    def __init__(
        self,
        step_id: str,
        step_index: int,
        capability_urn: str,
        display_name: str,
        sub_goal: str,
        selection_reason: str,
        input_bindings: Dict[str, StepInputBinding],
        output_definitions: Dict[str, StepOutputDefinition],
        dependencies: Optional[List[str]] = None,
        dependency_types: Optional[Dict[str, str]] = None,
        readiness: str = "READY"
    ):
        self.step_id = step_id
        self.step_index = step_index
        self.capability_urn = capability_urn
        self.display_name = display_name
        self.sub_goal = sub_goal
        self.selection_reason = selection_reason
        self.input_bindings = dict(input_bindings)
        self.output_definitions = dict(output_definitions)
        self.dependencies = list(dependencies or [])
        self.dependency_types = dict(dependency_types or {})
        self.readiness = readiness

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_index": self.step_index,
            "capability_urn": self.capability_urn,
            "display_name": self.display_name,
            "sub_goal": self.sub_goal,
            "selection_reason": self.selection_reason,
            "input_bindings": {k: v.to_dict() for k, v in self.input_bindings.items()},
            "output_definitions": {k: v.to_dict() for k, v in self.output_definitions.items()},
            "dependencies": self.dependencies,
            "dependency_types": self.dependency_types,
            "readiness": self.readiness
        }


class ExecutionPlan:
    """
    Structured, inspectable, and explainable capability execution plan.
    Strictly declarative; contains zero execution mechanisms.
    """
    def __init__(
        self,
        plan_id: str,
        request_query: str,
        plan_type: str,
        status: str,
        steps: List[PlanStep],
        dag_edges: List[Tuple[str, str, str, str]],  # (upstream_id, downstream_id, dep_type, reason)
        execution_order: List[str],
        missing_inputs: List[Dict[str, Any]],
        clarifying_questions: List[str],
        explanation: str,
        evidence_summary: Optional[Dict[str, Any]] = None
    ):
        self.plan_id = plan_id
        self.request_query = request_query
        self.plan_type = plan_type
        self.status = status
        self.steps = list(steps)
        self.dag_edges = list(dag_edges)
        self.execution_order = list(execution_order)
        self.missing_inputs = list(missing_inputs)
        self.clarifying_questions = list(clarifying_questions)
        self.explanation = explanation
        self.evidence_summary = dict(evidence_summary or {})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "request_query": self.request_query,
            "plan_type": self.plan_type,
            "status": self.status,
            "steps": [s.to_dict() for s in self.steps],
            "dag_edges": [
                {"upstream": e[0], "downstream": e[1], "type": e[2], "reason": e[3]}
                for e in self.dag_edges
            ],
            "execution_order": self.execution_order,
            "missing_inputs": self.missing_inputs,
            "clarifying_questions": self.clarifying_questions,
            "explanation": self.explanation,
            "evidence_summary": self.evidence_summary
        }


# ----------------------------------------------------------------------------
# Core Engine: CapabilityPlanningEngineV1
# ----------------------------------------------------------------------------

class CapabilityPlanningEngineV1:
    """
    Deterministic multi-capability planning engine.
    Orchestrates request decomposition, candidate retrieval, 4-tier dependency analysis,
    output contract evidence enforcement, and data-flow parameter binding.
    """

    def __init__(
        self,
        conn: Any,
        profile_service: CapabilityProfileService,
        retrieval_engine: CapabilityRetrievalEngineV11,
        parameter_engine: ParameterUnderstandingEngineV1
    ):
        self.conn = conn
        self.profile_service = profile_service
        self.retrieval_engine = retrieval_engine
        self.parameter_engine = parameter_engine

    # ------------------------------------------------------------------------
    # 1. Multiplicity Detection & Sub-Goal Decomposition
    # ------------------------------------------------------------------------

    def decompose_query(self, query: str) -> List[str]:
        """
        Decomposes a compound natural-language query into distinct sub-goals.
        Preserves single-capability queries without artificial multi-step inflation.
        """
        text = (query or "").strip()
        if not text:
            return []

        # Sequential phrases with highest splitting priority
        split_phrases = [
            r"\s+and\s+then\s+",
            r"\s+followed\s+by\s+",
            r"\s+after\s+that\s+",
            r"\s+and\s+subsequently\s+",
            r"\s*;\s*",
        ]
        for pat in split_phrases:
            parts = [p.strip() for p in re.split(pat, text, flags=re.IGNORECASE) if p.strip()]
            if len(parts) > 1:
                return parts

        # Action-based conjunction splitting: e.g. "verb X and verb Y"
        # Split on " and " only if parts represent substantive action clauses
        and_parts = [p.strip() for p in re.split(r"\s+and\s+", text, flags=re.IGNORECASE) if p.strip()]
        if len(and_parts) > 1:
            action_indicators = {
                "compress", "calculate", "hash", "format", "query", "parse", "extract",
                "clone", "inspect", "read", "convert", "find", "check", "validate",
                "ping", "encrypt", "generate", "verify", "show", "get", "list"
            }
            # Merge parts that do not begin with an action verb back into the preceding part
            sub_goals: List[str] = []
            for part in and_parts:
                first_words = {w.lower() for w in re.findall(r"\b[a-zA-Z]+\b", part)[:3]}
                if sub_goals and not (first_words & action_indicators):
                    sub_goals[-1] = f"{sub_goals[-1]} and {part}"
                else:
                    sub_goals.append(part)

            if len(sub_goals) > 1:
                # Ensure each identified sub-goal contains at least one action indicator
                if all(bool({w.lower() for w in re.findall(r"\b[a-zA-Z]+\b", sg)[:3]} & action_indicators) for sg in sub_goals):
                    return sub_goals

        # Single-capability request
        return [text]

    # ------------------------------------------------------------------------
    # 2. Output Contract Introspection & Evidence Classification
    # ------------------------------------------------------------------------

    def get_output_definitions(
        self,
        capability_urn: str,
        profile: CapabilitySemanticProfile
    ) -> Dict[str, StepOutputDefinition]:
        """
        Resolves formal, documented, or inferred outputs with strict evidence tracking.
        """
        outputs: Dict[str, StepOutputDefinition] = {}

        # 1. Check formal output_schema in profile
        if profile.output_schema.evidence == EvidenceSource.EXTRACTED and profile.output_schema.value:
            schema = profile.output_schema.value
            props = schema.get("properties", {})
            for field, defn in props.items():
                ftype = defn.get("type", "any") if isinstance(defn, dict) else "any"
                fdesc = defn.get("description") if isinstance(defn, dict) else None
                outputs[field] = StepOutputDefinition(
                    field_name=field,
                    field_type=ftype,
                    evidence=OutputEvidenceSource.FORMALLY_DECLARED,
                    description=fdesc,
                    notes="Deterministically extracted from formal outputSchema."
                )
            if outputs:
                return outputs

        # 2. Check authoritative documented capability outputs in corpus
        cap_id = capability_urn.split(":")[-1]
        if cap_id in DOCUMENTED_CAPABILITY_OUTPUTS:
            for doc_out in DOCUMENTED_CAPABILITY_OUTPUTS[cap_id]:
                outputs[doc_out["field_name"]] = StepOutputDefinition(
                    field_name=doc_out["field_name"],
                    field_type=doc_out["field_type"],
                    evidence=OutputEvidenceSource.DOCUMENTED,
                    description=doc_out.get("description"),
                    notes=f"Authoritative output contract documented for '{cap_id}'."
                )
            if outputs:
                return outputs

        # 3. Check if tool description documents return semantics
        desc = profile.description.value or ""
        m_returns = re.search(r"returns\s+([a-zA-Z0-9_\-\s,]+)", desc, re.IGNORECASE)
        if m_returns:
            raw_field = re.sub(r"[^a-zA-Z0-9_]", "_", m_returns.group(1).split(",")[0].strip().lower()).strip("_")
            if raw_field:
                outputs[raw_field] = StepOutputDefinition(
                    field_name=raw_field,
                    field_type="string",
                    evidence=OutputEvidenceSource.INFERRED,
                    description=m_returns.group(0),
                    notes="Inferred from return keyword in description."
                )
                return outputs

        # 4. Unknown output schema
        outputs["result"] = StepOutputDefinition(
            field_name="result",
            field_type="any",
            evidence=OutputEvidenceSource.UNKNOWN,
            description="Unknown output structure",
            notes="No formal or documented output schema available."
        )
        return outputs

    # ------------------------------------------------------------------------
    # 3. Four-Category Dependency Classification
    # ------------------------------------------------------------------------

    def classify_dependency(
        self,
        step_a: PlanStep,
        step_b: PlanStep,
        user_query: str
    ) -> Tuple[str, Optional[str], Optional[Tuple[str, str]]]:
        """
        Classifies dependency between step_a and step_b into one of 4 categories:
        1. OUTPUT_TO_INPUT
        2. SEQUENTIAL (Resource / State)
        3. SHARED_INPUT
        4. INDEPENDENT

        Returns: (DependencyType, Reason, BindingPair[out_field, in_param] or None)
        """
        urn_a = step_a.capability_urn.lower()
        urn_b = step_b.capability_urn.lower()

        # Check 1: SEQUENTIAL State / Resource Dependency
        # Step A establishes a stateful resource (e.g. clone git repo) required by Step B
        if "clone-git-repository" in urn_a and any(term in urn_b for term in ("inspect-git-commit", "parse-git-status", "format-git-diff")):
            reason = f"Step '{step_b.step_id}' requires git repository created by Step '{step_a.step_id}'."
            return DependencyType.SEQUENTIAL, reason, ("target_dir", "repo_path")

        # Check 2: OUTPUT_TO_INPUT Data Dependency
        # Step B requires an input that matches a FORMALLY_DECLARED or DOCUMENTED output of Step A
        for out_name, out_def in step_a.output_definitions.items():
            if out_def.evidence not in (OutputEvidenceSource.FORMALLY_DECLARED, OutputEvidenceSource.DOCUMENTED):
                continue

            for in_name, in_binding in step_b.input_bindings.items():
                if not in_binding.required:
                    continue

                # Name matching heuristics (exact name or domain synonym)
                is_match = False
                if out_name == in_name:
                    is_match = True
                elif out_name in ("archive_path", "output_archive", "target_dir", "repo_path") and in_name in ("file_path", "repo_path", "path", "data", "payload"):
                    is_match = True
                elif out_name in ("pem_string", "formatted_query", "document_text", "records_text") and in_name in ("cert_pem", "query", "content", "text"):
                    is_match = True
                elif out_name in ("bounding_polygon", "polygon") and in_name in ("polygon", "coordinates"):
                    is_match = True
                elif out_name in ("normalized_ip",) and in_name in ("host", "target"):
                    is_match = True

                if is_match:
                    reason = f"Step '{step_b.step_id}' input '{in_name}' consumes Step '{step_a.step_id}' output '{out_name}'."
                    return DependencyType.OUTPUT_TO_INPUT, reason, (out_name, in_name)

        # Check 3: SHARED_INPUT Dependency
        # Both steps consume the identical input resource, but neither produces data for the other
        shared_inputs = set(step_a.input_bindings.keys()) & set(step_b.input_bindings.keys())
        if shared_inputs and any(term in shared_inputs for term in ("repo_path", "path", "file_path", "host")):
            reason = f"Steps '{step_a.step_id}' and '{step_b.step_id}' operate on shared input {sorted(shared_inputs)}."
            return DependencyType.SHARED_INPUT, reason, None

        # Check 4: INDEPENDENT
        return DependencyType.INDEPENDENT, "Operations are independent with no data or resource coupling.", None

    # ------------------------------------------------------------------------
    # 4. Topological Ordering & Cycle Detection
    # ------------------------------------------------------------------------

    @staticmethod
    def compute_topological_order(
        step_ids: List[str],
        edges: List[Tuple[str, str, str, str]]
    ) -> Tuple[List[str], bool]:
        """
        Computes deterministic topological order using Kahn's algorithm.
        Returns: (ordered_step_ids, has_cycle)
        """
        in_degree: Dict[str, int] = {sid: 0 for sid in step_ids}
        adj: Dict[str, List[str]] = {sid: [] for sid in step_ids}

        for u, v, dep_type, _ in edges:
            if dep_type in (DependencyType.OUTPUT_TO_INPUT, DependencyType.SEQUENTIAL):
                if u in in_degree and v in in_degree:
                    adj[u].append(v)
                    in_degree[v] += 1

        queue = [sid for sid in step_ids if in_degree[sid] == 0]
        order = []

        while queue:
            # Deterministic pop
            curr = queue.pop(0)
            order.append(curr)
            for neighbor in adj[curr]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        has_cycle = len(order) < len(step_ids)
        return order, has_cycle

    # ------------------------------------------------------------------------
    # 5. Core Plan Synthesis
    # ------------------------------------------------------------------------

    def create_plan(
        self,
        query: str,
        user_arguments: Optional[Dict[str, Any]] = None
    ) -> ExecutionPlan:
        """
        Constructs an explainable, dependency-aware ExecutionPlan for a user request.
        """
        plan_id = f"plan-{uuid.uuid4().hex[:8]}"
        raw_query = (query or "").strip()

        # Step 1: Preflight Abstention Check via Retrieval Engine V1.1
        # If the whole query triggers abstention (ambiguous or out-of-domain), abstain immediately
        whole_retrieval = self.retrieval_engine.retrieve(raw_query, limit=3, min_score_threshold=0.25)
        if whole_retrieval.abstained:
            return ExecutionPlan(
                plan_id=plan_id,
                request_query=raw_query,
                plan_type="ABSTAINED",
                status=PlanReadinessStatus.PLAN_ABSTAIN,
                steps=[],
                dag_edges=[],
                execution_order=[],
                missing_inputs=[],
                clarifying_questions=[],
                explanation=f"Planner safely abstained: {whole_retrieval.abstention_reason}",
                evidence_summary={"retrieval_status": "ABSTAINED", "reason": whole_retrieval.abstention_reason}
            )

        # Step 2: Decompose Query into Sub-Goals
        sub_goals = self.decompose_query(raw_query)
        if not sub_goals:
            return ExecutionPlan(
                plan_id=plan_id,
                request_query=raw_query,
                plan_type="ABSTAINED",
                status=PlanReadinessStatus.PLAN_ABSTAIN,
                steps=[],
                dag_edges=[],
                execution_order=[],
                missing_inputs=[],
                clarifying_questions=[],
                explanation="Planner received empty or unparseable query.",
                evidence_summary={}
            )

        # Step 3: Match Capabilities for Each Sub-Goal
        plan_steps: List[PlanStep] = []
        is_ambiguous = False
        ambiguity_notes: List[str] = []

        for idx, sub_g in enumerate(sub_goals, start=1):
            sub_res = self.retrieval_engine.retrieve(sub_g, limit=3, min_score_threshold=0.25)
            if sub_res.abstained or not sub_res.candidates:
                # Sub-goal cannot be satisfied by registered capabilities
                return ExecutionPlan(
                    plan_id=plan_id,
                    request_query=raw_query,
                    plan_type="ABSTAINED",
                    status=PlanReadinessStatus.PLAN_ABSTAIN,
                    steps=[],
                    dag_edges=[],
                    execution_order=[],
                    missing_inputs=[],
                    clarifying_questions=[f"Could not find a capability to satisfy: '{sub_g}'."],
                    explanation=f"Planner abstained: Sub-goal '{sub_g}' could not be matched to any registered capability.",
                    evidence_summary={"unmatched_sub_goal": sub_g}
                )

            top_cand = sub_res.candidates[0]

            # Ambiguity check: if top 2 candidates have identical scores
            if len(sub_res.candidates) > 1:
                cand2 = sub_res.candidates[1]
                if abs(top_cand.relevance_score - cand2.relevance_score) < 0.001 and top_cand.capability_urn != cand2.capability_urn:
                    is_ambiguous = True
                    ambiguity_notes.append(f"Sub-goal '{sub_g}' is ambiguous between '{top_cand.display_name}' and '{cand2.display_name}'.")

            # Load capability profile and requirements
            profile = self.profile_service.get_profile(top_cand.capability_urn)
            reqs, _ = self.parameter_engine.get_parameter_requirements(profile)

            # Build initial input bindings
            bindings: Dict[str, StepInputBinding] = {}
            for r in reqs:
                bindings[r.name] = StepInputBinding(
                    param_name=r.name,
                    param_type=r.param_type,
                    required=r.required,
                    source_type=BindingSourceType.UNRESOLVED
                )

            # Resolve output definitions
            outputs = self.get_output_definitions(top_cand.capability_urn, profile)

            step = PlanStep(
                step_id=f"step-{idx}",
                step_index=idx,
                capability_urn=top_cand.capability_urn,
                display_name=top_cand.display_name,
                sub_goal=sub_g,
                selection_reason=f"Top candidate ({top_cand.relevance_score:.3f}) matching intent: '{sub_g}'",
                input_bindings=bindings,
                output_definitions=outputs
            )
            plan_steps.append(step)

        # Step 4: Classify Dependencies & Construct DAG Edges
        dag_edges: List[Tuple[str, str, str, str]] = []  # (u, v, dep_type, reason)
        bindings_to_apply: List[Tuple[str, str, str, str]] = []  # (u, v, out_field, in_param)

        for i in range(len(plan_steps)):
            for j in range(i + 1, len(plan_steps)):
                step_a = plan_steps[i]
                step_b = plan_steps[j]

                dep_type, reason, binding_pair = self.classify_dependency(step_a, step_b, raw_query)

                # An "and" connector alone must NOT establish a DAG edge.
                # Only OUTPUT_TO_INPUT and SEQUENTIAL establish DAG edges
                if dep_type in (DependencyType.OUTPUT_TO_INPUT, DependencyType.SEQUENTIAL):
                    dag_edges.append((step_a.step_id, step_b.step_id, dep_type, reason))
                    step_b.dependencies.append(step_a.step_id)
                    step_b.dependency_types[step_a.step_id] = dep_type

                    if binding_pair:
                        bindings_to_apply.append((step_a.step_id, step_b.step_id, binding_pair[0], binding_pair[1]))
                elif dep_type == DependencyType.SHARED_INPUT:
                    step_b.dependency_types[step_a.step_id] = DependencyType.SHARED_INPUT

        # Step 5: Check Cycles and Compute Topological Order
        step_ids = [s.step_id for s in plan_steps]
        exec_order, has_cycle = self.compute_topological_order(step_ids, dag_edges)

        if has_cycle:
            return ExecutionPlan(
                plan_id=plan_id,
                request_query=raw_query,
                plan_type="INVALID_CYCLE",
                status=PlanReadinessStatus.PLAN_INVALID,
                steps=plan_steps,
                dag_edges=dag_edges,
                execution_order=[],
                missing_inputs=[],
                clarifying_questions=[],
                explanation="Plan contains an invalid cyclic dependency between operations.",
                evidence_summary={"error": "CYCLIC_DEPENDENCY"}
            )

        # Step 6: Parameter Precedence & Conflict Detection
        # Precedence: 1. User supplied -> 2. Validated Upstream Output -> 3. Schema Default -> 4. Unresolved
        # Must detect conflicts between user input and upstream output!
        has_conflict = False
        conflict_explanations: List[str] = []
        step_map = {s.step_id: s for s in plan_steps}

        for step in plan_steps:
            # Parse explicit inputs for this step from prompt and user_arguments
            profile = self.profile_service.get_profile(step.capability_urn)
            reqs, _ = self.parameter_engine.get_parameter_requirements(profile)

            # Check explicit inputs supplied by user
            combined_input: Dict[str, Any] = dict(user_arguments or {})

            # Clean URL tokens to prevent pseudo-path ambiguity for filesystem parameters
            url_candidates = re.findall(r"(https?://[^\s\"'\)]+|git@[^\s\"'\)]+)", raw_query)
            clean_sub_goal = step.sub_goal
            clean_raw_query = raw_query
            for u in url_candidates:
                clean_sub_goal = clean_sub_goal.replace(u, "URL_TOKEN")
                clean_raw_query = clean_raw_query.replace(u, "URL_TOKEN")

            # 1a. If step requires URL parameter and URL was present, map it
            for r in reqs:
                if any(t in r.name.lower() for t in ("url", "uri")) and url_candidates and r.name not in combined_input:
                    combined_input[r.name] = url_candidates[0]

            # 1b. If step is compress-tar-archive, check for "compress <src> into ... <dest>"
            if "compress-tar-archive" in step.capability_urn:
                m_comp = re.search(r"compress\s+([a-zA-Z0-9_\-\./]+)\s+into(?:\s+[a-zA-Z0-9_\-]+)*\s+([a-zA-Z0-9_\-\./]+)", step.sub_goal, re.IGNORECASE)
                if m_comp:
                    src, dest = m_comp.group(1), m_comp.group(2)
                    if "source_dir" in [r.name for r in reqs] and "source_dir" not in combined_input:
                        combined_input["source_dir"] = src
                    if "output_archive" in [r.name for r in reqs] and "output_archive" not in combined_input:
                        combined_input["output_archive"] = dest

            # Parse explicit inputs for sub-goal and full query
            parsed_sub, _, _ = self.parameter_engine.parse_user_input(clean_sub_goal, reqs)
            for k, (v, _, _, _) in parsed_sub.items():
                if k not in combined_input:
                    combined_input[k] = v

            if len(plan_steps) == 1:
                parsed_explicit, _, _ = self.parameter_engine.parse_user_input(clean_raw_query, reqs)
                for k, (v, _, _, _) in parsed_explicit.items():
                    if k not in combined_input:
                        combined_input[k] = v

            # 1. Bind explicit user inputs
            for p_name, p_val in combined_input.items():
                if p_name in step.input_bindings:
                    req_def = next((r for r in reqs if r.name == p_name), None)
                    if req_def:
                        is_valid, norm_val, err = self.parameter_engine.validate_and_normalize(req_def, p_val)
                        step.input_bindings[p_name] = StepInputBinding(
                            param_name=p_name,
                            param_type=req_def.param_type,
                            required=req_def.required,
                            source_type=BindingSourceType.USER_SUPPLIED,
                            bound_value=norm_val,
                            is_valid=is_valid,
                            validation_error=err
                        )

            # 2. Bind upstream outputs (with conflict detection!)
            for u_id, v_id, out_f, in_p in bindings_to_apply:
                if v_id == step.step_id:
                    u_step = step_map[u_id]
                    out_def = u_step.output_definitions.get(out_f)
                    in_binding = step.input_bindings.get(in_p)

                    if not in_binding or not out_def:
                        continue

                    # Verify Output Contract Evidence
                    # Only FORMALLY_DECLARED or DOCUMENTED may support a validated binding
                    if out_def.evidence not in (OutputEvidenceSource.FORMALLY_DECLARED, OutputEvidenceSource.DOCUMENTED):
                        # Inferred or Unknown outputs cannot form a verified binding!
                        in_binding.source_type = BindingSourceType.UNRESOLVED
                        in_binding.validation_error = (
                            f"Output '{out_f}' from Step '{u_id}' has evidence level {out_def.evidence} "
                            "and cannot support a verified data-flow binding."
                        )
                        continue

                    # CONFLICT DETECTION: Did user explicitly supply a conflicting value for this slot?
                    if in_binding.source_type == BindingSourceType.USER_SUPPLIED:
                        has_conflict = True
                        conflict_msg = (
                            f"Binding Conflict on Step '{step.step_id}' parameter '{in_p}': "
                            f"User explicitly supplied '{in_binding.bound_value}', which contradicts "
                            f"upstream pipeline output from Step '{u_id}.{out_f}'."
                        )
                        in_binding.source_type = BindingSourceType.CONFLICT
                        in_binding.is_valid = False
                        in_binding.conflict_details = conflict_msg
                        conflict_explanations.append(conflict_msg)
                        continue

                    # Type compatibility validation
                    req_def = next((r for r in reqs if r.name == in_p), None)
                    if req_def:
                        # Output type must match parameter expected type
                        if out_def.field_type != "any" and req_def.param_type != "any":
                            if not self._is_type_compatible(out_def.field_type, req_def.param_type):
                                in_binding.is_valid = False
                                in_binding.validation_error = (
                                    f"Type mismatch: Step '{u_id}' produces '{out_def.field_type}', "
                                    f"but Step '{step.step_id}' parameter '{in_p}' expects '{req_def.param_type}'."
                                )
                                continue

                        step.input_bindings[in_p] = StepInputBinding(
                            param_name=in_p,
                            param_type=req_def.param_type,
                            required=req_def.required,
                            source_type=BindingSourceType.STEP_OUTPUT,
                            source_step_id=u_id,
                            source_output_field=out_f,
                            bound_value=f"${{{u_id}.{out_f}}}",
                            is_valid=True
                        )

            # 3. Apply Schema Defaults for remaining unresolved
            for r in reqs:
                in_binding = step.input_bindings.get(r.name)
                if in_binding and in_binding.source_type == BindingSourceType.UNRESOLVED:
                    if r.default is not None:
                        is_valid, norm_val, err = self.parameter_engine.validate_and_normalize(r, r.default)
                        step.input_bindings[r.name] = StepInputBinding(
                            param_name=r.name,
                            param_type=r.param_type,
                            required=r.required,
                            source_type=BindingSourceType.SCHEMA_DEFAULT,
                            bound_value=norm_val,
                            is_valid=is_valid,
                            validation_error=err
                        )

        # Step 7: Evaluate Overall Readiness
        missing_inputs: List[Dict[str, Any]] = []
        clarifying_questions: List[str] = []
        has_invalid_bindings = False

        for step in plan_steps:
            step_has_missing = False
            for in_name, in_b in step.input_bindings.items():
                if not in_b.is_valid:
                    has_invalid_bindings = True
                elif in_b.required and in_b.source_type == BindingSourceType.UNRESOLVED:
                    step_has_missing = True
                    missing_inputs.append({
                        "step_id": step.step_id,
                        "step_name": step.display_name,
                        "parameter": in_name,
                        "type": in_b.param_type
                    })
                    clarifying_questions.append(
                        f"Step '{step.display_name}' ({step.step_id}) requires parameter '{in_name}' (type: {in_b.param_type})."
                    )

            if not step.input_bindings:
                step.readiness = "READY"
            elif any(not b.is_valid for b in step.input_bindings.values()):
                step.readiness = "INVALID"
            elif step_has_missing:
                step.readiness = "INCOMPLETE"
            else:
                step.readiness = "READY"

        # Determine Final Plan Status
        if has_conflict:
            plan_status = PlanReadinessStatus.PLAN_INVALID
            explanation = "Plan contains parameter binding conflicts: " + "; ".join(conflict_explanations)
        elif has_invalid_bindings:
            plan_status = PlanReadinessStatus.PLAN_INVALID
            explanation = "Plan violates parameter type or schema compatibility constraints."
        elif is_ambiguous:
            plan_status = PlanReadinessStatus.PLAN_INCOMPLETE
            explanation = "Ambiguous candidate capabilities detected: " + "; ".join(ambiguity_notes)
            clarifying_questions.extend(ambiguity_notes)
        elif missing_inputs:
            plan_status = PlanReadinessStatus.PLAN_INCOMPLETE
            explanation = (
                f"Plan structure valid, but requires {len(missing_inputs)} missing input(s) across steps. "
                "Clarifying questions generated."
            )
        else:
            plan_status = PlanReadinessStatus.PLAN_READY
            explanation = (
                f"Execution plan ready ({len(plan_steps)} steps, {len(dag_edges)} dependencies). "
                "All required parameter bindings are verified by sufficient evidence. Execution disabled."
            )

        plan_type = "SINGLE_CAPABILITY" if len(plan_steps) == 1 else "MULTI_CAPABILITY_DAG"
        if len(plan_steps) > 1 and len(dag_edges) == 0:
            plan_type = "MULTI_CAPABILITY_INDEPENDENT"

        return ExecutionPlan(
            plan_id=plan_id,
            request_query=raw_query,
            plan_type=plan_type,
            status=plan_status,
            steps=plan_steps,
            dag_edges=dag_edges,
            execution_order=exec_order,
            missing_inputs=missing_inputs,
            clarifying_questions=clarifying_questions,
            explanation=explanation,
            evidence_summary={
                "step_count": len(plan_steps),
                "edge_count": len(dag_edges),
                "is_ambiguous": is_ambiguous
            }
        )

    @staticmethod
    def _is_type_compatible(out_type: str, in_type: str) -> bool:
        """Determines if output type is assignable to parameter type."""
        ot = out_type.lower()
        it = in_type.lower()
        if ot == it or it == "any" or ot == "any":
            return True
        if "string" in it and "string" in ot:
            return True
        if ("int" in it or "number" in it) and ("int" in ot or "number" in ot):
            return True
        return False

    # ------------------------------------------------------------------------
    # 6. CLI Output Formatting
    # ------------------------------------------------------------------------

    @staticmethod
    def format_cli_output(plan: ExecutionPlan) -> str:
        """Formats the execution plan for operator terminal inspection."""
        lines = []
        lines.append("=" * 74)
        lines.append(" LIVING CAPABILITY SYSTEM (LCS) — MULTI-CAPABILITY EXECUTION PLAN")
        lines.append("=" * 74)
        lines.append(f"  Plan ID:             {plan.plan_id}")
        lines.append(f"  Plan Type:           {plan.plan_type}")
        lines.append(f"  Readiness Status:    {plan.status}")
        lines.append(f"  Request Query:       {plan.request_query!r}")
        lines.append(f"  Execution Order:     {' -> '.join(plan.execution_order) if plan.execution_order else '(none)'}")
        lines.append(f"  Explanation:         {plan.explanation}")

        lines.append("\n[Planned Operations & Dependency Graph]")
        if plan.steps:
            for s in plan.steps:
                dep_str = f" [Prerequisites: {', '.join(s.dependencies)}]" if s.dependencies else " [Independent / Entry]"
                lines.append(f"  * [{s.step_id}] {s.display_name} ({s.capability_urn}){dep_str}")
                lines.append(f"    - Sub-Goal:        {s.sub_goal}")
                lines.append(f"    - Readiness:       {s.readiness}")
                lines.append(f"    - Selection Reason:{s.selection_reason}")

                if s.input_bindings:
                    lines.append("    - Input Bindings:")
                    for p_name, b in sorted(s.input_bindings.items()):
                        req_tag = "REQ" if b.required else "OPT"
                        if b.source_type == BindingSourceType.STEP_OUTPUT:
                            src_desc = f"OUTPUT_OF ${{{b.source_step_id}.{b.source_output_field}}}"
                        elif b.source_type == BindingSourceType.USER_SUPPLIED:
                            src_desc = f"USER ({b.bound_value!r})"
                        elif b.source_type == BindingSourceType.SCHEMA_DEFAULT:
                            src_desc = f"DEFAULT ({b.bound_value!r})"
                        elif b.source_type == BindingSourceType.CONFLICT:
                            src_desc = f"CONFLICT: {b.conflict_details}"
                        else:
                            src_desc = "UNRESOLVED"
                        err_str = f" [ERROR: {b.validation_error}]" if not b.is_valid and b.validation_error else ""
                        lines.append(f"      * {p_name} ({b.param_type}) [{req_tag}]: {src_desc}{err_str}")

                if s.output_definitions:
                    lines.append("    - Produced Outputs:")
                    for out_name, out_def in sorted(s.output_definitions.items()):
                        lines.append(f"      * {out_name} ({out_def.field_type}) [{out_def.evidence}]")
        else:
            lines.append("  * (No steps planned)")

        if plan.dag_edges:
            lines.append("\n[Dependency Edges]")
            for u, v, dep_t, r in plan.dag_edges:
                lines.append(f"  - {u} ──({dep_t})──> {v}: {r}")

        if plan.missing_inputs:
            lines.append("\n[Missing Required Inputs]")
            for mi in plan.missing_inputs:
                lines.append(f"  ! {mi['step_id']} ({mi['step_name']}) -> {mi['parameter']} ({mi['type']})")

        if plan.clarifying_questions:
            lines.append("\n[Clarifying Questions & Actionable Requests]")
            for idx, q in enumerate(plan.clarifying_questions, start=1):
                lines.append(f"  {idx}. {q}")

        lines.append("=" * 74)
        return "\n".join(lines)


__all__ = [
    "PlanReadinessStatus",
    "DependencyType",
    "OutputEvidenceSource",
    "BindingSourceType",
    "StepOutputDefinition",
    "StepInputBinding",
    "PlanStep",
    "ExecutionPlan",
    "CapabilityPlanningEngineV1"
]
