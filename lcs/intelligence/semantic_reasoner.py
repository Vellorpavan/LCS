"""
Call Me — Host-Assisted Semantic Reasoning & Requirement Coverage Validator
==========================================================================
Provides:
1. Generalized objective-to-requirement decomposition across arbitrary domains.
2. Compact candidate brief generation (skills + installed agents, scripts,
   references, prerequisites, and limitations) for host AI reasoning.
3. Deterministic validation & governance gating over host-assisted decisions
   (never blindly trusting host-generated capability IDs or instructions).
4. Deterministic local semantic reasoning fallback when host reasoning is
   unavailable, pairing existing installed agents with complementary skills.
5. Bidirectional coverage validation:
   - Every explicit requirement is covered by a capability or reported as a gap.
   - Every selected capability has a defensible relationship to the objective.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..inventory.hybrid_retrieval import (
    HybridSemanticRetriever,
    STOPWORDS,
    TECH_SHORT_TOKENS,
    TECHNICAL_SYNONYMS,
    stem_token,
)
from ..inventory.models import ResourceType


@dataclass
class RequirementItem:
    id: str
    text: str
    kind: str = "explicit"  # "explicit" | "implicit"
    keywords: List[str] = field(default_factory=list)


@dataclass
class CapabilitySelection:
    urn: str
    name: str
    resource_type: str
    covers_requirements: List[str] = field(default_factory=list)
    agent_urn: Optional[str] = None
    agent_id: Optional[str] = None
    agent_source: Optional[str] = None
    paired_skills: List[str] = field(default_factory=list)
    justification: str = ""
    expected_deliverables: List[str] = field(default_factory=list)
    verification_commands: List[str] = field(default_factory=list)
    relevance_score: float = 0.0


@dataclass
class CapabilityGap:
    requirement_id: str
    requirement_text: str
    reason: str
    discovery_query: str
    suggested_discovery_urn: Optional[str] = None


@dataclass
class SemanticReasoningResult:
    objective: str
    reasoning_mode: str  # "host_assisted" | "local_fallback"
    host_model: Optional[str]
    requirements: List[RequirementItem]
    selections: List[CapabilitySelection]
    rejected_candidates: List[Dict[str, str]]
    gaps: List[CapabilityGap]
    coverage_complete: bool
    validation_errors: List[str] = field(default_factory=list)
    needs_clarification: bool = False
    clarification_questions: List[str] = field(default_factory=list)
    abstention_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "objective": self.objective,
            "reasoning_mode": self.reasoning_mode,
            "host_model": self.host_model,
            "requirements": [asdict(r) for r in self.requirements],
            "selections": [asdict(s) for s in self.selections],
            "rejected_candidates": list(self.rejected_candidates),
            "gaps": [asdict(g) for g in self.gaps],
            "coverage_complete": self.coverage_complete,
            "validation_errors": list(self.validation_errors),
            "needs_clarification": self.needs_clarification,
            "clarification_questions": list(self.clarification_questions),
            "abstention_reason": self.abstention_reason,
        }


def _extract_keywords(text: str) -> List[str]:
    tokens = re.split(r"[^a-zA-Z0-9_\-]+", text.lower())
    out = []
    for t in tokens:
        if not t:
            continue
        if t in TECH_SHORT_TOKENS or (len(t) > 2 and t not in STOPWORDS):
            if t not in out:
                out.append(t)
    return out


class SemanticReasoner:
    """
    Combines fast local retrieval with structured host-assisted semantic reasoning
    and deterministic coverage/governance validation.
    """

    @staticmethod
    def decompose_requirements(objective: str) -> List[RequirementItem]:
        """
        Decomposes an arbitrary natural-language objective into explicit
        functional requirement items without domain-specific hardcoding.
        """
        clean = (objective or "").strip()
        if not clean:
            return []

        # 1. Split on explicit sequential or semicolon boundaries
        primary_chunks = [
            c.strip()
            for c in re.split(
                r"\b(?:and\s+then|then|followed\s+by|afterwards|and\s+finally)\b|[;]",
                clean,
                flags=re.IGNORECASE,
            )
            if len(c.strip()) > 2
        ]

        clauses: List[str] = []
        for chunk in primary_chunks:
            # 2. Split on comma / ", and " lists
            comma_parts = [
                p.strip()
                for p in re.split(r",\s*(?:and\s+)?|\s+and\s+(?=[a-z0-9])", chunk, flags=re.IGNORECASE)
                if len(p.strip()) > 2
            ]
            for part in comma_parts:
                # 3. Split "Build X with Y" when Y is a distinct functional component
                with_parts = [
                    wp.strip()
                    for wp in re.split(r"\b(?:with|plus|including)\b", part, flags=re.IGNORECASE)
                    if len(wp.strip()) > 2
                ]
                if len(with_parts) > 1 and all(len(_extract_keywords(wp)) >= 1 for wp in with_parts):
                    clauses.extend(with_parts)
                else:
                    clauses.append(part)

        # Deduplicate while preserving order
        reqs: List[RequirementItem] = []
        seen_texts: Set[str] = set()
        for c in clauses:
            norm = c.lower().strip(" .")
            if not norm or norm in seen_texts:
                continue
            kws = _extract_keywords(norm)
            if not kws:
                continue
            seen_texts.add(norm)
            reqs.append(
                RequirementItem(
                    id=f"req-item-{len(reqs) + 1}",
                    text=c.strip(" ."),
                    kind="explicit",
                    keywords=kws,
                )
            )

        if not reqs:
            reqs.append(
                RequirementItem(
                    id="req-item-1",
                    text=clean,
                    kind="explicit",
                    keywords=_extract_keywords(clean),
                )
            )

        return reqs

    @classmethod
    def build_candidate_brief(
        cls,
        inventory: Any,
        hydration_engine: Optional[Any],
        objective: str,
        requirements: List[RequirementItem],
        max_skills: int = 15,
        max_agents: int = 10,
        max_total_budget: int = 24,
    ) -> Dict[str, Any]:
        """
        Builds a compact, token-efficient candidate brief using adaptive
        requirement-driven retrieval:
        - Retrieves initial candidates independently per requirement.
        - Selectively expands retrieval (up to limit=25) only for uncovered
          requirements while respecting max_total_budget.
        - Extracts deep skill/agent metadata (scripts, references, templates,
          prerequisites, languages/frameworks, permissions, and limitations).
        """
        skill_candidates: Dict[str, Any] = {}
        agent_candidates: Dict[str, Any] = {}

        all_records = inventory.list_all() if hasattr(inventory, "list_all") else []
        agent_records = [r for r in all_records if getattr(r, "resource_type", None) == ResourceType.AGENT]

        # 1. Initial retrieval across objective and each decomposed requirement
        for q in [objective] + [r.text for r in requirements]:
            for m in inventory.search(q, limit=6):
                if m.urn.endswith((":call-me", ":call_me")):
                    continue
                if getattr(m, "resource_type", None) == ResourceType.AGENT:
                    agent_candidates.setdefault(m.urn, m)
                else:
                    skill_candidates.setdefault(m.urn, m)

        # 2. Selective expansion for any requirement lacking >= 2 justified candidates
        for req in requirements:
            if len(skill_candidates) >= max_total_budget:
                break
            justified_for_req = [
                rec for rec in skill_candidates.values()
                if cls.is_capability_justified(rec, objective, [req])[0]
            ]
            if len(justified_for_req) < 2:
                for exp_limit in (15, 25):
                    if len(skill_candidates) >= max_total_budget:
                        break
                    for m in inventory.search(req.text, limit=exp_limit):
                        if m.urn.endswith((":call-me", ":call_me")):
                            continue
                        if getattr(m, "resource_type", None) != ResourceType.AGENT:
                            if m.urn not in skill_candidates and cls.is_capability_justified(m, objective, [req])[0]:
                                skill_candidates[m.urn] = m
                                if len(skill_candidates) >= max_total_budget:
                                    break
                    # Check if requirement now has >= 2 justified candidates
                    if sum(1 for rec in skill_candidates.values() if cls.is_capability_justified(rec, objective, [req])[0]) >= 2:
                        break

        # 3. Explicitly score installed agents across the objective + requirements
        if agent_records:
            for q in [objective] + [r.text for r in requirements]:
                for a in HybridSemanticRetriever.search(agent_records, q, limit=4):
                    agent_candidates.setdefault(a.urn, a)

        def _summarize_record(rec: Any) -> Dict[str, Any]:
            prov = getattr(rec, "provenance", None)
            source_path = getattr(prov, "source_path", None) if prov else None
            exec_req = getattr(rec, "execution_requirements", None)
            summary = {
                "urn": rec.urn,
                "name": rec.name,
                "resource_type": rec.resource_type.value if hasattr(rec.resource_type, "value") else str(rec.resource_type),
                "description": (rec.description or "")[:300],
                "tags": list(getattr(rec, "tags", []) or []),
                "source_path": source_path,
                "scripts": [],
                "references": [],
                "templates": [],
                "prerequisites": [],
                "limitations": [],
                "permissions": {
                    "network_required": getattr(exec_req, "network_required", False) if exec_req else False,
                    "sandbox_required": getattr(exec_req, "sandbox_required", True) if exec_req else True,
                    "security_flags": list(getattr(rec, "security_flags", []) or []),
                },
            }
            if hydration_engine:
                try:
                    hyd = hydration_engine.hydrate_capability(rec.urn)
                    for dep in getattr(hyd, "dependencies", []) or []:
                        dep_name = getattr(dep, "name", str(dep))
                        dep_type = str(getattr(dep, "resource_type", ""))
                        if "SCRIPT" in dep_type or dep_name.endswith((".py", ".sh", ".ps1")):
                            summary["scripts"].append(dep_name)
                        elif "TEMPLATE" in dep_type or "template" in dep_name.lower():
                            summary["templates"].append(dep_name)
                        elif "DOC" in dep_type or dep_name.endswith(".md"):
                            summary["references"].append(dep_name)
                        else:
                            summary["prerequisites"].append(dep_name)
                    raw_inst = getattr(hyd, "raw_instructions", None) or getattr(hyd, "instructions_preview", None) or ""
                    if raw_inst:
                        summary["instructions_excerpt"] = raw_inst[:300]
                        # Extract any explicit limitation/warning lines
                        for line in raw_inst.splitlines():
                            low = line.lower()
                            if any(k in low for k in ("limitation", "never ", "do not ", "requires ", "prerequisite")):
                                summary["limitations"].append(line.strip()[:140])
                                if len(summary["limitations"]) >= 3:
                                    break
                except Exception:
                    pass
            return summary

        effective_skill_cap = min(max_total_budget, max(max_skills, len(requirements) * 3))
        return {
            "objective": objective,
            "requirements": [asdict(r) for r in requirements],
            "candidate_skills": [_summarize_record(r) for r in list(skill_candidates.values())[:effective_skill_cap]],
            "candidate_agents": [_summarize_record(r) for r in list(agent_candidates.values())[:max_agents]],
        }

    @classmethod
    def is_capability_justified(
        cls,
        record: Any,
        objective: str,
        requirements: List[RequirementItem],
    ) -> Tuple[bool, str]:
        """
        Deterministically verifies whether a candidate capability has a defensible
        relationship to the objective or at least one explicit requirement.
        """
        r_name = (getattr(record, "name", "") or "").lower()
        r_desc = (getattr(record, "description", "") or "").lower()
        r_tags = set(t.lower() for t in (getattr(record, "tags", []) or []))

        obj_tokens = _extract_keywords(objective)
        req_tokens: List[str] = []
        for req in requirements:
            for kw in req.keywords:
                if kw not in req_tokens:
                    req_tokens.append(kw)
        all_tokens = list(dict.fromkeys(obj_tokens + req_tokens))

        expanded: Set[str] = set()
        for t in all_tokens:
            expanded.add(t)
            expanded |= stem_token(t)
            for syn in TECHNICAL_SYNONYMS.get(t, []):
                expanded.add(syn.lower())

        query_ngrams = HybridSemanticRetriever.score_record  # type: ignore
        score = HybridSemanticRetriever.score_record(
            record, objective.lower(), all_tokens, expanded, set()
        )
        # Also check best single-requirement score
        best_req_score = score
        best_req_id = requirements[0].id if requirements else "req-item-1"
        for req in requirements:
            req_exp: Set[str] = set()
            for kw in req.keywords:
                req_exp.add(kw)
                req_exp |= stem_token(kw)
                for syn in TECHNICAL_SYNONYMS.get(kw, []):
                    req_exp.add(syn.lower())
            rs = HybridSemanticRetriever.score_record(
                record, req.text.lower(), req.keywords, req_exp, set()
            )
            if rs > best_req_score:
                best_req_score = rs
                best_req_id = req.id

        if best_req_score < HybridSemanticRetriever.MIN_ABSTAIN_THRESHOLD:
            return False, f"Score {best_req_score:.1f} below relevance threshold ({HybridSemanticRetriever.MIN_ABSTAIN_THRESHOLD})"

        return True, f"Defensible match for {best_req_id} (score={best_req_score:.1f})"

    @classmethod
    def _match_existing_agent(
        cls,
        skill_record: Any,
        req: Optional[RequirementItem],
        agent_records: List[Any],
        active_host: str = "",
    ) -> Optional[Any]:
        """Finds the best matching existing installed AGENT for a capability/requirement."""
        if not agent_records:
            return None
        query_parts = [getattr(skill_record, "name", ""), getattr(skill_record, "description", "")]
        if req:
            query_parts.append(req.text)
        query = " ".join(p for p in query_parts if p)

        matches = HybridSemanticRetriever.search(agent_records, query, limit=5)
        for m in matches:
            m_name = m.name.lower()
            if "host agent" in m_name or "lcs skill agent" in m_name or "mcp server host" in m_name or m_name.startswith("lcs-"):
                continue
            if active_host and "antigravity" in active_host and m.urn.startswith("urn:lcs:agent:opencode"):
                continue
            return m
        return None

    @classmethod
    def _derive_deliverables_and_commands(
        cls,
        cap_name: str,
        cap_desc: str,
        covered_reqs: List[RequirementItem],
    ) -> Tuple[List[str], List[str]]:
        """
        Derives expected deliverables and verification commands from capability metadata
        and covered requirement semantics without hardcoding specific project titles.
        """
        clean_ident = cap_name.lower().replace("-", "_")
        combined_text = " ".join([cap_name.lower(), cap_desc.lower()] + [r.text.lower() for r in covered_reqs])

        deliverables: List[str] = []
        commands: List[str] = []

        is_testing = any(w in clean_ident for w in ("test", "pytest", "tdd", "qa", "verify")) or any(
            w in " ".join(r.text.lower() for r in covered_reqs)
            for w in ("pytest", "unittest", "integration suite", "test suite", "unit test", "tests")
        )
        is_frontend_html = any(w in combined_text for w in ("html", "dashboard", "frontend")) and (
            "html" in " ".join(r.text.lower() for r in covered_reqs)
        )

        if "telemetry" in clean_ident:
            deliverables.append("telemetry.py")
        elif "health" in clean_ident:
            deliverables.append("health.py")
        elif "scaffold" in clean_ident or "structure" in clean_ident:
            deliverables.append("app.py")
        elif "assembly" in clean_ident or "runner" in clean_ident or "main" in clean_ident:
            deliverables.append("main.py")
        elif any(w in clean_ident for w in ("test", "pytest", "tdd", "qa", "verify")):
            deliverables.append("test_service.py")
            if "pytest" in combined_text:
                commands.append("python3 -m pytest")
            else:
                commands.append("python3 test_service.py")
        else:
            deliverables.append(f"{clean_ident}.py")

        if is_frontend_html and ("dashboard" in clean_ident or "frontend" in clean_ident):
            if "dashboard.html" not in deliverables:
                deliverables.append("dashboard.html")

        if is_testing and not commands:
            if "test_service.py" not in deliverables:
                deliverables.append("test_service.py")
            commands.append("python3 -m pytest" if "pytest" in combined_text else "python3 test_service.py")

        return deliverables, commands

    @classmethod
    def validate_and_build_from_host_decision(
        cls,
        objective: str,
        requirements: List[RequirementItem],
        host_decision: Dict[str, Any],
        inventory: Any,
        active_host: str = "",
        host_model: Optional[str] = None,
        is_compatible_fn: Optional[Callable[[str, str], bool]] = None,
    ) -> SemanticReasoningResult:
        """
        Deterministically validates a structured host AI reasoning decision against
        verified inventory, governance, justification, and requirement coverage rules.
        Never blindly trusts host-generated capability IDs or execution instructions.
        """
        validation_errors: List[str] = []
        rejected: List[Dict[str, str]] = list(host_decision.get("rejected_candidates", []))
        selections: List[CapabilitySelection] = []
        covered_req_ids: Set[str] = set()

        all_records = inventory.list_all() if hasattr(inventory, "list_all") else []
        by_urn = {r.urn: r for r in all_records}
        by_name = {r.name.lower(): r for r in all_records}
        agent_records = [r for r in all_records if getattr(r, "resource_type", None) == ResourceType.AGENT]

        for item in host_decision.get("selected_capabilities", []):
            raw_urn = item.get("urn", "")
            rec = by_urn.get(raw_urn) or by_name.get(raw_urn.lower())
            if not rec:
                validation_errors.append(f"Rejected hallucinated/unverified capability '{raw_urn}' not in inventory.")
                rejected.append({"urn": raw_urn, "reason": "Not found in verified inventory"})
                continue

            if is_compatible_fn and not is_compatible_fn(rec.urn, active_host):
                validation_errors.append(f"Rejected host-incompatible capability '{rec.urn}'.")
                rejected.append({"urn": rec.urn, "reason": "Incompatible with active host"})
                continue

            justified, just_reason = cls.is_capability_justified(rec, objective, requirements)
            if not justified:
                validation_errors.append(f"Rejected unjustified capability '{rec.urn}': {just_reason}")
                rejected.append({"urn": rec.urn, "reason": just_reason})
                continue

            # Validate optional agent assignment
            agent_rec = None
            raw_agent = item.get("agent_id") or item.get("agent_urn")
            if raw_agent:
                agent_rec = by_urn.get(raw_agent) or by_name.get(raw_agent.lower())
                if not agent_rec or getattr(agent_rec, "resource_type", None) != ResourceType.AGENT:
                    validation_errors.append(f"Unverified agent '{raw_agent}' ignored; falling back to inventory match.")
                    agent_rec = None
            if not agent_rec:
                cov_reqs = [r for r in requirements if r.id in (item.get("covers_requirements") or [])]
                agent_rec = cls._match_existing_agent(rec, cov_reqs[0] if cov_reqs else None, agent_records, active_host)

            # Validate paired skills
            valid_paired: List[str] = []
            for p_urn in item.get("paired_skills", []) or []:
                p_rec = by_urn.get(p_urn) or by_name.get(p_urn.lower())
                if p_rec and (not is_compatible_fn or is_compatible_fn(p_rec.urn, active_host)):
                    valid_paired.append(p_rec.urn)

            cov_ids = list(item.get("covers_requirements") or [])
            for cid in cov_ids:
                covered_req_ids.add(cid)

            cov_reqs = [r for r in requirements if r.id in cov_ids]
            delivs, cmds = cls._derive_deliverables_and_commands(rec.name, rec.description or "", cov_reqs)
            if item.get("expected_deliverables"):
                for d in item["expected_deliverables"]:
                    if d not in delivs and ".." not in d and ":" not in d:
                        delivs.append(d)

            selections.append(
                CapabilitySelection(
                    urn=rec.urn,
                    name=rec.name,
                    resource_type=rec.resource_type.value if hasattr(rec.resource_type, "value") else str(rec.resource_type),
                    covers_requirements=cov_ids,
                    agent_urn=agent_rec.urn if agent_rec else None,
                    agent_id=agent_rec.name if agent_rec else None,
                    agent_source=getattr(getattr(agent_rec, "provenance", None), "source_path", None) if agent_rec else None,
                    paired_skills=valid_paired,
                    justification=item.get("justification") or just_reason,
                    expected_deliverables=delivs,
                    verification_commands=cmds,
                )
            )

        gaps: List[CapabilityGap] = []
        for g in host_decision.get("missing_capabilities", []) or []:
            gaps.append(
                CapabilityGap(
                    requirement_id=g.get("requirement_id", "unknown"),
                    requirement_text=g.get("requirement_text", g.get("needed_capability", "")),
                    reason=g.get("reason", "Identified missing capability by host reasoning"),
                    discovery_query=g.get("needed_capability", g.get("requirement_text", "")),
                )
            )

        # Ensure every explicit requirement is accounted for
        gap_req_ids = {g.requirement_id for g in gaps}
        for req in requirements:
            if req.id not in covered_req_ids and req.id not in gap_req_ids:
                gaps.append(
                    CapabilityGap(
                        requirement_id=req.id,
                        requirement_text=req.text,
                        reason="Requirement not covered by any validated capability",
                        discovery_query=req.text,
                    )
                )

        return SemanticReasoningResult(
            objective=objective,
            reasoning_mode="host_assisted",
            host_model=host_model,
            requirements=requirements,
            selections=selections,
            rejected_candidates=rejected,
            gaps=gaps,
            coverage_complete=len(gaps) == 0 and len(selections) > 0,
            validation_errors=validation_errors,
        )

    @classmethod
    def reason_locally(
        cls,
        objective: str,
        inventory: Any,
        active_host: str = "",
        is_compatible_fn: Optional[Callable[[str, str], bool]] = None,
        max_steps: int = 8,
    ) -> SemanticReasoningResult:
        """
        Deterministic local semantic reasoning fallback:
        - Decomposes objective into explicit requirements.
        - Retrieves candidates per requirement and validates justification.
        - Rejects unrelated capabilities and detects missing capability gaps.
        - Pairs selected skills with matching existing installed specialist agents.
        """
        clean_tokens = [t for t in re.split(r"[^a-zA-Z0-9_\-]+", (objective or "").strip().lower()) if t]
        vague_pronouns = {"it", "this", "that", "something", "anything", "everything", "stuff", "thing"}
        meaningful_kws = _extract_keywords(objective or "")
        is_ambiguous = (
            not clean_tokens
            or (len(clean_tokens) <= 2 and any(t in vague_pronouns for t in clean_tokens))
            or (len(meaningful_kws) == 0)
        )
        if is_ambiguous:
            return SemanticReasoningResult(
                objective=objective,
                reasoning_mode="local_fallback",
                host_model=None,
                requirements=[],
                selections=[],
                rejected_candidates=[],
                gaps=[],
                coverage_complete=False,
                needs_clarification=True,
                clarification_questions=[
                    "What target system, language, or deliverable should be built or modified?",
                    "Are there specific verification tests or acceptance criteria required?"
                ],
                abstention_reason="ambiguous_objective",
            )

        requirements = cls.decompose_requirements(objective)
        all_records = inventory.list_all() if hasattr(inventory, "list_all") else []
        agent_records = [r for r in all_records if getattr(r, "resource_type", None) == ResourceType.AGENT]

        # Pre-compute whole-objective search once (prevents modifier-clause splitting from losing context)
        obj_matches = inventory.search(objective, limit=12) if hasattr(inventory, "search") else []
        obj_tokens = _extract_keywords(objective)
        obj_exp: Set[str] = set()
        for t in obj_tokens:
            obj_exp.add(t)
            obj_exp |= stem_token(t)
            for syn in TECHNICAL_SYNONYMS.get(t, []):
                obj_exp.add(syn.lower())

        obj_scores: Dict[str, float] = {}
        for om in obj_matches:
            if not om.urn.endswith((":call-me", ":call_me")):
                obj_scores[om.urn] = HybridSemanticRetriever.score_record(om, objective.lower(), obj_tokens, obj_exp, set())

        selected_by_urn: Dict[str, CapabilitySelection] = {}
        rejected: List[Dict[str, str]] = []
        gaps: List[CapabilityGap] = []
        agent_cache: Dict[str, Optional[Any]] = {}

        # Discovery capability lookup (cached from all_records, zero extra inventory scan)
        discovery_urn = None
        for d_cand in all_records:
            d_name = d_cand.name.lower()
            d_desc = (d_cand.description or "").lower()
            if "skill-scout" in d_name or ("search" in d_desc and "skill" in d_desc and "source" in d_desc):
                discovery_urn = d_cand.urn
                break

        # Build merged candidate pool: whole-objective top hits + selective per-requirement hits
        for req in requirements:
            req_lower = req.text.lower()
            strong_from_obj = []
            for om in obj_matches:
                if getattr(om, "resource_type", None) == ResourceType.AGENT or om.urn.endswith((":call-me", ":call_me")):
                    continue
                req_sc = HybridSemanticRetriever.score_record(om, req_lower, req.keywords, set(req.keywords), set())
                if req_sc >= 35.0 or (obj_scores.get(om.urn, 0.0) >= 60.0 and req_sc >= 15.0):
                    strong_from_obj.append(om)

            # Only scan inventory for this requirement if obj_matches didn't yield >= 2 strong hits
            if len(strong_from_obj) >= 2 or not hasattr(inventory, "search"):
                merged = list(obj_matches)
            else:
                req_matches = inventory.search(req.text, limit=6)
                merged = list(obj_matches)
                seen_m = {m.urn for m in merged}
                for rm in req_matches:
                    if rm.urn not in seen_m:
                        merged.append(rm)
                        seen_m.add(rm.urn)

            skill_matches = [m for m in merged if getattr(m, "resource_type", None) != ResourceType.AGENT]
            if not skill_matches and hasattr(inventory, "search"):
                exp_matches = inventory.search(req.text, limit=20)
                skill_matches = [m for m in exp_matches if getattr(m, "resource_type", None) != ResourceType.AGENT]
                if exp_matches:
                    merged = exp_matches
            ordered_matches = skill_matches if skill_matches else merged
            req_covered = False
            req_wants_testing = any(w in req_lower for w in ("test", "pytest", "unittest", "tdd", "qa", "verify", "verification", "spec", "suite"))

            scored_candidates: List[Tuple[float, Any]] = []
            for m in ordered_matches:
                if m.urn.endswith((":call-me", ":call_me")):
                    continue
                if is_compatible_fn and not is_compatible_fn(m.urn, active_host):
                    continue

                obj_score = obj_scores.get(m.urn)
                if obj_score is None:
                    obj_score = HybridSemanticRetriever.score_record(m, objective.lower(), obj_tokens, obj_exp, set())
                    obj_scores[m.urn] = obj_score
                req_score = HybridSemanticRetriever.score_record(m, req_lower, req.keywords, set(req.keywords), set())
                best_score = max(obj_score, req_score)
                if best_score < HybridSemanticRetriever.MIN_ABSTAIN_THRESHOLD:
                    rejected.append({"urn": m.urn, "reason": f"Score {best_score:.1f} below threshold"})
                    continue

                m_lower = m.name.lower()
                is_testing_cap = any(w in m_lower for w in ("testing", "tdd", "test-audit", "test-runner", "e2e-testing"))
                if is_testing_cap and not req_wants_testing:
                    rejected.append({"urn": m.urn, "reason": f"Testing capability not requested by '{req.text}'"})
                    continue
                scored_candidates.append((best_score, m))

            # Rank by best_score descending so stronger retrieval results are never pushed out by clause order
            scored_candidates.sort(key=lambda x: x[0], reverse=True)

            for best_score, m in scored_candidates:
                if any(s.name.lower() == m.name.lower() for s in selected_by_urn.values()):
                    existing_sel = next(s for s in selected_by_urn.values() if s.name.lower() == m.name.lower())
                    if req.id not in existing_sel.covers_requirements:
                        existing_sel.covers_requirements.append(req.id)
                    existing_sel.relevance_score = max(existing_sel.relevance_score, best_score)
                    req_covered = True
                    continue

                req_covered = True
                if m.urn in selected_by_urn:
                    if req.id not in selected_by_urn[m.urn].covers_requirements:
                        selected_by_urn[m.urn].covers_requirements.append(req.id)
                    selected_by_urn[m.urn].relevance_score = max(selected_by_urn[m.urn].relevance_score, best_score)
                else:
                    if req.id not in agent_cache:
                        agent_cache[req.id] = cls._match_existing_agent(m, req, agent_records, active_host)
                    agent_rec = agent_cache[req.id]
                    delivs, cmds = cls._derive_deliverables_and_commands(m.name, m.description or "", [req])
                    selected_by_urn[m.urn] = CapabilitySelection(
                        urn=m.urn,
                        name=m.name,
                        resource_type=m.resource_type.value if hasattr(m.resource_type, "value") else str(m.resource_type),
                        covers_requirements=[req.id],
                        agent_urn=agent_rec.urn if agent_rec else None,
                        agent_id=agent_rec.name if agent_rec else None,
                        agent_source=getattr(getattr(agent_rec, "provenance", None), "source_path", None) if agent_rec else None,
                        paired_skills=[m.urn],
                        justification=f"Defensible match for {req.id} (score={best_score:.1f})",
                        expected_deliverables=delivs,
                        verification_commands=cmds,
                        relevance_score=best_score,
                    )
                if len([s for s in selected_by_urn.values() if req.id in s.covers_requirements]) >= 3:
                    break

            if not req_covered:
                gaps.append(
                    CapabilityGap(
                        requirement_id=req.id,
                        requirement_text=req.text,
                        reason="No installed capability satisfies requirement above confidence threshold",
                        discovery_query=req.text,
                        suggested_discovery_urn=discovery_urn,
                    )
                )

        # Confidence-aware fallback: preserve top-3 strong whole-objective retrieval hits if not already selected
        obj_wants_testing = any(w in objective.lower() for w in ("test", "pytest", "unittest", "tdd", "qa", "verify", "verification", "spec", "suite"))
        for om in [m for m in obj_matches if getattr(m, "resource_type", None) != ResourceType.AGENT][:3]:
            if om.urn.endswith((":call-me", ":call_me")):
                continue
            if is_compatible_fn and not is_compatible_fn(om.urn, active_host):
                continue
            sc = obj_scores.get(om.urn, 0.0)
            if sc < HybridSemanticRetriever.MIN_ABSTAIN_THRESHOLD:
                continue
            is_testing_cap = any(w in om.name.lower() for w in ("testing", "tdd", "test-audit", "test-runner", "e2e-testing"))
            if is_testing_cap and not obj_wants_testing:
                continue
            if om.urn not in selected_by_urn and not any(s.name.lower() == om.name.lower() for s in selected_by_urn.values()):
                req0 = requirements[0] if requirements else None
                agent_rec = agent_cache.get(req0.id) if req0 and req0.id in agent_cache else cls._match_existing_agent(om, req0, agent_records, active_host)
                delivs, cmds = cls._derive_deliverables_and_commands(om.name, om.description or "", [req0] if req0 else [])
                selected_by_urn[om.urn] = CapabilitySelection(
                    urn=om.urn,
                    name=om.name,
                    resource_type=om.resource_type.value if hasattr(om.resource_type, "value") else str(om.resource_type),
                    covers_requirements=[req0.id] if req0 else [],
                    agent_urn=agent_rec.urn if agent_rec else None,
                    agent_id=agent_rec.name if agent_rec else None,
                    agent_source=getattr(getattr(agent_rec, "provenance", None), "source_path", None) if agent_rec else None,
                    paired_skills=[om.urn],
                    justification=f"Confidence-preserving whole-objective match (score={sc:.1f})",
                    expected_deliverables=delivs,
                    verification_commands=cmds,
                    relevance_score=sc,
                )

        # Rank selections by whole-objective + requirement relevance score and enforce max_steps
        ranked_selections = sorted(selected_by_urn.values(), key=lambda s: s.relevance_score, reverse=True)[:max_steps]
        selected_by_urn = {s.urn: s for s in ranked_selections}

        # Re-derive deliverables/commands with full covered requirements
        req_by_id = {r.id: r for r in requirements}
        for sel in selected_by_urn.values():
            cov_reqs = [req_by_id[rid] for rid in sel.covers_requirements if rid in req_by_id]
            rec = next((r for r in all_records if r.urn == sel.urn), None)
            delivs, cmds = cls._derive_deliverables_and_commands(
                sel.name, (rec.description if rec else "") or "", cov_reqs
            )
            sel.expected_deliverables = delivs
            sel.verification_commands = cmds

        selections = list(selected_by_urn.values())
        # Multi-skill composition: link complementary skills assigned to the same installed agent
        skills_by_agent: Dict[str, List[str]] = {}
        for sel in selections:
            if sel.agent_id:
                skills_by_agent.setdefault(sel.agent_id, [])
                if sel.urn not in skills_by_agent[sel.agent_id]:
                    skills_by_agent[sel.agent_id].append(sel.urn)
        for sel in selections:
            if sel.agent_id and sel.agent_id in skills_by_agent:
                sel.paired_skills = list(skills_by_agent[sel.agent_id])

        abstention_reason = None
        if not selections and gaps:
            abstention_reason = "out_of_domain_or_missing_capability"

        return SemanticReasoningResult(
            objective=objective,
            reasoning_mode="local_fallback",
            host_model=None,
            requirements=requirements,
            selections=selections,
            rejected_candidates=rejected,
            gaps=gaps,
            coverage_complete=len(gaps) == 0 and len(selections) > 0,
            abstention_reason=abstention_reason,
        )
