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


@dataclass
class CapabilityGap:
    requirement_id: str
    requirement_text: str
    reason: str
    discovery_query: str


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
    ) -> Dict[str, Any]:
        """
        Builds a compact, token-efficient candidate brief containing top skills and
        installed agents with descriptions, tags, scripts/references, and constraints
        for host AI reasoning.
        """
        skill_candidates: Dict[str, Any] = {}
        agent_candidates: Dict[str, Any] = {}

        all_records = inventory.list_all() if hasattr(inventory, "list_all") else []
        agent_records = [r for r in all_records if getattr(r, "resource_type", None) == ResourceType.AGENT]

        # Gather skill candidates across objective + each requirement
        search_queries = [objective] + [r.text for r in requirements]
        for q in search_queries:
            for m in inventory.search(q, limit=5):
                if m.urn.endswith((":call-me", ":call_me")):
                    continue
                if getattr(m, "resource_type", None) == ResourceType.AGENT:
                    agent_candidates.setdefault(m.urn, m)
                else:
                    skill_candidates.setdefault(m.urn, m)

        # Explicitly score installed agents across the objective + requirements
        if agent_records:
            for q in search_queries:
                for a in HybridSemanticRetriever.search(agent_records, q, limit=4):
                    agent_candidates.setdefault(a.urn, a)

        def _summarize_record(rec: Any) -> Dict[str, Any]:
            prov = getattr(rec, "provenance", None)
            source_path = getattr(prov, "source_path", None) if prov else None
            summary = {
                "urn": rec.urn,
                "name": rec.name,
                "resource_type": rec.resource_type.value if hasattr(rec.resource_type, "value") else str(rec.resource_type),
                "description": (rec.description or "")[:300],
                "tags": list(getattr(rec, "tags", []) or []),
                "source_path": source_path,
                "scripts": [],
                "references": [],
                "prerequisites": [],
                "limitations": [],
            }
            if hydration_engine:
                try:
                    hyd = hydration_engine.hydrate_capability(rec.urn)
                    for dep in getattr(hyd, "dependencies", []) or []:
                        dep_name = getattr(dep, "name", str(dep))
                        dep_type = str(getattr(dep, "resource_type", ""))
                        if "SCRIPT" in dep_type or dep_name.endswith((".py", ".sh")):
                            summary["scripts"].append(dep_name)
                        elif "DOC" in dep_type or dep_name.endswith(".md"):
                            summary["references"].append(dep_name)
                        else:
                            summary["prerequisites"].append(dep_name)
                    if getattr(hyd, "instructions_preview", None):
                        summary["instructions_excerpt"] = hyd.instructions_preview[:250]
                except Exception:
                    pass
            return summary

        return {
            "objective": objective,
            "requirements": [asdict(r) for r in requirements],
            "candidate_skills": [_summarize_record(r) for r in list(skill_candidates.values())[:max_skills]],
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
        requirements = cls.decompose_requirements(objective)
        all_records = inventory.list_all() if hasattr(inventory, "list_all") else []
        agent_records = [r for r in all_records if getattr(r, "resource_type", None) == ResourceType.AGENT]

        selected_by_urn: Dict[str, CapabilitySelection] = {}
        rejected: List[Dict[str, str]] = []
        gaps: List[CapabilityGap] = []

        for req in requirements:
            matches = inventory.search(req.text, limit=8) if hasattr(inventory, "search") else []
            # Prefer skills for step capabilities (agents are paired via _match_existing_agent),
            # falling back to agents only if no skill matches.
            skill_matches = [m for m in matches if getattr(m, "resource_type", None) != ResourceType.AGENT]
            ordered_matches = skill_matches if skill_matches else matches
            req_covered = False

            for m in ordered_matches:
                if m.urn.endswith((":call-me", ":call_me")):
                    continue
                if is_compatible_fn and not is_compatible_fn(m.urn, active_host):
                    continue
                # Deduplicate by normalized name if already selected
                if any(s.name.lower() == m.name.lower() for s in selected_by_urn.values()):
                    existing_sel = next(s for s in selected_by_urn.values() if s.name.lower() == m.name.lower())
                    if req.id not in existing_sel.covers_requirements:
                        existing_sel.covers_requirements.append(req.id)
                    req_covered = True
                    continue

                justified, reason = cls.is_capability_justified(m, objective, [req])
                if not justified:
                    rejected.append({"urn": m.urn, "reason": f"Unjustified for '{req.text}': {reason}"})
                    continue

                # If requirement does not mention testing/verification, skip testing-only capabilities
                # when a primary implementation capability already covers the requirement.
                req_lower = req.text.lower()
                m_lower = m.name.lower()
                req_wants_testing = any(w in req_lower for w in ("test", "pytest", "unittest", "tdd", "qa", "verify", "verification", "spec", "suite"))
                is_testing_cap = any(w in m_lower for w in ("testing", "tdd", "test-audit", "test-runner", "e2e-testing"))
                if is_testing_cap and not req_wants_testing:
                    rejected.append({"urn": m.urn, "reason": f"Testing capability not requested by '{req.text}'"})
                    continue

                req_covered = True
                if m.urn in selected_by_urn:
                    if req.id not in selected_by_urn[m.urn].covers_requirements:
                        selected_by_urn[m.urn].covers_requirements.append(req.id)
                else:
                    if len(selected_by_urn) >= max_steps:
                        break
                    agent_rec = cls._match_existing_agent(m, req, agent_records, active_host)
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
                        justification=reason,
                        expected_deliverables=delivs,
                        verification_commands=cmds,
                    )
                # Take top 1-2 justified capabilities per requirement
                if len([s for s in selected_by_urn.values() if req.id in s.covers_requirements]) >= 2:
                    break

            if not req_covered:
                # Check if any already-selected capability covers this requirement
                covered_by_existing = False
                for sel in selected_by_urn.values():
                    rec = next((r for r in all_records if r.urn == sel.urn), None)
                    if rec:
                        ok, _ = cls.is_capability_justified(rec, req.text, [req])
                        if ok:
                            sel.covers_requirements.append(req.id)
                            covered_by_existing = True
                            break
                if not covered_by_existing:
                    gaps.append(
                        CapabilityGap(
                            requirement_id=req.id,
                            requirement_text=req.text,
                            reason="No installed capability satisfies requirement above confidence threshold",
                            discovery_query=req.text,
                        )
                    )

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
        return SemanticReasoningResult(
            objective=objective,
            reasoning_mode="local_fallback",
            host_model=None,
            requirements=requirements,
            selections=selections,
            rejected_candidates=rejected,
            gaps=gaps,
            coverage_complete=len(gaps) == 0 and len(selections) > 0,
        )
