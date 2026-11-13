"""
Living Capability System (LCS) — Capability Intelligence Layer: Retrieval Engine V1
===================================================================================
Provides explainable, natural-language capability retrieval grounded in:
1. Capability Semantic Profiles (parameter schemas, purpose, operational boundaries)
2. SQLite FTS5 index (lexical candidate matching)
3. Authoritative M1-M3 registry and policy decisions

Recommends capabilities only; strictly does NOT execute tools.
Separates task relevance from interface trust/policy decisions.
Supports principled abstention (NO_SUITABLE_CAPABILITY_FOUND).
"""

import re
import json
import sqlite3
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple

from capability_profile_v2b import (
    EvidenceSource,
    ProfileField,
    ParameterProfile,
    CapabilitySemanticProfile,
    CapabilityProfileService
)
from capability_discovery_v2b import DiscoveryIndexService, SearchResult
from interface_policy_v2b import InterfacePolicyService, InterfaceTrustPolicy


# ----------------------------------------------------------------------------
# 1. Query Processing & Normalization
# ----------------------------------------------------------------------------

ENGLISH_STOPWORDS: Set[str] = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and",
    "any", "are", "aren't", "as", "at", "be", "because", "been", "before", "being",
    "below", "between", "both", "but", "by", "can", "cannot", "could", "couldn't",
    "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during",
    "each", "few", "for", "from", "further", "had", "hadn't", "has", "hasn't",
    "have", "haven't", "having", "he", "he'd", "he'll", "he's", "her", "here",
    "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i",
    "i'd", "i'll", "i'm", "i've", "if", "in", "into", "is", "isn't", "it",
    "it's", "its", "itself", "let's", "me", "more", "most", "mustn't", "my",
    "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or",
    "other", "ought", "our", "ours", "ourselves", "out", "over", "own", "same",
    "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't", "so",
    "some", "such", "than", "that", "that's", "the", "their", "theirs", "them",
    "themselves", "then", "there", "there's", "these", "they", "they'd", "they'll",
    "they're", "they've", "this", "those", "through", "to", "too", "under",
    "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're",
    "we've", "were", "weren't", "what", "what's", "when", "when's", "where",
    "where's", "which", "while", "who", "who's", "whom", "why", "why's", "with",
    "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've",
    "your", "yours", "yourself", "yourselves",
    # Conversational filler
    "please", "help", "want", "need", "like", "check", "whether", "proper",
    "run", "execute", "give", "find", "show", "tell", "tell me", "perform", "make"
}

# Domain-specific synonym mappings (canonical concept -> set of related terms)
CONCEPT_SYNONYMS: Dict[str, Set[str]] = {
    "pdf": {"pdf", "acrobat"},
    "document": {"doc", "docx", "document", "markdown", "plaintext"},
    "database": {"sql", "sqlite", "relational", "database"},
    "spatial": {
        "polygon", "geodesic", "haversine", "waypoint", "coordinates", "gis",
        "latitude", "longitude", "lat", "lon", "gps", "envelope", "distance", "range"
    },
    "security": {"hsts", "cybersecurity", "security", "header", "headers"},
    "statistics": {"variance", "stddev", "statistics", "statistical"},
    "version": {"semver", "versioning", "prerelease"}
}


@dataclass
class ProcessedQuery:
    """Represents a structured natural language user query."""
    raw_query: str
    tokens: List[str]
    core_terms: List[str]
    expanded_terms: Set[str]
    detected_concepts: Set[str]
    is_ambiguous: bool = False
    ambiguity_reason: Optional[str] = None


class QueryProcessor:
    """
    Cleans, tokenizes, and normalizes natural-language search queries.
    Preserves raw queries for explainability.
    """

    @staticmethod
    def stem(word: str) -> str:
        """Lightweight deterministic suffix-stripping stemmer."""
        w = word.lower()
        if len(w) <= 3:
            return w
        # Common plurals and verb forms
        if w.endswith("ies") and len(w) > 4:
            return w[:-3] + "y"
        if w.endswith("es") and len(w) > 3 and not w.endswith("ses"):
            return w[:-2]
        if w.endswith("s") and not w.endswith("ss") and len(w) > 3:
            return w[:-1]
        if w.endswith("ing") and len(w) > 4:
            return w[:-3]
        if w.endswith("ed") and len(w) > 4:
            return w[:-2]
        if w.endswith("ly") and len(w) > 4:
            return w[:-2]
        return w

    @classmethod
    def process(cls, query: str) -> ProcessedQuery:
        raw_query = query.strip()
        # Extract alphanumeric words and hyphenated terms
        words = re.findall(r"[a-zA-Z0-9_-]+", raw_query.lower())
        tokens = [w for w in words if len(w) > 1]

        # Extract core terms (filtering conversational stopwords)
        core_terms = []
        for t in tokens:
            cleaned = t.strip("-_")
            if cleaned and cleaned not in ENGLISH_STOPWORDS:
                core_terms.append(cleaned)

        # Detect concepts and expand synonyms
        detected_concepts = set()
        expanded_terms = set(core_terms)

        # Check for ambiguity
        is_ambiguous = False
        ambiguity_reason = None
        generic_terms = {
            "process", "data", "check", "system", "inspect", "handle",
            "records", "record", "manage", "analyze", "operation", "item", "items"
        }
        if len(core_terms) <= 2:
            if not core_terms or all(t in generic_terms for t in core_terms):
                is_ambiguous = True
                ambiguity_reason = (
                    "The query is too generic or underspecified. "
                    "Missing domain context (e.g. document, database, security headers, spatial metrics, statistics)."
                )

        for term in core_terms:
            stemmed = cls.stem(term)
            expanded_terms.add(stemmed)

            # Check concept dictionaries (exact term or stem only, no raw substring)
            for concept, synonyms in CONCEPT_SYNONYMS.items():
                if term in synonyms or stemmed in synonyms:
                    detected_concepts.add(concept)
                    expanded_terms.update(synonyms)

        return ProcessedQuery(
            raw_query=raw_query,
            tokens=tokens,
            core_terms=core_terms,
            expanded_terms=expanded_terms,
            detected_concepts=detected_concepts,
            is_ambiguous=is_ambiguous,
            ambiguity_reason=ambiguity_reason
        )


# ----------------------------------------------------------------------------
# 2. Candidate Scoring & Explainability Models
# ----------------------------------------------------------------------------

@dataclass
class ScoredCandidate:
    """Represents a ranked capability match with explainable audit evidence."""
    capability_urn: str
    display_name: str
    description: str
    category: str
    relevance_score: float  # Normalized 0.0 to 1.0
    matching_terms: List[str]
    matching_fields: Dict[str, List[str]]
    input_compatibility: Dict[str, Any]
    evidence_quality: Dict[str, str]
    missing_information: List[str]
    reasons: List[str]
    trust_status: str
    policy_decision: Optional[str] = None
    attestation_id: Optional[str] = None
    origin_uri: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_urn": self.capability_urn,
            "display_name": self.display_name,
            "description": self.description,
            "category": self.category,
            "relevance_score": round(self.relevance_score, 4),
            "matching_terms": self.matching_terms,
            "matching_fields": self.matching_fields,
            "input_compatibility": self.input_compatibility,
            "evidence_quality": self.evidence_quality,
            "missing_information": self.missing_information,
            "reasons": self.reasons,
            "trust_status": self.trust_status,
            "policy_decision": self.policy_decision,
            "attestation_id": self.attestation_id,
            "origin_uri": self.origin_uri
        }


@dataclass
class RetrievalResult:
    """Complete retrieval response, including candidates or abstention details."""
    raw_query: str
    processed_query: ProcessedQuery
    candidates: List[ScoredCandidate]
    abstained: bool = False
    abstention_code: Optional[str] = None  # e.g. "NO_SUITABLE_CAPABILITY_FOUND", "AMBIGUOUS_REQUEST"
    abstention_reason: Optional[str] = None
    missing_query_information: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.raw_query,
            "abstained": self.abstained,
            "abstention_code": self.abstention_code,
            "abstention_reason": self.abstention_reason,
            "missing_query_information": self.missing_query_information,
            "candidates": [c.to_dict() for c in self.candidates]
        }


# ----------------------------------------------------------------------------
# 3. Capability Retrieval Engine
# ----------------------------------------------------------------------------

class CapabilityRetrievalEngine:
    """
    Core retrieval engine matching natural-language tasks against LCS capabilities.
    Combines:
    - FTS5 keyword indexing
    - Semantic profile parameter & schema inspection
    - Multi-signal explainable scoring
    - Principled abstention logic
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        profile_service: CapabilityProfileService,
        index_service: Optional[DiscoveryIndexService] = None,
        iface_service: Optional[InterfacePolicyService] = None,
        default_policy: Optional[InterfaceTrustPolicy] = None
    ):
        self.conn = conn
        self.profile_service = profile_service
        self.index_service = index_service or DiscoveryIndexService(conn)
        self.iface_service = iface_service
        self.default_policy = default_policy or InterfaceTrustPolicy(
            policy_name="retrieval-audit-policy",
            allowed_attester_ids={"urn:lcs:attester:security:local-authority"},
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

    def retrieve(
        self,
        query: str,
        limit: int = 5,
        min_score_threshold: float = 0.25
    ) -> RetrievalResult:
        """
        Executes explainable capability retrieval for a natural-language query.
        Returns a RetrievalResult with ranked ScoredCandidates or abstains.
        """
        processed = QueryProcessor.process(query)

        # 1. Check for empty query
        if not processed.core_terms and not processed.tokens:
            return RetrievalResult(
                raw_query=query,
                processed_query=processed,
                candidates=[],
                abstained=True,
                abstention_code="NO_SUITABLE_CAPABILITY_FOUND",
                abstention_reason="Empty or non-meaningful query provided.",
                missing_query_information="Specify the task or capability needed."
            )

        # 2. Check for ambiguity
        if processed.is_ambiguous:
            return RetrievalResult(
                raw_query=query,
                processed_query=processed,
                candidates=[],
                abstained=True,
                abstention_code="AMBIGUOUS_REQUEST",
                abstention_reason=processed.ambiguity_reason,
                missing_query_information=(
                    "Target domain, file type, or specific action not specified. "
                    "Examples: 'extract tables from PDF', 'execute SQL query', 'calculate polygon area'."
                )
            )

        # 3. Retrieve all registered capabilities to score
        cur = self.conn.cursor()
        cur.execute("SELECT capability_urn FROM capability_declarations;")
        all_urns = [r[0] for r in cur.fetchall()]

        if not all_urns:
            return RetrievalResult(
                raw_query=query,
                processed_query=processed,
                candidates=[],
                abstained=True,
                abstention_code="NO_SUITABLE_CAPABILITY_FOUND",
                abstention_reason="No capabilities are registered in this LCS instance."
            )

        candidates: List[ScoredCandidate] = []

        for urn in all_urns:
            try:
                profile = self.profile_service.get_profile(urn)
                scored = self._score_candidate(profile, processed)
                if scored and scored.relevance_score > 0.0:
                    candidates.append(scored)
            except Exception:
                continue

        # 4. Sort candidates deterministically by relevance score descending, then URN ascending
        candidates.sort(key=lambda c: (-c.relevance_score, c.capability_urn))

        # 5. Filter qualifying candidates that meet minimum relevance threshold
        qualifying = [c for c in candidates if c.relevance_score >= min_score_threshold]

        # 6. Abstention Evaluation
        if not qualifying:
            top_score = candidates[0].relevance_score if candidates else 0.0
            return RetrievalResult(
                raw_query=query,
                processed_query=processed,
                candidates=[],
                abstained=True,
                abstention_code="NO_SUITABLE_CAPABILITY_FOUND",
                abstention_reason=(
                    f"No registered capability sufficiently matched the task. "
                    f"(Top relevance score {top_score:.2f} was below threshold {min_score_threshold:.2f})."
                ),
                missing_query_information="Check if the required tool is registered or adjust search phrasing."
            )

        # 7. Apply limit
        top_candidates = qualifying[:limit]

        return RetrievalResult(
            raw_query=query,
            processed_query=processed,
            candidates=top_candidates,
            abstained=False
        )

    @staticmethod
    def _match_field_terms(query_terms: Set[str], text: str) -> List[str]:
        if not text:
            return []
        text_words = set(re.findall(r"[a-zA-Z0-9_-]+", text.lower()))
        text_stems = {QueryProcessor.stem(w) for w in text_words}
        matches = []
        for t in query_terms:
            t_clean = t.lower().strip()
            if not t_clean or len(t_clean) <= 1:
                continue
            t_stem = QueryProcessor.stem(t_clean)
            if t_clean in text_words or t_stem in text_stems:
                matches.append(t_clean)
        return sorted(set(matches))

    def _score_candidate(
        self,
        profile: CapabilitySemanticProfile,
        query: ProcessedQuery
    ) -> Optional[ScoredCandidate]:
        """
        Computes multi-signal explainable relevance score for a single candidate profile.
        Weights:
        - Display Name: 0.35
        - Description: 0.35
        - Parameters: 0.20
        - Category: 0.10
        Evidence discount:
        - EXPLICIT: 1.0x
        - EXTRACTED: 0.95x
        - INFERRED: 0.60x
        - UNKNOWN: 0.0x
        """
        matching_terms: Set[str] = set()
        matching_fields: Dict[str, List[str]] = {
            "name": [],
            "description": [],
            "parameters": [],
            "category": []
        }
        evidence_quality: Dict[str, str] = {}
        reasons: List[str] = []

        all_query_terms = query.expanded_terms | set(query.core_terms)

        # Signal 1: Display Name (Weight 0.35)
        name_val = str(profile.display_name.value).lower()
        name_matches = self._match_field_terms(all_query_terms, name_val)
        name_score = 0.0
        if name_matches:
            matching_terms.update(name_matches)
            matching_fields["name"].extend(sorted(set(name_matches)))
            evidence_quality["name"] = profile.display_name.evidence
            name_ev_mult = 1.0 if profile.display_name.evidence == EvidenceSource.EXPLICIT else 0.95
            name_score = min(1.0, len(name_matches) / max(1, len(name_val.split()))) * name_ev_mult
            reasons.append(f"Name matched terms: {sorted(set(name_matches))} [{profile.display_name.evidence}]")

        # Signal 2: Description (Weight 0.35)
        desc_val = str(profile.description.value).lower()
        desc_matches = self._match_field_terms(all_query_terms, desc_val)
        desc_score = 0.0
        if desc_matches:
            matching_terms.update(desc_matches)
            matching_fields["description"].extend(sorted(set(desc_matches)))
            evidence_quality["description"] = profile.description.evidence
            desc_ev_mult = 1.0 if profile.description.evidence == EvidenceSource.EXPLICIT else 0.60
            desc_score = min(1.0, len(desc_matches) / 3.0) * desc_ev_mult
            reasons.append(f"Description matched terms: {sorted(set(desc_matches))} [{profile.description.evidence}]")

        # Signal 3: Input Parameters (Weight 0.20)
        param_matches: List[str] = []
        param_ev = EvidenceSource.UNKNOWN
        input_comp: Dict[str, Any] = {
            "required_parameters": profile.required_inputs.value or [],
            "optional_parameters": profile.optional_inputs.value or [],
            "matched_parameters": [],
            "missing_required": []
        }
        if profile.inputs.value:
            param_ev = profile.inputs.evidence
            evidence_quality["parameters"] = param_ev
            for p in profile.inputs.value:
                p_name = p.get("name", "").lower()
                p_desc = str(p.get("description") or "").lower()
                is_req = p.get("required", False)

                p_matched_terms = self._match_field_terms(all_query_terms, f"{p_name} {p_desc}")
                if p_matched_terms:
                    param_matches.extend(p_matched_terms)
                    input_comp["matched_parameters"].append(p.get("name"))
                elif is_req:
                    input_comp["missing_required"].append(p.get("name"))

        param_score = 0.0
        if param_matches:
            matching_terms.update(param_matches)
            matching_fields["parameters"].extend(sorted(set(param_matches)))
            param_ev_mult = 0.95 if param_ev == EvidenceSource.EXTRACTED else 0.60
            param_score = min(1.0, len(param_matches) / 2.0) * param_ev_mult
            reasons.append(f"Parameters matched terms: {sorted(set(param_matches))} [{param_ev}]")

        # Signal 4: Category & Concept (Weight 0.10)
        cat_val = str(profile.category.value).lower()
        cat_matches = self._match_field_terms(all_query_terms, cat_val)
        concept_match = False
        if any(c in cat_val for c in query.detected_concepts):
            concept_match = True
        cat_score = 0.0
        if cat_matches or concept_match:
            if cat_matches:
                matching_terms.update(cat_matches)
                matching_fields["category"].extend(sorted(set(cat_matches)))
            evidence_quality["category"] = profile.category.evidence
            # Category is typically INFERRED heuristics, so discounted
            cat_ev_mult = 0.60 if profile.category.evidence == EvidenceSource.INFERRED else 1.0
            cat_score = (1.0 if concept_match else 0.5) * cat_ev_mult
            reasons.append(f"Category matched: '{cat_val}' [{profile.category.evidence}]")
            # Category is typically INFERRED heuristics, so discounted
            cat_ev_mult = 0.60 if profile.category.evidence == EvidenceSource.INFERRED else 1.0
            cat_score = (1.0 if concept_match else 0.5) * cat_ev_mult
            reasons.append(f"Category matched: '{cat_val}' [{profile.category.evidence}]")

        # Early exit if no matching terms at all
        if not matching_terms and not concept_match:
            return None

        # Term coverage penalty / boost
        # Measures what percentage of user's core query terms were matched
        core_matches = [t for t in query.core_terms if t in matching_terms or QueryProcessor.stem(t) in matching_terms]
        core_coverage = len(core_matches) / max(1, len(query.core_terms))

        raw_score = (
            0.35 * name_score +
            0.35 * desc_score +
            0.20 * param_score +
            0.10 * cat_score
        )

        # Composite score blending field weight with query coverage
        # High coverage significantly boosts confidence; low coverage penalizes stray words
        final_score = raw_score * (0.35 + 0.65 * core_coverage)
        final_score = min(1.0, max(0.0, final_score))

        # Missing information analysis
        missing_info: List[str] = []
        if input_comp["missing_required"]:
            missing_info.append(
                f"Missing required parameter(s): {', '.join(input_comp['missing_required'])} "
                f"(not specified in request)"
            )
        for unk in profile.unknown_fields:
            if unk in ("dependencies", "permissions", "limitations"):
                missing_info.append(f"Undeclared {unk} [UNKNOWN evidence]")

        # Fetch trust and policy status independently
        trust_status = "UNVERIFIED"
        policy_decision = None
        attestation_id = profile.evidence_references.get("attestation_id")
        origin_uri = profile.evidence_references.get("source_origin")

        if self.iface_service and profile.source_interface.value:
            iface_urn = profile.source_interface.value
            try:
                dec = self.iface_service.evaluate_policy(iface_urn, self.default_policy)
                trust_status = dec.status
                policy_decision = dec.decision
            except Exception:
                trust_status = profile.evidence_references.get("policy_status", "UNVERIFIED")
        else:
            trust_status = profile.evidence_references.get("policy_status", "UNVERIFIED")

        return ScoredCandidate(
            capability_urn=profile.capability_id,
            display_name=profile.display_name.value,
            description=profile.description.value,
            category=profile.category.value,
            relevance_score=final_score,
            matching_terms=sorted(matching_terms),
            matching_fields={k: v for k, v in matching_fields.items() if v},
            input_compatibility=input_comp,
            evidence_quality=evidence_quality,
            missing_information=missing_info,
            reasons=reasons,
            trust_status=trust_status,
            policy_decision=policy_decision,
            attestation_id=attestation_id,
            origin_uri=origin_uri
        )

    @staticmethod
    def format_cli_output(result: RetrievalResult) -> str:
        """Formats the retrieval result cleanly for CLI presentation."""
        lines = []
        lines.append("=" * 74)
        lines.append(" LIVING CAPABILITY SYSTEM (LCS) — NATURAL LANGUAGE RETRIEVAL")
        lines.append("=" * 74)
        lines.append(f"  User Query:          \"{result.raw_query}\"")
        lines.append(f"  Core Search Terms:   {', '.join(result.processed_query.core_terms) or '(none)'}")
        if result.processed_query.detected_concepts:
            lines.append(f"  Detected Concepts:   {', '.join(sorted(result.processed_query.detected_concepts))}")

        if result.abstained:
            lines.append("\n" + "-" * 74)
            lines.append(f" [ABSTENTION] Result: {result.abstention_code}")
            lines.append("-" * 74)
            lines.append(f"  Reason:              {result.abstention_reason}")
            if result.missing_query_information:
                lines.append(f"  Missing Information: {result.missing_query_information}")
            lines.append("\n  No capability was recommended. Tool execution is prohibited.")
            lines.append("=" * 74)
            return "\n".join(lines)

        lines.append(f"\n  Found {len(result.candidates)} Relevant Candidate(s):")
        lines.append("-" * 74)

        for i, c in enumerate(result.candidates, start=1):
            lines.append(f"\n[{i}] {c.display_name}")
            lines.append(f"    Canonical URN:     {c.capability_urn}")
            lines.append(f"    Relevance Score:   {c.relevance_score:.4f} / 1.0000")
            lines.append(f"    Category:          {c.category}")
            lines.append(f"    Trust / Policy:    {c.trust_status} (Policy: {c.policy_decision or 'EVALUATED'})")
            lines.append(f"    Matched Terms:     {', '.join(c.matching_terms)}")

            # Matching Fields Breakdown
            field_items = [f"{k}: {', '.join(v)}" for k, v in c.matching_fields.items()]
            lines.append(f"    Matched Fields:    {'; '.join(field_items)}")

            # Input Compatibility
            req_params = c.input_compatibility.get("required_parameters", [])
            opt_params = c.input_compatibility.get("optional_parameters", [])
            matched_params = c.input_compatibility.get("matched_parameters", [])
            lines.append(f"    Required Inputs:   {', '.join(req_params) if req_params else '(none)'}")
            if opt_params:
                lines.append(f"    Optional Inputs:   {', '.join(opt_params)}")
            if matched_params:
                lines.append(f"    Inputs Matched:    {', '.join(matched_params)}")

            # Missing Information
            if c.missing_information:
                lines.append("    Missing Info:      " + " | ".join(c.missing_information[:2]))

            # Explanation Reasons
            lines.append("    Matching Reasons:")
            for r in c.reasons:
                lines.append(f"      * {r}")

        lines.append("\n" + "=" * 74)
        lines.append(" Recommendation only. Tool execution is prohibited by LCS security policy.")
        lines.append("=" * 74)
        return "\n".join(lines)
