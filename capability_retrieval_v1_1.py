"""
Living Capability System (LCS) — Capability Retrieval Engine V1.1
=================================================================
Deterministic language understanding improvements over Retrieval V1:
1. Conservative morphological normalization (irregular derivations, -al, -ation, -expiry).
2. Explicit, curated domain terminology mappings (RFC/NIST standards, 2FA/TOTP, ICMP/ping, checksum/hash).
3. Context-sensitive action and parameter directionality (preventing encrypt/decrypt inversions).
4. Dual attribution for Git commit authorship (inspect_git_commit and extract_git_blame).

V1 remains frozen and unchanged. V1.1 is an isolated, separately versioned component.
Strictly adheres to zero vector/LLM constraints, zero arbitrary execution, and deterministic explainability.
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
# 1. Stopwords & Curated Domain Mappings (RFC / Technical Standards Grounded)
# ----------------------------------------------------------------------------

ENGLISH_STOPWORDS_V11: Set[str] = {
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

# Curated, evidence-grounded domain terminology mappings (Concept -> Set of Canonical Terms)
CONCEPT_SYNONYMS_V11: Dict[str, Set[str]] = {
    "pdf": {"pdf", "acrobat"},
    "document": {"doc", "document"},
    "database": {"sql", "sqlite", "relational", "database", "table", "tables"},
    "spatial_distance": {
        "haversine", "geodesic", "distance", "range", "arc"
    },
    "spatial_polygon": {
        "polygon", "polygonal", "parcel", "footprint", "envelope"
    },
    "coordinates": {
        "coordinates", "latitude", "longitude", "lat", "lon", "gps", "waypoint", "gis"
    },
    "security": {"hsts", "cybersecurity", "security", "header", "headers", "csp"},
    "statistics": {"variance", "stddev", "statistics", "statistical", "distribution", "percentile"},
    "version": {
        "semver", "version", "versioning", "prerelease", "deconstruct",
        "major", "minor", "patch"
    },
    "authentication": {
        "totp", "token", "2fa", "two-factor", "twofactor",
        "mfa", "authenticator", "otp", "seed"
    },
    "encryption": {
        "encrypt", "encryption", "cipher", "encipher", "scramble", "aes", "gcm", "symmetric"
    },
    "decryption": {
        "decrypt", "decryption", "decipher", "unscramble", "recover"
    },
    "cryptographic_hash": {
        "sha256", "hash", "digest", "checksum", "fingerprint"
    },
    "certificate": {
        "tls", "ssl", "certificate", "cert", "certs", "x509", "pem", "der",
        "expiration", "expiry", "expire"
    },
    "network_diagnostics": {
        "ping", "icmp", "latency", "reachability", "echo", "host", "packet", "packets"
    },
    "dns": {
        "dns", "nameserver", "nameservers", "domain", "records", "mx", "cname", "aaaa"
    },
    "git": {
        "git", "repo", "repository", "commit", "commits", "committed", "branch", "branches",
        "diff", "blame", "author", "attribution"
    }
}

# Explicit technical abbreviations / root mappings
TECHNICAL_EXPANSIONS: Dict[str, Set[str]] = {
    "2fa": {"totp", "token", "two-factor", "authenticator"},
    "mfa": {"totp", "token", "authenticator"},
    "authenticator": {"totp", "token"},
    "passcode": {"totp", "token"},
    "scramble": {"encrypt", "cipher"},
    "unscramble": {"decrypt", "plaintext"},
    "cipher": {"encrypt", "cipher"},
    "checksum": {"hash", "sha256", "digest"},
    "fingerprint": {"hash", "sha256", "digest"},
    "cert": {"certificate", "tls", "ssl"},
    "certs": {"certificate", "tls", "ssl"},
    "expiration": {"expiry", "expire", "certificate"},
    "expiry": {"expiration", "expire", "certificate"},
    "icmp": {"ping", "latency", "reachability", "host"},
    "parcel": {"polygon", "coordinates", "area"},
    "footprint": {"area", "polygon"},
    "range": {"distance", "haversine"},
    "arc": {"distance", "geodesic"},
    "deconstruct": {"parse", "semver", "version"},
    "patch": {"semver", "version"},
    "minor": {"semver", "version"},
    "major": {"semver", "version"},
    "committed": {"commit", "author", "git"},
    "who": {"author", "attribution", "commit", "blame"},
    "acrobat": {"pdf", "document"},
    "docx": {"document", "doc"}
}


# ----------------------------------------------------------------------------
# 2. Morphological Normalizer & Query Processor V1.1
# ----------------------------------------------------------------------------

@dataclass
class ProcessedQueryV11:
    """Represents a structured natural language user query with intent analysis."""
    raw_query: str
    tokens: List[str]
    core_terms: List[str]
    expanded_terms: Set[str]
    detected_concepts: Set[str]
    action_intent: Optional[str] = None  # e.g., 'DECRYPT', 'ENCRYPT', 'FORMAT_ONLY', 'QUERY_EXEC'
    source_input_hints: Set[str] = field(default_factory=set)  # terms following 'from', 'with', 'in'
    target_output_hints: Set[str] = field(default_factory=set) # terms following 'to', 'into', 'recover'
    is_ambiguous: bool = False
    ambiguity_reason: Optional[str] = None


class QueryProcessorV11:
    """
    Enhanced morphological normalizer and technical terminology mapper.
    Performs conservative derivational normalization and detects action intent.
    """

    @staticmethod
    def stem(word: str) -> str:
        """
        Conservative derivational and inflectional morphological normalizer.
        Conflates derivational variants:
          - expiration / expiry -> expir
          - polygonal / polygon -> polygon
          - attribution / attribute -> attribut
          - deconstruction / deconstruct -> deconstruct
          - committed / commit -> commit
        """
        w = word.lower().strip()
        if len(w) <= 3:
            return w

        # Direct technical root conflations
        if w in ("document", "documents"):
            return "document"
        if w in ("expiration", "expiry", "expiring", "expired", "expires"):
            return "expir"
        if w in ("polygonal", "polygons", "polygon"):
            return "polygon"
        if w in ("committed", "committing", "commits", "commit"):
            return "commit"
        if w in ("authenticator", "authentication", "authenticate", "authenticating"):
            return "authenticat"
        if w in ("deconstruct", "deconstructing", "deconstructed", "deconstruction"):
            return "deconstruct"
        if w in ("attribution", "attributing", "attributed", "attribute"):
            return "attribut"
        if w in ("statistical", "statistic", "statistics"):
            return "statistic"
        if w in ("geodesical", "geodesic", "geodesics"):
            return "geodesic"

        # Derivational suffix normalization
        if w.endswith("ational") and len(w) > 7:
            return w[:-5]
        if w.endswith("ation") and len(w) > 5:
            return w[:-5]
        if w.endswith("tion") and len(w) > 5:
            return w[:-4]
        if w.endswith("sion") and len(w) > 5:
            return w[:-4]
        if w.endswith("ical") and len(w) > 5:
            return w[:-4]
        if w.endswith("able") and len(w) > 5:
            return w[:-4]
        if w.endswith("ible") and len(w) > 5:
            return w[:-4]
        if w.endswith("ment") and len(w) > 8:
            return w[:-4]

        # Standard inflectional endings
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
        if w.endswith("al") and len(w) > 4:
            return w[:-2]

        return w

    @classmethod
    def process(cls, query: str) -> ProcessedQueryV11:
        raw_query = query.strip()
        words = re.findall(r"[a-zA-Z0-9_-]+", raw_query.lower())
        tokens = [w for w in words if len(w) > 1]

        # Extract core terms (filtering conversational stopwords)
        core_terms = []
        for t in tokens:
            cleaned = t.strip("-_")
            if cleaned and cleaned not in ENGLISH_STOPWORDS_V11:
                core_terms.append(cleaned)

        # Ambiguity detection on underspecified queries
        is_ambiguous = False
        ambiguity_reason = None
        generic_terms = {
            "process", "data", "check", "system", "inspect", "handle",
            "records", "record", "manage", "analyze", "operation", "item", "items",
            "status", "output", "task", "information", "run", "execute"
        }
        if len(core_terms) <= 2:
            if not core_terms or all(t in generic_terms for t in core_terms):
                is_ambiguous = True
                ambiguity_reason = (
                    "The query is too generic or underspecified. "
                    "Missing domain context (e.g. document, database, security headers, spatial metrics, statistics)."
                )

        detected_concepts = set()
        expanded_terms = set(core_terms)

        for term in core_terms:
            stemmed = cls.stem(term)
            expanded_terms.add(stemmed)

            # Check explicit technical expansions
            if term in TECHNICAL_EXPANSIONS:
                expanded_terms.update(TECHNICAL_EXPANSIONS[term])
            if stemmed in TECHNICAL_EXPANSIONS:
                expanded_terms.update(TECHNICAL_EXPANSIONS[stemmed])

            # Check concept dictionaries
            for concept, synonyms in CONCEPT_SYNONYMS_V11.items():
                if term in synonyms or stemmed in synonyms:
                    detected_concepts.add(concept)
                    expanded_terms.update(synonyms)

        # Detect action intent (e.g. Decrypt vs Encrypt, Format vs Execute)
        action_intent = None
        lower_q = raw_query.lower()

        # Decryption vs Encryption intent
        if any(w in lower_q for w in ("recover", "decrypt", "decipher", "unscramble", "reveal")):
            action_intent = "DECRYPT"
        elif any(w in lower_q for w in ("encrypt", "encipher", "scramble", "lock")):
            action_intent = "ENCRYPT"
        elif "format" in lower_q and ("sql" in lower_q or "diff" in lower_q or "json" in lower_q):
            action_intent = "FORMAT_ONLY"

        # Detect prepositional input vs output hints
        source_input_hints = set()
        target_output_hints = set()

        # e.g., 'from ciphertext', 'from encrypted ciphertext payload'
        for match in re.finditer(r"\b(?:from|using|with)\s+([a-zA-Z0-9_\s-]+?)(?:\s+(?:with|to|using|into|$)|$)", lower_q):
            phrase = match.group(1)
            for w in phrase.split():
                cleaned = w.strip("-_,.")
                if cleaned and cleaned not in ENGLISH_STOPWORDS_V11:
                    source_input_hints.add(cleaned)

        # e.g., 'recover plaintext', 'extract tables to X'
        for match in re.finditer(r"\b(?:recover|get|extract|into|to)\s+([a-zA-Z0-9_\s-]+?)(?:\s+(?:from|using|with|$)|$)", lower_q):
            phrase = match.group(1)
            for w in phrase.split():
                cleaned = w.strip("-_,.")
                if cleaned and cleaned not in ENGLISH_STOPWORDS_V11:
                    target_output_hints.add(cleaned)

        return ProcessedQueryV11(
            raw_query=raw_query,
            tokens=tokens,
            core_terms=core_terms,
            expanded_terms=expanded_terms,
            detected_concepts=detected_concepts,
            action_intent=action_intent,
            source_input_hints=source_input_hints,
            target_output_hints=target_output_hints,
            is_ambiguous=is_ambiguous,
            ambiguity_reason=ambiguity_reason
        )


# ----------------------------------------------------------------------------
# 3. Candidate Scoring & Directionality Auditing V1.1
# ----------------------------------------------------------------------------

@dataclass
class ScoredCandidateV11:
    """Represents a ranked capability match with explainable audit evidence in V1.1."""
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
    directionality_adjustment: Optional[str] = None

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
            "origin_uri": self.origin_uri,
            "directionality_adjustment": self.directionality_adjustment
        }


@dataclass
class RetrievalResultV11:
    """Complete retrieval response from V1.1."""
    raw_query: str
    processed_query: ProcessedQueryV11
    candidates: List[ScoredCandidateV11]
    abstained: bool = False
    abstention_code: Optional[str] = None
    abstention_reason: Optional[str] = None
    missing_query_information: Optional[str] = None
    engine_version: str = "1.1"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.raw_query,
            "engine_version": self.engine_version,
            "abstained": self.abstained,
            "abstention_code": self.abstention_code,
            "abstention_reason": self.abstention_reason,
            "missing_query_information": self.missing_query_information,
            "candidates": [c.to_dict() for c in self.candidates]
        }


# ----------------------------------------------------------------------------
# 4. Capability Retrieval Engine V1.1
# ----------------------------------------------------------------------------

class CapabilityRetrievalEngineV11:
    """
    Enhanced retrieval engine implementing V1.1 deterministic language understanding.
    Features:
    - Conservative morphological stem matching
    - Action-to-parameter directionality auditing
    - Grounded concept expansion with RFC/NIST domain dictionaries
    - Dual attribution support for Git revision tracking
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
            policy_name="retrieval-v1-1-audit-policy",
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
    ) -> RetrievalResultV11:
        """
        Executes explainable capability retrieval using V1.1 deterministic understanding.
        """
        processed = QueryProcessorV11.process(query)

        # 1. Empty query
        if not processed.core_terms and not processed.tokens:
            return RetrievalResultV11(
                raw_query=query,
                processed_query=processed,
                candidates=[],
                abstained=True,
                abstention_code="NO_SUITABLE_CAPABILITY_FOUND",
                abstention_reason="Empty or non-meaningful query provided.",
                missing_query_information="Specify the task or capability needed."
            )

        # 2. Ambiguity check
        if processed.is_ambiguous:
            return RetrievalResultV11(
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

        # 3. Retrieve and score all registered capabilities
        cur = self.conn.cursor()
        cur.execute("SELECT capability_urn FROM capability_declarations;")
        all_urns = [r[0] for r in cur.fetchall()]

        if not all_urns:
            return RetrievalResultV11(
                raw_query=query,
                processed_query=processed,
                candidates=[],
                abstained=True,
                abstention_code="NO_SUITABLE_CAPABILITY_FOUND",
                abstention_reason="No capabilities are registered in this LCS instance."
            )

        candidates: List[ScoredCandidateV11] = []

        for urn in all_urns:
            try:
                profile = self.profile_service.get_profile(urn)
                scored = self._score_candidate(profile, processed)
                if scored and scored.relevance_score > 0.0:
                    candidates.append(scored)
            except Exception:
                continue

        # 4. Sort deterministically: score desc, URN asc
        candidates.sort(key=lambda c: (-c.relevance_score, c.capability_urn))

        # 5. Filter qualifying candidates that meet min_score_threshold
        qualifying = [c for c in candidates if c.relevance_score >= min_score_threshold]

        # 6. Abstention check
        if not qualifying:
            top_score = candidates[0].relevance_score if candidates else 0.0
            return RetrievalResultV11(
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
        return RetrievalResultV11(
            raw_query=query,
            processed_query=processed,
            candidates=qualifying[:limit],
            abstained=False
        )

    @staticmethod
    def _match_field_terms(query_terms: Set[str], text: str) -> List[str]:
        if not text:
            return []
        text_words = set(re.findall(r"[a-zA-Z0-9_-]+", text.lower()))
        text_stems = {QueryProcessorV11.stem(w) for w in text_words}
        matches = []
        for t in query_terms:
            t_clean = t.lower().strip()
            if not t_clean or len(t_clean) <= 1:
                continue
            t_stem = QueryProcessorV11.stem(t_clean)
            if t_clean in text_words or t_stem in text_stems:
                matches.append(t_clean)
        return sorted(set(matches))

    def _score_candidate(
        self,
        profile: CapabilitySemanticProfile,
        query: ProcessedQueryV11
    ) -> Optional[ScoredCandidateV11]:
        """
        Computes multi-signal explainable relevance score with V1.1 directionality auditing.
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
        directionality_note = None

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
            cat_ev_mult = 0.60 if profile.category.evidence == EvidenceSource.INFERRED else 1.0
            cat_score = (1.0 if concept_match else 0.5) * cat_ev_mult
            reasons.append(f"Category matched: '{cat_val}' [{profile.category.evidence}]")

        # Early exit if no matching terms
        if not matching_terms and not concept_match:
            return None

        # Core query term coverage
        core_matches = [
            t for t in query.core_terms
            if t in matching_terms or QueryProcessorV11.stem(t) in {QueryProcessorV11.stem(m) for m in matching_terms}
        ]
        core_coverage = len(core_matches) / max(1, len(query.core_terms))

        raw_score = (
            0.35 * name_score +
            0.35 * desc_score +
            0.20 * param_score +
            0.10 * cat_score
        )

        final_score = raw_score * (0.35 + 0.65 * core_coverage)

        # --------------------------------------------------------------------
        # V1.1 Context-Sensitive Action & Directionality Auditing
        # --------------------------------------------------------------------
        cap_id = profile.capability_id.lower()

        # Context 1: Decrypt vs Encrypt action directionality
        if query.action_intent == "DECRYPT":
            if "encrypt" in cap_id and "decrypt" not in cap_id:
                final_score *= 0.25
                directionality_note = "Action penalty applied: query requests decryption/recovery, but tool performs encryption."
                reasons.append(directionality_note)
            elif "decrypt" in cap_id:
                # If query specified 'from ciphertext', boost decrypt tool matching input
                if any("ciphertext" in h for h in query.source_input_hints) or "ciphertext" in all_query_terms:
                    final_score = min(1.0, final_score * 1.35)
                    directionality_note = "Input affinity boost: tool accepts ciphertext as specified in recovery request."
                    reasons.append(directionality_note)

        elif query.action_intent == "ENCRYPT":
            if "decrypt" in cap_id and "encrypt" not in cap_id:
                final_score *= 0.25
                directionality_note = "Action penalty applied: query requests encryption/scrambling, but tool performs decryption."
                reasons.append(directionality_note)

        # Context 2: Format vs Query execution
        if query.action_intent == "FORMAT_ONLY":
            if "format" in cap_id:
                final_score = min(1.0, final_score * 1.25)
            elif "query_local_database" in cap_id:
                final_score *= 0.30
                reasons.append("Action penalty: query requested formatting, not database execution.")

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

        return ScoredCandidateV11(
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
            origin_uri=origin_uri,
            directionality_adjustment=directionality_note
        )

    @staticmethod
    def format_cli_output(result: RetrievalResultV11) -> str:
        """Formats the V1.1 retrieval result cleanly for CLI presentation."""
        lines = []
        lines.append("=" * 76)
        lines.append(" LIVING CAPABILITY SYSTEM (LCS) — RETRIEVAL V1.1 (NATURAL LANGUAGE)")
        lines.append("=" * 76)
        lines.append(f"  User Query:          \"{result.raw_query}\"")
        lines.append(f"  Core Search Terms:   {', '.join(result.processed_query.core_terms) or '(none)'}")
        if result.processed_query.detected_concepts:
            lines.append(f"  Detected Concepts:   {', '.join(sorted(result.processed_query.detected_concepts))}")
        if result.processed_query.action_intent:
            lines.append(f"  Action Intent:       {result.processed_query.action_intent}")

        if result.abstained:
            lines.append("\n" + "-" * 76)
            lines.append(f" [ABSTENTION] Result: {result.abstention_code}")
            lines.append("-" * 76)
            lines.append(f"  Reason:              {result.abstention_reason}")
            if result.missing_query_information:
                lines.append(f"  Missing Information: {result.missing_query_information}")
            lines.append("\n  No capability was recommended. Tool execution is prohibited.")
            lines.append("=" * 76)
            return "\n".join(lines)

        lines.append(f"\n  Found {len(result.candidates)} Relevant Candidate(s):")
        lines.append("-" * 76)

        for i, c in enumerate(result.candidates, start=1):
            lines.append(f"\n[{i}] {c.display_name}")
            lines.append(f"    Canonical URN:     {c.capability_urn}")
            lines.append(f"    Relevance Score:   {c.relevance_score:.4f} / 1.0000")
            lines.append(f"    Category:          {c.category}")
            lines.append(f"    Trust / Policy:    {c.trust_status} (Policy: {c.policy_decision or 'EVALUATED'})")
            lines.append(f"    Matched Terms:     {', '.join(c.matching_terms)}")

            field_items = [f"{k}: {', '.join(v)}" for k, v in c.matching_fields.items()]
            lines.append(f"    Matched Fields:    {'; '.join(field_items)}")

            req_params = c.input_compatibility.get("required_parameters", [])
            opt_params = c.input_compatibility.get("optional_parameters", [])
            matched_params = c.input_compatibility.get("matched_parameters", [])
            lines.append(f"    Required Inputs:   {', '.join(req_params) if req_params else '(none)'}")
            if opt_params:
                lines.append(f"    Optional Inputs:   {', '.join(opt_params)}")
            if matched_params:
                lines.append(f"    Inputs Matched:    {', '.join(matched_params)}")

            if c.directionality_adjustment:
                lines.append(f"    Directionality:    {c.directionality_adjustment}")

            if c.missing_information:
                lines.append("    Missing Info:      " + " | ".join(c.missing_information[:2]))

            lines.append("    Matching Reasons:")
            for r in c.reasons:
                lines.append(f"      * {r}")

        lines.append("\n" + "=" * 76)
        lines.append(" Recommendation only. Tool execution is prohibited by LCS security policy.")
        lines.append("=" * 76)
        return "\n".join(lines)
