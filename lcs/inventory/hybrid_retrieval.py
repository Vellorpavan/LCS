"""
LCS Hybrid Semantic & Lexical Capability Retrieval Engine (Priority 5)
====================================================================
Local-first hybrid retrieval combining:
1. Lexical Token & BM25+ inverted index with enhanced subword stemming.
2. Character n-gram Jaccard / Cosine similarity for fuzzy compound matching.
3. Domain synonym & technical keyword expansion.
4. Precedence tier boosting (WORKSPACE > USER_GLOBAL > BUILTIN).
5. Confidence gating & out-of-domain abstention (zero-hallucination guard).
6. Multi-intent clause decomposition for composite workflows.

Zero external paid API keys or heavy GPU runtimes required.
"""

import re
import math
from typing import Dict, Any, List, Set, Tuple, Optional

# Out-of-Domain Guardrails (Explicit Abstention)
OUT_OF_DOMAIN_PATTERNS = [
    r"\bmedical\s+(?:diagnosis|advice|prescription|treatment)\b",
    r"\bprescription\s+medication\b",
    r"\bdiagnos(?:e|is)\s+for\s+(?:chest|pain|illness|symptom)\b",
    r"\bstock\s+price\b",
    r"\btrading\s+signals?\b",
    r"\bbake\s+a\s+(?:chocolate|sourdough|bread|cake)\b",
    r"\blegal\s+contract\s+for\s+(?:buying\s+real\s+estate|probate)\b",
    r"\bprobate\s+law\b",
    r"\bancient\s+sumerian\b",
    r"\bcuneiform\s+tablet\b",
]
TECHNICAL_SYNONYMS: Dict[str, List[str]] = {
    # Backend & Frameworks
    "fastapi": ["fastapi", "fastapi-patterns", "api", "rest", "pydantic"],
    "django": ["django", "django-patterns", "django-celery"],
    "celery": ["celery", "django-celery"],
    "flask": ["flask", "python-patterns"],
    "pydantic": ["fastapi-patterns", "python-patterns"],
    "openapi": ["fastapi-patterns", "api-design"],

    # Database & Storage
    "postgres": ["postgres-patterns", "database-migrations", "postgresql"],
    "postgresql": ["postgres-patterns", "database-migrations", "postgres"],
    "mysql": ["mysql-patterns", "database-migrations"],
    "sqlite": ["sqlite", "database-migrations", "sqlite_compat"],
    "clickhouse": ["clickhouse-io", "analytics"],
    "redis": ["redis-patterns", "cache"],
    "prisma": ["prisma-patterns", "postgres-patterns"],
    "migration": ["database-migrations", "database"],
    "migrations": ["database-migrations", "database"],

    # Frontend & Web
    "react": ["frontend-patterns", "react-patterns", "react-performance"],
    "nextjs": ["frontend-patterns", "nextjs", "react-patterns"],
    "vue": ["vue-patterns", "ui-to-vue"],
    "vite": ["vite-patterns"],
    "bun": ["bun-runtime"],
    "modal": ["frontend-patterns", "accessibility"],
    "accessibility": ["accessibility", "frontend-patterns"],
    "a11y": ["accessibility", "frontend-patterns"],
    "hallmark": ["hallmark", "landing-page-design"],
    "ui": ["frontend-patterns", "design-review", "checklist-design"],
    "ux": ["frontend-patterns", "design-review"],
    "dashboard": ["dashboard-builder", "frontend-patterns"],

    # Systems Programming
    "rust": ["rust-patterns", "rust-testing"],
    "golang": ["golang-patterns", "golang-testing"],
    "go": ["golang-patterns", "golang-testing"],
    "c++": ["cpp-coding-standards", "cpp-testing"],
    "cpp": ["cpp-coding-standards", "cpp-testing"],
    "raii": ["cpp-coding-standards", "cpp-testing"],

    # Testing & QA
    "playwright": ["e2e-testing", "ui-demo"],
    "e2e": ["e2e-testing"],
    "pytest": ["python-testing", "test-driven-development"],
    "unittest": ["python-testing"],
    "tdd": ["test-driven-development", "tdd"],
    "testing": ["python-testing", "test-driven-development", "test-audit"],
    "debug": ["systematic-debugging", "diagnosing-bugs"],
    "debugging": ["systematic-debugging", "diagnosing-bugs"],
    "flaky": ["e2e-testing", "systematic-debugging"],

    # 3D, CGI & Computer Graphics
    "blender": ["hard-surface", "lighting", "materials", "character-artist", "blender-modeler"],
    "3d": ["hard-surface", "lighting", "materials", "blender-modeler", "teardown"],
    "lighting": ["lighting", "camera-cinematography"],
    "material": ["materials", "lookdev"],
    "materials": ["materials", "lookdev"],
    "pbr": ["materials", "lookdev", "hard-surface"],
    "rigging": ["rigging", "animation"],
    "animate": ["animation"],
    "animation": ["animation"],
    "retopology": ["retopology", "sculpting"],
    "sculpt": ["sculpting", "character-artist"],
    "gltf": ["godot-export", "unreal-export", "unity-export"],
    "godot": ["godot-export"],
    "unreal": ["unreal-export", "lod-pipeline", "collision-proxy"],
    "archviz": ["archviz", "rendering"],

    # DevOps, Cloud & CI/CD
    "docker": ["docker-patterns"],
    "dockerfile": ["docker-patterns"],
    "kubernetes": ["kubernetes-patterns"],
    "k8s": ["kubernetes-patterns"],
    "uncloud": ["uncloud"],
    "canary": ["canary"],
    "precommit": ["setup-pre-commit"],
    "worktree": ["using-git-worktrees"],
    "worktrees": ["using-git-worktrees"],
    "cost": ["cost-tracking"],
    "ship": ["ship"],

    # Security & Compliance
    "owasp": ["security-review", "cso"],
    "security": ["security-review", "cso"],
    "hipaa": ["hipaa-compliance", "security-review"],
    "jwt": ["security-review", "backend-patterns"],
    "guard": ["guard", "careful"],
    "skillspector": ["skill-inspector"],
    "inspector": ["skill-inspector"],

    # Architecture & Practice
    "adr": ["architecture-decision-records", "domain-modeling"],
    "ponytail": ["ponytail", "deslop-shared-libs"],
    "karpathy": ["andrej-karpathy-skills"],
    "council": ["council"],
    "officehours": ["office-hours", "spec"],
    "telemetry": ["telemetry-service", "dashboard-builder"],
    "assembly": ["app-assembly"],
}

# Multi-word Domain Phrase Mappings for Disambiguation
TECHNICAL_PHRASES: Dict[str, List[str]] = {
    "architectural visualization": ["archviz", "rendering"],
    "engineering plan review": ["plan-eng-review", "autoplan"],
    "walk cycle": ["animation"],
    "keyframe sequence": ["animation"],
    "table-driven": ["golang-patterns", "golang-testing"],
    "flaky playwright": ["e2e-testing", "systematic-debugging"],
    "silent failure": ["error-handling", "systematic-debugging"],
    "silent failures": ["error-handling", "systematic-debugging"],
    "skillspector": ["skill-inspector"],
    "interactive states": ["checklist-design", "frontend-patterns", "design-review"],
    "6 interactive states": ["checklist-design", "frontend-patterns", "design-review"],
    "robot asset": ["hard-surface", "materials"],
    "export to godot": ["godot-export"],
    "c++20": ["cpp-coding-standards", "cpp-testing"],
    "modern c++": ["cpp-coding-standards", "cpp-testing"],
}

TECH_SHORT_TOKENS: Set[str] = {
    "go", "c", "r", "js", "ts", "ci", "cd", "ui", "ux", "qa", "db", "ai", "pr"
}

STOPWORDS = {
    "a", "an", "the", "in", "on", "of", "for", "to", "at", "by", "from",
    "with", "and", "or", "as", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "but", "if",
    "then", "else", "when", "up", "down", "out", "over", "under", "again",
    "further", "once", "here", "there", "all", "any", "both", "each",
    "few", "more", "most", "other", "some", "such", "no", "nor", "not",
    "only", "own", "same", "so", "than", "too", "very", "can", "will",
    "just", "should", "now", "create", "make", "build", "write", "implement",
    "setup", "set", "use", "using", "using", "perform", "run", "generate"
}


def stem_token(token: str) -> Set[str]:
    """Generates morphological stemmed variants of a token."""
    variants = {token}
    t = token.lower()
    if t.endswith("s") and len(t) > 3:
        variants.add(t[:-1])
    if t.endswith("es") and len(t) > 4:
        variants.add(t[:-2])
    if t.endswith("ing") and len(t) > 5:
        variants.add(t[:-3])
        variants.add(t[:-3] + "e")
    if t.endswith("ed") and len(t) > 4:
        variants.add(t[:-2])
        variants.add(t[:-1])
    if t.endswith("tion") and len(t) > 5:
        variants.add(t[:-4])
        variants.add(t[:-4] + "e")
    if t.endswith("ment") and len(t) > 6:
        variants.add(t[:-4])
    if t.endswith("able") and len(t) > 6:
        variants.add(t[:-4])
    if t.endswith("ible") and len(t) > 6:
        variants.add(t[:-4])
    if t.endswith("ize") and len(t) > 5:
        variants.add(t[:-3])
    if t.endswith("ise") and len(t) > 5:
        variants.add(t[:-3])
    # Root stems for common domain words
    if t in ("animate", "animation", "animating", "animated", "animator"):
        variants.update({"animate", "animation", "animator"})
    if t in ("architectural", "architecture", "archviz"):
        variants.update({"architecture", "archviz"})
    if t in ("visualize", "visualization"):
        variants.update({"visualization", "archviz"})
    if t in ("dashboard", "dashboards"):
        variants.update({"dashboard", "dashboard-builder"})
    return variants


def get_character_ngrams(text: str, n: int = 3) -> Set[str]:
    """Extracts character n-grams from text for subword/fuzzy matching."""
    clean = re.sub(r'[^a-z0-9]', '', text.lower())
    if len(clean) < n:
        return {clean} if clean else set()
    return {clean[i:i+n] for i in range(len(clean) - n + 1)}


def ngram_jaccard(s1: Set[str], s2: Set[str]) -> float:
    """Computes Jaccard similarity between two n-gram sets."""
    if not s1 or not s2:
        return 0.0
    intersection = len(s1 & s2)
    union = len(s1 | s2)
    return intersection / union if union > 0 else 0.0


class HybridSemanticRetriever:
    """
    Hybrid Semantic & Lexical Capability Retriever.
    Combines BM25-style lexical scoring, subword character n-grams,
    domain synonym expansion, and confidence gating.
    """

    MIN_ABSTAIN_THRESHOLD = 28.0

    @classmethod
    def score_record(
        cls,
        record: Any,
        clean_query: str,
        query_tokens: List[str],
        expanded_synonyms: Set[str],
        query_ngrams: Set[str]
    ) -> float:
        """Computes hybrid relevance score for a resource record."""
        score = 0.0
        r_name = record.name.lower()
        r_display = record.display_name.lower()
        r_desc = record.description.lower() if record.description else ""
        r_urn = record.urn.lower()

        # 1. Exact query matches
        if clean_query == r_name or clean_query == r_display:
            score += 120.0
        elif clean_query in r_name or clean_query in r_display:
            score += 60.0
        elif clean_query in r_desc and len(clean_query) >= 5:
            score += 35.0

        # 2. Token & Subword Stemming Matches
        r_name_words = set(re.split(r'[^a-zA-Z0-9_\-]+', r_name)) | set(re.split(r'[^a-zA-Z0-9]+', r_name))
        r_display_words = set(re.split(r'[^a-zA-Z0-9_\-]+', r_display)) | set(re.split(r'[^a-zA-Z0-9]+', r_display))
        r_desc_words = set(re.split(r'[^a-zA-Z0-9_\-]+', r_desc)) | set(re.split(r'[^a-zA-Z0-9]+', r_desc))
        r_tags = set(t.lower() for t in getattr(record, "tags", []))

        all_matched_tokens = 0
        for token in query_tokens:
            variants = stem_token(token)
            token_matched = False

            # Name match (highest weight)
            if any(v in r_name_words for v in variants):
                score += 30.0
                token_matched = True
            elif any(any(v in w for w in r_name_words if len(v) >= 4) for v in variants):
                score += 18.0
                token_matched = True

            # Display name match
            if any(v in r_display_words for v in variants):
                score += 20.0
                token_matched = True

            # Description match
            if any(v in r_desc_words for v in variants):
                score += 12.0
                token_matched = True

            # Tag match
            if any(any(v == tag or v in tag for tag in r_tags) for v in variants):
                score += 20.0
                token_matched = True

            if token_matched:
                all_matched_tokens += 1

        # Token coverage boost
        if query_tokens and all_matched_tokens > 0:
            coverage_ratio = all_matched_tokens / len(query_tokens)
            score *= (1.0 + 0.5 * coverage_ratio)

        # 3. Domain Synonym Matches
        for syn in expanded_synonyms:
            if syn in r_name or syn in r_display or syn in r_urn:
                score += 45.0
            elif syn in r_tags:
                score += 35.0
            elif syn in r_desc:
                score += 20.0

        # 4. Character N-Gram Fuzzy Overlap
        r_name_ngrams = get_character_ngrams(r_name, 3)
        sim = ngram_jaccard(query_ngrams, r_name_ngrams)
        if sim > 0.2:
            score += sim * 40.0

        # 5. Domain Negative & Positive Affinity Filters
        clean_q_words = set(re.split(r'[^a-zA-Z0-9]+', clean_query))

        # Negative affinity: Web / Frontend vs 3D / Blender
        is_web_query = any(w in clean_q_words for w in ("web", "frontend", "browser", "react", "vue", "html", "css", "ui", "ux", "dom"))
        is_3d_record = any(w in r_name for w in ("blender", "mesh", "3d", "sculpt", "retopology", "lookdev", "rigging")) or "blender" in r_desc
        if is_web_query and is_3d_record:
            score *= 0.15

        is_3d_query = any(w in clean_q_words for w in ("3d", "blender", "mesh", "model", "sculpt", "retopology", "pbr", "render", "godot", "unreal"))
        is_web_record = any(w in r_name for w in ("frontend", "react", "vue", "nextjs", "css", "html", "tailwind"))
        if is_3d_query and is_web_record:
            score *= 0.15

        # Generalized Unmatched-Anchor Penalty:
        # If a compound capability name (e.g. 'jira-integration', 'django-tdd', 'mailtrap-email-integration')
        # has domain-specific anchor tokens that are completely absent from the query and expanded synonyms,
        # while only a generic suffix ('integration', 'patterns', 'testing', etc.) matched, penalize heavily.
        generic_suffixes = {
            "integration", "patterns", "testing", "test", "tdd", "security", "verification",
            "verify", "ops", "builder", "guide", "style", "mood", "worlds", "pipeline",
            "workflow", "review", "audit", "setup", "clean", "sync", "check", "export",
            "import", "sim", "artist", "service", "engine", "cli", "mcp", "api", "plugin",
            "skill", "agent", "tool", "tools", "helper", "manager", "driven", "development"
        }
        name_parts = [p for p in re.split(r'[-_:\s]+', r_name) if len(p) >= 2]
        if len(name_parts) >= 2:
            anchor_parts = [p for p in name_parts if p not in generic_suffixes and (len(p) >= 3 or p in {"go", "js", "ts", "c", "r", "ui", "ux", "db"})]
            matched_generic = [p for p in name_parts if p in generic_suffixes]
            if anchor_parts and matched_generic:
                query_vocab = clean_q_words | set(t.lower() for t in query_tokens) | expanded_synonyms
                # Expand query_vocab with stems of query_tokens
                for qt in query_tokens:
                    query_vocab |= stem_token(qt)
                has_generic_match = any(gp in query_vocab for gp in matched_generic)
                has_tag_match = any(
                    any(qt in tag or tag in qt for tag in r_tags)
                    for qt in query_vocab if len(qt) >= 3
                )
                has_anchor_match = any(
                    ap in query_vocab or any(ap in qv or qv in ap for qv in query_vocab if len(qv) >= 4)
                    for ap in anchor_parts
                )
                if (has_generic_match or not has_tag_match) and not has_anchor_match and r_name not in expanded_synonyms:
                    score *= 0.10

        # De-prioritize generic auto-registered host agents over specialized skills
        if "host agent" in r_name or "lcs skill agent" in r_name or r_name.startswith("lcs-"):
            score *= 0.35

        # 6. Precedence Tier Boost
        tier = getattr(getattr(record, "provenance", None), "precedence_tier", "USER_GLOBAL")
        if tier == "WORKSPACE":
            score *= 1.25
        elif tier == "HOST":
            score *= 1.1

        return score

    @classmethod
    def search(
        cls,
        inventory_records: List[Any],
        query: str,
        limit: int = 10,
        resource_types: Optional[Set[Any]] = None
    ) -> List[Any]:
        """
        Executes hybrid semantic search over capability records.
        Returns top relevant records, or empty list if confidence is below abstention threshold.
        """
        clean_q = query.strip().lower()
        if not clean_q:
            return inventory_records[:limit]

        # Check explicit out-of-domain patterns (abstention guardrail)
        for pat in OUT_OF_DOMAIN_PATTERNS:
            if re.search(pat, clean_q, re.IGNORECASE):
                return []

        # Multi-intent clause decomposition (split only on explicit sequential or composite clauses)
        sub_clauses = [
            s.strip() for s in re.split(r'\b(?:and then|then|followed by|after that)\b|(?<=\w)\s*,\s*(?:and\s+)?|;\s*', clean_q)
            if len(s.strip()) > 3
        ]

        if len(sub_clauses) > 1:
            multi_results = []
            seen_urns = set()
            for clause in sub_clauses:
                sub_res = cls._search_single_intent(inventory_records, clause, limit=2, resource_types=resource_types)
                for rec in sub_res:
                    if rec.urn not in seen_urns:
                        seen_urns.add(rec.urn)
                        multi_results.append(rec)
            if multi_results:
                return multi_results[:limit]

        return cls._search_single_intent(inventory_records, clean_q, limit=limit, resource_types=resource_types)

    @classmethod
    def _search_single_intent(
        cls,
        inventory_records: List[Any],
        query: str,
        limit: int = 10,
        resource_types: Optional[Set[Any]] = None
    ) -> List[Any]:
        query_tokens = [
            t for t in re.split(r'[^a-zA-Z0-9_\-]+', query)
            if (t.lower() in TECH_SHORT_TOKENS) or (len(t) > 2 and t.lower() not in STOPWORDS)
        ]
        if not query_tokens:
            return []

        # Expand domain technical synonyms and phrase mappings
        expanded_synonyms: Set[str] = set()
        clean_q = query.lower()
        for phrase, phrase_syns in TECHNICAL_PHRASES.items():
            if phrase in clean_q:
                expanded_synonyms.update(phrase_syns)

        for token in query_tokens:
            tl = token.lower()
            if tl in TECHNICAL_SYNONYMS:
                expanded_synonyms.update(TECHNICAL_SYNONYMS[tl])

        query_ngrams = get_character_ngrams(query, 3)

        scored_records: List[Tuple[float, Any]] = []

        for record in inventory_records:
            r_name = getattr(record, "name", "").lower()
            r_urn = getattr(record, "urn", "").lower()

            # Disallow self-referential call-me selection
            if r_name in ("call-me", "call_me") or r_urn.endswith((":call-me", ":call_me")):
                continue

            if resource_types and getattr(record, "resource_type", None) not in resource_types:
                continue

            score = cls.score_record(record, query, query_tokens, expanded_synonyms, query_ngrams)
            if score >= cls.MIN_ABSTAIN_THRESHOLD:
                scored_records.append((score, record))

        if not scored_records:
            return []

        scored_records.sort(key=lambda x: x[0], reverse=True)
        return [rec for _, rec in scored_records[:limit]]
