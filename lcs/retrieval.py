"""
LCS Capability Retrieval Package Wrapper
========================================
Exposes the capability intelligence retrieval engine and query processing components
for both Retrieval V1 (frozen baseline) and Retrieval V1.1 (deterministic language understanding).
"""

from capability_retrieval_v1 import (
    ENGLISH_STOPWORDS,
    CONCEPT_SYNONYMS,
    ProcessedQuery,
    QueryProcessor,
    ScoredCandidate,
    RetrievalResult,
    CapabilityRetrievalEngine,
    CapabilityRetrievalEngine as CapabilityRetrievalEngineV1
)

from capability_retrieval_v1_1 import (
    ENGLISH_STOPWORDS_V11,
    CONCEPT_SYNONYMS_V11,
    TECHNICAL_EXPANSIONS,
    ProcessedQueryV11,
    QueryProcessorV11,
    ScoredCandidateV11,
    RetrievalResultV11,
    CapabilityRetrievalEngineV11
)

from skill_intelligence_v1 import (
    UnifiedRetrievalCoordinator,
    UnifiedRetrievalCandidate
)

__all__ = [
    # V1 (frozen)
    "ENGLISH_STOPWORDS",
    "CONCEPT_SYNONYMS",
    "ProcessedQuery",
    "QueryProcessor",
    "ScoredCandidate",
    "RetrievalResult",
    "CapabilityRetrievalEngine",
    "CapabilityRetrievalEngineV1",
    # V1.1
    "ENGLISH_STOPWORDS_V11",
    "CONCEPT_SYNONYMS_V11",
    "TECHNICAL_EXPANSIONS",
    "ProcessedQueryV11",
    "QueryProcessorV11",
    "ScoredCandidateV11",
    "RetrievalResultV11",
    "CapabilityRetrievalEngineV11",
    # Unified Skill Intelligence Coordinator
    "UnifiedRetrievalCoordinator",
    "UnifiedRetrievalCandidate"
]


