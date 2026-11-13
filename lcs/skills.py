"""
LCS Skill Intelligence Package Wrapper
======================================
Exposes Skill Discovery and Intelligence V1 components, taxonomy classification,
safe descriptor reading, CAS ingestion, Merkle bundling, semantic profiling,
catalog indexing, and the Unified Retrieval Coordinator.
"""

import os
import sys

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from skill_discovery_v1 import (
    ArtifactTaxonomyKind,
    EnvironmentOrigin,
    PrecedenceTier,
    SkillLifecycleState,
    DiscoveredArtifactRecord,
    SafeFileReader,
    DiscoveryRootResolver,
    ArtifactTaxonomyClassifier,
    BundleManifestHasher,
    AntigravityDiscoveryAdapter,
    ClaudeCodeDiscoveryAdapter,
    OpenCodeDiscoveryAdapter,
    SkillDiscoveryEngineV1,
    SkillDiscoveryError,
    PathTraversalSecurityError,
    DescriptorSecurityError,
    FileSizeExceededError,
    SymlinkCycleError,
    MalformedArtifactError,
    MAX_INSTRUCTION_FILE_SIZE,
    MAX_ASSET_FILE_SIZE,
    MAX_DIRECTORY_RECURSION_DEPTH,
)

from skill_intelligence_v1 import (
    ensure_skill_intelligence_schema,
    SkillIngestionService,
    SkillUnderstandingEngine,
    SkillCatalogService,
    UnifiedRetrievalCoordinator,
    UnifiedRetrievalCandidate,
    SkillIntelligenceServiceV1,
)

__all__ = [
    "ArtifactTaxonomyKind",
    "EnvironmentOrigin",
    "PrecedenceTier",
    "SkillLifecycleState",
    "DiscoveredArtifactRecord",
    "SafeFileReader",
    "DiscoveryRootResolver",
    "ArtifactTaxonomyClassifier",
    "BundleManifestHasher",
    "AntigravityDiscoveryAdapter",
    "ClaudeCodeDiscoveryAdapter",
    "OpenCodeDiscoveryAdapter",
    "SkillDiscoveryEngineV1",
    "SkillDiscoveryError",
    "PathTraversalSecurityError",
    "DescriptorSecurityError",
    "FileSizeExceededError",
    "SymlinkCycleError",
    "MalformedArtifactError",
    "MAX_INSTRUCTION_FILE_SIZE",
    "MAX_ASSET_FILE_SIZE",
    "MAX_DIRECTORY_RECURSION_DEPTH",
    "ensure_skill_intelligence_schema",
    "SkillIngestionService",
    "SkillUnderstandingEngine",
    "SkillCatalogService",
    "UnifiedRetrievalCoordinator",
    "UnifiedRetrievalCandidate",
    "SkillIntelligenceServiceV1",
]
