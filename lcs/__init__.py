"""
Living Capability System (LCS)
==============================
Canonical Stage 2B Implementation: Milestones 1–4 Integrated.
"""

from .config import LCSConfig
from .context import LCSContext
from .storage import SecureCASStorageEngine, PersistentReceiptKeyStore
from .registry import CapabilityRegistrationService, CapabilityDefinition
from .policy import InterfacePolicyService, InterfaceTrustPolicy
from .discovery import CapabilityDiscoveryPipeline, DiscoveryIndexService
from .profile import CapabilitySemanticProfile, CapabilityProfileService, EvidenceSource
from .retrieval import CapabilityRetrievalEngine, RetrievalResult, QueryProcessor
from .parameter import (
    ParameterUnderstandingEngineV1,
    ParameterReadinessResult,
    ParameterReadinessStatus,
    ParameterRequirement,
    MappedParameter
)
from .planning import (
    CapabilityPlanningEngineV1,
    ExecutionPlan,
    PlanStep,
    PlanReadinessStatus,
    DependencyType,
    OutputEvidenceSource,
    BindingSourceType
)
from .governance import (
    ExecutionGovernanceEngineV1,
    GovernanceStatus,
    ApproverRole,
    ApproverConsent,
    ExecutionAuthorizationToken,
    DispatchPermit,
    GovernanceEvaluationResult,
    GovernanceAuditLedger,
    compute_plan_integrity_hash,
    canonicalize_jcs
)
from .skills import (
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
    ensure_skill_intelligence_schema,
    SkillIngestionService,
    SkillUnderstandingEngine,
    SkillCatalogService,
    UnifiedRetrievalCoordinator,
    UnifiedRetrievalCandidate,
    SkillIntelligenceServiceV1
)
from .execution import (
    ExecutionLifecycleState,
    StepExecutionStatus,
    StepReversibilityType,
    StepExecutionRecord,
    ExecutionRunResult,
    ExecutionEngineError,
    PreflightVerificationError,
    StepExecutionTimeoutError,
    StepExecutionError,
    UnresolvedParameterError,
    PathTraversalExecutionError,
    CompensationExecutionError,
    PathSecurityValidator,
    ProcessSupervisor,
    MCPToolHandler,
    SkillExecutionHandler,
    NativeSimulationHandler,
    ExecutionEngineV1,
    ensure_execution_engine_schema
)
from .migrations import MigrationManager
from .mcp_server import LCSMCPServer, run_mcp_server
from .dashboard import run_dashboard

__version__ = "3.0.0"
__all__ = [
    "LCSConfig",
    "LCSContext",
    "LCSMCPServer",
    "run_mcp_server",
    "run_dashboard",
    "SecureCASStorageEngine",
    "PersistentReceiptKeyStore",
    "CapabilityRegistrationService",
    "CapabilityDefinition",
    "InterfacePolicyService",
    "InterfaceTrustPolicy",
    "CapabilityDiscoveryPipeline",
    "DiscoveryIndexService",
    "CapabilitySemanticProfile",
    "CapabilityProfileService",
    "EvidenceSource",
    "CapabilityRetrievalEngine",
    "RetrievalResult",
    "QueryProcessor",
    "ParameterUnderstandingEngineV1",
    "ParameterReadinessResult",
    "ParameterReadinessStatus",
    "ParameterRequirement",
    "MappedParameter",
    "CapabilityPlanningEngineV1",
    "ExecutionPlan",
    "PlanStep",
    "PlanReadinessStatus",
    "DependencyType",
    "OutputEvidenceSource",
    "BindingSourceType",
    "ExecutionGovernanceEngineV1",
    "GovernanceStatus",
    "ApproverRole",
    "ApproverConsent",
    "ExecutionAuthorizationToken",
    "DispatchPermit",
    "GovernanceEvaluationResult",
    "GovernanceAuditLedger",
    "compute_plan_integrity_hash",
    "canonicalize_jcs",
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
    "ensure_skill_intelligence_schema",
    "SkillIngestionService",
    "SkillUnderstandingEngine",
    "SkillCatalogService",
    "UnifiedRetrievalCoordinator",
    "UnifiedRetrievalCandidate",
    "SkillIntelligenceServiceV1",
    "ExecutionLifecycleState",
    "StepExecutionStatus",
    "StepReversibilityType",
    "StepExecutionRecord",
    "ExecutionRunResult",
    "ExecutionEngineError",
    "PreflightVerificationError",
    "StepExecutionTimeoutError",
    "StepExecutionError",
    "UnresolvedParameterError",
    "PathTraversalExecutionError",
    "CompensationExecutionError",
    "PathSecurityValidator",
    "ProcessSupervisor",
    "MCPToolHandler",
    "SkillExecutionHandler",
    "NativeSimulationHandler",
    "ExecutionEngineV1",
    "ensure_execution_engine_schema",
    "MigrationManager",
]

