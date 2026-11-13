"""
LCS Execution Governance Package Wrapper
========================================
Exposes the Execution Governance V1 engine, models, canonical plan hashing,
EAT tokens, DispatchPermits, and hash-chained audit ledgers.
"""

import os
import sys

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from governance_policy_v1 import (
    canonicalize_jcs,
    extract_canonical_plan_payload,
    compute_plan_integrity_hash,
    GovernanceStatus,
    ApproverRole,
    ResourceCategory,
    ReversibilityType,
    ApproverConsent,
    PolicyRevision,
    ExecutionAuthorizationToken,
    DispatchPermit,
    GovernanceEvaluationResult,
    GovernanceError,
    GovernanceBlockedError,
    GovernanceRejectedError,
    PlanIntegrityTamperedError,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    TokenRevokedError,
    DispatchPermitAlreadyUsedError,
    DispatchPermitExpiredError,
    DispatchPermitInvalidError,
    PolicyRevisionMismatchError,
    AttestationRevokedError,
    PermissionViolationError,
    UnsupportedStorageTopologyError,
    AuditChainIntegrityError,
    AuditLogTailTruncatedError,
    AuditDirectorySyncError,
    ensure_governance_schema,
    check_storage_topology,
    get_current_policy_revision,
    increment_policy_revision,
    evaluate_resource_boundaries,
    GovernanceAuditLedger,
    ExecutionGovernanceEngineV1
)

__all__ = [
    "canonicalize_jcs",
    "extract_canonical_plan_payload",
    "compute_plan_integrity_hash",
    "GovernanceStatus",
    "ApproverRole",
    "ResourceCategory",
    "ReversibilityType",
    "ApproverConsent",
    "PolicyRevision",
    "ExecutionAuthorizationToken",
    "DispatchPermit",
    "GovernanceEvaluationResult",
    "GovernanceError",
    "GovernanceBlockedError",
    "GovernanceRejectedError",
    "PlanIntegrityTamperedError",
    "TokenAlreadyConsumedError",
    "TokenExpiredError",
    "TokenRevokedError",
    "DispatchPermitAlreadyUsedError",
    "DispatchPermitExpiredError",
    "DispatchPermitInvalidError",
    "PolicyRevisionMismatchError",
    "AttestationRevokedError",
    "PermissionViolationError",
    "UnsupportedStorageTopologyError",
    "AuditChainIntegrityError",
    "AuditLogTailTruncatedError",
    "AuditDirectorySyncError",
    "ensure_governance_schema",
    "check_storage_topology",
    "get_current_policy_revision",
    "increment_policy_revision",
    "evaluate_resource_boundaries",
    "GovernanceAuditLedger",
    "ExecutionGovernanceEngineV1"
]
