"""
LCS Resource-Specific Verification Models (Phase 2B)
====================================================
Defines verification states, evidence tiers, and verification result dataclasses
to eliminate the 'exit 0 fallacy' and enforce zero-trust multi-tier checks.
"""

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class VerificationState(str, Enum):
    """Authoritative verification lifecycle states."""
    RETRIEVED            = "RETRIEVED"             # Authoritative source loaded
    PREPARED             = "PREPARED"              # Input parameters and dependencies validated
    ACTIVATED            = "ACTIVATED"             # Hash-On-Activation verified
    EXECUTED             = "EXECUTED"              # Execution attempt launched
    COMPLETED_UNVERIFIED = "COMPLETED_UNVERIFIED"  # Exited with code 0 or payload, but unvalidated
    VERIFIED             = "VERIFIED"              # All multi-tier resource gates passed
    FAILED               = "FAILED"                # Failed any verification criterion


class EvidenceTier(int, Enum):
    """5-Tier Verification Evidence Hierarchy."""
    TIER_1_IDENTITY_INTEGRITY    = 1  # CAS digests, signatures, Hash-On-Activation
    TIER_2_RETRIEVAL_ACTIVATION  = 2  # Complete instructions, dependencies, inputs
    TIER_3_EXECUTION_EVIDENCE    = 3  # Process traces, stdio streams, exit codes
    TIER_4_CONTRACT_COMPLIANCE   = 4  # Output schemas, non-empty artifacts, stderr audits
    TIER_5_TASK_OUTCOME_AUDIT    = 5  # Final user task deliverable verification


@dataclass
class EvidenceRecord:
    """Discrete evidence verification assertion."""
    tier: EvidenceTier
    criterion: str
    passed: bool
    evidence_digest: Optional[str] = None
    details: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class VerificationResult:
    """Consolidated multi-tier verification report for a resource execution step."""
    resource_id: str
    resource_type: str
    state: VerificationState
    is_verified: bool
    evidence_records: List[EvidenceRecord] = field(default_factory=list)
    cas_trace_digest: Optional[str] = None
    error_details: Optional[str] = None
    completed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def add_evidence(
        self,
        tier: EvidenceTier,
        criterion: str,
        passed: bool,
        digest: Optional[str] = None,
        details: Optional[str] = None
    ) -> None:
        self.evidence_records.append(EvidenceRecord(
            tier=tier,
            criterion=criterion,
            passed=passed,
            evidence_digest=digest,
            details=details
        ))
        if not passed:
            self.is_verified = False
            self.state = VerificationState.FAILED
            if not self.error_details:
                self.error_details = f"Failed Tier {tier.value} criterion: {criterion} - {details}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "state": self.state.value,
            "is_verified": self.is_verified,
            "cas_trace_digest": self.cas_trace_digest,
            "error_details": self.error_details,
            "completed_at": self.completed_at,
            "evidence_count": len(self.evidence_records),
            "evidence_passed": sum(1 for e in self.evidence_records if e.passed)
        }
