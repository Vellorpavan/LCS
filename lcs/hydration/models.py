"""
LCS Capability Instruction Hydration Models (Phase 2B)
======================================================
Defines data structures and decoupled state representations for deep capability hydration,
provenance preservation, and auxiliary resource tracking.
"""

import os
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


class ResourceUtilizationState(str, Enum):
    """
    Decoupled Task Execution and Utilization State Machine (Axis 3).
    Tracks the progression of a specific capability through a task lifecycle.
    """
    DISCOVERED           = "DISCOVERED"            # Identified in catalog/index
    RETRIEVED            = "RETRIEVED"             # Authoritative root bytes loaded from CAS/disk
    HYDRATED             = "HYDRATED"              # Complete instructions and auxiliary assets loaded
    PREPARED             = "PREPARED"              # Dependencies resolved, verification gates staged
    ACTIVATED            = "ACTIVATED"             # Hash-On-Activation verified, EAT token bound
    EXECUTED             = "EXECUTED"              # Execution completed by engine/subagent
    COMPLETED_UNVERIFIED = "COMPLETED_UNVERIFIED"  # Finished execution but output not yet audited
    VERIFIED             = "VERIFIED"              # All multi-tier resource-specific gates passed
    FAILED               = "FAILED"                # Any integrity, schema, or execution check failed


@dataclass
class AuxiliaryFileRecord:
    """Represents a supporting asset (script, template, reference doc) inside a capability bundle."""
    relative_path: str
    absolute_path: str
    content_bytes: bytes
    digest: str
    size_bytes: int
    mime_type: str = "text/plain"

    @property
    def content_text(self) -> str:
        try:
            return self.content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return self.content_bytes.decode("utf-8", errors="replace")


@dataclass
class DependencyReference:
    """Represents a declared dependency on another resource (skill, tool, script, template)."""
    name: str
    target_urn_or_path: str
    resource_type: str  # "SKILL", "MCP_TOOL", "SCRIPT", "TEMPLATE", etc.
    is_mandatory: bool = True
    version_spec: Optional[str] = None
    description: Optional[str] = None


@dataclass
class HydratedCapability:
    """
    Complete, provenance-preserving hydrated capability representation.
    Guarantees original instructions are never replaced with AI-generated summaries.
    """
    capability_urn: str
    name: str
    raw_instructions: str
    instruction_digest: str
    state: ResourceUtilizationState = ResourceUtilizationState.HYDRATED
    source_path: Optional[str] = None
    cas_digest: Optional[str] = None
    is_bundle: bool = False
    bundle_root_path: Optional[str] = None
    bundle_manifest_digest: Optional[str] = None
    auxiliary_files: Dict[str, AuxiliaryFileRecord] = field(default_factory=dict)
    dependencies: List[DependencyReference] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    is_complete: bool = True
    missing_dependencies: List[str] = field(default_factory=list)

    def get_auxiliary_file(self, rel_path: str) -> Optional[AuxiliaryFileRecord]:
        """Looks up an auxiliary file by relative path normalized with forward slashes."""
        norm_path = rel_path.replace("\\", "/").lstrip("/")
        return self.auxiliary_files.get(norm_path)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_urn": self.capability_urn,
            "name": self.name,
            "instruction_digest": self.instruction_digest,
            "state": self.state.value,
            "source_path": self.source_path,
            "cas_digest": self.cas_digest,
            "is_bundle": self.is_bundle,
            "bundle_manifest_digest": self.bundle_manifest_digest,
            "auxiliary_count": len(self.auxiliary_files),
            "dependency_count": len(self.dependencies),
            "is_complete": self.is_complete,
            "missing_dependencies": list(self.missing_dependencies),
            "provenance": dict(self.provenance)
        }
