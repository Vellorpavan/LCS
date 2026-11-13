"""
LCS Capability Registry Package Wrapper
"""

import os
import sys

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from capability_registry_v2b import (
    CapabilityDefinition,
    CapabilityRegistrationService,
    CanonicalCapabilityURN,
    parse_canonical_urn,
    RegistrationResult,
    RetrievedCapability,
    CapabilityRegistryError,
    InvalidCapabilityURNError,
    InvalidCapabilityDefinitionError,
    CapabilityRegistrationConflictError,
    CapabilityNotFoundError,
    CapabilityIntegrityMismatchError,
    CapabilityCorruptionError,
    SQLiteForeignKeyEnforcementError,
    SUPPORTED_ENTITY_KINDS
)

__all__ = [
    "CapabilityDefinition",
    "CapabilityRegistrationService",
    "CanonicalCapabilityURN",
    "parse_canonical_urn",
    "RegistrationResult",
    "RetrievedCapability",
    "CapabilityRegistryError",
    "InvalidCapabilityURNError",
    "InvalidCapabilityDefinitionError",
    "CapabilityRegistrationConflictError",
    "CapabilityNotFoundError",
    "CapabilityIntegrityMismatchError",
    "CapabilityCorruptionError",
    "SQLiteForeignKeyEnforcementError",
    "SUPPORTED_ENTITY_KINDS",
]
