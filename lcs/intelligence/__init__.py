"""LCS Intelligence package: host-assisted semantic reasoning and requirement coverage validation."""
from .semantic_reasoner import (
    RequirementItem,
    CapabilitySelection,
    CapabilityGap,
    SemanticReasoningResult,
    SemanticReasoner,
)

__all__ = [
    "RequirementItem",
    "CapabilitySelection",
    "CapabilityGap",
    "SemanticReasoningResult",
    "SemanticReasoner",
]
