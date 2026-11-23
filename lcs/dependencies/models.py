"""
LCS Dependency Resolution Models (Phase 2B)
===========================================
Defines resource types, dependency edges, and graph nodes for multi-resource
capability dependency resolution.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


class ResourceType(str, Enum):
    """Resource classification across the Living Capability System."""
    SKILL              = "SKILL"
    AGENT              = "AGENT"
    MCP_TOOL           = "MCP_TOOL"
    MCP_SERVER         = "MCP_SERVER"
    SCRIPT             = "SCRIPT"
    WORKFLOW           = "WORKFLOW"
    TEMPLATE           = "TEMPLATE"
    DOCUMENTATION      = "DOCUMENTATION"
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"


class DependencyType(str, Enum):
    """Dependency requirement level."""
    MANDATORY = "MANDATORY"
    OPTIONAL  = "OPTIONAL"


@dataclass
class DependencyNode:
    """Represents a discrete resource vertex in the dependency graph."""
    resource_id: str
    resource_type: ResourceType
    display_name: str = ""
    is_mandatory: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyEdge:
    """Represents a directed dependency edge: dependent_id depends on depends_on_id."""
    dependent_id: str
    depends_on_id: str
    dependency_type: DependencyType = DependencyType.MANDATORY
    metadata: Dict[str, Any] = field(default_factory=dict)
