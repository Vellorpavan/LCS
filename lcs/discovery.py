"""
LCS Discovery & MCP Package Wrapper
"""

import os
import sys

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from capability_discovery_v2b import (
    DiscoveryError,
    MCPProtocolError,
    MCPTimeoutError,
    SchemaNormalizationError,
    NormalizedDiscoveredTool,
    DiscoverySummary,
    SearchResult,
    MCPSchemaNormalizer,
    DEFAULT_SYSTEM_ENV_VARS,
    MCPDiscoveryClient,
    DiscoveryIndexService,
    CapabilityDiscoveryPipeline
)

__all__ = [
    "DiscoveryError",
    "MCPProtocolError",
    "MCPTimeoutError",
    "SchemaNormalizationError",
    "NormalizedDiscoveredTool",
    "DiscoverySummary",
    "SearchResult",
    "MCPSchemaNormalizer",
    "DEFAULT_SYSTEM_ENV_VARS",
    "MCPDiscoveryClient",
    "DiscoveryIndexService",
    "CapabilityDiscoveryPipeline",
]
