"""
LCS Environment Adapters Package
================================
Provides the unified adapter framework and concrete adapters for:
- Generic POSIX (Universal fallback)
- Claude Code
- OpenCode
- Google Antigravity
Along with live reachability probing, operational health monitoring,
and Hash-On-Activation verification.
"""

from .base import (
    AdapterFeature,
    EnvironmentKind,
    OperationalStatus,
    CapabilityRoot,
    ResourceProbeResult,
    AdapterReachabilityReport,
    MCPConfigEntry,
    SubagentHandle,
    StepExecutionResult,
    AdapterError,
    UnsupportedAdapterFeatureError,
    EnvironmentUnreachableError,
    PathTraversalSecurityError,
    ProbeTimeoutError,
    ContentIntegrityMismatchError,
    EnvironmentAdapter,
    AdapterRegistry,
)

from .probes import LiveProbeEngine
from .generic import GenericPOSIXAdapter
from .claude_code import ClaudeCodeAdapter
from .opencode import OpenCodeAdapter
from .antigravity import AntigravityAdapter
from .activation_verifier import ActivationIntegrityVerifier, ActivationIntegrityRecord

__all__ = [
    "AdapterFeature",
    "EnvironmentKind",
    "OperationalStatus",
    "CapabilityRoot",
    "ResourceProbeResult",
    "AdapterReachabilityReport",
    "MCPConfigEntry",
    "SubagentHandle",
    "StepExecutionResult",
    "AdapterError",
    "UnsupportedAdapterFeatureError",
    "EnvironmentUnreachableError",
    "PathTraversalSecurityError",
    "ProbeTimeoutError",
    "ContentIntegrityMismatchError",
    "EnvironmentAdapter",
    "AdapterRegistry",
    "LiveProbeEngine",
    "GenericPOSIXAdapter",
    "ClaudeCodeAdapter",
    "OpenCodeAdapter",
    "AntigravityAdapter",
    "ActivationIntegrityVerifier",
    "ActivationIntegrityRecord",
]
