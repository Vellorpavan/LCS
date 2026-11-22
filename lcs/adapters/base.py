"""
LCS Environment Adapter Framework — Common Contracts & Interfaces
=================================================================
Provides the authoritative abstract base classes, feature flag bitmasks,
operational status enums, dataclasses, and error types for integrating
host agent environments (Google Antigravity, Claude Code, OpenCode, Generic POSIX).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, Flag, auto
from typing import Dict, Any, List, Optional, Set
import datetime
import os


# ============================================================================
# 1. Feature Enumerations & Status Models
# ============================================================================

class AdapterFeature(Flag):
    """
    Bitmask of features explicitly supported by an Environment Adapter.
    Unsupported operations must be un-flagged and fail closed.
    """
    NONE                         = 0
    SLASH_COMMAND_REGISTRATION   = auto()  # Can install/update slash command templates
    SKILL_DISCOVERY              = auto()  # Can discover directory-based skill bundles
    COMMAND_DISCOVERY            = auto()  # Can discover single-file command macros
    RULE_DISCOVERY               = auto()  # Can discover ambient rule files (e.g. CLAUDE.md)
    MCP_CONFIG_DISCOVERY         = auto()  # Can discover configured MCP servers
    MCP_TOOL_INVOCATION          = auto()  # Can invoke MCP tools over stdio/SSE
    AGENT_DELEGATION             = auto()  # Can spawn and message subagents
    INTERACTIVE_TTY_CONSENT      = auto()  # Can prompt user via terminal [y/n]
    CONVERSATIONAL_MODAL_CONSENT = auto()  # Can prompt user via host chat/modal turn
    EXECUTION_TRACE_STREAMING    = auto()  # Can stream live stdout/stderr during dispatch


class EnvironmentKind(str, Enum):
    """Supported host agent environments."""
    ANTIGRAVITY   = "antigravity"
    CLAUDE_CODE   = "claude_code"
    OPENCODE      = "opencode"
    GENERIC_POSIX = "generic_posix"
    CODEX = "codex"


class OperationalStatus(str, Enum):
    """
    Seven-stage operational health status of an environment or individual resource.
    Operational status is dynamic and can fluctuate over time.
    """
    UNCHECKED    = "UNCHECKED"     # Initial state before live probe
    REACHABLE    = "REACHABLE"     # Physical path or socket verified accessible
    CONNECTED    = "CONNECTED"     # Protocol handshake (JSON-RPC initialize / ping) succeeded
    AVAILABLE    = "AVAILABLE"     # Gate 1 trust status ACTIVE and attestation verified
    DEGRADED     = "DEGRADED"      # Attestation expired, probe latency high, or partial failure
    DISCONNECTED = "DISCONNECTED"  # Subprocess exited or socket closed
    UNREACHABLE  = "UNREACHABLE"   # Path missing, permission denied, or probe timed out
    REVOKED      = "REVOKED"       # Trust policy revoked or explicitly disabled by operator


# ============================================================================
# 2. Structural Dataclasses and Value Objects
# ============================================================================

@dataclass(frozen=True)
class CapabilityRoot:
    """A verified filesystem root containing capability artifacts."""
    root_path: str
    precedence_tier: str = "WORKSPACE"  # WORKSPACE, HOST, USER_GLOBAL, BUILTIN
    origin: str = "generic_posix"       # antigravity, claude_code, opencode, generic_posix
    is_writable: bool = False
    has_bundle_manifest: bool = False

    @property
    def path(self) -> str:
        """Alias for root_path."""
        return self.root_path


@dataclass(frozen=True)
class ResourceProbeResult:
    """Outcome of an active reachability probe against a specific resource."""
    resource_id: str
    resource_kind: str  # MCP_SERVER, SKILL_ROOT, AGENT_SOCKET, CLI_BINARY
    status: OperationalStatus
    latency_ms: float
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def response_latency_ms(self) -> float:
        """Alias for latency_ms."""
        return self.latency_ms


@dataclass(frozen=True)
class AdapterReachabilityReport:
    """Aggregated operational health report for an adapter across its resources."""
    adapter_id: str
    environment_kind: EnvironmentKind
    overall_status: OperationalStatus
    checked_at: datetime.datetime
    probes: List[ResourceProbeResult] = field(default_factory=list)


@dataclass(frozen=True)
class MCPConfigEntry:
    """Discovered configuration for an MCP server."""
    server_id: str
    command: str
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None
    server_name: Optional[str] = None
    source_file: Optional[str] = None


@dataclass(frozen=True)
class SubagentHandle:
    """Opaque handle to an active subagent in environments supporting delegation."""
    subagent_id: str
    role_name: str
    created_at: datetime.datetime
    environment: EnvironmentKind
    status: str
    process: Optional[Any] = None

    @property
    def role(self) -> str:
        return self.role_name

    @property
    def conversation_id(self) -> str:
        return self.subagent_id


@dataclass(frozen=True)
class StepExecutionResult:
    """Outcome of executing a capability step inside an environment."""
    step_id: str
    exit_code: int
    stdout_bytes: bytes
    stderr_bytes: bytes
    duration_ms: float
    cas_trace_digest: Optional[str] = None
    output_payload: Optional[Dict[str, Any]] = None


# ============================================================================
# 3. Exceptions
# ============================================================================

class AdapterError(Exception):
    """Base exception for all adapter failures."""
    pass


class UnsupportedAdapterFeatureError(AdapterError):
    """Raised when an operation is attempted on an adapter lacking the declared feature flag."""
    pass


class EnvironmentUnreachableError(AdapterError):
    """Raised when an active reachability probe fails."""
    def __init__(self, resource_id: str, reason: str):
        super().__init__(f"Resource '{resource_id}' is unreachable: {reason}")
        self.resource_id = resource_id
        self.reason = reason


class PathTraversalSecurityError(AdapterError):
    """Raised when descriptor-relative checks detect symlink escape or relative traversal."""
    pass


class ProbeTimeoutError(AdapterError):
    """Raised when a live reachability probe exceeds its deadline."""
    pass


class ContentIntegrityMismatchError(AdapterError):
    """Raised when on-disk bytes fail SHA-256 verification against the catalog CAS digest."""
    def __init__(self, capability_urn: str, expected_digest: str, actual_digest: str):
        super().__init__(
            f"Integrity mismatch for '{capability_urn}': "
            f"expected {expected_digest}, got {actual_digest}"
        )
        self.capability_urn = capability_urn
        self.expected_digest = expected_digest
        self.actual_digest = actual_digest


# ============================================================================
# 4. Abstract Base Class: EnvironmentAdapter
# ============================================================================

class EnvironmentAdapter(ABC):
    """
    Authoritative abstract base class for all LCS Environment Adapters.
    Every host environment integration must implement this contract.
    """

    # -------------------------------------------------------------------------
    # 1. Environment Identification
    # -------------------------------------------------------------------------

    @property
    @abstractmethod
    def adapter_id(self) -> str:
        """Unique identifier (e.g. 'adapter.antigravity.v1')."""
        pass

    @property
    @abstractmethod
    def environment_kind(self) -> EnvironmentKind:
        """Target environment enum value."""
        pass

    @property
    def kind(self) -> EnvironmentKind:
        """Convenience alias for environment_kind."""
        return self.environment_kind

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable display name for logs and UI."""
        pass

    @property
    @abstractmethod
    def declared_features(self) -> AdapterFeature:
        """Bitmask of features explicitly supported by this adapter."""
        pass

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = os.path.realpath(workspace_root) if workspace_root else os.path.realpath(os.getcwd())

    def has_feature(self, feature: AdapterFeature) -> bool:
        """Checks if a specific feature flag is declared by this adapter."""
        return bool(self.declared_features & feature)

    def assert_feature(self, feature: AdapterFeature) -> None:
        """Raises UnsupportedAdapterFeatureError if feature is not declared."""
        if not self.has_feature(feature):
            raise UnsupportedAdapterFeatureError(
                f"{self.display_name} does not support feature: {feature.name}"
            )

    @abstractmethod
    def detect_active(self, workspace_root: Optional[str] = None) -> bool:
        """
        Determines whether this environment is currently active in the workspace.
        Returns True only if concrete environment signatures exist on disk or in env.
        """
        pass

    # -------------------------------------------------------------------------
    # 2. Capability Roots & Manifest Discovery
    # -------------------------------------------------------------------------

    @abstractmethod
    def discover_capability_roots(self, workspace_root: Optional[str] = None) -> List[CapabilityRoot]:
        """
        Discovers verified filesystem directories hosting skills, commands, or rules.
        Must enforce POSIX descriptor-relative checks (no unverified symlinks).
        """
        pass

    # -------------------------------------------------------------------------
    # 3. Live Reachability Probing
    # -------------------------------------------------------------------------

    @abstractmethod
    def probe_reachability(self, workspace_root: Optional[str] = None) -> AdapterReachabilityReport:
        """
        Actively checks operational reachability of environment resources:
        - Checks that skill directories exist and are readable with O_NOFOLLOW.
        - Pings configured MCP stdio/SSE servers with strict timeouts.
        - Verifies execution permissions for binaries.
        Must NOT rely solely on static configuration files.
        """
        pass

    # -------------------------------------------------------------------------
    # 4. Slash-Command Registration & Maintenance
    # -------------------------------------------------------------------------

    def register_slash_command(
        self,
        command_name: str = "call-me",
        description: str = "",
        workspace_root: Optional[str] = None
    ) -> Any:
        """
        Installs the environment-specific slash command artifact.
        Fails closed with UnsupportedAdapterFeatureError if unsupported.
        """
        self.assert_feature(AdapterFeature.SLASH_COMMAND_REGISTRATION)
        raise NotImplementedError(f"{self.display_name} has not implemented register_slash_command")

    # -------------------------------------------------------------------------
    # 5. Skill & Instruction Exact Access
    # -------------------------------------------------------------------------

    @abstractmethod
    def read_skill_exact_bytes(self, relative_path: str, root: Optional[CapabilityRoot] = None) -> bytes:
        """
        Reads exact, un-modified bytes of an instruction or asset file.
        Must enforce path confinement to prevent directory traversal.
        """
        pass

    # -------------------------------------------------------------------------
    # 6. MCP Server & Tool Access
    # -------------------------------------------------------------------------

    def discover_mcp_servers(self, workspace_root: Optional[str] = None) -> List[MCPConfigEntry]:
        """
        Parses host-specific MCP configuration files (e.g. claude.json, opencode.json).
        """
        if not self.has_feature(AdapterFeature.MCP_CONFIG_DISCOVERY):
            return []
        raise NotImplementedError(f"{self.display_name} has not implemented discover_mcp_servers")

    def discover_mcp_configurations(self, workspace_root: Optional[str] = None) -> List[MCPConfigEntry]:
        """Convenience alias for discover_mcp_servers."""
        return self.discover_mcp_servers(workspace_root)

    def invoke_mcp_tool(
        self,
        server_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        timeout_seconds: int = 30
    ) -> Dict[str, Any]:
        """
        Dispatches an MCP tool call through host-managed protocol transport.
        """
        self.assert_feature(AdapterFeature.MCP_TOOL_INVOCATION)
        raise NotImplementedError(f"{self.display_name} has not implemented invoke_mcp_tool")

    # -------------------------------------------------------------------------
    # 7. Agent Delegation & Subagent Spawning
    # -------------------------------------------------------------------------

    def spawn_subagent(
        self,
        role: str,
        initial_prompt: str = "",
        workspace_root: Optional[str] = None,
        timeout_seconds: int = 300,
        prompt: Optional[str] = None,
        type_name: Optional[str] = None
    ) -> SubagentHandle:
        """
        Spawns an autonomous subagent in host platforms supporting multi-agent delegation.
        """
        self.assert_feature(AdapterFeature.AGENT_DELEGATION)
        raise NotImplementedError(f"{self.display_name} has not implemented spawn_subagent")

    def wait_subagent(self, handle: SubagentHandle) -> Dict[str, Any]:
        """
        Blocks or awaits completion of an active subagent task.
        """
        self.assert_feature(AdapterFeature.AGENT_DELEGATION)
        raise NotImplementedError(f"{self.display_name} has not implemented wait_subagent")

    # -------------------------------------------------------------------------
    # 8. Human Approver Consent & Permissions
    # -------------------------------------------------------------------------

    def request_approver_consent(
        self,
        capability_urn: str,
        action_summary: str,
        parameters: Dict[str, Any],
        required_role: str
    ) -> bool:
        """
        Requests human or role-based consent for Gate 2 governance evaluation.
        Can use TTY prompt, host dialog, or fail-closed refusal.
        """
        raise NotImplementedError(f"{self.display_name} has not implemented request_approver_consent")

    # -------------------------------------------------------------------------
    # 9. Evidence Collection & Audit Anchors
    # -------------------------------------------------------------------------

    @abstractmethod
    def collect_execution_evidence(
        self,
        step_id: str,
        raw_stdout: bytes,
        raw_stderr: bytes,
        exit_code: int
    ) -> Dict[str, Any]:
        """
        Packages execution evidence into a normalized dictionary for CAS trace ingestion.
        """
        pass


# ============================================================================
# 5. Adapter Registry
# ============================================================================

class AdapterRegistry:
    """
    Central registry for managing, registering, and dynamically resolving Environment Adapters.
    Supports built-in adapters (Codex, Antigravity, Claude Code, OpenCode, Generic POSIX)
    as well as dynamically loaded custom adapters.
    """

    DEFAULT_PRECEDENCE = {
        EnvironmentKind.CODEX: 90,
        "codex": 90,
        EnvironmentKind.ANTIGRAVITY: 80,
        "antigravity": 80,
        EnvironmentKind.CLAUDE_CODE: 70,
        "claude_code": 70,
        EnvironmentKind.OPENCODE: 60,
        "opencode": 60,
        EnvironmentKind.GENERIC_POSIX: 0,
        "generic_posix": 0,
    }

    def __init__(self):
        self._adapters: Dict[str, EnvironmentAdapter] = {}
        self._precedence: Dict[str, int] = {}

    def _normalize_key(self, kind: Any) -> str:
        if hasattr(kind, "value"):
            return str(kind.value).lower()
        return str(kind).lower()

    def register(self, adapter: EnvironmentAdapter, precedence: Optional[int] = None) -> None:
        """Registers an adapter instance for its declared environment kind with optional precedence score."""
        key = self._normalize_key(adapter.environment_kind)
        self._adapters[key] = adapter

        if precedence is not None:
            self._precedence[key] = precedence
        elif hasattr(adapter, "precedence") and isinstance(getattr(adapter, "precedence"), int):
            self._precedence[key] = getattr(adapter, "precedence")
        elif key in self.DEFAULT_PRECEDENCE:
            self._precedence[key] = self.DEFAULT_PRECEDENCE[key]
        elif adapter.environment_kind in self.DEFAULT_PRECEDENCE:
            self._precedence[key] = self.DEFAULT_PRECEDENCE[adapter.environment_kind]
        else:
            self._precedence[key] = 50

    def get(self, kind: Any) -> Optional[EnvironmentAdapter]:
        """Retrieves registered adapter by environment kind or string key."""
        key = self._normalize_key(kind)
        return self._adapters.get(key)

    def get_active_adapter(self, workspace_root: Optional[str] = None) -> EnvironmentAdapter:
        """
        Determines the active environment adapter with deterministic precedence and safe fallback:
        1. Resolves effective workspace root (explicit argument, or from registered adapter instances, or cwd).
        2. Evaluates detect_active(ws) on all registered non-fallback adapters.
        3. Selects active adapter with highest precedence score (breaking ties deterministically by adapter_id).
        4. Safe fallback: returns GENERIC_POSIX if registered.
        """
        ws = workspace_root
        if not ws:
            for ad in self._adapters.values():
                if hasattr(ad, "workspace_root") and ad.workspace_root:
                    ws = ad.workspace_root
                    break
        ws = ws or os.getcwd()

        active_candidates: List[Tuple[int, str, EnvironmentAdapter]] = []
        generic_key = self._normalize_key(EnvironmentKind.GENERIC_POSIX)

        for key, adapter in self._adapters.items():
            if key == generic_key:
                continue
            if adapter.detect_active(ws):
                p_score = self._precedence.get(key, 50)
                active_candidates.append((p_score, adapter.adapter_id, adapter))

        if active_candidates:
            active_candidates.sort(key=lambda item: (-item[0], item[1]))
            return active_candidates[0][2]

        # Step 2: Fallback to generic POSIX
        fallback = self._adapters.get(generic_key)
        if fallback:
            return fallback

        raise EnvironmentUnreachableError(
            "registry",
            "No active environment adapter found and generic POSIX fallback is not registered."
        )

    def detect_active(self, workspace_root: Optional[str] = None) -> EnvironmentAdapter:
        """Convenience alias for get_active_adapter."""
        return self.get_active_adapter(workspace_root)

    def list_all(self) -> List[EnvironmentAdapter]:
        """Lists all registered adapters sorted by precedence descending."""
        sorted_keys = sorted(
            self._adapters.keys(),
            key=lambda k: (-self._precedence.get(k, 0), self._adapters[k].adapter_id)
        )
        return [self._adapters[k] for k in sorted_keys]
