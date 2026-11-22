"""
LCS Unified Capability Inventory Models
=======================================
Defines the authoritative domain models, resource taxonomies, operational lifecycle states,
context transfer payloads, and audit representations for unified capability coordination.

Guiding Principles:
1. Preserve original content, source paths, content hashes, and provenance bit-for-bit.
2. Differentiate distinct resource semantics: Agents, Skills, Tools, MCP Servers,
   Commands, Scripts, Workflows, Rules, Templates, and References.
3. Multi-stage operational status: DISCOVERED -> CONFIGURED -> REACHABLE -> CONNECTED
   -> AUTHORIZED -> EXECUTABLE -> ACTIVATED -> VERIFIED.
4. Token-budget-aware context transfer: Send only task-relevant instructions and dependencies.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, List, Optional, Set
import datetime
import hashlib


class ResourceType(str, Enum):
    """
    Unified taxonomy of capability resources supported by LCS.
    Preserves distinct semantics across heterogeneous AI coding environments.
    """
    AGENT              = "AGENT"               # Specialized subagent or persona definition
    SKILL              = "SKILL"               # Domain skill bundle (e.g. SKILL.md)
    TOOL               = "TOOL"                # Individual executable tool (native function or MCP tool)
    MCP_TOOL           = "MCP_TOOL"            # MCP tool representation
    MCP_SERVER         = "MCP_SERVER"          # Model Context Protocol server endpoint
    COMMAND            = "COMMAND"             # Slash command or macro (e.g. /call-me, /review)
    SCRIPT             = "SCRIPT"              # Executable script (Python, Bash, Node)
    WORKFLOW           = "WORKFLOW"            # Multi-step orchestrated execution plan
    AGENT_INSTRUCTION  = "AGENT_INSTRUCTION"   # Direct system prompt or agent instruction file
    RULE               = "RULE"                # Ambient workspace rule (e.g. CLAUDE.md, AGENTS.md)
    TEMPLATE           = "TEMPLATE"            # Scaffold, prompt, or Jinja template
    REFERENCE          = "REFERENCE"           # Reference documentation or data specification
    DOCUMENTATION      = "DOCUMENTATION"       # Documentation file
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"  # External dependency reference


class OperationalLifecycleState(str, Enum):
    """
    Fine-grained eight-stage operational lifecycle state machine.
    Distinguishes static discovery from active connection, authorization, and verification.
    """
    DISCOVERED   = "DISCOVERED"    # Located on disk, host environment, or remote index
    CONFIGURED   = "CONFIGURED"    # Valid parameters, manifest, or schema parsed
    REACHABLE    = "REACHABLE"     # Physical path or socket verified accessible
    CONNECTED    = "CONNECTED"     # Protocol handshake (JSON-RPC initialize / ping) succeeded
    AUTHORIZED   = "AUTHORIZED"    # Evaluated and approved against Governance Gate 1 policy
    EXECUTABLE   = "EXECUTABLE"    # Ready for dispatch (mandatory dependencies satisfied)
    ACTIVATED    = "ACTIVATED"     # Hash-On-Activation verified, bound to single-use EAT token
    VERIFIED     = "VERIFIED"      # Execution deliverable passed multi-tier verification gates
    UNAVAILABLE  = "UNAVAILABLE"   # Inaccessible, broken, or dependency missing
    BLOCKED      = "BLOCKED"       # Denied by policy, security audit, or operator revocation


@dataclass(frozen=True)
class ExecutionRequirement:
    """Declared execution prerequisites for a capability."""
    runtime_environment: str = "generic_posix"  # posix, python, node, bash
    min_runtime_version: Optional[str] = None
    required_binaries: List[str] = field(default_factory=list)
    required_env_vars: List[str] = field(default_factory=list)
    network_required: bool = False
    sandbox_required: bool = True
    timeout_seconds: int = 300


@dataclass(frozen=True)
class ProvenanceRecord:
    """Immutable provenance tracking an artifact to its source origin."""
    origin_host: str                            # antigravity, claude_code, opencode, generic_posix
    precedence_tier: str                        # WORKSPACE, HOST, USER_GLOBAL, BUILTIN
    source_path: str                            # Original path where discovered
    resolved_path: str                          # Canonical realpath
    content_hash: str                           # Authoritative SHA-256 of primary instruction/definition
    bundle_manifest_hash: Optional[str] = None  # Merkle hash for multi-file bundles
    version: str = "1.0.0"                      # Version string if declared
    discovered_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


@dataclass
class UnifiedResourceRecord:
    """
    Authoritative representation of a registered resource in the Unified Capability Inventory.
    Maintains exact content provenance, operational status, dependencies, and requirements.
    """
    urn: str
    name: str
    resource_type: ResourceType
    display_name: str
    description: str
    raw_content: str
    raw_content_digest: str
    provenance: ProvenanceRecord
    lifecycle_state: OperationalLifecycleState = OperationalLifecycleState.DISCOVERED
    execution_requirements: ExecutionRequirement = field(default_factory=ExecutionRequirement)
    is_bundle: bool = False
    bundle_root_path: Optional[str] = None
    auxiliary_files: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    declared_dependencies: List[Dict[str, Any]] = field(default_factory=list)
    missing_dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    security_flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "urn": self.urn,
            "name": self.name,
            "resource_type": self.resource_type.value,
            "display_name": self.display_name,
            "description": self.description,
            "raw_content_digest": self.raw_content_digest,
            "lifecycle_state": self.lifecycle_state.value,
            "is_bundle": self.is_bundle,
            "auxiliary_file_count": len(self.auxiliary_files),
            "dependency_count": len(self.declared_dependencies),
            "missing_dependencies": list(self.missing_dependencies),
            "security_flags": list(self.security_flags),
            "provenance": {
                "origin_host": self.provenance.origin_host,
                "precedence_tier": self.provenance.precedence_tier,
                "source_path": self.provenance.source_path,
                "content_hash": self.provenance.content_hash,
                "version": self.provenance.version,
            }
        }


@dataclass(frozen=True)
class ConflictRecord:
    """Tracks duplicate capabilities or conflicting versions across hosts or tiers."""
    urn: str
    name: str
    conflicting_versions: List[str]
    locations: List[str]
    chosen_record_urn: str
    resolution_reason: str


@dataclass
class DeepRetrievalResult:
    """Outcome of deep capability retrieval for a task."""
    primary_resource: UnifiedResourceRecord
    resolved_dependencies: List[UnifiedResourceRecord] = field(default_factory=list)
    missing_dependencies: List[str] = field(default_factory=list)
    inaccessible_resources: List[Dict[str, str]] = field(default_factory=list)
    compatibility_passed: bool = True
    compatibility_notes: List[str] = field(default_factory=list)
    is_executable: bool = True
    execution_requirements: ExecutionRequirement = field(default_factory=ExecutionRequirement)


@dataclass
class ContextTransferPayload:
    """
    Token-efficient, provenance-preserving payload constructed for model or subagent delegation.
    Contains only task-relevant instructions, satisfied dependencies, and execution parameters.
    """
    task_query: str
    primary_urn: str
    instructions_text: str
    dependency_snippets: Dict[str, str] = field(default_factory=dict)
    execution_guidance: str = ""
    estimated_tokens: int = 0
    token_budget_limit: Optional[int] = None
    budget_exceeded: bool = False
    token_metric: str = "ESTIMATE"
    omitted_references: List[str] = field(default_factory=list)
    provenance_hashes: Dict[str, str] = field(default_factory=dict)
    audit_timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Standard conservative token estimation: max(1, ceil(len(text) / 3.8))."""
        if not text:
            return 0
        return max(1, int(len(text) / 3.8) + 1)
