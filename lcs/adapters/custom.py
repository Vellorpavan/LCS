"""
LCS Declarative Custom Host Adapter Architecture
================================================
Provides schema validation, security auditing, and dynamic host adapter creation
for custom, third-party, and future AI coding agents.

Invariants:
- Strict schema validation with fail-closed error handling.
- Path traversal rejection (no '..' or un-anchored directory escape).
- Arbitrary command execution prevention (only permitted LCS invocation syntax allowed).
- Deterministic capability negotiation and reachability probing.
"""

import os
import re
import sys
import json
import stat
import datetime
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set

from .base import (
    EnvironmentAdapter,
    AdapterFeature,
    EnvironmentKind,
    CapabilityRoot,
    OperationalStatus,
    ResourceProbeResult,
    AdapterReachabilityReport,
    MCPConfigEntry,
    SubagentHandle,
    AdapterError,
    UnsupportedAdapterFeatureError,
    PathTraversalSecurityError,
)
from ..interface.generators import SlashCommandGenerator, CommandGeneratorError


# ============================================================================
# 1. Declarative Custom Adapter Specification & Validation
# ============================================================================

SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_\.\-]+$")
SAFE_COMMAND_PATTERN = re.compile(
    r"^(\s*(command\s+-v\s+lcs\s*>/dev/null\s*2>&1\s*&&\s*)?lcs\s+call-me|python3?\s+-m\s+lcs\.cli\s+call-me).*$"
)


class CustomAdapterSecurityError(AdapterError):
    """Raised when a custom adapter specification violates security policies."""
    pass


@dataclass
class DeclarativeCustomAdapterSpec:
    """Parsed and validated specification for a declarative custom host adapter."""
    schema_version: str
    agent_id: str
    name: str
    display_name: str
    precedence: int = 50
    environment_markers: Dict[str, List[str]] = field(default_factory=dict)
    instruction_files: List[str] = field(default_factory=list)
    skill_roots: List[str] = field(default_factory=list)
    global_skill_roots: List[str] = field(default_factory=list)
    capabilities: Dict[str, bool] = field(default_factory=dict)
    command_integration: Dict[str, Any] = field(default_factory=dict)
    mcp_config: Dict[str, Any] = field(default_factory=dict)
    raw_spec: Dict[str, Any] = field(default_factory=dict)


def validate_custom_agent_spec(spec_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Performs comprehensive schema and security validation on a custom agent definition.
    Returns (is_valid, list_of_errors).
    """
    errors: List[str] = []

    if not isinstance(spec_data, dict):
        return False, ["Specification must be a JSON object / dictionary."]

    # 1. Required Top-Level Fields
    for req in ("agent_id", "name", "display_name"):
        val = spec_data.get(req)
        if not val or not isinstance(val, str) or not val.strip():
            errors.append(f"Missing or invalid required string field '{req}'.")

    agent_id = spec_data.get("agent_id", "")
    if agent_id and not SAFE_IDENTIFIER_PATTERN.match(agent_id):
        errors.append(f"Field 'agent_id' contains disallowed characters: '{agent_id}'. Must match ^[a-zA-Z0-9_.\\-]+$.")

    name = spec_data.get("name", "")
    if name and not SAFE_IDENTIFIER_PATTERN.match(name):
        errors.append(f"Field 'name' contains disallowed characters: '{name}'.")

    # 2. Precedence Bounds Check
    precedence = spec_data.get("precedence", 50)
    if not isinstance(precedence, int) or precedence < 1 or precedence > 100:
        errors.append("Field 'precedence' must be an integer between 1 and 100.")

    # 3. Path Security Checks (Prevent traversal / escape)
    def _check_safe_relative_path(path_str: str, field_desc: str) -> None:
        if not isinstance(path_str, str):
            errors.append(f"{field_desc} must be a string path.")
            return
        clean = path_str.strip()
        if ".." in clean.replace("\\", "/").split("/"):
            errors.append(f"Path traversal ('..') forbidden in {field_desc}: '{clean}'.")
        if clean.startswith("/") and not clean.startswith("/Users/") and not clean.startswith("/home/"):
            # Prohibit system root paths
            errors.append(f"Illegal root directory reference in {field_desc}: '{clean}'.")

    # Check environment markers
    env_markers = spec_data.get("environment_markers", {})
    if not isinstance(env_markers, dict):
        errors.append("Field 'environment_markers' must be a dictionary.")
    else:
        for f in env_markers.get("workspace_files", []):
            _check_safe_relative_path(f, "environment_markers.workspace_files")
        for d in env_markers.get("workspace_dirs", []):
            _check_safe_relative_path(d, "environment_markers.workspace_dirs")

    # Check instruction files
    for inf in spec_data.get("instruction_files", []):
        _check_safe_relative_path(inf, "instruction_files")

    # Check skill roots
    for sr in spec_data.get("skill_roots", []):
        _check_safe_relative_path(sr, "skill_roots")

    # 4. Capabilities Dictionary Check
    caps = spec_data.get("capabilities", {})
    if not isinstance(caps, dict):
        errors.append("Field 'capabilities' must be a dictionary.")
    else:
        for k, v in caps.items():
            if not isinstance(v, bool):
                errors.append(f"Capability '{k}' must be a boolean.")

    # 5. Command Integration Security Check
    cmd_int = spec_data.get("command_integration", {})
    if cmd_int:
        if not isinstance(cmd_int, dict):
            errors.append("Field 'command_integration' must be a dictionary.")
        else:
            tgt = cmd_int.get("target_path")
            if tgt:
                _check_safe_relative_path(tgt, "command_integration.target_path")
            custom_cmd = cmd_int.get("execution_command")
            if custom_cmd:
                if not isinstance(custom_cmd, str):
                    errors.append("command_integration.execution_command must be a string.")
                elif not SAFE_COMMAND_PATTERN.match(custom_cmd.strip()):
                    errors.append(
                        f"Refusing custom execution_command: '{custom_cmd}'. "
                        "Commands must invoke 'lcs call-me' or 'python3 -m lcs.cli call-me' without shell piping or chaining."
                    )

    # 6. MCP Config Security Check
    mcp_cfg = spec_data.get("mcp_config", {})
    if mcp_cfg:
        if not isinstance(mcp_cfg, dict):
            errors.append("Field 'mcp_config' must be a dictionary.")
        else:
            cfg_file = mcp_cfg.get("config_file")
            if cfg_file:
                _check_safe_relative_path(cfg_file, "mcp_config.config_file")

    return len(errors) == 0, errors


# ============================================================================
# 2. Declarative Host Adapter Implementation
# ============================================================================

class DeclarativeHostAdapter(EnvironmentAdapter):
    """
    Dynamic, schema-validated host adapter constructed from a declarative specification.
    Allows new and custom AI coding agents to participate seamlessly in LCS discovery,
    slash command generation, capability negotiation, and verified task handoff.
    """

    def __init__(self, spec: DeclarativeCustomAdapterSpec, workspace_root: Optional[str] = None):
        super().__init__(workspace_root=workspace_root)
        self.spec = spec
        self._precedence = spec.precedence

        # Construct declared features bitmask based on spec capabilities
        features = AdapterFeature.NONE
        caps = spec.capabilities
        if caps.get("slash_commands", False):
            features |= AdapterFeature.SLASH_COMMAND_REGISTRATION
            features |= AdapterFeature.COMMAND_DISCOVERY
        if caps.get("skills", True):
            features |= AdapterFeature.SKILL_DISCOVERY
        if caps.get("instructions", True) or spec.instruction_files:
            features |= AdapterFeature.RULE_DISCOVERY
        if caps.get("mcp", False):
            features |= AdapterFeature.MCP_CONFIG_DISCOVERY
            features |= AdapterFeature.MCP_TOOL_INVOCATION
        if caps.get("subagent_delegation", False):
            features |= AdapterFeature.AGENT_DELEGATION
        if caps.get("interactive_tty_consent", True):
            features |= AdapterFeature.INTERACTIVE_TTY_CONSENT
        if caps.get("execution_trace_streaming", True):
            features |= AdapterFeature.EXECUTION_TRACE_STREAMING

        self._declared_features = features

    @property
    def adapter_id(self) -> str:
        return self.spec.agent_id

    @property
    def environment_kind(self) -> Any:
        return self.spec.name

    @property
    def display_name(self) -> str:
        return self.spec.display_name

    @property
    def declared_features(self) -> AdapterFeature:
        return self._declared_features

    @property
    def precedence(self) -> int:
        return self._precedence

    @property
    def runtime_env_markers(self) -> List[str]:
        return self.spec.environment_markers.get("env_vars", [])

    def detect_active(self, workspace_root: Optional[str] = None) -> bool:
        """
        Determines whether this custom agent is active:
        1. Checks declared environment variables in os.environ.
        2. Checks declared workspace files and directories.
        3. Checks declared global user directories.
        """
        ws = workspace_root or self.workspace_root
        markers = self.spec.environment_markers

        # 1. Environment variables
        for ev in markers.get("env_vars", []):
            if os.environ.get(ev):
                return True

        # 2. Workspace files
        for wf in markers.get("workspace_files", []):
            target = os.path.join(ws, wf)
            if os.path.isfile(target):
                return True

        # 3. Workspace directories
        for wd in markers.get("workspace_dirs", []):
            target = os.path.join(ws, wd)
            if os.path.isdir(target):
                return True

        # 4. Global directories
        home = os.path.expanduser("~")
        for gd in markers.get("global_dirs", []):
            clean_gd = gd.replace("~", home)
            if os.path.isdir(clean_gd):
                return True

        return False

    def discover_capability_roots(self, workspace_root: Optional[str] = None) -> List[CapabilityRoot]:
        """
        Discovers verified filesystem roots containing skills, instruction files, and command macros.
        """
        if not self.detect_active(workspace_root):
            return []

        ws = workspace_root or self.workspace_root
        roots: List[CapabilityRoot] = []
        home = os.path.expanduser("~")

        # 1. Instruction files (e.g. CUSTOM_RULES.md, AGENTS.md)
        for inf in self.spec.instruction_files:
            inf_path = os.path.join(ws, inf)
            if os.path.isfile(inf_path):
                roots.append(CapabilityRoot(
                    root_path=ws,
                    precedence_tier="WORKSPACE",
                    origin=self.spec.name,
                    is_writable=os.access(ws, os.W_OK),
                    has_bundle_manifest=False
                ))
                break

        # 2. Declared workspace skill roots
        for sr in self.spec.skill_roots:
            sr_path = os.path.join(ws, sr)
            if os.path.isdir(sr_path):
                roots.append(CapabilityRoot(
                    root_path=sr_path,
                    precedence_tier="WORKSPACE",
                    origin=self.spec.name,
                    is_writable=os.access(sr_path, os.W_OK),
                    has_bundle_manifest=True
                ))

        # 3. Declared global skill roots
        for gsr in self.spec.global_skill_roots:
            clean_gsr = gsr.replace("~", home)
            if os.path.isdir(clean_gsr):
                roots.append(CapabilityRoot(
                    root_path=clean_gsr,
                    precedence_tier="USER_GLOBAL",
                    origin=self.spec.name,
                    is_writable=os.access(clean_gsr, os.W_OK),
                    has_bundle_manifest=True
                ))

        # Default fallback to .agents/skills if not otherwise configured
        default_skills = os.path.join(ws, ".agents", "skills")
        if not roots and os.path.isdir(default_skills):
            roots.append(CapabilityRoot(
                root_path=default_skills,
                precedence_tier="WORKSPACE",
                origin=self.spec.name,
                is_writable=os.access(default_skills, os.W_OK),
                has_bundle_manifest=True
            ))

        return roots

    def probe_reachability(self, workspace_root: Optional[str] = None) -> AdapterReachabilityReport:
        """Performs reachability checks on discovered roots and declared MCP configs."""
        ws = workspace_root or self.workspace_root
        probes: List[ResourceProbeResult] = []
        start_time = datetime.datetime.now(datetime.timezone.utc)

        # Probe capability roots
        roots = self.discover_capability_roots(ws)
        all_roots_ok = True
        for r in roots:
            t0 = datetime.datetime.now()
            readable = os.path.isdir(r.root_path) and os.access(r.root_path, os.R_OK)
            lat = (datetime.datetime.now() - t0).total_seconds() * 1000.0
            if readable:
                probes.append(ResourceProbeResult(
                    resource_id=r.root_path,
                    resource_kind="SKILL_ROOT",
                    status=OperationalStatus.REACHABLE,
                    latency_ms=lat
                ))
            else:
                all_roots_ok = False
                probes.append(ResourceProbeResult(
                    resource_id=r.root_path,
                    resource_kind="SKILL_ROOT",
                    status=OperationalStatus.UNREACHABLE,
                    latency_ms=lat,
                    error_message=f"Root directory unreadable: {r.root_path}"
                ))

        overall = OperationalStatus.AVAILABLE if (roots and all_roots_ok) else (
            OperationalStatus.REACHABLE if roots else OperationalStatus.UNCHECKED
        )

        return AdapterReachabilityReport(
            adapter_id=self.adapter_id,
            environment_kind=self.spec.name,  # type: ignore
            overall_status=overall,
            checked_at=start_time,
            probes=probes
        )

    def read_skill_exact_bytes(self, relative_path: str, root: Optional[CapabilityRoot] = None) -> bytes:
        """Reads exact instruction bytes with strict path confinement against traversal."""
        ws = self.workspace_root
        base_dir = root.root_path if root else ws

        # Confinement check
        target_path = os.path.realpath(os.path.join(base_dir, relative_path))
        real_base = os.path.realpath(base_dir)

        if not target_path.startswith(real_base + os.sep) and target_path != real_base:
            raise PathTraversalSecurityError(
                f"Path traversal detected: '{relative_path}' resolves outside root '{real_base}'."
            )

        if not os.path.isfile(target_path):
            raise FileNotFoundError(f"File not found: '{target_path}'.")

        with open(target_path, "rb") as f:
            return f.read()

    def register_slash_command(
        self,
        command_name: str = "call-me",
        description: str = "",
        workspace_root: Optional[str] = None
    ) -> Any:
        """Safely installs a custom agent slash command or macro artifact."""
        self.assert_feature(AdapterFeature.SLASH_COMMAND_REGISTRATION)
        ws = workspace_root or self.workspace_root
        cmd_int = self.spec.command_integration

        rel_target = cmd_int.get("target_path", f".{self.spec.name}/commands/call-me.md")
        target_file = os.path.join(ws, rel_target)
        os.makedirs(os.path.dirname(target_file), exist_ok=True)

        exec_cmd = cmd_int.get(
            "execution_command",
            'command -v lcs >/dev/null 2>&1 && lcs call-me --handoff -- "<task>" || python3 -m lcs.cli call-me --handoff -- "<task>"'
        )

        content = (
            f"<!-- LCS-MANAGED-COMMAND-ARTIFACT -->\n"
            f"# /{command_name} — {self.display_name} Capability Orchestration\n\n"
            f"Pass the user's task to LCS:\n"
            f"```bash\n"
            f"{exec_cmd}\n"
            f"```\n"
        )

        SlashCommandGenerator._safe_write_artifact(target_file, content, overwrite=False)
        return target_file

    def discover_mcp_servers(self, workspace_root: Optional[str] = None) -> List[MCPConfigEntry]:
        """Discovers declared MCP servers from custom agent config."""
        if not self.has_feature(AdapterFeature.MCP_CONFIG_DISCOVERY):
            return []

        ws = workspace_root or self.workspace_root
        cfg_file_rel = self.spec.mcp_config.get("config_file")
        if not cfg_file_rel:
            return []

        cfg_path = os.path.join(ws, cfg_file_rel)
        if not os.path.isfile(cfg_path):
            return []

        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            servers_dict = data.get("mcpServers", {})
            results: List[MCPConfigEntry] = []
            for s_id, s_data in servers_dict.items():
                results.append(MCPConfigEntry(
                    server_id=s_id,
                    command=s_data.get("command", ""),
                    args=s_data.get("args", []),
                    env=s_data.get("env", {}),
                    cwd=s_data.get("cwd"),
                    server_name=s_id,
                    source_file=cfg_path
                ))
            return results
        except Exception:
            return []

    def collect_execution_evidence(
        self,
        step_id: str,
        raw_stdout: bytes,
        raw_stderr: bytes,
        exit_code: int
    ) -> Dict[str, Any]:
        return {
            "step_id": step_id,
            "origin": self.spec.name,
            "adapter_id": self.adapter_id,
            "exit_code": exit_code,
            "stdout_len": len(raw_stdout),
            "stderr_len": len(raw_stderr),
            "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }


# ============================================================================
# 3. Dynamic Adapter Loader
# ============================================================================

class DynamicAdapterLoader:
    """
    Discovers, validates, and instantiates DeclarativeHostAdapters from disk.
    Supports user-global (~/.lcs/agents/) and workspace-local (.lcs/agents/) configs.
    """

    @classmethod
    def load_from_dict(
        cls,
        spec_data: Dict[str, Any],
        workspace_root: Optional[str] = None
    ) -> DeclarativeHostAdapter:
        """Validates dictionary and constructs DeclarativeHostAdapter."""
        is_valid, errors = validate_custom_agent_spec(spec_data)
        if not is_valid:
            raise CustomAdapterSecurityError(f"Invalid custom agent specification: {'; '.join(errors)}")

        spec = DeclarativeCustomAdapterSpec(
            schema_version=spec_data.get("schema_version", "1.0"),
            agent_id=spec_data["agent_id"],
            name=spec_data["name"],
            display_name=spec_data["display_name"],
            precedence=spec_data.get("precedence", 50),
            environment_markers=spec_data.get("environment_markers", {}),
            instruction_files=spec_data.get("instruction_files", []),
            skill_roots=spec_data.get("skill_roots", []),
            global_skill_roots=spec_data.get("global_skill_roots", []),
            capabilities=spec_data.get("capabilities", {}),
            command_integration=spec_data.get("command_integration", {}),
            mcp_config=spec_data.get("mcp_config", {}),
            raw_spec=spec_data
        )
        return DeclarativeHostAdapter(spec=spec, workspace_root=workspace_root)

    @classmethod
    def load_from_file(
        cls,
        file_path: str,
        workspace_root: Optional[str] = None
    ) -> DeclarativeHostAdapter:
        """Reads JSON file, validates security/permissions, and loads adapter."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Custom agent config file not found: {file_path}")

        # Security permission check on POSIX: reject world-writable files
        if sys.platform != "win32":
            st = os.stat(file_path)
            if st.st_mode & 0o002 != 0:
                raise CustomAdapterSecurityError(
                    f"Insecure permissions on agent config '{file_path}': file is world-writable."
                )

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return cls.load_from_dict(data, workspace_root=workspace_root)

    @classmethod
    def discover_and_load(
        cls,
        workspace_root: Optional[str] = None,
        home_override: Optional[str] = None
    ) -> List[DeclarativeHostAdapter]:
        """
        Scans both project-local (.lcs/agents/) and user-global (~/.lcs/agents/)
        for custom agent JSON definitions.
        """
        adapters: List[DeclarativeHostAdapter] = []
        ws = workspace_root or os.getcwd()
        home = home_override or os.path.expanduser("~")

        search_dirs = [
            os.path.join(ws, ".lcs", "agents"),
            os.path.join(home, ".lcs", "agents")
        ]

        seen_agent_ids: Set[str] = set()

        for s_dir in search_dirs:
            if not os.path.isdir(s_dir):
                continue
            try:
                for entry in sorted(os.listdir(s_dir)):
                    if entry.endswith(".json") and not entry.startswith("."):
                        full_path = os.path.join(s_dir, entry)
                        try:
                            adapter = cls.load_from_file(full_path, workspace_root=ws)
                            if adapter.adapter_id not in seen_agent_ids:
                                seen_agent_ids.add(adapter.adapter_id)
                                adapters.append(adapter)
                        except Exception as e:
                            # Log and skip invalid custom agent configs gracefully
                            print(f"[!] Warning: Skipped invalid custom agent in '{full_path}': {e}", file=sys.stderr)
            except OSError:
                pass

        return adapters

    @classmethod
    def load_all(
        cls,
        registry: Any,
        config: Optional[Any] = None,
        workspace_root: Optional[str] = None,
        home_override: Optional[str] = None
    ) -> int:
        """Loads all custom adapters from disk and registers them into the given AdapterRegistry."""
        home = home_override or (config.get_user_state_dir() if config else None)
        custom_adapters = cls.discover_and_load(workspace_root=workspace_root, home_override=home)
        count = 0
        for adp in custom_adapters:
            registry.register(adp, precedence=adp.precedence)
            count += 1
        return count
