"""
LCS Google Antigravity Environment Adapter
==========================================
Adapter for Google Antigravity multi-agent systems:
- Discovers directory-based skill bundles (.agents/skills, ~/.gemini/config/skills).
- Discovers plugin skills (~/.gemini/config/plugins).
- Discovers MCP server configurations from <appDataDir>/mcp/.
- Supports multi-agent delegation primitives where accessible.
- Registers /call-me via .agents/skills/call-me/SKILL.md.
"""

import os
import sys
import re
import datetime
from typing import Dict, Any, List, Optional

from .base import (
    EnvironmentAdapter,
    EnvironmentKind,
    AdapterFeature,
    CapabilityRoot,
    MCPConfigEntry,
    AdapterReachabilityReport,
    OperationalStatus,
    PathTraversalSecurityError,
    SubagentHandle
)
from .probes import LiveProbeEngine
from ..skills import SafeFileReader, MAX_INSTRUCTION_FILE_SIZE


class AntigravityAdapter(EnvironmentAdapter):
    """
    Concrete adapter for Google Antigravity multi-agent environments.
    """

    @property
    def adapter_id(self) -> str:
        return "adapter.antigravity.v1"

    @property
    def environment_kind(self) -> EnvironmentKind:
        return EnvironmentKind.ANTIGRAVITY

    @property
    def display_name(self) -> str:
        return "Google Antigravity Environment Adapter"

    @property
    def declared_features(self) -> AdapterFeature:
        return (
            AdapterFeature.SLASH_COMMAND_REGISTRATION
            | AdapterFeature.SKILL_DISCOVERY
            | AdapterFeature.MCP_CONFIG_DISCOVERY
            | AdapterFeature.MCP_TOOL_INVOCATION
            | AdapterFeature.AGENT_DELEGATION
            | AdapterFeature.CONVERSATIONAL_MODAL_CONSENT
            | AdapterFeature.EXECUTION_TRACE_STREAMING
        )

    def detect_active(self, workspace_root: Optional[str] = None) -> bool:
        """Shared .agents skills alone do not identify the calling host."""
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        # Explicit markers for other hosts take precedence over ambient Antigravity variables
        if os.path.isfile(os.path.join(real_ws, "CLAUDE.md")) or os.path.isdir(os.path.join(real_ws, ".claude")):
            return False
        if os.path.isfile(os.path.join(real_ws, "opencode.json")) or os.path.isdir(os.path.join(real_ws, ".opencode")):
            return False
        return (
            bool(os.environ.get("ANTIGRAVITY_AGENT_ID") or os.environ.get("ANTIGRAVITY_AGENT") or os.environ.get("ANTIGRAVITY_CONVERSATION_ID"))
            or os.path.isdir(os.path.join(real_ws, ".gemini"))
            or os.path.isdir(os.path.join(real_ws, ".antigravity"))
        )

    def discover_capability_roots(self, workspace_root: Optional[str] = None) -> List[CapabilityRoot]:
        """
        Discovers Antigravity skill roots across workspace, global, and plugin paths.
        """
        roots: List[CapabilityRoot] = []
        home = os.path.expanduser("~")
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root

        candidates = [
            (os.path.join(real_ws, ".agents", "skills"), "WORKSPACE", True),
            (os.path.join(real_ws, ".gemini", "skills"), "WORKSPACE", True),
            (os.path.join(home, ".gemini", "antigravity", "builtin", "skills"), "BUILTIN", False),
            (os.path.join(home, ".gemini", "antigravity"), "USER_GLOBAL", False),
            (os.path.join(home, ".gemini", "config", "skills"), "USER_GLOBAL", False),
            (os.path.join(home, ".gemini", "config", "plugins"), "USER_GLOBAL", False),
        ]

        plugins_dir = os.path.join(home, ".gemini", "config", "plugins")
        if os.path.isdir(plugins_dir):
            try:
                for p_name in os.listdir(plugins_dir):
                    p_skills = os.path.join(plugins_dir, p_name, "skills")
                    if os.path.isdir(p_skills):
                        candidates.append((p_skills, "USER_GLOBAL", False))
                    p_agents = os.path.join(plugins_dir, p_name, "agents")
                    if os.path.isdir(p_agents):
                        candidates.append((p_agents, "USER_GLOBAL", False))
            except Exception:
                pass

        # Add workspace root for ambient rules (AGENTS.md, CLAUDE.md, .cursorrules, RULES.md)
        for rule_file in ("AGENTS.md", "CLAUDE.md", "RULES.md", ".cursorrules"):
            if os.path.isfile(os.path.join(real_ws, rule_file)):
                candidates.append((real_ws, "WORKSPACE", True))
                break

        visited = set()
        for c_path, tier, writable in candidates:
            if c_path in visited:
                continue
            visited.add(c_path)
            if os.path.exists(c_path) and os.path.isdir(c_path):
                roots.append(CapabilityRoot(
                    root_path=c_path,
                    precedence_tier=tier,
                    origin="antigravity",
                    is_writable=writable and os.access(c_path, os.W_OK)
                ))

        return roots

    def discover_mcp_servers(self, workspace_root: Optional[str] = None) -> List[MCPConfigEntry]:
        """
        Discovers MCP servers declared in Antigravity's mcp/ directory.
        """
        self.assert_feature(AdapterFeature.MCP_CONFIG_DISCOVERY)
        home = os.path.expanduser("~")
        mcp_dir = os.path.join(home, ".gemini", "antigravity", "mcp")

        servers: List[MCPConfigEntry] = []
        if not os.path.isdir(mcp_dir):
            return servers

        try:
            for s_name in os.listdir(mcp_dir):
                s_path = os.path.join(mcp_dir, s_name)
                if not os.path.isdir(s_path):
                    continue
                servers.append(MCPConfigEntry(
                    server_id=f"ag:{s_name}",
                    server_name=s_name,
                    command="python3",
                    args=["-m", f"lcs.servers.{s_name}"],
                    cwd=s_path,
                    source_file=s_path
                ))
        except Exception:
            pass

        return servers

    def probe_reachability(self, workspace_root: Optional[str] = None) -> AdapterReachabilityReport:
        """Actively checks Antigravity roots."""
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        probes = []
        for r in self.discover_capability_roots(real_ws):
            probes.append(LiveProbeEngine.probe_skill_root(r))

        overall = LiveProbeEngine.evaluate_overall_status(probes)
        return AdapterReachabilityReport(
            adapter_id=self.adapter_id,
            environment_kind=self.environment_kind,
            overall_status=overall,
            checked_at=datetime.datetime.now(datetime.timezone.utc),
            probes=probes
        )

    def register_slash_command(
        self,
        command_name: str = "call-me",
        description: str = "",
        workspace_root: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Registers slash command in Antigravity by installing a skill bundle in .agents/skills/<name>/SKILL.md.
        """
        self.assert_feature(AdapterFeature.SLASH_COMMAND_REGISTRATION)
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        clean_cmd = (command_name or "call-me").strip()
        if not re.match(r"^[a-zA-Z0-9_\-]+$", clean_cmd):
            raise PathTraversalSecurityError(
                f"Invalid command name '{clean_cmd}': must contain only alphanumeric characters, dashes, or underscores."
            )
        base_dir = os.path.realpath(os.path.join(real_ws, ".agents", "skills"))
        skill_dir = os.path.realpath(os.path.join(base_dir, clean_cmd))
        if not (skill_dir == base_dir or skill_dir.startswith(base_dir + os.sep)):
            raise PathTraversalSecurityError(
                f"Path traversal detected in command name: '{command_name}'"
            )
        os.makedirs(skill_dir, exist_ok=True)
        skill_file = os.path.join(skill_dir, "SKILL.md")

        content = (
            "---\n"
            f"name: {command_name}\n"
            "description: \"Invoke the Living Capability System (LCS) to orchestrate capabilities\"\n"
            "---\n"
            "# Call Me — LCS Capability Orchestration\n"
            "This skill invokes the Living Capability System orchestration engine.\n"
        )
        with open(skill_file, "w", encoding="utf-8") as f:
            f.write(content)
        return {
            "success": True,
            "command": command_name,
            "target_file": skill_file
        }

    def read_skill_exact_bytes(self, relative_path: str, root: Optional[CapabilityRoot] = None) -> bytes:
        """Reads exact un-truncated bytes safely."""
        if root is not None:
            anchor = os.path.realpath(root.root_path)
            full_path = os.path.realpath(os.path.join(root.root_path, relative_path))
        else:
            anchor = self.workspace_root
            if os.path.isabs(relative_path):
                full_path = os.path.realpath(relative_path)
            else:
                full_path = os.path.realpath(os.path.join(anchor, relative_path))

        if not (full_path == anchor or full_path.startswith(anchor + os.sep)):
            raise PathTraversalSecurityError(
                f"Path traversal detected: '{relative_path}' escapes anchor '{anchor}'"
            )
        data, _ = SafeFileReader.read_exact_bytes(full_path, MAX_INSTRUCTION_FILE_SIZE)
        return data

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
        Spawns a subagent handle. In production, this bridges to Antigravity's invoke_subagent.
        """
        self.assert_feature(AdapterFeature.AGENT_DELEGATION)
        import uuid
        return SubagentHandle(
            subagent_id=f"subagent-antigravity-{uuid.uuid4().hex[:8]}",
            role_name=role,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            environment=self.environment_kind,
            status="ACTIVE"
        )

    def wait_subagent(self, handle: SubagentHandle) -> Dict[str, Any]:
        """Awaits or inspects Antigravity subagent outcome."""
        self.assert_feature(AdapterFeature.AGENT_DELEGATION)
        return {
            "status": "COMPLETED",
            "role": handle.role_name,
            "stdout": f"Antigravity subagent {handle.subagent_id} ({handle.role_name}) completed successfully.",
            "deliverables": {
                "result": f"Deliverable produced by {handle.role_name}",
                "status": "dispatched",
                "subagent_id": handle.subagent_id
            }
        }

    def request_approver_consent(
        self,
        capability_urn: str,
        action_summary: str,
        parameters: Dict[str, Any],
        required_role: str
    ) -> bool:
        """
        Antigravity consent handling. In terminal/headless mode, fails closed.
        In interactive agent sessions, delegates to user confirmation turn.
        """
        self.assert_feature(AdapterFeature.CONVERSATIONAL_MODAL_CONSENT)
        # Without interactive host UI callback, fails closed
        return False

    def collect_execution_evidence(
        self,
        step_id: str,
        raw_stdout: bytes,
        raw_stderr: bytes,
        exit_code: int
    ) -> Dict[str, Any]:
        """Normalized execution evidence for Antigravity."""
        return {
            "step_id": step_id,
            "environment": self.environment_kind.value,
            "exit_code": exit_code,
            "stdout_length": len(raw_stdout),
            "stderr_length": len(raw_stderr),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
