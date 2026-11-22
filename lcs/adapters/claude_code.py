"""
LCS Claude Code Environment Adapter
===================================
Adapter for Anthropic's Claude Code CLI environment:
- Discovers single-file slash commands (.claude/commands/*.md).
- Discovers ambient rules (CLAUDE.md, .claude/rules/*.md).
- Discovers skills in ~/.claude/skills/.
- Parses MCP server configurations from claude.json and ~/.claude/config.json.
- Installs / updates the /call-me command macro template.
- Gated: External subagent delegation is explicitly UNSUPPORTED.
"""

import os
import sys
import re
import json
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
    UnsupportedAdapterFeatureError
)
from .probes import LiveProbeEngine
from ..skills import SafeFileReader, MAX_INSTRUCTION_FILE_SIZE


class ClaudeCodeAdapter(EnvironmentAdapter):
    """
    Concrete adapter for Claude Code CLI agent environments.
    """

    @property
    def adapter_id(self) -> str:
        return "adapter.claude_code.v1"

    @property
    def environment_kind(self) -> EnvironmentKind:
        return EnvironmentKind.CLAUDE_CODE

    @property
    def display_name(self) -> str:
        return "Claude Code Environment Adapter"

    @property
    def declared_features(self) -> AdapterFeature:
        return (
            AdapterFeature.SLASH_COMMAND_REGISTRATION
            | AdapterFeature.SKILL_DISCOVERY
            | AdapterFeature.COMMAND_DISCOVERY
            | AdapterFeature.RULE_DISCOVERY
            | AdapterFeature.MCP_CONFIG_DISCOVERY
            | AdapterFeature.MCP_TOOL_INVOCATION
            | AdapterFeature.INTERACTIVE_TTY_CONSENT
            | AdapterFeature.EXECUTION_TRACE_STREAMING
        )

    def detect_active(self, workspace_root: Optional[str] = None) -> bool:
        """
        Detects Claude Code by inspecting workspace or active process markers:
        - .claude/ directory in workspace
        - CLAUDE.md file in workspace
        - CLAUDE_CODE_ENTRYPOINT environment variable
        """
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        return (
            os.path.isdir(os.path.join(real_ws, ".claude"))
            or os.path.isfile(os.path.join(real_ws, "CLAUDE.md"))
            or bool(os.environ.get("CLAUDE_CODE_ENTRYPOINT"))
        )

    def discover_capability_roots(self, workspace_root: Optional[str] = None) -> List[CapabilityRoot]:
        """
        Discovers Claude Code command, rule, and skill roots.
        """
        roots: List[CapabilityRoot] = []
        home = os.path.expanduser("~")
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root

        candidates = [
            (os.path.join(real_ws, ".claude", "commands"), "WORKSPACE", True),
            (os.path.join(real_ws, ".claude", "rules"), "WORKSPACE", True),
            (os.path.join(real_ws, ".claude", "skills"), "WORKSPACE", True),
            (os.path.join(home, ".claude", "commands"), "USER_GLOBAL", False),
            (os.path.join(home, ".claude", "rules"), "USER_GLOBAL", False),
            (os.path.join(home, ".claude", "skills"), "USER_GLOBAL", False),
        ]

        # Add root CLAUDE.md parent if present
        if os.path.isfile(os.path.join(real_ws, "CLAUDE.md")):
            candidates.append((real_ws, "WORKSPACE", True))

        visited = set()
        for c_path, tier, writable in candidates:
            if c_path in visited:
                continue
            visited.add(c_path)
            if os.path.exists(c_path) and os.path.isdir(c_path):
                roots.append(CapabilityRoot(
                    root_path=c_path,
                    precedence_tier=tier,
                    origin="claude_code",
                    is_writable=writable and os.access(c_path, os.W_OK)
                ))

        return roots

    def discover_mcp_servers(self, workspace_root: Optional[str] = None) -> List[MCPConfigEntry]:
        """
        Parses MCP server configuration from claude.json, .claude.json, ~/.claude/config.json,
        or .claude/mcp.json.
        """
        self.assert_feature(AdapterFeature.MCP_CONFIG_DISCOVERY)
        home = os.path.expanduser("~")
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        config_files = [
            os.path.join(real_ws, "claude.json"),
            os.path.join(real_ws, ".claude.json"),
            os.path.join(real_ws, ".claude", "mcp.json"),
            os.path.join(home, ".claude", "config.json"),
            os.path.join(home, ".claude", "mcp.json"),
        ]

        servers: List[MCPConfigEntry] = []
        visited_ids = set()

        for cfg_path in config_files:
            if not os.path.isfile(cfg_path):
                continue
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                mcp_section = data.get("mcpServers") or data.get("mcp_servers") or {}
                if isinstance(mcp_section, dict):
                    for s_id, s_conf in mcp_section.items():
                        if s_id in visited_ids or not isinstance(s_conf, dict):
                            continue
                        cmd = s_conf.get("command")
                        if not cmd:
                            continue
                        visited_ids.add(s_id)
                        servers.append(MCPConfigEntry(
                            server_id=f"claude:{s_id}",
                            server_name=s_id,
                            command=cmd,
                            args=s_conf.get("args", []),
                            env=s_conf.get("env", {}),
                            cwd=s_conf.get("cwd") or real_ws,
                            source_file=cfg_path
                        ))
            except Exception:
                continue

        return servers

    def probe_reachability(self, workspace_root: Optional[str] = None) -> AdapterReachabilityReport:
        """
        Actively checks roots and configured MCP servers.
        """
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        probes = []
        roots = self.discover_capability_roots(real_ws)
        for r in roots:
            probes.append(LiveProbeEngine.probe_skill_root(r))

        servers = self.discover_mcp_servers(real_ws)
        for s in servers:
            probes.append(LiveProbeEngine.probe_mcp_server(s, timeout_seconds=2.0))

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
        Installs or updates the Claude Code command macro in .claude/commands/<command_name>.md.
        """
        self.assert_feature(AdapterFeature.SLASH_COMMAND_REGISTRATION)
        if os.path.isabs(command_name) or (os.path.isdir(command_name) if command_name else False):
            real_ws = os.path.realpath(command_name)
            cmd = description or "call-me"
            desc = "Invoke the Living Capability System (LCS) to orchestrate capabilities"
        else:
            real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
            cmd = command_name or "call-me"
            desc = description or "Invoke the Living Capability System (LCS) to orchestrate capabilities"

        clean_cmd = cmd.strip()
        if not re.match(r"^[a-zA-Z0-9_\-]+$", clean_cmd):
            raise PathTraversalSecurityError(
                f"Invalid command name '{clean_cmd}': must contain only alphanumeric characters, dashes, or underscores."
            )

        cmds_dir = os.path.realpath(os.path.join(real_ws, ".claude", "commands"))
        cmd_file = os.path.realpath(os.path.join(cmds_dir, f"{clean_cmd}.md"))
        if not (cmd_file.startswith(cmds_dir + os.sep)):
            raise PathTraversalSecurityError(
                f"Path traversal detected in command name: '{clean_cmd}'"
            )
        os.makedirs(cmds_dir, exist_ok=True)

        content = (
            "---\n"
            f"name: {clean_cmd}\n"
            f"description: \"{desc}\"\n"
            "---\n"
            f"Please run LCS orchestration for the following task: $ARGUMENTS\n"
        )
        with open(cmd_file, "w", encoding="utf-8") as f:
            f.write(content)
        return {
            "success": True,
            "command": cmd,
            "target_file": cmd_file
        }

    def read_skill_exact_bytes(self, relative_path: str, root: Optional[CapabilityRoot] = None) -> bytes:
        """Reads exact instruction bytes safely."""
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

    def request_approver_consent(
        self,
        capability_urn: str,
        action_summary: str,
        parameters: Dict[str, Any],
        required_role: str
    ) -> bool:
        """Prompts for consent via interactive terminal if available."""
        self.assert_feature(AdapterFeature.INTERACTIVE_TTY_CONSENT)
        if not sys.stdin.isatty():
            return False
        try:
            print(f"\n[CLAUDE CODE GOVERNANCE] Approve '{capability_urn}' as {required_role}?")
            print(f"Action: {action_summary}")
            ans = input("Proceed? [y/N]: ").strip().lower()
            return ans in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    def collect_execution_evidence(
        self,
        step_id: str,
        raw_stdout: bytes,
        raw_stderr: bytes,
        exit_code: int
    ) -> Dict[str, Any]:
        """Normalized execution evidence for Claude Code."""
        return {
            "step_id": step_id,
            "environment": self.environment_kind.value,
            "exit_code": exit_code,
            "stdout_length": len(raw_stdout),
            "stderr_length": len(raw_stderr),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
