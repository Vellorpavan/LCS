"""
LCS OpenCode Environment Adapter
================================
Adapter for the open-source OpenCode manifest-driven agent harness:
- Parses opencode.json project configuration and instruction arrays.
- Discovers skills in .opencode/skills/ and commands in .opencode/commands/.
- Discovers MCP server configurations from opencode.json mcpServers.
- Registers /call-me command in opencode.json and .opencode/commands/.
- Gated: Process-based agent delegation is supported when configured.
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
    PathTraversalSecurityError
)
from .probes import LiveProbeEngine
from ..skills import SafeFileReader, MAX_INSTRUCTION_FILE_SIZE


class OpenCodeAdapter(EnvironmentAdapter):
    """
    Concrete adapter for OpenCode manifest-driven agent environments.
    """

    @property
    def adapter_id(self) -> str:
        return "adapter.opencode.v1"

    @property
    def environment_kind(self) -> EnvironmentKind:
        return EnvironmentKind.OPENCODE

    @property
    def display_name(self) -> str:
        return "OpenCode Environment Adapter"

    @property
    def declared_features(self) -> AdapterFeature:
        return (
            AdapterFeature.SLASH_COMMAND_REGISTRATION
            | AdapterFeature.SKILL_DISCOVERY
            | AdapterFeature.COMMAND_DISCOVERY
            | AdapterFeature.MCP_CONFIG_DISCOVERY
            | AdapterFeature.MCP_TOOL_INVOCATION
            | AdapterFeature.INTERACTIVE_TTY_CONSENT
        )

    def detect_active(self, workspace_root: Optional[str] = None) -> bool:
        """
        Detects OpenCode by checking for opencode.json or .opencode/ directory.
        """
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        return (
            os.path.isfile(os.path.join(real_ws, "opencode.json"))
            or os.path.isdir(os.path.join(real_ws, ".opencode"))
        )

    def discover_capability_roots(self, workspace_root: Optional[str] = None) -> List[CapabilityRoot]:
        """
        Discovers OpenCode roots from .opencode/skills, .opencode/commands,
        and instructions declared in opencode.json.
        """
        roots: List[CapabilityRoot] = []
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root

        candidates = [
            (os.path.join(real_ws, ".opencode", "skills"), "WORKSPACE", True),
            (os.path.join(real_ws, ".opencode", "commands"), "WORKSPACE", True),
        ]

        # Check declared instructions in opencode.json
        manifest_path = os.path.join(real_ws, "opencode.json")
        if os.path.isfile(manifest_path):
            candidates.append((real_ws, "WORKSPACE", True))
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                instructions = data.get("instructions", [])
                if isinstance(instructions, list):
                    for inst in instructions:
                        if isinstance(inst, str) and os.path.isabs(inst) and os.path.isdir(inst):
                            candidates.append((os.path.realpath(inst), "HOST", False))
            except Exception:
                pass

        visited = set()
        for c_path, tier, writable in candidates:
            if c_path in visited:
                continue
            visited.add(c_path)
            if os.path.exists(c_path) and os.path.isdir(c_path):
                roots.append(CapabilityRoot(
                    root_path=c_path,
                    precedence_tier=tier,
                    origin="opencode",
                    is_writable=writable and os.access(c_path, os.W_OK)
                ))

        return roots

    def discover_mcp_servers(self, workspace_root: Optional[str] = None) -> List[MCPConfigEntry]:
        """
        Parses mcpServers from opencode.json.
        """
        self.assert_feature(AdapterFeature.MCP_CONFIG_DISCOVERY)
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        manifest_path = os.path.join(real_ws, "opencode.json")
        if not os.path.isfile(manifest_path):
            return []

        servers: List[MCPConfigEntry] = []
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            mcp_section = data.get("mcpServers")
            if not mcp_section and isinstance(data.get("mcp"), dict):
                mcp_section = data.get("mcp", {}).get("servers")
            mcp_section = mcp_section or {}
            if isinstance(mcp_section, dict):
                for s_id, s_conf in mcp_section.items():
                    if not isinstance(s_conf, dict):
                        continue
                    cmd = s_conf.get("command")
                    if not cmd:
                        continue
                    if isinstance(cmd, list):
                        exec_cmd = cmd[0] if cmd else ""
                        exec_args = cmd[1:] + s_conf.get("args", [])
                    else:
                        exec_cmd = cmd
                        exec_args = s_conf.get("args", [])
                    servers.append(MCPConfigEntry(
                        server_id=f"opencode:{s_id}",
                        server_name=s_id,
                        command=exec_cmd,
                        args=exec_args,
                        env=s_conf.get("env", {}),
                        cwd=s_conf.get("cwd") or real_ws,
                        source_file=manifest_path
                    ))
        except Exception:
            pass

        return servers

    def probe_reachability(self, workspace_root: Optional[str] = None) -> AdapterReachabilityReport:
        """Actively checks OpenCode roots and configured MCP servers."""
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        probes = []
        for r in self.discover_capability_roots(real_ws):
            probes.append(LiveProbeEngine.probe_skill_root(r))
        for s in self.discover_mcp_servers(real_ws):
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
        Installs or updates command in .opencode/commands/<command_name>.md and opencode.json.
        """
        self.assert_feature(AdapterFeature.SLASH_COMMAND_REGISTRATION)
        if os.path.isabs(command_name) or (os.path.isdir(command_name) if command_name else False):
            real_ws = os.path.realpath(command_name)
            cmd = description or "call-me"
        else:
            real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
            cmd = command_name or "call-me"

        clean_cmd = cmd.lstrip("/").strip()
        if not re.match(r"^[a-zA-Z0-9_\-]+$", clean_cmd):
            raise PathTraversalSecurityError(
                f"Invalid command name '{clean_cmd}': must contain only alphanumeric characters, dashes, or underscores."
            )

        cmds_dir = os.path.realpath(os.path.join(real_ws, ".opencode", "commands"))
        cmd_file = os.path.realpath(os.path.join(cmds_dir, f"{clean_cmd}.md"))
        if not (cmd_file.startswith(cmds_dir + os.sep)):
            raise PathTraversalSecurityError(
                f"Path traversal detected in command name: '{clean_cmd}'"
            )
        os.makedirs(cmds_dir, exist_ok=True)

        with open(cmd_file, "w", encoding="utf-8") as f:
            f.write(f"# Command: {clean_cmd}\nExecute LCS capability orchestration.\n")

        # Also add to opencode.json if writable
        manifest_path = os.path.join(real_ws, "opencode.json")
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                cmds = data.setdefault("commands", {})
                if isinstance(cmds, dict):
                    cmds[f"/{clean_cmd}"] = f".opencode/commands/{clean_cmd}.md"
                with open(manifest_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception:
                pass

        return {
            "success": True,
            "command": f"/{clean_cmd}",
            "macro_file": cmd_file
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

    def request_approver_consent(
        self,
        capability_urn: str,
        action_summary: str,
        parameters: Dict[str, Any],
        required_role: str
    ) -> bool:
        """Terminal prompt consent."""
        self.assert_feature(AdapterFeature.INTERACTIVE_TTY_CONSENT)
        if not sys.stdin.isatty():
            return False
        try:
            print(f"\n[OPENCODE GOVERNANCE] Approve '{capability_urn}' as {required_role}?")
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
        """Normalized execution evidence for OpenCode."""
        return {
            "step_id": step_id,
            "environment": self.environment_kind.value,
            "exit_code": exit_code,
            "stdout_length": len(raw_stdout),
            "stderr_length": len(raw_stderr),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
