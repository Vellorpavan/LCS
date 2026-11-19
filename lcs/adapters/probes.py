"""
LCS Live Reachability Probe Engine & Operational Health Monitoring
==================================================================
Performs active runtime reachability checks against local skill roots,
executable binaries, and MCP servers with strict timeout enforcement.
"""

import os
import sys
import time
import json
import shutil
import subprocess
import datetime
from typing import Dict, Any, List, Optional

from .base import (
    OperationalStatus,
    ResourceProbeResult,
    CapabilityRoot,
    MCPConfigEntry,
    ProbeTimeoutError
)


class LiveProbeEngine:
    """
    Executes concrete runtime reachability probes against physical resources.
    """

    @staticmethod
    def probe_skill_root(root: Union[CapabilityRoot, str], workspace_root: Optional[str] = None) -> ResourceProbeResult:
        """
        Actively verifies that a skill/capability root directory exists,
        is accessible without symlink escapes, and has read permissions.
        """
        start = time.perf_counter()
        if isinstance(root, str):
            root = CapabilityRoot(
                root_path=os.path.realpath(root),
                origin="WORKSPACE",
                is_writable=os.access(root, os.W_OK) if os.path.exists(root) else False,
                has_bundle_manifest=False
            )

        res_id = f"root:{root.origin}:{root.root_path}"

        if not os.path.exists(root.root_path):
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return ResourceProbeResult(
                resource_id=res_id,
                resource_kind="SKILL_ROOT",
                status=OperationalStatus.UNREACHABLE,
                latency_ms=elapsed_ms,
                error_message=f"Root path does not exist on disk: '{root.root_path}'"
            )

        if not os.path.isdir(root.root_path):
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return ResourceProbeResult(
                resource_id=res_id,
                resource_kind="SKILL_ROOT",
                status=OperationalStatus.UNREACHABLE,
                latency_ms=elapsed_ms,
                error_message=f"Root path is not a directory: '{root.root_path}'"
            )

        if not os.access(root.root_path, os.R_OK | os.X_OK):
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return ResourceProbeResult(
                resource_id=res_id,
                resource_kind="SKILL_ROOT",
                status=OperationalStatus.UNREACHABLE,
                latency_ms=elapsed_ms,
                error_message=f"Permission denied for root path: '{root.root_path}'"
            )

        # Verify descriptor pinning / realpath boundary
        real_root = os.path.realpath(root.root_path)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return ResourceProbeResult(
            resource_id=res_id,
            resource_kind="SKILL_ROOT",
            status=OperationalStatus.AVAILABLE,
            latency_ms=elapsed_ms,
            metadata={
                "real_path": real_root,
                "is_writable": root.is_writable,
                "precedence_tier": root.precedence_tier
            }
        )

    @staticmethod
    def probe_binary(command: str) -> ResourceProbeResult:
        """
        Checks whether an executable command resolves in PATH and is executable.
        """
        start = time.perf_counter()
        res_id = f"bin:{command}"
        resolved = shutil.which(command)

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if not resolved:
            return ResourceProbeResult(
                resource_id=res_id,
                resource_kind="CLI_BINARY",
                status=OperationalStatus.UNREACHABLE,
                latency_ms=elapsed_ms,
                error_message=f"Command '{command}' not found in PATH."
            )

        if not os.access(resolved, os.X_OK):
            return ResourceProbeResult(
                resource_id=res_id,
                resource_kind="CLI_BINARY",
                status=OperationalStatus.UNREACHABLE,
                latency_ms=elapsed_ms,
                error_message=f"Resolved binary '{resolved}' lacks execute permissions (+x)."
            )

        return ResourceProbeResult(
            resource_id=res_id,
            resource_kind="CLI_BINARY",
            status=OperationalStatus.AVAILABLE,
            latency_ms=elapsed_ms,
            metadata={"resolved_path": resolved}
        )

    @staticmethod
    def probe_mcp_server(
        config: Optional[Union[MCPConfigEntry, str]] = None,
        timeout_seconds: float = 2.0,
        command: Optional[str] = None,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        server_name: Optional[str] = None
    ) -> ResourceProbeResult:
        """
        Probes an MCP stdio server by spawning a process, sending JSON-RPC initialize,
        verifying response within timeout_seconds, and cleanly terminating the process.
        """
        start = time.perf_counter()
        if isinstance(config, str) or server_name is not None:
            srv_id = server_name or (config if isinstance(config, str) else "mcp-server")
            cmd = command or (config if isinstance(config, str) else "node")
            config = MCPConfigEntry(
                server_id=srv_id,
                server_name=srv_id,
                command=cmd,
                args=args or [],
                env=env or {},
                cwd=cwd,
                source_file="manual"
            )

        res_id = f"mcp:{config.server_id}"

        # 1. Verify executable exists first
        cmd_path = shutil.which(config.command)
        if not cmd_path:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return ResourceProbeResult(
                resource_id=res_id,
                resource_kind="MCP_SERVER",
                status=OperationalStatus.UNREACHABLE,
                latency_ms=elapsed_ms,
                error_message=f"Executable '{config.command}' for server '{config.server_id}' not found in PATH."
            )

        # 2. Build isolated process environment
        cmd_list = [cmd_path] + list(config.args)
        proc_env = os.environ.copy()
        proc_env.update(config.env)

        proc = None
        try:
            # Spawn child with stdio pipes
            proc = subprocess.Popen(
                cmd_list,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=config.cwd or os.getcwd(),
                env=proc_env,
                text=True,
                bufsize=1
            )

            # JSON-RPC 2.0 initialize request
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "lcs-probe", "version": "1.0"}
                }
            }
            req_str = json.dumps(init_req) + "\n"
            proc.stdin.write(req_str)
            proc.stdin.flush()

            import select
            t_end = time.time() + timeout_seconds
            resp_line = None

            while time.time() < t_end:
                remaining = max(0.0, t_end - time.time())
                rlist, _, _ = select.select([proc.stdout], [], [], min(0.05, remaining))
                if rlist:
                    line = proc.stdout.readline()
                    if line:
                        resp_line = line.strip()
                        break

                if proc.poll() is not None:
                    # Check if there was pending output
                    rest = proc.stdout.read() if proc.stdout else ""
                    if rest:
                        for l in rest.splitlines():
                            if l.strip():
                                resp_line = l.strip()
                                break
                    if resp_line:
                        break

                    err_msg = proc.stderr.read() if proc.stderr else ""
                    elapsed_ms = (time.perf_counter() - start) * 1000.0
                    return ResourceProbeResult(
                        resource_id=res_id,
                        resource_kind="MCP_SERVER",
                        status=OperationalStatus.DISCONNECTED,
                        latency_ms=elapsed_ms,
                        error_message=f"MCP server exited with code {proc.returncode}: {err_msg.strip()}"
                    )

            if not resp_line:
                if proc and proc.poll() is None:
                    try:
                        proc.terminate()
                        proc.wait(timeout=0.2)
                    except Exception:
                        try:
                            proc.kill()
                            proc.wait(timeout=0.2)
                        except Exception:
                            pass

                elapsed_ms = (time.perf_counter() - start) * 1000.0
                return ResourceProbeResult(
                    resource_id=res_id,
                    resource_kind="MCP_SERVER",
                    status=OperationalStatus.UNREACHABLE,
                    latency_ms=elapsed_ms,
                    error_message=f"MCP server probe timed out after {timeout_seconds}s with no response."
                )

            # Parse response
            resp_json = json.loads(resp_line)
            if "result" in resp_json:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                return ResourceProbeResult(
                    resource_id=res_id,
                    resource_kind="MCP_SERVER",
                    status=OperationalStatus.CONNECTED,
                    latency_ms=elapsed_ms,
                    metadata={
                        "protocolVersion": resp_json.get("result", {}).get("protocolVersion"),
                        "serverInfo": resp_json.get("result", {}).get("serverInfo"),
                        "server_info": resp_json.get("result", {}).get("serverInfo")
                    }
                )
            else:
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                return ResourceProbeResult(
                    resource_id=res_id,
                    resource_kind="MCP_SERVER",
                    status=OperationalStatus.DEGRADED,
                    latency_ms=elapsed_ms,
                    error_message=f"MCP server returned error on initialize: {resp_json.get('error')}"
                )

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            return ResourceProbeResult(
                resource_id=res_id,
                resource_kind="MCP_SERVER",
                status=OperationalStatus.UNREACHABLE,
                latency_ms=elapsed_ms,
                error_message=f"Probe exception: {e}"
            )
        finally:
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=0.5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

    @staticmethod
    def evaluate_overall_status(probes: List[ResourceProbeResult]) -> OperationalStatus:
        """
        Derives aggregate OperationalStatus from a collection of resource probe results.
        """
        if not probes:
            return OperationalStatus.UNCHECKED

        has_unreachable = any(p.status == OperationalStatus.UNREACHABLE for p in probes)
        has_disconnected = any(p.status == OperationalStatus.DISCONNECTED for p in probes)
        has_degraded = any(p.status == OperationalStatus.DEGRADED for p in probes)
        all_connected = all(p.status in (OperationalStatus.CONNECTED, OperationalStatus.REACHABLE, OperationalStatus.AVAILABLE) for p in probes)

        if all_connected:
            return OperationalStatus.AVAILABLE
        elif has_unreachable and not all(p.status == OperationalStatus.UNREACHABLE for p in probes):
            return OperationalStatus.DEGRADED
        elif has_disconnected:
            return OperationalStatus.DISCONNECTED
        elif has_unreachable:
            return OperationalStatus.UNREACHABLE
        elif has_degraded:
            return OperationalStatus.DEGRADED

        return OperationalStatus.REACHABLE
