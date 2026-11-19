"""
LCS Generic POSIX Environment Adapter
=====================================
Universal fallback adapter implementing capabilities genuinely available
through the local operating system (macOS / Linux POSIX):
- Filesystem discovery from LCS_SKILL_PATHS and local workspace roots.
- Exact instruction retrieval with POSIX descriptor pinning.
- Safe reachability checks and executable discovery.
- Interactive TTY approver consent.
- Normalized execution evidence collection.
"""

import os
import sys
import datetime
from typing import Dict, Any, List, Optional

from .base import (
    EnvironmentAdapter,
    EnvironmentKind,
    AdapterFeature,
    CapabilityRoot,
    AdapterReachabilityReport,
    OperationalStatus,
    PathTraversalSecurityError
)
from .probes import LiveProbeEngine
from ..skills import SafeFileReader, DiscoveryRootResolver, MAX_INSTRUCTION_FILE_SIZE


class GenericPOSIXAdapter(EnvironmentAdapter):
    """
    Standard POSIX environment adapter running on any compliant UNIX/macOS system.
    """

    @property
    def adapter_id(self) -> str:
        return "adapter.generic_posix.v1"

    @property
    def environment_kind(self) -> EnvironmentKind:
        return EnvironmentKind.GENERIC_POSIX

    @property
    def display_name(self) -> str:
        return "Generic POSIX Environment Adapter"

    @property
    def declared_features(self) -> AdapterFeature:
        return (
            AdapterFeature.SKILL_DISCOVERY
            | AdapterFeature.MCP_TOOL_INVOCATION
            | AdapterFeature.INTERACTIVE_TTY_CONSENT
        )

    def detect_active(self, workspace_root: Optional[str] = None) -> bool:
        """Generic POSIX adapter is always available as the universal fallback."""
        return True

    def discover_capability_roots(self, workspace_root: Optional[str] = None) -> List[CapabilityRoot]:
        """
        Discovers capability roots from LCS_SKILL_PATHS environment variable
        and standard local workspace convention directories.
        """
        roots: List[CapabilityRoot] = []
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root

        # 1. Standard workspace skill roots
        candidates = [
            (os.path.join(real_ws, ".agents", "skills"), "WORKSPACE", True),
            (os.path.join(real_ws, "skills"), "WORKSPACE", True),
        ]

        # 2. Inspect environment variable LCS_SKILL_PATHS
        env_paths = os.environ.get("LCS_SKILL_PATHS", "")
        if env_paths:
            for p in env_paths.split(os.pathsep):
                p = p.strip()
                if p:
                    candidates.append((os.path.realpath(p), "HOST", False))

        # Check and resolve each candidate
        visited_paths = set()
        for c_path, tier, writable in candidates:
            if c_path in visited_paths:
                continue
            visited_paths.add(c_path)
            if os.path.exists(c_path) and os.path.isdir(c_path):
                roots.append(CapabilityRoot(
                    root_path=c_path,
                    precedence_tier=tier,
                    origin="generic_posix",
                    is_writable=writable and os.access(c_path, os.W_OK)
                ))

        return roots

    def probe_reachability(self, workspace_root: Optional[str] = None) -> AdapterReachabilityReport:
        """Actively probes all discovered capability roots."""
        real_ws = os.path.realpath(workspace_root) if workspace_root else self.workspace_root
        roots = self.discover_capability_roots(real_ws)
        probes = [LiveProbeEngine.probe_skill_root(r) for r in roots]
        overall = LiveProbeEngine.evaluate_overall_status(probes)

        return AdapterReachabilityReport(
            adapter_id=self.adapter_id,
            environment_kind=self.environment_kind,
            overall_status=overall,
            checked_at=datetime.datetime.now(datetime.timezone.utc),
            probes=probes
        )

    def read_skill_exact_bytes(self, relative_path: str, root: Optional[CapabilityRoot] = None) -> bytes:
        """
        Reads exact un-truncated bytes under descriptor pinning and root confinement.
        """
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
        """
        Requests human approver consent via interactive terminal prompt if TTY attached.
        Fails closed (returns False) in non-interactive/headless environments.
        """
        self.assert_feature(AdapterFeature.INTERACTIVE_TTY_CONSENT)

        if not sys.stdin.isatty():
            return False

        print("\n" + "=" * 60)
        print(f" [LCS GOVERNANCE] APPROVER CONSENT REQUIRED ({required_role})")
        print("=" * 60)
        print(f" Capability: {capability_urn}")
        print(f" Action:     {action_summary}")
        print(f" Parameters: {parameters}")
        print("-" * 60)

        try:
            ans = input(f"Approve execution as role '{required_role}'? [y/N]: ").strip().lower()
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
        """Collects normalized execution evidence."""
        return {
            "step_id": step_id,
            "environment": self.environment_kind.value,
            "exit_code": exit_code,
            "stdout_length": len(raw_stdout),
            "stderr_length": len(raw_stderr),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
