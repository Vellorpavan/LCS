"""Codex session detection and workspace skill discovery."""

import os

from .base import CapabilityRoot, EnvironmentKind
from .generic import GenericPOSIXAdapter


class CodexAdapter(GenericPOSIXAdapter):
    adapter_id = "adapter.codex.v1"
    environment_kind = EnvironmentKind.CODEX
    display_name = "Codex"

    def detect_active(self, workspace_root=None):
        return bool(os.environ.get("CODEX_THREAD_ID") or os.environ.get("CODEX_SESSION_ID"))

    def discover_capability_roots(self, workspace_root=None):
        if not self.detect_active():
            return []
        workspace = workspace_root or self.workspace_root
        paths = [(os.path.join(workspace, ".agents", "skills"), "WORKSPACE"),
                 (os.path.expanduser("~/.agents/skills"), "USER_GLOBAL")]
        for rule_file in ("AGENTS.md", "CLAUDE.md", "RULES.md", ".cursorrules"):
            if os.path.isfile(os.path.join(workspace, rule_file)):
                paths.append((workspace, "WORKSPACE"))
                break
        return [CapabilityRoot(root_path=path, precedence_tier=tier, origin="codex",
                               is_writable=os.access(path, os.W_OK))
                for path, tier in paths if os.path.isdir(path)]
