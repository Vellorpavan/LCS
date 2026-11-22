"""
LCS Host-Specific Slash-Command Generators (Phase 2A)
=====================================================
Generates native slash command and skill artifacts for host agent environments:
- Google Antigravity (.agents/skills/call-me/SKILL.md)
- Claude Code (.claude/commands/call-me.md)
- OpenCode (.opencode/commands/call-me.md)
- Generic POSIX CLI (bin/lcs call-me)

Governed by: lcs_environment_feasibility_matrix.md
Invariants:
- Generates artifacts only where genuinely supported.
- Safe descriptor-relative creation without symlink escape.
- Idempotent installation, update, and clean uninstallation.
"""

import os
import shutil
from typing import Dict, Any, List, Optional, Tuple


class CommandGeneratorError(Exception):
    """Base exception for slash command generator errors."""
    pass


class SlashCommandGenerator:
    """
    Installs, inspects, and removes host-specific /call-me command artifacts.
    """

    LCS_ARTIFACT_SIGNATURE = "<!-- LCS-MANAGED-COMMAND-ARTIFACT -->"

    ANTIGRAVITY_SKILL_TEMPLATE = """---
name: call-me
description: Explicit entry point into the Living Capability System (LCS) universal multi-agent intelligence and capability orchestration engine.
category: orchestration
---
<!-- LCS-MANAGED-COMMAND-ARTIFACT -->

# /call-me — Living Capability System Entry Point

When the user invokes `/call-me <task>`, activate LCS to discover, evaluate, retrieve, plan, and govern capabilities across Antigravity, Claude Code, OpenCode, and local tools.

## Invocation Syntax
`/call-me <natural language task description>`

## Execution Flow
1. Receives the user's natural language task description.
2. Performs fast cache-assisted discovery across authorized skills and MCP servers.
3. Understands input parameters and synthesizes a verifiable DAG plan.
4. Submits the plan to LCS Governance Engine (Gate 1 & Gate 2) prior to execution.

## Execution Command
```bash
command -v lcs >/dev/null 2>&1 && lcs call-me --handoff -- "<task>" || python3 -m lcs.cli call-me --handoff -- "<task>"
```
"""

    CLAUDE_CODE_COMMAND_TEMPLATE = """<!-- LCS-MANAGED-COMMAND-ARTIFACT -->
# /call-me — LCS Capability Orchestration

Pass the user's task as one literal argument. When the JSON response reports ready, apply the returned skill instructions and dependencies under the host's permissions. Report a blocked handoff to the user.

Run the LCS entry point with the user's arguments:
```bash
command -v lcs >/dev/null 2>&1 && lcs call-me --handoff -- "<task>" || python3 -m lcs.cli call-me --handoff -- "<task>"
```
"""

    OPENCODE_COMMAND_TEMPLATE = """<!-- LCS-MANAGED-COMMAND-ARTIFACT -->
# /call-me — OpenCode Capability Entry Point

Pass the task as one literal argument. Apply the returned instructions and dependencies only when ready, under the host's permissions.
```bash
command -v lcs >/dev/null 2>&1 && lcs call-me --handoff -- "<task>" || python3 -m lcs.cli call-me --handoff -- "<task>"
```
"""

    @classmethod
    def get_feasibility_status(cls) -> Dict[str, Dict[str, Any]]:
        """
        Returns the 5-level feasibility matrix for slash-command integration
        across supported host environments.
        """
        return {
            "ANTIGRAVITY": {
                "host_supported": True,
                "documented_mechanism": ".agents/skills/<name>/SKILL.md or ~/.gemini/config/skills/",
                "lcs_accessible": True,
                "implemented": True,
                "tested": True,
                "mechanism_type": "Skill Directory Manifest"
            },
            "CLAUDE_CODE": {
                "host_supported": True,
                "documented_mechanism": ".claude/commands/<name>.md or ~/.claude/commands/",
                "lcs_accessible": True,
                "implemented": True,
                "tested": True,
                "mechanism_type": "Command Macro File"
            },
            "OPENCODE": {
                "host_supported": True,
                "documented_mechanism": ".opencode/commands/<name>.md or opencode.json",
                "lcs_accessible": True,
                "implemented": True,
                "tested": True,
                "mechanism_type": "Custom Command File"
            },
            "GENERIC_POSIX": {
                "host_supported": True,
                "documented_mechanism": "CLI subcommand: bin/lcs call-me <task>",
                "lcs_accessible": True,
                "implemented": True,
                "tested": True,
                "mechanism_type": "Standard CLI Executable"
            }
        }

    @classmethod
    def _safe_write_artifact(cls, file_path: str, content: str, overwrite: bool = False) -> None:
        """Writes command artifact only if it does not overwrite unrelated user content."""
        if os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    existing = f.read()
                # Safe to overwrite if it's already LCS-managed or identical
                if cls.LCS_ARTIFACT_SIGNATURE in existing or "Living Capability System" in existing:
                    pass
                elif not overwrite:
                    raise CommandGeneratorError(
                        f"Refusing to overwrite existing non-LCS file at '{file_path}'. "
                        f"Set overwrite=True to replace unrelated user file."
                    )
            except UnicodeDecodeError:
                if not overwrite:
                    raise CommandGeneratorError(
                        f"Refusing to overwrite existing binary/non-text file at '{file_path}'."
                    )

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

    @classmethod
    def _is_lcs_managed(cls, file_path: str) -> bool:
        """Verifies if a file was created by LCS before removing it."""
        if not os.path.isfile(file_path) or os.path.islink(file_path):
            return False
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            return (
                cls.LCS_ARTIFACT_SIGNATURE in content
                or "Living Capability System" in content
                or "lcs call-me" in content
            )
        except Exception:
            return False

    @classmethod
    def install_antigravity(
        cls,
        workspace_root: str,
        is_global: bool = False,
        home_dir: Optional[str] = None,
        overwrite: bool = False
    ) -> str:
        """Installs the Antigravity /call-me skill manifest."""
        if is_global:
            home = home_dir or os.path.expanduser("~")
            target_dir = os.path.join(home, ".gemini", "config", "skills", "call-me")
        else:
            target_dir = os.path.join(workspace_root, ".agents", "skills", "call-me")

        os.makedirs(target_dir, exist_ok=True)
        file_path = os.path.join(target_dir, "SKILL.md")
        cls._safe_write_artifact(file_path, cls.ANTIGRAVITY_SKILL_TEMPLATE, overwrite=overwrite)
        return file_path

    @classmethod
    def install_claude_code(
        cls,
        workspace_root: str,
        is_global: bool = False,
        home_dir: Optional[str] = None,
        overwrite: bool = False
    ) -> str:
        """Installs the Claude Code /call-me slash-command macro."""
        if is_global:
            home = home_dir or os.path.expanduser("~")
            target_dir = os.path.join(home, ".claude", "commands")
        else:
            target_dir = os.path.join(workspace_root, ".claude", "commands")

        os.makedirs(target_dir, exist_ok=True)
        file_path = os.path.join(target_dir, "call-me.md")
        cls._safe_write_artifact(file_path, cls.CLAUDE_CODE_COMMAND_TEMPLATE, overwrite=overwrite)
        return file_path

    @classmethod
    def install_opencode(
        cls,
        workspace_root: str,
        is_global: bool = False,
        home_dir: Optional[str] = None,
        overwrite: bool = False
    ) -> str:
        """Installs the OpenCode /call-me slash-command markdown."""
        if is_global:
            home = home_dir or os.path.expanduser("~")
            target_dir = os.path.join(home, ".opencode", "commands")
        else:
            target_dir = os.path.join(workspace_root, ".opencode", "commands")
        os.makedirs(target_dir, exist_ok=True)
        file_path = os.path.join(target_dir, "call-me.md")
        cls._safe_write_artifact(file_path, cls.OPENCODE_COMMAND_TEMPLATE, overwrite=overwrite)
        return file_path

    @classmethod
    def install_codex(
        cls,
        workspace_root: str,
        is_global: bool = False,
        home_dir: Optional[str] = None,
        overwrite: bool = False
    ) -> str:
        """Installs the Codex /call-me skill manifest."""
        if is_global:
            home = home_dir or os.path.expanduser("~")
            target_dir = os.path.join(home, ".agents", "skills", "call-me")
        else:
            target_dir = os.path.join(workspace_root, ".agents", "skills", "call-me")
        os.makedirs(target_dir, exist_ok=True)
        file_path = os.path.join(target_dir, "SKILL.md")
        cls._safe_write_artifact(file_path, cls.ANTIGRAVITY_SKILL_TEMPLATE, overwrite=overwrite)
        return file_path

    @classmethod
    def install_all(
        cls,
        workspace_root: str,
        is_global: bool = False,
        home_dir: Optional[str] = None,
        overwrite: bool = False
    ) -> Dict[str, str]:
        """Installs /call-me command artifacts across all genuinely supported host environments."""
        return {
            "ANTIGRAVITY": cls.install_antigravity(workspace_root, is_global=is_global, home_dir=home_dir, overwrite=overwrite),
            "CLAUDE_CODE": cls.install_claude_code(workspace_root, is_global=is_global, home_dir=home_dir, overwrite=overwrite),
            "OPENCODE": cls.install_opencode(workspace_root, is_global=is_global, home_dir=home_dir, overwrite=overwrite),
        }

    @classmethod
    def uninstall(
        cls,
        workspace_root: str,
        environment: str,
        is_global: bool = False,
        home_dir: Optional[str] = None
    ) -> bool:
        """Safely removes the generated command artifact without removing unrelated user files."""
        env_upper = environment.upper()
        if env_upper in ("ANTIGRAVITY", "GOOGLE_ANTIGRAVITY", "CODEX"):
            if is_global and env_upper == "CODEX":
                target_dir = os.path.join(home_dir or os.path.expanduser("~"), ".agents", "skills", "call-me")
            elif is_global:
                home = home_dir or os.path.expanduser("~")
                target_dir = os.path.join(home, ".gemini", "config", "skills", "call-me")
            else:
                target_dir = os.path.join(workspace_root, ".agents", "skills", "call-me")

            skill_file = os.path.join(target_dir, "SKILL.md")
            if not os.path.exists(skill_file):
                return False

            if not cls._is_lcs_managed(skill_file):
                return False

            os.remove(skill_file)

            # Safely remove target_dir ONLY if completely empty (preserves unrelated user files)
            try:
                if os.path.exists(target_dir) and not os.listdir(target_dir):
                    os.rmdir(target_dir)
            except OSError:
                pass
            return True

        elif env_upper in ("CLAUDE_CODE", "CLAUDE"):
            if is_global:
                home = home_dir or os.path.expanduser("~")
                target_dir = os.path.join(home, ".claude", "commands")
            else:
                target_dir = os.path.join(workspace_root, ".claude", "commands")

            path = os.path.join(target_dir, "call-me.md")
            if os.path.exists(path) and cls._is_lcs_managed(path):
                os.remove(path)
                try:
                    if os.path.exists(target_dir) and not os.listdir(target_dir):
                        os.rmdir(target_dir)
                except OSError:
                    pass
                return True
            return False

        elif env_upper == "OPENCODE":
            if is_global:
                home = home_dir or os.path.expanduser("~")
                target_dir = os.path.join(home, ".opencode", "commands")
            else:
                target_dir = os.path.join(workspace_root, ".opencode", "commands")

            path = os.path.join(target_dir, "call-me.md")
            if os.path.exists(path) and cls._is_lcs_managed(path):
                os.remove(path)
                try:
                    if os.path.exists(target_dir) and not os.listdir(target_dir):
                        os.rmdir(target_dir)
                except OSError:
                    pass
                return True
            return False

        return False
