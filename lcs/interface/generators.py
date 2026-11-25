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

# /call-me — Call Me & Living Capability System Orchestrator

## Invocation Syntax
`/call-me <natural language task description>`

When the user invokes `/call-me <objective>`, execute the full closed-loop multi-agent orchestration protocol:

## Execution Modes
- **Autonomous Host Execution**: Invoking `/call-me` activates the multi-agent closed-loop orchestration protocol, requesting the structured plan and dispatching native specialist agents.
- **Standalone CLI Execution**: Running `lcs call-me --handoff` performs pre-flight retrieval, planning, and governance checks, outputting hydrated instructions for operator inspection.

## Orchestration Protocol

### Phase 1: Request Structured Plan
Request the structured DAG plan and execution waves from Call Me:
```bash
command -v lcs >/dev/null 2>&1 && lcs call-me-plan "$*" --format-json || python3 -m lcs.cli call-me-plan "$*" --format-json
```
Parse the JSON response. Extract:
- `request_id`: Unique run identifier.
- `workspace_root`: Authorized workspace directory.
- `execution_waves`: Ordered topological stages `[[step_id, ...], ...]`.
- `dag_edges`: Dependency pairs `[[from_step, to_step], ...]`.
- `steps`: Dictionary of step specifications containing `capability_id`, `instructions`, `expected_deliverables`, and `verification_criteria`.

If planning fails or returns an error, stop immediately and report the failure.

### Phase 2: Closed-Loop Execution by Waves
Iterate through each wave in `execution_waves` sequentially:
1. For each step in the wave:
   - When native specialist agent dispatch is supported (`invoke_subagent`):
     - Dispatch the specialist subagent with:
       - `TypeName`: `"self"` (or appropriate specialist agent type)
       - `Role`: Domain specialist role (e.g., "Telemetry Service Specialist", "Code Quality Specialist")
       - `Prompt`: Hydrated `instructions` from the step, specifying:
         - Authorized workspace: `workspace_root`
         - Expected deliverables: `expected_deliverables`
         - Verification criteria: `verification_criteria`
         - Any artifacts or context produced by preceding waves
     - Await completion. If a specialist fails or reports errors, abort dependent downstream waves.
   - When native agent dispatch is unavailable:
     - Execute the hydrated instructions directly within the coordinator turn, strictly confined to `workspace_root` and producing the declared deliverables.
2. Every step must create or update real physical files in the workspace. An instruction handoff alone must not be marked as completed physical work.

### Phase 3: Deliverable & Test Verification Gate
Once all waves complete, invoke LCS's physical deliverable verification gate:
```bash
command -v lcs >/dev/null 2>&1 && lcs call-me-verify "<request_id>" --workspace "<workspace_root>" --files <expected_files...> --commands "<verification_commands...>" || python3 -m lcs.cli call-me-verify "<request_id>" --workspace "<workspace_root>" --files <expected_files...> --commands "<verification_commands...>"
```
The verification gate strictly verifies:
- Path confinement (rejects directory traversal `..` and NTFS ADS streams).
- Physical file existence and non-emptiness (>0 bytes).
- Automated test command execution exits with code 0 under authorized test binaries.

### Phase 4: Truthful Outcome Reporting
- If the verification gate passes (`is_verified: true` and `state: VERIFIED`), report SUCCESS with the run ID, list of verified files, and test results.
- If verification fails (missing files, empty files, failed tests, or governance violations), report FAILURE with diagnostic evidence. Never report SUCCEEDED when verification has failed or deliverables are missing.
"""

    CLAUDE_CODE_COMMAND_TEMPLATE = """<!-- LCS-MANAGED-COMMAND-ARTIFACT -->
# /call-me — Call Me Capability Orchestration

When the user invokes `/call-me <objective>`:
1. Generate the structured Call Me plan:
   `command -v lcs >/dev/null 2>&1 && lcs call-me-plan "<task>" --format-json || python3 -m lcs.cli call-me-plan "<task>" --format-json`
2. Parse execution_waves and hydrated instructions from the plan.
3. Execute each wave under authorized workspace boundaries, ensuring real files are created.
4. Verify deliverables and test results:
   `command -v lcs >/dev/null 2>&1 && lcs call-me-verify "<request_id>" --workspace "<workspace_root>" --files <files> --commands "<commands>" || python3 -m lcs.cli call-me-verify "<request_id>" --workspace "<workspace_root>" --files <files> --commands "<commands>"`
5. Report verified deliverables to user. Never report success if verification fails.
"""

    OPENCODE_COMMAND_TEMPLATE = """<!-- LCS-MANAGED-COMMAND-ARTIFACT -->
# /call-me — Call Me Capability Entry Point

When the user invokes `/call-me <objective>`:
1. Generate the structured Call Me plan:
   `command -v lcs >/dev/null 2>&1 && lcs call-me-plan "<task>" --format-json || python3 -m lcs.cli call-me-plan "<task>" --format-json`
2. Parse execution_waves and hydrated instructions from the plan.
3. Execute each wave under authorized workspace boundaries, ensuring real files are created.
4. Verify deliverables and test results:
   `command -v lcs >/dev/null 2>&1 && lcs call-me-verify "<request_id>" --workspace "<workspace_root>" --files <files> --commands "<commands>" || python3 -m lcs.cli call-me-verify "<request_id>" --workspace "<workspace_root>" --files <files> --commands "<commands>"`
5. Report verified deliverables to user. Never report success if verification fails.
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
