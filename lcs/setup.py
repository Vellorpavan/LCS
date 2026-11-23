"""
LCS Universal Local Setup & Diagnostics Engine
==============================================
Provides local-first setup, host agent detection, diagnostic auditing,
and safe repair behaviors for LCS across macOS, Linux, and Windows.

Invariants:
- Preserves existing host configurations and non-LCS files (requires --force to overwrite).
- Enforces secure state directory permissions (0o700 on POSIX).
- Preserves database schemas and executes pending migrations idempotently.
- Works reliably across terminal restarts and varied workspace directories.
"""

import os
import sys
import shutil
import sqlite3
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from lcs.config import LCSConfig
from lcs.context import LCSContext
from lcs.migrations import MigrationManager
from lcs.interface.generators import SlashCommandGenerator, CommandGeneratorError


@dataclass
class HostDetectionInfo:
    """Detection status and paths for a target coding agent host."""
    name: str
    environment: str
    is_detected: bool
    detection_evidence: List[str] = field(default_factory=list)
    command_target_path: Optional[str] = None
    command_status: str = "MISSING"  # MISSING, INSTALLED, CONFLICT, UNKNOWN
    is_global: bool = False


@dataclass
class DiagnosticCheck:
    """Individual diagnostic health check record."""
    category: str  # STATE_DIR, DATABASE, CAS_STORAGE, KEY_STORE, EXECUTABLE, AGENT_INTEGRATIONS
    name: str
    status: str  # PASS, WARN, FAIL
    message: str
    remediation: Optional[str] = None


class HostDetector:
    """
    Detects compatible installed coding agents on the machine and active workspace.
    Supports Google Antigravity, Claude Code, OpenCode, Codex, and Generic POSIX.
    """

    @classmethod
    def detect_all(
        cls,
        workspace_root: Optional[str] = None,
        home_override: Optional[str] = None,
        is_global: bool = True
    ) -> Dict[str, HostDetectionInfo]:
        """Scans host filesystem and environment to detect installed coding agents."""
        home = home_override or os.path.expanduser("~")
        workspace = workspace_root or os.getcwd()
        results: Dict[str, HostDetectionInfo] = {}

        # 1. Antigravity
        ag_evidence = []
        ag_global_cfg = os.path.join(home, ".gemini", "config")
        ag_global_app = os.path.join(home, ".gemini", "antigravity")
        if os.path.isdir(ag_global_cfg):
            ag_evidence.append(f"Directory exists: {ag_global_cfg}")
        if os.path.isdir(ag_global_app):
            ag_evidence.append(f"Directory exists: {ag_global_app}")
        if any(k.startswith("ANTIGRAVITY_") for k in os.environ):
            ag_evidence.append("Environment variable ANTIGRAVITY_* set")
        if shutil.which("gemini"):
            ag_evidence.append(f"Executable found in PATH: {shutil.which('gemini')}")
        if not is_global and os.path.isdir(os.path.join(workspace, ".agents")):
            ag_evidence.append(f"Workspace directory exists: {os.path.join(workspace, '.agents')}")

        ag_cmd_path = (
            os.path.join(home, ".gemini", "config", "skills", "call-me", "SKILL.md")
            if is_global
            else os.path.join(workspace, ".agents", "skills", "call-me", "SKILL.md")
        )
        ag_status = cls._check_command_status(ag_cmd_path)
        results["ANTIGRAVITY"] = HostDetectionInfo(
            name="Google Antigravity",
            environment="antigravity",
            is_detected=bool(ag_evidence),
            detection_evidence=ag_evidence,
            command_target_path=ag_cmd_path,
            command_status=ag_status,
            is_global=is_global,
        )

        # 2. Claude Code
        cc_evidence = []
        cc_global_dir = os.path.join(home, ".claude")
        if os.path.isdir(cc_global_dir):
            cc_evidence.append(f"Directory exists: {cc_global_dir}")
        if shutil.which("claude"):
            cc_evidence.append(f"Executable found in PATH: {shutil.which('claude')}")
        if any(k.startswith("CLAUDE_") for k in os.environ):
            cc_evidence.append("Environment variable CLAUDE_* set")
        if not is_global and os.path.isdir(os.path.join(workspace, ".claude")):
            cc_evidence.append(f"Workspace directory exists: {os.path.join(workspace, '.claude')}")

        cc_cmd_path = (
            os.path.join(home, ".claude", "commands", "call-me.md")
            if is_global
            else os.path.join(workspace, ".claude", "commands", "call-me.md")
        )
        cc_status = cls._check_command_status(cc_cmd_path)
        results["CLAUDE_CODE"] = HostDetectionInfo(
            name="Claude Code",
            environment="claude_code",
            is_detected=bool(cc_evidence),
            detection_evidence=cc_evidence,
            command_target_path=cc_cmd_path,
            command_status=cc_status,
            is_global=is_global,
        )

        # 3. OpenCode
        oc_evidence = []
        oc_global_dir = os.path.join(home, ".opencode")
        oc_config_dir = os.path.join(home, ".config", "opencode")
        if os.path.isdir(oc_global_dir):
            oc_evidence.append(f"Directory exists: {oc_global_dir}")
        if os.path.isdir(oc_config_dir):
            oc_evidence.append(f"Directory exists: {oc_config_dir}")
        if shutil.which("opencode"):
            oc_evidence.append(f"Executable found in PATH: {shutil.which('opencode')}")
        if not is_global and (
            os.path.isdir(os.path.join(workspace, ".opencode"))
            or os.path.isfile(os.path.join(workspace, "opencode.json"))
        ):
            oc_evidence.append("Workspace .opencode/ or opencode.json detected")

        oc_cmd_path = (
            os.path.join(home, ".opencode", "commands", "call-me.md")
            if is_global
            else os.path.join(workspace, ".opencode", "commands", "call-me.md")
        )
        oc_status = cls._check_command_status(oc_cmd_path)
        results["OPENCODE"] = HostDetectionInfo(
            name="OpenCode",
            environment="opencode",
            is_detected=bool(oc_evidence),
            detection_evidence=oc_evidence,
            command_target_path=oc_cmd_path,
            command_status=oc_status,
            is_global=is_global,
        )

        # 4. Codex
        cdx_evidence = []
        cdx_global_agents = os.path.join(home, ".agents")
        cdx_global_dir = os.path.join(home, ".codex")
        if os.path.isdir(cdx_global_agents):
            cdx_evidence.append(f"Directory exists: {cdx_global_agents}")
        if os.path.isdir(cdx_global_dir):
            cdx_evidence.append(f"Directory exists: {cdx_global_dir}")
        if any(k.startswith("CODEX_") for k in os.environ):
            cdx_evidence.append("Environment variable CODEX_* set")

        cdx_cmd_path = (
            os.path.join(home, ".agents", "skills", "call-me", "SKILL.md")
            if is_global
            else os.path.join(workspace, ".agents", "skills", "call-me", "SKILL.md")
        )
        cdx_status = cls._check_command_status(cdx_cmd_path)
        results["CODEX"] = HostDetectionInfo(
            name="Codex",
            environment="codex",
            is_detected=bool(cdx_evidence),
            detection_evidence=cdx_evidence,
            command_target_path=cdx_cmd_path,
            command_status=cdx_status,
            is_global=is_global,
        )

        # 5. Generic POSIX CLI
        gen_cmd_path = shutil.which("lcs") or sys.executable
        results["GENERIC_POSIX"] = HostDetectionInfo(
            name="Generic POSIX CLI",
            environment="generic_posix",
            is_detected=True,
            detection_evidence=["Always supported on POSIX/Windows CLI"],
            command_target_path=gen_cmd_path,
            command_status="INSTALLED" if shutil.which("lcs") else "RESOLVED_INTERPRETER",
            is_global=is_global,
        )

        return results

    @classmethod
    def _check_command_status(cls, file_path: str) -> str:
        """Determines whether a command file is missing, LCS-managed, or a foreign conflict."""
        if not os.path.exists(file_path):
            return "MISSING"
        if SlashCommandGenerator._is_lcs_managed(file_path):
            return "INSTALLED"
        return "CONFLICT"


class SetupDiagnostics:
    """
    Evaluates system and workspace health across 6 core dimensions:
    1. State Directory
    2. Relational Database & Migrations
    3. Content-Addressable Storage (CAS)
    4. Cryptographic Key Store
    5. Executable & Environment Resolution
    6. Agent Integrations & Slash Commands
    """

    @classmethod
    def run_checks(
        cls,
        config: LCSConfig,
        workspace_root: Optional[str] = None,
        is_global: bool = True,
        home_override: Optional[str] = None
    ) -> List[DiagnosticCheck]:
        checks: List[DiagnosticCheck] = []

        # 1. State Directory Checks
        if not os.path.exists(config.root_dir):
            checks.append(DiagnosticCheck(
                category="STATE_DIR",
                name="state_directory_exists",
                status="FAIL",
                message=f"LCS state directory does not exist: {config.root_dir}",
                remediation="Run 'lcs setup' to create the directory."
            ))
        else:
            if not os.access(config.root_dir, os.R_OK | os.W_OK):
                checks.append(DiagnosticCheck(
                    category="STATE_DIR",
                    name="state_directory_permissions",
                    status="FAIL",
                    message=f"LCS state directory is not readable/writable: {config.root_dir}",
                    remediation=f"Check permissions on {config.root_dir}."
                ))
            else:
                checks.append(DiagnosticCheck(
                    category="STATE_DIR",
                    name="state_directory_accessible",
                    status="PASS",
                    message=f"State directory accessible at {config.root_dir} (global={config.is_user_global})"
                ))

            # POSIX permission check: 0o700
            if sys.platform != "win32":
                mode = os.stat(config.root_dir).st_mode & 0o777
                if mode & 0o077 != 0:
                    checks.append(DiagnosticCheck(
                        category="STATE_DIR",
                        name="state_directory_secure_mode",
                        status="WARN",
                        message=f"State directory mode is {oct(mode)}, expected 0o700",
                        remediation=f"Run 'chmod 700 {config.root_dir}' or 'lcs setup --repair'."
                    ))
                else:
                    checks.append(DiagnosticCheck(
                        category="STATE_DIR",
                        name="state_directory_secure_mode",
                        status="PASS",
                        message="State directory has secure mode 0o700"
                    ))

        # 2. Relational Database & Migrations
        if not os.path.exists(config.db_path):
            checks.append(DiagnosticCheck(
                category="DATABASE",
                name="database_file_exists",
                status="FAIL",
                message=f"SQLite database file not found: {config.db_path}",
                remediation="Run 'lcs setup' to initialize and migrate the database."
            ))
        else:
            try:
                conn = sqlite3.connect(config.db_path)
                cur = conn.cursor()
                cur.execute("PRAGMA integrity_check;")
                res = cur.fetchone()[0]
                if res != "ok":
                    checks.append(DiagnosticCheck(
                        category="DATABASE",
                        name="database_integrity",
                        status="FAIL",
                        message=f"SQLite integrity check failed: {res}",
                        remediation="Run 'lcs setup --repair' or restore from backup."
                    ))
                else:
                    checks.append(DiagnosticCheck(
                        category="DATABASE",
                        name="database_integrity",
                        status="PASS",
                        message="SQLite integrity check passed (PRAGMA integrity_check = ok)"
                    ))

                # Check migrations
                mm = MigrationManager(db_path=config.db_path, schema_dir=config.schema_dir)
                status_list = mm.get_status()
                applied = sum(1 for m in status_list if m["applied"])
                total = len(status_list)
                if applied < total:
                    checks.append(DiagnosticCheck(
                        category="DATABASE",
                        name="database_migrations",
                        status="WARN",
                        message=f"Pending migrations: {applied}/{total} applied",
                        remediation="Run 'lcs setup --repair' to apply pending migrations."
                    ))
                else:
                    checks.append(DiagnosticCheck(
                        category="DATABASE",
                        name="database_migrations",
                        status="PASS",
                        message=f"All database migrations applied ({applied}/{total})"
                    ))
                conn.close()
            except Exception as e:
                checks.append(DiagnosticCheck(
                    category="DATABASE",
                    name="database_connectivity",
                    status="FAIL",
                    message=f"Could not connect to database: {e}",
                    remediation="Check database permissions or rebuild with 'lcs setup --repair'."
                ))

        # 3. Content-Addressable Storage (CAS)
        cas_dirs = [
            ("cas_objects", os.path.join(config.cas_root, "objects")),
            ("cas_staging", os.path.join(config.cas_root, "staging")),
        ]
        cas_all_ok = True
        for name, dpath in cas_dirs:
            if not os.path.isdir(dpath) or not os.access(dpath, os.W_OK):
                cas_all_ok = False
                checks.append(DiagnosticCheck(
                    category="CAS_STORAGE",
                    name=name,
                    status="FAIL",
                    message=f"CAS directory missing or unwritable: {dpath}",
                    remediation="Run 'lcs setup --repair' to create storage hierarchy."
                ))
        if cas_all_ok:
            checks.append(DiagnosticCheck(
                category="CAS_STORAGE",
                name="cas_directories",
                status="PASS",
                message="All CAS storage directories present and writable"
            ))

        # 4. Cryptographic Key Store
        key_ring = os.path.join(config.key_store_dir, "key_ring.json")
        key_bin = os.path.join(config.key_store_dir, "receipt_signing_key.bin")
        active_key_file = key_ring if os.path.isfile(key_ring) else (key_bin if os.path.isfile(key_bin) else None)

        if not active_key_file:
            checks.append(DiagnosticCheck(
                category="KEY_STORE",
                name="receipt_signing_key",
                status="FAIL",
                message=f"Receipt signing key ring missing in: {config.key_store_dir}",
                remediation="Run 'lcs setup --repair' to generate cryptographic signing key."
            ))
        else:
            ksize = os.path.getsize(active_key_file)
            if ksize == 0:
                checks.append(DiagnosticCheck(
                    category="KEY_STORE",
                    name="receipt_signing_key",
                    status="FAIL",
                    message=f"Receipt signing key file is empty: {active_key_file}",
                    remediation="Run 'lcs setup --repair' to regenerate signing key."
                ))
            else:
                checks.append(DiagnosticCheck(
                    category="KEY_STORE",
                    name="receipt_signing_key",
                    status="PASS",
                    message=f"Receipt signing key present ({os.path.basename(active_key_file)}, {ksize} bytes)"
                ))

        # 5. Executable & Environment Resolution
        which_lcs = shutil.which("lcs")
        if which_lcs:
            checks.append(DiagnosticCheck(
                category="EXECUTABLE",
                name="lcs_in_path",
                status="PASS",
                message=f"'lcs' command is available in PATH: {which_lcs}"
            ))
        else:
            checks.append(DiagnosticCheck(
                category="EXECUTABLE",
                name="lcs_in_path",
                status="WARN",
                message="'lcs' command is not currently in PATH. Slash commands will fall back to python3 -m lcs.cli.",
                remediation="Ensure your Python environment's bin/ directory is in your shell PATH."
            ))

        # 6. Agent Integrations & Slash Commands
        hosts = HostDetector.detect_all(
            workspace_root=workspace_root,
            home_override=home_override,
            is_global=is_global
        )
        for h_key, h_info in hosts.items():
            if h_key == "GENERIC_POSIX":
                continue
            if h_info.is_detected:
                if h_info.command_status == "INSTALLED":
                    checks.append(DiagnosticCheck(
                        category="AGENT_INTEGRATIONS",
                        name=f"agent_{h_info.environment}",
                        status="PASS",
                        message=f"{h_info.name} detected; /call-me integration is active: {h_info.command_target_path}"
                    ))
                elif h_info.command_status == "CONFLICT":
                    checks.append(DiagnosticCheck(
                        category="AGENT_INTEGRATIONS",
                        name=f"agent_{h_info.environment}",
                        status="WARN",
                        message=f"{h_info.name} detected; conflicting unmanaged file at {h_info.command_target_path}",
                        remediation="Run 'lcs setup --force' to overwrite the conflicting file."
                    ))
                else:
                    checks.append(DiagnosticCheck(
                        category="AGENT_INTEGRATIONS",
                        name=f"agent_{h_info.environment}",
                        status="WARN",
                        message=f"{h_info.name} detected but /call-me is not installed at {h_info.command_target_path}",
                        remediation="Run 'lcs setup' to install the integration."
                    ))

        return checks


class SetupEngine:
    """
    Main orchestration engine for LCS setup, diagnostics, and repairs.
    """

    @classmethod
    def run_setup(
        cls,
        is_global: bool = True,
        workspace_root: Optional[str] = None,
        home_override: Optional[str] = None,
        environments: Optional[List[str]] = None,
        overwrite: bool = False,
        root_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes idempotent LCS setup:
        1. Resolves and initializes state directories.
        2. Applies relational database migrations.
        3. Initializes CAS storage hierarchy and cryptographic signing key.
        4. Detects installed coding agents.
        5. Installs slash command and skill artifacts safely (handles conflicts).
        6. Runs comprehensive post-setup diagnostics.
        """
        workspace = workspace_root or os.getcwd()
        home = home_override or os.path.expanduser("~")

        # 1. Resolve configuration
        resolved_root = root_override
        if not is_global and not resolved_root:
            resolved_root = os.path.join(workspace, ".lcs")

        cfg = LCSConfig.resolve(
            root_override=resolved_root,
            is_global=is_global,
            home_override=home_override,
            workspace_root=workspace
        )
        cfg.ensure_directories()

        # Enforce 0o700 mode on state directory
        if sys.platform != "win32":
            try:
                os.chmod(cfg.root_dir, 0o700)
                os.chmod(cfg.cas_root, 0o700)
                os.chmod(cfg.key_store_dir, 0o700)
            except OSError:
                pass

        # 2 & 3. Context auto-migrates DB, builds CAS, and initializes key store
        with LCSContext(config=cfg, auto_migrate=True) as ctx:
            pass

        # 4. Detect agents
        detected_hosts = HostDetector.detect_all(
            workspace_root=workspace,
            home_override=home_override,
            is_global=is_global
        )

        target_envs = [e.lower() for e in environments] if environments else ["all"]
        install_results: Dict[str, Dict[str, Any]] = {}

        # 5. Safe registration across target environments
        agents_to_install = []
        if "all" in target_envs:
            agents_to_install = ["antigravity", "claude_code", "opencode", "codex"]
        else:
            agents_to_install = target_envs

        for agent in agents_to_install:
            agent_key = agent.upper().replace("-", "_")
            if agent_key == "CLAUDE":
                agent_key = "CLAUDE_CODE"

            h_info = detected_hosts.get(agent_key)
            target_path = h_info.command_target_path if h_info else None

            # Conflict detection pre-check
            if target_path and os.path.exists(target_path):
                if not SlashCommandGenerator._is_lcs_managed(target_path) and not overwrite:
                    install_results[agent] = {
                        "status": "CONFLICT_SKIPPED",
                        "path": target_path,
                        "message": "Preserved existing non-LCS file. Use --force to overwrite."
                    }
                    continue

            try:
                if agent_key == "ANTIGRAVITY":
                    p = SlashCommandGenerator.install_antigravity(
                        workspace_root=workspace,
                        is_global=is_global,
                        home_dir=home,
                        overwrite=overwrite
                    )
                    install_results["antigravity"] = {"status": "INSTALLED", "path": p}
                elif agent_key == "CLAUDE_CODE":
                    p = SlashCommandGenerator.install_claude_code(
                        workspace_root=workspace,
                        is_global=is_global,
                        home_dir=home,
                        overwrite=overwrite
                    )
                    install_results["claude_code"] = {"status": "INSTALLED", "path": p}
                elif agent_key == "OPENCODE":
                    p = SlashCommandGenerator.install_opencode(
                        workspace_root=workspace,
                        is_global=is_global,
                        home_dir=home,
                        overwrite=overwrite
                    )
                    install_results["opencode"] = {"status": "INSTALLED", "path": p}
                elif agent_key == "CODEX":
                    p = SlashCommandGenerator.install_codex(
                        workspace_root=workspace,
                        is_global=is_global,
                        home_dir=home,
                        overwrite=overwrite
                    )
                    install_results["codex"] = {"status": "INSTALLED", "path": p}
            except CommandGeneratorError as cge:
                install_results[agent] = {
                    "status": "CONFLICT_ERROR",
                    "path": target_path,
                    "message": str(cge)
                }
            except Exception as e:
                install_results[agent] = {
                    "status": "ERROR",
                    "path": target_path,
                    "message": str(e)
                }

        # 6. Post-setup diagnostic checks
        diag_checks = SetupDiagnostics.run_checks(
            config=cfg,
            workspace_root=workspace,
            is_global=is_global,
            home_override=home_override
        )

        has_fail = any(c.status == "FAIL" for c in diag_checks)
        has_warn = any(c.status == "WARN" for c in diag_checks)
        overall = "UNHEALTHY" if has_fail else ("DEGRADED" if has_warn else "HEALTHY")

        return {
            "status": "ERROR" if has_fail else ("WARNING" if has_warn else "SUCCESS"),
            "overall_health": overall,
            "is_global": is_global,
            "root_dir": cfg.root_dir,
            "db_path": cfg.db_path,
            "installed_integrations": install_results,
            "diagnostics": [
                {
                    "category": c.category,
                    "name": c.name,
                    "status": c.status,
                    "message": c.message,
                    "remediation": c.remediation
                }
                for c in diag_checks
            ]
        }

    @classmethod
    def run_check(
        cls,
        is_global: bool = True,
        workspace_root: Optional[str] = None,
        home_override: Optional[str] = None,
        root_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """Runs diagnostics check without creating directories or mutating state."""
        workspace = workspace_root or os.getcwd()
        resolved_root = root_override
        if not is_global and not resolved_root:
            resolved_root = os.path.join(workspace, ".lcs")

        cfg = LCSConfig.resolve(
            root_override=resolved_root,
            is_global=is_global,
            home_override=home_override,
            workspace_root=workspace
        )
        diag_checks = SetupDiagnostics.run_checks(
            config=cfg,
            workspace_root=workspace,
            is_global=is_global,
            home_override=home_override
        )

        has_fail = any(c.status == "FAIL" for c in diag_checks)
        has_warn = any(c.status == "WARN" for c in diag_checks)
        overall = "UNHEALTHY" if has_fail else ("DEGRADED" if has_warn else "HEALTHY")

        return {
            "status": "ERROR" if has_fail else ("WARNING" if has_warn else "SUCCESS"),
            "overall_health": overall,
            "is_global": is_global,
            "root_dir": cfg.root_dir,
            "db_path": cfg.db_path,
            "diagnostics": [
                {
                    "category": c.category,
                    "name": c.name,
                    "status": c.status,
                    "message": c.message,
                    "remediation": c.remediation
                }
                for c in diag_checks
            ]
        }

    @classmethod
    def run_repair(
        cls,
        is_global: bool = True,
        workspace_root: Optional[str] = None,
        home_override: Optional[str] = None,
        environments: Optional[List[str]] = None,
        overwrite: bool = False,
        root_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Repairs damaged or missing state directories, missing migrations,
        corrupted/missing keys, or missing command files.
        """
        repaired_items: List[str] = []
        workspace = workspace_root or os.getcwd()
        home = home_override or os.path.expanduser("~")

        resolved_root = root_override
        if not is_global and not resolved_root:
            resolved_root = os.path.join(workspace, ".lcs")

        cfg = LCSConfig.resolve(
            root_override=resolved_root,
            is_global=is_global,
            home_override=home_override,
            workspace_root=workspace
        )

        # 1. Repair directories and permissions
        if not os.path.exists(cfg.root_dir) or not os.path.exists(cfg.cas_root) or not os.path.exists(cfg.key_store_dir):
            cfg.ensure_directories()
            repaired_items.append(f"Restored directory structure at {cfg.root_dir}")

        if sys.platform != "win32":
            try:
                os.chmod(cfg.root_dir, 0o700)
                os.chmod(cfg.cas_root, 0o700)
                os.chmod(cfg.key_store_dir, 0o700)
                repaired_items.append("Enforced 0o700 permissions on state directories")
            except OSError:
                pass

        # 2. Repair DB & migrations
        mm = MigrationManager(db_path=cfg.db_path, schema_dir=cfg.schema_dir)
        applied = mm.apply_pending()
        if applied:
            repaired_items.append(f"Applied {len(applied)} pending database migrations: {applied}")

        # 3. Context auto-heals CAS subdirectories and key store
        with LCSContext(config=cfg, auto_migrate=True) as ctx:
            key_ring = os.path.join(cfg.key_store_dir, "key_ring.json")
            if not os.path.isfile(key_ring) or os.path.getsize(key_ring) == 0:
                ctx.cas_engine.key_store._load_or_initialize_under_lock()
                repaired_items.append("Regenerated missing cryptographic receipt signing key ring")

        # 4. Repair command files
        setup_res = cls.run_setup(
            is_global=is_global,
            workspace_root=workspace,
            home_override=home,
            environments=environments,
            overwrite=overwrite,
            root_override=root_override
        )

        setup_res["repaired_items"] = repaired_items
        return setup_res
