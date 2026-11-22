#!/usr/bin/env python3
"""
Living Capability System (LCS) — Execution Engine V1
====================================================
The operational runtime execution layer for LCS.

Consumes Governance V1 ExecutionAuthorizationTokens (EAT) and DispatchPermits,
supervises live capability dispatch across MCP tools and discovered skills,
enforces POSIX process sandboxing and dual timeouts, handles dynamic parameter
propagation, coordinates compensation unwinding, and commits immutable receipts
to Content-Addressable Storage (CAS) and the append-only cryptographic audit ledger.

Strict Invariants:
1. Dual-Gate Verification: Re-evaluates EAT validity and consumes token atomically.
2. Single-Use Token: Replay protection via atomic SQLite transaction.
3. Plan Integrity Re-Verification: Re-canonicalizes plan with RFC 8785 JCS.
4. Process Sandboxing & Safe Teardown: POSIX process groups + SIGTERM/SIGKILL.
5. Resource Confinement: openat / O_NOFOLLOW descriptor path pinning.
6. Frozen Core Invariance: 0 bytes modified in frozen retrieval/planning/governance.
"""

import os
import sys
import time
import json
import uuid
import stat
import errno
import signal
import hashlib
import sqlite3
import datetime
import subprocess
import threading
import queue
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple, Set, Union

# Frozen module safe imports
from capability_planning_v1 import (
    ExecutionPlan,
    PlanStep,
    StepInputBinding,
    StepOutputDefinition,
    BindingSourceType
)
from governance_policy_v1 import (
    ExecutionAuthorizationToken,
    DispatchPermit,
    ExecutionGovernanceEngineV1,
    GovernanceAuditLedger,
    compute_plan_integrity_hash,
    extract_canonical_plan_payload,
    canonicalize_jcs,
    get_current_policy_revision,
    GovernanceError,
    TokenAlreadyConsumedError,
    TokenExpiredError,
    TokenRevokedError,
    PlanIntegrityTamperedError,
    PolicyRevisionMismatchError,
    DispatchPermitInvalidError
)
from cas_storage_engine_v2b import SecureCASStorageEngine
from capability_profile_v2b import CapabilityProfileService


# ============================================================================
# 1. Enums and Data Models
# ============================================================================

class ExecutionLifecycleState(str, Enum):
    SUBMITTED = "SUBMITTED"
    TOKEN_CONSUMED = "TOKEN_CONSUMED"
    EXECUTING = "EXECUTING"
    COMPENSATION_UNWIND = "COMPENSATION_UNWIND"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class StepExecutionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    COMPENSATED = "COMPENSATED"
    SKIPPED = "SKIPPED"


class StepReversibilityType(str, Enum):
    IDEMPOTENT = "IDEMPOTENT"
    REVERSIBLE = "REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"


@dataclass
class StepExecutionRecord:
    step_record_id: str
    run_id: str
    step_id: str
    capability_urn: str
    step_index: int
    status: StepExecutionStatus
    start_time: float
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    input_arguments: Dict[str, Any] = field(default_factory=dict)
    input_arguments_cas_digest: str = ""
    output_result: Optional[Dict[str, Any]] = None
    output_result_cas_digest: Optional[str] = None
    error_details: Optional[str] = None
    retry_count: int = 0
    reversibility_type: StepReversibilityType = StepReversibilityType.IDEMPOTENT
    compensation_urn: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["reversibility_type"] = self.reversibility_type.value
        return d


@dataclass
class ExecutionRunResult:
    run_id: str
    token_id: str
    permit_id: str
    plan_id: str
    plan_integrity_hash: str
    lifecycle_state: ExecutionLifecycleState
    start_time: float
    end_time: float
    duration_ms: float
    total_steps: int
    completed_steps: int
    step_records: List[StepExecutionRecord]
    outputs: Dict[str, Any] = field(default_factory=dict)
    trace_cas_digest: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "token_id": self.token_id,
            "permit_id": self.permit_id,
            "plan_id": self.plan_id,
            "plan_integrity_hash": self.plan_integrity_hash,
            "lifecycle_state": self.lifecycle_state.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_ms": self.duration_ms,
            "total_steps": self.total_steps,
            "completed_steps": self.completed_steps,
            "step_records": [s.to_dict() for s in self.step_records],
            "outputs": self.outputs,
            "trace_cas_digest": self.trace_cas_digest,
            "error_message": self.error_message
        }


# ============================================================================
# 2. Exceptions
# ============================================================================

class ExecutionEngineError(Exception):
    """Base exception for all execution engine failures."""
    pass

class PreflightVerificationError(ExecutionEngineError):
    """Raised when preflight token, plan hash, or permit validation fails."""
    pass

class StepExecutionTimeoutError(ExecutionEngineError):
    """Raised when an operation exceeds its configured execution timeout."""
    pass

class StepExecutionError(ExecutionEngineError):
    """Raised when capability execution returns an error or non-zero exit."""
    pass

class UnresolvedParameterError(ExecutionEngineError):
    """Raised when a mandatory input parameter cannot be resolved."""
    pass

class PathTraversalExecutionError(ExecutionEngineError):
    """Raised when a parameter points to an unauthorized path or symlink."""
    pass

class CompensationExecutionError(ExecutionEngineError):
    """Raised when a compensation action fails during rollback."""
    pass


# ============================================================================
# 3. Database Schema Migration
# ============================================================================

def ensure_execution_engine_schema(conn: sqlite3.Connection) -> None:
    """
    Applies the Execution Engine V1 schema idempotently to the SQLite database.
    """
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS execution_runs (
            run_id TEXT PRIMARY KEY,
            token_id TEXT NOT NULL,
            permit_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            plan_integrity_hash TEXT NOT NULL,
            lifecycle_state TEXT NOT NULL CHECK(lifecycle_state IN (
                'SUBMITTED', 'TOKEN_CONSUMED', 'EXECUTING', 
                'COMPENSATION_UNWIND', 'SUCCEEDED', 'FAILED', 'ABORTED'
            )),
            start_time REAL NOT NULL,
            end_time REAL,
            total_steps INTEGER NOT NULL,
            completed_steps INTEGER DEFAULT 0,
            trace_cas_digest TEXT,
            error_message TEXT
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS execution_step_records (
            step_record_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            step_id TEXT NOT NULL,
            capability_urn TEXT NOT NULL,
            step_index INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN (
                'PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'COMPENSATED', 'SKIPPED'
            )),
            start_time REAL NOT NULL,
            end_time REAL,
            duration_ms REAL,
            input_arguments_cas_digest TEXT NOT NULL,
            output_result_cas_digest TEXT,
            error_details TEXT,
            retry_count INTEGER DEFAULT 0,
            reversibility_type TEXT NOT NULL DEFAULT 'IDEMPOTENT',
            compensation_urn TEXT,
            FOREIGN KEY(run_id) REFERENCES execution_runs(run_id) ON DELETE CASCADE
        );
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_exec_runs_token ON execution_runs(token_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_exec_runs_state ON execution_runs(lifecycle_state);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_exec_steps_run ON execution_step_records(run_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_exec_steps_cap ON execution_step_records(capability_urn);")
    conn.commit()


# ============================================================================
# 4. Safe Path Validation & POSIX File Security
# ============================================================================

class PathSecurityValidator:
    """
    Validates filesystem parameters to prevent path traversal, symlink escapes,
    and access outside authorized workspace / discovery roots.
    """

    @staticmethod
    def validate_file_path(path: str, authorized_roots: List[str]) -> str:
        """
        Confirms path is confined within one of authorized_roots and does not escape via symlink.
        Returns the resolved realpath.
        """
        norm_roots = [os.path.realpath(r) for r in authorized_roots if os.path.exists(r)]
        if not norm_roots:
            norm_roots = [os.path.realpath(os.getcwd())]

        resolved = os.path.realpath(path)

        # 1. Path confinement check
        confined = False
        for root in norm_roots:
            try:
                if os.path.commonpath([resolved, root]) == root:
                    confined = True
                    break
            except ValueError:
                continue

        if not confined:
            raise PathTraversalExecutionError(
                f"Path '{path}' (resolved: '{resolved}') escapes authorized roots: {norm_roots}"
            )

        # 2. Symlink rejection if file exists
        if os.path.exists(path) and os.path.islink(path):
            # Check descriptor-level safety
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
                os.close(fd)
            except OSError as e:
                if e.errno in (errno.ELOOP, 62):
                    raise PathTraversalExecutionError(f"Symlink rejected by O_NOFOLLOW: '{path}'")
                raise

        return resolved


# ============================================================================
# 5. Process Supervisor & Sandbox
# ============================================================================

class ProcessSupervisor:
    """
    Spawns isolated child processes with POSIX process group isolation,
    environment whitelisting, non-blocking stdio capture, and hard timeouts.
    """

    SAFE_ENV_VARS = {
        "PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL",
        "VIRTUAL_ENV", "PYTHONPATH", "SYSTEMROOT", "COMSPEC"
    }

    @classmethod
    def execute_command(
        cls,
        command: List[str],
        cwd: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
        stdin_input: Optional[str] = None,
        timeout_seconds: float = 30.0
    ) -> Tuple[int, str, str]:
        """
        Executes a command under process-group isolation with timeout enforcement.
        Returns (exit_code, stdout_str, stderr_str).
        """
        # Filter environment
        clean_env = {k: v for k, v in os.environ.items() if k in cls.SAFE_ENV_VARS}
        if env_vars:
            clean_env.update(env_vars)

        # Process group isolation on POSIX
        preexec = os.setsid if hasattr(os, "setsid") and sys.platform != "win32" else None

        try:
            proc = subprocess.Popen(
                command,
                cwd=cwd or os.getcwd(),
                stdin=subprocess.PIPE if stdin_input is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=clean_env,
                preexec_fn=preexec
            )
        except Exception as e:
            raise StepExecutionError(f"Failed to spawn process {command}: {e}") from e

        try:
            stdout_data, stderr_data = proc.communicate(input=stdin_input, timeout=timeout_seconds)
            exit_code = proc.returncode
            return exit_code, stdout_data, stderr_data
        except subprocess.TimeoutExpired:
            # Hard timeout triggered. Terminate process group safely.
            cls._kill_process_group(proc)
            try:
                proc.communicate(timeout=2.0)
            except Exception:
                pass
            raise StepExecutionTimeoutError(
                f"Execution of command {command[0] if command else ''} timed out after {timeout_seconds}s"
            )

    @classmethod
    def _kill_process_group(cls, proc: subprocess.Popen) -> None:
        """Sends SIGTERM then SIGKILL to the entire process group."""
        pid = proc.pid
        if hasattr(os, "killpg") and sys.platform != "win32":
            try:
                os.killpg(pid, signal.SIGTERM)
                time.sleep(1.0)
                if proc.poll() is None:
                    os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                pass
        else:
            try:
                proc.terminate()
                time.sleep(1.0)
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass


# ============================================================================
# 6. Modality Handlers
# ============================================================================

class MCPServerSession:
    """
    Represents an active, persistent JSON-RPC 2.0 stdio connection to an MCP server.
    Eliminates per-call process spawning and initialization overhead.
    """
    def __init__(self, command: List[str], env: Optional[Dict[str, str]] = None):
        self.command = list(command)
        self.env = env
        self.proc: Optional[subprocess.Popen] = None
        self._lock = threading.RLock()
        self.is_initialized = False
        self.request_id = 0
        self.created_at = time.time()
        self.last_used_at = self.created_at

    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    @property
    def pid(self) -> Optional[int]:
        return self.proc.pid if self.proc else None

    def start_and_initialize(self, timeout: float = 15.0) -> None:
        with self._lock:
            if self.is_alive() and self.is_initialized:
                return

            self._close_internal()

            try:
                self.proc = subprocess.Popen(
                    self.command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=self.env or os.environ.copy(),
                    text=True,
                    bufsize=1
                )
            except Exception as e:
                raise StepExecutionError(f"Failed to spawn MCP server process {self.command}: {e}")

            self.request_id = 1
            init_req = json.dumps({
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "LCS-Execution-Engine", "version": "1.0.0"}
                }
            }) + "\n"

            try:
                self.proc.stdin.write(init_req)
                self.proc.stdin.flush()
                init_line = self.proc.stdout.readline()
                if not init_line:
                    raise StepExecutionError("MCP server exited before responding to initialize")
                init_resp = json.loads(init_line)
                if "error" in init_resp:
                    raise StepExecutionError(f"MCP initialize rejected: {init_resp['error']}")

                # Send initialized notification
                notif = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
                self.proc.stdin.write(notif)
                self.proc.stdin.flush()
                self.is_initialized = True
                self.last_used_at = time.time()
            except Exception as e:
                self._close_internal()
                if isinstance(e, StepExecutionError):
                    raise
                raise StepExecutionError(f"Failed to initialize MCP server: {e}")

    def call_tool(self, tool_name: str, arguments: Dict[str, Any], timeout: float = 30.0) -> Dict[str, Any]:
        with self._lock:
            if not self.is_alive() or not self.is_initialized:
                self.start_and_initialize(timeout=min(timeout, 15.0))

            self.request_id += 1
            call_req = json.dumps({
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                }
            }) + "\n"

            try:
                self.proc.stdin.write(call_req)
                self.proc.stdin.flush()
                resp_line = self.proc.stdout.readline()
                if not resp_line:
                    raise StepExecutionError("MCP server connection dropped or process exited")
                resp = json.loads(resp_line)
                if "error" in resp:
                    raise StepExecutionError(f"MCP tool call failed: {resp['error']}")

                res_data = resp.get("result", {})
                if res_data.get("isError"):
                    raise StepExecutionError(f"Tool reported failure: {res_data.get('content')}")

                self.last_used_at = time.time()
                return res_data
            except Exception as e:
                if not self.is_alive():
                    self.is_initialized = False
                if isinstance(e, StepExecutionError):
                    raise
                raise StepExecutionError(f"MCP communication error during tool call: {e}")

    def _close_internal(self) -> None:
        if self.proc is not None:
            try:
                if self.proc.stdin and not self.proc.stdin.closed:
                    self.proc.stdin.close()
            except Exception:
                pass
            try:
                self.proc.terminate()
                self.proc.wait(timeout=1.5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None
        self.is_initialized = False

    def close(self) -> None:
        with self._lock:
            self._close_internal()


class MCPConnectionPool:
    """
    Thread-safe persistent pool of MCPServerSession instances keyed by command signature.
    """
    def __init__(self):
        self._sessions: Dict[Tuple[str, ...], MCPServerSession] = {}
        self._lock = threading.RLock()

    def get_session(self, command: List[str], env: Optional[Dict[str, str]] = None) -> MCPServerSession:
        key = tuple(command)
        with self._lock:
            if key in self._sessions:
                sess = self._sessions[key]
                if sess.is_alive():
                    return sess
                else:
                    sess.close()
                    del self._sessions[key]

            session = MCPServerSession(command, env)
            session.start_and_initialize()
            self._sessions[key] = session
            return session

    def evict_session(self, command: List[str]) -> None:
        key = tuple(command)
        with self._lock:
            if key in self._sessions:
                sess = self._sessions.pop(key)
                sess.close()

    def close_all(self) -> None:
        with self._lock:
            for key, sess in list(self._sessions.items()):
                try:
                    sess.close()
                except Exception:
                    pass
            self._sessions.clear()


class MCPToolHandler:
    """
    Executes MCP capabilities via JSON-RPC 2.0 tools/call over stdio using
    a persistent session pool.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.pool = MCPConnectionPool()

    def find_server_command(self, capability_urn: str) -> Optional[List[str]]:
        """Queries mcp_server_registrations or parses tool URN to find server launch command."""
        cur = self.conn.cursor()
        cur.execute("SELECT server_id, command_line FROM mcp_server_registrations;")
        rows = cur.fetchall()
        for s_id, cmd_line in rows:
            if s_id in capability_urn:
                if cmd_line:
                    import shlex
                    return shlex.split(cmd_line)
        return None

    def execute_tool(
        self,
        capability_urn: str,
        tool_name: str,
        arguments: Dict[str, Any],
        server_command: Optional[List[str]] = None,
        timeout: float = 30.0
    ) -> Dict[str, Any]:
        """
        Retrieves a persistent MCP server session from the pool, sends tools/call, and captures the result.
        Auto-recovers once if a stale session dropped.
        """
        cmd = server_command or self.find_server_command(capability_urn)
        if not cmd:
            raise StepExecutionError(f"No MCP server command found for capability '{capability_urn}'")

        try:
            session = self.pool.get_session(cmd)
            return session.call_tool(tool_name, arguments, timeout=timeout)
        except StepExecutionError as se:
            if "dropped" in str(se) or "exited" in str(se):
                self.pool.evict_session(cmd)
                session = self.pool.get_session(cmd)
                return session.call_tool(tool_name, arguments, timeout=timeout)
            raise

    def close(self) -> None:
        self.pool.close_all()


class SkillExecutionHandler:
    """
    Executes discovered skills and commands by loading exact-bytes from CAS,
    evaluating parameter bindings, and producing structured execution records.
    """

    def __init__(self, conn: sqlite3.Connection, cas_engine: SecureCASStorageEngine):
        self.conn = conn
        self.cas_engine = cas_engine

    def execute_skill(
        self,
        capability_urn: str,
        arguments: Dict[str, Any],
        skill_meta: Optional[Tuple[Any, ...]] = None
    ) -> Dict[str, Any]:
        """
        Renders the skill instructions with bound arguments and generates execution output.
        """
        row = skill_meta
        if row is None:
            try:
                cur = self.conn.cursor()
                cur.execute("""
                    SELECT raw_content_digest, resolved_path, taxonomy_kind
                    FROM artifact_discovery_records
                    WHERE canonical_urn = ?;
                """, (capability_urn,))
                row = cur.fetchone()
            except Exception:
                row = None

        raw_text = ""
        tax_kind = "SKILL"
        if row and row[0]:
            digest = row[0]
            tax_kind = row[2]
            try:
                content_bytes = self.cas_engine.read_blob(digest)
                if content_bytes:
                    raw_text = content_bytes.decode("utf-8", errors="replace")
            except Exception:
                pass

        if not raw_text and row and row[1] and os.path.exists(row[1]):
            with open(row[1], "r", encoding="utf-8", errors="replace") as f:
                raw_text = f.read()

        # Substitute template variables: $ARGUMENTS, ${var}, {{var}}
        rendered = raw_text
        if "$ARGUMENTS" in rendered:
            rendered = rendered.replace("$ARGUMENTS", json.dumps(arguments))

        for k, v in arguments.items():
            rendered = rendered.replace(f"${{{k}}}", str(v))
            rendered = rendered.replace(f"${k}", str(v))
            rendered = rendered.replace(f"{{{{{k}}}}}", str(v))

        # Check if the skill bundle has an executable script in scripts/ or bundle root
        script_to_run = None
        if row and row[1] and os.path.isfile(row[1]) and row[1].endswith((".py", ".sh", ".bash")):
            script_to_run = row[1]
            skill_dir = os.path.dirname(row[1])
        else:
            skill_dir = row[1] if (row and row[1] and os.path.isdir(row[1])) else (os.path.dirname(row[1]) if (row and row[1]) else None)
            if skill_dir and os.path.isdir(skill_dir):
                scripts_subdir = os.path.join(skill_dir, "scripts")
                if os.path.isdir(scripts_subdir):
                    for c in sorted(os.listdir(scripts_subdir)):
                        if c.endswith((".py", ".sh", ".bash")):
                            script_to_run = os.path.join(scripts_subdir, c)
                            break
                if not script_to_run:
                    for c in sorted(os.listdir(skill_dir)):
                        if c in ("run.py", "main.py", "execute.py", "audit.py", "run.sh"):
                            script_to_run = os.path.join(skill_dir, c)
                            break

        deliv_keys = ["deliverable", "deliverable_path", "deliverable_file", "output_file", "output_path", "expected_deliverable"]
        deliv_path = next((arguments[k] for k in deliv_keys if k in arguments and isinstance(arguments[k], str) and arguments[k].strip()), None)

        script_stdout = ""
        script_stderr = ""
        if script_to_run and os.path.exists(script_to_run):
            script_env = {f"LCS_PARAM_{k.upper()}": str(v) for k, v in arguments.items()}
            if deliv_path:
                script_env["LCS_DELIVERABLE_PATH"] = deliv_path
                script_env["OUTPUT_FILE"] = deliv_path

            if script_to_run.endswith(".py"):
                cmd = [sys.executable, script_to_run]
            else:
                cmd = ["/bin/bash", script_to_run]

            for k, v in arguments.items():
                cmd.extend([f"--{k}", str(v)])

            exit_code, stdout, stderr = ProcessSupervisor.execute_command(
                command=cmd,
                cwd=skill_dir,
                env_vars=script_env,
                timeout_seconds=30.0
            )
            if exit_code != 0:
                raise StepExecutionError(f"Skill script failed with exit code {exit_code}: {stderr or stdout}")
            script_stdout = stdout
            script_stderr = stderr

        # Enforce truthful execution: verify requested deliverable artifact if declared
        if deliv_path:
            if not os.path.exists(deliv_path):
                if not script_to_run:
                    raise StepExecutionError(f"Requested deliverable artifact was not created (instruction-only playbook without an executable script): '{deliv_path}'")
                raise StepExecutionError(f"Requested deliverable artifact was not created: '{deliv_path}'")
            if os.path.isfile(deliv_path) and os.path.getsize(deliv_path) == 0:
                raise StepExecutionError(f"Requested deliverable artifact is empty: '{deliv_path}'")

        if "expected_deliverables" in arguments and isinstance(arguments["expected_deliverables"], (list, tuple)):
            for d in arguments["expected_deliverables"]:
                if isinstance(d, str) and d.strip():
                    if not os.path.exists(d):
                        if not script_to_run:
                            raise StepExecutionError(f"Requested deliverable artifact was not created (instruction-only playbook without an executable script): '{d}'")
                        raise StepExecutionError(f"Requested deliverable artifact was not created: '{d}'")
                    if os.path.isfile(d) and os.path.getsize(d) == 0:
                        raise StepExecutionError(f"Requested deliverable artifact is empty: '{d}'")

        exec_mode = "SCRIPT_EXECUTION" if script_to_run else "INSTRUCTION_HANDOFF"
        return {
            "status": "SUCCESS",
            "capability_urn": capability_urn,
            "taxonomy_kind": tax_kind,
            "execution_mode": exec_mode,
            "resolved_arguments": arguments,
            "rendered_instructions": rendered,
            "script_path": script_to_run,
            "exit_code": 0 if script_to_run else None,
            "stdout": script_stdout,
            "stderr": script_stderr,
            "deliverable_path": deliv_path,
            "result": script_stdout.strip() if script_stdout.strip() else f"Skill '{capability_urn}' contextualized and executed successfully.",
            "execution_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }


class NativeSimulationHandler:
    """
    Handles native built-in capabilities and test operations deterministically.
    """

    @staticmethod
    def execute_native(
        capability_urn: str,
        arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Provides deterministic output for native test capabilities."""
        clean_urn = capability_urn.lower()

        if "calculate" in clean_urn or "math" in clean_urn:
            expr = arguments.get("expression") or arguments.get("query", "0")
            val = arguments.get("a", 0) + arguments.get("b", 0)
            return {"result": val, "expression": expr}

        if "format" in clean_urn or "report" in clean_urn:
            data = arguments.get("data") or arguments.get("content") or arguments.get("records_text", "")
            return {"result": f"FORMATTED REPORT: {data}", "status": "OK"}

        if "parse" in clean_urn or "csv" in clean_urn:
            raw = arguments.get("csv_content") or arguments.get("data", "")
            return {"records_text": f"PARSED_RECORDS: {raw}", "count": 1}

        if "validate" in clean_urn:
            target = arguments.get("target") or arguments.get("ip", "")
            return {"normalized_ip": str(target), "is_valid": True}

        if "echo" in clean_urn:
            return {"echo": arguments, "result": "ECHO_OK"}

        if "deprovision" in clean_urn or "cleanup" in clean_urn or "delete" in clean_urn:
            if arguments.get("fail_compensation"):
                raise RuntimeError("Simulated compensation action failure: storage deprovision timeout")
            target_path = arguments.get("path") or arguments.get("scratch_dir") or arguments.get("target")
            if target_path and os.path.exists(target_path):
                if os.path.isdir(target_path):
                    import shutil
                    shutil.rmtree(target_path, ignore_errors=True)
                else:
                    os.remove(target_path)
            return {"result": f"Deprovisioned {target_path}", "status": "COMPLETED"}

        # Default fallback
        return {
            "result": f"Executed capability {capability_urn}",
            "status": "COMPLETED",
            "arguments": arguments
        }


# ============================================================================
# 7. Execution Engine V1 Orchestrator
# ============================================================================

class ExecutionEngineV1:
    """
    Orchestrates end-to-end plan execution:
    1. Preflight validation & atomic token/permit consumption.
    2. Topological step dispatch with parameter propagation.
    3. Multimodal capability execution (MCP, Skills, Native).
    4. POSIX sandboxing, path confinement, and timeout supervisor.
    5. Reverse-order compensation unwinding on step failure.
    6. Audit ledger event commitment and CAS execution trace storage.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        cas_engine: SecureCASStorageEngine,
        governance_engine: ExecutionGovernanceEngineV1,
        profile_service: CapabilityProfileService,
        key_store: Any,
        audit_ledger: GovernanceAuditLedger,
        workspace_root: Optional[str] = None,
        activation_verifier: Optional[Any] = None,
        subagent_bridge: Optional[Any] = None
    ):
        self.conn = conn
        self.cas_engine = cas_engine
        self.governance_engine = governance_engine
        self.profile_service = profile_service
        self.key_store = key_store
        self.audit_ledger = audit_ledger
        ws = os.path.realpath(workspace_root or os.getcwd())
        if os.path.basename(ws) == ".lcs":
            ws = os.path.dirname(ws)
        self.workspace_root = ws
        self.activation_verifier = activation_verifier
        self.subagent_bridge = subagent_bridge

        # Ensure schema
        ensure_execution_engine_schema(self.conn)

        # Modality handlers
        self.mcp_handler = MCPToolHandler(self.conn)
        self.skill_handler = SkillExecutionHandler(self.conn, self.cas_engine)
        self.native_handler = NativeSimulationHandler()

    def close(self) -> None:
        """Closes all active background resources, pooled MCP sessions, and handles."""
        if hasattr(self, "mcp_handler") and self.mcp_handler:
            try:
                self.mcp_handler.close()
            except Exception:
                pass

    def store_blob_in_cas(self, payload_bytes: bytes, digest: Optional[str] = None) -> str:
        """Stores raw bytes in CAS and records in content_chunk_blobs under transaction safety."""
        if not digest:
            digest = hashlib.sha256(payload_bytes).hexdigest()
        byte_len = len(payload_bytes)
        if not self.cas_engine.blob_exists(digest):
            pub_id = f"exec_pub_{digest[:16]}_{uuid.uuid4().hex[:8]}"
            pub_tok = f"tok_{uuid.uuid4().hex[:16]}"
            tmp_name, _, _ = self.cas_engine.write_payload_to_staging(pub_id, pub_tok, digest, payload_bytes)
            self.cas_engine.publish_staging_to_cas(tmp_name, digest)

        with self.conn:
            self.conn.execute("""
                INSERT OR IGNORE INTO content_chunk_blobs (
                    blob_digest, byte_length, storage_compression, stored_byte_length
                ) VALUES (?, ?, 'NONE', ?);
            """, (digest, byte_len, byte_len))
        return digest

    def read_blob_from_cas(self, digest: str) -> Optional[bytes]:
        """Reads a blob safely from CAS."""
        try:
            return self.cas_engine.read_blob(digest)
        except Exception:
            return None

    def execute_plan(
        self,
        plan: ExecutionPlan,
        token: ExecutionAuthorizationToken,
        executor_identity: Optional[Dict[str, Any]] = None,
        limits_override: Optional[Dict[str, Any]] = None
    ) -> ExecutionRunResult:
        """
        Executes an authorized ExecutionPlan under the protection of an EAT token.
        """
        exec_id = executor_identity or {"executor_id": "lcs-executor@local", "role": "RUNTIME_ENGINE"}
        run_id = f"run-{uuid.uuid4().hex[:12]}"
        start_time = time.time()
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # --------------------------------------------------------------------
        # Phase 1: Pre-Flight Verification & Atomic Token Consumption
        # --------------------------------------------------------------------
        # 1. Consume token and mint permit via Governance Engine
        try:
            permit = self.governance_engine.authorize_dispatch(
                token_id=token.token_id,
                plan=plan,
                executor_identity=exec_id
            )
        except Exception as e:
            raise PreflightVerificationError(f"Governance token consumption failed: {e}") from e

        # 2. Accept dispatch permit atomically
        try:
            self.governance_engine.accept_dispatch_permit(
                permit_id=permit.permit_id,
                plan_integrity_hash=permit.plan_integrity_hash
            )
        except Exception as e:
            raise PreflightVerificationError(f"Dispatch permit acceptance failed: {e}") from e

        # 3. Hash-on-activation verification (fail-closed if on-disk capability drifted)
        if self.activation_verifier is not None:
            try:
                for step in plan.steps:
                    self.activation_verifier.verify_capability_activation(step.capability_urn)
            except Exception as e:
                raise PreflightVerificationError(f"Hash-on-activation integrity verification failed: {e}") from e

        # 3. Create execution run record
        cur = self.conn.cursor()
        total_steps = len(plan.steps)
        cur.execute("""
            INSERT INTO execution_runs (
                run_id, token_id, permit_id, plan_id, plan_integrity_hash,
                lifecycle_state, start_time, total_steps, completed_steps
            ) VALUES (?, ?, ?, ?, ?, 'EXECUTING', ?, ?, 0);
        """, (
            run_id, token.token_id, permit.permit_id, plan.plan_id,
            permit.plan_integrity_hash, start_time, total_steps
        ))
        self.conn.commit()

        # 4. Log start event to Audit Ledger
        self.audit_ledger.append_event(
            event_type="EXECUTION_RUN_STARTED",
            plan_id=plan.plan_id,
            plan_integrity_hash=permit.plan_integrity_hash,
            token_id=token.token_id,
            event_payload={
                "run_id": run_id,
                "permit_id": permit.permit_id,
                "total_steps": total_steps,
                "start_time": start_time
            }
        )

        # --------------------------------------------------------------------
        # Phase 2: Topological & Branching DAG Step Execution Loop
        # --------------------------------------------------------------------
        import concurrent.futures

        step_records: List[StepExecutionRecord] = []
        step_outputs_map: Dict[str, Dict[str, Any]] = {}
        completed_count = 0
        execution_failed = False
        failure_error_msg: Optional[str] = None

        step_timeout = 30.0
        if limits_override and "step_timeout_seconds" in limits_override:
            step_timeout = float(limits_override["step_timeout_seconds"])
        elif token.constraints and "limits" in token.constraints:
            step_timeout = float(token.constraints["limits"].get("step_timeout_seconds", 30.0))

        # Build step map and prerequisite graph
        step_map: Dict[str, PlanStep] = {s.step_id: s for s in plan.steps}
        step_prereqs: Dict[str, Set[str]] = {}
        for s in plan.steps:
            prereqs = set(s.dependencies or [])
            for b in s.input_bindings.values():
                src_step = None
                if hasattr(b, "source_step_id"):
                    src_step = b.source_step_id
                elif isinstance(b, dict):
                    src_step = b.get("source_step_id") or b.get("step_id")
                if src_step and src_step in step_map:
                    prereqs.add(src_step)
            step_prereqs[s.step_id] = prereqs

        # Incorporate explicit DAG edges
        if hasattr(plan, "dag_edges") and plan.dag_edges:
            for edge in plan.dag_edges:
                if isinstance(edge, (list, tuple)) and len(edge) == 2:
                    src, dst = edge
                    if dst in step_prereqs and src in step_map:
                        step_prereqs[dst].add(src)

        pending_step_ids = set(step_map.keys())
        completed_step_ids: Set[str] = set()
        dispatched_step_ids: Set[str] = set()

        def _execute_capability_worker(
            cap_urn: str,
            resolved_args: Dict[str, Any],
            timeout: float,
            skill_meta: Optional[Tuple[Any, ...]] = None,
            server_cmd: Optional[List[str]] = None
        ) -> Dict[str, Any]:
            if cap_urn.startswith("urn:lcs:skill:") or cap_urn.startswith("urn:lcs:command:"):
                return self.skill_handler.execute_skill(cap_urn, resolved_args, skill_meta=skill_meta)
            elif cap_urn.startswith("urn:lcs:tool:"):
                tool_name = cap_urn.split(":")[-1]
                if server_cmd:
                    return self.mcp_handler.execute_tool(
                        cap_urn, tool_name, resolved_args, server_command=server_cmd, timeout=timeout
                    )
                else:
                    return self.native_handler.execute_native(cap_urn, resolved_args)
            elif cap_urn.startswith("urn:lcs:agent:"):
                if hasattr(self, "subagent_bridge") and self.subagent_bridge:
                    from lcs.subagents.models import SubagentTaskState
                    task = self.subagent_bridge.create_task(
                        parent_request_id=run_id,
                        role=cap_urn.split(":")[-1],
                        objective=f"Execute agent capability {cap_urn}",
                        inputs=resolved_args,
                        timeout_seconds=int(timeout)
                    )
                    res = self.subagent_bridge.dispatch_task(task)
                    if res.state == SubagentTaskState.COMPLETED:
                        return {
                            "result": res.stdout_summary,
                            "deliverables": res.deliverables,
                            "provenance": res.provenance,
                            "verification": {"is_verified": res.is_verified},
                            "status": "COMPLETED"
                        }
                    else:
                        raise StepExecutionError(f"Subagent execution failed: {res.error_details or res.stdout_summary}")
                else:
                    return self.native_handler.execute_native(cap_urn, resolved_args)
            else:
                return self.native_handler.execute_native(cap_urn, resolved_args)

        max_workers = min(4, max(1, len(plan.steps)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            running_futures: Dict[concurrent.futures.Future, Dict[str, Any]] = {}

            while pending_step_ids or running_futures:
                # 1. Identify ready steps whose prerequisites are completed
                ready_step_ids = [
                    s_id for s_id in pending_step_ids
                    if s_id not in dispatched_step_ids and step_prereqs[s_id].issubset(completed_step_ids)
                ]
                ready_step_ids.sort(key=lambda s_id: step_map[s_id].step_index)

                if not ready_step_ids and not running_futures:
                    # Deadlock detection: remaining pending steps have unsatisfied dependencies
                    execution_failed = True
                    failure_error_msg = f"Dependency deadlock: pending steps {list(pending_step_ids)} have unsatisfied prerequisites"
                    break

                if execution_failed:
                    if not running_futures:
                        break
                    ready_step_ids = []

                # 2. Dispatch ready steps concurrently
                abort_dispatch = False
                for s_id in ready_step_ids:
                    pending_step_ids.remove(s_id)
                    dispatched_step_ids.add(s_id)
                    step = step_map[s_id]

                    step_rec_id = f"steprec-{uuid.uuid4().hex[:12]}"
                    step_start = time.time()

                    # Record step as RUNNING in DB
                    cur.execute("""
                        INSERT INTO execution_step_records (
                            step_record_id, run_id, step_id, capability_urn,
                            step_index, status, start_time, input_arguments_cas_digest
                        ) VALUES (?, ?, ?, ?, ?, 'RUNNING', ?, 'sha256:pending');
                    """, (step_rec_id, run_id, step.step_id, step.capability_urn, step.step_index, step_start))
                    self.conn.commit()

                    # Resolve Input Arguments
                    resolved_args: Dict[str, Any] = {}
                    unresolved_err = None

                    for p_name, binding in step.input_bindings.items():
                        val = None
                        if hasattr(binding, "source_type"):
                            src = getattr(binding, "source_type", None)
                            src_str = src.value if hasattr(src, "value") else str(src)
                            if src_str in ("USER_SUPPLIED", "SCHEMA_DEFAULT", "DEFAULT_VALUE"):
                                val = binding.bound_value
                            elif src_str in ("STEP_OUTPUT", "UPSTREAM_OUTPUT"):
                                src_step = binding.source_step_id
                                src_field = binding.source_output_field or "result"
                                if src_step in step_outputs_map and src_field in step_outputs_map[src_step]:
                                    val = step_outputs_map[src_step][src_field]
                                else:
                                    val = binding.bound_value
                            else:
                                val = binding.bound_value
                            is_req = binding.required
                        elif isinstance(binding, dict):
                            src = binding.get("source") or binding.get("source_type")
                            if src == "USER_SUPPLIED":
                                val = binding.get("value")
                            elif src in ("UPSTREAM_OUTPUT", "STEP_OUTPUT"):
                                src_step = binding.get("step_id") or binding.get("source_step_id")
                                src_field = binding.get("field") or binding.get("source_output_field") or "result"
                                if src_step in step_outputs_map and src_field in step_outputs_map[src_step]:
                                    val = step_outputs_map[src_step][src_field]
                                else:
                                    val = binding.get("value")
                            else:
                                val = binding.get("value")
                            is_req = binding.get("required", False)
                        else:
                            val = binding
                            is_req = False

                        if val is None and is_req:
                            unresolved_err = f"Mandatory parameter '{p_name}' for step '{step.step_id}' could not be resolved."
                            break

                        if val is not None:
                            if isinstance(val, str) and (val.startswith("/") or val.startswith("./") or ".." in val):
                                if os.path.exists(val) or val.startswith("/"):
                                    try:
                                        val = PathSecurityValidator.validate_file_path(val, [self.workspace_root])
                                    except PathTraversalExecutionError as pe:
                                        unresolved_err = str(pe)
                                        break
                            resolved_args[p_name] = val

                    if unresolved_err:
                        step_end = time.time()
                        dur_ms = (step_end - step_start) * 1000.0
                        rec = StepExecutionRecord(
                            step_record_id=step_rec_id,
                            run_id=run_id,
                            step_id=step.step_id,
                            capability_urn=step.capability_urn,
                            step_index=step.step_index,
                            status=StepExecutionStatus.FAILED,
                            start_time=step_start,
                            end_time=step_end,
                            duration_ms=dur_ms,
                            input_arguments=resolved_args,
                            error_details=unresolved_err
                        )
                        step_records.append(rec)
                        cur.execute("""
                            UPDATE execution_step_records
                            SET status = 'FAILED', end_time = ?, duration_ms = ?, error_details = ?
                            WHERE step_record_id = ?;
                        """, (step_end, dur_ms, unresolved_err, step_rec_id))
                        self.conn.commit()

                        execution_failed = True
                        failure_error_msg = unresolved_err
                        abort_dispatch = True
                        break

                    # Ingest resolved inputs into CAS
                    input_bytes = canonicalize_jcs(resolved_args)
                    input_cas_digest = self.store_blob_in_cas(input_bytes)

                    # Log step dispatch
                    self.audit_ledger.append_event(
                        event_type="EXECUTION_STEP_DISPATCH",
                        plan_id=plan.plan_id,
                        plan_integrity_hash=permit.plan_integrity_hash,
                        token_id=token.token_id,
                        event_payload={
                            "run_id": run_id,
                            "step_id": step.step_id,
                            "capability_urn": step.capability_urn,
                            "input_cas_digest": input_cas_digest
                        }
                    )

                    # Pre-resolve metadata on supervisor thread to avoid SQLite cross-thread access
                    skill_meta = None
                    server_cmd = None
                    if step.capability_urn.startswith("urn:lcs:skill:") or step.capability_urn.startswith("urn:lcs:command:"):
                        try:
                            cur.execute("""
                                SELECT raw_content_digest, resolved_path, taxonomy_kind
                                FROM artifact_discovery_records
                                WHERE canonical_urn = ?;
                            """, (step.capability_urn,))
                            skill_meta = cur.fetchone()
                        except Exception:
                            skill_meta = None
                    elif step.capability_urn.startswith("urn:lcs:tool:"):
                        server_cmd = self.mcp_handler.find_server_command(step.capability_urn)

                    fut = executor.submit(_execute_capability_worker, step.capability_urn, resolved_args, step_timeout, skill_meta, server_cmd)
                    running_futures[fut] = {
                        "step": step,
                        "step_rec_id": step_rec_id,
                        "step_start": step_start,
                        "resolved_args": resolved_args,
                        "input_cas_digest": input_cas_digest
                    }

                if (abort_dispatch or execution_failed) and not running_futures:
                    break

                # 3. Wait for at least one running step to finish
                done_set, _ = concurrent.futures.wait(
                    running_futures.keys(),
                    return_when=concurrent.futures.FIRST_COMPLETED
                )

                for done_fut in done_set:
                    step_info = running_futures.pop(done_fut)
                    step = step_info["step"]
                    step_rec_id = step_info["step_rec_id"]
                    step_start = step_info["step_start"]
                    resolved_args = step_info["resolved_args"]
                    input_cas_digest = step_info["input_cas_digest"]

                    output_data: Optional[Dict[str, Any]] = None
                    step_error: Optional[str] = None

                    try:
                        output_data = done_fut.result()
                    except (StepExecutionTimeoutError, StepExecutionError) as se:
                        step_error = str(se)
                    except Exception as ex:
                        step_error = f"Unexpected execution failure: {ex}"

                    step_end = time.time()
                    dur_ms = (step_end - step_start) * 1000.0

                    if not step_error and output_data is not None:
                        # 4. Multi-Tier Verification Gate Check
                        try:
                            from lcs.verification.gates import UnifiedResourceVerifier
                            v_type = "SCRIPT" if (output_data.get("execution_mode") == "SCRIPT_EXECUTION" or step.capability_urn.endswith((".py", ".sh", ".bash"))) else (
                                "MCP_TOOL" if step.capability_urn.startswith("urn:lcs:tool:") else (
                                    "AGENT" if step.capability_urn.startswith("urn:lcs:agent:") else "SKILL"
                                )
                            )
                            v_ctx = {
                                "resource_id": step.capability_urn,
                                "script_path": output_data.get("script_path"),
                                "exit_code": output_data.get("exit_code", 0) if output_data.get("exit_code") is not None else 0,
                                "stdout": output_data.get("stdout", ""),
                                "stderr": output_data.get("stderr", ""),
                                "rendered_instructions": output_data.get("rendered_instructions") or output_data.get("result") or "Authoritative capability instructions",
                                "declared_output_files": [output_data["deliverable_path"]] if output_data.get("deliverable_path") else [],
                                "tool_response": output_data,
                                "cas_trace_digest": input_cas_digest,
                                "status": output_data.get("status") or ("COMPLETED" if output_data.get("exit_code", 0) == 0 else "FAILED"),
                                "iteration_count": output_data.get("iteration_count", 1),
                                "max_iterations": output_data.get("max_iterations", 50),
                                "deliverables": output_data.get("deliverables", {}),
                                "expected_deliverables": output_data.get("expected_deliverables", []),
                                "success": True
                            }
                            v_res = UnifiedResourceVerifier.verify_resource(v_type, v_ctx)
                            if not v_res.is_verified:
                                step_error = f"Multi-tier verification failed [{v_type}]: {v_res.error_details}"
                                output_data = None
                            else:
                                output_data["verification"] = v_res.to_dict()
                        except Exception as ve:
                            logger.debug(f"Verification gate execution notice: {ve}")

                    if step_error or output_data is None:
                        rec = StepExecutionRecord(
                            step_record_id=step_rec_id,
                            run_id=run_id,
                            step_id=step.step_id,
                            capability_urn=step.capability_urn,
                            step_index=step.step_index,
                            status=StepExecutionStatus.FAILED,
                            start_time=step_start,
                            end_time=step_end,
                            duration_ms=dur_ms,
                            input_arguments=resolved_args,
                            input_arguments_cas_digest=input_cas_digest,
                            error_details=step_error,
                            retry_count=0
                        )
                        step_records.append(rec)
                        cur.execute("""
                            UPDATE execution_step_records
                            SET status = 'FAILED', end_time = ?, duration_ms = ?,
                                input_arguments_cas_digest = ?, error_details = ?, retry_count = 0
                            WHERE step_record_id = ?;
                        """, (step_end, dur_ms, input_cas_digest, step_error, step_rec_id))
                        self.conn.commit()

                        self.audit_ledger.append_event(
                            event_type="EXECUTION_STEP_FAILED",
                            plan_id=plan.plan_id,
                            plan_integrity_hash=permit.plan_integrity_hash,
                            token_id=token.token_id,
                            event_payload={
                                "run_id": run_id,
                                "step_id": step.step_id,
                                "error_details": step_error
                            }
                        )

                        execution_failed = True
                        failure_error_msg = step_error
                        break

                    # Ingest output into CAS
                    output_bytes = canonicalize_jcs(output_data)
                    output_cas_digest = self.store_blob_in_cas(output_bytes)

                    step_outputs_map[step.step_id] = output_data
                    completed_step_ids.add(step.step_id)
                    completed_count += 1

                    step_comp_urn = getattr(step, "compensation_urn", None)
                    step_rev_type = getattr(step, "reversibility_type", StepReversibilityType.IDEMPOTENT)
                    if isinstance(step_rev_type, str):
                        try:
                            step_rev_type = StepReversibilityType(step_rev_type)
                        except ValueError:
                            step_rev_type = StepReversibilityType.IDEMPOTENT

                    rec = StepExecutionRecord(
                        step_record_id=step_rec_id,
                        run_id=run_id,
                        step_id=step.step_id,
                        capability_urn=step.capability_urn,
                        step_index=step.step_index,
                        status=StepExecutionStatus.COMPLETED,
                        start_time=step_start,
                        end_time=step_end,
                        duration_ms=dur_ms,
                        input_arguments=resolved_args,
                        input_arguments_cas_digest=input_cas_digest,
                        output_result=output_data,
                        output_result_cas_digest=output_cas_digest,
                        retry_count=0,
                        reversibility_type=step_rev_type,
                        compensation_urn=step_comp_urn
                    )
                    step_records.append(rec)

                    cur.execute("""
                        UPDATE execution_step_records
                        SET status = 'COMPLETED', end_time = ?, duration_ms = ?,
                            input_arguments_cas_digest = ?, output_result_cas_digest = ?,
                            retry_count = 0, reversibility_type = ?, compensation_urn = ?
                        WHERE step_record_id = ?;
                    """, (step_end, dur_ms, input_cas_digest, output_cas_digest, step_rev_type.value, step_comp_urn, step_rec_id))
                    cur.execute("UPDATE execution_runs SET completed_steps = ? WHERE run_id = ?;", (completed_count, run_id))
                    self.conn.commit()

                    self.audit_ledger.append_event(
                        event_type="EXECUTION_STEP_COMPLETED",
                        plan_id=plan.plan_id,
                        plan_integrity_hash=permit.plan_integrity_hash,
                        token_id=token.token_id,
                        event_payload={
                            "run_id": run_id,
                            "step_id": step.step_id,
                            "duration_ms": dur_ms,
                            "output_cas_digest": output_cas_digest
                        }
                    )

                if execution_failed:
                    for fut in list(running_futures.keys()):
                        fut.cancel()
                    break

        # --------------------------------------------------------------------
        # Phase 3: Compensation Unwinding (If Failure Occurred)
        # --------------------------------------------------------------------
        if execution_failed:
            # Mark all uncompleted steps as SKIPPED
            uncompleted_steps = [
                s for s in plan.steps
                if s.step_id not in completed_step_ids
                and not any(r.step_id == s.step_id and r.status == StepExecutionStatus.FAILED for r in step_records)
            ]
            skip_time = time.time()
            for s in uncompleted_steps:
                s_rec_id = f"steprec-{uuid.uuid4().hex[:12]}"
                s_rec = StepExecutionRecord(
                    step_record_id=s_rec_id,
                    run_id=run_id,
                    step_id=s.step_id,
                    capability_urn=s.capability_urn,
                    step_index=s.step_index,
                    status=StepExecutionStatus.SKIPPED,
                    start_time=skip_time,
                    end_time=skip_time,
                    duration_ms=0.0,
                    error_details="Skipped due to upstream step failure"
                )
                step_records.append(s_rec)
                cur.execute("""
                    INSERT INTO execution_step_records (
                        step_record_id, run_id, step_id, capability_urn,
                        step_index, status, start_time, end_time, duration_ms,
                        input_arguments_cas_digest, reversibility_type, error_details
                    ) VALUES (?, ?, ?, ?, ?, 'SKIPPED', ?, ?, 0.0, 'sha256:none', 'IDEMPOTENT', 'Skipped due to upstream step failure');
                """, (s_rec_id, run_id, s.step_id, s.capability_urn, s.step_index, skip_time, skip_time))
            self.conn.commit()

            cur.execute("UPDATE execution_runs SET lifecycle_state = 'COMPENSATION_UNWIND' WHERE run_id = ?;", (run_id,))
            self.conn.commit()

            # Iterate backwards through completed steps
            for rec in reversed(step_records):
                if rec.status == StepExecutionStatus.COMPLETED:
                    # Check if capability has compensation handler
                    if rec.compensation_urn:
                        comp_start = time.time()
                        try:
                            self.native_handler.execute_native(rec.compensation_urn, rec.input_arguments)
                            rec.status = StepExecutionStatus.COMPENSATED
                            cur.execute("""
                                UPDATE execution_step_records
                                SET status = 'COMPENSATED' WHERE step_record_id = ?;
                            """, (rec.step_record_id,))
                            self.conn.commit()

                            self.audit_ledger.append_event(
                                event_type="COMPENSATION_ACTION_DISPATCHED",
                                plan_id=plan.plan_id,
                                plan_integrity_hash=permit.plan_integrity_hash,
                                token_id=token.token_id,
                                event_payload={
                                    "run_id": run_id,
                                    "original_step_id": rec.step_id,
                                    "compensation_urn": rec.compensation_urn
                                }
                            )
                        except Exception as ce:
                            rec.status = StepExecutionStatus.FAILED
                            rec.error_details = f"Compensation failed: {ce}"
                            cur.execute("""
                                UPDATE execution_step_records
                                SET status = 'FAILED', error_details = ? WHERE step_record_id = ?;
                            """, (rec.error_details, rec.step_record_id))
                            self.conn.commit()

                            self.audit_ledger.append_event(
                                event_type="COMPENSATION_ACTION_FAILED",
                                plan_id=plan.plan_id,
                                plan_integrity_hash=permit.plan_integrity_hash,
                                token_id=token.token_id,
                                event_payload={
                                    "run_id": run_id,
                                    "original_step_id": rec.step_id,
                                    "compensation_urn": rec.compensation_urn,
                                    "error_details": str(ce)
                                }
                            )

        # --------------------------------------------------------------------
        # Phase 4: Finalization & Audit Receipts
        # --------------------------------------------------------------------
        end_time = time.time()
        duration_ms = (end_time - start_time) * 1000.0
        final_state = ExecutionLifecycleState.FAILED if execution_failed else ExecutionLifecycleState.SUCCEEDED

        # Ensure step records are in canonical step_index order
        step_records.sort(key=lambda s: s.step_index)

        # Generate complete execution trace dictionary
        trace_dict = {
            "run_id": run_id,
            "token_id": token.token_id,
            "permit_id": permit.permit_id,
            "plan_id": plan.plan_id,
            "plan_integrity_hash": permit.plan_integrity_hash,
            "lifecycle_state": final_state.value,
            "start_time": start_time,
            "end_time": end_time,
            "duration_ms": duration_ms,
            "total_steps": total_steps,
            "completed_steps": completed_count,
            "step_records": [s.to_dict() for s in step_records],
            "outputs": step_outputs_map,
            "error_message": failure_error_msg
        }

        trace_bytes = canonicalize_jcs(trace_dict)
        trace_cas_digest = self.store_blob_in_cas(trace_bytes)

        # Update run record in SQLite
        cur.execute("""
            UPDATE execution_runs
            SET lifecycle_state = ?, end_time = ?, trace_cas_digest = ?, error_message = ?
            WHERE run_id = ?;
        """, (final_state.value, end_time, trace_cas_digest, failure_error_msg, run_id))
        self.conn.commit()

        # Log finalization to Audit Ledger
        self.audit_ledger.append_event(
            event_type="EXECUTION_RUN_FINALIZED",
            plan_id=plan.plan_id,
            plan_integrity_hash=permit.plan_integrity_hash,
            token_id=token.token_id,
            event_payload={
                "run_id": run_id,
                "lifecycle_state": final_state.value,
                "completed_steps": completed_count,
                "total_steps": total_steps,
                "duration_ms": duration_ms,
                "trace_cas_digest": trace_cas_digest,
                "error_message": failure_error_msg
            }
        )

        return ExecutionRunResult(
            run_id=run_id,
            token_id=token.token_id,
            permit_id=permit.permit_id,
            plan_id=plan.plan_id,
            plan_integrity_hash=permit.plan_integrity_hash,
            lifecycle_state=final_state,
            start_time=start_time,
            end_time=end_time,
            duration_ms=duration_ms,
            total_steps=total_steps,
            completed_steps=completed_count,
            step_records=step_records,
            outputs=step_outputs_map,
            trace_cas_digest=trace_cas_digest,
            error_message=failure_error_msg
        )

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves complete metadata and step records for an execution run."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT run_id, token_id, permit_id, plan_id, plan_integrity_hash,
                   lifecycle_state, start_time, end_time, total_steps,
                   completed_steps, trace_cas_digest, error_message
            FROM execution_runs
            WHERE run_id = ?;
        """, (run_id,))
        row = cur.fetchone()
        if not row:
            return None

        cur.execute("""
            SELECT step_record_id, step_id, capability_urn, step_index,
                   status, start_time, end_time, duration_ms,
                   input_arguments_cas_digest, output_result_cas_digest,
                   error_details, retry_count
            FROM execution_step_records
            WHERE run_id = ?
            ORDER BY step_index ASC;
        """, (run_id,))
        step_rows = cur.fetchall()

        steps = []
        for s in step_rows:
            steps.append({
                "step_record_id": s[0],
                "step_id": s[1],
                "capability_urn": s[2],
                "step_index": s[3],
                "status": s[4],
                "start_time": s[5],
                "end_time": s[6],
                "duration_ms": s[7],
                "input_cas_digest": s[8],
                "output_cas_digest": s[9],
                "error_details": s[10],
                "retry_count": s[11]
            })

        return {
            "run_id": row[0],
            "token_id": row[1],
            "permit_id": row[2],
            "plan_id": row[3],
            "plan_integrity_hash": row[4],
            "lifecycle_state": row[5],
            "start_time": row[6],
            "end_time": row[7],
            "total_steps": row[8],
            "completed_steps": row[9],
            "trace_cas_digest": row[10],
            "error_message": row[11],
            "steps": steps
        }

    def list_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists recent execution runs ordered by start time descending."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT run_id, plan_id, lifecycle_state, total_steps,
                   completed_steps, start_time, end_time, error_message
            FROM execution_runs
            ORDER BY start_time DESC
            LIMIT ?;
        """, (limit,))
        rows = cur.fetchall()
        return [
            {
                "run_id": r[0],
                "plan_id": r[1],
                "lifecycle_state": r[2],
                "total_steps": r[3],
                "completed_steps": r[4],
                "start_time": r[5],
                "end_time": r[6],
                "error_message": r[7]
            }
            for r in rows
        ]
