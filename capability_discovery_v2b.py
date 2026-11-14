#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 4: Capability Discovery & MCP Integration
=================================================================
Implements:
1. SQLite FTS5 Discovery Index:
   - Full-text search over capability names, descriptions, categories, keywords, provenance.
   - Authoritative index reconstruction from CAS and database records.
2. MCP Discovery Adapter:
   - Connects to local MCP servers over standard I/O (JSON-RPC 2.0).
   - Executes protocol handshake (initialize, notifications/initialized).
   - Discovers tools via tools/list with pagination handling (nextCursor).
   - Normalizes tool names, descriptions, input schemas into canonical LCS definitions.
   - Explicitly rejects code execution (tools/call is disabled).
3. Registration & Zero-Trust Verification Pipeline:
   - Ingests normalized tools into M2 CAS storage and capability declarations.
   - Associates tools with an agent interface declaration.
   - Applies M3 cryptographic attestation and policy evaluation.
   - Preserves source provenance and verification status.
4. Grounded Search Interface:
   - Natural query resolution and keyword search over registered capabilities.
   - Returns structured search results including capability URN, provenance, and policy trust status.
"""

import os
import re
import sys
import json
import time
import uuid
import hashlib
import sqlite3
import subprocess
import threading
import queue
from typing import Dict, Any, List, Tuple, Optional, Set, NamedTuple

from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    CASError,
    CASValidationError,
    CASSecurityViolationError,
    CASBlobNotFoundError,
    CASDigestMismatchError
)
from capability_registry_v2b import (
    parse_canonical_urn,
    CanonicalCapabilityURN,
    CapabilityRegistrationService,
    CapabilityDefinition,
    CapabilityNotFoundError,
    SQLiteForeignKeyEnforcementError,
    InvalidCapabilityURNError
)
from interface_policy_v2b import (
    AgentDeclaration,
    InterfaceDeclaration,
    InterfaceCapabilityRef,
    InterfaceAttestation,
    InterfaceTrustPolicy,
    PolicyEvaluationDecision,
    InterfacePolicyService
)


# ----------------------------------------------------------------------------
# Custom Exceptions
# ----------------------------------------------------------------------------

class DiscoveryError(CASError):
    """Base exception for discovery and MCP integration errors."""
    pass

class MCPProtocolError(DiscoveryError):
    """Raised when an MCP server violates protocol expectations or returns an error."""
    pass

class MCPTimeoutError(MCPProtocolError):
    """Raised when an MCP server request exceeds the configured response timeout."""
    pass

class SchemaNormalizationError(DiscoveryError, CASValidationError):
    """Raised when an MCP tool declaration cannot be normalized to a canonical capability definition."""
    pass


# ----------------------------------------------------------------------------
# Data Models: Discovered Tool & Search Result
# ----------------------------------------------------------------------------

class NormalizedDiscoveredTool:
    """Normalized representation of a tool discovered from an MCP server."""
    def __init__(
        self,
        raw_name: str,
        canonical_urn: str,
        display_name: str,
        description: str,
        input_schema: Dict[str, Any],
        category: str,
        keywords: List[str],
        source_server_name: str,
        source_origin: str,
        output_schema: Optional[Dict[str, Any]] = None
    ):
        self.raw_name = raw_name
        self.canonical_urn = canonical_urn
        self.display_name = display_name
        self.description = description
        self.input_schema = input_schema
        self.output_schema = output_schema
        self.category = category
        self.keywords = list(keywords)
        self.source_server_name = source_server_name
        self.source_origin = source_origin

    def to_capability_definition(self, created_at: Optional[str] = None) -> CapabilityDefinition:
        """Converts the discovered tool into an authoritative LCS CapabilityDefinition."""
        parsed = parse_canonical_urn(self.canonical_urn)
        clean_id = parsed.identifier

        ts = created_at or time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())

        return CapabilityDefinition(
            capability_id=self.canonical_urn,
            display_name=self.display_name,
            description=self.description,
            capability_type="tool",
            schema_version=1,
            input_interface_ref=f"urn:lcs:interface:schema:{clean_id}-input",
            output_interface_ref=f"urn:lcs:interface:schema:{clean_id}-output",
            provenance={
                "author": self.source_server_name,
                "created_at": ts,
                "license": "Proprietary/Discovered",
                "source_origin": self.source_origin,
                "original_tool_name": self.raw_name
            },
            content_integrity={"digest_algorithm": "sha256"}
        )


class SearchResult(NamedTuple):
    """Grounded search result returned by the FTS5 discovery engine."""
    capability_urn: str
    name: str
    description: str
    capability_type: str
    category: str
    keywords: str
    provenance_author: str
    provenance_origin: str
    provenance_license: str
    trust_status: str
    rank: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_urn": self.capability_urn,
            "name": self.name,
            "description": self.description,
            "capability_type": self.capability_type,
            "category": self.category,
            "keywords": [k.strip() for k in self.keywords.split(",") if k.strip()],
            "provenance": {
                "author": self.provenance_author,
                "origin": self.provenance_origin,
                "license": self.provenance_license
            },
            "trust_status": self.trust_status,
            "relevance_rank": round(self.rank, 4)
        }


# ----------------------------------------------------------------------------
# Component 1: MCP Discovery Client
# ----------------------------------------------------------------------------

DEFAULT_SYSTEM_ENV_VARS: Set[str] = frozenset({
    "PATH", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR",
    "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE",
    "PYTHONPATH", "PYTHONHOME"
})


class MCPDiscoveryClient:
    """
    Subprocess-based JSON-RPC 2.0 client that connects to local MCP servers
    over standard I/O with process isolation, bounded timeouts, and safe cleanup.
    """
    def __init__(
        self,
        command: List[str],
        server_name: str = "local-mcp-server",
        timeout: float = 10.0,
        env_allowlist: Optional[Set[str]] = None,
        custom_env: Optional[Dict[str, str]] = None
    ):
        self.command = command
        self.server_name = server_name
        self.timeout = float(timeout)
        self.env_allowlist = set(env_allowlist) if env_allowlist else set()
        self.custom_env = dict(custom_env) if custom_env else {}
        self.process: Optional[subprocess.Popen] = None
        self._request_id = 1
        self._response_queue: queue.Queue = queue.Queue()
        self._stdout_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._stderr_lines: List[str] = []
        self._stderr_lock = threading.Lock()
        self._stop_event = threading.Event()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def _build_isolated_env(self) -> Dict[str, str]:
        """
        Constructs an isolated execution environment:
        - Preserves essential process execution variables (PATH, HOME, TMPDIR, etc.)
        - Forwards explicitly allowlisted host variables
        - Injects custom environment variables
        - Unlisted parent environment variables are dropped
        """
        allowed = set(DEFAULT_SYSTEM_ENV_VARS) | self.env_allowlist
        isolated: Dict[str, str] = {}
        for k, v in os.environ.items():
            if k in allowed:
                isolated[k] = v
        if self.custom_env:
            isolated.update(self.custom_env)
        return isolated

    def _redact_secrets(self, text: str) -> str:
        """Redacts sensitive values (tokens, secrets, credentials) from strings."""
        if not text:
            return ""
        all_vars = dict(self.custom_env)
        for k in self.env_allowlist:
            if k in os.environ:
                all_vars[k] = os.environ[k]

        result = text
        for k, v in all_vars.items():
            if not v or len(v) < 3:
                continue
            k_upper = k.upper()
            if any(s in k_upper for s in ("KEY", "SECRET", "TOKEN", "PASS", "AUTH", "CREDENTIAL", "PRIVATE")):
                result = result.replace(v, "***REDACTED***")
        return result

    def _get_stderr(self) -> str:
        with self._stderr_lock:
            raw = "".join(self._stderr_lines).strip()
            return self._redact_secrets(raw)

    def connect(self) -> None:
        """Spawns the local MCP server subprocess and performs the initialize handshake."""
        if self.process is not None:
            return

        isolated_env = self._build_isolated_env()

        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=isolated_env
            )
        except Exception as e:
            masked_cmd = [self._redact_secrets(str(c)) for c in self.command]
            raise MCPProtocolError(f"Failed to spawn MCP server process with command {masked_cmd}: {e}") from e

        self._stop_event.clear()
        self._response_queue = queue.Queue()
        with self._stderr_lock:
            self._stderr_lines = []

        proc = self.process

        def _stdout_worker():
            try:
                for line in iter(proc.stdout.readline, ""):
                    if self._stop_event.is_set():
                        break
                    self._response_queue.put(("LINE", line))
            except (OSError, ValueError):
                pass
            finally:
                self._response_queue.put(("EOF", None))

        def _stderr_worker():
            try:
                for line in iter(proc.stderr.readline, ""):
                    if self._stop_event.is_set():
                        break
                    with self._stderr_lock:
                        if len(self._stderr_lines) < 200:
                            self._stderr_lines.append(line)
            except (OSError, ValueError):
                pass

        self._stdout_thread = threading.Thread(target=_stdout_worker, daemon=True, name="mcp-stdout-reader")
        self._stderr_thread = threading.Thread(target=_stderr_worker, daemon=True, name="mcp-stderr-reader")
        self._stdout_thread.start()
        self._stderr_thread.start()

        # Step 1: Send initialize request
        init_req = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "LCS-Discovery-Adapter",
                    "version": "1.0.0"
                }
            }
        }
        init_resp = self._send_request(init_req)
        if "error" in init_resp:
            raise MCPProtocolError(f"MCP server rejected initialization: {init_resp['error']}")

        # Step 2: Send notifications/initialized notification
        notif = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        self._send_notification(notif)

    def disconnect(self) -> None:
        """Terminates the MCP server process cleanly without indefinite waits."""
        self._stop_event.set()
        proc = self.process
        self.process = None

        if proc is not None:
            # Signal EOF on stdin
            try:
                if proc.stdin and not proc.stdin.closed:
                    proc.stdin.close()
            except Exception:
                pass

            # Terminate safely with timeout, then force kill
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                        proc.wait(timeout=2.0)
                    except Exception:
                        pass
                except Exception:
                    pass

            try:
                if proc.stdout and not proc.stdout.closed:
                    proc.stdout.close()
            except Exception:
                pass
            try:
                if proc.stderr and not proc.stderr.closed:
                    proc.stderr.close()
            except Exception:
                pass

        if self._stdout_thread and self._stdout_thread.is_alive():
            self._stdout_thread.join(timeout=0.5)
        if self._stderr_thread and self._stderr_thread.is_alive():
            self._stderr_thread.join(timeout=0.5)

    def list_tools(self) -> List[Dict[str, Any]]:
        """
        Discovers all tools exposed by the MCP server using tools/list,
        traversing any pagination cursors until exhaustion.
        """
        if self.process is None:
            raise MCPProtocolError("MCP client is not connected")

        all_tools: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params: Dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor

            req = {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "tools/list",
                "params": params
            }
            resp = self._send_request(req)
            if "error" in resp:
                raise MCPProtocolError(f"MCP tools/list failed: {resp['error']}")

            result = resp.get("result", {})
            tools = result.get("tools", [])
            all_tools.extend(tools)

            cursor = result.get("nextCursor")
            if not cursor:
                break

        return all_tools

    def _next_id(self) -> int:
        req_id = self._request_id
        self._request_id += 1
        return req_id

    def _send_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        if self.process is None or self.process.poll() is not None:
            err = self._get_stderr()
            raise MCPProtocolError(f"MCP server process is not running. Stderr: {err}")

        line = json.dumps(req) + "\n"
        try:
            self.process.stdin.write(line)
            self.process.stdin.flush()
        except (OSError, BrokenPipeError) as e:
            err = self._get_stderr()
            raise MCPProtocolError(f"Failed writing to MCP server stdio (broken pipe/closed): {e}. Stderr: {err}") from e

        try:
            msg_type, payload = self._response_queue.get(timeout=self.timeout)
        except queue.Empty:
            method_name = req.get("method", "unknown")
            req_id = req.get("id", "unknown")
            # Safely terminate child process on timeout
            self.disconnect()
            raise MCPTimeoutError(
                f"MCP request '{method_name}' (id={req_id}) timed out after {self.timeout:.1f}s. "
                f"Child process was terminated safely."
            )

        if msg_type == "EOF":
            err_output = self._get_stderr()
            self.disconnect()
            raise MCPProtocolError(f"MCP server closed stdout unexpectedly. Stderr: {err_output}")

        resp_line = payload
        try:
            return json.loads(resp_line.strip())
        except json.JSONDecodeError as e:
            redacted = self._redact_secrets(resp_line.strip())
            raise MCPProtocolError(f"Malformed JSON response from MCP server: {redacted}") from e

    def _send_notification(self, notif: Dict[str, Any]) -> None:
        if self.process is None or self.process.poll() is not None:
            err = self._get_stderr()
            raise MCPProtocolError(f"MCP server process is not running. Stderr: {err}")

        line = json.dumps(notif) + "\n"
        try:
            self.process.stdin.write(line)
            self.process.stdin.flush()
        except (OSError, BrokenPipeError) as e:
            err = self._get_stderr()
            raise MCPProtocolError(f"Failed sending notification to MCP server: {e}. Stderr: {err}") from e


# ----------------------------------------------------------------------------
# Component 2: Schema Normalizer
# ----------------------------------------------------------------------------

class MCPSchemaNormalizer:
    """
    Normalizes raw MCP tool payloads into canonical LCS identifiers,
    structured descriptions, and formal CapabilityDefinitions.
    """
    @staticmethod
    def normalize_tool(
        tool_data: Dict[str, Any],
        server_name: str,
        namespace_prefix: str = "mcp"
    ) -> NormalizedDiscoveredTool:
        raw_name = tool_data.get("name")
        if not raw_name or not isinstance(raw_name, str):
            raise SchemaNormalizationError(f"MCP tool missing valid 'name': {tool_data}")

        raw_desc = tool_data.get("description", "")
        if not isinstance(raw_desc, str) or not raw_desc.strip():
            raw_desc = f"Tool '{raw_name}' discovered from MCP server '{server_name}'."
        raw_desc = raw_desc.strip()

        input_schema = tool_data.get("inputSchema", {})
        if not isinstance(input_schema, dict):
            input_schema = {}

        output_schema = tool_data.get("outputSchema")
        if not isinstance(output_schema, dict):
            output_schema = None

        # Canonicalize identifier: lowercase, replace underscores and invalid chars with hyphens
        clean_server = re.sub(r"[^a-z0-9-]", "-", server_name.lower().replace("_", "-")).strip("-") or "server"
        clean_id = re.sub(r"[^a-z0-9-]", "-", raw_name.lower().replace("_", "-")).strip("-")
        clean_id = re.sub(r"-+", "-", clean_id)
        if not clean_id:
            clean_id = f"tool-{uuid.uuid4().hex[:8]}"

        namespace = f"{namespace_prefix}.{clean_server}"
        canonical_urn = f"urn:lcs:tool:{namespace}:{clean_id}"

        # Validate canonical URN compliance
        try:
            parse_canonical_urn(canonical_urn)
        except InvalidCapabilityURNError as e:
            raise SchemaNormalizationError(
                f"Generated canonical URN '{canonical_urn}' is invalid: {e}"
            ) from e

        # Generate readable display name
        display_name = " ".join(word.capitalize() for word in clean_id.replace("_", "-").split("-"))

        # Infer category and keywords
        category = MCPSchemaNormalizer._infer_category(clean_id, raw_desc)
        keywords = MCPSchemaNormalizer._extract_keywords(clean_id, raw_desc)

        source_origin = f"mcp://{clean_server}/{raw_name}"

        return NormalizedDiscoveredTool(
            raw_name=raw_name,
            canonical_urn=canonical_urn,
            display_name=display_name,
            description=raw_desc,
            input_schema=input_schema,
            category=category,
            keywords=keywords,
            source_server_name=server_name,
            source_origin=source_origin,
            output_schema=output_schema
        )

    @staticmethod
    def _infer_category(identifier: str, description: str) -> str:
        text = f"{identifier} {description}".lower()
        if any(w in text for w in ("pdf", "doc", "document", "text", "convert", "extract")):
            return "document"
        elif any(w in text for w in ("sql", "db", "database", "query", "sqlite", "table")):
            return "database"
        elif any(w in text for w in ("math", "calc", "calculate", "sum", "arithmetic")):
            return "math"
        elif any(w in text for w in ("web", "http", "api", "fetch", "network", "url")):
            return "network"
        return "utility"

    @staticmethod
    def _extract_keywords(identifier: str, description: str) -> List[str]:
        words = re.findall(r"[a-zA-Z0-9]{3,}", f"{identifier} {description}".lower())
        stopwords = {"this", "that", "with", "from", "into", "path", "file", "local", "tool"}
        unique_words = []
        for w in words:
            if w not in stopwords and w not in unique_words:
                unique_words.append(w)
        return unique_words[:10]


# ----------------------------------------------------------------------------
# Component 3: FTS5 Discovery Index Service
# ----------------------------------------------------------------------------

class DiscoveryIndexService:
    """
    Manages SQLite FTS5 full-text indexing, keyword queries, and authoritative
    index rebuilds from CAS and relational declarations.
    """
    def __init__(self, conn: sqlite3.Connection):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("conn must be a sqlite3.Connection")
        self.conn = conn
        self.ensure_schema()

    def ensure_schema(self) -> None:
        """Applies the Milestone 4 FTS5 schema migration idempotently."""
        migration_path = os.path.join(os.path.dirname(__file__), "lcs_schema_m4_migration.sql")
        if not os.path.exists(migration_path):
            pkg_schema = os.path.join(os.path.dirname(__file__), "lcs", "schemas", "lcs_schema_m4_migration.sql")
            if os.path.exists(pkg_schema):
                migration_path = pkg_schema
        with open(migration_path, "r", encoding="utf-8") as f:
            ddl = f.read()
        self.conn.executescript(ddl)
        self.conn.commit()

    def index_capability(
        self,
        cap_def: CapabilityDefinition,
        trust_status: str = "UNVERIFIED",
        category: str = "utility",
        keywords: Optional[List[str]] = None
    ) -> None:
        """Indexes or updates a capability in the FTS5 discovery table."""
        keywords_str = ", ".join(keywords) if keywords else ""
        prov = cap_def.provenance or {}
        author = str(prov.get("author", "unknown"))
        origin = str(prov.get("source_origin", "unknown"))
        license_name = str(prov.get("license", "unknown"))

        cur = self.conn.cursor()
        # Remove existing FTS record if present
        cur.execute("DELETE FROM capability_fts WHERE capability_urn = ?;", (cap_def.capability_id,))

        cur.execute("""
            INSERT INTO capability_fts (
                capability_urn, name, description, capability_type, category,
                keywords, provenance_author, provenance_origin, provenance_license, trust_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            cap_def.capability_id,
            cap_def.display_name,
            cap_def.description,
            cap_def.capability_type,
            category,
            keywords_str,
            author,
            origin,
            license_name,
            trust_status
        ))
        self.conn.commit()

    def update_trust_status(self, capability_urn: str, new_status: str) -> bool:
        """Updates the trust status of an indexed capability."""
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE capability_fts
            SET trust_status = ?
            WHERE capability_urn = ?;
        """, (new_status, capability_urn))
        self.conn.commit()
        return cur.rowcount > 0

    def rebuild_index(
        self,
        cas_engine: SecureCASStorageEngine,
        iface_service: Optional[InterfacePolicyService] = None,
        policy: Optional[InterfaceTrustPolicy] = None
    ) -> int:
        """
        Reconstructs the FTS5 discovery index from authoritative registry records:
        1. Clears current FTS5 table.
        2. Queries all registered capabilities in capability_declarations.
        3. Reads exact definitions from CAS storage, verifying hash integrity.
        4. Resolves policy trust status from interface declarations.
        5. Re-indexes each capability.
        """
        cur = self.conn.cursor()
        cur.execute("DELETE FROM capability_fts;")

        cur.execute("""
            SELECT capability_urn, definition_blob_digest, display_name, capability_type
            FROM capability_declarations;
        """)
        rows = cur.fetchall()

        count = 0
        for cap_urn, digest, display_name, cap_type in rows:
            if not cas_engine.blob_exists(digest):
                continue
            payload = cas_engine.read_blob(digest)
            if hashlib.sha256(payload).hexdigest() != digest:
                continue

            cap_dict = json.loads(payload.decode("utf-8"))
            cap_def = CapabilityDefinition.from_dict(cap_dict)

            # Resolve trust status via interface bindings if service provided
            trust_status = "UNVERIFIED"
            if iface_service and policy:
                cur.execute("""
                    SELECT interface_urn FROM interface_capability_bindings
                    WHERE capability_urn = ?
                    LIMIT 1;
                """, (cap_urn,))
                b_row = cur.fetchone()
                if b_row:
                    dec = iface_service.evaluate_policy(b_row[0], policy)
                    trust_status = dec.status

            category = MCPSchemaNormalizer._infer_category(cap_urn, cap_def.description)
            keywords = MCPSchemaNormalizer._extract_keywords(cap_urn, cap_def.description)

            self.index_capability(
                cap_def=cap_def,
                trust_status=trust_status,
                category=category,
                keywords=keywords
            )
            count += 1

        self.conn.commit()
        return count

    def search(
        self,
        query: str,
        policy_filter: Optional[str] = None,
        limit: int = 10
    ) -> List[SearchResult]:
        """
        Performs grounded full-text search against registered capabilities.
        Uses FTS5 keyword matching with prefix support.
        """
        clean_terms = re.findall(r"[a-zA-Z0-9_-]+", query)
        if not clean_terms:
            return []

        # Construct FTS5 match query: (term1* OR term2* ...)
        fts_match = " OR ".join(f'"{term}"*' for term in clean_terms)

        sql = """
            SELECT capability_urn, name, description, capability_type, category,
                   keywords, provenance_author, provenance_origin, provenance_license,
                   trust_status, rank
            FROM capability_fts
            WHERE capability_fts MATCH ?
        """
        params: List[Any] = [fts_match]

        if policy_filter:
            sql += " AND trust_status = ?"
            params.append(policy_filter)

        sql += " ORDER BY rank LIMIT ?;"
        params.append(limit)

        cur = self.conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()

        results: List[SearchResult] = []
        for r in rows:
            results.append(SearchResult(
                capability_urn=r[0],
                name=r[1],
                description=r[2],
                capability_type=r[3],
                category=r[4],
                keywords=r[5],
                provenance_author=r[6],
                provenance_origin=r[7],
                provenance_license=r[8],
                trust_status=r[9],
                rank=float(r[10])
            ))
        return results


# ----------------------------------------------------------------------------
# Component 4: Unified Discovery & Attestation Pipeline
# ----------------------------------------------------------------------------

class DiscoverySummary:
    """Summary record of an MCP discovery, registration, and trust evaluation run."""
    def __init__(
        self,
        server_name: str,
        agent_urn: str,
        interface_urn: str,
        discovered_tools: List[NormalizedDiscoveredTool],
        registered_capabilities: List[str],
        attestation_id: str,
        policy_decision: PolicyEvaluationDecision
    ):
        self.server_name = server_name
        self.agent_urn = agent_urn
        self.interface_urn = interface_urn
        self.discovered_tools = discovered_tools
        self.registered_capabilities = registered_capabilities
        self.attestation_id = attestation_id
        self.policy_decision = policy_decision

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_name": self.server_name,
            "agent_urn": self.agent_urn,
            "interface_urn": self.interface_urn,
            "discovered_tool_count": len(self.discovered_tools),
            "registered_capability_urns": self.registered_capabilities,
            "attestation_id": self.attestation_id,
            "policy_decision": self.policy_decision.decision,
            "policy_status": self.policy_decision.status,
            "reasons": list(self.policy_decision.reasons)
        }


class CapabilityDiscoveryPipeline:
    """
    End-to-end orchestrator connecting MCP discovery, M2 registration,
    M3 attestation & policy evaluation, and M4 FTS5 indexing.
    """
    def __init__(
        self,
        conn: sqlite3.Connection,
        cas_engine: SecureCASStorageEngine,
        cap_service: Optional[CapabilityRegistrationService] = None,
        iface_service: Optional[InterfacePolicyService] = None,
        index_service: Optional[DiscoveryIndexService] = None,
        profile_service: Optional[Any] = None
    ):
        self.conn = conn
        self.cas_engine = cas_engine
        self.cap_service = cap_service or CapabilityRegistrationService(conn, cas_engine)
        self.iface_service = iface_service or InterfacePolicyService(conn, cas_engine, self.cap_service)
        self.index_service = index_service or DiscoveryIndexService(conn)
        if profile_service is not None:
            self.profile_service = profile_service
        else:
            try:
                from capability_profile_v2b import CapabilityProfileService
                self.profile_service = CapabilityProfileService(conn, cas_engine)
            except Exception:
                self.profile_service = None

    def discover_and_register_mcp_server(
        self,
        command: List[str],
        server_name: str,
        trust_policy: InterfaceTrustPolicy,
        attester_id: str = "urn:lcs:attester:security:local-authority",
        timeout: float = 10.0,
        env_allowlist: Optional[Set[str]] = None,
        custom_env: Optional[Dict[str, str]] = None
    ) -> DiscoverySummary:
        """
        Executes the 6-phase discovery, registration, attestation, and indexing flow:
        1. Connects to local MCP server and lists tools.
        2. Normalizes MCP tools into canonical LCS CapabilityDefinitions.
        3. Registers agent declaration in SQLite.
        4. Registers each capability in CAS & SQLite via M2.
        5. Registers interface declaration binding all capabilities via M3.
        6. Generates cryptographic attestation and evaluates policy.
        7. Indexes all capabilities into FTS5 with authoritative trust status.
        """
        # Phase 1: MCP tools/list
        with MCPDiscoveryClient(
            command=command,
            server_name=server_name,
            timeout=timeout,
            env_allowlist=env_allowlist,
            custom_env=custom_env
        ) as client:
            raw_tools = client.list_tools()

        # Phase 2: Schema Normalization
        discovered: List[NormalizedDiscoveredTool] = []
        for raw in raw_tools:
            norm = MCPSchemaNormalizer.normalize_tool(raw, server_name)
            discovered.append(norm)

        clean_server = re.sub(r"[^a-z0-9_-]", "-", server_name.lower()).strip("-")
        agent_urn = f"urn:lcs:agent:mcp.{clean_server}:host"
        interface_urn = f"urn:lcs:interface:mcp.{clean_server}:tools-v1"

        # Phase 3: Register Agent
        # Check if agent is already registered to preserve original creation timestamp
        cur = self.conn.cursor()
        cur.execute("SELECT provenance_json FROM agent_declarations WHERE agent_urn = ?;", (agent_urn,))
        agent_row = cur.fetchone()
        existing_agent_created_at = None
        if agent_row and agent_row[0]:
            try:
                existing_agent_prov = json.loads(agent_row[0])
                existing_agent_created_at = existing_agent_prov.get("created_at")
            except Exception:
                pass

        agent_decl = AgentDeclaration(
            agent_urn=agent_urn,
            display_name=f"MCP Server Host ({server_name})",
            description=f"Host agent for tools exposed by local MCP server '{server_name}'.",
            provenance={
                "author": server_name,
                "created_at": existing_agent_created_at or time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                "license": "Proprietary/Discovered",
                "source_origin": f"mcp://{clean_server}"
            }
        )
        self.iface_service.register_agent(agent_decl)

        # Phase 4: Register Capabilities in M2
        registered_urns: List[str] = []
        cap_refs: List[InterfaceCapabilityRef] = []
        resolved_cap_defs: List[CapabilityDefinition] = []

        for norm in discovered:
            cur.execute("""
                SELECT definition_blob_digest FROM capability_declarations
                WHERE capability_urn = ?;
            """, (norm.canonical_urn,))
            row = cur.fetchone()
            existing_cap_def = None
            if row:
                existing_digest = row[0]
                if self.cas_engine.blob_exists(existing_digest):
                    try:
                        raw_bytes = self.cas_engine.read_blob(existing_digest)
                        existing_data = json.loads(raw_bytes.decode("utf-8"))
                        existing_prov = existing_data.get("provenance", {})
                        stable_existing_prov = {
                            k: v for k, v in existing_prov.items()
                            if k not in ("created_at", "registered_at", "timestamp")
                        }
                        stable_proposed_prov = {
                            k: v for k, v in {
                                "author": norm.source_server_name,
                                "license": "Proprietary/Discovered",
                                "source_origin": norm.source_origin,
                                "original_tool_name": norm.raw_name
                            }.items()
                            if k in stable_existing_prov
                        }
                        if (all(existing_prov.get(k) == v for k, v in stable_proposed_prov.items()) and
                            existing_data.get("display_name") == norm.display_name and
                            existing_data.get("description") == norm.description):
                            existing_cap_def = CapabilityDefinition.from_dict(existing_data)
                    except Exception:
                        pass

            if existing_cap_def:
                cap_def = existing_cap_def
            else:
                cap_def = norm.to_capability_definition()

            reg_res = self.cap_service.register_capability(cap_def)
            registered_urns.append(reg_res.capability_id)
            cap_refs.append(InterfaceCapabilityRef(reg_res.capability_id, reg_res.blob_digest))
            resolved_cap_defs.append(cap_def)

        # Phase 5: Register Interface & Attest in M3
        # Check if interface already registered to preserve original creation timestamp
        cur.execute("SELECT declaration_blob_digest FROM interface_declarations WHERE interface_urn = ?;", (interface_urn,))
        iface_row = cur.fetchone()
        existing_iface_decl = None
        if iface_row and self.cas_engine.blob_exists(iface_row[0]):
            try:
                existing_decl_data = json.loads(self.cas_engine.read_blob(iface_row[0]).decode("utf-8"))
                existing_prov = existing_decl_data.get("provenance", {})
                stable_existing_prov = {
                    k: v for k, v in existing_prov.items()
                    if k not in ("created_at", "registered_at", "timestamp")
                }
                stable_proposed_prov = {
                    "author": server_name,
                    "license": "Proprietary/Discovered",
                    "source_origin": f"mcp://{clean_server}"
                }
                existing_caps = existing_decl_data.get("capabilities", [])
                proposed_caps = [c.to_dict() for c in cap_refs]
                if (stable_existing_prov == stable_proposed_prov and
                    existing_decl_data.get("agent_urn") == agent_urn and
                    existing_decl_data.get("interface_version") == 1 and
                    existing_caps == proposed_caps):
                    existing_iface_decl = InterfaceDeclaration.from_dict(existing_decl_data)
            except Exception:
                pass

        if existing_iface_decl:
            iface_decl = existing_iface_decl
        else:
            iface_decl = InterfaceDeclaration(
                interface_urn=interface_urn,
                agent_urn=agent_urn,
                interface_version=1,
                display_name=f"{server_name} Toolset Interface v1",
                description=f"Unified capability interface for {len(discovered)} tools from '{server_name}'.",
                capabilities=cap_refs,
                provenance={
                    "author": server_name,
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                    "license": "Proprietary/Discovered",
                    "source_origin": f"mcp://{clean_server}"
                }
            )
        self.iface_service.register_interface(iface_decl)

        att = self.iface_service.attest_interface(interface_urn, attester_id=attester_id)
        decision = self.iface_service.evaluate_policy(interface_urn, policy=trust_policy)

        # Phase 6: Index in FTS5 with Grounded Trust Status & Store Semantic Profile
        for norm, cap_def in zip(discovered, resolved_cap_defs):
            self.index_service.index_capability(
                cap_def=cap_def,
                trust_status=decision.status,
                category=norm.category,
                keywords=norm.keywords
            )
            if getattr(self, "profile_service", None):
                try:
                    cap_digest = next(
                        (c.expected_definition_digest for c in cap_refs if c.capability_urn == cap_def.capability_id),
                        None
                    )
                    prof = self.profile_service.generate_profile_from_schema(
                        capability_urn=cap_def.capability_id,
                        display_name=cap_def.display_name,
                        description=cap_def.description,
                        input_schema=norm.input_schema,
                        output_schema=getattr(norm, "output_schema", None),
                        category=norm.category,
                        agent_urn=agent_urn,
                        interface_urn=interface_urn,
                        attestation_id=att.attestation_id,
                        policy_status=decision.status,
                        source_origin=norm.source_origin,
                        source_author=norm.source_server_name,
                        definition_digest=cap_digest
                    )
                    self.profile_service.store_profile(prof)
                except Exception:
                    pass

        # Record MCP Server in registry
        self.conn.execute("""
            INSERT OR REPLACE INTO mcp_server_registrations (
                server_id, server_name, transport_type, command_line, last_sync_at
            ) VALUES (?, ?, 'STDIO', ?, datetime('now'));
        """, (clean_server, server_name, " ".join(command)))
        self.conn.commit()

        return DiscoverySummary(
            server_name=server_name,
            agent_urn=agent_urn,
            interface_urn=interface_urn,
            discovered_tools=discovered,
            registered_capabilities=registered_urns,
            attestation_id=att.attestation_id,
            policy_decision=decision
        )
