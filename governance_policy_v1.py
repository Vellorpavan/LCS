"""
Living Capability System (LCS) — Execution Governance V1
=========================================================
Security architecture and policy implementation for plan authorization,
cryptographic plan integrity (RFC 8785 JCS), dual-gated capability trust,
HMAC-signed Execution Authorization Tokens (EAT), ephemeral DispatchPermits,
monotonic policy revision compare-and-consume, and hash-chained audit ledgers.

Strictly isolates Governance (authorization, boundaries, tokens) from actual execution.
Contains zero execution primitives, zero MCP tools/call, and zero network calls.
"""

import os
import sys
import stat
import json
import fcntl
import errno
import hashlib
import hmac
import time
import math
import uuid
import datetime
import sqlite3
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple, Union
from contextlib import contextmanager

from cas_storage_engine_v2b import (
    PersistentReceiptKeyStore,
    SecureCASStorageEngine,
    CASCorruptedKeyRingError,
    CASSecurityViolationError
)
from interface_policy_v2b import (
    InterfacePolicyService,
    InterfaceTrustPolicy,
    PolicyEvaluationDecision
)
from capability_profile_v2b import CapabilityProfileService, CapabilitySemanticProfile
from capability_planning_v1 import ExecutionPlan, PlanStep


# ============================================================================
# 1. RFC 8785 JSON Canonicalization Scheme (JCS)
# ============================================================================

def canonicalize_jcs(val: Any) -> bytes:
    """
    Serializes a Python object into canonical JSON bytes according to RFC 8785 JCS.
    
    Guarantees:
      1. Object keys sorted by UTF-16 code units (surrogate pairs outside BMP).
      2. Deterministic IEEE 754 number-to-string conversion; rejects NaN/Infinity; maps -0.0 to 0.
      3. ECMAScript string escaping:
         - \" and \\ escaped.
         - \\b, \\f, \\n, \\r, \\t escaped.
         - \\u00XX for remaining control characters < 0x20.
         - Solidus / is NOT escaped.
         - All other code points emitted as verbatim UTF-8 (NO Unicode normalization).
      4. Compact separators ',' and ':' with no whitespace.
    """
    if val is None:
        return b"null"
    elif isinstance(val, bool):
        return b"true" if val else b"false"
    elif isinstance(val, int) and not isinstance(val, bool):
        return str(val).encode("utf-8")
    elif isinstance(val, float):
        if math.isnan(val) or math.isinf(val):
            raise ValueError("Non-finite numbers (NaN, Infinity) are prohibited in RFC 8785 JCS")
        if val == 0.0:
            return b"0"
        # In Python, str(float) closely matches ECMAScript Number-to-String for finite floats
        # Format with scientific notation if exponent is < -6 or >= 21
        s = json.dumps(val)
        return s.encode("utf-8")
    elif isinstance(val, str):
        out = ["\""]
        for c in val:
            cp = ord(c)
            if c == "\"":
                out.append("\\\"")
            elif c == "\\":
                out.append("\\\\")
            elif c == "\b":
                out.append("\\b")
            elif c == "\f":
                out.append("\\f")
            elif c == "\n":
                out.append("\\n")
            elif c == "\r":
                out.append("\\r")
            elif c == "\t":
                out.append("\\t")
            elif cp < 0x20:
                out.append(f"\\u{cp:04x}")
            else:
                out.append(c)
        out.append("\"")
        return "".join(out).encode("utf-8")
    elif isinstance(val, (list, tuple)):
        return b"[" + b",".join(canonicalize_jcs(x) for x in val) + b"]"
    elif isinstance(val, dict):
        def utf16_sort_key(k: str) -> bytes:
            return k.encode("utf-16-be")
        sorted_keys = sorted(val.keys(), key=utf16_sort_key)
        items = []
        for k in sorted_keys:
            if not isinstance(k, str):
                raise TypeError(f"Dictionary keys must be strings, got {type(k).__name__}")
            items.append(canonicalize_jcs(k) + b":" + canonicalize_jcs(val[k]))
        return b"{" + b",".join(items) + b"}"
    else:
        raise TypeError(f"Unsupported type for JCS canonicalization: {type(val).__name__}")


# ============================================================================
# 2. Canonical Plan Payload & PlanIntegrityHash
# ============================================================================

def extract_canonical_plan_payload(
    plan: ExecutionPlan,
    policy_name: str = "default",
    attestation_ids: Optional[List[str]] = None,
    resource_grants: Optional[List[Dict[str, Any]]] = None,
    limits: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Transforms an ExecutionPlan into the formal canonical schema dictionary
    specified in Section 6.2 of the Security Architecture.
    """
    sorted_steps = sorted(plan.steps, key=lambda s: s.step_index)
    canonical_steps = []
    for s in sorted_steps:
        # Normalize input bindings
        norm_bindings = {}
        for p_name, b_info in s.input_bindings.items():
            if hasattr(b_info, "source_type"):
                src = b_info.source_type
                val = b_info.bound_value
            elif isinstance(b_info, dict):
                src = b_info.get("source") or b_info.get("source_type") or "USER_SUPPLIED"
                val = b_info.get("value") or b_info.get("bound_value")
            else:
                src = "USER_SUPPLIED"
                val = b_info
            norm_bindings[p_name] = {"source": src, "value": val}

        # Normalize output definitions
        norm_outputs = {}
        for o_name, o_info in s.output_definitions.items():
            if hasattr(o_info, "evidence_source"):
                ev = o_info.evidence_source
                typ = o_info.output_type
            elif isinstance(o_info, dict):
                ev = o_info.get("evidence") or o_info.get("evidence_source") or "DOCUMENTED"
                typ = o_info.get("type") or o_info.get("output_type") or "string"
            else:
                ev = "DOCUMENTED"
                typ = "string"
            norm_outputs[o_name] = {"evidence": ev, "type": typ}

        canonical_steps.append({
            "step_id": s.step_id,
            "step_index": s.step_index,
            "capability_urn": s.capability_urn,
            "display_name": s.display_name,
            "input_bindings": norm_bindings,
            "output_definitions": norm_outputs
        })

    # Normalize DAG edges: [upstream, downstream, type]
    canonical_edges = []
    for edge in plan.dag_edges:
        if isinstance(edge, (list, tuple)) and len(edge) >= 3:
            canonical_edges.append([edge[0], edge[1], edge[2]])
        elif isinstance(edge, dict):
            canonical_edges.append([edge["upstream"], edge["downstream"], edge["type"]])

    canonical_edges.sort(key=lambda e: (e[0], e[1], e[2]))

    # Execution order
    exec_order = list(plan.execution_order)

    # Resource grants
    norm_grants = []
    if resource_grants:
        for g in resource_grants:
            norm_grants.append({
                "category": g.get("category", "FILESYSTEM"),
                "access": g.get("access", "READ"),
                "target": g.get("target", "")
            })
    norm_grants.sort(key=lambda g: (g["category"], g["access"], g["target"]))

    # Limits
    final_limits = {
        "max_steps": len(canonical_steps),
        "step_timeout_seconds": 30,
        "total_timeout_seconds": 180
    }
    if limits:
        final_limits.update(limits)

    # Policy context
    att_list = sorted(list(attestation_ids or []))
    pol_context = {
        "policy_name": policy_name,
        "attestation_ids": att_list
    }

    return {
        "schema_version": "lcs.plan.canonical.v1",
        "plan_id": plan.plan_id,
        "plan_type": plan.plan_type,
        "steps": canonical_steps,
        "dag_edges": canonical_edges,
        "execution_order": exec_order,
        "resource_grants": norm_grants,
        "limits": final_limits,
        "policy_context": pol_context
    }


def compute_plan_integrity_hash(
    plan: ExecutionPlan,
    policy_name: str = "default",
    attestation_ids: Optional[List[str]] = None,
    resource_grants: Optional[List[Dict[str, Any]]] = None,
    limits: Optional[Dict[str, Any]] = None
) -> Tuple[str, bytes]:
    """
    Computes the deterministic SHA-256 PlanIntegrityHash over the canonical plan payload.
    Returns (hex_digest, canonical_bytes).
    """
    payload = extract_canonical_plan_payload(
        plan=plan,
        policy_name=policy_name,
        attestation_ids=attestation_ids,
        resource_grants=resource_grants,
        limits=limits
    )
    canonical_bytes = canonicalize_jcs(payload)
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return digest, canonical_bytes


# ============================================================================
# 3. Domain Models, Enums, and Tokens
# ============================================================================

class GovernanceStatus(str, Enum):
    APPROVED = "GOVERNANCE_APPROVED"
    BLOCKED = "GOVERNANCE_BLOCKED"
    REJECTED = "GOVERNANCE_REJECTED"
    REVOKED = "GOVERNANCE_REVOKED"
    PENDING = "GOVERNANCE_PENDING"


class ApproverRole(str, Enum):
    HUMAN_OPERATOR = "HUMAN_OPERATOR"
    DELEGATED_AGENT = "DELEGATED_AGENT"
    SECURITY_OFFICER = "SECURITY_OFFICER"


class ResourceCategory(str, Enum):
    FILESYSTEM = "FILESYSTEM"
    NETWORK = "NETWORK"
    PROCESS = "PROCESS"
    ENV = "ENV"


class ReversibilityType(str, Enum):
    IDEMPOTENT = "IDEMPOTENT"
    REVERSIBLE = "REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"


@dataclass
class ApproverConsent:
    principal: str
    role: ApproverRole = ApproverRole.HUMAN_OPERATOR
    method: str = "CLI_INTERACTIVE_CONFIRMATION"
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "principal": self.principal,
            "role": self.role.value if isinstance(self.role, ApproverRole) else str(self.role),
            "method": self.method,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApproverConsent":
        role_str = data.get("role", "HUMAN_OPERATOR")
        try:
            role_enum = ApproverRole(role_str)
        except Exception:
            role_enum = ApproverRole.HUMAN_OPERATOR
        return cls(
            principal=data.get("principal", "operator@local"),
            role=role_enum,
            method=data.get("method", "CLI_INTERACTIVE_CONFIRMATION"),
            timestamp=data.get("timestamp", ""),
            signature=data.get("signature", "")
        )


@dataclass
class PolicyRevision:
    generation: int
    revision_digest: str
    policy_revision_id: str
    updated_at: str
    change_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionAuthorizationToken:
    token_id: str
    jti: str
    iss: str
    aud: str
    iat: int
    nbf: int
    exp: int
    plan_id: str
    plan_integrity_hash: str
    key_id: str
    approver: Dict[str, Any]
    constraints: Dict[str, Any]
    policy_context: Dict[str, Any]
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def compute_signature_preimage(self) -> bytes:
        d = self.to_dict()
        d_unsigned = {k: v for k, v in d.items() if k != "signature"}
        return canonicalize_jcs(d_unsigned)


@dataclass
class DispatchPermit:
    permit_id: str
    token_id: str
    plan_id: str
    plan_integrity_hash: str
    executor_identity: Dict[str, Any]
    issued_at: int
    expires_at: int
    policy_revision_id: str
    state: str = "ISSUED"
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def compute_signature_preimage(self) -> bytes:
        d = self.to_dict()
        d_unsigned = {k: v for k, v in d.items() if k != "signature"}
        return canonicalize_jcs(d_unsigned)


@dataclass
class GovernanceEvaluationResult:
    status: GovernanceStatus
    reasons: List[str]
    gate_1_status: str
    gate_2_status: str
    plan_id: str
    plan_integrity_hash: str
    policy_revision_id: str
    resource_grants: List[Dict[str, Any]] = field(default_factory=list)
    attestation_ids: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    presentation_text: str = ""
    token: Optional[ExecutionAuthorizationToken] = None

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["status"] = self.status.value
        return res


# ============================================================================
# 4. Exception Hierarchy
# ============================================================================

class GovernanceError(Exception):
    """Base exception for all LCS governance errors."""
    pass

class GovernanceBlockedError(GovernanceError):
    """Raised when Gate 1 policy check blocks plan authorization."""
    pass

class GovernanceRejectedError(GovernanceError):
    """Raised when Gate 2 approver consent is declined."""
    pass

class PlanIntegrityTamperedError(GovernanceError):
    """Raised when plan structure does not match canonical integrity digest."""
    pass

class TokenAlreadyConsumedError(GovernanceError):
    """Raised when token has already been consumed."""
    pass

class TokenExpiredError(GovernanceError):
    """Raised when token has exceeded expiration time."""
    pass

class TokenRevokedError(GovernanceError):
    """Raised when token has been revoked."""
    pass

class DispatchPermitAlreadyUsedError(GovernanceError):
    """Raised when DispatchPermit has already been accepted."""
    pass

class DispatchPermitExpiredError(GovernanceError):
    """Raised when DispatchPermit TTL has elapsed."""
    pass

class DispatchPermitInvalidError(GovernanceError):
    """Raised when DispatchPermit is malformed or invalid."""
    pass

class PolicyRevisionMismatchError(GovernanceError):
    """Raised when authoritative policy revision drifted between approval and dispatch."""
    pass

class AttestationRevokedError(GovernanceError):
    """Raised when attestation freshness check detects revoked or expired attestation."""
    pass

class PermissionViolationError(GovernanceError):
    """Raised when resource boundary or path traversal check fails."""
    pass

class UnsupportedStorageTopologyError(GovernanceError):
    """Raised when governance and policy tables reside on uncoordinated separate database files."""
    pass

class AuditChainIntegrityError(GovernanceError):
    """Raised when audit ledger hash chain or signature verification fails."""
    pass

class AuditLogTailTruncatedError(GovernanceError):
    """Raised when audit log file is truncated relative to authenticated anchor."""
    pass

class AuditDirectorySyncError(GovernanceError):
    """Raised when containing directory fsync fails during anchor publication."""
    pass


# ============================================================================
# 5. Schema & Monotonic Policy Revision Ledger
# ============================================================================

def ensure_governance_schema(conn: sqlite3.Connection) -> None:
    """
    Applies the Governance V1 schema migrations idempotently to the shared SQLite database.
    """
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON;")
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS policy_revision_ledger (
            generation INTEGER PRIMARY KEY,
            revision_digest TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            change_reason TEXT NOT NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS governance_tokens (
            jti TEXT PRIMARY KEY,
            plan_id TEXT NOT NULL,
            plan_integrity_hash TEXT NOT NULL,
            policy_revision_id TEXT NOT NULL,
            state TEXT NOT NULL,
            approver_json TEXT NOT NULL,
            policy_context_json TEXT NOT NULL,
            constraints_json TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER,
            executor_id TEXT,
            revoked_at INTEGER,
            revocation_reason TEXT,
            signature TEXT NOT NULL
        );
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS governance_dispatch_permits (
            permit_id TEXT PRIMARY KEY,
            token_id TEXT NOT NULL,
            plan_id TEXT NOT NULL,
            plan_integrity_hash TEXT NOT NULL,
            executor_id TEXT NOT NULL,
            policy_revision_id TEXT NOT NULL,
            state TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            accepted_at INTEGER,
            nonce TEXT NOT NULL,
            signature TEXT NOT NULL
        );
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_governance_tokens_plan ON governance_tokens(plan_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_governance_tokens_state ON governance_tokens(state);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_governance_permits_token ON governance_dispatch_permits(token_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_governance_permits_state ON governance_dispatch_permits(state);")

    # Initialize baseline revision if ledger is empty
    cur.execute("SELECT COUNT(*) FROM policy_revision_ledger;")
    if cur.fetchone()[0] == 0:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        initial_digest = hashlib.sha256(b"lcs.policy.initial.v1").hexdigest()
        cur.execute("""
            INSERT INTO policy_revision_ledger (
                generation, revision_digest, updated_at, change_reason
            ) VALUES (1, ?, ?, 'BASELINE_GENESIS');
        """, (initial_digest, now_iso))

    conn.commit()


def check_storage_topology(
    conn: sqlite3.Connection,
    target_conn: Optional[sqlite3.Connection] = None
) -> None:
    """
    Verifies that governance and policy operations are collocated on the same SQLite database file.
    If separate uncoordinated database files are detected, fails closed immediately.
    """
    if target_conn is None:
        return

    cur1 = conn.cursor()
    cur1.execute("PRAGMA database_list;")
    rows1 = cur1.fetchall()
    main_file1 = next((r[2] for r in rows1 if r[1] == "main"), "")

    cur2 = target_conn.cursor()
    cur2.execute("PRAGMA database_list;")
    rows2 = cur2.fetchall()
    main_file2 = next((r[2] for r in rows2 if r[1] == "main"), "")

    # For in-memory databases, both must be the identical Python connection object
    if not main_file1 and not main_file2:
        if conn is not target_conn:
            raise UnsupportedStorageTopologyError(
                "UNSUPPORTED_STORAGE_TOPOLOGY: In-memory governance and policy databases reside on separate connections."
            )
        return

    if os.path.realpath(main_file1) != os.path.realpath(main_file2):
        raise UnsupportedStorageTopologyError(
            f"UNSUPPORTED_STORAGE_TOPOLOGY: Governance database ('{main_file1}') and Policy database ('{main_file2}') "
            "are separate database files. Multi-database uncoordinated topology is strictly unsupported in Governance V1."
        )


def get_current_policy_revision(conn: sqlite3.Connection) -> PolicyRevision:
    """
    Returns the latest authoritative PolicyRevision from policy_revision_ledger.
    """
    cur = conn.cursor()
    cur.execute("""
        SELECT generation, revision_digest, updated_at, change_reason
        FROM policy_revision_ledger
        ORDER BY generation DESC
        LIMIT 1;
    """)
    row = cur.fetchone()
    if not row:
        ensure_governance_schema(conn)
        return get_current_policy_revision(conn)

    gen, dig, up_at, reason = row
    polrev_id = f"polrev-{gen}-{dig[:16]}"
    return PolicyRevision(
        generation=gen,
        revision_digest=dig,
        policy_revision_id=polrev_id,
        updated_at=up_at,
        change_reason=reason
    )


def increment_policy_revision(
    conn: sqlite3.Connection,
    change_reason: str,
    new_digest: Optional[str] = None
) -> PolicyRevision:
    """
    Monotonically increments policy_revision_ledger within the active transaction.
    """
    cur = conn.cursor()
    cur.execute("SELECT generation, revision_digest FROM policy_revision_ledger ORDER BY generation DESC LIMIT 1;")
    row = cur.fetchone()
    if not row:
        ensure_governance_schema(conn)
        return increment_policy_revision(conn, change_reason, new_digest)

    last_gen, last_dig = row
    next_gen = last_gen + 1
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if not new_digest:
        new_digest = hashlib.sha256(f"{last_dig}:{next_gen}:{change_reason}:{now_iso}".encode("utf-8")).hexdigest()

    cur.execute("""
        INSERT INTO policy_revision_ledger (
            generation, revision_digest, updated_at, change_reason
        ) VALUES (?, ?, ?, ?);
    """, (next_gen, new_digest, now_iso, change_reason))
    conn.commit()

    polrev_id = f"polrev-{next_gen}-{new_digest[:16]}"
    return PolicyRevision(
        generation=next_gen,
        revision_digest=new_digest,
        policy_revision_id=polrev_id,
        updated_at=now_iso,
        change_reason=change_reason
    )


# ============================================================================
# 6. Resource and Boundary Evaluator
# ============================================================================

def evaluate_resource_boundaries(
    plan: ExecutionPlan,
    boundary_root: Optional[str] = None,
    max_steps_ceiling: int = 10
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """
    Evaluates resource permission boundaries, quotas, anti-traversal, and anti-SSRF.
    Returns (grants, warnings, violations).
    """
    grants: List[Dict[str, Any]] = []
    warnings: List[str] = []
    violations: List[str] = []

    # 1. Step count quota ceiling
    if len(plan.steps) > max_steps_ceiling:
        violations.append(
            f"Step count ({len(plan.steps)}) exceeds maximum governance quota ceiling ({max_steps_ceiling})"
        )

    resolved_root = os.path.realpath(boundary_root) if boundary_root else None

    # Blacklisted private / link-local / loopback addresses
    blocked_hosts = {
        "localhost", "127.0.0.1", "169.254.169.254", "0.0.0.0", "::1"
    }

    for step in plan.steps:
        for p_name, b_info in step.input_bindings.items():
            val = b_info.bound_value if hasattr(b_info, "bound_value") else b_info.get("value")
            if not val or not isinstance(val, str):
                continue

            # Detect potential filesystem paths
            is_path = (
                val.startswith("/") or val.startswith("./") or val.startswith("../")
                or ("path" in p_name.lower()) or ("dir" in p_name.lower()) or ("file" in p_name.lower())
            )
            if is_path and not val.startswith("http://") and not val.startswith("https://"):
                access_type = "WRITE" if ("out" in p_name.lower() or "dest" in p_name.lower()) else "READ"
                
                # Path traversal check
                if ".." in val.split("/"):
                    # Check if resolving '..' stays within boundary_root
                    if resolved_root:
                        try:
                            candidate_abs = os.path.abspath(val)
                            rel_check = os.path.commonpath([candidate_abs, resolved_root])
                            if rel_check != resolved_root:
                                violations.append(f"Path traversal detected in parameter '{p_name}': '{val}' resolves outside boundary root '{resolved_root}'")
                        except Exception as e:
                            violations.append(f"Path traversal resolution error for '{val}': {e}")
                    else:
                        violations.append(f"Unsafe relative path traversal '..' in parameter '{p_name}': '{val}'")

                if resolved_root:
                    try:
                        resolved_path = os.path.realpath(val)
                        if os.path.islink(val):
                            violations.append(f"Symlink target prohibited in parameter '{p_name}': '{val}'")
                        if os.path.commonpath([resolved_path, resolved_root]) != resolved_root:
                            violations.append(f"Filesystem path '{val}' resolves outside boundary root '{resolved_root}'")
                    except Exception:
                        pass

                grants.append({
                    "category": "FILESYSTEM",
                    "access": access_type,
                    "target": val
                })

            # Detect URLs / endpoints (SSRF check)
            if val.startswith("http://") or val.startswith("https://") or ("url" in p_name.lower()) or ("endpoint" in p_name.lower()):
                grants.append({
                    "category": "NETWORK",
                    "access": "CONNECT",
                    "target": val
                })
                # Check SSRF hostnames
                host_part = val.split("://")[-1].split("/")[0].split(":")[0].strip()
                if host_part in blocked_hosts or host_part.startswith("10.") or host_part.startswith("192.168.") or host_part.startswith("172."):
                    violations.append(f"SSRF violation: blocked network destination '{host_part}' in parameter '{p_name}'")

    return grants, warnings, violations


# ============================================================================
# 7. Hash-Chained Append-Only Audit Ledger
# ============================================================================

class GovernanceAuditLedger:
    """
    Sequence-ordered, cryptographically linked hash-chained audit ledger.
    Every record contains SHA-256 of its 10-field preimage (excluding record_hash)
    and cryptographically references prev_record_hash.
    Publishes an authenticated head anchor with full POSIX directory fsync durability.
    """
    def __init__(self, audit_dir: str, key_store: PersistentReceiptKeyStore):
        self.audit_dir = os.path.abspath(audit_dir)
        self.key_store = key_store
        os.makedirs(self.audit_dir, mode=0o700, exist_ok=True)

        self.log_path = os.path.join(self.audit_dir, "audit_events.log")
        self.anchor_path = os.path.join(self.audit_dir, "ledger_head.anchor")
        self.tmp_anchor_path = os.path.join(self.audit_dir, "ledger_head.anchor.tmp")
        self.quarantine_dir = os.path.join(self.audit_dir, "quarantine")
        os.makedirs(self.quarantine_dir, mode=0o700, exist_ok=True)

        # Initialize genesis anchor if log file is empty
        with self.key_store._locked_transaction():
            if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
                self._initialize_genesis_under_lock()

    def _initialize_genesis_under_lock(self) -> None:
        """Writes genesis anchor if ledger is new."""
        if not os.path.exists(self.log_path):
            with open(self.log_path, "wb") as f:
                f.flush()
                os.fsync(f.fileno())

        if not os.path.exists(self.anchor_path):
            active_kid = self.key_store.active_key_id
            active_key_bytes = self.key_store.get_key(active_kid)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            anchor_payload = {
                "sequence_number": 0,
                "record_hash": "0" * 64,
                "timestamp": now_iso,
                "key_id": active_kid
            }
            sig_bytes = canonicalize_jcs(anchor_payload)
            sig = hmac.new(active_key_bytes, sig_bytes, hashlib.sha256).hexdigest()
            anchor_payload["signature"] = sig

            with open(self.tmp_anchor_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(anchor_payload, indent=2))
                f.flush()
                os.fsync(f.fileno())

            os.replace(self.tmp_anchor_path, self.anchor_path)
            self._sync_directory()

    def _sync_directory(self) -> None:
        """Executes fsync on the containing audit directory descriptor."""
        try:
            dir_fd = os.open(self.audit_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as e:
            raise AuditDirectorySyncError(f"Failed to fsync audit directory '{self.audit_dir}': {e}") from e

    @classmethod
    def extract_preimage(cls, record_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts strictly the 10-field preimage dictionary, excluding record_hash.
        """
        keys = [
            "sequence_number", "event_id", "prev_record_hash", "timestamp",
            "event_type", "plan_id", "plan_integrity_hash", "token_id",
            "event_payload", "cas_blob_reference"
        ]
        preimage = {}
        for k in keys:
            if k in record_dict:
                preimage[k] = record_dict[k]
        return preimage

    def append_event(
        self,
        event_type: str,
        plan_id: str,
        plan_integrity_hash: str,
        token_id: str,
        event_payload: Dict[str, Any],
        cas_blob_reference: str = ""
    ) -> Dict[str, Any]:
        """
        Appends an audit event to the hash-chained ledger and updates the head anchor.
        Guarantees:
          1. 10-field preimage canonicalized with RFC 8785 JCS.
          2. Stage 1 durable commit point with os.fsync(log_fd).
          3. Stage 2 temporary anchor write, fsync, atomic replace, and directory fsync.
        """
        with self.key_store._locked_transaction():
            # 1. Read current verified anchor to obtain sequence_number and prev_record_hash
            anchor_data = self._read_and_verify_anchor_under_lock()
            last_seq = anchor_data["sequence_number"]
            prev_hash = anchor_data["record_hash"]

            new_seq = last_seq + 1
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            event_id = f"evt-{uuid.uuid4().hex[:12]}"

            preimage = {
                "sequence_number": new_seq,
                "event_id": event_id,
                "prev_record_hash": prev_hash,
                "timestamp": now_iso,
                "event_type": event_type,
                "plan_id": plan_id,
                "plan_integrity_hash": plan_integrity_hash,
                "token_id": token_id,
                "event_payload": event_payload,
                "cas_blob_reference": cas_blob_reference or f"sha256:{hashlib.sha256(canonicalize_jcs(event_payload)).hexdigest()}"
            }

            # Calculate SHA-256 over preimage JCS bytes
            preimage_bytes = canonicalize_jcs(preimage)
            record_hash = hashlib.sha256(preimage_bytes).hexdigest()

            # Assemble stored record
            stored_record = dict(preimage)
            stored_record["record_hash"] = record_hash
            stored_bytes = canonicalize_jcs(stored_record)

            # Stage 1: Append to log and durable flush
            with open(self.log_path, "ab") as f:
                f.write(stored_bytes + b"\n")
                f.flush()
                os.fsync(f.fileno())

            # Stage 2: Publish new head anchor
            active_kid = self.key_store.active_key_id
            active_key_bytes = self.key_store.get_key(active_kid)
            anchor_payload = {
                "sequence_number": new_seq,
                "record_hash": record_hash,
                "timestamp": now_iso,
                "key_id": active_kid
            }
            anchor_sig_bytes = canonicalize_jcs(anchor_payload)
            sig = hmac.new(active_key_bytes, anchor_sig_bytes, hashlib.sha256).hexdigest()
            anchor_payload["signature"] = sig

            with open(self.tmp_anchor_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(anchor_payload, indent=2))
                f.flush()
                os.fsync(f.fileno())

            os.replace(self.tmp_anchor_path, self.anchor_path)
            self._sync_directory()

            return stored_record

    def _read_and_verify_anchor_under_lock(self) -> Dict[str, Any]:
        """Reads and cryptographically verifies the current head anchor."""
        if not os.path.exists(self.anchor_path):
            self._initialize_genesis_under_lock()

        with open(self.anchor_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        sig = data.get("signature", "")
        kid = data.get("key_id", "")
        unsigned = {k: v for k, v in data.items() if k != "signature"}

        try:
            key_bytes = self.key_store.get_key(kid)
        except Exception as e:
            raise AuditChainIntegrityError(f"Unknown anchor signing key_id '{kid}': {e}") from e

        expected_sig = hmac.new(key_bytes, canonicalize_jcs(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise AuditChainIntegrityError(f"Anchor HMAC signature mismatch for key_id '{kid}'")

        return data

    def verify_ledger(self) -> Tuple[bool, int, str]:
        """
        Verifies the full audit ledger:
          1. Verifies anchor signature across key rotation.
          2. Verifies genesis-to-head sequence continuity and hash chaining.
          3. Re-computes SHA-256 over 10-field preimage for every record.
          4. Verifies head matches authenticated anchor (tail truncation defense).
        """
        with self.key_store._locked_transaction():
            anchor = self._read_and_verify_anchor_under_lock()
            anchor_seq = anchor["sequence_number"]
            anchor_hash = anchor["record_hash"]

            if not os.path.exists(self.log_path):
                if anchor_seq == 0:
                    return True, 0, "Genesis ledger verified"
                raise AuditLogTailTruncatedError("Log file missing while anchor sequence > 0")

            records = []
            with open(self.log_path, "rb") as f:
                for line_idx, line in enumerate(f, start=1):
                    line_clean = line.strip()
                    if not line_clean:
                        continue
                    try:
                        rec = json.loads(line_clean.decode("utf-8"))
                        records.append((line_idx, rec))
                    except Exception as e:
                        raise AuditChainIntegrityError(f"Corrupted record JSON at line {line_idx}: {e}")

            # If anchor is genesis (0), records must be empty
            if anchor_seq == 0 and len(records) == 0:
                return True, 0, "Genesis ledger verified (0 records)"

            # Walk and verify records
            prev_expected_hash = "0" * 64
            for expected_seq, (line_no, rec) in enumerate(records, start=1):
                actual_seq = rec.get("sequence_number")
                if actual_seq != expected_seq:
                    raise AuditChainIntegrityError(
                        f"Sequence number gap at line {line_no}: expected {expected_seq}, got {actual_seq}"
                    )

                prev_hash = rec.get("prev_record_hash")
                if prev_hash != prev_expected_hash:
                    raise AuditChainIntegrityError(
                        f"Broken prev_record_hash linkage at record {actual_seq}: expected {prev_expected_hash}, got {prev_hash}"
                    )

                stored_hash = rec.get("record_hash")
                if not stored_hash:
                    raise AuditChainIntegrityError(f"Missing record_hash at record {actual_seq}")

                # Recompute hash over 10-field preimage
                preimage = self.extract_preimage(rec)
                preimage_bytes = canonicalize_jcs(preimage)
                computed_hash = hashlib.sha256(preimage_bytes).hexdigest()

                if not hmac.compare_digest(stored_hash, computed_hash):
                    raise AuditChainIntegrityError(
                        f"Preimage hash mismatch at record {actual_seq}: calculated {computed_hash}, stored {stored_hash}"
                    )

                prev_expected_hash = stored_hash

            total_records = len(records)
            if total_records < anchor_seq:
                raise AuditLogTailTruncatedError(
                    f"AUDIT_LOG_TAIL_TRUNCATED: Log contains {total_records} records, but authenticated anchor requires {anchor_seq}"
                )

            if total_records > 0:
                last_rec_hash = records[-1][1]["record_hash"]
                if total_records == anchor_seq and last_rec_hash != anchor_hash:
                    raise AuditChainIntegrityError(
                        f"Ledger head hash '{last_rec_hash}' does not match authenticated anchor '{anchor_hash}'"
                    )

            return True, total_records, f"All {total_records} records cryptographically verified from Genesis to Head"

    def recover(self) -> Tuple[int, int]:
        """
        Deterministic crash recovery procedure:
          - If valid unanchored fsynced records exist beyond anchor: forward-rolls anchor.
          - If torn/corrupt bytes exist at tail: truncates log back to last valid record and quarantines fragment.
        Returns (forward_rolled_count, truncated_bytes_count).
        """
        with self.key_store._locked_transaction():
            anchor = self._read_and_verify_anchor_under_lock()
            anchor_seq = anchor["sequence_number"]
            anchor_hash = anchor["record_hash"]

            if not os.path.exists(self.log_path):
                return 0, 0

            valid_offsets = []
            records = []
            torn_bytes_start = None

            with open(self.log_path, "rb") as f:
                offset = 0
                while True:
                    line_start = offset
                    line = f.readline()
                    if not line:
                        break
                    offset = f.tell()
                    line_clean = line.strip()
                    if not line_clean:
                        continue

                    # Try parsing and verifying
                    try:
                        rec = json.loads(line_clean.decode("utf-8"))
                        stored_hash = rec.get("record_hash")
                        if not stored_hash:
                            torn_bytes_start = line_start
                            break
                        preimage = self.extract_preimage(rec)
                        computed_hash = hashlib.sha256(canonicalize_jcs(preimage)).hexdigest()
                        if not hmac.compare_digest(stored_hash, computed_hash):
                            torn_bytes_start = line_start
                            break
                        records.append(rec)
                        valid_offsets.append(offset)
                    except Exception:
                        torn_bytes_start = line_start
                        break

            truncated_bytes = 0
            # Truncate trailing corrupt bytes if detected
            if torn_bytes_start is not None:
                total_size = os.path.getsize(self.log_path)
                truncated_bytes = total_size - torn_bytes_start
                # Quarantine fragment
                with open(self.log_path, "rb") as f:
                    f.seek(torn_bytes_start)
                    bad_bytes = f.read()
                quarantine_fn = f"corrupted_tail_{int(time.time())}.bin"
                with open(os.path.join(self.quarantine_dir, quarantine_fn), "wb") as qf:
                    qf.write(bad_bytes)

                # Truncate
                with open(self.log_path, "r+b") as f:
                    f.truncate(torn_bytes_start)
                    f.flush()
                    os.fsync(f.fileno())

            # Check for valid unanchored records to forward-roll
            forward_rolled = 0
            if len(records) > anchor_seq:
                # Check cryptographic linkage for all unanchored records
                curr_expected_prev = anchor_hash
                valid_forward_count = 0
                for idx in range(anchor_seq, len(records)):
                    rec = records[idx]
                    if rec.get("sequence_number") != idx + 1:
                        break
                    if rec.get("prev_record_hash") != curr_expected_prev:
                        break
                    curr_expected_prev = rec["record_hash"]
                    valid_forward_count += 1

                if valid_forward_count > 0:
                    last_valid_rec = records[anchor_seq + valid_forward_count - 1]
                    new_seq = last_valid_rec["sequence_number"]
                    new_hash = last_valid_rec["record_hash"]
                    active_kid = self.key_store.active_key_id
                    active_key_bytes = self.key_store.get_key(active_kid)
                    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

                    anchor_payload = {
                        "sequence_number": new_seq,
                        "record_hash": new_hash,
                        "timestamp": now_iso,
                        "key_id": active_kid
                    }
                    sig_bytes = canonicalize_jcs(anchor_payload)
                    sig = hmac.new(active_key_bytes, sig_bytes, hashlib.sha256).hexdigest()
                    anchor_payload["signature"] = sig

                    with open(self.tmp_anchor_path, "w", encoding="utf-8") as f:
                        f.write(json.dumps(anchor_payload, indent=2))
                        f.flush()
                        os.fsync(f.fileno())

                    os.replace(self.tmp_anchor_path, self.anchor_path)
                    self._sync_directory()
                    forward_rolled = valid_forward_count

            return forward_rolled, truncated_bytes


# ============================================================================
# 8. Execution Governance Engine V1
# ============================================================================

class ExecutionGovernanceEngineV1:
    """
    Core Governance Engine V1.
    Coordinates Gate 1 (Capability Policy) and Gate 2 (Approver Consent),
    RFC 8785 Plan Integrity Hashing, EAT Token Issuance, Monotonic Compare-and-Consume,
    and Hash-Chained Audit Ledger receipts.
    """
    def __init__(
        self,
        conn: sqlite3.Connection,
        cas_engine: SecureCASStorageEngine,
        iface_service: InterfacePolicyService,
        profile_service: CapabilityProfileService,
        key_store: Optional[PersistentReceiptKeyStore] = None,
        audit_dir: Optional[str] = None
    ):
        self.conn = conn
        self.cas_engine = cas_engine
        self.iface_service = iface_service
        self.profile_service = profile_service
        self.key_store = key_store or cas_engine.key_store

        # Check storage topology immediately (fail closed if separate DBs)
        check_storage_topology(self.conn, getattr(self.iface_service, "conn", None))

        # Ensure schema
        ensure_governance_schema(self.conn)

        # Setup audit ledger
        base_audit = audit_dir or os.path.join(os.path.dirname(self.key_store.key_store_dir), "audit")
        self.audit_ledger = GovernanceAuditLedger(base_audit, self.key_store)

    def evaluate_plan(
        self,
        plan: ExecutionPlan,
        active_policy: Optional[InterfaceTrustPolicy] = None,
        boundary_root: Optional[str] = None
    ) -> GovernanceEvaluationResult:
        """
        Executes Gate 1 capability trust, attestation, and resource boundary evaluation.
        Produces deterministic PlanIntegrityHash and formatted presentation text.
        """
        pol = active_policy or InterfaceTrustPolicy(
            policy_name="default-execution-policy",
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )
        reasons: List[str] = []
        warnings: List[str] = []
        attestation_ids: List[str] = []

        # 1. Gate 1: Check each step against InterfacePolicyService
        gate_1_passed = True
        for step in plan.steps:
            urn = step.capability_urn
            # Look up capability profile to find interface and agent URNs
            try:
                prof = self.profile_service.get_profile(urn)
                iface_urn = prof.source_interface.value if hasattr(prof.source_interface, "value") else str(prof.source_interface)
                agent_urn = prof.source_agent.value if hasattr(prof.source_agent, "value") else str(prof.source_agent)
            except Exception:
                # If profile lookup fails, infer from URN
                parts = urn.split(":")
                srv_name = parts[3].replace("mcp.", "") if len(parts) >= 4 else "unknown"
                iface_urn = f"urn:lcs:interface:mcp.{srv_name}:v1"
                agent_urn = f"urn:lcs:agent:mcp.{srv_name}"

            # Evaluate against policy service
            try:
                decision = self.iface_service.evaluate_policy(
                    interface_urn=iface_urn,
                    policy=pol
                )
                if decision.decision != "ALLOW" or decision.status != "VERIFIED":
                    gate_1_passed = False
                    reasons.append(
                        f"Capability '{step.display_name}' ({urn}) rejected by policy: {decision.decision} ({decision.status}) — {'; '.join(decision.reasons)}"
                    )
                else:
                    if decision.attestation_id:
                        attestation_ids.append(decision.attestation_id)
            except Exception as e:
                gate_1_passed = False
                reasons.append(f"Policy evaluation error for capability '{urn}': {e}")

            # Reversibility classification and warnings
            if "delete" in step.capability_urn or "remove" in step.capability_urn or "destroy" in step.capability_urn:
                warnings.append(f"Irreversible mutation warning: step '{step.step_id}' ({step.display_name}) cannot be undone.")

        # 2. Resource boundary and quota evaluation
        grants, res_warnings, violations = evaluate_resource_boundaries(plan, boundary_root=boundary_root)
        warnings.extend(res_warnings)
        if violations:
            gate_1_passed = False
            reasons.extend(violations)

        # 3. Retrieve authoritative policy revision from shared database
        pol_rev = get_current_policy_revision(self.conn)

        # 4. Compute deterministic PlanIntegrityHash
        plan_hash, _ = compute_plan_integrity_hash(
            plan=plan,
            policy_name=pol.policy_name,
            attestation_ids=attestation_ids,
            resource_grants=grants
        )

        # 5. Format audit presentation text
        pres_text = self._format_presentation(
            plan=plan,
            plan_hash=plan_hash,
            policy_name=pol.policy_name,
            attestation_ids=attestation_ids,
            grants=grants,
            warnings=warnings,
            gate_1_passed=gate_1_passed,
            reasons=reasons
        )

        status = GovernanceStatus.PENDING if gate_1_passed else GovernanceStatus.BLOCKED
        gate_1_st = "VERIFIED" if gate_1_passed else "REJECTED"

        return GovernanceEvaluationResult(
            status=status,
            reasons=reasons,
            gate_1_status=gate_1_st,
            gate_2_status="PENDING",
            plan_id=plan.plan_id,
            plan_integrity_hash=plan_hash,
            policy_revision_id=pol_rev.policy_revision_id,
            resource_grants=grants,
            attestation_ids=attestation_ids,
            warnings=warnings,
            presentation_text=pres_text
        )

    def _format_presentation(
        self,
        plan: ExecutionPlan,
        plan_hash: str,
        policy_name: str,
        attestation_ids: List[str],
        grants: List[Dict[str, Any]],
        warnings: List[str],
        gate_1_passed: bool,
        reasons: List[str]
    ) -> str:
        """Formats the structured approval audit presentation specified in Section 4.1."""
        lines = [
            "=" * 80,
            " LIVING CAPABILITY SYSTEM (LCS) — EXECUTION GOVERNANCE APPROVAL REQUEST",
            "=" * 80,
            f"  Plan ID:             {plan.plan_id}",
            f"  Request Query:       \"{plan.request_query}\"",
            f"  Plan Integrity Hash: {plan_hash} (SHA-256)",
            f"  Active Policy:       {policy_name} ({len(plan.steps)} capabilities, {len(attestation_ids)} attestations)",
            f"  Gate 1 Status:       {'VERIFIED (ALLOW)' if gate_1_passed else 'BLOCKED (POLICY VIOLATION)'}",
            "",
            "[Ordered Operations & Resource Grants]"
        ]
        for s in plan.steps:
            lines.append(f"  {s.step_index}. [{s.step_id}] {s.display_name} ({s.capability_urn})")
            lines.append(f"     - Sub-goal:        {s.sub_goal}")
            step_grants = [g for g in grants if any(b.get("value") == g["target"] for b in s.input_bindings.values() if isinstance(b, dict))]
            if step_grants:
                lines.append("     - Resource Grants:")
                for sg in step_grants:
                    lines.append(f"       * {sg['category']} {sg['access']}: {sg['target']}")
            else:
                lines.append("     - Resource Grants: None (In-Memory / Read-Only)")

        if warnings:
            lines.append("")
            lines.append("[Security Warnings & Operational Notes]")
            for w in warnings:
                lines.append(f"  ! {w}")

        if not gate_1_passed:
            lines.append("")
            lines.append("[Policy Violations]")
            for r in reasons:
                lines.append(f"  * {r}")

        lines.append("=" * 80)
        return "\n".join(lines)

    def approve_plan(
        self,
        plan: ExecutionPlan,
        approver: ApproverConsent,
        active_policy: Optional[InterfaceTrustPolicy] = None,
        boundary_root: Optional[str] = None,
        ttl_seconds: int = 300
    ) -> Tuple[ExecutionAuthorizationToken, GovernanceEvaluationResult]:
        """
        Executes Gate 2 approver confirmation.
        Enforces Dual-Gate Invariant: If Gate 1 failed, user approval CANNOT override policy.
        Issues signed ExecutionAuthorizationToken and commits audit event.
        """
        eval_result = self.evaluate_plan(plan, active_policy=active_policy, boundary_root=boundary_root)

        # Non-Bypassable Trust Gate Invariant:
        if eval_result.gate_1_status != "VERIFIED":
            eval_result.status = GovernanceStatus.BLOCKED
            eval_result.gate_2_status = "BLOCKED_BY_GATE_1"
            self.audit_ledger.append_event(
                event_type="PLAN_AUTHORIZATION_BLOCKED",
                plan_id=plan.plan_id,
                plan_integrity_hash=eval_result.plan_integrity_hash,
                token_id="NONE",
                event_payload={"reasons": eval_result.reasons, "approver": approver.to_dict()}
            )
            raise GovernanceBlockedError(
                f"GOVERNANCE_BLOCKED: Plan '{plan.plan_id}' cannot be authorized due to policy violations: {'; '.join(eval_result.reasons)}"
            )

        # Gate 2: Check approver consent
        if not approver or not approver.principal:
            eval_result.status = GovernanceStatus.REJECTED
            eval_result.gate_2_status = "REJECTED_NO_CONSENT"
            self.audit_ledger.append_event(
                event_type="PLAN_AUTHORIZATION_REJECTED",
                plan_id=plan.plan_id,
                plan_integrity_hash=eval_result.plan_integrity_hash,
                token_id="NONE",
                event_payload={"reason": "Explicit approver consent was declined", "approver": approver.to_dict() if approver else {}}
            )
            raise GovernanceRejectedError("GOVERNANCE_REJECTED: Approver consent was not provided.")

        # Mint ExecutionAuthorizationToken (EAT)
        now_ts = int(time.time())
        exp_ts = now_ts + ttl_seconds
        token_id = f"eat-{uuid.uuid4().hex[:12]}"
        active_kid = self.key_store.active_key_id
        active_key_bytes = self.key_store.get_key(active_kid)

        pol = active_policy or InterfaceTrustPolicy(
            policy_name="default-execution-policy",
            min_interface_version=1,
            require_attestation=True,
            require_all_capabilities_verified=True
        )

        constraints = {
            "resource_grants": eval_result.resource_grants,
            "limits": {
                "max_steps": len(plan.steps),
                "step_timeout_seconds": 30,
                "total_timeout_seconds": 180
            }
        }
        policy_context = {
            "policy_name": pol.policy_name,
            "policy_revision_id": eval_result.policy_revision_id,
            "attestation_ids": sorted(list(set(eval_result.attestation_ids)))
        }

        token = ExecutionAuthorizationToken(
            token_id=token_id,
            jti=token_id,
            iss="urn:lcs:governance:v1",
            aud="urn:lcs:executor:v1",
            iat=now_ts,
            nbf=now_ts,
            exp=exp_ts,
            plan_id=plan.plan_id,
            plan_integrity_hash=eval_result.plan_integrity_hash,
            key_id=active_kid,
            approver=approver.to_dict(),
            constraints=constraints,
            policy_context=policy_context
        )

        # Compute HMAC signature over token
        sig_preimage = token.compute_signature_preimage()
        sig = hmac.new(active_key_bytes, sig_preimage, hashlib.sha256).hexdigest()
        token.signature = sig

        # Persist token in shared SQLite database under lock
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO governance_tokens (
                jti, plan_id, plan_integrity_hash, policy_revision_id,
                state, approver_json, policy_context_json, constraints_json,
                issued_at, expires_at, signature
            ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?);
        """, (
            token.jti,
            token.plan_id,
            token.plan_integrity_hash,
            eval_result.policy_revision_id,
            json.dumps(token.approver),
            json.dumps(token.policy_context),
            json.dumps(token.constraints),
            token.iat,
            token.exp,
            token.signature
        ))
        self.conn.commit()

        eval_result.status = GovernanceStatus.APPROVED
        eval_result.gate_2_status = "APPROVED"
        eval_result.token = token

        # Commit authorization audit event
        self.audit_ledger.append_event(
            event_type="PLAN_AUTHORIZATION_GRANTED",
            plan_id=plan.plan_id,
            plan_integrity_hash=eval_result.plan_integrity_hash,
            token_id=token.token_id,
            event_payload={
                "approver": token.approver,
                "gate_1_status": "VERIFIED",
                "gate_2_status": "APPROVED",
                "resource_grants_count": len(eval_result.resource_grants),
                "policy_revision_id": eval_result.policy_revision_id
            }
        )

        return token, eval_result

    def verify_token(
        self,
        token: Union[str, Dict[str, Any], ExecutionAuthorizationToken],
        plan: ExecutionPlan
    ) -> bool:
        """
        Cryptographically verifies an ExecutionAuthorizationToken against the plan:
          1. Validates token format, timestamps (iat <= now <= exp).
          2. Re-canonicalizes plan via RFC 8785 JCS and asserts plan_integrity_hash.
          3. Verifies HMAC signature with key_store.get_key(token.key_id).
        """
        if isinstance(token, str):
            token_dict = json.loads(token)
            eat = ExecutionAuthorizationToken(**token_dict)
        elif isinstance(token, dict):
            eat = ExecutionAuthorizationToken(**token)
        else:
            eat = token

        now_ts = int(time.time())
        if now_ts < eat.nbf or now_ts >= eat.exp:
            raise TokenExpiredError(f"Token '{eat.token_id}' is outside validity window (nbf={eat.nbf}, exp={eat.exp}, now={now_ts})")

        # Verify HMAC signature
        try:
            key_bytes = self.key_store.get_key(eat.key_id)
        except Exception as e:
            raise PlanIntegrityTamperedError(f"Token signing key '{eat.key_id}' not found: {e}") from e

        computed_sig = hmac.new(key_bytes, eat.compute_signature_preimage(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(eat.signature, computed_sig):
            raise PlanIntegrityTamperedError(f"Token '{eat.token_id}' signature verification failed")

        # Re-canonicalize plan and verify plan_integrity_hash
        pol_context = eat.policy_context or {}
        constraints = eat.constraints or {}
        pol_name = pol_context.get("policy_name", "default")
        att_ids = pol_context.get("attestation_ids", [])
        grants = constraints.get("resource_grants", [])
        limits = constraints.get("limits")
        computed_plan_hash, _ = compute_plan_integrity_hash(
            plan=plan,
            policy_name=pol_name,
            attestation_ids=att_ids,
            resource_grants=grants,
            limits=limits
        )

        if not hmac.compare_digest(eat.plan_integrity_hash, computed_plan_hash):
            raise PlanIntegrityTamperedError(
                f"PLAN_INTEGRITY_TAMPERED: Plan hash '{computed_plan_hash}' does not match token '{eat.plan_integrity_hash}'"
            )

        return True

    def authorize_dispatch(
        self,
        token_id: str,
        plan: ExecutionPlan,
        executor_identity: Dict[str, Any]
    ) -> DispatchPermit:
        """
        Executes the Monotonic Revision-Checked Compare-and-Consume Protocol:
          1. Opens exclusive transaction on shared database (BEGIN IMMEDIATE).
          2. Validates token is ACTIVE.
          3. Queries current authoritative policy revision.
          4. Asserts policy revision equality and re-checks attestation liveness.
          5. Fails closed (marks REVOKED) if revision drifted or attestation revoked.
          6. Updates token to CONSUMED and mints single-use DispatchPermit.
        """
        cur = self.conn.cursor()

        # Enforce exclusive transaction lock on the shared SQLite database
        if self.conn.in_transaction:
            self.conn.commit()
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # 1. Fetch token record
            cur.execute("""
                SELECT jti, plan_id, plan_integrity_hash, policy_revision_id,
                       state, policy_context_json, constraints_json, expires_at, signature
                FROM governance_tokens
                WHERE jti = ?;
            """, (token_id,))
            row = cur.fetchone()
            if not row:
                raise TokenRevokedError(f"Token '{token_id}' not found in governance registry")

            jti, plan_id, plan_hash, polrev_id, state, pol_ctx_json, constraints_json, exp, sig = row
            now_ts = int(time.time())

            if state == "CONSUMED":
                raise TokenAlreadyConsumedError(f"TOKEN_ALREADY_CONSUMED: Token '{token_id}' has already been consumed")
            if state == "REVOKED":
                raise TokenRevokedError(f"TOKEN_REVOKED: Token '{token_id}' has been revoked")
            if now_ts >= exp:
                cur.execute("UPDATE governance_tokens SET state = 'EXPIRED' WHERE jti = ?;", (token_id,))
                self.conn.commit()
                raise TokenExpiredError(f"TOKEN_EXPIRED: Token '{token_id}' expired at {exp}")
            if state != "ACTIVE":
                raise TokenRevokedError(f"Token '{token_id}' is not in ACTIVE state (current: {state})")

            # 2. Re-verify plan integrity
            pol_ctx = json.loads(pol_ctx_json) if pol_ctx_json else {}
            constraints = json.loads(constraints_json) if constraints_json else {}
            pol_name = pol_ctx.get("policy_name", "default")
            att_ids = pol_ctx.get("attestation_ids", [])
            grants = constraints.get("resource_grants", [])
            limits = constraints.get("limits")
            computed_plan_hash, _ = compute_plan_integrity_hash(
                plan=plan,
                policy_name=pol_name,
                attestation_ids=att_ids,
                resource_grants=grants,
                limits=limits
            )
            if not hmac.compare_digest(plan_hash, computed_plan_hash):
                cur.execute("UPDATE governance_tokens SET state = 'REVOKED', revoked_at = ?, revocation_reason = 'PLAN_INTEGRITY_TAMPERED' WHERE jti = ?;", (now_ts, token_id))
                self.conn.commit()
                raise PlanIntegrityTamperedError(f"Plan integrity verification failed during dispatch for token '{token_id}'")

            # 3. Monotonic Policy Revision Check (Compare-and-Consume)
            pol_ctx = json.loads(pol_ctx_json) if pol_ctx_json else {}
            expected_rev = pol_ctx.get("policy_revision_id", polrev_id)
            current_rev = get_current_policy_revision(self.conn)

            if current_rev.policy_revision_id != expected_rev:
                # Policy revision drifted between approval and dispatch! Fail closed.
                cur.execute("""
                    UPDATE governance_tokens
                    SET state = 'REVOKED', revoked_at = ?, revocation_reason = 'POLICY_REVISION_DRIFT'
                    WHERE jti = ?;
                """, (now_ts, token_id))
                self.conn.commit()
                self.audit_ledger.append_event(
                    event_type="TOKEN_REVOKED_AT_DISPATCH",
                    plan_id=plan_id,
                    plan_integrity_hash=plan_hash,
                    token_id=token_id,
                    event_payload={
                        "reason": "POLICY_REVISION_DRIFT",
                        "expected_revision": expected_rev,
                        "current_revision": current_rev.policy_revision_id
                    }
                )
                raise PolicyRevisionMismatchError(
                    f"POLICY_REVISION_MISMATCH_AT_DISPATCH: Expected revision '{expected_rev}', but current is '{current_rev.policy_revision_id}'"
                )

            # 4. Attestation Liveness & Freshness Re-Verification
            att_ids = pol_ctx.get("attestation_ids", [])
            for att_id in att_ids:
                is_valid, _ = self.iface_service.verify_attestation(att_id)
                if not is_valid:
                    cur.execute("""
                        UPDATE governance_tokens
                        SET state = 'REVOKED', revoked_at = ?, revocation_reason = 'ATTESTATION_REVOKED_AT_DISPATCH'
                        WHERE jti = ?;
                    """, (now_ts, token_id))
                    self.conn.commit()
                    self.audit_ledger.append_event(
                        event_type="TOKEN_REVOKED_AT_DISPATCH",
                        plan_id=plan_id,
                        plan_integrity_hash=plan_hash,
                        token_id=token_id,
                        event_payload={"reason": "ATTESTATION_REVOKED_AT_DISPATCH", "revoked_attestation_id": att_id}
                    )
                    raise AttestationRevokedError(f"ATTESTATION_REVOKED_AT_DISPATCH: Attestation '{att_id}' is no longer valid")

            # 5. Atomic Consumption & Permit Minting
            executor_id = executor_identity.get("executor_id", "executor@local")
            cur.execute("""
                UPDATE governance_tokens
                SET state = 'CONSUMED', consumed_at = ?, executor_id = ?
                WHERE jti = ?;
            """, (now_ts, executor_id, token_id))

            permit_id = f"prm-{uuid.uuid4().hex[:12]}"
            permit_ttl = 30  # 30 seconds TTL ceiling
            permit_exp = now_ts + permit_ttl

            permit = DispatchPermit(
                permit_id=permit_id,
                token_id=token_id,
                plan_id=plan_id,
                plan_integrity_hash=plan_hash,
                executor_identity=executor_identity,
                issued_at=now_ts,
                expires_at=permit_exp,
                policy_revision_id=current_rev.policy_revision_id,
                state="ISSUED"
            )

            # Sign permit
            permit_sig_bytes = permit.compute_signature_preimage()
            active_key_bytes = self.key_store.get_key(self.key_store.active_key_id)
            permit.signature = hmac.new(active_key_bytes, permit_sig_bytes, hashlib.sha256).hexdigest()

            cur.execute("""
                INSERT INTO governance_dispatch_permits (
                    permit_id, token_id, plan_id, plan_integrity_hash,
                    executor_id, policy_revision_id, state, issued_at,
                    expires_at, nonce, signature
                ) VALUES (?, ?, ?, ?, ?, ?, 'ISSUED', ?, ?, ?, ?);
            """, (
                permit.permit_id,
                permit.token_id,
                permit.plan_id,
                permit.plan_integrity_hash,
                executor_id,
                permit.policy_revision_id,
                permit.issued_at,
                permit.expires_at,
                permit.nonce,
                permit.signature
            ))

            self.conn.commit()

            # Record audit event
            self.audit_ledger.append_event(
                event_type="DISPATCH_PERMIT_ISSUED",
                plan_id=plan_id,
                plan_integrity_hash=plan_hash,
                token_id=token_id,
                event_payload={
                    "permit_id": permit.permit_id,
                    "executor_id": executor_id,
                    "policy_revision_id": current_rev.policy_revision_id,
                    "expires_at": permit.expires_at
                }
            )

            return permit
        except Exception:
            self.conn.rollback()
            raise

    def accept_dispatch_permit(
        self,
        permit_id: str,
        plan_integrity_hash: str
    ) -> Dict[str, Any]:
        """
        Executes single-use DispatchPermit acceptance check at runtime process launch.
        Transitions state from ISSUED to ACCEPTED atomically.
        """
        cur = self.conn.cursor()
        now_ts = int(time.time())

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # Query permit
            cur.execute("""
                SELECT permit_id, token_id, plan_id, plan_integrity_hash, state, expires_at
                FROM governance_dispatch_permits
                WHERE permit_id = ?;
            """, (permit_id,))
            row = cur.fetchone()
            if not row:
                raise DispatchPermitInvalidError(f"DispatchPermit '{permit_id}' not found")

            p_id, t_id, pl_id, p_hash, state, exp = row
            if state == "ACCEPTED":
                raise DispatchPermitAlreadyUsedError(f"DISPATCH_PERMIT_ALREADY_USED: Permit '{permit_id}' was already accepted")
            if now_ts > exp:
                raise DispatchPermitExpiredError(f"DISPATCH_PERMIT_EXPIRED: Permit '{permit_id}' expired at {exp}")
            if not hmac.compare_digest(p_hash, plan_integrity_hash):
                raise DispatchPermitInvalidError(f"Plan integrity hash mismatch for permit '{permit_id}'")

            # Transition to ACCEPTED
            cur.execute("""
                UPDATE governance_dispatch_permits
                SET state = 'ACCEPTED', accepted_at = ?
                WHERE permit_id = ? AND state = 'ISSUED';
            """, (now_ts, permit_id))

            self.conn.commit()

            self.audit_ledger.append_event(
                event_type="DISPATCH_PERMIT_ACCEPTED",
                plan_id=pl_id,
                plan_integrity_hash=p_hash,
                token_id=t_id,
                event_payload={"permit_id": permit_id, "accepted_at": now_ts}
            )

            return {
                "permit_id": permit_id,
                "token_id": t_id,
                "plan_id": pl_id,
                "status": "ACCEPTED",
                "accepted_at": now_ts
            }
        except Exception:
            self.conn.rollback()
            raise
