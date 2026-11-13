#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 3: Interface Attestation & Policy Engine
================================================================
Implements:
1. Agent & Interface Identity:
   - AgentDeclaration: Canonical agent identity with structured provenance.
   - InterfaceDeclaration: Deterministic interface identity binding agent, version,
     constituent capability definitions, and metadata.
2. Interface Attestation:
   - InterfaceAttestation: Cryptographic binding between interface identity, version,
     content digests, and active HMAC signing key from PersistentReceiptKeyStore.
   - Modification detection: Tampering with interface or capability definitions causes
     verification to fail closed.
   - Restart verification: Keys and attestations reliably verify across application restarts.
3. Policy Evaluation Layer:
   - InterfaceTrustPolicy: Declarative trust configuration (allowed attesters, agents,
     origins, licenses, version requirements).
   - PolicyEvaluationDecision: Structured, explainable decision distinguishing
     VERIFIED, UNVERIFIED, REJECTED, and UNAVAILABLE states.
4. Persistent Storage & Referential Integrity:
   - Fully integrated with SQLite foreign keys and CAS storage engine.
   - Purely declarative (zero code execution).
"""

import os
import sys
import json
import time
import uuid
import hmac
import hashlib
import sqlite3
from typing import Dict, Any, List, Tuple, Optional, Set, NamedTuple

from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    CASError,
    CASValidationError,
    CASSecurityViolationError,
    CASBlobNotFoundError,
    CASDigestMismatchError,
    CASPublicationConflictError
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


# ----------------------------------------------------------------------------
# Custom Exceptions
# ----------------------------------------------------------------------------

class InterfacePolicyError(CASError):
    """Base exception for interface policy and attestation errors."""
    pass

class InvalidInterfaceURNError(InterfacePolicyError, CASValidationError):
    """Raised when an interface or agent URN violates canonical syntax rules."""
    pass

class InvalidInterfaceDeclarationError(InterfacePolicyError, CASValidationError):
    """Raised when an interface declaration fails structural or semantic validation."""
    pass

class AttestationVerificationError(InterfacePolicyError):
    """Raised when an attestation fails cryptographic or digest verification."""
    pass

class InterfaceNotFoundError(InterfacePolicyError):
    """Raised when a requested interface URN is not registered."""
    pass

class AgentNotFoundError(InterfacePolicyError):
    """Raised when a requested agent URN is not registered."""
    pass

class PolicyEvaluationError(InterfacePolicyError):
    """Raised when an unrecoverable error occurs during policy evaluation."""
    pass


# ----------------------------------------------------------------------------
# Data Models: Agent & Interface Declarations
# ----------------------------------------------------------------------------

class AgentDeclaration:
    """Canonical declaration of an agent identity with structured provenance."""
    def __init__(
        self,
        agent_urn: str,
        display_name: str,
        description: str = "",
        provenance: Optional[Dict[str, Any]] = None
    ):
        parsed = parse_canonical_urn(agent_urn)
        if parsed.entity_kind != "agent":
            raise InvalidInterfaceURNError(
                f"Agent URN must have entity kind 'agent', got '{parsed.entity_kind}' in '{agent_urn}'"
            )
        self.agent_urn = parsed.raw_urn
        self.display_name = str(display_name).strip()
        if not self.display_name:
            raise InvalidInterfaceDeclarationError("Agent display_name cannot be empty")
        self.description = str(description).strip()
        self.provenance = provenance if provenance is not None else {}
        self._validate_provenance()

    def _validate_provenance(self) -> None:
        required = {"author", "created_at", "license", "source_origin"}
        missing = required - set(self.provenance.keys())
        if missing:
            raise InvalidInterfaceDeclarationError(
                f"Agent provenance missing required fields: {sorted(missing)}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_urn": self.agent_urn,
            "display_name": self.display_name,
            "description": self.description,
            "provenance": self.provenance
        }

    def to_deterministic_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True
        ).encode("utf-8")

    def compute_sha256(self) -> str:
        return hashlib.sha256(self.to_deterministic_json_bytes()).hexdigest()


class InterfaceCapabilityRef(NamedTuple):
    """Reference binding a capability URN to its expected definition digest."""
    capability_urn: str
    expected_definition_digest: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_urn": self.capability_urn,
            "expected_definition_digest": self.expected_definition_digest
        }


class InterfaceDeclaration:
    """
    Canonical interface declaration defining the contract of an agent interface,
    its version, associated capability definitions, and provenance metadata.
    """
    def __init__(
        self,
        interface_urn: str,
        agent_urn: str,
        interface_version: int,
        display_name: str,
        description: str,
        capabilities: List[InterfaceCapabilityRef],
        provenance: Dict[str, Any],
        schema_version: int = 1
    ):
        parsed_iface = parse_canonical_urn(interface_urn)
        if parsed_iface.entity_kind != "interface":
            raise InvalidInterfaceURNError(
                f"Interface URN must have entity kind 'interface', got '{parsed_iface.entity_kind}' in '{interface_urn}'"
            )
        self.interface_urn = parsed_iface.raw_urn

        parsed_agent = parse_canonical_urn(agent_urn)
        if parsed_agent.entity_kind != "agent":
            raise InvalidInterfaceURNError(
                f"Agent URN must have entity kind 'agent', got '{parsed_agent.entity_kind}' in '{agent_urn}'"
            )
        self.agent_urn = parsed_agent.raw_urn

        if not isinstance(interface_version, int) or interface_version < 1:
            raise InvalidInterfaceDeclarationError(
                f"interface_version must be a positive integer, got: {interface_version!r}"
            )
        self.interface_version = interface_version

        self.display_name = str(display_name).strip()
        if not self.display_name:
            raise InvalidInterfaceDeclarationError("Interface display_name cannot be empty")
        self.description = str(description).strip()

        if not capabilities:
            raise InvalidInterfaceDeclarationError("Interface must bind at least one capability reference")

        # Validate capability references
        seen_caps: Set[str] = set()
        validated_caps: List[InterfaceCapabilityRef] = []
        for ref in capabilities:
            cap_urn = ref.capability_urn
            digest = ref.expected_definition_digest.lower()
            parsed_cap = parse_canonical_urn(cap_urn)
            if parsed_cap.entity_kind not in ("tool", "skill"):
                raise InvalidInterfaceDeclarationError(
                    f"Bound capability must have entity kind 'tool' or 'skill', got '{parsed_cap.entity_kind}' in '{cap_urn}'"
                )
            if cap_urn in seen_caps:
                raise InvalidInterfaceDeclarationError(f"Duplicate capability URN in interface declaration: {cap_urn}")
            seen_caps.add(cap_urn)

            if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
                raise InvalidInterfaceDeclarationError(
                    f"Invalid expected_definition_digest for '{cap_urn}': expected 64 hex characters, got '{digest}'"
                )
            validated_caps.append(InterfaceCapabilityRef(cap_urn, digest))

        # Sort capabilities deterministically by capability_urn
        validated_caps.sort(key=lambda r: r.capability_urn)
        self.capabilities = tuple(validated_caps)

        self.provenance = provenance if provenance is not None else {}
        self._validate_provenance()
        self.schema_version = schema_version

    def _validate_provenance(self) -> None:
        required = {"author", "created_at", "license", "source_origin"}
        missing = required - set(self.provenance.keys())
        if missing:
            raise InvalidInterfaceDeclarationError(
                f"Interface provenance missing required fields: {sorted(missing)}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interface_urn": self.interface_urn,
            "agent_urn": self.agent_urn,
            "interface_version": self.interface_version,
            "schema_version": self.schema_version,
            "display_name": self.display_name,
            "description": self.description,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "provenance": self.provenance
        }

    def to_deterministic_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True
        ).encode("utf-8")

    def compute_sha256(self) -> str:
        return hashlib.sha256(self.to_deterministic_json_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InterfaceDeclaration":
        caps = [
            InterfaceCapabilityRef(
                capability_urn=c["capability_urn"],
                expected_definition_digest=c["expected_definition_digest"]
            )
            for c in data.get("capabilities", [])
        ]
        return cls(
            interface_urn=data["interface_urn"],
            agent_urn=data["agent_urn"],
            interface_version=data["interface_version"],
            display_name=data["display_name"],
            description=data["description"],
            capabilities=caps,
            provenance=data.get("provenance", {}),
            schema_version=data.get("schema_version", 1)
        )


# ----------------------------------------------------------------------------
# Data Models: Interface Attestation
# ----------------------------------------------------------------------------

class InterfaceAttestation:
    """
    Cryptographic attestation asserting the authenticity, version, content digest,
    and capability bindings of an agent interface, signed using HMAC-SHA256 from
    the persistent key store.
    """
    def __init__(
        self,
        attestation_id: str,
        interface_urn: str,
        agent_urn: str,
        interface_version: int,
        interface_digest: str,
        capability_bindings: List[Dict[str, str]],
        attester_id: str,
        attested_at: str,
        key_id: str,
        signature: str,
        attestation_blob_digest: Optional[str] = None
    ):
        self.attestation_id = attestation_id
        self.interface_urn = interface_urn
        self.agent_urn = agent_urn
        self.interface_version = interface_version
        self.interface_digest = interface_digest.lower()
        # Ensure capability_bindings are sorted deterministically
        self.capability_bindings = tuple(sorted(capability_bindings, key=lambda b: b["capability_urn"]))
        self.attester_id = attester_id
        self.attested_at = attested_at
        self.key_id = key_id
        self.signature = signature.lower()
        self.attestation_blob_digest = attestation_blob_digest or self.compute_sha256()

    def to_claims_dict(self) -> Dict[str, Any]:
        """Returns the claims payload over which the signature is calculated."""
        return {
            "attestation_id": self.attestation_id,
            "attester_id": self.attester_id,
            "attested_at": self.attested_at,
            "agent_urn": self.agent_urn,
            "interface_urn": self.interface_urn,
            "interface_version": self.interface_version,
            "interface_digest": self.interface_digest,
            "capability_bindings": list(self.capability_bindings),
            "key_id": self.key_id
        }

    def to_claims_bytes(self) -> bytes:
        return json.dumps(
            self.to_claims_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True
        ).encode("utf-8")

    def to_full_dict(self) -> Dict[str, Any]:
        claims = self.to_claims_dict()
        claims["signature"] = self.signature
        return claims

    def to_deterministic_json_bytes(self) -> bytes:
        return json.dumps(
            self.to_full_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True
        ).encode("utf-8")

    def compute_sha256(self) -> str:
        return hashlib.sha256(self.to_deterministic_json_bytes()).hexdigest()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InterfaceAttestation":
        return cls(
            attestation_id=data["attestation_id"],
            interface_urn=data["interface_urn"],
            agent_urn=data["agent_urn"],
            interface_version=data["interface_version"],
            interface_digest=data["interface_digest"],
            capability_bindings=data["capability_bindings"],
            attester_id=data["attester_id"],
            attested_at=data["attested_at"],
            key_id=data["key_id"],
            signature=data["signature"],
            attestation_blob_digest=data.get("attestation_blob_digest")
        )


# ----------------------------------------------------------------------------
# Data Models: Policy & Decision
# ----------------------------------------------------------------------------

class InterfaceTrustPolicy:
    """Configured policy requirements against which an interface declaration is evaluated."""
    def __init__(
        self,
        policy_name: str,
        allowed_attester_ids: Optional[Set[str]] = None,
        allowed_agent_urns: Optional[Set[str]] = None,
        allowed_source_origins: Optional[Set[str]] = None,
        required_licenses: Optional[Set[str]] = None,
        min_interface_version: int = 1,
        require_attestation: bool = True,
        require_all_capabilities_verified: bool = True
    ):
        self.policy_name = policy_name
        self.allowed_attester_ids = set(allowed_attester_ids) if allowed_attester_ids is not None else None
        self.allowed_agent_urns = set(allowed_agent_urns) if allowed_agent_urns is not None else None
        self.allowed_source_origins = set(allowed_source_origins) if allowed_source_origins is not None else None
        self.required_licenses = set(required_licenses) if required_licenses is not None else None
        self.min_interface_version = min_interface_version
        self.require_attestation = require_attestation
        self.require_all_capabilities_verified = require_all_capabilities_verified


class PolicyEvaluationDecision:
    """Structured, explainable evaluation decision produced by the policy engine."""
    def __init__(
        self,
        decision_id: str,
        interface_urn: str,
        agent_urn: str,
        interface_version: int,
        policy_name: str,
        decision: str,
        status: str,
        reasons: List[str],
        attestation_id: Optional[str] = None,
        evaluated_at: Optional[str] = None
    ):
        if decision not in ("ALLOW", "DENY"):
            raise PolicyEvaluationError(f"Invalid policy decision: {decision!r} (must be ALLOW or DENY)")
        if status not in ("VERIFIED", "UNVERIFIED", "REJECTED", "UNAVAILABLE"):
            raise PolicyEvaluationError(f"Invalid policy status: {status!r}")

        self.decision_id = decision_id
        self.interface_urn = interface_urn
        self.agent_urn = agent_urn
        self.interface_version = interface_version
        self.policy_name = policy_name
        self.decision = decision
        self.status = status
        self.reasons = tuple(reasons)
        self.attestation_id = attestation_id
        self.evaluated_at = evaluated_at or time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "interface_urn": self.interface_urn,
            "agent_urn": self.agent_urn,
            "interface_version": self.interface_version,
            "policy_name": self.policy_name,
            "decision": self.decision,
            "status": self.status,
            "reasons": list(self.reasons),
            "attestation_id": self.attestation_id,
            "evaluated_at": self.evaluated_at
        }


# ----------------------------------------------------------------------------
# Core Service: InterfacePolicyService
# ----------------------------------------------------------------------------

class InterfacePolicyService:
    """
    Manages agent and interface registration, cryptographic interface attestation,
    attestation verification across process restarts, and explainable policy evaluation.
    """
    def __init__(
        self,
        conn: sqlite3.Connection,
        cas_engine: SecureCASStorageEngine,
        cap_registry: Optional[CapabilityRegistrationService] = None
    ):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("conn must be a sqlite3.Connection")
        if not isinstance(cas_engine, SecureCASStorageEngine):
            raise TypeError("cas_engine must be a SecureCASStorageEngine")

        self.conn = conn
        self.cas_engine = cas_engine
        self.cap_registry = cap_registry or CapabilityRegistrationService(conn, cas_engine)

        self._ensure_foreign_keys()
        self.ensure_schema()

    def _ensure_foreign_keys(self) -> None:
        """Enforces that SQLite foreign keys are active. Fails closed if not possible."""
        if self.conn.in_transaction:
            raise SQLiteForeignKeyEnforcementError(
                "Cannot enable SQLite foreign-key enforcement during an active uncommitted transaction."
            )
        cur = self.conn.cursor()
        cur.execute("PRAGMA foreign_keys;")
        row = cur.fetchone()
        if not row or row[0] != 1:
            self.conn.execute("PRAGMA foreign_keys = ON;")
            cur.execute("PRAGMA foreign_keys;")
            check_row = cur.fetchone()
            if not check_row or check_row[0] != 1:
                raise SQLiteForeignKeyEnforcementError("Failed to enable SQLite foreign-key enforcement")

    def ensure_schema(self) -> None:
        """Applies the Milestone 3 schema migration idempotently."""
        migration_path = os.path.join(os.path.dirname(__file__), "lcs_schema_m3_migration.sql")
        with open(migration_path, "r", encoding="utf-8") as f:
            ddl = f.read()
        self.conn.executescript(ddl)
        self.conn.commit()

    # ------------------------------------------------------------------------
    # Agent Registration
    # ------------------------------------------------------------------------

    def register_agent(self, agent: AgentDeclaration) -> AgentDeclaration:
        """Registers a canonical agent identity in entity_urn_registry and agent_declarations."""
        cur = self.conn.cursor()

        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # Check existing
            cur.execute("""
                SELECT provenance_json, display_name, description
                FROM agent_declarations
                WHERE agent_urn = ?;
            """, (agent.agent_urn,))
            row = cur.fetchone()
            if row:
                existing_prov = json.loads(row[0]) if row[0] else {}
                # Separate immutable identity/provenance attributes from creation timestamps
                stable_existing = {
                    k: v for k, v in existing_prov.items()
                    if k not in ("created_at", "registered_at", "timestamp")
                }
                stable_proposed = {
                    k: v for k, v in agent.provenance.items()
                    if k not in ("created_at", "registered_at", "timestamp")
                }

                existing_display = row[1]
                existing_desc = row[2]

                if (stable_existing == stable_proposed and
                    agent.display_name == existing_display and
                    agent.description == existing_desc):
                    # Idempotent re-registration: preserve original creation timestamp
                    if "created_at" in existing_prov:
                        agent.provenance["created_at"] = existing_prov["created_at"]
                    self.conn.commit()
                    return agent
                else:
                    self.conn.rollback()
                    raise InterfacePolicyError(
                        f"Agent '{agent.agent_urn}' already registered with different provenance"
                    )

            prov_json = json.dumps(agent.provenance, sort_keys=True, separators=(",", ":"))

            cur.execute("""
                INSERT OR IGNORE INTO entity_urn_registry (
                    entity_urn, entity_kind, lifecycle_state
                ) VALUES (?, 'CAPABILITY', 'PENDING');
            """, (agent.agent_urn,))

            cur.execute("""
                INSERT OR IGNORE INTO capabilities (
                    capability_urn, name, version, description
                ) VALUES (?, ?, '1.0.0', ?);
            """, (agent.agent_urn, agent.display_name, agent.description))

            cur.execute("""
                UPDATE entity_urn_registry
                SET lifecycle_state = 'ACTIVE'
                WHERE entity_urn = ?;
            """, (agent.agent_urn,))

            cur.execute("""
                INSERT INTO agent_declarations (
                    agent_urn, display_name, description, provenance_json
                ) VALUES (?, ?, ?, ?);
            """, (agent.agent_urn, agent.display_name, agent.description, prov_json))

            self.conn.commit()
            return agent
        except Exception:
            self.conn.rollback()
            raise

    # ------------------------------------------------------------------------
    # Interface Registration
    # ------------------------------------------------------------------------

    def register_interface(self, interface: InterfaceDeclaration) -> InterfaceDeclaration:
        """
        Registers a canonical interface declaration:
        1. Confirms associated agent is registered.
        2. Confirms all referenced capabilities exist in capability_declarations and match digest.
        3. Checks if interface is already registered in SQLite:
           - If stable identity and provenance attributes match, preserves original creation
             timestamp and returns idempotently without writing redundant CAS blobs or rows.
           - If stable attributes or capabilities differ, raises InterfacePolicyError.
        4. Persists declaration payload in CAS storage.
        5. Persists interface and capability bindings in SQLite under BEGIN IMMEDIATE.
        """
        cur = self.conn.cursor()

        # 1. Verify agent exists
        cur.execute("SELECT 1 FROM agent_declarations WHERE agent_urn = ?;", (interface.agent_urn,))
        if not cur.fetchone():
            raise AgentNotFoundError(f"Agent '{interface.agent_urn}' is not registered")

        # 2. Verify all capability references exist in capability_declarations with matching digest
        for cap_ref in interface.capabilities:
            cur.execute("""
                SELECT definition_blob_digest FROM capability_declarations
                WHERE capability_urn = ?;
            """, (cap_ref.capability_urn,))
            row = cur.fetchone()
            if not row:
                raise CapabilityNotFoundError(
                    f"Referenced capability '{cap_ref.capability_urn}' is not registered in capability_declarations"
                )
            if row[0].lower() != cap_ref.expected_definition_digest.lower():
                raise InvalidInterfaceDeclarationError(
                    f"Digest mismatch for capability '{cap_ref.capability_urn}': "
                    f"expected '{cap_ref.expected_definition_digest}', registered is '{row[0]}'"
                )

        # 3. Fast-path check: Check if interface is already registered in SQLite
        cur.execute("""
            SELECT declaration_blob_digest, agent_urn, interface_version, display_name, description, schema_version
            FROM interface_declarations
            WHERE interface_urn = ?;
        """, (interface.interface_urn,))
        existing_row = cur.fetchone()

        if existing_row:
            existing_digest = existing_row[0]
            if self.cas_engine.blob_exists(existing_digest):
                existing_bytes = self.cas_engine.read_blob(existing_digest)
                existing_dict = json.loads(existing_bytes.decode("utf-8"))
                existing_prov = existing_dict.get("provenance", {})

                # Separate immutable identity/provenance attributes from creation timestamps
                stable_existing_prov = {
                    k: v for k, v in existing_prov.items()
                    if k not in ("created_at", "registered_at", "timestamp")
                }
                stable_proposed_prov = {
                    k: v for k, v in interface.provenance.items()
                    if k not in ("created_at", "registered_at", "timestamp")
                }

                existing_caps = existing_dict.get("capabilities", [])
                proposed_caps = [c.to_dict() for c in interface.capabilities]

                if (stable_existing_prov == stable_proposed_prov and
                    interface.agent_urn == existing_row[1] and
                    interface.interface_version == existing_row[2] and
                    interface.display_name == existing_row[3] and
                    interface.description == existing_row[4] and
                    interface.schema_version == existing_row[5] and
                    existing_caps == proposed_caps):
                    # Idempotent match: preserve original creation timestamp
                    if "created_at" in existing_prov:
                        interface.provenance["created_at"] = existing_prov["created_at"]
                    return interface
                else:
                    raise InterfacePolicyError(
                        f"Interface '{interface.interface_urn}' already registered with different definition digest: "
                        f"existing '{existing_digest}', proposed '{interface.compute_sha256()}'"
                    )

        payload_bytes = interface.to_deterministic_json_bytes()
        digest = hashlib.sha256(payload_bytes).hexdigest()
        byte_len = len(payload_bytes)

        # 4. Write declaration to CAS storage
        pub_id = f"iface_pub_{digest[:16]}_{uuid.uuid4().hex[:8]}"
        pub_tok = f"tok_{uuid.uuid4().hex[:16]}"
        tmp_name, _, _ = self.cas_engine.write_payload_to_staging(pub_id, pub_tok, digest, payload_bytes)
        self.cas_engine.publish_staging_to_cas(tmp_name, digest)

        # 5. Immediate transaction in SQLite
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            # Re-check under lock in case of concurrent registration race
            cur.execute("""
                SELECT declaration_blob_digest FROM interface_declarations
                WHERE interface_urn = ?;
            """, (interface.interface_urn,))
            row = cur.fetchone()
            if row:
                if row[0] == digest:
                    self.conn.commit()
                    return interface
                else:
                    self.conn.rollback()
                    raise InterfacePolicyError(
                        f"Interface '{interface.interface_urn}' already registered with different definition digest: "
                        f"existing '{row[0]}', proposed '{digest}'"
                    )

            # Record in content_chunk_blobs
            cur.execute("""
                INSERT OR IGNORE INTO content_chunk_blobs (
                    blob_digest, byte_length, storage_compression, stored_byte_length
                ) VALUES (?, ?, 'NONE', ?);
            """, (digest, byte_len, byte_len))

            # Record in entity_urn_registry
            cur.execute("""
                INSERT OR IGNORE INTO entity_urn_registry (
                    entity_urn, entity_kind, lifecycle_state
                ) VALUES (?, 'CAPABILITY', 'PENDING');
            """, (interface.interface_urn,))

            cur.execute("""
                INSERT OR IGNORE INTO capabilities (
                    capability_urn, name, version, description
                ) VALUES (?, ?, '1.0.0', ?);
            """, (interface.interface_urn, interface.display_name, interface.description))

            cur.execute("""
                UPDATE entity_urn_registry
                SET lifecycle_state = 'ACTIVE'
                WHERE entity_urn = ?;
            """, (interface.interface_urn,))

            # Insert interface declaration
            cur.execute("""
                INSERT INTO interface_declarations (
                    interface_urn, agent_urn, interface_version, display_name,
                    description, declaration_blob_digest, schema_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (
                interface.interface_urn,
                interface.agent_urn,
                interface.interface_version,
                interface.display_name,
                interface.description,
                digest,
                interface.schema_version
            ))

            # Insert capability bindings
            for cap_ref in interface.capabilities:
                binding_id = f"bnd_{hashlib.sha256((interface.interface_urn + ':' + cap_ref.capability_urn).encode()).hexdigest()[:24]}"
                cur.execute("""
                    INSERT INTO interface_capability_bindings (
                        binding_id, interface_urn, capability_urn, expected_definition_digest
                    ) VALUES (?, ?, ?, ?);
                """, (binding_id, interface.interface_urn, cap_ref.capability_urn, cap_ref.expected_definition_digest))

            self.conn.commit()
            return interface
        except Exception:
            self.conn.rollback()
            raise

    # ------------------------------------------------------------------------
    # Interface Attestation
    # ------------------------------------------------------------------------

    def attest_interface(
        self,
        interface_urn: str,
        attester_id: str = "urn:lcs:attester:local:system",
        force: bool = False
    ) -> InterfaceAttestation:
        """
        Creates a cryptographic attestation for an interface:
        1. Verifies interface exists and retrieves its declaration.
        2. If force=False, checks if an existing valid attestation for this
           (interface_urn, attester_id) with matching interface_digest already exists.
           If valid, reuses it without creating unnecessary duplicate attestations.
        3. Confirms all referenced capability definition blobs are intact on disk.
        4. Obtains active HMAC key from PersistentReceiptKeyStore.
        5. Calculates HMAC-SHA256 signature over canonical attestation claims.
        6. Ingests attestation into CAS storage.
        7. Persists attestation in interface_attestations table.
        """
        cur = self.conn.cursor()
        cur.execute("""
            SELECT agent_urn, interface_version, declaration_blob_digest
            FROM interface_declarations
            WHERE interface_urn = ?;
        """, (interface_urn,))
        row = cur.fetchone()
        if not row:
            raise InterfaceNotFoundError(f"Interface '{interface_urn}' is not registered")
        agent_urn, iface_version, iface_digest = row[0], row[1], row[2]

        # Verify interface declaration blob in CAS
        if not self.cas_engine.blob_exists(iface_digest):
            raise CASBlobNotFoundError(f"CAS blob for interface declaration '{iface_digest}' not found")
        iface_bytes = self.cas_engine.read_blob(iface_digest)
        actual_iface_digest = hashlib.sha256(iface_bytes).hexdigest()
        if actual_iface_digest != iface_digest:
            raise CASDigestMismatchError(f"Interface blob corrupted: expected '{iface_digest}', got '{actual_iface_digest}'")

        # Reuse existing valid attestation if interface definition is unchanged
        if not force:
            cur.execute("""
                SELECT attestation_id, attestation_blob_digest, interface_digest
                FROM interface_attestations
                WHERE interface_urn = ? AND attester_id = ?
                ORDER BY attested_at DESC, created_at DESC;
            """, (interface_urn, attester_id))
            existing_attests = cur.fetchall()
            for ex_att_id, ex_blob_dig, ex_iface_dig in existing_attests:
                if ex_iface_dig == iface_digest and self.cas_engine.blob_exists(ex_blob_dig):
                    valid, _ = self.verify_attestation(ex_att_id)
                    if valid:
                        raw_att_bytes = self.cas_engine.read_blob(ex_blob_dig)
                        att_dict = json.loads(raw_att_bytes.decode("utf-8"))
                        return InterfaceAttestation.from_dict(att_dict)

        # Query all bound capabilities and verify their definitions in CAS
        cur.execute("""
            SELECT capability_urn, expected_definition_digest
            FROM interface_capability_bindings
            WHERE interface_urn = ?
            ORDER BY capability_urn ASC;
        """, (interface_urn,))
        bindings = cur.fetchall()
        if not bindings:
            raise InvalidInterfaceDeclarationError(f"Interface '{interface_urn}' has no bound capabilities")

        cap_bindings_list = []
        for cap_urn, exp_digest in bindings:
            if not self.cas_engine.blob_exists(exp_digest):
                raise CASBlobNotFoundError(
                    f"Capability definition blob '{exp_digest}' for '{cap_urn}' not found in CAS storage"
                )
            cap_bytes = self.cas_engine.read_blob(exp_digest)
            computed_cap_digest = hashlib.sha256(cap_bytes).hexdigest()
            if computed_cap_digest != exp_digest:
                raise CASDigestMismatchError(
                    f"Capability definition blob for '{cap_urn}' corrupted: "
                    f"expected '{exp_digest}', got '{computed_cap_digest}'"
                )
            cap_bindings_list.append({
                "capability_urn": cap_urn,
                "definition_digest": exp_digest
            })

        # Cryptographic signing using active key from key store
        key_id, key_secret = self.cas_engine.key_store.get_active_key()
        attestation_id = f"att_{uuid.uuid4().hex[:16]}"
        attested_at = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

        # Construct attestation object (without signature first to build claims bytes)
        att = InterfaceAttestation(
            attestation_id=attestation_id,
            interface_urn=interface_urn,
            agent_urn=agent_urn,
            interface_version=iface_version,
            interface_digest=iface_digest,
            capability_bindings=cap_bindings_list,
            attester_id=attester_id,
            attested_at=attested_at,
            key_id=key_id,
            signature=""  # Computed below
        )

        claims_bytes = att.to_claims_bytes()
        sig = hmac.new(key_secret, claims_bytes, hashlib.sha256).hexdigest()
        att.signature = sig
        att.attestation_blob_digest = att.compute_sha256()

        # Ingest attestation into CAS storage
        att_bytes = att.to_deterministic_json_bytes()
        att_digest = att.attestation_blob_digest
        pub_id = f"att_pub_{att_digest[:16]}_{uuid.uuid4().hex[:8]}"
        pub_tok = f"tok_{uuid.uuid4().hex[:16]}"
        tmp_name, _, _ = self.cas_engine.write_payload_to_staging(pub_id, pub_tok, att_digest, att_bytes)
        self.cas_engine.publish_staging_to_cas(tmp_name, att_digest)

        # Persist attestation in SQLite under immediate transaction
        self.conn.execute("BEGIN IMMEDIATE;")
        try:
            cur.execute("""
                INSERT OR IGNORE INTO content_chunk_blobs (
                    blob_digest, byte_length, storage_compression, stored_byte_length
                ) VALUES (?, ?, 'NONE', ?);
            """, (att_digest, len(att_bytes), len(att_bytes)))

            cur.execute("""
                INSERT INTO interface_attestations (
                    attestation_id, interface_urn, agent_urn, interface_version,
                    interface_digest, attester_id, key_id, signature,
                    attestation_blob_digest, attested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                att.attestation_id,
                att.interface_urn,
                att.agent_urn,
                att.interface_version,
                att.interface_digest,
                att.attester_id,
                att.key_id,
                att.signature,
                att_digest,
                att.attested_at
            ))
            self.conn.commit()
            return att
        except Exception:
            self.conn.rollback()
            raise

    # ------------------------------------------------------------------------
    # Attestation Verification
    # ------------------------------------------------------------------------

    def verify_attestation(self, attestation_id: str) -> Tuple[bool, List[str]]:
        """
        Verifies an interface attestation across restarts:
        1. Retrieves attestation record from SQLite.
        2. Retrieves HMAC key from PersistentReceiptKeyStore by key_id.
        3. Verifies HMAC-SHA256 signature against claims bytes.
        4. Verifies attestation blob in CAS matches attestation_blob_digest.
        5. Verifies interface declaration blob in CAS matches interface_digest.
        6. Verifies every bound capability definition in CAS matches attested digest.
        7. Returns (is_valid, reasons).
        """
        reasons: List[str] = []
        cur = self.conn.cursor()
        cur.execute("""
            SELECT attestation_id, interface_urn, agent_urn, interface_version,
                   interface_digest, attester_id, key_id, signature,
                   attestation_blob_digest, attested_at
            FROM interface_attestations
            WHERE attestation_id = ?;
        """, (attestation_id,))
        row = cur.fetchone()
        if not row:
            return False, [f"Attestation ID '{attestation_id}' not found in database"]

        (
            att_id, iface_urn, agent_urn, iface_ver, iface_digest,
            attester_id, key_id, sig, att_blob_digest, attested_at
        ) = row

        # Query capability bindings from DB
        cur.execute("""
            SELECT capability_urn, expected_definition_digest
            FROM interface_capability_bindings
            WHERE interface_urn = ?
            ORDER BY capability_urn ASC;
        """, (iface_urn,))
        binding_rows = cur.fetchall()
        cap_bindings = [
            {"capability_urn": r[0], "definition_digest": r[1]}
            for r in binding_rows
        ]

        # 1. Retrieve key from key store
        try:
            key_secret = self.cas_engine.key_store.get_key(key_id)
        except Exception as e:
            return False, [f"Failed to retrieve verification key '{key_id}' from key store: {e}"]

        # 2. Reconstruct attestation claims and verify HMAC
        att = InterfaceAttestation(
            attestation_id=att_id,
            interface_urn=iface_urn,
            agent_urn=agent_urn,
            interface_version=iface_ver,
            interface_digest=iface_digest,
            capability_bindings=cap_bindings,
            attester_id=attester_id,
            attested_at=attested_at,
            key_id=key_id,
            signature=sig,
            attestation_blob_digest=att_blob_digest
        )

        expected_sig = hmac.new(key_secret, att.to_claims_bytes(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig.lower(), expected_sig.lower()):
            return False, ["Cryptographic HMAC signature verification failed (tampered claims or signature)"]

        # 3. Verify attestation blob in CAS
        if not self.cas_engine.blob_exists(att_blob_digest):
            return False, [f"Attestation blob '{att_blob_digest}' is missing from CAS storage"]
        try:
            actual_att_bytes = self.cas_engine.read_blob(att_blob_digest)
            if hashlib.sha256(actual_att_bytes).hexdigest() != att_blob_digest:
                return False, [f"Attestation blob '{att_blob_digest}' in CAS is corrupted"]
        except (CASDigestMismatchError, Exception) as e:
            return False, [f"Attestation blob '{att_blob_digest}' in CAS is corrupted or unreadable: {e}"]

        # 4. Verify interface declaration blob in CAS
        if not self.cas_engine.blob_exists(iface_digest):
            return False, [f"Interface declaration blob '{iface_digest}' is missing from CAS storage"]
        try:
            actual_iface_bytes = self.cas_engine.read_blob(iface_digest)
            if hashlib.sha256(actual_iface_bytes).hexdigest() != iface_digest:
                return False, [f"Interface declaration blob '{iface_digest}' in CAS is corrupted / modified"]
        except (CASDigestMismatchError, Exception) as e:
            return False, [f"Interface declaration blob '{iface_digest}' in CAS is corrupted / modified: {e}"]

        # 5. Verify all capability definition blobs in CAS
        for binding in cap_bindings:
            c_urn = binding["capability_urn"]
            c_exp = binding["definition_digest"]
            if not self.cas_engine.blob_exists(c_exp):
                return False, [f"Capability definition blob '{c_exp}' for '{c_urn}' missing from CAS storage"]
            try:
                actual_cap_bytes = self.cas_engine.read_blob(c_exp)
                if hashlib.sha256(actual_cap_bytes).hexdigest() != c_exp:
                    return False, [f"Capability definition blob for '{c_urn}' has been modified / corrupted on disk"]
            except (CASDigestMismatchError, Exception) as e:
                return False, [f"Capability definition blob for '{c_urn}' has been modified / corrupted on disk: {e}"]

        reasons.append("HMAC signature verified against persistent key store")
        reasons.append("Interface declaration digest matches authentic CAS content")
        reasons.append(f"All {len(cap_bindings)} capability definition digests verified in CAS storage")
        return True, reasons

    # ------------------------------------------------------------------------
    # Policy Evaluation Layer
    # ------------------------------------------------------------------------

    def evaluate_policy(
        self,
        interface_urn: str,
        policy: InterfaceTrustPolicy
    ) -> PolicyEvaluationDecision:
        """
        Evaluates whether an interface satisfies configured trust requirements:
        1. Checks whether interface exists in DB and CAS.
        2. Retrieves latest attestation for interface (if any).
        3. Verifies attestation validity.
        4. Evaluates trust requirements (attester, agent, version, source origin, license).
        5. Persists decision to interface_policy_decisions table.
        6. Returns structured PolicyEvaluationDecision.
        """
        cur = self.conn.cursor()
        decision_id = f"dec_{uuid.uuid4().hex[:16]}"
        reasons: List[str] = []

        # Step 1: Check interface in DB
        cur.execute("""
            SELECT agent_urn, interface_version, declaration_blob_digest
            FROM interface_declarations
            WHERE interface_urn = ?;
        """, (interface_urn,))
        row = cur.fetchone()
        if not row:
            decision = PolicyEvaluationDecision(
                decision_id=decision_id,
                interface_urn=interface_urn,
                agent_urn="urn:lcs:agent:unknown:unknown",
                interface_version=0,
                policy_name=policy.policy_name,
                decision="DENY",
                status="UNAVAILABLE",
                reasons=[f"Interface '{interface_urn}' is not registered in database"]
            )
            return decision

        agent_urn, iface_version, iface_digest = row[0], row[1], row[2]

        # Step 2: Check interface declaration in CAS
        if not self.cas_engine.blob_exists(iface_digest):
            decision = PolicyEvaluationDecision(
                decision_id=decision_id,
                interface_urn=interface_urn,
                agent_urn=agent_urn,
                interface_version=iface_version,
                policy_name=policy.policy_name,
                decision="DENY",
                status="UNAVAILABLE",
                reasons=[f"Interface declaration CAS content '{iface_digest}' is missing from disk"]
            )
            self._persist_decision(decision)
            return decision

        try:
            iface_bytes = self.cas_engine.read_blob(iface_digest)
            if hashlib.sha256(iface_bytes).hexdigest() != iface_digest:
                raise CASDigestMismatchError("Interface declaration content mismatch")
            iface_decl = InterfaceDeclaration.from_dict(json.loads(iface_bytes.decode("utf-8")))
        except Exception as e:
            decision = PolicyEvaluationDecision(
                decision_id=decision_id,
                interface_urn=interface_urn,
                agent_urn=agent_urn,
                interface_version=iface_version,
                policy_name=policy.policy_name,
                decision="DENY",
                status="UNAVAILABLE",
                reasons=[f"Interface declaration content in CAS is corrupted or unreadable: {e}"]
            )
            self._persist_decision(decision)
            return decision

        # Step 3: Check attestation
        cur.execute("""
            SELECT attestation_id, attester_id, key_id
            FROM interface_attestations
            WHERE interface_urn = ?
            ORDER BY created_at DESC
            LIMIT 1;
        """, (interface_urn,))
        att_row = cur.fetchone()

        attestation_id: Optional[str] = None
        attester_id: Optional[str] = None

        if not att_row:
            if policy.require_attestation:
                decision = PolicyEvaluationDecision(
                    decision_id=decision_id,
                    interface_urn=interface_urn,
                    agent_urn=agent_urn,
                    interface_version=iface_version,
                    policy_name=policy.policy_name,
                    decision="DENY",
                    status="UNVERIFIED",
                    reasons=["Interface declaration has no cryptographic attestation; policy requires verified attestation"]
                )
                self._persist_decision(decision)
                return decision
        else:
            attestation_id = att_row[0]
            attester_id = att_row[1]

            # Verify attestation
            is_valid, verif_reasons = self.verify_attestation(attestation_id)
            if not is_valid:
                decision = PolicyEvaluationDecision(
                    decision_id=decision_id,
                    interface_urn=interface_urn,
                    agent_urn=agent_urn,
                    interface_version=iface_version,
                    policy_name=policy.policy_name,
                    decision="DENY",
                    status="REJECTED",
                    reasons=[f"Attestation verification failed: {r}" for r in verif_reasons],
                    attestation_id=attestation_id
                )
                self._persist_decision(decision)
                return decision
            reasons.extend(verif_reasons)

        # Step 4: Check capabilities integrity if required
        if policy.require_all_capabilities_verified:
            cur.execute("""
                SELECT capability_urn, expected_definition_digest
                FROM interface_capability_bindings
                WHERE interface_urn = ?;
            """, (interface_urn,))
            bindings = cur.fetchall()
            for cap_urn, exp_digest in bindings:
                if not self.cas_engine.blob_exists(exp_digest):
                    decision = PolicyEvaluationDecision(
                        decision_id=decision_id,
                        interface_urn=interface_urn,
                        agent_urn=agent_urn,
                        interface_version=iface_version,
                        policy_name=policy.policy_name,
                        decision="DENY",
                        status="UNAVAILABLE",
                        reasons=[f"Referenced capability '{cap_urn}' content is missing from CAS storage"],
                        attestation_id=attestation_id
                    )
                    self._persist_decision(decision)
                    return decision
                try:
                    cap_bytes = self.cas_engine.read_blob(exp_digest)
                    if hashlib.sha256(cap_bytes).hexdigest() != exp_digest:
                        raise CASDigestMismatchError("Digest mismatch")
                except (CASDigestMismatchError, Exception) as e:
                    decision = PolicyEvaluationDecision(
                        decision_id=decision_id,
                        interface_urn=interface_urn,
                        agent_urn=agent_urn,
                        interface_version=iface_version,
                        policy_name=policy.policy_name,
                        decision="DENY",
                        status="REJECTED",
                        reasons=[f"Referenced capability '{cap_urn}' definition has been altered / corrupted on disk: {e}"],
                        attestation_id=attestation_id
                    )
                    self._persist_decision(decision)
                    return decision
            reasons.append(f"All {len(bindings)} bound capabilities verified intact on disk")

        # Step 5: Evaluate Trust Policy Constraints
        rejected_reasons: List[str] = []

        # Version check
        if iface_version < policy.min_interface_version:
            rejected_reasons.append(
                f"Interface version {iface_version} is below policy minimum {policy.min_interface_version}"
            )

        # Attester ID check
        if policy.allowed_attester_ids is not None:
            if attester_id not in policy.allowed_attester_ids:
                rejected_reasons.append(
                    f"Attester '{attester_id}' is not in allowed attesters list: {sorted(policy.allowed_attester_ids)}"
                )

        # Agent URN check
        if policy.allowed_agent_urns is not None:
            if agent_urn not in policy.allowed_agent_urns:
                rejected_reasons.append(
                    f"Agent '{agent_urn}' is not in allowed agents list: {sorted(policy.allowed_agent_urns)}"
                )

        # Source origin check
        prov_origin = iface_decl.provenance.get("source_origin")
        if policy.allowed_source_origins is not None:
            if prov_origin not in policy.allowed_source_origins:
                rejected_reasons.append(
                    f"Interface source origin '{prov_origin}' is not in allowed origins list: {sorted(policy.allowed_source_origins)}"
                )

        # License check
        prov_license = iface_decl.provenance.get("license")
        if policy.required_licenses is not None:
            if prov_license not in policy.required_licenses:
                rejected_reasons.append(
                    f"Interface license '{prov_license}' is not in required licenses list: {sorted(policy.required_licenses)}"
                )

        if rejected_reasons:
            decision = PolicyEvaluationDecision(
                decision_id=decision_id,
                interface_urn=interface_urn,
                agent_urn=agent_urn,
                interface_version=iface_version,
                policy_name=policy.policy_name,
                decision="DENY",
                status="REJECTED",
                reasons=rejected_reasons,
                attestation_id=attestation_id
            )
            self._persist_decision(decision)
            return decision

        # All policy checks passed
        reasons.append(f"Interface version {iface_version} meets or exceeds minimum {policy.min_interface_version}")
        if policy.allowed_attester_ids:
            reasons.append(f"Attester '{attester_id}' verified against allowed attester set")
        if policy.allowed_agent_urns:
            reasons.append(f"Agent '{agent_urn}' verified against allowed agent set")
        if policy.allowed_source_origins:
            reasons.append(f"Source origin '{prov_origin}' verified against allowed origin set")
        if policy.required_licenses:
            reasons.append(f"License '{prov_license}' verified against required license set")

        decision = PolicyEvaluationDecision(
            decision_id=decision_id,
            interface_urn=interface_urn,
            agent_urn=agent_urn,
            interface_version=iface_version,
            policy_name=policy.policy_name,
            decision="ALLOW",
            status="VERIFIED",
            reasons=reasons,
            attestation_id=attestation_id
        )
        self._persist_decision(decision)
        return decision

    def _persist_decision(self, decision: PolicyEvaluationDecision) -> None:
        """Persists the policy evaluation decision audit trail into interface_policy_decisions."""
        try:
            self.conn.execute("""
                INSERT INTO interface_policy_decisions (
                    decision_id, interface_urn, policy_name, decision, status,
                    reasons_json, attestation_id, evaluated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                decision.decision_id,
                decision.interface_urn,
                decision.policy_name,
                decision.decision,
                decision.status,
                json.dumps(decision.reasons),
                decision.attestation_id,
                decision.evaluated_at
            ))
            self.conn.commit()
        except Exception:
            # If interface_urn does not exist in DB (e.g. unknown interface), ignore FK error
            try:
                self.conn.rollback()
            except Exception:
                pass

    def retrieve_decision(self, decision_id: str) -> Optional[PolicyEvaluationDecision]:
        """Retrieves an audit record of a past policy decision."""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT d.decision_id, d.interface_urn, i.agent_urn, i.interface_version,
                   d.policy_name, d.decision, d.status, d.reasons_json,
                   d.attestation_id, d.evaluated_at
            FROM interface_policy_decisions d
            LEFT JOIN interface_declarations i ON d.interface_urn = i.interface_urn
            WHERE d.decision_id = ?;
        """, (decision_id,))
        row = cur.fetchone()
        if not row:
            return None
        return PolicyEvaluationDecision(
            decision_id=row[0],
            interface_urn=row[1],
            agent_urn=row[2] or "unknown",
            interface_version=row[3] or 1,
            policy_name=row[4],
            decision=row[5],
            status=row[6],
            reasons=json.loads(row[7]),
            attestation_id=row[8],
            evaluated_at=row[9]
        )
