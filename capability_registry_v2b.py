#!/usr/bin/env python3
"""
LCS Stage 2B — Milestone 2: Capability Registration & Canonical CAS Ingestion
=============================================================================
Implements canonical URN validation, versioned declarative capability definitions,
deterministic canonical JSON serialization, and transactional integration with
the Stage 2B CAS storage engine.

Security & Architectural Invariants:
1. Canonical Lowercase ASCII URN Format:
   `urn:lcs:<entity_kind>:<namespace>:<identifier>`
   Supported entity kinds: 'tool', 'skill', 'agent', 'interface'.
   Strict validation: rejects uppercase, spaces, colons in namespace or identifier,
   slashes, percent-encoding, leading/trailing dots/hyphens. Never silently normalizes.
2. Declarative Capability Definition:
   Deterministic serialization: keys sorted, standard compact separators (',', ':'),
   UTF-8 encoded. Equivalent definitions always produce identical bytes.
3. Declarative-Only Specification:
   Example capability `urn:lcs:tool:system.math:eval-add` is purely declarative
   (zero execution of arbitrary code or runtime subprocesses).
4. CAS Ingestion & Transactional Registration:
   - Validates URN and definition.
   - Deterministic serialization & SHA-256 computation.
   - Stores exact bytes in CAS using SecureCASStorageEngine.
   - Persists mapping in SQLite `capability_declarations` with FK to `capabilities`
     and `content_chunk_blobs`.
   - Enforces duplicate registration invariant: identical definition is idempotent,
     conflicting definition is strictly rejected.
5. Retrieval & Integrity Verification:
   - Retrieves exact bytes from CAS descriptor-relative with O_NOFOLLOW.
   - Verifies SHA-256 matches registered reference.
   - Reconstructs definition and confirms byte-for-byte equality with serialization.
   - Missing or corrupted CAS content raises explicit errors; no silent repair.
"""

import os
import re
import sys
import json
import time
import uuid
import errno
import hashlib
import sqlite3
from typing import Dict, Any, Optional, NamedTuple

from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    CASError,
    CASValidationError,
    CASSecurityViolationError,
    CASBlobNotFoundError,
    CASDigestMismatchError,
    CASPublicationConflictError
)

# ----------------------------------------------------------------------------
# Custom Exceptions
# ----------------------------------------------------------------------------

class CapabilityRegistryError(CASError):
    """Base exception for capability registry errors."""
    pass

class SQLiteForeignKeyEnforcementError(CapabilityRegistryError):
    """Raised when SQLite foreign key enforcement cannot be guaranteed or enabled on the connection."""
    pass

class InvalidCapabilityURNError(CapabilityRegistryError, CASValidationError):
    """Raised when a capability URN violates canonical syntax rules."""
    pass

class InvalidCapabilityDefinitionError(CapabilityRegistryError, CASValidationError):
    """Raised when a capability definition fails structural or semantic validation."""
    pass

class CapabilityRegistrationConflictError(CapabilityRegistryError):
    """Raised when attempting to register a different definition under an existing canonical ID."""
    pass

class CapabilityNotFoundError(CapabilityRegistryError):
    """Raised when a requested capability URN is not registered."""
    pass

class CapabilityCorruptionError(CapabilityRegistryError):
    """Raised when retrieved capability content is corrupted or fails integrity check."""
    pass

class CapabilityIntegrityMismatchError(CapabilityRegistryError):
    """Raised when retrieved capability payload does not match its registered URN or digest."""
    pass


# ----------------------------------------------------------------------------
# Canonical URN Model & Parsing
# ----------------------------------------------------------------------------

CANONICAL_URN_PATTERN = re.compile(
    r"^urn:lcs:(tool|skill|agent|interface):([a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*):([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)$"
)

SUPPORTED_ENTITY_KINDS = frozenset({"tool", "skill", "agent", "interface"})

class CanonicalCapabilityURN(NamedTuple):
    entity_kind: str
    namespace: str
    identifier: str
    raw_urn: str

def parse_canonical_urn(urn: str) -> CanonicalCapabilityURN:
    """
    Parses and strictly validates a canonical LCS capability URN.
    Syntax: urn:lcs:<entity_kind>:<namespace>:<identifier>
    
    Rules:
    - Entire string must be lowercase ASCII.
    - entity_kind must be one of: 'tool', 'skill', 'agent', 'interface'.
    - namespace: length 3 to 64, dot-separated segments of [a-z0-9_-]+.
    - identifier: length 1 to 64, [a-z0-9-]+.
    - No percent-encoding, colons, slashes, or whitespace allowed.
    - Never silently normalizes invalid input; raises InvalidCapabilityURNError.
    """
    if not isinstance(urn, str):
        raise InvalidCapabilityURNError(f"Capability URN must be a string, got {type(urn).__name__}")
        
    # Check ASCII
    try:
        urn.encode("ascii")
    except UnicodeEncodeError as e:
        raise InvalidCapabilityURNError(f"Non-ASCII characters are prohibited in capability URN: {urn!r}") from e

    # Reject uppercase characters immediately
    if any(c.isupper() for c in urn):
        raise InvalidCapabilityURNError(f"Uppercase characters are strictly prohibited in canonical URN: {urn!r}")

    # Reject percent-encoding or escapes
    if "%" in urn or "\\" in urn or "/" in urn:
        raise InvalidCapabilityURNError(f"Escapes, slashes, and percent-encoding are prohibited in canonical URN: {urn!r}")

    # Reject whitespace or control characters
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in urn):
        raise InvalidCapabilityURNError(f"Whitespace and control characters are prohibited in canonical URN: {urn!r}")

    match = CANONICAL_URN_PATTERN.match(urn)
    if not match:
        raise InvalidCapabilityURNError(f"Malformed or noncanonical capability URN format: {urn!r}")

    kind, namespace, identifier = match.groups()

    if len(namespace) < 3 or len(namespace) > 64:
        raise InvalidCapabilityURNError(
            f"Capability namespace length ({len(namespace)}) must be between 3 and 64 characters: {namespace!r}"
        )

    if len(identifier) < 1 or len(identifier) > 64:
        raise InvalidCapabilityURNError(
            f"Capability identifier length ({len(identifier)}) must be between 1 and 64 characters: {identifier!r}"
        )

    return CanonicalCapabilityURN(
        entity_kind=kind,
        namespace=namespace,
        identifier=identifier,
        raw_urn=urn
    )


# ----------------------------------------------------------------------------
# Versioned Declarative Capability Definition
# ----------------------------------------------------------------------------

class CapabilityDefinition:
    """
    Versioned, declarative definition for a living capability.
    Deterministic JSON serialization ensures equivalent definitions produce
    identical SHA-256 digests and bit-for-bit identical storage bytes.
    """
    def __init__(
        self,
        capability_id: str,
        display_name: str,
        description: str,
        capability_type: str,
        schema_version: int = 1,
        input_interface_ref: Optional[str] = None,
        output_interface_ref: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
        content_integrity: Optional[Dict[str, Any]] = None
    ):
        self.capability_id = capability_id
        self.display_name = display_name
        self.description = description
        self.capability_type = capability_type
        self.schema_version = schema_version
        self.input_interface_ref = input_interface_ref
        self.output_interface_ref = output_interface_ref
        self.provenance = dict(provenance) if provenance else {}
        self.content_integrity = dict(content_integrity) if content_integrity else {"digest_algorithm": "sha256"}
        self.validate()

    def validate(self) -> CanonicalCapabilityURN:
        """Validates all fields and semantic constraints."""
        parsed_urn = parse_canonical_urn(self.capability_id)

        if not isinstance(self.display_name, str) or not (1 <= len(self.display_name) <= 128):
            raise InvalidCapabilityDefinitionError(
                f"display_name must be a string between 1 and 128 characters, got: {self.display_name!r}"
            )

        if not isinstance(self.description, str) or not (1 <= len(self.description) <= 4096):
            raise InvalidCapabilityDefinitionError(
                f"description must be a string between 1 and 4096 characters, got: {self.description!r}"
            )

        if self.capability_type != parsed_urn.entity_kind:
            raise InvalidCapabilityDefinitionError(
                f"capability_type '{self.capability_type}' must match URN entity_kind '{parsed_urn.entity_kind}'"
            )

        if self.schema_version != 1:
            raise InvalidCapabilityDefinitionError(
                f"Unsupported schema_version: {self.schema_version} (expected 1)"
            )

        if self.input_interface_ref is not None:
            if not isinstance(self.input_interface_ref, str) or not self.input_interface_ref:
                raise InvalidCapabilityDefinitionError("input_interface_ref must be a non-empty string or None")
            parse_canonical_urn(self.input_interface_ref)

        if self.output_interface_ref is not None:
            if not isinstance(self.output_interface_ref, str) or not self.output_interface_ref:
                raise InvalidCapabilityDefinitionError("output_interface_ref must be a non-empty string or None")
            parse_canonical_urn(self.output_interface_ref)

        required_prov_keys = {"author", "created_at", "license", "source_origin"}
        missing_prov = required_prov_keys - set(self.provenance.keys())
        if missing_prov:
            raise InvalidCapabilityDefinitionError(f"Missing mandatory provenance fields: {sorted(missing_prov)}")

        for pk in required_prov_keys:
            val = self.provenance[pk]
            if not isinstance(val, str) or not val:
                raise InvalidCapabilityDefinitionError(f"Provenance field '{pk}' must be a non-empty string")

        if self.content_integrity.get("digest_algorithm") != "sha256":
            raise InvalidCapabilityDefinitionError("content_integrity.digest_algorithm must be 'sha256'")

        return parsed_urn

    def to_dict(self) -> Dict[str, Any]:
        """Converts definition to a canonical dictionary representation."""
        return {
            "schema_version": self.schema_version,
            "capability_id": self.capability_id,
            "capability_type": self.capability_type,
            "display_name": self.display_name,
            "description": self.description,
            "input_interface_ref": self.input_interface_ref,
            "output_interface_ref": self.output_interface_ref,
            "provenance": {
                "author": self.provenance["author"],
                "created_at": self.provenance["created_at"],
                "license": self.provenance["license"],
                "source_origin": self.provenance["source_origin"]
            },
            "content_integrity": {
                "digest_algorithm": self.content_integrity.get("digest_algorithm", "sha256")
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityDefinition":
        """Reconstructs and validates CapabilityDefinition from a dictionary."""
        if not isinstance(data, dict):
            raise InvalidCapabilityDefinitionError(f"Expected dict for capability definition, got {type(data).__name__}")
            
        return cls(
            capability_id=data.get("capability_id", ""),
            display_name=data.get("display_name", ""),
            description=data.get("description", ""),
            capability_type=data.get("capability_type", ""),
            schema_version=data.get("schema_version", 1),
            input_interface_ref=data.get("input_interface_ref"),
            output_interface_ref=data.get("output_interface_ref"),
            provenance=data.get("provenance"),
            content_integrity=data.get("content_integrity")
        )

    def to_deterministic_json_bytes(self) -> bytes:
        """
        Produces bit-for-bit deterministic UTF-8 JSON bytes:
        - Keys sorted alphabetically.
        - Compact delimiters (',', ':') with zero extraneous whitespace.
        - ensure_ascii=True for strict 7-bit ASCII compatibility in string literals.
        """
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True
        ).encode("utf-8")

    def compute_sha256(self) -> str:
        """Computes the SHA-256 digest of the deterministically serialized bytes."""
        return hashlib.sha256(self.to_deterministic_json_bytes()).hexdigest()


# ----------------------------------------------------------------------------
# Canonical Example Harmless Capability (Declarative Only)
# ----------------------------------------------------------------------------

EVAL_ADD_CAPABILITY_DEF = CapabilityDefinition(
    capability_id="urn:lcs:tool:system.math:eval-add",
    display_name="Math Evaluator: Add",
    description="Declarative specification for deterministic integer addition.",
    capability_type="tool",
    schema_version=1,
    input_interface_ref="urn:lcs:interface:system.math:eval-add-input",
    output_interface_ref="urn:lcs:interface:system.math:eval-add-output",
    provenance={
        "author": "LCS Systems Architecture Team",
        "created_at": "2026-11-11T00:00:00Z",
        "license": "Apache-2.0",
        "source_origin": "lcs.builtin.math.eval_add"
    },
    content_integrity={
        "digest_algorithm": "sha256"
    }
)


# ----------------------------------------------------------------------------
# Registration & Ingestion Service
# ----------------------------------------------------------------------------

class RegistrationResult(NamedTuple):
    capability_id: str
    blob_digest: str
    byte_size: int
    durability_level: str
    is_duplicate: bool
    registered_at: str

class RetrievedCapability(NamedTuple):
    definition: CapabilityDefinition
    raw_bytes: bytes
    blob_digest: str
    stored_byte_length: int
    registered_at: str

class CapabilityRegistrationService:
    """
    Transactional service that coordinates canonical capability validation,
    deterministic serialization, physical CAS ingestion, and SQLite relational persistence.
    """
    def __init__(self, conn: sqlite3.Connection, cas_engine: SecureCASStorageEngine):
        self.conn = conn
        self.cas_engine = cas_engine
        self._ensure_foreign_keys()
        self.ensure_schema()

    def _ensure_foreign_keys(self) -> None:
        """
        Enforces that SQLite foreign keys are active on self.conn.
        Fails closed with SQLiteForeignKeyEnforcementError if foreign keys cannot be guaranteed.
        """
        if not isinstance(self.conn, sqlite3.Connection):
            raise SQLiteForeignKeyEnforcementError(
                f"Expected sqlite3.Connection, got {type(self.conn).__name__}"
            )

        cur = self.conn.cursor()
        cur.execute("PRAGMA foreign_keys;")
        row = cur.fetchone()
        current_state = row[0] if row else 0

        if current_state == 1:
            return

        # Foreign keys are currently OFF.
        # In SQLite, PRAGMA foreign_keys = ON is a silent no-op inside an active transaction.
        if getattr(self.conn, "in_transaction", False):
            raise SQLiteForeignKeyEnforcementError(
                "Cannot enable SQLite foreign-key enforcement during an active uncommitted transaction. "
                "In SQLite, 'PRAGMA foreign_keys = ON' is a no-op inside transactions."
            )

        try:
            self.conn.execute("PRAGMA foreign_keys = ON;")
        except Exception as e:
            raise SQLiteForeignKeyEnforcementError(
                f"Failed to execute 'PRAGMA foreign_keys = ON': {e}"
            ) from e

        cur.execute("PRAGMA foreign_keys;")
        row = cur.fetchone()
        new_state = row[0] if row else 0
        if new_state != 1:
            raise SQLiteForeignKeyEnforcementError(
                f"SQLite foreign-key enforcement failed: PRAGMA foreign_keys returned {new_state} (expected 1)"
            )

    def ensure_schema(self) -> None:
        """Ensures the relational capability association table exists."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS capability_declarations (
                capability_urn TEXT PRIMARY KEY,
                definition_blob_digest TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                display_name TEXT NOT NULL,
                capability_type TEXT NOT NULL CHECK (capability_type IN ('tool', 'skill', 'agent', 'interface')),
                registered_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (capability_urn) REFERENCES capabilities(capability_urn) ON DELETE RESTRICT,
                FOREIGN KEY (definition_blob_digest) REFERENCES content_chunk_blobs(blob_digest) ON DELETE RESTRICT
            );
        """)
        self.conn.commit()

    def renew_publication_lease(self, publication_id: str, extend_seconds: int = 60) -> bool:
        """
        Renews an active publication lease by updating heartbeat_at and extending lease_expires_at.
        Transitions lease_state to HEARTBEAT_ACTIVE.
        Returns True if successfully renewed, False if lease is expired, aborted, or conflicting.
        """
        cur = self.conn.cursor()
        cur.execute("""
            UPDATE active_cas_publications
            SET heartbeat_at = datetime('now'),
                lease_expires_at = datetime('now', ? || ' seconds'),
                lease_state = CASE WHEN lease_state = 'ACQUIRED' THEN 'HEARTBEAT_ACTIVE' ELSE lease_state END
            WHERE publication_id = ?
              AND lease_state IN ('ACQUIRED', 'HEARTBEAT_ACTIVE', 'PUBLISHED')
              AND datetime('now') <= lease_expires_at;
        """, (str(extend_seconds), publication_id))
        self.conn.commit()
        return cur.rowcount > 0

    def register_capability(
        self,
        definition: CapabilityDefinition,
        pub_id: Optional[str] = None,
        lease_seconds: int = 60
    ) -> RegistrationResult:
        """
        Executes the 9-step canonical registration and CAS ingestion workflow:
        1. Validate canonical capability ID & definition.
        2. Serialize deterministically.
        3. Compute SHA-256 digest.
        4. Check duplicate-registration status (idempotent vs conflict).
        5. Acquire active publication lease in active_cas_publications to prevent GC races.
        6. Ingest exact serialized bytes into CAS storage.
        7. Persist association in SQLite with full foreign-key integrity.
        8. Advance publication lease to COMMITTED.
        9. Return structured RegistrationResult.
        """
        definition.validate()
        urn = definition.capability_id

        payload_bytes = definition.to_deterministic_json_bytes()
        digest = hashlib.sha256(payload_bytes).hexdigest()
        byte_len = len(payload_bytes)

        # 1. Fast-path check: return duplicate if already registered with identical digest
        cur = self.conn.cursor()
        cur.execute("""
            SELECT definition_blob_digest, registered_at
            FROM capability_declarations
            WHERE capability_urn = ?;
        """, (urn,))
        row = cur.fetchone()
        if row:
            existing_digest, reg_time = row[0], row[1]
            if existing_digest == digest:
                return RegistrationResult(
                    capability_id=urn,
                    blob_digest=digest,
                    byte_size=byte_len,
                    durability_level="DEDUPLICATED",
                    is_duplicate=True,
                    registered_at=reg_time
                )
            else:
                raise CapabilityRegistrationConflictError(
                    f"Duplicate registration conflict: capability '{urn}' is already registered "
                    f"with digest '{existing_digest}', cannot overwrite with different digest '{digest}'."
                )

        # 2. Acquire an active publication lease in active_cas_publications.
        # This protects the blob from GC sweeps between staging/linkat and SQLite commit.
        actual_pub_id = pub_id if pub_id else f"cap_pub_{digest[:16]}_{uuid.uuid4().hex[:8]}"
        pub_token = f"tok_{uuid.uuid4().hex[:16]}"

        try:
            self.conn.execute("""
                INSERT INTO active_cas_publications (
                    publication_id, blob_digest, worker_id, lease_token, lease_state,
                    heartbeat_at, lease_expires_at
                ) VALUES (
                    ?, ?, 'worker_capability_reg', ?, 'ACQUIRED',
                    datetime('now'), datetime('now', ? || ' seconds')
                );
            """, (actual_pub_id, digest, pub_token, str(lease_seconds)))
            self.conn.commit()
        except sqlite3.IntegrityError as e:
            try:
                self.conn.rollback()
            except Exception:
                pass
            if "CAS_GC_CONFLICT" in str(e):
                raise CASPublicationConflictError(
                    f"Cannot register capability '{urn}': blob '{digest}' is currently reserved for GC deletion: {e}"
                ) from e
            raise

        try:
            # 3. Write to staging
            tmp_name, total_bytes, durability = self.cas_engine.write_payload_to_staging(
                actual_pub_id, pub_token, digest, payload_bytes
            )

            # Heartbeat check & renewal: verify lease is valid and active before publishing to CAS
            if not self.renew_publication_lease(actual_pub_id, extend_seconds=lease_seconds):
                raise CASPublicationConflictError(
                    f"Publication lease '{actual_pub_id}' expired or was lost before CAS publication phase."
                )

            # Atomically link staging file into CAS objects shard
            self.cas_engine.publish_staging_to_cas(tmp_name, digest)

            # 4. Immediate write transaction to persist records and commit lease
            self.conn.execute("BEGIN IMMEDIATE;")
            try:
                # Re-check under lock in case of concurrent registration race
                cur.execute("""
                    SELECT definition_blob_digest, registered_at
                    FROM capability_declarations
                    WHERE capability_urn = ?;
                """, (urn,))
                row = cur.fetchone()
                if row:
                    existing_digest, reg_time = row[0], row[1]
                    if existing_digest == digest:
                        self.conn.execute("""
                            UPDATE active_cas_publications
                            SET lease_state = 'COMMITTED'
                            WHERE publication_id = ?;
                        """, (actual_pub_id,))
                        self.conn.commit()
                        return RegistrationResult(
                            capability_id=urn,
                            blob_digest=digest,
                            byte_size=byte_len,
                            durability_level=durability,
                            is_duplicate=True,
                            registered_at=reg_time
                        )
                    else:
                        self.conn.rollback()
                        self.conn.execute("""
                            UPDATE active_cas_publications
                            SET lease_state = 'ABORTED'
                            WHERE publication_id = ?;
                        """, (actual_pub_id,))
                        raise CapabilityRegistrationConflictError(
                            f"Duplicate registration conflict: capability '{urn}' is already registered "
                            f"with digest '{existing_digest}', cannot overwrite with different digest '{digest}'."
                        )

                cur.execute("""
                    INSERT OR IGNORE INTO content_chunk_blobs (
                        blob_digest, byte_length, storage_compression, stored_byte_length
                    ) VALUES (?, ?, 'NONE', ?);
                """, (digest, byte_len, byte_len))

                cur.execute("""
                    INSERT INTO entity_urn_registry (
                        entity_urn, entity_kind, lifecycle_state
                    ) VALUES (?, 'CAPABILITY', 'PENDING');
                """, (urn,))

                cur.execute("""
                    INSERT INTO capabilities (
                        capability_urn, name, version, description
                    ) VALUES (?, ?, '1.0.0', ?);
                """, (urn, definition.display_name, definition.description))

                cur.execute("""
                    UPDATE entity_urn_registry
                    SET lifecycle_state = 'ACTIVE'
                    WHERE entity_urn = ?;
                """, (urn,))

                cur.execute("""
                    INSERT INTO capability_declarations (
                        capability_urn, definition_blob_digest, schema_version, display_name, capability_type
                    ) VALUES (?, ?, ?, ?, ?);
                """, (urn, digest, definition.schema_version, definition.display_name, definition.capability_type))

                cur.execute("SELECT registered_at FROM capability_declarations WHERE capability_urn = ?;", (urn,))
                reg_time = cur.fetchone()[0]

                # Verify publication lease is still active and unexpired before committing
                cur.execute("""
                    SELECT 1 FROM active_cas_publications
                    WHERE publication_id = ?
                      AND lease_state IN ('ACQUIRED', 'HEARTBEAT_ACTIVE', 'PUBLISHED')
                      AND datetime('now') <= lease_expires_at;
                """, (actual_pub_id,))
                if not cur.fetchone():
                    self.conn.rollback()
                    raise CASPublicationConflictError(
                        f"Publication lease '{actual_pub_id}' expired before database commit."
                    )

                self.conn.execute("""
                    UPDATE active_cas_publications
                    SET lease_state = 'COMMITTED'
                    WHERE publication_id = ?;
                """, (actual_pub_id,))

                self.conn.commit()

                return RegistrationResult(
                    capability_id=urn,
                    blob_digest=digest,
                    byte_size=byte_len,
                    durability_level=durability,
                    is_duplicate=False,
                    registered_at=reg_time
                )
            except Exception:
                self.conn.rollback()
                raise
        except Exception:
            try:
                self.conn.execute("""
                    UPDATE active_cas_publications
                    SET lease_state = 'ABORTED'
                    WHERE publication_id = ?;
                """, (actual_pub_id,))
                self.conn.commit()
            except Exception:
                pass
            raise

    def retrieve_capability(self, capability_id: str) -> RetrievedCapability:
        """
        Retrieves, verifies, and reconstructs a registered capability by its canonical URN:
        1. Validates canonical URN format.
        2. Looks up mapping in SQLite capability_declarations.
        3. Reads exact blob from CAS storage descriptor-relative with O_NOFOLLOW.
        4. Verifies retrieved content SHA-256 matches registered digest.
        5. Reconstructs CapabilityDefinition from JSON.
        6. Confirms byte-for-byte equality with original deterministic serialization.
        7. Returns RetrievedCapability.
        """
        parse_canonical_urn(capability_id)
        
        cur = self.conn.cursor()
        cur.execute("""
            SELECT definition_blob_digest, registered_at
            FROM capability_declarations
            WHERE capability_urn = ?;
        """, (capability_id,))
        row = cur.fetchone()
        
        if not row:
            raise CapabilityNotFoundError(f"Capability '{capability_id}' is not registered")
            
        expected_digest, registered_at = row[0], row[1]
        
        try:
            raw_bytes = self.cas_engine.read_blob(expected_digest)
        except CASBlobNotFoundError as e:
            raise CASBlobNotFoundError(
                f"Missing CAS content for capability '{capability_id}': blob '{expected_digest}' not found on disk"
            ) from e
        except CASDigestMismatchError as e:
            raise CapabilityCorruptionError(
                f"Corrupted CAS content for capability '{capability_id}': {e}"
            ) from e

        actual_digest = hashlib.sha256(raw_bytes).hexdigest()
        if actual_digest != expected_digest:
            raise CapabilityCorruptionError(
                f"Integrity digest mismatch for '{capability_id}': expected '{expected_digest}', got '{actual_digest}'"
            )

        try:
            data = json.loads(raw_bytes.decode("utf-8"))
        except Exception as e:
            raise CapabilityCorruptionError(
                f"Corrupted JSON payload in CAS blob '{expected_digest}' for capability '{capability_id}': {e}"
            ) from e

        reconstructed = CapabilityDefinition.from_dict(data)
        
        if reconstructed.capability_id != capability_id:
            raise CapabilityIntegrityMismatchError(
                f"Payload mismatch: CAS blob contains capability_id '{reconstructed.capability_id}', expected '{capability_id}'"
            )

        reserialized = reconstructed.to_deterministic_json_bytes()
        if reserialized != raw_bytes:
            raise CapabilityCorruptionError(
                f"Non-deterministic serialization mismatch for capability '{capability_id}': reconstructed bytes differ"
            )

        return RetrievedCapability(
            definition=reconstructed,
            raw_bytes=raw_bytes,
            blob_digest=expected_digest,
            stored_byte_length=len(raw_bytes),
            registered_at=registered_at
        )

    def is_registered(self, capability_id: str) -> bool:
        """Returns True if capability_id is registered and active."""
        try:
            parse_canonical_urn(capability_id)
        except InvalidCapabilityURNError:
            return False
        cur = self.conn.cursor()
        cur.execute("SELECT 1 FROM capability_declarations WHERE capability_urn = ?;", (capability_id,))
        return cur.fetchone() is not None
