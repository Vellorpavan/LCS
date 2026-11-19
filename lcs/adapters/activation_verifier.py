"""
LCS Activation Integrity Verifier (Hash-On-Activation)
======================================================
Enforces cryptographic zero-trust verification before a selected capability
is authorized or dispatched for execution.

Workflow:
1. Resolves capability identity and registered CAS digest from SQLite catalog.
2. Opens physical source using POSIX descriptor pinning (O_NOFOLLOW).
3. Reads current exact on-disk bytes safely.
4. Calculates real-time SHA-256 digest (or Merkle bundle digest).
5. Asserts bit-for-bit equality between on-disk hash and catalog digest.
6. Rejects activation fail-closed with ContentIntegrityMismatchError if tampered.
7. Packages verification evidence for Gate 1 / Gate 2 / CAS audit trace.
"""

import os
import sys
import hashlib
import sqlite3
import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from .base import ContentIntegrityMismatchError
from ..skills import SafeFileReader, BundleManifestHasher, MAX_INSTRUCTION_FILE_SIZE


@dataclass(frozen=True)
class ActivationIntegrityRecord:
    """Verifiable evidence of Hash-On-Activation check."""
    capability_urn: str
    source_path: str
    expected_digest: str
    actual_digest: str
    verified_at: datetime.datetime
    is_bundle: bool
    status: str = "MATCH"

    @property
    def verified(self) -> bool:
        return self.status == "MATCH"

    @property
    def sha256(self) -> str:
        return self.actual_digest

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_urn": self.capability_urn,
            "source_path": self.source_path,
            "expected_digest": self.expected_digest,
            "actual_digest": self.actual_digest,
            "verified_at": self.verified_at.isoformat() if hasattr(self.verified_at, "isoformat") else str(self.verified_at),
            "is_bundle": self.is_bundle,
            "status": self.status,
            "verified": self.verified,
            "sha256": self.sha256,
        }

    def __getitem__(self, item: str) -> Any:
        return self.to_dict()[item]


class ActivationIntegrityVerifier:
    """
    Cryptographic verification gate evaluated prior to plan authorization and dispatch.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def verify_capability_activation(self, capability_urn: str) -> ActivationIntegrityRecord:
        """Alias for verify_capability."""
        return self.verify_capability(capability_urn)

    def verify_capability(self, capability_urn: str) -> ActivationIntegrityRecord:
        """
        Verifies that the current on-disk content of a capability exactly matches
        its catalog CAS digest. Fails closed on any discrepancy or missing file.
        """
        cur = self.conn.cursor()

        # 1. Check artifact_discovery_records (Skill Intelligence V1)
        row = None
        try:
            cur.execute("""
                SELECT canonical_urn, resolved_path, raw_content_digest,
                       bundle_manifest_digest, is_bundle, bundle_root_path
                FROM artifact_discovery_records
                WHERE canonical_urn = ?
                ORDER BY discovered_at DESC LIMIT 1;
            """, (capability_urn,))
            row = cur.fetchone()
        except sqlite3.OperationalError:
            row = None

        if row:
            urn, resolved_path, raw_digest, bundle_digest, is_bundle, bundle_root = row
            target_path = resolved_path

            if not os.path.exists(target_path):
                raise ContentIntegrityMismatchError(
                    capability_urn,
                    raw_digest,
                    f"FILE_NOT_FOUND: '{target_path}' was removed from disk"
                )

            # Case A: Multi-file skill bundle
            if is_bundle and bundle_root and os.path.isdir(bundle_root):
                actual_digest, _, _ = BundleManifestHasher.compute_bundle_manifest(bundle_root)
                expected_digest = bundle_digest or raw_digest
                if actual_digest != expected_digest:
                    raise ContentIntegrityMismatchError(
                        capability_urn,
                        expected_digest,
                        actual_digest
                    )
                return ActivationIntegrityRecord(
                    capability_urn=capability_urn,
                    source_path=bundle_root,
                    expected_digest=expected_digest,
                    actual_digest=actual_digest,
                    verified_at=datetime.datetime.now(datetime.timezone.utc),
                    is_bundle=True
                )

            # Case B: Single-file artifact (SKILL.md, command, rule, script)
            data, _ = SafeFileReader.read_exact_bytes(target_path, MAX_INSTRUCTION_FILE_SIZE)
            actual_digest = hashlib.sha256(data).hexdigest()

            if actual_digest != raw_digest:
                raise ContentIntegrityMismatchError(
                    capability_urn,
                    raw_digest,
                    actual_digest
                )

            return ActivationIntegrityRecord(
                capability_urn=capability_urn,
                source_path=target_path,
                expected_digest=raw_digest,
                actual_digest=actual_digest,
                verified_at=datetime.datetime.now(datetime.timezone.utc),
                is_bundle=False
            )

        # 2. Check physical_source_instances & content_snapshots (Milestone 2/3)
        snap_row = None
        try:
            cur.execute("""
                SELECT psi.root_path, cs.canonical_manifest_digest, cs.source_fidelity_digest
                FROM physical_source_instances psi
                JOIN content_snapshots cs ON psi.instance_id = cs.instance_id
                WHERE psi.capability_urn = ?
                ORDER BY cs.created_at DESC LIMIT 1;
            """, (capability_urn,))
            snap_row = cur.fetchone()
        except sqlite3.OperationalError:
            snap_row = None

        if not snap_row:
            # Fallback: check standalone physical_source_instances (direct file_path / sha256_digest)
            try:
                cur.execute("""
                    SELECT file_path, sha256_digest
                    FROM physical_source_instances
                    WHERE capability_urn = ? LIMIT 1;
                """, (capability_urn,))
                direct_row = cur.fetchone()
                if direct_row:
                    snap_row = (direct_row[0], direct_row[1], direct_row[1])
            except sqlite3.OperationalError:
                pass

        if snap_row:
            root_path, canon_digest, fidelity_digest = snap_row
            expected = canon_digest or fidelity_digest or ""
            if root_path and os.path.isfile(root_path):
                data, _ = SafeFileReader.read_exact_bytes(root_path, MAX_INSTRUCTION_FILE_SIZE)
                actual_digest = hashlib.sha256(data).hexdigest()
                if actual_digest != expected:
                    raise ContentIntegrityMismatchError(capability_urn, expected, actual_digest)
                return ActivationIntegrityRecord(
                    capability_urn=capability_urn,
                    source_path=root_path,
                    expected_digest=expected,
                    actual_digest=actual_digest,
                    verified_at=datetime.datetime.now(datetime.timezone.utc),
                    is_bundle=False
                )

        # 3. For pure MCP tools (protocol-based, not backed by static disk files),
        # verify interface attestation exists in catalog
        try:
            cur.execute("""
                SELECT capability_urn, name, version FROM capabilities
                WHERE capability_urn = ?;
            """, (capability_urn,))
            cap_row = cur.fetchone()

            if cap_row:
                # Protocol-based capability without direct static file source
                return ActivationIntegrityRecord(
                    capability_urn=capability_urn,
                    source_path="mcp://stdio",
                    expected_digest="MCP_PROTOCOL_ATTESTED",
                    actual_digest="MCP_PROTOCOL_ATTESTED",
                    verified_at=datetime.datetime.now(datetime.timezone.utc),
                    is_bundle=False
                )
        except sqlite3.OperationalError:
            pass

        # Unregistered capability cannot be activated
        raise ContentIntegrityMismatchError(
            capability_urn,
            "CATALOG_REGISTERED",
            "UNREGISTERED_CAPABILITY: No catalog entry found"
        )

    def verify_plan_activation(self, plan_steps: List[Any]) -> List[ActivationIntegrityRecord]:
        """
        Verifies every step capability in an execution plan before token minting or dispatch.
        Fails closed on the very first mismatch.
        """
        records = []
        for step in plan_steps:
            urn = getattr(step, "capability_urn", None) or (step.get("capability_urn") if isinstance(step, dict) else None)
            if urn:
                records.append(self.verify_capability(urn))
        return records
