"""
LCS Task Request Contract & Data Models (Phase 2A)
==================================================
Defines the versioned, structured request and response contracts for the
/call-me entry point. Governed by RFC 8785 JSON Canonicalization Scheme (JCS).

Invariants:
- The original user instruction is preserved exactly bit-for-bit.
- Normalization must not silently alter user intent.
- Zero secrets in logs or serialization.
"""

import os
import uuid
import json
from enum import Enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# RFC 8785 JSON Canonicalization Scheme serializer
from governance_policy_v1 import canonicalize_jcs


class ConsentState(str, Enum):
    """Tracks authorization and consent status of the user's invocation."""
    EXPLICIT_INVOCATION = "EXPLICIT_INVOCATION"
    CONSENT_GRANTED = "CONSENT_GRANTED"
    CONSENT_PENDING = "CONSENT_PENDING"
    CONSENT_REJECTED = "CONSENT_REJECTED"


@dataclass
class TaskRequest:
    """
    Versioned structured request produced when a user invokes /call-me.
    Schema Version: lcs.task.request.v1
    """
    request_id: str
    session_id: str
    original_instruction: str
    normalized_task_description: str
    schema_version: str = "lcs.task.request.v1"
    inputs_and_references: Dict[str, Any] = field(default_factory=dict)
    constraints: List[str] = field(default_factory=list)
    expected_deliverables: List[str] = field(default_factory=list)
    invocation_environment: str = "GENERIC_POSIX"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    consent_and_authorization_state: ConsentState = ConsentState.EXPLICIT_INVOCATION
    provenance: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        raw_instruction: str,
        environment: str = "GENERIC_POSIX",
        session_id: Optional[str] = None,
        inputs: Optional[Dict[str, Any]] = None,
        constraints: Optional[List[str]] = None,
        deliverables: Optional[List[str]] = None
    ) -> "TaskRequest":
        """
        Constructs a validated TaskRequest preserving original instruction bytes.
        """
        if not raw_instruction or not raw_instruction.strip():
            raise ValueError("Task instruction cannot be empty.")

        req_id = f"req-{uuid.uuid4().hex[:12]}"
        sess_id = session_id or f"sess-{uuid.uuid4().hex[:12]}"

        # Normalization: strip leading/trailing whitespace without changing semantics
        normalized = raw_instruction.strip()

        return cls(
            request_id=req_id,
            session_id=sess_id,
            original_instruction=raw_instruction,
            normalized_task_description=normalized,
            inputs_and_references=inputs or {},
            constraints=constraints or [],
            expected_deliverables=deliverables or [],
            invocation_environment=environment,
            created_at=datetime.now(timezone.utc).isoformat(),
            consent_and_authorization_state=ConsentState.EXPLICIT_INVOCATION,
            provenance={
                "client": "lcs-call-me",
                "env": environment,
                "pid": os.getpid()
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "original_instruction": self.original_instruction,
            "normalized_task_description": self.normalized_task_description,
            "inputs_and_references": dict(self.inputs_and_references),
            "constraints": list(self.constraints),
            "expected_deliverables": list(self.expected_deliverables),
            "invocation_environment": self.invocation_environment,
            "created_at": self.created_at,
            "consent_and_authorization_state": self.consent_and_authorization_state.value if isinstance(self.consent_and_authorization_state, ConsentState) else str(self.consent_and_authorization_state),
            "provenance": dict(self.provenance)
        }

    def to_canonical_json(self) -> str:
        """Serializes request using RFC 8785 JSON Canonicalization Scheme."""
        res = canonicalize_jcs(self.to_dict())
        return res.decode("utf-8") if isinstance(res, bytes) else res

    def to_canonical_bytes(self) -> bytes:
        """Serializes request using RFC 8785 JSON Canonicalization Scheme as bytes."""
        res = canonicalize_jcs(self.to_dict())
        return res if isinstance(res, bytes) else res.encode("utf-8")

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskRequest":
        consent_val = data.get("consent_and_authorization_state", ConsentState.EXPLICIT_INVOCATION)
        if isinstance(consent_val, str):
            try:
                consent_val = ConsentState(consent_val)
            except ValueError:
                consent_val = ConsentState.EXPLICIT_INVOCATION

        return cls(
            schema_version=data.get("schema_version", "lcs.task.request.v1"),
            request_id=data["request_id"],
            session_id=data.get("session_id", f"sess-{uuid.uuid4().hex[:12]}"),
            original_instruction=data["original_instruction"],
            normalized_task_description=data.get("normalized_task_description", data["original_instruction"]),
            inputs_and_references=data.get("inputs_and_references", {}),
            constraints=data.get("constraints", []),
            expected_deliverables=data.get("expected_deliverables", []),
            invocation_environment=data.get("invocation_environment", "GENERIC_POSIX"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            consent_and_authorization_state=consent_val,
            provenance=data.get("provenance", {})
        )


@dataclass
class InvocationResponse:
    """
    Standard response returned immediately to the user upon /call-me invocation.
    Contains session tracking identifiers and candidate capability matches.
    """
    request_id: str
    session_id: str
    status: str  # "ACCEPTED", "REJECTED", "ERROR"
    message: str
    candidate_count: int = 0
    candidate_urns: List[str] = field(default_factory=list)
    governance_status: str = "PENDING_APPROVAL"
    error_details: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
