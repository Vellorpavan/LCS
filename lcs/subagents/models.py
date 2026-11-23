"""
LCS Subagent Coordination Models (Phase 2B)
===========================================
Defines parent-child task representations, state models, and execution results
for governed subagent delegation.
"""

from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class SubagentTaskState(str, Enum):
    """Lifecycle states for delegated child agent tasks."""
    QUEUED    = "QUEUED"
    RUNNING   = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"
    CANCELLED = "CANCELLED"
    TIMEOUT   = "TIMEOUT"


@dataclass
class SubagentTask:
    """Structured child task request for subagent delegation."""
    parent_request_id: str
    child_task_id: str
    role: str
    objective: str
    inputs: Dict[str, Any] = field(default_factory=dict)
    constraints: List[str] = field(default_factory=list)
    expected_deliverables: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parent_request_id": self.parent_request_id,
            "child_task_id": self.child_task_id,
            "role": self.role,
            "objective": self.objective,
            "inputs": dict(self.inputs),
            "constraints": list(self.constraints),
            "expected_deliverables": list(self.expected_deliverables),
            "timeout_seconds": self.timeout_seconds,
            "created_at": self.created_at
        }


@dataclass
class SubagentExecutionResult:
    """Verifiable execution result returned by a delegated subagent."""
    child_task_id: str
    parent_request_id: str
    state: SubagentTaskState
    deliverables: Dict[str, Any] = field(default_factory=dict)
    stdout_summary: str = ""
    duration_ms: float = 0.0
    provenance: Dict[str, Any] = field(default_factory=dict)
    is_verified: bool = False
    error_details: Optional[str] = None
    completed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "child_task_id": self.child_task_id,
            "parent_request_id": self.parent_request_id,
            "state": self.state.value,
            "deliverables": dict(self.deliverables),
            "stdout_summary": self.stdout_summary,
            "duration_ms": self.duration_ms,
            "is_verified": self.is_verified,
            "error_details": self.error_details,
            "completed_at": self.completed_at,
            "provenance": dict(self.provenance)
        }
