"""
LCS Cache Models & Data Structures
==================================
Defines data structures for filesystem stat tracking, delta change events,
and capability summary projections used by the LCS high-performance caching layer.
"""

import os
import stat
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Set


class ChangeKind(str, Enum):
    """Classification of filesystem and capability state transitions."""
    ADDED = "ADDED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    RENAMED = "RENAMED"
    UNMODIFIED = "UNMODIFIED"


@dataclass(frozen=True)
class StatMetadata:
    """
    POSIX filesystem stat metadata used for Level 1 rapid candidate filtering.
    Notice: Metadata checks are heuristic pre-filters and NEVER establish content integrity.
    """
    path: str
    st_size: int
    st_mtime_ns: int
    st_ino: int
    st_dev: int
    is_dir: bool = False

    def matches(self, other: "StatMetadata") -> bool:
        """Compares essential stat attributes to detect physical file modifications."""
        if other is None:
            return False
        return (
            self.st_size == other.st_size
            and self.st_mtime_ns == other.st_mtime_ns
            and self.st_ino == other.st_ino
            and self.st_dev == other.st_dev
        )

    @classmethod
    def from_stat(cls, path: str, st: os.stat_result, is_dir: bool = False) -> "StatMetadata":
        return cls(
            path=os.path.abspath(path),
            st_size=st.st_size,
            st_mtime_ns=getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)),
            st_ino=st.st_ino,
            st_dev=st.st_dev,
            is_dir=is_dir or stat.S_ISDIR(st.st_mode)
        )

    @classmethod
    def from_path(cls, path: str) -> Optional["StatMetadata"]:
        try:
            # We use os.lstat or os.stat with follow_symlinks=False to observe symlinks directly
            st = os.stat(path, follow_symlinks=False)
            is_dir = stat.S_ISDIR(st.st_mode)
            return cls.from_stat(path, st, is_dir=is_dir)
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
            return None


@dataclass
class CapabilitySummary:
    """
    Lean in-memory projection of an indexed capability for sub-millisecond retrieval.
    Payload size is bounded to <= 100 tokens to prevent LLM context bloat.
    """
    urn: str
    name: str
    display_name: str
    description: str
    taxonomy_kind: str
    environment_origin: str
    source_path: str
    resolved_path: str
    raw_content_digest: str
    bundle_manifest_digest: Optional[str] = None
    is_bundle: bool = False
    bundle_root_path: Optional[str] = None
    precedence_tier: int = 20
    lifecycle_state: str = "AVAILABLE"
    dependencies: List[str] = field(default_factory=list)
    stat_meta: Optional[StatMetadata] = None
    last_verified_at: Optional[str] = None
    estimated_tokens: int = 0

    def __post_init__(self):
        if not self.estimated_tokens:
            self.estimated_tokens = self.calculate_estimated_tokens()

    def calculate_estimated_tokens(self) -> int:
        """
        Calculates conservative token estimate for candidate summary representation.
        Enforces a soft bound of <= 100 tokens per capability.
        """
        text = f"{self.urn} {self.display_name} {self.description} {self.taxonomy_kind} {self.environment_origin}"
        # Standard conservative heuristic: 1 token ~= 4 characters
        return max(1, len(text) // 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "urn": self.urn,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "taxonomy_kind": self.taxonomy_kind,
            "environment_origin": self.environment_origin,
            "source_path": self.source_path,
            "resolved_path": self.resolved_path,
            "raw_content_digest": self.raw_content_digest,
            "bundle_manifest_digest": self.bundle_manifest_digest,
            "is_bundle": self.is_bundle,
            "bundle_root_path": self.bundle_root_path,
            "precedence_tier": self.precedence_tier,
            "lifecycle_state": self.lifecycle_state,
            "dependencies": list(self.dependencies),
            "estimated_tokens": self.estimated_tokens,
            "last_verified_at": self.last_verified_at,
        }


@dataclass
class DeltaChange:
    """Represents a discrete filesystem or capability state transition."""
    kind: ChangeKind
    path: str
    old_path: Optional[str] = None
    urn: Optional[str] = None
    stat_meta: Optional[StatMetadata] = None
    content_digest: Optional[str] = None
    old_content_digest: Optional[str] = None
    is_bundle: bool = False
    bundle_root: Optional[str] = None
    affected_dependencies: List[str] = field(default_factory=list)
