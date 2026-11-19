"""
LCS Cache Subsystem
===================
Provides high-performance incremental caching, filesystem monitoring,
two-level delta invalidation, and recovery mechanisms for LCS capabilities.
"""

from .models import (
    ChangeKind,
    StatMetadata,
    CapabilitySummary,
    DeltaChange,
)

from .delta import DeltaEngine

from .watcher import (
    FilesystemWatcher,
    WatcherError,
)

from .cache import (
    LocalCapabilityCache,
    CacheCorruptionError,
)

__all__ = [
    "ChangeKind",
    "StatMetadata",
    "CapabilitySummary",
    "DeltaChange",
    "DeltaEngine",
    "FilesystemWatcher",
    "WatcherError",
    "LocalCapabilityCache",
    "CacheCorruptionError",
]
