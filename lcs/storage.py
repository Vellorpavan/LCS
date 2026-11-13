"""
LCS Storage Engine Package Wrapper
"""

import os
import sys

# Ensure root LCS directory is importable
_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    PersistentReceiptKeyStore,
    CASError,
    CASSecurityViolationError,
    CASDigestMismatchError,
    CASPublicationConflictError,
    CASDeletionError,
    CASBlobNotFoundError,
    CASInterruptionError,
    CASStagingCleanupError,
    CASDurabilityError,
    CASValidationError
)

__all__ = [
    "SecureCASStorageEngine",
    "PersistentReceiptKeyStore",
    "CASError",
    "CASSecurityViolationError",
    "CASDigestMismatchError",
    "CASPublicationConflictError",
    "CASDeletionError",
    "CASBlobNotFoundError",
    "CASInterruptionError",
    "CASStagingCleanupError",
    "CASDurabilityError",
    "CASValidationError",
]
