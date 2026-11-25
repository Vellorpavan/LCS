"""
Call Me Synchronization Package (Priority 7)
"""

from .contract import ProjectContractManager, ConcurrentContractConflictError

__all__ = ["ProjectContractManager", "ConcurrentContractConflictError"]
