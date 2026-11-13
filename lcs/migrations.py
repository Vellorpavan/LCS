"""
LCS Database Migrations Package Wrapper
"""

import os
import sys

_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from migration_manager import (
    MigrationManager,
    MigrationError,
    MIGRATIONS_REGISTRY
)

__all__ = [
    "MigrationManager",
    "MigrationError",
    "MIGRATIONS_REGISTRY",
]

