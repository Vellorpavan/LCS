"""
LCS Configuration & Path Management
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class LCSConfig:
    root_dir: str
    db_path: str
    cas_root: str
    key_store_dir: str
    schema_dir: str

    @classmethod
    def resolve(cls, root_override: Optional[str] = None, schema_override: Optional[str] = None) -> "LCSConfig":
        """
        Resolves LCS paths. Priority:
          1. root_override parameter
          2. LCS_ROOT environment variable
          3. .lcs in current working directory if exists
          4. ~/.lcs
        """
        if root_override:
            root = os.path.realpath(root_override)
        elif os.environ.get("LCS_ROOT"):
            root = os.path.realpath(os.environ["LCS_ROOT"])
        elif os.path.exists(os.path.join(os.getcwd(), ".lcs")):
            root = os.path.realpath(os.path.join(os.getcwd(), ".lcs"))
        else:
            # Default to local .lcs in current working directory for localized project isolation
            root = os.path.realpath(os.path.join(os.getcwd(), ".lcs"))

        if schema_override:
            s_dir = os.path.realpath(schema_override)
        else:
            # Point to canonical LCS project directory containing .sql migrations
            pkg_dir = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
            parent_dir = os.path.dirname(pkg_dir)
            if os.path.exists(os.path.join(parent_dir, "lcs_schema_v2b.sql")):
                s_dir = parent_dir
            elif os.path.exists(os.path.join(pkg_dir, "schemas", "lcs_schema_v2b.sql")):
                s_dir = os.path.join(pkg_dir, "schemas")
            else:
                s_dir = pkg_dir

        return cls(
            root_dir=root,
            db_path=os.path.join(root, "lcs.db"),
            cas_root=os.path.join(root, "cas"),
            key_store_dir=os.path.join(root, "keys"),
            schema_dir=s_dir
        )

    def ensure_directories(self) -> None:
        """Creates root, cas, and keys directories with secure permissions."""
        os.makedirs(self.root_dir, mode=0o700, exist_ok=True)
        os.makedirs(self.cas_root, mode=0o700, exist_ok=True)
        os.makedirs(self.key_store_dir, mode=0o700, exist_ok=True)
