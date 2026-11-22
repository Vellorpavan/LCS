"""
LCS Configuration & Path Management
"""

import os
import sys
from dataclasses import dataclass
from typing import Optional


@dataclass
class LCSConfig:
    root_dir: str
    db_path: str
    cas_root: str
    key_store_dir: str
    schema_dir: str
    user_state_dir: Optional[str] = None

    @classmethod
    def get_user_state_dir(cls, home_override: Optional[str] = None) -> str:
        """
        Returns the persistent user-level LCS state directory across platforms.
        Precedence:
          1. LCS_USER_STATE_DIR environment variable (explicit directory path)
          2. home_override/.lcs (if provided)
          3. LCS_USER_HOME/.lcs environment variable
          4. Windows: %APPDATA%/lcs or ~/.lcs
          5. Unix/macOS: ~/.lcs
        """
        if os.environ.get("LCS_USER_STATE_DIR"):
            return os.path.realpath(os.environ["LCS_USER_STATE_DIR"])
        if home_override:
            return os.path.realpath(os.path.join(home_override, ".lcs"))
        if os.environ.get("LCS_USER_HOME"):
            return os.path.realpath(os.path.join(os.environ["LCS_USER_HOME"], ".lcs"))

        if sys.platform == "win32":
            app_data = os.environ.get("APPDATA")
            if app_data:
                return os.path.realpath(os.path.join(app_data, "lcs"))
            return os.path.realpath(os.path.expanduser("~/.lcs"))

        return os.path.realpath(os.path.expanduser("~/.lcs"))

    @property
    def is_user_global(self) -> bool:
        """True if this configuration points to the persistent user-level directory."""
        expected = os.path.realpath(self.user_state_dir or self.get_user_state_dir())
        return os.path.realpath(self.root_dir) == expected

    @property
    def is_project_local(self) -> bool:
        """True if this configuration is project-local."""
        return not self.is_user_global

    @classmethod
    def resolve(
        cls,
        root_override: Optional[str] = None,
        schema_override: Optional[str] = None,
        is_global: bool = False,
        home_override: Optional[str] = None,
        workspace_root: Optional[str] = None,
    ) -> "LCSConfig":
        """
        Resolves LCS paths. Priority:
          1. root_override parameter
          2. is_global=True -> persistent user state directory
          3. LCS_ROOT environment variable
          4. .lcs in workspace_root / current working directory if exists (project-local isolation)
          5. Persistent user state directory if initialized (contains lcs.db)
          6. Default to local .lcs in current working directory
        """
        user_state_dir = cls.get_user_state_dir(home_override=home_override)
        ws = workspace_root or os.getcwd()
        local_candidate = os.path.join(ws, ".lcs")

        if root_override:
            root = os.path.realpath(root_override)
        elif is_global:
            root = user_state_dir
        elif os.environ.get("LCS_ROOT"):
            root = os.path.realpath(os.environ["LCS_ROOT"])
        elif os.path.exists(local_candidate):
            root = os.path.realpath(local_candidate)
        elif os.path.exists(os.path.join(user_state_dir, "lcs.db")):
            root = user_state_dir
        else:
            # Default to local .lcs in current working directory for localized project isolation
            root = os.path.realpath(local_candidate)

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
            schema_dir=s_dir,
            user_state_dir=user_state_dir,
        )

    def ensure_directories(self) -> None:
        """Creates root, cas, and keys directories with secure permissions."""
        os.makedirs(self.root_dir, mode=0o700, exist_ok=True)
        os.makedirs(self.cas_root, mode=0o700, exist_ok=True)
        os.makedirs(self.key_store_dir, mode=0o700, exist_ok=True)
