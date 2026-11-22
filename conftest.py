"""
Pytest configuration for LCS repository.
Installs cross-platform compatibility shims before tests are collected.
"""

import sys
import os

repo_root = os.path.abspath(os.path.dirname(__file__))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

cur_pp = os.environ.get("PYTHONPATH", "")
if repo_root not in cur_pp:
    os.environ["PYTHONPATH"] = f"{repo_root}{os.pathsep}{cur_pp}" if cur_pp else repo_root

if sys.platform == "win32":
    from lcs.locking import install_windows_fcntl_shim
    install_windows_fcntl_shim()

