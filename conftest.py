"""
Pytest configuration for LCS repository.
Installs cross-platform compatibility shims before tests are collected.
"""

import sys

if sys.platform == "win32":
    from lcs.locking import install_windows_fcntl_shim
    install_windows_fcntl_shim()
