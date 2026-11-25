#!/usr/bin/env bash
# ==============================================================================
# Call Me — Safe Uninstaller (macOS & Linux)
# Removes Call Me binaries, venv, and host slash-command integrations.
# Preserves user data and databases unless --purge is explicitly specified.
# ==============================================================================

set -euo pipefail

INSTALL_DIR="${CALL_ME_HOME:-$HOME/.call-me}"
VENV_DIR="$INSTALL_DIR/venv"
BIN_DIR="${CALL_ME_BIN_DIR:-$HOME/.local/bin}"

PURGE_DATA=false
if [ "${1:-}" = "--purge" ] || [ "${1:-}" = "-f" ]; then
    PURGE_DATA=true
fi

echo "========================================================================"
echo " CALL ME — UNINSTALLATION"
echo "========================================================================"

# 1. Remove host integrations using Call Me CLI if available
if [ -x "$BIN_DIR/call-me" ]; then
    echo "[+] Removing AI host command integrations..."
    "$BIN_DIR/call-me" uninstall-command --global || true
elif [ -x "$VENV_DIR/bin/call-me" ]; then
    "$VENV_DIR/bin/call-me" uninstall-command --global || true
fi

# 2. Remove binary wrappers
echo "[+] Removing launcher scripts from $BIN_DIR..."
rm -f "$BIN_DIR/call-me"
rm -f "$BIN_DIR/lcs"

# 3. Remove isolated virtual environment
if [ -d "$VENV_DIR" ]; then
    echo "[+] Removing isolated virtual environment at $VENV_DIR..."
    rm -rf "$VENV_DIR"
fi

# 4. Handle user data
if [ "$PURGE_DATA" = true ]; then
    echo "[+] Purging user data and databases at $INSTALL_DIR and ~/.lcs..."
    rm -rf "$INSTALL_DIR"
    rm -rf "$HOME/.lcs"
    echo "    Data purged completely."
else
    echo "[i] User state and databases at ~/.lcs were preserved."
    echo "    To delete all data and databases, run: ./uninstall.sh --purge"
fi

echo "========================================================================"
echo " Call Me has been successfully uninstalled."
echo "========================================================================"
