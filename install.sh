#!/usr/bin/env bash
# ==============================================================================
# Call Me — Universal Multi-Agent Capability Orchestrator Installer
# Supported platforms: macOS (Apple Silicon / Intel) & Linux (x86_64, aarch64)
# ==============================================================================

set -euo pipefail

CALL_ME_VERSION="3.2.0rc4"
INSTALL_DIR="${CALL_ME_HOME:-$HOME/.call-me}"
VENV_DIR="$INSTALL_DIR/venv"
BIN_DIR="${CALL_ME_BIN_DIR:-$HOME/.local/bin}"

# Terminal color output helpers
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    BOLD=''
    NC=''
fi

echo -e "${BLUE}========================================================================${NC}"
echo -e "${BOLD} CALL ME — MULTI-AGENT CAPABILITY ORCHESTRATOR INSTALLER v${CALL_ME_VERSION}${NC}"
echo -e "${BLUE}========================================================================${NC}"

# 1. Platform Detection
OS_TYPE="$(uname -s)"
ARCH_TYPE="$(uname -m)"

case "$OS_TYPE" in
    Darwin)
        PLATFORM="macOS"
        ;;
    Linux)
        PLATFORM="Linux"
        ;;
    *)
        echo -e "${RED}[ERROR] Unsupported operating system: $OS_TYPE${NC}"
        echo -e "For Windows, run: powershell -ExecutionPolicy Bypass -File install.ps1"
        exit 1
        ;;
esac

echo -e "[+] Detected Platform: ${BOLD}$PLATFORM ($ARCH_TYPE)${NC}"

# 2. Python Detection (Requirement: >= 3.10)
PYTHON_CANDIDATES=("python3.14" "python3.13" "python3.12" "python3.11" "python3.10" "python3")
PYTHON_BIN=""

for cand in "${PYTHON_CANDIDATES[@]}"; do
    if command -v "$cand" >/dev/null 2>&1; then
        VER_STR="$("$cand" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
        if [ -n "$VER_STR" ]; then
            MAJOR="$(echo "$VER_STR" | cut -d. -f1)"
            MINOR="$(echo "$VER_STR" | cut -d. -f2)"
            if [ "$MAJOR" -eq 3 ] && [ "$MINOR" -ge 10 ]; then
                PYTHON_BIN="$(command -v "$cand")"
                echo -e "[+] Found compatible Python: ${BOLD}$PYTHON_BIN (v$VER_STR)${NC}"
                break
            fi
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[ERROR] Python 3.10 or higher is required but was not found on PATH.${NC}"
    echo -e "\nRemediation:"
    if [ "$PLATFORM" = "macOS" ]; then
        echo -e "  macOS (Homebrew): brew install python3"
    elif [ "$PLATFORM" = "Linux" ]; then
        echo -e "  Ubuntu/Debian:    sudo apt update && sudo apt install -y python3 python3-venv python3-pip"
        echo -e "  Fedora/RHEL:      sudo dnf install -y python3 python3-pip"
        echo -e "  Arch Linux:       sudo pacman -S python python-pip"
    fi
    exit 1
fi

# Verify venv module availability
if ! "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; then
    echo -e "${RED}[ERROR] Python 'venv' module is missing.${NC}"
    if [ "$PLATFORM" = "Linux" ]; then
        echo -e "  Install venv: sudo apt install -y python3-venv"
    fi
    exit 1
fi

# 3. Isolated Environment Setup
echo -e "[+] Preparing isolated environment at: ${BOLD}$VENV_DIR${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"

if [ -d "$VENV_DIR" ]; then
    echo -e "    Updating existing isolated environment..."
else
    "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# Upgrade pip quietly
"$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip

# 4. Package Installation
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/pyproject.toml" ]; then
    echo -e "[+] Installing Call Me from local repository: ${BOLD}$SCRIPT_DIR${NC}"
    "$VENV_DIR/bin/pip" install --quiet "$SCRIPT_DIR"
else
    echo -e "[+] Installing Call Me from package..."
    "$VENV_DIR/bin/pip" install --quiet lcs-core
fi

# 5. Expose Executables on PATH
echo -e "[+] Exposing executables in: ${BOLD}$BIN_DIR${NC}"

# Create wrapper script for call-me
cat <<EOF > "$BIN_DIR/call-me"
#!/usr/bin/env sh
exec "$VENV_DIR/bin/call-me" "\$@"
EOF
chmod +x "$BIN_DIR/call-me"

# Create wrapper script for lcs
cat <<EOF > "$BIN_DIR/lcs"
#!/usr/bin/env sh
exec "$VENV_DIR/bin/lcs" "\$@"
EOF
chmod +x "$BIN_DIR/lcs"

echo -e "    Created ${BOLD}$BIN_DIR/call-me${NC}"
echo -e "    Created ${BOLD}$BIN_DIR/lcs${NC}"

# 6. Automatic Host Integration & Health Diagnostics
echo -e "\n[+] Configuring AI host integrations..."
"$BIN_DIR/call-me" setup --repair

# 7. PATH Verification & Guidance
case ":$PATH:" in
    *":$BIN_DIR:"*)
        PATH_CONFIGURED=true
        ;;
    *)
        PATH_CONFIGURED=false
        ;;
esac

echo -e "\n${GREEN}========================================================================${NC}"
echo -e "${BOLD}${GREEN} CALL ME v${CALL_ME_VERSION} INSTALLED SUCCESSFULLY!${NC}"
echo -e "${GREEN}========================================================================${NC}"

if [ "$PATH_CONFIGURED" = false ]; then
    echo -e "${YELLOW}[NOTICE] '$BIN_DIR' is not currently in your PATH.${NC}"
    echo -e "To make 'call-me' available in all terminal sessions, add it to your shell profile:\n"
    if [ -n "${ZSH_VERSION:-}" ] || [ -f "$HOME/.zshrc" ]; then
        echo -e "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc"
        echo -e "  source ~/.zshrc"
    else
        echo -e "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo -e "  source ~/.bashrc"
    fi
    echo ""
fi

echo -e "Quick Start:"
echo -e "  In your AI host:     Type ${BOLD}/call-me <any objective>${NC}"
echo -e "  From your terminal:  Type ${BOLD}call-me \"<objective>\"${NC}"
echo -e "  Diagnostics:         Type ${BOLD}call-me setup --doctor${NC}"
echo -e "  Uninstall:           Run ${BOLD}./uninstall.sh${NC}\n"
