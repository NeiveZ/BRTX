#!/usr/bin/env bash
# BRTX - Brute Force & Credential Tester
# Author: NeiveZ | github.com/NeiveZ/BRTX

set -euo pipefail

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

ok()   { echo -e "  ${GREEN}[+]${RESET} $*"; }
err()  { echo -e "  ${RED}[-]${RESET} $*"; }
info() { echo -e "  ${CYAN}[*]${RESET} $*"; }
warn() { echo -e "  ${YELLOW}[!]${RESET} $*"; }

check_python() {
    command -v "$PYTHON" &>/dev/null || { err "Python 3 not found."; exit 1; }
    PY_VER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    "$PYTHON" -c "import sys; exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null \
        && ok "Python $PY_VER detected" \
        || warn "Python $PY_VER — BRTX recommends Python 3.10+"
}

install_deps() {
    info "Installing optional dependencies..."
    "$PYTHON" -m pip install paramiko --quiet --break-system-packages 2>/dev/null \
        && ok "paramiko installed (SSH module)" \
        || warn "Could not install paramiko — SSH module will not work"
}

check_system_deps() {
    info "Checking system tools..."
    command -v smbclient &>/dev/null \
        && ok "smbclient found (SMB module)" \
        || warn "smbclient not found — SMB module will not work (apt install smbclient)"
}

create_dirs() {
    mkdir -p "$SCRIPT_DIR/reports" "$SCRIPT_DIR/wordlists"
    ok "Directory structure verified"
}

run_tool() {
    cd "$SCRIPT_DIR"
    exec "$PYTHON" brtx.py "$@"
}

case "${1:-}" in
    --install|-i)
        echo -e "\n${BOLD}${RED}BRTX Installer${RESET}\n"
        check_python
        install_deps
        check_system_deps
        create_dirs
        chmod +x "$SCRIPT_DIR/brtx.py" 2>/dev/null || true
        echo
        ok "Installation complete."
        info "Run with: ${CYAN}./brtx.sh${RESET}"
        echo
        ;;
    --check)
        check_python
        check_system_deps
        ;;
    --help|-h)
        echo -e """
${BOLD}${RED}BRTX${RESET} — Brute Force & Credential Tester

${BOLD}Usage:${RESET}
  ./brtx.sh            Launch interactive shell
  ./brtx.sh --install  Install dependencies
  ./brtx.sh --check    Check system dependencies
  ./brtx.sh --help     Show this help

${BOLD}Modules:${RESET}
  brute/http   HTTP login form brute force
  brute/ssh    SSH brute force (requires paramiko)
  brute/ftp    FTP brute force
  brute/smb    SMB brute force (requires smbclient)
"""
        ;;
    *)
        check_python
        create_dirs
        run_tool "$@"
        ;;
esac
