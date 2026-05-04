#!/bin/bash
# Apex CLI v8.x — Installer
# Self-documenting: every step prints clear status. No silent failures.
# Supports: Ubuntu, Debian, Linux Mint, Fedora, Arch, macOS (brew)

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m'

ERRORS=0

echo -e "${RED}"
cat << 'EOF'
                     ______
                  .-"      "-.
                 /            \
                |              |
                |,  .-.  .-.  ,|
                | )(__/  \__)( |
                |/     /\     \|
                (_     ^^     _)
                 \__|IIIIII|__/
                  | \IIIIII/ |
                  \          /
                   `--------`
EOF
echo -e "${NC}"
echo -e "${CYAN}       Apex CLI v8.x — Installer${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
skip() { echo -e "  ${YELLOW}[~]${NC} $1 (already installed)"; }
fail() { echo -e "  ${RED}[!]${NC} $1"; ERRORS=$((ERRORS + 1)); }
info() { echo -e "  ${CYAN}[+]${NC} $1"; }

# --- Helper: install apt packages one-by-one so missing ones don't kill the run ---
apt_install_each() {
    for pkg in "$@"; do
        if dpkg -s "$pkg" &>/dev/null; then
            skip "$pkg"
        else
            if sudo apt-get install -y -qq "$pkg" 2>/dev/null; then
                ok "$pkg"
            else
                fail "$pkg — not available in repos (optional)"
            fi
        fi
    done
}

install_go_tool() {
    local name=$1 url=$2
    if command -v "$name" &>/dev/null || [ -f "$REAL_HOME/go/bin/$name" ]; then
        skip "$name"
    else
        info "Installing $name..."
        if sudo -u "$REAL_USER" env GOPATH="$REAL_HOME/go" PATH="$PATH:/usr/local/go/bin:$REAL_HOME/go/bin" go install "$url" 2>/dev/null; then
            ok "$name"
        else
            fail "$name — go install failed (optional, install manually)"
        fi
    fi
}

# ─── 1. System packages ───
echo -e "${CYAN}[1/6] System packages${NC}"
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq 2>/dev/null
    apt_install_each python3 python3-pip python3-venv curl git wget nmap libssl-dev libffi-dev
    # These may not be in default repos on all distros — try individually
    apt_install_each sqlmap seclists
elif command -v dnf &>/dev/null; then
    sudo dnf install -y -q python3 python3-pip curl git nmap 2>/dev/null && ok "dnf core packages" || fail "dnf core packages"
    sudo dnf install -y -q sqlmap 2>/dev/null && ok "sqlmap" || fail "sqlmap (optional)"
elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm python python-pip curl git nmap 2>/dev/null && ok "pacman core packages" || fail "pacman core packages"
    sudo pacman -Sy --noconfirm sqlmap 2>/dev/null && ok "sqlmap" || fail "sqlmap (optional)"
elif command -v brew &>/dev/null; then
    brew install python3 curl git nmap sqlmap 2>/dev/null && ok "brew packages" || fail "brew packages"
else
    fail "Unknown package manager — install python3, pip3, nmap, sqlmap manually"
fi

# ─── 2. Python dependencies ───
echo ""
echo -e "${CYAN}[2/6] Python dependencies${NC}"

# Determine pip install flags — --break-system-packages needed on Python 3.12+ (PEP 668)
PIP_FLAGS="-q"
if sudo -u "$REAL_USER" pip3 install --break-system-packages --dry-run pip &>/dev/null; then
    PIP_FLAGS="--break-system-packages -q"
    info "Using --break-system-packages (PEP 668 system)"
fi

if sudo -u "$REAL_USER" pip3 install $PIP_FLAGS -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null; then
    ok "Python packages from requirements.txt"
else
    fail "pip install from requirements.txt — try: pip3 install -r requirements.txt"
fi

# Install Playwright browsers (optional — only needed for JS crawling)
if sudo -u "$REAL_USER" python3 -c "import playwright" 2>/dev/null; then
    info "Installing Playwright Chromium browser..."
    if python3 -m playwright install chromium --with-deps 2>/dev/null; then
        ok "Playwright Chromium"
    else
        fail "Playwright Chromium (optional — JS crawling won't work without it)"
    fi
else
    fail "Playwright not installed — JS crawling disabled (optional)"
fi

# ─── 3. Go runtime ───
echo ""
echo -e "${CYAN}[3/6] Go runtime${NC}"
if ! command -v go &>/dev/null; then
    info "Installing Go..."
    GO_VERSION="1.22.4"
    ARCH=$(uname -m)
    case "$ARCH" in
        aarch64|arm64) GOARCH="arm64" ;;
        *)             GOARCH="amd64" ;;
    esac
    if wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz; then
        sudo rm -rf /usr/local/go
        sudo tar -C /usr/local -xzf /tmp/go.tar.gz
        rm -f /tmp/go.tar.gz
        ok "Go ${GO_VERSION}"
    else
        fail "Go download failed — install manually: https://go.dev/dl/"
    fi
else
    skip "Go ($(go version 2>/dev/null | awk '{print $3}'))"
fi
export PATH="$PATH:/usr/local/go/bin:$REAL_HOME/go/bin"

# ─── 4. Go security tools ───
echo ""
echo -e "${CYAN}[4/6] Go-based security tools${NC}"
if command -v go &>/dev/null || [ -x /usr/local/go/bin/go ]; then
    install_go_tool subfinder         "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    install_go_tool httpx             "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    install_go_tool nuclei            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_go_tool ffuf              "github.com/ffuf/ffuf/v2@latest"
    install_go_tool assetfinder       "github.com/tomnomnom/assetfinder@latest"
    install_go_tool interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    install_go_tool amass             "github.com/owasp-amass/amass/v4/...@latest"

    # Update nuclei templates
    if command -v nuclei &>/dev/null || [ -f "$REAL_HOME/go/bin/nuclei" ]; then
        info "Updating nuclei templates..."
        if sudo -u "$REAL_USER" "$REAL_HOME/go/bin/nuclei" -update-templates -silent 2>/dev/null || nuclei -update-templates -silent 2>/dev/null; then
            ok "Nuclei templates updated"
        else
            fail "Nuclei template update (run manually: nuclei -update-templates)"
        fi
    fi
else
    fail "Go not available — skipping all Go-based tools (subfinder, httpx, nuclei, ffuf, etc.)"
fi

# ─── 5. Install apex-cli ───
echo ""
echo -e "${CYAN}[5/6] Installing apex-cli${NC}"
chmod +x "$SCRIPT_DIR/apex.py"
if sudo ln -sf "$SCRIPT_DIR/apex.py" /usr/local/bin/apex-cli; then
    ok "apex-cli → /usr/local/bin/apex-cli"
else
    fail "Could not symlink apex-cli to /usr/local/bin/ — run with sudo"
fi

# Add Go bin to PATH permanently
SHELL_RC="$REAL_HOME/.bashrc"
[ -f "$REAL_HOME/.zshrc" ] && SHELL_RC="$REAL_HOME/.zshrc"
if ! grep -q 'go/bin' "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$SHELL_RC"
    ok "Added Go to PATH in $SHELL_RC"
fi

# ─── 6. Verification ───
echo ""
echo -e "${CYAN}[6/6] Verification${NC}"
for tool in apex-cli python3 pip3 nmap; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool"
    else
        fail "$tool — REQUIRED but not found"
    fi
done
for tool in subfinder httpx nuclei ffuf sqlmap assetfinder interactsh-client; do
    if command -v "$tool" &>/dev/null || [ -f "$REAL_HOME/go/bin/$tool" ]; then
        ok "$tool"
    else
        fail "$tool — not found (optional)"
    fi
done

# Check wordlist
if [ -f /usr/share/seclists/Discovery/Web-Content/common.txt ]; then
    ok "SecLists wordlist"
elif [ -f "$SCRIPT_DIR/wordlist.txt" ]; then
    ok "Bundled wordlist"
else
    fail "No wordlist found — install seclists or add wordlist.txt"
fi

# Check Python deps
if python3 -c "import rich, jinja2, requests, bs4, lxml" 2>/dev/null; then
    ok "Python deps importable"
else
    fail "Some Python deps missing — run: pip3 install -r requirements.txt"
fi

# ─── Summary ───
echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}✓ Installation complete — all tools ready!${NC}"
else
    echo -e "${YELLOW}⚠ Installation complete with ${ERRORS} warning(s) — check [!] items above${NC}"
    echo -e "  Re-run this script after fixing issues. It's safe to run multiple times."
fi
echo ""
echo -e "  Verify:  ${CYAN}apex-cli --tools${NC}"
echo -e "  Scan:    ${CYAN}apex-cli example.com${NC}"
echo -e "  Deep:    ${CYAN}apex-cli example.com --deep --report html json${NC}"
