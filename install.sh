#!/bin/bash
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m'

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

ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
skip() { echo -e "  ${YELLOW}[~]${NC} $1 (already installed)"; }
fail() { echo -e "  ${RED}[!]${NC} $1"; }
info() { echo -e "  ${CYAN}[+]${NC} $1"; }

install_go_tool() {
    local name=$1 url=$2
    if command -v "$name" &>/dev/null || [ -f "$HOME/go/bin/$name" ]; then
        skip "$name"
    else
        info "Installing $name..."
        if go install "$url" 2>/dev/null; then
            ok "$name"
        else
            fail "$name — go install failed"
        fi
    fi
}

# --- System deps ---
echo -e "${CYAN}[1/6] System packages${NC}"
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq \
        python3 python3-pip curl git wget \
        nmap sqlmap seclists \
        libssl-dev libffi-dev 2>/dev/null
    ok "apt packages"
elif command -v dnf &>/dev/null; then
    sudo dnf install -y -q python3 python3-pip curl git nmap sqlmap 2>/dev/null
    ok "dnf packages"
elif command -v pacman &>/dev/null; then
    sudo pacman -Sy --noconfirm python python-pip curl git nmap sqlmap 2>/dev/null
    ok "pacman packages"
elif command -v brew &>/dev/null; then
    brew install python3 curl git nmap sqlmap 2>/dev/null
    ok "brew packages"
else
    fail "Unknown package manager — install python3, nmap, sqlmap manually"
fi

# --- Python deps ---
echo ""
echo -e "${CYAN}[2/6] Python dependencies${NC}"
PIP_ARGS="--break-system-packages -q"
pip3 install $PIP_ARGS \
    "rich==13.7.0" \
    "Jinja2==3.1.6" \
    "requests==2.31.0" \
    "beautifulsoup4==4.12.3" \
    "lxml==5.2.1" \
    "pyyaml>=6.0" \
    "websocket-client>=1.6.0" \
    "httpx[http2]>=0.25.0" \
    "playwright>=1.40.0" \
    2>/dev/null || pip3 install -q \
    "rich==13.7.0" "Jinja2==3.1.6" "requests==2.31.0" \
    "beautifulsoup4==4.12.3" "lxml==5.2.1" \
    "pyyaml>=6.0" "websocket-client>=1.6.0" \
    "httpx[http2]>=0.25.0" "playwright>=1.40.0"
ok "Python packages (rich, jinja2, requests, bs4, lxml, pyyaml, websocket-client, httpx, playwright)"

# Install Playwright browsers
info "Installing Playwright Chromium browser..."
python3 -m playwright install chromium --with-deps 2>/dev/null && ok "Playwright Chromium" || fail "Playwright Chromium (optional)"

# --- Go ---
echo ""
echo -e "${CYAN}[3/6] Go runtime${NC}"
if ! command -v go &>/dev/null; then
    info "Installing Go..."
    GO_VERSION="1.22.4"
    ARCH=$(uname -m)
    [ "$ARCH" = "aarch64" ] && GOARCH="arm64" || GOARCH="amd64"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    ok "Go ${GO_VERSION}"
else
    skip "Go ($(go version | awk '{print $3}'))"
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# --- Go security tools ---
echo ""
echo -e "${CYAN}[4/6] Go-based security tools${NC}"
install_go_tool subfinder     "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool httpx         "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool nuclei        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool ffuf          "github.com/ffuf/ffuf/v2@latest"
install_go_tool assetfinder   "github.com/tomnomnom/assetfinder@latest"
install_go_tool interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
install_go_tool amass         "github.com/owasp-amass/amass/v4/...@latest"

# Update nuclei templates
if command -v nuclei &>/dev/null || [ -f "$HOME/go/bin/nuclei" ]; then
    info "Updating nuclei templates..."
    "${HOME}/go/bin/nuclei" -update-templates -silent 2>/dev/null \
        || nuclei -update-templates -silent 2>/dev/null \
        && ok "Nuclei templates updated" || skip "Nuclei templates"
fi

# --- Install apex-cli ---
echo ""
echo -e "${CYAN}[5/6] Installing apex-cli${NC}"
chmod +x "$SCRIPT_DIR/apex.py"
sudo ln -sf "$SCRIPT_DIR/apex.py" /usr/local/bin/apex-cli
ok "apex-cli → /usr/local/bin/apex-cli"

# Add Go bin to PATH permanently
SHELL_RC="$HOME/.bashrc"
[ -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.zshrc"
[ -f "$HOME/.config/fish/config.fish" ] && SHELL_RC="$HOME/.config/fish/config.fish"
if ! grep -q 'go/bin' "$SHELL_RC" 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$SHELL_RC"
    ok "Added Go to PATH in $SHELL_RC"
fi

# --- Verify ---
echo ""
echo -e "${CYAN}[6/6] Verification${NC}"
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
ALL_OK=true
for tool in apex-cli subfinder httpx nuclei ffuf nmap sqlmap assetfinder interactsh-client; do
    if command -v "$tool" &>/dev/null || [ -f "$HOME/go/bin/$tool" ]; then
        ok "$tool"
    else
        fail "$tool — not found (optional)"
        ALL_OK=false
    fi
done

# Check wordlist
if [ -f /usr/share/seclists/Discovery/Web-Content/common.txt ]; then
    ok "SecLists wordlist (/usr/share/seclists)"
elif [ -f "$SCRIPT_DIR/wordlist.txt" ]; then
    ok "Bundled wordlist"
else
    fail "No wordlist — install seclists: sudo apt install seclists"
fi

# Check Python deps
python3 -c "import rich, jinja2, requests, bs4, lxml; print('  \033[1;32m[✓]\033[0m Python deps OK')"

echo ""
if $ALL_OK; then
    echo -e "${GREEN}✓ Installation complete — all tools ready!${NC}"
else
    echo -e "${YELLOW}⚠ Installation complete — some optional tools missing${NC}"
fi
echo ""
echo -e "Verify:  ${CYAN}apex-cli --tools${NC}"
echo -e "Scan:    ${CYAN}apex-cli example.com${NC}"
echo -e "Deep:    ${CYAN}apex-cli example.com --deep --report html json${NC}"
echo -e "Watch:   ${CYAN}apex-cli example.com --watch 24${NC}"
echo -e "Bounty:  ${CYAN}apex-auto --bounty${NC}"
