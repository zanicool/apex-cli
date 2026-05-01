#!/bin/bash
set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m'

echo -e "${RED}"
echo '                     ______'
echo '                  .-"      "-.'
echo '                 /            \'
echo '                |              |'
echo '                |,  .-.  .-.  ,|'
echo '                | )(__/  \__)( |'
echo '                |/     /\     \|'
echo '                (_     ^^     _)'
echo '                 \__|IIIIII|__/'
echo '                  | \IIIIII/ |'
echo '                  \          /'
echo '                   `--------`'
echo -e "${NC}"
echo -e "${CYAN}       Apex CLI v3.0 — Installer${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- Helper ---
ok()   { echo -e "  ${GREEN}[✓]${NC} $1"; }
skip() { echo -e "  ${YELLOW}[~]${NC} $1 (already installed)"; }
fail() { echo -e "  ${RED}[!]${NC} $1"; }
info() { echo -e "  ${CYAN}[+]${NC} $1"; }

install_go_tool() {
    local name=$1 url=$2
    if command -v "$name" &>/dev/null; then
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
echo -e "${CYAN}[1/5] System packages${NC}"
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3 python3-pip curl git nmap sqlmap seclists 2>/dev/null
    ok "apt packages (python3, nmap, sqlmap, seclists)"
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
echo -e "${CYAN}[2/5] Python dependencies${NC}"
pip3 install --break-system-packages -q \
    rich==13.7.0 Jinja2==3.1.6 requests==2.31.0 beautifulsoup4==4.12.3 lxml==5.2.1 2>/dev/null \
    || pip3 install -q rich==13.7.0 Jinja2==3.1.6 requests==2.31.0 beautifulsoup4==4.12.3 lxml==5.2.1
ok "Python packages (rich, jinja2, requests, bs4, lxml)"

# --- Go tools ---
echo ""
echo -e "${CYAN}[3/5] Go-based security tools${NC}"
if ! command -v go &>/dev/null; then
    info "Installing Go..."
    GO_VERSION="1.22.4"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    ok "Go ${GO_VERSION}"
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

install_go_tool subfinder  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool httpx      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool nuclei     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool ffuf       "github.com/ffuf/ffuf/v2@latest"

# Update nuclei templates
if command -v nuclei &>/dev/null; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && ok "Nuclei templates" || skip "Nuclei templates"
fi

# --- Install apex-cli ---
echo ""
echo -e "${CYAN}[4/5] Installing apex-cli${NC}"
chmod +x "$SCRIPT_DIR/apex.py"
sudo ln -sf "$SCRIPT_DIR/apex.py" /usr/local/bin/apex-cli
ok "apex-cli → /usr/local/bin/apex-cli"

# Add Go bin to PATH if not already there
if ! echo "$PATH" | grep -q "$HOME/go/bin"; then
    SHELL_RC="$HOME/.bashrc"
    [ -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.zshrc"
    if ! grep -q 'go/bin' "$SHELL_RC" 2>/dev/null; then
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$SHELL_RC"
        ok "Added Go to PATH in $SHELL_RC"
    fi
fi

# --- Verify ---
echo ""
echo -e "${CYAN}[5/5] Verification${NC}"
for tool in apex-cli subfinder httpx nuclei ffuf nmap sqlmap; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool"
    else
        fail "$tool — not found"
    fi
done

# Check wordlist
if [ -f /usr/share/seclists/Discovery/Web-Content/common.txt ]; then
    ok "SecLists wordlist"
elif [ -f "$SCRIPT_DIR/wordlist.txt" ]; then
    ok "Bundled wordlist"
else
    fail "No wordlist found"
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo -e "Run: ${CYAN}apex-cli --tools${NC} to verify"
echo -e "Scan: ${CYAN}apex-cli example.com${NC}"
