#!/bin/bash
# Apex CLI — Fingerprint Discovery
# Finds live instances of vulnerable stacks via HTTP fingerprinting.
# Uses public search engines (Shodan, Censys, FOFA) + direct probing.
# LEGAL: Only probes targets in scope (bug bounty programs).
set -uo pipefail

OUTDIR="./output/discover-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/discover.log"
TARGETS="$OUTDIR/targets.jsonl"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!!]\033[0m $*" | tee -a "$LOG"; }

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Stack Fingerprint Discovery           ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

# ═══ Fingerprint signatures ═══
# Each stack has unique HTTP response characteristics
declare -A SIGNATURES
# Langflow: returns specific headers/paths
SIGNATURES[langflow_health]="/health"
SIGNATURES[langflow_api]="/api/v1/version"
SIGNATURES[langflow_login]="/api/v1/login"
# Open-WebUI: specific paths
SIGNATURES[openwebui_api]="/api/config"
SIGNATURES[openwebui_health]="/health"
SIGNATURES[openwebui_auth]="/api/v1/auths/signin"
# Dify: specific paths
SIGNATURES[dify_console]="/console/api/setup"
SIGNATURES[dify_health]="/health"
SIGNATURES[dify_apps]="/v1/apps"
# Flowise
SIGNATURES[flowise_api]="/api/v1/flows"
SIGNATURES[flowise_health]="/api/v1/ping"
# n8n
SIGNATURES[n8n_health]="/healthz"
SIGNATURES[n8n_api]="/api/v1/workflows"

# ═══ Known response patterns for identification ═══
identify_stack() {
  local url="$1"
  local results=""
  
  # Probe health/version endpoints
  local resp
  resp=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}|%{size_download}" "$url/api/v1/version" 2>/dev/null)
  local code="${resp%%|*}"
  
  # Langflow: /api/v1/version returns JSON with version
  if [[ "$code" == "200" ]]; then
    local body
    body=$(curl -sk --max-time 5 "$url/api/v1/version" 2>/dev/null)
    if echo "$body" | grep -qi "langflow\|version"; then
      results="langflow"
      local ver=$(echo "$body" | grep -o '"version":"[^"]*"' | head -1)
      echo "{\"url\":\"$url\",\"stack\":\"langflow\",\"version\":$ver,\"confidence\":\"high\"}" >> "$TARGETS"
      crit "LANGFLOW: $url ($ver)"
      return
    fi
  fi
  
  # Open-WebUI: /api/config returns config object
  resp=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$url/api/config" 2>/dev/null)
  if [[ "$resp" == "200" ]]; then
    local body
    body=$(curl -sk --max-time 5 "$url/api/config" 2>/dev/null)
    if echo "$body" | grep -qi "open.webui\|webui\|ollama"; then
      results="open-webui"
      echo "{\"url\":\"$url\",\"stack\":\"open-webui\",\"confidence\":\"high\"}" >> "$TARGETS"
      crit "OPEN-WEBUI: $url"
      return
    fi
  fi
  
  # Dify: /console/api/setup
  resp=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$url/console/api/setup" 2>/dev/null)
  if [[ "$resp" == "200" || "$resp" == "401" ]]; then
    local body
    body=$(curl -sk --max-time 5 "$url/console/api/setup" 2>/dev/null)
    if echo "$body" | grep -qi "dify\|setup_status"; then
      results="dify"
      echo "{\"url\":\"$url\",\"stack\":\"dify\",\"confidence\":\"high\"}" >> "$TARGETS"
      crit "DIFY: $url"
      return
    fi
  fi
  
  # Flowise: /api/v1/ping
  resp=$(curl -sk --max-time 5 "$url/api/v1/ping" 2>/dev/null)
  if echo "$resp" | grep -qi "pong\|flowise"; then
    results="flowise"
    echo "{\"url\":\"$url\",\"stack\":\"flowise\",\"confidence\":\"high\"}" >> "$TARGETS"
    crit "FLOWISE: $url"
    return
  fi
  
  # n8n: /healthz
  resp=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$url/healthz" 2>/dev/null)
  if [[ "$resp" == "200" ]]; then
    local body
    body=$(curl -sk --max-time 5 -H "Accept: application/json" "$url/healthz" 2>/dev/null)
    if echo "$body" | grep -qi "n8n\|healthy"; then
      results="n8n"
      echo "{\"url\":\"$url\",\"stack\":\"n8n\",\"confidence\":\"medium\"}" >> "$TARGETS"
      ok "N8N: $url"
      return
    fi
  fi
  
  # Generic: check response headers for clues
  local headers
  headers=$(curl -sk --max-time 5 -I "$url" 2>/dev/null)
  if echo "$headers" | grep -qi "langflow"; then
    echo "{\"url\":\"$url\",\"stack\":\"langflow\",\"confidence\":\"low\",\"source\":\"header\"}" >> "$TARGETS"
    warn "LANGFLOW (header): $url"
  elif echo "$headers" | grep -qi "open-webui\|webui"; then
    echo "{\"url\":\"$url\",\"stack\":\"open-webui\",\"confidence\":\"low\",\"source\":\"header\"}" >> "$TARGETS"
    warn "OPEN-WEBUI (header): $url"
  fi
}

# ═══ Google Dork queries (for manual use / reference) ═══
generate_dorks() {
  local dork_file="$OUTDIR/dorks.txt"
  cat > "$dork_file" << 'EOF'
# Langflow instances
intitle:"Langflow" inurl:"/flow"
inurl:"/api/v1/version" "langflow"
inurl:"/api/v1/flows" -github -docs
"langflow" "sign in" -github.com -docs.langflow

# Open-WebUI instances
intitle:"Open WebUI" inurl:"/auth"
inurl:"/api/config" "ollama" -github
"open-webui" "sign in" -github.com

# Dify instances
intitle:"Dify" inurl:"/signin"
inurl:"/console/api" "dify" -github
"dify.ai" "sign in" -github.com -docs

# Flowise instances
intitle:"Flowise" inurl:"/chatflows"
inurl:"/api/v1/flows" "flowise" -github

# n8n instances (many public)
intitle:"n8n" inurl:"/workflow"
inurl:"/healthz" "n8n" -github

# Generic AI/LLM platforms exposed
inurl:"/api/v1/chat" "model" "messages" -docs -github
inurl:"/v1/completions" -openai.com -docs
EOF
  log "Dorks saved: $dork_file"
}

# ═══ Shodan/Censys queries (requires API key) ═══
search_shodan() {
  local query="$1" label="$2"
  if [[ -z "${SHODAN_API_KEY:-}" ]]; then
    warn "SHODAN_API_KEY not set — skipping Shodan search"
    return
  fi
  log "Shodan: $label"
  local results
  results=$(curl -s "https://api.shodan.io/shodan/host/search?key=$SHODAN_API_KEY&query=$query&facets=org" 2>/dev/null)
  local count=$(echo "$results" | grep -o '"total":[0-9]*' | head -1 | cut -d: -f2)
  ok "  Found: ${count:-0} hosts"
  
  # Extract IPs
  echo "$results" | grep -o '"ip_str":"[^"]*"' | sed 's/"ip_str":"//;s/"//' | while read -r ip; do
    echo "{\"url\":\"http://$ip\",\"stack\":\"$label\",\"source\":\"shodan\",\"confidence\":\"medium\"}" >> "$TARGETS"
  done
}

# ═══ Probe from URL list ═══
probe_urls() {
  local url_file="$1"
  if [[ ! -f "$url_file" ]]; then
    warn "No URL file: $url_file"
    return
  fi
  local total=$(wc -l < "$url_file" | tr -d ' ')
  log "Probing $total URLs..."
  local i=0
  while IFS= read -r url; do
    i=$((i + 1))
    [[ -z "$url" || "$url" == "#"* ]] && continue
    # Ensure URL has scheme
    [[ "$url" != http* ]] && url="https://$url"
    printf "\r  %d/%d  " "$i" "$total"
    identify_stack "$url" &
    # Throttle: max 10 parallel
    [[ $((i % 10)) -eq 0 ]] && wait
  done < "$url_file"
  wait
  echo ""
}

# ═══ Main ═══
MODE="${1:-dorks}"

case "$MODE" in
  dorks)
    log "Mode: Generate Google dorks for manual discovery"
    generate_dorks
    ;;
  shodan)
    log "Mode: Shodan search"
    search_shodan "http.title:langflow" "langflow"
    search_shodan "http.title:\"Open WebUI\"" "open-webui"
    search_shodan "http.title:Dify" "dify"
    search_shodan "http.title:Flowise" "flowise"
    search_shodan "http.title:n8n" "n8n"
    ;;
  probe)
    URL_FILE="${2:?Usage: $0 probe <urls.txt>}"
    log "Mode: Probe URLs from file"
    probe_urls "$URL_FILE"
    ;;
  single)
    URL="${2:?Usage: $0 single <url>}"
    log "Mode: Single target probe"
    identify_stack "$URL"
    ;;
  *)
    echo "Usage: $0 <mode> [args]"
    echo ""
    echo "Modes:"
    echo "  dorks           Generate Google dork queries"
    echo "  shodan          Search Shodan (needs SHODAN_API_KEY)"
    echo "  probe <file>    Probe URLs from file"
    echo "  single <url>    Probe single URL"
    exit 1
    ;;
esac

# ═══ Summary ═══
echo ""
FOUND=0
[[ -f "$TARGETS" ]] && FOUND=$(wc -l < "$TARGETS" | tr -d ' ')
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           DISCOVERY COMPLETE                  ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
ok "Targets found: $FOUND"
ok "Results:       $TARGETS"
ok "Dorks:         $OUTDIR/dorks.txt"
ok "Log:           $LOG"

if [[ $FOUND -gt 0 ]]; then
  echo ""
  log "Discovered targets:"
  cat "$TARGETS" | while IFS= read -r line; do
    echo "  $line"
  done
fi
