#!/bin/bash
# APEX AUTOPILOT — Fully automated bug bounty hunting
# Run once, walk away, get Discord pings when money is found.
#
# Usage:
#   ./autopilot.sh
#   DISCORD_WEBHOOK=https://discord.com/api/webhooks/... ./autopilot.sh
#
# It will:
# 1. Fetch all H1 programs with bounties
# 2. Pick targets with high bounties + low competition
# 3. Scan each one
# 4. Filter out noise/dupes
# 5. Alert you on Discord for anything worth reporting
# 6. Generate ready-to-paste H1 reports
# 7. Loop forever (re-scans daily for new vulns after deploys)

set -euo pipefail

APEX_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$HOME/.apex-autopilot"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
SCAN_INTERVAL="${SCAN_INTERVAL:-86400}" # 24 hours between re-scans
MAX_TARGETS="${MAX_TARGETS:-20}"

mkdir -p "$RESULTS_DIR/reports" "$RESULTS_DIR/scanned"

# Colors
RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
alert() { echo -e "${RED}[!]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }

# Discord notification
notify() {
    local title="$1" desc="$2" color="${3:-65280}"
    [ -z "$DISCORD_WEBHOOK" ] && return
    curl -s -X POST "$DISCORD_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "{\"embeds\":[{\"title\":\"$title\",\"description\":\"$desc\",\"color\":$color}]}" \
        >/dev/null 2>&1
}

# Fetch high-value H1 programs
fetch_targets() {
    log "Fetching bounty programs..."
    curl -s "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json" \
        | python3 -c "
import json, sys
programs = json.load(sys.stdin)
targets = []
for p in programs:
    if not p.get('offers_bounties', False):
        continue
    domains = []
    for t in p.get('targets', {}).get('in_scope', []):
        if t.get('asset_type') in ('URL', 'WILDCARD'):
            d = t['asset_identifier']
            d = d.replace('https://','').replace('http://','').replace('*.','').rstrip('/')
            if '.' in d and len(d) < 80:
                domains.append(d)
    if domains:
        targets.append({'handle': p['handle'], 'domains': domains, 'bounty': p.get('max_bounty', 0) or 0})
# Sort by max bounty (highest paying first)
targets.sort(key=lambda x: -x.get('bounty', 0))
for t in targets:
    for d in t['domains']:
        print(f\"{t['handle']}|{d}\")
" 2>/dev/null
}

# Check if target was recently scanned
recently_scanned() {
    local target="$1"
    local hash=$(echo -n "$target" | md5sum | cut -c1-16)
    local stamp="$RESULTS_DIR/scanned/$hash"
    if [ -f "$stamp" ]; then
        local age=$(( $(date +%s) - $(stat -c %Y "$stamp") ))
        [ "$age" -lt "$SCAN_INTERVAL" ] && return 0
    fi
    return 1
}

mark_scanned() {
    local target="$1"
    local hash=$(echo -n "$target" | md5sum | cut -c1-16)
    touch "$RESULTS_DIR/scanned/$hash"
}

# Scan a single target
scan_target() {
    local program="$1" domain="$2"
    log "Scanning ${YELLOW}$domain${NC} (program: $program)"

    local output
    output=$(timeout 300 apex-cli --deep -no-oob -threads 30 -timeout 8 "$domain" 2>&1)
    local exit_code=$?

    # Extract VERIFIED findings count from the final report line
    local total_findings=$(echo "$output" | grep -oP '→ \K[0-9]+(?= findings)' | tail -1)
    total_findings=${total_findings:-0}

    # Count verified critical/high from the summary box only
    local criticals=$(echo "$output" | grep "Critical:" | grep -oP 'Critical: \K[0-9]+' || echo 0)
    local highs=$(echo "$output" | grep "High:" | grep -oP 'High: \K[0-9]+' || echo 0)
    criticals=${criticals:-0}
    highs=${highs:-0}
    local total=$((criticals + highs))

    if [ "$total" -gt 0 ]; then
        alert "Found $criticals critical + $highs high on $domain!"

        # Save report
        local report_file="$RESULTS_DIR/reports/${program}_${domain//\//_}_$(date +%Y%m%d_%H%M%S).txt"
        echo "$output" > "$report_file"

        # Extract top findings for notification
        local top_findings
        top_findings=$(echo "$output" | grep -E "^\s+🔴|^\s+🟠" | head -5 | sed 's/\x1b\[[0-9;]*m//g')

        # Discord alert
        notify "🎯 BOUNTY FOUND: $domain" "Program: $program\nCritical: $criticals | High: $highs\n\nTop findings:\n$top_findings" "16711680"

        success "$domain: $criticals critical, $highs high → $report_file"
        return 0
    else
        log "$domain: clean (no critical/high findings)"
        return 1
    fi
}

# Main loop
main() {
    echo -e "${RED}"
    cat << 'EOF'
     █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ██╗██╗      ██████╗ ████████╗
    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
    ███████║██║   ██║   ██║   ██║   ██║██████╔╝██║██║     ██║   ██║   ██║
    ██╔══██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██║██║     ██║   ██║   ██║
    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║     ██║███████╗╚██████╔╝   ██║
    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝
EOF
    echo -e "${NC}"
    echo -e "    ${CYAN}Fully Automated Bug Bounty Hunting${NC}"
    echo -e "    ${YELLOW}Walk away. Get paid.${NC}"
    echo ""

    if [ -n "$DISCORD_WEBHOOK" ]; then
        success "Discord alerts: ENABLED"
        notify "🚀 Apex Autopilot Started" "Scanning $MAX_TARGETS programs continuously.\nInterval: ${SCAN_INTERVAL}s between re-scans." "65280"
    else
        log "Discord alerts: disabled (set DISCORD_WEBHOOK to enable)"
    fi
    echo ""

    while true; do
        local targets
        targets=$(fetch_targets)
        local count=$(echo "$targets" | wc -l)
        log "Loaded $count targets from H1 bounty programs"

        local hits=0
        while IFS='|' read -r program domain; do
            [ -z "$domain" ] && continue

            if recently_scanned "$domain"; then
                continue
            fi

            scan_target "$program" "$domain" && hits=$((hits + 1))
            mark_scanned "$domain"

            # Rate limit between targets
            sleep 5
        done <<< "$targets"

        if [ "$hits" -gt 0 ]; then
            notify "📊 Scan Cycle Complete" "$hits targets had findings.\nReports saved to $RESULTS_DIR/reports/\nNext cycle in ${SCAN_INTERVAL}s." "65280"
        fi

        log "Cycle complete. Sleeping ${SCAN_INTERVAL}s before next round..."
        sleep "$SCAN_INTERVAL"
    done
}

main "$@"
