#!/bin/bash
# Apex CLI — Autonomous Network Scanner
# Discovers hosts → finds HTTP services → feeds them to apex-cli
set -uo pipefail

APEX="$(dirname "$0")/../build/apex-cli"
OUTDIR="./output/network-$(date +%Y%m%d-%H%M%S)"
SUBNET="${1:-}"
APEX_FLAGS=(--smart --confidence 2)

log() { echo -e "\033[1;34m[*]\033[0m $*"; }
ok() { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }

# Detect local subnet (pick LAN, skip loopback and tunnels)
if [ -z "$SUBNET" ]; then
  SUBNET=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | grep -v "10.5\." | awk '{print $2}' | head -1)
  SUBNET="${SUBNET%.*}.0/24"
fi
IFACE=$(route get "${SUBNET%0/24}1" 2>/dev/null | awk '/interface:/{print $2}' || echo "en0")

mkdir -p "$OUTDIR"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║  APEX — Autonomous Network Scanner   ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
log "Interface: $IFACE"
log "Subnet:    $SUBNET"
log "Output:    $OUTDIR"
echo ""

# Phase 1: Host discovery (fast ARP ping)
log "Phase 1/4: Host discovery (-sn on $SUBNET)"
nmap -sn -T5 "$SUBNET" -oG "$OUTDIR/hosts.txt" 2>/dev/null &
NMAP_PID=$!
# Show spinner while waiting
while kill -0 $NMAP_PID 2>/dev/null; do
  printf "\r  ⏳ scanning..."
  sleep 0.5
done
printf "\r                \r"
wait $NMAP_PID
HOSTS=$(grep "Up" "$OUTDIR/hosts.txt" | awk '{print $2}')
HOST_COUNT=$(echo "$HOSTS" | grep -c . || echo 0)
ok "Found $HOST_COUNT live hosts:"
for h in $HOSTS; do echo "    $h"; done
echo ""

# Phase 2: Port scan — find HTTP services (parallel, fast)
log "Phase 2/4: Finding HTTP services"
HTTP_TARGETS=()
for host in $HOSTS; do
  printf "  → probing %s ... " "$host"
  open=$(nmap -p 80,443,8080,8443,8000,3000,5000,9090 -T5 --open --host-timeout 5s "$host" 2>/dev/null | grep "^[0-9]" || true)
  if [ -n "$open" ]; then
    while IFS= read -r line; do
      port=$(echo "$line" | awk -F/ '{print $1}')
      if echo "$line" | grep -q "ssl\|https"; then
        HTTP_TARGETS+=("https://$host:$port")
        echo -n "https:$port "
      else
        HTTP_TARGETS+=("http://$host:$port")
        echo -n "http:$port "
      fi
    done <<<"$open"
    echo ""
  else
    echo "no web ports"
  fi
done
echo ""
ok "Found ${#HTTP_TARGETS[@]} HTTP service(s)"
echo ""

# Phase 3: Deep fingerprinting (OS, hostname, MAC, versions, weak crypto)
log "Phase 3/4: Deep fingerprinting"
echo ""
for host in $HOSTS; do
  log "Profiling $host..."
  # Full fingerprint: versions, scripts, OS if root
  OS_FLAG=""
  [ "$(id -u)" -eq 0 ] && OS_FLAG="-O"
  nmap -sV -sC $OS_FLAG --host-timeout 30s -T4 --top-ports 20 "$host" -oN "$OUTDIR/profile-$host.txt" 2>/dev/null

  # Parse and display
  printf "\n  ┌─ %s " "$host"
  # MAC + vendor
  mac=$(grep "MAC Address" "$OUTDIR/profile-$host.txt" 2>/dev/null | head -1 | sed 's/MAC Address: //')
  [ -n "$mac" ] && printf "(%s)" "$mac"
  echo ""
  # Hostname
  hostname=$(grep -i "hostname\|NetBIOS\|commonName\|Device type" "$OUTDIR/profile-$host.txt" 2>/dev/null | head -1 | sed 's/^[|_ ]*/  │ /')
  [ -n "$hostname" ] && echo "$hostname"
  # OS guess
  os=$(grep "OS details\|Running:" "$OUTDIR/profile-$host.txt" 2>/dev/null | head -1 | sed 's/^/  │ /')
  [ -n "$os" ] && echo "$os"
  # Open services with versions
  echo "  │ Services:"
  grep "^[0-9].*open" "$OUTDIR/profile-$host.txt" 2>/dev/null | while read -r line; do
    echo "  │   $line"
  done
  # Weak security indicators from NSE scripts
  weak=$(grep -i "weak\|anonymous\|default\|plain\|unencrypted\|SSLv\|TLSv1.0\|TLSv1.1\|self-signed\|expired" "$OUTDIR/profile-$host.txt" 2>/dev/null | sed 's/^[|_ ]*/  │ ⚠ /')
  [ -n "$weak" ] && echo "$weak"
  echo "  └─"
done
echo ""
ok "Profiles saved to $OUTDIR/profile-*.txt"
echo ""

# Bonus: Quick traffic snapshot (5 seconds, no root needed for stats)
log "Traffic snapshot (5s)..."
if [ "$(id -u)" -eq 0 ] && command -v tcpdump >/dev/null 2>&1; then
  timeout 5 tcpdump -i "$IFACE" -nn -q 2>/dev/null | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -10 >"$OUTDIR/traffic-top.txt" || true
  echo "  Top talkers (5s capture):"
  cat "$OUTDIR/traffic-top.txt" | while read -r cnt ip; do
    printf "    %5s pkts  %s\n" "$cnt" "$ip"
  done
else
  # Use netstat as non-root alternative
  echo "  Active connections from this host:"
  netstat -an 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -10 | while read -r cnt ip; do
    printf "    %5s conn  %s\n" "$cnt" "$ip"
  done
fi
echo ""

# Phase 4: Apex vulnerability scan on each HTTP target
log "Phase 4/4: Vulnerability scanning with apex-cli"
echo ""
for target in "${HTTP_TARGETS[@]}"; do
  log "Scanning: $target"
  target_dir="$OUTDIR/${target//[:\\/]/_}"
  mkdir -p "$target_dir"
  "$APEX" "$target" "${APEX_FLAGS[@]}" --output "$target_dir" 2>&1 | tail -5
  echo ""
done

# Summary
echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║           SCAN COMPLETE              ║"
echo "  ╚══════════════════════════════════════╝"
echo ""
ok "Hosts discovered:  $HOST_COUNT"
ok "HTTP services:     ${#HTTP_TARGETS[@]}"
ok "Results:           $OUTDIR/"
echo ""

# Auto-summarize findings
log "Findings summary:"
for rpt in "$OUTDIR"/*/report.json; do
  [ -f "$rpt" ] || continue
  target_name=$(basename "$(dirname "$rpt")" | sed 's|___|://|;s|_|.|g')
  iconv -f utf-8 -t utf-8 -c "$rpt" | python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    findings=d.get('findings',[])
    if findings:
        print(f'  {\"$target_name\"}:')
        for f in findings:
            print(f'    [{f[\"severity\"]}] {f[\"type\"]}: {f.get(\"detail\",\"\")[:70]}')
except: pass
" 2>/dev/null
done
echo ""
