#!/bin/bash
# Apex CLI — ISP/Provider Network Diagnostics
# When internet is down, maps what parts of the provider network still work.
# Designed for KPN/Trined fiber but works generically.
set -uo pipefail

OUTDIR="./output/isp-diag-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOGFILE="$OUTDIR/diag.log"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOGFILE"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOGFILE"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOGFILE"; }
err()  { echo -e "\033[1;31m[-]\033[0m $*" | tee -a "$LOGFILE"; }

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — ISP/Provider Network Diagnostics      ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

# ─── Detect topology ───
LAN_GW=$(route -n get default 2>/dev/null | awk '/gateway/{print $2}' | head -1)
LAN_IF=$(route -n get default 2>/dev/null | awk '/interface/{print $2}' | head -1)
# Get the real WAN gateway (skip VPN)
WAN_GW=$(netstat -rn 2>/dev/null | grep "^default" | grep -v "utun" | awk '{print $2}' | head -1)
WAN_IF=$(netstat -rn 2>/dev/null | grep "^default" | grep -v "utun" | awk '{print $NF}' | head -1)

log "Active gateway: $LAN_GW ($LAN_IF)"
log "WAN gateway:    ${WAN_GW:-unknown} (${WAN_IF:-unknown})"
log "Output:         $OUTDIR"
echo ""

# ─── Known KPN/Trined infrastructure ───
# Mapped from traceroute + rDNS + whois
declare -A ISP_MAP=(
  ["10.0.0.1"]="router          UniFi Dream Machine SE"
  ["91.214.67.2"]="isp-edge-1      Trined/Packethub edge router"
  ["91.214.67.3"]="isp-edge-2      Trined/Packethub edge router"
  ["109.236.95.105"]="backbone-ams-1  Worldstream bb11-ams3 (DC Amsterdam)"
  ["109.236.95.107"]="backbone-ams-2  Worldstream bb11-ams3 (DC Amsterdam)"
  ["109.236.95.178"]="backbone-ww-1   Worldstream bb02-nldw (DC Waalwijk)"
  ["109.236.95.182"]="backbone-ww-2   Worldstream bb01-nldw (DC Waalwijk)"
  ["109.236.95.144"]="peering         Worldstream peering router"
  ["74.125.242.187"]="google-peer-1   Google peering point"
  ["74.125.243.133"]="google-peer-2   Google peering point"
)

KPN_DNS=("195.121.1.34" "195.121.1.66")
GOOGLE_DNS=("8.8.8.8" "8.8.4.4")
CF_DNS=("1.1.1.1" "1.0.0.1")
TEST_HOSTS=("www.google.com" "www.kpn.com" "www.cloudflare.com")

resolve_name() {
  local ip="$1"
  echo "${ISP_MAP[$ip]:-unknown         $ip}"
}

# ═══ Phase 1: Local network ═══
log "Phase 1: Local network check"
echo ""
for target in "${WAN_GW:-10.0.0.1}" "10.0.0.1"; do
  if ping -c1 -W2 "$target" >/dev/null 2>&1; then
    ok "  Router $target: ✓ reachable"
  else
    err "  Router $target: ✗ unreachable"
  fi
done
echo ""

# ═══ Phase 2: ISP gateway / first hop ═══
log "Phase 2: ISP gateway (first hop beyond router)"
echo ""

# Traceroute first 3 hops to find ISP infra
log "  Tracing route (max 6 hops)..."
traceroute -m 6 -w 2 -n 8.8.8.8 2>/dev/null | tee "$OUTDIR/traceroute.txt" | while read -r line; do
  echo "  $line" | tee -a "$LOGFILE"
done
echo ""

# Extract ISP hops (non-private IPs from trace)
ISP_HOPS=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$OUTDIR/traceroute.txt" 2>/dev/null \
  | grep -vE "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" | sort -u)

# Also add known infrastructure
for known_ip in "${!ISP_MAP[@]}"; do
  echo "$known_ip" | grep -qE "^(10\.|192\.168\.)" || ISP_HOPS="$ISP_HOPS
$known_ip"
done
ISP_HOPS=$(echo "$ISP_HOPS" | sort -u | grep -v "^$")

log "  Probing ISP infrastructure..."
echo ""
printf "  %-18s %-16s %-35s %s\n" "IP" "ALIAS" "DESCRIPTION" "STATUS" | tee -a "$LOGFILE"
printf "  %-18s %-16s %-35s %s\n" "──────────────────" "────────────────" "───────────────────────────────────" "──────" | tee -a "$LOGFILE"
for hop in $ISP_HOPS; do
  [ -z "$hop" ] && continue
  name=$(resolve_name "$hop")
  alias=$(echo "$name" | awk '{print $1}')
  desc=$(echo "$name" | cut -d' ' -f2- | sed 's/^ *//')
  if ping -c1 -W2 "$hop" >/dev/null 2>&1; then
    latency=$(ping -c1 -W2 "$hop" 2>/dev/null | grep "time=" | grep -oE "time=[0-9.]+" | cut -d= -f2)
    printf "  %-18s %-16s %-35s ✓ %sms\n" "$hop" "$alias" "$desc" "$latency" | tee -a "$LOGFILE"
    echo "$hop|$alias|up|${latency}ms" >> "$OUTDIR/isp-hops.txt"
  else
    printf "  %-18s %-16s %-35s ✗ DOWN\n" "$hop" "$alias" "$desc" | tee -a "$LOGFILE"
    echo "$hop|$alias|down|" >> "$OUTDIR/isp-hops.txt"
  fi
done
echo ""

# ═══ Phase 3: DNS resolution ═══
log "Phase 3: DNS resolution"
echo ""

# Test local router DNS
for dns in "10.0.0.1" "${KPN_DNS[@]}" "${GOOGLE_DNS[@]}" "${CF_DNS[@]}"; do
  result=$(dig +short +time=2 +tries=1 @"$dns" www.google.com 2>/dev/null | head -1)
  if [ -n "$result" ]; then
    ok "  DNS $dns: ✓ resolves ($result)"
    echo "$dns|up|$result" >> "$OUTDIR/dns-check.txt"
  else
    err "  DNS $dns: ✗ no response"
    echo "$dns|down|" >> "$OUTDIR/dns-check.txt"
  fi
done
echo ""

# ═══ Phase 4: Internet connectivity ═══
log "Phase 4: Internet reachability"
echo ""

for target in "${GOOGLE_DNS[@]}" "${CF_DNS[@]}"; do
  if ping -c1 -W3 "$target" >/dev/null 2>&1; then
    ok "  Ping $target: ✓"
  else
    err "  Ping $target: ✗"
  fi
done
echo ""

# HTTP check
for host in "${TEST_HOSTS[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "https://$host/" 2>/dev/null)
  if [ "$code" -ge 200 ] && [ "$code" -lt 400 ]; then
    ok "  HTTPS $host: ✓ ($code)"
    echo "$host|up|$code" >> "$OUTDIR/http-check.txt"
  else
    err "  HTTPS $host: ✗ ($code)"
    echo "$host|down|$code" >> "$OUTDIR/http-check.txt"
  fi
done
echo ""

# ═══ Phase 5: VPN/Tailscale fallback ═══
log "Phase 5: VPN/Tailscale status"
echo ""

if ifconfig utun10 >/dev/null 2>&1; then
  vpn_gw=$(route -n get -ifscope utun10 default 2>/dev/null | awk '/gateway/{print $2}')
  if ping -c1 -W2 "${vpn_gw:-10.5.0.1}" >/dev/null 2>&1; then
    ok "  Tailscale tunnel: ✓ active (gw: ${vpn_gw:-10.5.0.1})"
    # Can we reach internet via tailscale?
    if curl -s --max-time 5 --interface utun10 https://ifconfig.me >/dev/null 2>&1; then
      ok "  Tailscale internet: ✓ (exit node working)"
    else
      warn "  Tailscale internet: ✗ (tunnel up but no exit node)"
    fi
  else
    err "  Tailscale tunnel: ✗ down"
  fi
else
  warn "  No VPN tunnel detected"
fi
echo ""

# ═══ Phase 6: Workaround assessment ═══
log "Phase 6: Workaround assessment"
echo ""

INTERNET=false
VPN_OK=false
ISP_OK=false
DNS_OK=false

# Check results
grep -q "|up|" "$OUTDIR/http-check.txt" 2>/dev/null && INTERNET=true
grep -q "utun.*active" "$OUTDIR/diag.log" 2>/dev/null && VPN_OK=true
grep -q "|up|" "$OUTDIR/isp-hops.txt" 2>/dev/null && ISP_OK=true
grep -q "|up|" "$OUTDIR/dns-check.txt" 2>/dev/null && DNS_OK=true

if $INTERNET; then
  ok "  Internet: WORKING — no workaround needed"
else
  err "  Internet: DOWN"
  echo ""
  if $VPN_OK; then
    ok "  → Workaround: route traffic via Tailscale exit node"
    echo "    sudo route delete default"
    echo "    sudo route add default 10.5.0.1"
  fi
  if $ISP_OK && ! $INTERNET; then
    warn "  → ISP infra reachable but internet down = ISP upstream issue"
    warn "    Provider gateway responds, problem is beyond their edge"
  fi
  if $DNS_OK && ! $INTERNET; then
    warn "  → DNS works but HTTP fails = possible routing/peering issue"
    warn "    Try: curl --resolve host:443:IP to bypass DNS"
  fi
  if ! $ISP_OK && ! $INTERNET; then
    err "  → ISP gateway dead = local loop or fiber issue"
    err "    Check ONT/modem lights, restart modem, call KPN"
  fi
fi

# ═══ Summary ═══
echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           DIAGNOSTIC COMPLETE                 ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
ok "Results: $OUTDIR/"
echo "    traceroute.txt — path to internet"
echo "    isp-hops.txt   — ISP infrastructure status"
echo "    dns-check.txt  — DNS server status"
echo "    http-check.txt — HTTP reachability"
echo "    diag.log       — full log"
