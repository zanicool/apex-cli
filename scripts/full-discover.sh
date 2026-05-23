#!/bin/bash
# Apex CLI — Full Network & IoT Discovery (resumable)
# State is logged to $OUTDIR/state.log so we can resume after crash.
set -uo pipefail

OUTDIR="${1:-./output/discover-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
STATE="$OUTDIR/state.log"
LOGFILE="$OUTDIR/run.log"
START_TIME=$SECONDS
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUI_DB="$SCRIPT_DIR/../data/iot-oui.db"

# ─── Helpers ───
log() { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOGFILE"; }
ok() { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOGFILE"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOGFILE"; }
step_done() { grep -qxF "$1" "$STATE" 2>/dev/null; }
mark_done() { echo "$1" >>"$STATE"; }
has() { command -v "$1" >/dev/null 2>&1; }

spin() {
  local pid=$1 msg="${2:-working}"
  local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  %s %s..." "${chars:i++%${#chars}:1}" "$msg"
    sleep 0.2
  done
  printf "\r  ✓ %s done\n" "$msg"
}

# ─── Detect network ───
LAN_IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | grep -E "10\.|192\.168\." | awk '{print $2}' | head -1)
SUBNET="${LAN_IP%.*}.0/24"

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Full Network & IoT Discovery          ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
log "Subnet: $SUBNET | Output: $OUTDIR"
[ -f "$STATE" ] && warn "Resuming — $(wc -l <"$STATE" | tr -d ' ') steps done"
echo ""

# ═══ PHASE 1: Host Discovery ═══
if ! step_done "hosts"; then
  log "Phase 1: Host discovery on $SUBNET"
  nmap -sn -T5 "$SUBNET" -oG "$OUTDIR/hosts.txt" 2>/dev/null &
  spin $! "scanning $SUBNET"
  wait $!
  mark_done "hosts"
fi
HOSTS=$(grep "Up" "$OUTDIR/hosts.txt" 2>/dev/null | awk '{print $2}')
HOST_COUNT=$(echo "$HOSTS" | grep -c . 2>/dev/null || echo 0)
ok "Live hosts: $HOST_COUNT"
echo ""

# ═══ PHASE 2: Port Scan ═══
log "Phase 2: Port scanning"
CURRENT=0
for host in $HOSTS; do
  CURRENT=$((CURRENT + 1))
  if ! step_done "ports:$host"; then
    printf "  [%d/%d] %s " "$CURRENT" "$HOST_COUNT" "$host" | tee -a "$LOGFILE"
    nmap -p 80,443,8080,8443,8000,3000,5000,9090,38899,1883 -T5 --open --host-timeout 10s "$host" \
      -oG "$OUTDIR/ports-$host.txt" 2>/dev/null &
    spin $! "ports $host"
    wait $!
    open=$(grep -c "open" "$OUTDIR/ports-$host.txt" 2>/dev/null || echo 0)
    echo "    → $open open" | tee -a "$LOGFILE"
    mark_done "ports:$host"
  fi
done
echo ""

# ═══ PHASE 3: IoT OUI Fingerprinting ═══
if ! step_done "iot-oui"; then
  log "Phase 3: IoT OUI fingerprinting"
  if [ ! -f "$OUI_DB" ]; then
    warn "OUI database not found: $OUI_DB"
  else
    arp -an 2>/dev/null | grep -v "incomplete\|ff:ff:ff" | while read -r line; do
      ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
      mac=$(echo "$line" | grep -oE '([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}')
      [ -z "$ip" ] || [ -z "$mac" ] && continue
      oui=$(echo "$mac" | tr -d ':' | cut -c1-6 | tr '[:lower:]' '[:upper:]')
      match=$(grep "^$oui" "$OUI_DB" 2>/dev/null | head -1)
      if [ -n "$match" ]; then
        vendor=$(echo "$match" | cut -d'|' -f2)
        device=$(echo "$match" | cut -d'|' -f3)
        echo "$ip|$mac|$vendor|$device" >>"$OUTDIR/iot-found.txt"
        printf "  ✓ %-15s %-18s %s %s\n" "$ip" "$mac" "$vendor" "$device" | tee -a "$LOGFILE"
      fi
    done
  fi
  mark_done "iot-oui"
fi
echo ""

# ═══ PHASE 4: IoT Protocol Probing ═══
log "Phase 4: IoT protocol probing"
CURRENT=0
for host in $HOSTS; do
  CURRENT=$((CURRENT + 1))
  if ! step_done "proto:$host"; then
    printf "  [%d/%d] %s " "$CURRENT" "$HOST_COUNT" "$host" | tee -a "$LOGFILE"

    # WiZ (UDP 38899)
    resp=$(echo '{"method":"getPilot","params":{}}' | nc -u -w1 "$host" 38899 2>/dev/null || true)
    [ -n "$resp" ] && echo "$host|wiz|$resp" >>"$OUTDIR/proto-found.txt" && log "WiZ!"

    # Shelly
    resp=$(curl -s --max-time 2 "http://$host/shelly" 2>/dev/null || true)
    echo "$resp" | grep -q "type\|mac\|fw" 2>/dev/null && echo "$host|shelly|$resp" >>"$OUTDIR/proto-found.txt"

    # Tasmota
    resp=$(curl -s --max-time 2 "http://$host/cm?cmnd=Status%200" 2>/dev/null || true)
    echo "$resp" | grep -q "StatusSTS\|Module" 2>/dev/null && echo "$host|tasmota|$resp" >>"$OUTDIR/proto-found.txt"

    # Hue Bridge
    resp=$(curl -s --max-time 2 "http://$host/api/config" 2>/dev/null || true)
    echo "$resp" | grep -q "bridgeid" 2>/dev/null && echo "$host|hue|$resp" >>"$OUTDIR/proto-found.txt"

    echo "" | tee -a "$LOGFILE"
    mark_done "proto:$host"
  fi
done
echo ""

# ═══ PHASE 5: mDNS + SSDP ═══
if ! step_done "mdns"; then
  log "Phase 5: mDNS & SSDP"
  for svc in _hap._tcp _googlecast._tcp _airplay._tcp _hue._tcp; do
    timeout 3 dns-sd -B "$svc" local. 2>/dev/null | grep "Add" >>"$OUTDIR/mdns.txt" 2>/dev/null || true
  done
  printf "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n" |
    nc -u -w3 239.255.255.250 1900 >"$OUTDIR/ssdp.txt" 2>/dev/null || true
  mark_done "mdns"
fi
echo ""

# ═══ PHASE 6: Apex vuln scan ═══
APEX="$SCRIPT_DIR/../build/apex-cli"
if [ -x "$APEX" ]; then
  log "Phase 6: Vulnerability scanning"
  for host in $HOSTS; do
    grep -oE "[0-9]+/open/tcp//http" "$OUTDIR/ports-$host.txt" 2>/dev/null | cut -d/ -f1 | while read -r port; do
      target="http://$host:$port"
      step="apex:$target"
      if ! step_done "$step"; then
        log "  → $target"
        tdir="$OUTDIR/${target//[:\\/]/_}"
        mkdir -p "$tdir"
        "$APEX" "$target" --smart --confidence 2 --output "$tdir" >>"$LOGFILE" 2>&1 || true
        mark_done "$step"
      fi
    done
  done
else
  warn "apex-cli not found — skipping vuln scan"
fi
echo ""

# ═══ SUMMARY ═══
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           DISCOVERY COMPLETE                  ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
ok "Hosts:       $HOST_COUNT"
ok "IoT (OUI):   $(wc -l <"$OUTDIR/iot-found.txt" 2>/dev/null | tr -d ' ' || echo 0)"
ok "IoT (proto): $(wc -l <"$OUTDIR/proto-found.txt" 2>/dev/null | tr -d ' ' || echo 0)"
ok "Elapsed:     $(((SECONDS - START_TIME) / 60))m $(((SECONDS - START_TIME) % 60))s"
ok "Output:      $OUTDIR/"
ok "State:       $STATE ($(wc -l <"$STATE" | tr -d ' ') checkpoints)"
echo ""
log "Resume: $0 $OUTDIR"
