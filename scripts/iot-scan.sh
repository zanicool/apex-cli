#!/bin/bash
# Apex CLI — IoT Device Fingerprinter
# Identifies IoT devices by OUI, mDNS, HTTP banners
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUI_DB="$SCRIPT_DIR/../data/iot-oui.db"
OUTDIR="./output/iot-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

log() { echo -e "\033[1;34m[*]\033[0m $*"; }
ok() { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }

if [ ! -f "$OUI_DB" ]; then
  echo "Error: OUI database not found at $OUI_DB" >&2
  exit 1
fi

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — IoT Fingerprinter                     ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

# ─── Step 1: OUI lookup from ARP table ───
log "Step 1: OUI fingerprinting from ARP table..."
echo ""
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
    printf "  ✓ %-15s %-18s %s %s\n" "$ip" "$mac" "$vendor" "$device"
  fi
done

IOT_COUNT=$(wc -l <"$OUTDIR/iot-found.txt" 2>/dev/null | tr -d ' ' || echo 0)
echo ""
ok "Identified $IOT_COUNT IoT devices"

# ─── Step 2: HTTP banner grab for firmware ───
echo ""
log "Step 2: Firmware detection via HTTP..."
if [ -f "$OUTDIR/iot-found.txt" ]; then
  while IFS='|' read -r ip mac vendor device; do
    printf "  → %-15s " "$ip"
    for url in "http://$ip/api/config" "http://$ip/shelly" "http://$ip/info" \
      "http://$ip/cm?cmnd=Status%200" "http://$ip/description.xml"; do
      resp=$(curl -s --max-time 2 "$url" 2>/dev/null)
      if [ -n "$resp" ] && [ ${#resp} -gt 5 ]; then
        version=$(echo "$resp" | grep -oiE '"(firmware|version|sw_version|swversion|fw_ver)"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1)
        if [ -n "$version" ]; then
          echo "$version"
          echo "$ip|$vendor|$device|$version|$url" >>"$OUTDIR/iot-versions.txt"
          break
        fi
      fi
    done
    grep -q "^$ip|" "$OUTDIR/iot-versions.txt" 2>/dev/null || echo "(no version)"
  done <"$OUTDIR/iot-found.txt"
fi

# ─── Step 3: mDNS ───
echo ""
log "Step 3: mDNS scan (3s per service)..."
for svc in _hap._tcp _hue._tcp _googlecast._tcp _spotify-connect._tcp _airplay._tcp; do
  results=$(timeout 3 dns-sd -B "$svc" local. 2>/dev/null | grep "Add" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}')
  if [ -n "$results" ]; then
    echo "  📡 $svc: $results"
    echo "$svc|$results" >>"$OUTDIR/mdns.txt"
  fi
done

# ─── Summary ───
echo ""
ok "Results: $OUTDIR/"
ok "  iot-found.txt    — $IOT_COUNT devices"
ok "  iot-versions.txt — firmware info"
ok "  mdns.txt         — mDNS services"
