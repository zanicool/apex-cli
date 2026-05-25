#!/bin/bash
# Apex CLI — IoT Protocol Discovery (WiZ, Tasmota, Shelly, Tuya, HomeKit, etc.)
set -uo pipefail

OUTDIR="./output/iot-proto-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

log() { echo -e "\033[1;34m[*]\033[0m $*"; }
ok() { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }

LAN_IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | grep -E "10\.0\.|192\.168\." | awk '{print $2}' | head -1)
SUBNET="${LAN_IP%.*}"

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — IoT Protocol Discovery                ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
log "Subnet: ${SUBNET}.0/24"
echo ""

# Collect all LAN IPs from ARP
HOSTS=$(arp -an 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep "^${SUBNET}\." | sort -t. -k4 -n | uniq | grep -v "\.255$")

# ─── 1. WiZ Bulbs (UDP 38899) ───
log "Probing WiZ protocol (UDP 38899)..."
for ip in $HOSTS; do
  resp=$(echo '{"method":"getPilot","params":{}}' | nc -u -w1 "$ip" 38899 2>/dev/null)
  [ -n "$resp" ] && echo "  ✓ WiZ bulb: $ip → $resp" && echo "$ip|wiz|$resp" >>"$OUTDIR/found.txt"
done
# Also try registration broadcast
echo '{"method":"registration","params":{"phoneMac":"AAAAAAAAAAAA","register":false,"phoneIp":"'"$LAN_IP"'"}}' | nc -u -w2 "${SUBNET}.255" 38899 >"$OUTDIR/wiz-broadcast.txt" 2>/dev/null || true
[ -s "$OUTDIR/wiz-broadcast.txt" ] && echo "  ✓ WiZ broadcast response" && cat "$OUTDIR/wiz-broadcast.txt"
grep -q "wiz" "$OUTDIR/found.txt" 2>/dev/null || echo "  (no WiZ responses)"
echo ""

# ─── 2. Shelly (HTTP /shelly) ───
log "Probing Shelly (HTTP /shelly)..."
for ip in $HOSTS; do
  resp=$(curl -s --max-time 1 "http://$ip/shelly" 2>/dev/null)
  if echo "$resp" | grep -q "type\|mac\|fw"; then
    echo "  ✓ Shelly: $ip → $resp"
    echo "$ip|shelly|$resp" >>"$OUTDIR/found.txt"
  fi
done &
SHELLY_PID=$!

# ─── 3. Tasmota (HTTP /cm?cmnd=Status) ───
log "Probing Tasmota (HTTP /cm)..."
for ip in $HOSTS; do
  resp=$(curl -s --max-time 1 "http://$ip/cm?cmnd=Status%200" 2>/dev/null)
  if echo "$resp" | grep -q "StatusSTS\|Module\|FriendlyName"; then
    echo "  ✓ Tasmota: $ip → $(echo "$resp" | grep -oE '"FriendlyName":\[[^]]+\]' | head -1)"
    echo "$ip|tasmota|$resp" >>"$OUTDIR/found.txt"
  fi
done &
TASMOTA_PID=$!

wait $SHELLY_PID 2>/dev/null
wait $TASMOTA_PID 2>/dev/null
grep -q "shelly" "$OUTDIR/found.txt" 2>/dev/null || echo "  (no Shelly responses)"
grep -q "tasmota" "$OUTDIR/found.txt" 2>/dev/null || echo "  (no Tasmota responses)"
echo ""

# ─── 4. ESPHome (HTTP /text_sensor/ or /light/) ───
log "Probing ESPHome..."
for ip in $HOSTS; do
  resp=$(curl -s --max-time 1 "http://$ip/" 2>/dev/null | head -3)
  if echo "$resp" | grep -qi "esphome"; then
    echo "  ✓ ESPHome: $ip"
    echo "$ip|esphome|$resp" >>"$OUTDIR/found.txt"
  fi
done
grep -q "esphome" "$OUTDIR/found.txt" 2>/dev/null || echo "  (no ESPHome responses)"
echo ""

# ─── 5. Philips Hue Bridge (HTTP /api/config) ───
log "Probing Hue Bridge..."
for ip in $HOSTS; do
  resp=$(curl -s --max-time 1 "http://$ip/api/config" 2>/dev/null)
  if echo "$resp" | grep -q "bridgeid\|modelid"; then
    model=$(echo "$resp" | grep -oE '"modelid":"[^"]+"')
    sw=$(echo "$resp" | grep -oE '"swversion":"[^"]+"')
    echo "  ✓ Hue Bridge: $ip — $model $sw"
    echo "$ip|hue|$resp" >>"$OUTDIR/found.txt"
  fi
done
grep -q "hue" "$OUTDIR/found.txt" 2>/dev/null || echo "  (no Hue Bridge)"
echo ""

# ─── 6. mDNS service discovery ───
log "mDNS discovery (4s)..."
for svc in _hap._tcp _wiz._tcp _hue._tcp _googlecast._tcp _spotify-connect._tcp _airplay._tcp _esphomelib._tcp; do
  results=$(timeout 2 dns-sd -B "$svc" local. 2>/dev/null | grep "Add" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}')
  if [ -n "$results" ]; then
    echo "  📡 $svc:"
    echo "$results" | while read -r name; do
      [ -n "$name" ] && echo "      $name"
    done
    echo "$svc|$results" >>"$OUTDIR/mdns.txt"
  fi
done
echo ""

# ─── 7. SSDP/UPnP ───
log "SSDP/UPnP discovery..."
SSDP=$(printf "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n" | nc -u -w3 239.255.255.250 1900 2>/dev/null || true)
if [ -n "$SSDP" ]; then
  echo "$SSDP" >"$OUTDIR/ssdp.txt"
  echo "$SSDP" | grep -iE "location|server" | sort -u | while read -r line; do
    echo "  $line"
  done
else
  echo "  (no SSDP responses)"
fi
echo ""

# ─── Summary ───
log "═══ RESULTS ═══"
echo ""
if [ -f "$OUTDIR/found.txt" ]; then
  while IFS='|' read -r ip proto data; do
    printf "  %-14s %-10s %s\n" "$ip" "$proto" "$(echo "$data" | grep -oE '"(type|fw|FriendlyName|modelid|swversion)"[[:space:]]*:[[:space:]]*"?[^",}]+"?' | tr '\n' ' ' | head -c 80)"
  done <"$OUTDIR/found.txt"
else
  echo "  No IoT protocols detected on probed hosts."
  echo "  Devices may use cloud-only protocols (Tuya Cloud, WiZ Cloud)."
fi
echo ""
ok "Results: $OUTDIR/"
