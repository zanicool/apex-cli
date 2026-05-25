#!/bin/bash
# Apex CLI — WiZ Lamp Discovery
# Finds WiZ smart bulbs via OUI + UDP 38899 + broadcast
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUI_DB="$SCRIPT_DIR/../data/iot-oui.db"

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — WiZ Lamp Finder                       ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""

LAN_IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v "127.0.0.1" | grep -E "10\.|192\.168\." | awk '{print $2}' | head -1)
SUBNET="${LAN_IP%.*}"
echo "[*] Subnet: ${SUBNET}.0/24"
echo ""

# Step 1: Broadcast registration to wake WiZ devices
echo "[*] Broadcasting WiZ registration..."
MAC=$(ifconfig en0 2>/dev/null | grep ether | awk '{print $2}' | tr -d ':')
echo "{\"method\":\"registration\",\"params\":{\"phoneMac\":\"${MAC:-AAAAAAAAAAAA}\",\"register\":true,\"phoneIp\":\"$LAN_IP\"}}" |
  nc -u -w2 "${SUBNET}.255" 38899 >/dev/null 2>&1 || true
sleep 1

# Step 2: Python UDP sweep (nc on macOS can't reliably receive UDP responses)
echo "[*] Sweeping ${SUBNET}.1-254 on UDP 38899..."
echo ""

python3 -c "
import socket, json, time, select

PORT = 38899
SUBNET = '$SUBNET'
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setblocking(False)
sock.bind(('0.0.0.0', 0))

pilot = json.dumps({'method':'getPilot','params':{}}).encode()
for i in range(1, 255):
    sock.sendto(pilot, (f'{SUBNET}.{i}', PORT))

found = []
deadline = time.time() + 5
while time.time() < deadline:
    ready = select.select([sock], [], [], 0.5)
    if ready[0]:
        try:
            data, addr = sock.recvfrom(1024)
            d = json.loads(data)
            r = d.get('result', {})
            found.append(addr[0])
            state = 'ON' if r.get('state') else 'OFF'
            dim = r.get('dimming', '?')
            temp = r.get('temp', '?')
            print(f'  ✓ #{len(found):<2} {addr[0]:15s} {state:3s}  dim={dim}%  temp={temp}K')
        except Exception:
            pass

print(f'')
print(f'════════════════════════════════════════')
print(f'  TOTAAL WiZ LAMPEN: {len(found)}')
print(f'════════════════════════════════════════')
sock.close()
" 2>&1

# Step 3: Also show OUI matches for context
if [ -f "$OUI_DB" ]; then
  echo ""
  echo "[*] Espressif/Shenzhen devices in ARP (potential WiZ):"
  arp -an 2>/dev/null | grep -v "incomplete" | while read -r line; do
    mac=$(echo "$line" | grep -oE '([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}')
    [ -z "$mac" ] && continue
    oui=$(echo "$mac" | tr -d ':' | cut -c1-6 | tr '[:lower:]' '[:upper:]')
    if echo "$oui" | grep -qE "^(240AC4|BCDDC2|245A4C|7CDFA1|D8BFC0|C44F33|DC4F22|F4928B|F492BF)$"; then
      ip=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
      printf "  · %-15s %s\n" "$ip" "$mac"
    fi
  done
fi
