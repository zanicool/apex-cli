#!/bin/bash
# Apex CLI — Network Discovery & Sniffing Wrapper
# Unified interface for nmap, arp-scan, masscan, netdiscover, tcpdump.
set -euo pipefail

OUTDIR="${APEX_OUTPUT:-./output/network}"
IFACE="${APEX_IFACE:-$(route get default 2>/dev/null | awk '/interface:/{print $2}' || echo "eth0")}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [options]

Commands:
  hosts [subnet]       Discover live hosts (arp-scan → nmap fallback)
  ports <target>       Port scan target (masscan → nmap fallback)
  services <target>    Service/version detection (nmap -sV)
  sniff [filter]       Packet capture (tcpdump)
  passive              Passive ARP discovery (netdiscover)
  full [subnet]        Full discovery: hosts → ports → services
  tools                Show available tools

Options:
  -i <iface>     Interface (default: $IFACE)
  -o <dir>       Output directory (default: $OUTDIR)
  -t <seconds>   Timeout (default: 30)
  -r <rate>      Packets/sec for masscan (default: 1000)

Examples:
  $(basename "$0") hosts 192.168.1.0/24
  $(basename "$0") ports 192.168.1.1
  $(basename "$0") sniff "port 80 or port 443"
  $(basename "$0") full 192.168.1.0/24
EOF
  exit 1
}

log() { echo -e "\033[1;34m[*]\033[0m $*"; }
ok() { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err() { echo -e "\033[1;31m[-]\033[0m $*" >&2; }

has() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "$1 requires root. Re-run with sudo."
    exit 1
  fi
}

local_subnet() {
  if has ip; then
    ip -4 route | awk '/src/{print $1; exit}'
  elif has ifconfig; then
    local ip
    ip=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2}')
    echo "${ip%.*}.0/24"
  else
    echo "192.168.1.0/24"
  fi
}

# Parse global options
TIMEOUT=30
RATE=1000
while getopts "i:o:t:r:" opt 2>/dev/null; do
  case $opt in
  i) IFACE="$OPTARG" ;;
  o) OUTDIR="$OPTARG" ;;
  t) TIMEOUT="$OPTARG" ;;
  r) RATE="$OPTARG" ;;
  *) ;;
  esac
done
shift $((OPTIND - 1))

CMD="${1:-}"
shift 2>/dev/null || true
mkdir -p "$OUTDIR"

cmd_tools() {
  echo "Network discovery tools:"
  for tool in nmap masscan arp-scan netdiscover tcpdump; do
    if has "$tool"; then
      printf "  ✓ %-15s %s\n" "$tool" "$(which "$tool")"
    else
      printf "  ✗ %-15s not installed\n" "$tool"
    fi
  done
}

cmd_hosts() {
  local subnet="${1:-$(local_subnet)}"
  log "Discovering hosts on $subnet (iface: $IFACE)"

  if has arp-scan; then
    need_root "arp-scan"
    local out="$OUTDIR/hosts-arp.txt"
    arp-scan --interface="$IFACE" "$subnet" | tee "$out"
    ok "Saved: $out"
  elif has nmap; then
    local out="$OUTDIR/hosts-nmap.txt"
    nmap -sn "$subnet" -oG "$out"
    grep "Up" "$out" | awk '{print $2}'
    ok "Saved: $out"
  else
    err "Need arp-scan or nmap. Install: brew install arp-scan nmap"
    exit 1
  fi
}

cmd_ports() {
  local target="${1:?target required}"
  log "Scanning ports on $target"

  if has masscan; then
    need_root "masscan"
    local out="$OUTDIR/ports-masscan.txt"
    masscan "$target" -p1-65535 --rate="$RATE" --wait=3 -oL "$out"
    grep "^open" "$out" | awk '{print $3"/"$4}'
    ok "Saved: $out"
  elif has nmap; then
    local out="$OUTDIR/ports-nmap.xml"
    nmap -p- --min-rate="$RATE" -T4 "$target" -oX "$out"
    ok "Saved: $out"
  else
    err "Need masscan or nmap. Install: brew install masscan nmap"
    exit 1
  fi
}

cmd_services() {
  local target="${1:?target required}"
  log "Service detection on $target"

  if ! has nmap; then
    err "Need nmap. Install: brew install nmap"
    exit 1
  fi

  local out="$OUTDIR/services-$target.xml"
  nmap -sV -sC --top-ports 1000 -T4 "$target" -oX "$out"
  ok "Saved: $out"
}

cmd_sniff() {
  local filter="${*:-}"
  log "Sniffing on $IFACE ${filter:+(filter: $filter)}"

  if ! has tcpdump; then
    err "Need tcpdump. Install: brew install tcpdump"
    exit 1
  fi

  need_root "tcpdump"
  local out
  out="$OUTDIR/capture-$(date +%s).pcap"
  log "Writing to $out (Ctrl+C to stop)"
  tcpdump -i "$IFACE" -w "$out" ${filter:+$filter}
  ok "Saved: $out"
}

cmd_passive() {
  log "Passive ARP discovery on $IFACE"

  if has netdiscover; then
    need_root "netdiscover"
    local out="$OUTDIR/passive-arp.txt"
    log "Listening for $TIMEOUT seconds..."
    timeout "$TIMEOUT" netdiscover -i "$IFACE" -p -P >"$out" 2>/dev/null || true
    cat "$out"
    ok "Saved: $out"
  elif has tcpdump; then
    need_root "tcpdump"
    local out="$OUTDIR/passive-arp.txt"
    log "Capturing ARP for $TIMEOUT seconds..."
    timeout "$TIMEOUT" tcpdump -i "$IFACE" -nn arp -l 2>/dev/null | tee "$out" || true
    ok "Saved: $out"
  else
    err "Need netdiscover or tcpdump."
    exit 1
  fi
}

cmd_full() {
  local subnet="${1:-$(local_subnet)}"
  log "Full network discovery: $subnet"

  # Phase 1: Host discovery
  log "Phase 1/3: Host discovery"
  local hosts
  if has nmap; then
    nmap -sn "$subnet" -oG "$OUTDIR/hosts.txt" >/dev/null
    hosts=$(grep "Up" "$OUTDIR/hosts.txt" | awk '{print $2}')
  else
    err "Need nmap for full scan"
    exit 1
  fi

  local count
  count=$(echo "$hosts" | grep -c . || echo 0)
  ok "Found $count live hosts"

  # Phase 2: Port scan each host
  log "Phase 2/3: Port scanning"
  for host in $hosts; do
    nmap -p- --min-rate="$RATE" -T4 "$host" -oG "$OUTDIR/ports-$host.txt" >/dev/null
    local open
    open=$(grep -c "open" "$OUTDIR/ports-$host.txt" 2>/dev/null || echo 0)
    echo "  $host: $open open ports"
  done

  # Phase 3: Service detection on hosts with open ports
  log "Phase 3/3: Service detection"
  for host in $hosts; do
    nmap -sV --top-ports 100 -T4 "$host" -oX "$OUTDIR/services-$host.xml" >/dev/null
  done

  ok "Full scan complete. Results in $OUTDIR/"
}

case "$CMD" in
hosts) cmd_hosts "$@" ;;
ports) cmd_ports "$@" ;;
services) cmd_services "$@" ;;
sniff) cmd_sniff "$@" ;;
passive) cmd_passive "$@" ;;
full) cmd_full "$@" ;;
tools) cmd_tools ;;
*) usage ;;
esac
