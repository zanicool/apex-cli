#!/bin/bash
# Apex CLI — Internet Infrastructure Health Map
# Probes root DNS, AMS-IX, Dutch ISPs, global CDN/cloud from your perspective.
# Logs everything so you know what's reachable when things break.
set -uo pipefail

OUTDIR="./output/infra-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"
LOG="$OUTDIR/infra.log"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { printf "  \033[32m✓\033[0m %-18s %5s  %s\n" "$1" "$2" "$3" | tee -a "$LOG"; }
fail() { printf "  \033[31m✗\033[0m %-18s %5s  %s\n" "$1" "DOWN" "$2" | tee -a "$LOG"; }

probe() {
  local ip="$1" name="$2"
  local ms=""
  # TCP probe on common ports (works through VPN/NAT), then ICMP fallback
  for port in 53 80 443; do
    ms=$(nc_time "$ip" "$port")
    [ -n "$ms" ] && break
  done
  if [ -z "$ms" ]; then
    ms=$(ping -c1 -W2 "$ip" 2>/dev/null | grep -oE "time=[0-9.]+" | cut -d= -f2)
  fi
  if [ -n "$ms" ]; then
    ok "$ip" "${ms}ms" "$name"
    echo "$ip|up|${ms}ms|$name" >> "$OUTDIR/results.txt"
  else
    fail "$ip" "$name"
    echo "$ip|down||$name" >> "$OUTDIR/results.txt"
  fi
}

# Measure TCP connect time in ms
nc_time() {
  local ip="$1" port="$2"
  local start end
  start=$(python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null)
  if nc -z -w2 -G2 "$ip" "$port" 2>/dev/null; then
    end=$(python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null)
    echo $(( end - start ))
  fi
}

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Internet Infrastructure Health Map    ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
log "Output: $OUTDIR"
log "Time:   $(date)"
log "Method: TCP probe (ports 53/80/443) + ICMP fallback"
echo "" | tee -a "$LOG"

# ═══════════════════════════════════════════════════════
log "── ROOT DNS SERVERS (13 stuks, basis van het internet) ──"
echo "" | tee -a "$LOG"
probe "198.41.0.4"      "a.root-servers.net (Verisign, USA)"
probe "199.9.14.201"    "b.root-servers.net (USC-ISI, USA)"
probe "192.33.4.12"     "c.root-servers.net (Cogent, USA)"
probe "199.7.91.13"     "d.root-servers.net (U Maryland, USA)"
probe "192.203.230.10"  "e.root-servers.net (NASA, USA)"
probe "192.5.5.241"     "f.root-servers.net (ISC, USA)"
probe "192.112.36.4"    "g.root-servers.net (US DoD, USA)"
probe "198.97.190.53"   "h.root-servers.net (US Army, USA)"
probe "192.36.148.17"   "i.root-servers.net (Netnod, SWEDEN)"
probe "192.58.128.30"   "j.root-servers.net (Verisign, USA)"
probe "193.0.14.129"    "k.root-servers.net (RIPE NCC, AMSTERDAM)"
probe "199.7.83.42"     "l.root-servers.net (ICANN, USA)"
probe "202.12.27.33"    "m.root-servers.net (WIDE, JAPAN)"

echo "" | tee -a "$LOG"
log "── .NL TLD SERVERS (SIDN, Arnhem) ──"
echo "" | tee -a "$LOG"
probe "194.0.28.53"     "ns1.dns.nl (SIDN Arnhem)"
probe "194.0.29.53"     "ns2.dns.nl (SIDN Arnhem)"
probe "194.0.30.53"     "ns3.dns.nl (SIDN anycast)"
probe "194.0.31.53"     "ns4.dns.nl (SIDN anycast)"

echo "" | tee -a "$LOG"
log "── AMS-IX (Amsterdam Internet Exchange) ──"
echo "" | tee -a "$LOG"
probe "80.249.208.1"    "ams-ix route-server rtr-dr1"
probe "80.249.209.1"    "ams-ix route-server rtr-glo"
probe "80.249.210.1"    "ams-ix route-server 3"
probe "80.249.211.1"    "ams-ix route-server 4"

echo "" | tee -a "$LOG"
log "── NL-IX (Netherlands Internet Exchange) ──"
echo "" | tee -a "$LOG"
probe "193.239.116.1"   "nl-ix route-server"
probe "193.239.117.1"   "nl-ix route-server 2"

echo "" | tee -a "$LOG"
log "── JOUW ISP: Trined/Packethub → Worldstream ──"
echo "" | tee -a "$LOG"
probe "91.214.67.2"     "trined edge-1 (jouw ISP gateway)"
probe "91.214.67.3"     "trined edge-2 (jouw ISP gateway)"
probe "109.236.95.105"  "worldstream bb11-ams3 (backbone Amsterdam)"
probe "109.236.95.107"  "worldstream bb11-ams3-2 (backbone Amsterdam)"
probe "109.236.95.178"  "worldstream bb02-nldw (backbone Waalwijk)"
probe "109.236.95.182"  "worldstream bb01-nldw (backbone Waalwijk)"
probe "109.236.95.144"  "worldstream peering router"

echo "" | tee -a "$LOG"
log "── KPN (grootste NL ISP) ──"
echo "" | tee -a "$LOG"
probe "195.121.1.34"    "kpn dns-1"
probe "195.121.1.66"    "kpn dns-2"
probe "213.75.0.1"      "kpn core router"
probe "195.190.228.1"   "kpn backbone"
probe "213.75.63.1"     "kpn peering"

echo "" | tee -a "$LOG"
log "── Ziggo / VodafoneZiggo ──"
echo "" | tee -a "$LOG"
probe "62.179.104.196"  "ziggo dns-1"
probe "62.179.104.197"  "ziggo dns-2"
probe "212.54.40.25"    "ziggo core"
probe "62.179.0.1"      "ziggo backbone"

echo "" | tee -a "$LOG"
log "── T-Mobile NL ──"
echo "" | tee -a "$LOG"
probe "80.57.0.1"       "t-mobile dns-1"
probe "80.57.0.2"       "t-mobile dns-2"

echo "" | tee -a "$LOG"
log "── XS4ALL / Freedom (KPN dochter) ──"
echo "" | tee -a "$LOG"
probe "194.109.6.66"    "xs4all dns-1"
probe "194.109.9.99"    "xs4all dns-2"
probe "194.109.0.1"     "xs4all core"

echo "" | tee -a "$LOG"
log "── Nederlandse Datacenters ──"
echo "" | tee -a "$LOG"
probe "109.236.80.1"    "worldstream DC (Naaldwijk)"
probe "178.162.128.1"   "leaseweb AMS"
probe "85.17.0.1"       "leaseweb core"
probe "149.210.128.1"   "transip DC"
probe "37.97.128.1"     "transip/team.blue"
probe "185.56.40.1"     "nforce entertainment"
probe "46.21.96.1"      "i3d.net (Rotterdam)"
probe "89.188.0.1"      "bit.nl (Ede)"
probe "83.149.64.1"     "true (Amsterdam)"
probe "141.138.128.1"   "greenhost (Amsterdam)"

echo "" | tee -a "$LOG"
log "── Cloudflare (anycast, AMS PoP) ──"
echo "" | tee -a "$LOG"
probe "1.1.1.1"         "cloudflare dns primary"
probe "1.0.0.1"         "cloudflare dns secondary"
probe "104.16.0.1"      "cloudflare CDN"
probe "172.64.0.1"      "cloudflare edge"

echo "" | tee -a "$LOG"
log "── Google (anycast, AMS PoP) ──"
echo "" | tee -a "$LOG"
probe "8.8.8.8"         "google dns primary"
probe "8.8.4.4"         "google dns secondary"
probe "216.239.32.10"   "google ns1"
probe "216.239.34.10"   "google ns2"
probe "142.250.179.1"   "google frontend AMS"
probe "74.125.242.187"  "google peering (jouw route)"
probe "74.125.243.133"  "google peering 2 (jouw route)"

echo "" | tee -a "$LOG"
log "── Microsoft / Azure (AMS region) ──"
echo "" | tee -a "$LOG"
probe "13.107.42.14"    "microsoft edge"
probe "204.79.197.200"  "bing.com"
probe "40.112.72.205"   "azure westeurope"
probe "52.232.0.1"      "azure NL"

echo "" | tee -a "$LOG"
log "── AWS (eu-west-1 Ireland, eu-central-1 Frankfurt) ──"
echo "" | tee -a "$LOG"
probe "52.94.76.1"      "aws eu-west-1 (Ireland)"
probe "54.239.28.85"    "aws cloudfront EU"
probe "3.120.0.1"       "aws eu-central-1 (Frankfurt)"

echo "" | tee -a "$LOG"
log "── Akamai (CDN, AMS PoP) ──"
echo "" | tee -a "$LOG"
probe "23.0.0.1"        "akamai edge"
probe "104.64.0.1"      "akamai CDN"

echo "" | tee -a "$LOG"
log "── Meta / Facebook ──"
echo "" | tee -a "$LOG"
probe "157.240.1.35"    "facebook edge"
probe "31.13.64.35"     "facebook EU"

echo "" | tee -a "$LOG"
log "── Quad9 / OpenDNS / andere DNS ──"
echo "" | tee -a "$LOG"
probe "9.9.9.9"         "quad9 dns (privacy)"
probe "208.67.222.222"  "opendns (Cisco)"
probe "208.67.220.220"  "opendns secondary"
probe "185.228.168.9"   "cleanbrowsing dns"
probe "76.76.2.0"       "controld dns"

# ═══ Summary ═══
echo "" | tee -a "$LOG"
echo "  ════════════════════════════════════════════════" | tee -a "$LOG"
UP="$(grep -c "|up|" "$OUTDIR/results.txt" || true)"
DOWN="$(grep -c "|down|" "$OUTDIR/results.txt" || true)"
TOTAL=$((UP + DOWN))
log "TOTAAL: $UP/$TOTAL bereikbaar, $DOWN onbereikbaar"
echo "" | tee -a "$LOG"
log "Resultaten: $OUTDIR/results.txt"
log "Log:        $LOG"

# Show what's down (the interesting part)
if [ "$DOWN" -gt 0 ]; then
  echo "" | tee -a "$LOG"
  log "── ONBEREIKBAAR ──"
  grep "|down|" "$OUTDIR/results.txt" | while IFS='|' read -r ip _ _ name; do
    printf "  ✗ %-18s %s\n" "$ip" "$name" | tee -a "$LOG"
  done
fi
