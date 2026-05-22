#!/usr/bin/env bash
# security-digest.sh — Daily/weekly security intelligence digest.
#
# Sources:
#   • CISA KEV (Known Exploited Vulnerabilities)
#   • NVD API (Critical CVEs last 24h/7d)
#   • Hacker News (security posts)
#   • Tweakers.net security
#   • nu.nl tech
#   • YouTube: John Hammond, Fireship, LiveOverflow, NetworkChuck
#   • The Hacker News RSS
#   • Krebs on Security
#
# Usage:
#   ./scripts/security-digest.sh              # Last 24 hours
#   ./scripts/security-digest.sh --week       # Last 7 days
#   ./scripts/security-digest.sh --markdown   # Output as .md file
#   ./scripts/security-digest.sh --cve CVE-2024-1234  # Lookup specific CVE
set -euo pipefail

# Config
PERIOD="1"  # days
FORMAT="terminal"
CVE_LOOKUP=""
OUTPUT_DIR="digests"

for arg in "$@"; do
  case $arg in
    --week) PERIOD=7 ;;
    --markdown) FORMAT="markdown" ;;
    --cve) shift; CVE_LOOKUP="${2:-}"; shift ;;
    --cve=*) CVE_LOOKUP="${arg#*=}" ;;
  esac
done

# Colors (terminal only)
if [ "$FORMAT" = "terminal" ]; then
  R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
  C='\033[0;36m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'
else
  R=''; G=''; Y=''; B=''; C=''; DIM=''; BOLD=''; NC=''
fi

header() { echo -e "\n${BOLD}${B}━━━ $1 ━━━${NC}\n"; }
subheader() { echo -e "${C}▸ $1${NC}"; }

# Date calc
if [[ "$OSTYPE" == "darwin"* ]]; then
  DATE_FROM=$(date -v-${PERIOD}d -u +%Y-%m-%dT00:00:00.000)
  DATE_NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000)
  DATE_DISPLAY=$(date +%Y-%m-%d)
else
  DATE_FROM=$(date -u -d "${PERIOD} days ago" +%Y-%m-%dT00:00:00.000)
  DATE_NOW=$(date -u +%Y-%m-%dT%H:%M:%S.000)
  DATE_DISPLAY=$(date +%Y-%m-%d)
fi

# Markdown output setup
MD_FILE=""
if [ "$FORMAT" = "markdown" ]; then
  mkdir -p "$OUTPUT_DIR"
  MD_FILE="${OUTPUT_DIR}/digest-${DATE_DISPLAY}.md"
  exec > >(tee "$MD_FILE")
  echo "# Security Digest — ${DATE_DISPLAY}"
  echo ""
fi

echo -e "${BOLD}🛡️  Security Digest — ${DATE_DISPLAY} (last ${PERIOD} day(s))${NC}"
echo ""

# ─── CVE Lookup ─────────────────────────────────────────────────────────────
if [ -n "$CVE_LOOKUP" ]; then
  header "CVE Lookup: $CVE_LOOKUP"
  curl -sf "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${CVE_LOOKUP}" 2>/dev/null | \
    python3 -c "
import json,sys
d=json.load(sys.stdin)
for v in d.get('vulnerabilities',[]):
  c=v['cve']
  desc=c['descriptions'][0]['value'] if c.get('descriptions') else 'N/A'
  metrics=c.get('metrics',{})
  score='N/A'
  for k in ['cvssMetricV31','cvssMetricV30','cvssMetricV2']:
    if k in metrics:
      score=str(metrics[k][0]['cvssData']['baseScore'])
      break
  print(f'  ID:       {c[\"id\"]}')
  print(f'  Score:    {score}')
  print(f'  Desc:     {desc[:200]}')
  print(f'  Published: {c.get(\"published\",\"?\")[:10]}')
" 2>/dev/null || echo "  Could not fetch CVE data"
  exit 0
fi

# ─── CISA KEV (Known Exploited Vulnerabilities) ────────────────────────────
header "🚨 CISA KEV — Actively Exploited"
curl -sf "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" 2>/dev/null | \
  python3 -c "
import json,sys
from datetime import datetime,timedelta
d=json.load(sys.stdin)
cutoff=(datetime.now()-timedelta(days=${PERIOD})).strftime('%Y-%m-%d')
recent=[v for v in d.get('vulnerabilities',[]) if v.get('dateAdded','')>=cutoff]
if not recent:
  print('  No new KEV entries in the last ${PERIOD} day(s)')
else:
  for v in recent[:15]:
    print(f'  ${R}[KEV]${NC} {v[\"cveID\"]} — {v[\"vendorProject\"]}/{v[\"product\"]}')
    print(f'        {v[\"shortDescription\"][:100]}')
    print(f'        Due: {v.get(\"dueDate\",\"?\")}')
    print()
" 2>/dev/null || echo "  Could not fetch CISA KEV"

# ─── NVD Critical CVEs ─────────────────────────────────────────────────────
header "🔴 Critical CVEs (CVSS ≥ 9.0)"
curl -sf "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${DATE_FROM}&pubEndDate=${DATE_NOW}&cvssV3Severity=CRITICAL&resultsPerPage=10" 2>/dev/null | \
  python3 -c "
import json,sys
d=json.load(sys.stdin)
vulns=d.get('vulnerabilities',[])
if not vulns:
  print('  No critical CVEs in the last ${PERIOD} day(s)')
else:
  print(f'  {len(vulns)} critical CVEs found:')
  print()
  for v in vulns[:10]:
    c=v['cve']
    desc=(c['descriptions'][0]['value'] if c.get('descriptions') else '')[:100]
    metrics=c.get('metrics',{})
    score='?'
    for k in ['cvssMetricV31','cvssMetricV30']:
      if k in metrics:
        score=str(metrics[k][0]['cvssData']['baseScore'])
        break
    print(f'  ${R}[{score}]${NC} {c[\"id\"]} — {desc}')
" 2>/dev/null || echo "  Could not fetch NVD data (rate limited?)"

# ─── Hacker News Security ──────────────────────────────────────────────────
header "🟠 Hacker News — Security"
curl -sf "https://hn.algolia.com/api/v1/search_by_date?query=security+vulnerability+CVE&tags=story&numericFilters=created_at_i>$(date -v-${PERIOD}d +%s 2>/dev/null || date -d "${PERIOD} days ago" +%s)" 2>/dev/null | \
  python3 -c "
import json,sys
d=json.load(sys.stdin)
for h in d.get('hits',[])[:8]:
  pts=h.get('points',0)
  title=h.get('title','')
  url=h.get('url','')[:60]
  print(f'  ${Y}[{pts}↑]${NC} {title}')
  if url: print(f'        {url}')
" 2>/dev/null || echo "  Could not fetch HN"

# ─── The Hacker News RSS ───────────────────────────────────────────────────
header "📰 The Hacker News"
curl -sf "https://feeds.feedburner.com/TheHackersNews" 2>/dev/null | \
  python3 -c "
import sys,re
content=sys.stdin.read()
titles=re.findall(r'<title><!\[CDATA\[(.*?)\]\]></title>',content)
links=re.findall(r'<link>(https://thehackernews.*?)</link>',content)
for t,l in list(zip(titles,links))[:6]:
  print(f'  • {t}')
" 2>/dev/null || echo "  Could not fetch THN"

# ─── Tweakers.net Security ─────────────────────────────────────────────────
header "🇳🇱 Tweakers.net — Security"
curl -sf "https://feeds.feedburner.com/tweakers/mixed" 2>/dev/null | \
  python3 -c "
import sys,re
content=sys.stdin.read()
items=re.findall(r'<title>(.*?)</title>',content)
security_kw=['security','hack','kwetsbaar','lek','patch','malware','ransomware','CVE','exploit','aanval']
hits=[t for t in items if any(k in t.lower() for k in security_kw)]
if not hits:
  print('  No security news in feed')
else:
  for t in hits[:6]:
    print(f'  • {t}')
" 2>/dev/null || echo "  Could not fetch Tweakers"

# ─── YouTube Security Channels ─────────────────────────────────────────────
header "🎬 YouTube — Security Creators"

fetch_yt() {
  local name="$1" channel_id="$2"
  subheader "$name"
  curl -sf "https://www.youtube.com/feeds/videos.xml?channel_id=${channel_id}" 2>/dev/null | \
    python3 -c "
import sys,re
content=sys.stdin.read()
titles=re.findall(r'<title>(.*?)</title>',content)[1:]  # skip channel title
published=re.findall(r'<published>(.*?)</published>',content)
links=re.findall(r'<link rel=\"alternate\" href=\"(.*?)\"/>',content)[1:]
from datetime import datetime,timedelta
cutoff=datetime.now()-timedelta(days=${PERIOD})
for i,(t,p) in enumerate(zip(titles,published)):
  try:
    pub=datetime.fromisoformat(p.replace('Z','+00:00').replace('+00:00',''))
  except:
    pub=datetime.now()
  if pub.replace(tzinfo=None)>=cutoff or ${PERIOD}>=7:
    print(f'    • {t}')
    if i>=3: break
" 2>/dev/null || echo "    Could not fetch"
}

fetch_yt "John Hammond" "UCVeW9qkBjo3zosnqUbG7CFw"
fetch_yt "Fireship" "UCsBjURrPoezykLs9EqgamOA"
fetch_yt "LiveOverflow" "UClcE-kVhqyiHCcjYwcpfj9w"
fetch_yt "NetworkChuck" "UC9x0AN7BWHpCDHSm9NiJFJQ"
fetch_yt "IppSec" "UCa6eh7gCkpPo5XXUDfygQQA"
fetch_yt "The Cyber Mentor" "UC0ArlFuFYMnM4BOY9rESEnw"

# ─── Krebs on Security ─────────────────────────────────────────────────────
header "🔒 Krebs on Security"
curl -sf "https://krebsonsecurity.com/feed/" 2>/dev/null | \
  python3 -c "
import sys,re
content=sys.stdin.read()
titles=re.findall(r'<title><!\[CDATA\[(.*?)\]\]></title>',content)
if not titles:
  titles=re.findall(r'<title>(.*?)</title>',content)
for t in titles[1:4]:
  print(f'  • {t}')
" 2>/dev/null || echo "  Could not fetch Krebs"

# ─── Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${DIM}  Generated: $(date '+%Y-%m-%d %H:%M') | Period: ${PERIOD}d | Sources: 10+${NC}"
if [ -n "$MD_FILE" ]; then
  echo -e "${DIM}  Saved: ${MD_FILE}${NC}"
fi
echo -e "${DIM}  Tip: ./scripts/security-digest.sh --cve CVE-2024-XXXX for details${NC}"
echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
