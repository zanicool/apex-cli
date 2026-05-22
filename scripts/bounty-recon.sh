#!/usr/bin/env bash
# bounty-recon.sh — Pre-hunt intelligence gathering for bug bounty targets.
#
# Gathers:
#   1. Program info (scope, rewards, response time)
#   2. Tech stack (from job postings, headers, JS)
#   3. Release cadence (GitHub releases, changelogs)
#   4. Recent CVEs for their stack
#   5. Open source repos to audit with cpm
#   6. News/breaches
#
# Usage:
#   ./scripts/bounty-recon.sh shopify
#   ./scripts/bounty-recon.sh --list              # Show top programs
#   ./scripts/bounty-recon.sh uber --deep         # Full recon
set -euo pipefail

B='\033[0;34m'; G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'
C='\033[0;36m'; DIM='\033[2m'; BOLD='\033[1m'; NC='\033[0m'

PROGRAM="${1:-}"
DEEP=false
[[ "${2:-}" == "--deep" ]] && DEEP=true

if [ -z "$PROGRAM" ] || [ "$PROGRAM" = "--list" ]; then
  echo -e "${BOLD}Top Bug Bounty Programs (by payout):${NC}\n"
  echo "  Program          Platform     Max Bounty   Scope"
  echo "  ─────────────────────────────────────────────────────────"
  echo "  google           H1/Bughunters \$31,337+    *.google.com"
  echo "  apple            Apple         \$200,000    *.apple.com"
  echo "  microsoft        MSRC          \$100,000    *.microsoft.com"
  echo "  meta             H1            \$50,000     *.facebook.com"
  echo "  shopify          H1            \$50,000     *.shopify.com"
  echo "  uber             H1            \$15,000     *.uber.com"
  echo "  github           H1            \$30,000     *.github.com"
  echo "  gitlab           H1            \$35,000     *.gitlab.com"
  echo "  slack            H1            \$10,000     *.slack.com"
  echo "  paypal           H1            \$20,000     *.paypal.com"
  echo "  twitter          H1            \$15,000     *.x.com"
  echo "  dropbox          H1            \$32,768     *.dropbox.com"
  echo "  coinbase         H1            \$50,000     *.coinbase.com"
  echo "  cloudflare       H1            \$3,000      *.cloudflare.com"
  echo "  nodejs           H1            \$2,500      nodejs/node"
  echo ""
  echo -e "  Usage: ${C}$0 <program-name>${NC}"
  exit 0
fi

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  BOUNTY RECON — ${PROGRAM}${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}\n"

# ─── 1. Program Info ────────────────────────────────────────────────────────
echo -e "${B}[1/6] Program Intelligence${NC}\n"

# Try to fetch HackerOne program info
H1_URL="https://hackerone.com/${PROGRAM}"
echo -e "  Platform: ${C}${H1_URL}${NC}"

# Fetch program page for scope
SCOPE_INFO=$(curl -sf "https://hackerone.com/${PROGRAM}" 2>/dev/null | \
  grep -oE '"(https?://[^"]+\.(com|io|net|org)[^"]*)"' | head -10 | sort -u || echo "")
if [ -n "$SCOPE_INFO" ]; then
  echo -e "  Scope domains:"
  echo "$SCOPE_INFO" | sed 's/^/    /'
fi

# Check Hacktivity for recent reports
echo -e "\n  Recent disclosed reports:"
curl -sf "https://hackerone.com/hacktivity?queryString=program:${PROGRAM}&filter=type:public" 2>/dev/null | \
  grep -oP '"title":"[^"]{10,80}"' 2>/dev/null | head -5 | sed 's/"title":"//;s/"$//' | \
  while read -r title; do echo "    • $title"; done || echo "    (could not fetch)"

# ─── 2. Tech Stack ─────────────────────────────────────────────────────────
echo -e "\n${B}[2/6] Tech Stack Detection${NC}\n"

# From job postings
echo -e "  ${DIM}Checking job postings...${NC}"
JOBS_URL="https://www.google.com/search?q=${PROGRAM}+careers+engineer+site:linkedin.com+OR+site:lever.co+OR+site:greenhouse.io"
echo -e "  Jobs: ${C}${JOBS_URL}${NC}"

# Detect from main domain
DOMAIN="${PROGRAM}.com"
echo -e "  Scanning ${DOMAIN} headers..."
HEADERS=$(curl -sI "https://${DOMAIN}" 2>/dev/null | grep -iE "^(server|x-powered|x-frame|set-cookie|content-security)" || echo "")
if [ -n "$HEADERS" ]; then
  echo "$HEADERS" | while read -r h; do echo "    $h"; done
fi

# Wappalyzer-style detection from response
BODY=$(curl -sf "https://${DOMAIN}" 2>/dev/null | head -200 || echo "")
echo -e "\n  Detected technologies:"
[[ "$BODY" == *"react"* || "$BODY" == *"React"* ]] && echo "    • React"
[[ "$BODY" == *"next"* || "$BODY" == *"_next"* ]] && echo "    • Next.js"
[[ "$BODY" == *"vue"* ]] && echo "    • Vue.js"
[[ "$BODY" == *"angular"* ]] && echo "    • Angular"
[[ "$BODY" == *"wp-content"* ]] && echo "    • WordPress"
[[ "$BODY" == *"shopify"* ]] && echo "    • Shopify"
[[ "$BODY" == *"cloudflare"* ]] && echo "    • Cloudflare"
[[ "$BODY" == *"graphql"* || "$BODY" == *"GraphQL"* ]] && echo "    • GraphQL"
[[ "$BODY" == *"stripe"* ]] && echo "    • Stripe"
[[ "$BODY" == *"segment"* ]] && echo "    • Segment"
[[ "$BODY" == *"datadog"* ]] && echo "    • Datadog"
[[ "$BODY" == *"sentry"* ]] && echo "    • Sentry"

# ─── 3. Release Cadence ────────────────────────────────────────────────────
echo -e "\n${B}[3/6] Release Cadence & Open Source${NC}\n"

# Check GitHub org
echo -e "  GitHub org: ${C}https://github.com/${PROGRAM}${NC}"
GH_REPOS=$(curl -sf "https://api.github.com/orgs/${PROGRAM}/repos?sort=updated&per_page=5" 2>/dev/null || echo "[]")
echo "$GH_REPOS" | python3 -c "
import json,sys
try:
  repos=json.load(sys.stdin)
  if isinstance(repos, list) and repos:
    print('  Recent repos:')
    for r in repos[:5]:
      lang=r.get('language','?') or '?'
      stars=r.get('stargazers_count',0)
      print(f'    • {r[\"name\"]} ({lang}, ★{stars}) — updated {r.get(\"updated_at\",\"?\")[:10]}')
    print()
    print('  🔍 Repos to audit with cpm:')
    for r in repos[:3]:
      print(f'    git clone {r[\"clone_url\"]}')
      print(f'    cd {r[\"name\"]} && cpm')
  else:
    print('    (no public repos or org not found)')
except: print('    (could not parse)')
" 2>/dev/null || echo "    (GitHub API unavailable)"

# ─── 4. Recent CVEs ────────────────────────────────────────────────────────
echo -e "\n${B}[4/6] Recent CVEs for Stack${NC}\n"

# Search NVD for program-related CVEs
curl -sf "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${PROGRAM}&resultsPerPage=5" 2>/dev/null | \
  python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  vulns=d.get('vulnerabilities',[])
  if vulns:
    for v in vulns[:5]:
      c=v['cve']
      desc=(c['descriptions'][0]['value'] if c.get('descriptions') else '')[:80]
      print(f'  {c[\"id\"]} — {desc}')
  else:
    print('  No CVEs found for this keyword')
except: print('  (NVD API unavailable)')
" 2>/dev/null || echo "  (could not fetch)"

# ─── 5. News & Breaches ────────────────────────────────────────────────────
echo -e "\n${B}[5/6] Security News & Breaches${NC}\n"

# HN search
curl -sf "https://hn.algolia.com/api/v1/search?query=${PROGRAM}+security+vulnerability&tags=story" 2>/dev/null | \
  python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  for h in d.get('hits',[])[:5]:
    pts=h.get('points',0)
    title=h.get('title','')
    print(f'  [{pts}↑] {title}')
except: pass
" 2>/dev/null || echo "  (could not fetch)"

# ─── 6. Attack Surface Summary ─────────────────────────────────────────────
echo -e "\n${B}[6/6] Attack Surface Summary${NC}\n"

echo -e "  ${BOLD}Recommended approach:${NC}"
echo ""
echo -e "  1. ${G}Scan main domain:${NC}"
echo -e "     ./build/apex-cli https://${DOMAIN} --pipeline"
echo ""
echo -e "  2. ${G}Scan subdomains:${NC}"
echo -e "     subfinder -d ${DOMAIN} -silent | httpx -silent | \\"
echo -e "       xargs -I{} ./build/apex-cli {} --smart --confidence 3"
echo ""
echo -e "  3. ${G}Audit open source repos:${NC}"
echo -e "     git clone https://github.com/${PROGRAM}/<repo>"
echo -e "     cd <repo> && cpm  # code quality + security checks"
echo ""
echo -e "  4. ${G}Monitor for changes:${NC}"
echo -e "     ./build/apex-cli https://${DOMAIN} --watch --watch-interval 21600"
echo ""
echo -e "  5. ${G}Check security digest:${NC}"
echo -e "     ./scripts/security-digest.sh --cve ${PROGRAM}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${DIM}Pro tips:${NC}"
echo -e "  • New features = new bugs. Watch their changelog/blog"
echo -e "  • Acquisitions = integration bugs. Check recent M&A"
echo -e "  • Job postings reveal internal tech (GraphQL, K8s, etc.)"
echo -e "  • GitHub issues/PRs sometimes leak security fixes before patch"
echo -e "  • Focus on what's UNIQUE to them, not generic vulns"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
