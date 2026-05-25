#!/bin/bash
# Apex CLI — Bounty Target Stack DB
# Persists: which companies use which stacks, fingerprinted over time.
# Focus: mid-tier programs (less competition, still pays).
# Usage:
#   ./scripts/bounty-stack-db.sh init          — create DB + seed from H1
#   ./scripts/bounty-stack-db.sh fingerprint   — probe all targets, update DB
#   ./scripts/bounty-stack-db.sh query <stack>  — find programs using <stack>
#   ./scripts/bounty-stack-db.sh list          — show all fingerprinted targets
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB="$SCRIPT_DIR/../data/bounty-targets.db"
LOG="$SCRIPT_DIR/../output/bounty-stack-$(date +%Y%m%d).log"
mkdir -p "$(dirname "$LOG")"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }
crit() { echo -e "\033[1;31m[!!]\033[0m $*" | tee -a "$LOG"; }

# ═══ DB Schema ═══
init_db() {
  sqlite3 "$DB" <<'SQL'
CREATE TABLE IF NOT EXISTS programs (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  platform TEXT DEFAULT 'hackerone',
  max_bounty INTEGER DEFAULT 0,
  scope TEXT,
  url TEXT,
  added_at TEXT DEFAULT (datetime('now')),
  last_scanned TEXT
);

CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  program_id INTEGER REFERENCES programs(id),
  domain TEXT NOT NULL,
  url TEXT,
  UNIQUE(program_id, domain)
);

CREATE TABLE IF NOT EXISTS fingerprints (
  id INTEGER PRIMARY KEY,
  target_id INTEGER REFERENCES targets(id),
  stack TEXT NOT NULL,
  version TEXT,
  confidence TEXT DEFAULT 'medium',
  source TEXT,
  first_seen TEXT DEFAULT (datetime('now')),
  last_seen TEXT DEFAULT (datetime('now')),
  UNIQUE(target_id, stack)
);

CREATE TABLE IF NOT EXISTS vulns (
  id INTEGER PRIMARY KEY,
  target_id INTEGER REFERENCES targets(id),
  finding TEXT NOT NULL,
  category TEXT,
  risk TEXT,
  status TEXT DEFAULT 'new',
  reported_at TEXT,
  bounty_amount INTEGER
);
SQL
  ok "DB initialized: $DB"
}

# ═══ Seed mid-tier programs from H1 ═══
seed_programs() {
  log "Fetching HackerOne programs..."
  local h1_data
  h1_data=$(curl -s "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json" 2>/dev/null)
  
  if [[ -z "$h1_data" ]]; then
    warn "Failed to fetch H1 data — seeding manually"
    seed_manual
    return
  fi
  
  # Filter: offers bounties, max bounty $500-$30000 (mid-tier = less competition)
  echo "$h1_data" | python3 -c "
import json, sys
programs = json.load(sys.stdin)
mid_tier = []
for p in programs:
    if not p.get('offers_bounties', False):
        continue
    targets = p.get('targets', {}).get('in_scope', [])
    domains = [t['asset_identifier'] for t in targets if t.get('asset_type') == 'URL']
    if not domains:
        continue
    # Mid-tier: not the top 20 programs everyone hunts
    name = p.get('handle', '')
    skip = ['google','apple','microsoft','meta','shopify','uber','twitter',
            'github','gitlab','paypal','yahoo','dropbox','slack','spotify',
            'snapchat','tiktok','netflix','amazon','coinbase','stripe']
    if name.lower() in skip:
        continue
    mid_tier.append({
        'name': name,
        'url': p.get('url', ''),
        'domains': domains[:20]  # max 20 domains per program
    })

# Sort by number of domains (more surface = more opportunity)
mid_tier.sort(key=lambda x: len(x['domains']), reverse=True)
for p in mid_tier[:100]:  # top 100 mid-tier
    print(json.dumps(p))
" 2>/dev/null | while IFS= read -r line; do
    local name=$(echo "$line" | python3 -c "import json,sys;print(json.load(sys.stdin)['name'])")
    local url=$(echo "$line" | python3 -c "import json,sys;print(json.load(sys.stdin)['url'])")
    
    sqlite3 "$DB" "INSERT OR IGNORE INTO programs (name, platform, url) VALUES ('$name', 'hackerone', '$url');"
    local prog_id=$(sqlite3 "$DB" "SELECT id FROM programs WHERE name='$name';")
    
    echo "$line" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for d in data['domains']:
    # Clean domain
    d = d.replace('https://','').replace('http://','').rstrip('/')
    if '*.' in d:
        d = d.replace('*.','')
    print(d)
" | while IFS= read -r domain; do
      sqlite3 "$DB" "INSERT OR IGNORE INTO targets (program_id, domain) VALUES ($prog_id, '$domain');" 2>/dev/null
    done
  done
  
  local prog_count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM programs;")
  local target_count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM targets;")
  ok "Seeded: $prog_count programs, $target_count targets"
}

seed_manual() {
  # Mid-tier programs known to use AI/LLM stacks
  sqlite3 "$DB" <<'SQL'
INSERT OR IGNORE INTO programs (name, platform, max_bounty, url) VALUES
  ('langflow', 'github', 5000, 'https://github.com/langflow-ai/langflow/security'),
  ('hoppscotch', 'github', 2000, 'https://github.com/hoppscotch/hoppscotch/security'),
  ('n8n', 'hackerone', 5000, 'https://hackerone.com/n8n'),
  ('flowise', 'github', 1000, 'https://github.com/FlowiseAI/Flowise/security'),
  ('open-webui', 'github', 1000, 'https://github.com/open-webui/open-webui/security'),
  ('dify', 'github', 5000, 'https://github.com/langgenius/dify/security'),
  ('supabase', 'hackerone', 10000, 'https://hackerone.com/supabase'),
  ('cal-com', 'huntr', 5000, 'https://huntr.com/repos/calcom/cal.com'),
  ('appsmith', 'hackerone', 5000, 'https://hackerone.com/appsmith'),
  ('nocodb', 'huntr', 2000, 'https://huntr.com/repos/nocodb/nocodb'),
  ('directus', 'huntr', 2000, 'https://huntr.com/repos/directus/directus'),
  ('strapi', 'huntr', 5000, 'https://huntr.com/repos/strapi/strapi'),
  ('medusa', 'huntr', 2000, 'https://huntr.com/repos/medusajs/medusa'),
  ('plane', 'github', 1000, 'https://github.com/makeplane/plane/security'),
  ('twenty', 'github', 1000, 'https://github.com/twentyhq/twenty/security');
SQL
  ok "Seeded 15 mid-tier programs manually"
}

# ═══ Fingerprint all targets ═══
fingerprint_all() {
  local targets
  targets=$(sqlite3 "$DB" "SELECT t.id, t.domain, p.name FROM targets t JOIN programs p ON t.program_id = p.id WHERE t.domain != '' ORDER BY RANDOM() LIMIT 200;")
  local total=$(echo "$targets" | grep -c "." || echo 0)
  log "Fingerprinting $total targets..."
  
  local i=0
  echo "$targets" | while IFS='|' read -r tid domain program; do
    [[ -z "$tid" ]] && continue
    i=$((i + 1))
    printf "\r  [%d/%d] %s " "$i" "$total" "$domain"
    
    local url="https://$domain"
    
    # Quick fingerprint via headers + known paths
    local headers
    headers=$(curl -sk --max-time 5 -I "$url" 2>/dev/null)
    
    # Check server header
    local server=$(echo "$headers" | grep -i "^server:" | sed 's/server: *//i' | tr -d '\r')
    [[ -n "$server" ]] && upsert_fingerprint "$tid" "server:$server" "" "header"
    
    # Check x-powered-by
    local powered=$(echo "$headers" | grep -i "^x-powered-by:" | sed 's/x-powered-by: *//i' | tr -d '\r')
    [[ -n "$powered" ]] && upsert_fingerprint "$tid" "$powered" "" "header"
    
    # Probe for known stacks
    # FastAPI/Starlette
    local body=$(curl -sk --max-time 3 "$url/docs" 2>/dev/null | head -100)
    if echo "$body" | grep -qi "swagger\|openapi\|fastapi"; then
      upsert_fingerprint "$tid" "fastapi" "" "probe:/docs"
    fi
    
    # Next.js
    body=$(curl -sk --max-time 3 "$url" 2>/dev/null | head -200)
    if echo "$body" | grep -qi "_next/static\|__NEXT_DATA__"; then
      upsert_fingerprint "$tid" "nextjs" "" "probe:html"
    fi
    
    # React
    if echo "$body" | grep -qi "__REACT\|react-root\|reactRoot"; then
      upsert_fingerprint "$tid" "react" "" "probe:html"
    fi
    
    # Langflow (must contain "langflow" in response)
    if curl -sk --max-time 3 "$url/api/v1/version" 2>/dev/null | grep -qi "langflow"; then
      local ver=$(curl -sk --max-time 3 "$url/api/v1/version" 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
      upsert_fingerprint "$tid" "langflow" "$ver" "probe:api"
    fi
    
    # Dify (must contain "dify" or specific setup fields)
    if curl -sk --max-time 3 "$url/console/api/setup" 2>/dev/null | grep -qi "dify\|setup_status\|init_password"; then
      upsert_fingerprint "$tid" "dify" "" "probe:api"
    fi
    
    # Open-WebUI
    if curl -sk --max-time 3 "$url/api/config" 2>/dev/null | grep -qi "webui\|ollama"; then
      upsert_fingerprint "$tid" "open-webui" "" "probe:api"
    fi
    
    # NestJS (via error format)
    if curl -sk --max-time 3 "$url/nonexistent-path-xyz" 2>/dev/null | grep -qi '"statusCode":404.*"message"'; then
      upsert_fingerprint "$tid" "nestjs" "" "probe:error"
    fi
    
    # Express (via error format)
    if echo "$headers" | grep -qi "x-powered-by.*express"; then
      upsert_fingerprint "$tid" "express" "" "header"
    fi
    
    # GraphQL
    if curl -sk --max-time 3 "$url/graphql" -H "Content-Type: application/json" -d '{"query":"{__typename}"}' 2>/dev/null | grep -qi "typename\|data"; then
      upsert_fingerprint "$tid" "graphql" "" "probe:graphql"
    fi
    
    # Update last_scanned
    sqlite3 "$DB" "UPDATE programs SET last_scanned = datetime('now') WHERE id = (SELECT program_id FROM targets WHERE id = $tid);" 2>/dev/null
    
    # Throttle
    sleep 0.2
  done
  echo ""
  
  local fp_count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM fingerprints;")
  ok "Fingerprints in DB: $fp_count"
}

upsert_fingerprint() {
  local tid="$1" stack="$2" version="$3" source="$4"
  sqlite3 "$DB" "INSERT INTO fingerprints (target_id, stack, version, source, confidence)
    VALUES ($tid, '$stack', '$version', '$source', 'medium')
    ON CONFLICT(target_id, stack) DO UPDATE SET
      last_seen = datetime('now'),
      version = CASE WHEN '$version' != '' THEN '$version' ELSE version END,
      source = '$source';" 2>/dev/null
}

# ═══ Query: find programs using a specific stack ═══
query_stack() {
  local stack="$1"
  log "Programs using '$stack':"
  echo ""
  printf "  %-20s %-30s %-15s %s\n" "Program" "Domain" "Version" "Last Seen"
  printf "  %-20s %-30s %-15s %s\n" "───────" "──────" "───────" "─────────"
  sqlite3 "$DB" "
    SELECT p.name, t.domain, f.version, f.last_seen
    FROM fingerprints f
    JOIN targets t ON f.target_id = t.id
    JOIN programs p ON t.program_id = p.id
    WHERE f.stack LIKE '%$stack%'
    ORDER BY f.last_seen DESC;
  " | while IFS='|' read -r name domain version last_seen; do
    printf "  %-20s %-30s %-15s %s\n" "$name" "$domain" "${version:-—}" "$last_seen"
  done
}

# ═══ List all fingerprinted targets ═══
list_all() {
  log "All fingerprinted targets:"
  echo ""
  printf "  %-20s %-30s %s\n" "Program" "Domain" "Stacks"
  printf "  %-20s %-30s %s\n" "───────" "──────" "──────"
  sqlite3 "$DB" "
    SELECT p.name, t.domain, GROUP_CONCAT(f.stack, ', ')
    FROM targets t
    JOIN programs p ON t.program_id = p.id
    LEFT JOIN fingerprints f ON f.target_id = t.id
    WHERE f.stack IS NOT NULL
    GROUP BY t.id
    ORDER BY p.name;
  " | while IFS='|' read -r name domain stacks; do
    printf "  %-20s %-30s %s\n" "$name" "$domain" "$stacks"
  done
  echo ""
  local total=$(sqlite3 "$DB" "SELECT COUNT(DISTINCT target_id) FROM fingerprints;")
  ok "Total fingerprinted: $total targets"
}

# ═══ Stats ═══
show_stats() {
  echo ""
  echo "  ╔═══════════════════════════════════════════════╗"
  echo "  ║  Bounty Target Stack DB                       ║"
  echo "  ╚═══════════════════════════════════════════════╝"
  echo ""
  local progs=$(sqlite3 "$DB" "SELECT COUNT(*) FROM programs;")
  local tgts=$(sqlite3 "$DB" "SELECT COUNT(*) FROM targets;")
  local fps=$(sqlite3 "$DB" "SELECT COUNT(*) FROM fingerprints;")
  local scanned=$(sqlite3 "$DB" "SELECT COUNT(*) FROM programs WHERE last_scanned IS NOT NULL;")
  ok "Programs:      $progs"
  ok "Targets:       $tgts"
  ok "Fingerprints:  $fps"
  ok "Scanned:       $scanned/$progs"
  echo ""
  log "Top stacks found:"
  sqlite3 "$DB" "SELECT stack, COUNT(*) as cnt FROM fingerprints GROUP BY stack ORDER BY cnt DESC LIMIT 15;" | while IFS='|' read -r stack cnt; do
    printf "  %-25s %s\n" "$stack" "$cnt"
  done
}

# ═══ Main ═══
CMD="${1:-stats}"

case "$CMD" in
  init)
    init_db
    seed_programs
    show_stats
    ;;
  seed)
    seed_programs
    ;;
  fingerprint)
    fingerprint_all
    show_stats
    ;;
  query)
    STACK="${2:?Usage: $0 query <stack-name>}"
    query_stack "$STACK"
    ;;
  list)
    list_all
    ;;
  stats)
    show_stats
    ;;
  *)
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  init          Create DB + seed mid-tier H1 programs"
    echo "  seed          Re-seed programs from H1"
    echo "  fingerprint   Probe all targets, detect stacks"
    echo "  query <stack> Find programs using a specific stack"
    echo "  list          Show all fingerprinted targets"
    echo "  stats         Show DB statistics"
    ;;
esac
