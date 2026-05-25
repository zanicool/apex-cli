#!/usr/bin/env bash
#
# supply-chain.sh — Full transitive dependency chain from bounty target to leaf library.
# Parses lockfiles for the complete graph: company → app → framework → lib → tool
#
# Usage:
#   ./scripts/supply-chain.sh build <path>         — parse lockfiles into DB
#   ./scripts/supply-chain.sh trace <pkg>          — trace all paths TO a package
#   ./scripts/supply-chain.sh chain <repo> <pkg>   — show chain from repo to package
#   ./scripts/supply-chain.sh leaves               — most-used leaf packages
#   ./scripts/supply-chain.sh vuln <pkg>           — who's affected if this has a CVE?
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB="$SCRIPT_DIR/../data/supply-chain.db"
mkdir -p "$(dirname "$DB")"

log()  { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }

init_db() {
  sqlite3 "$DB" <<'SQL'
CREATE TABLE IF NOT EXISTS repos (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS pkgs (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  version TEXT
);
CREATE TABLE IF NOT EXISTS edges (
  parent_id INTEGER REFERENCES pkgs(id),
  child_id INTEGER REFERENCES pkgs(id),
  repo_id INTEGER REFERENCES repos(id),
  PRIMARY KEY(parent_id, child_id, repo_id)
);
CREATE INDEX IF NOT EXISTS idx_edges_child ON edges(child_id);
CREATE INDEX IF NOT EXISTS idx_edges_parent ON edges(parent_id);
SQL
}

get_or_create_repo() {
  sqlite3 "$DB" "INSERT OR IGNORE INTO repos (name) VALUES ('$1');"
  sqlite3 "$DB" "SELECT id FROM repos WHERE name='$1';"
}

get_or_create_pkg() {
  local name="$1" ver="${2:-}"
  sqlite3 "$DB" "INSERT OR IGNORE INTO pkgs (name, version) VALUES ('$name', '$ver');"
  sqlite3 "$DB" "SELECT id FROM pkgs WHERE name='$name';"
}

# ═══ Parse package-lock.json (npm) ═══
parse_npm_lock() {
  local file="$1" repo_id="$2"
  python3 -c "
import json, sys, sqlite3

db = sqlite3.connect('$DB')
cur = db.cursor()
repo_id = $repo_id

with open('$file') as f:
    lock = json.load(f)

pkgs = lock.get('packages', {})
pkg_ids = {}

# First pass: create all packages
for path, info in pkgs.items():
    name = path.replace('node_modules/', '').split('node_modules/')[-1]
    if not name: name = '__ROOT__'
    ver = info.get('version', '')
    cur.execute('INSERT OR IGNORE INTO pkgs (name, version) VALUES (?, ?)', (name, ver))

db.commit()

# Get all pkg IDs
cur.execute('SELECT id, name FROM pkgs')
for row in cur.fetchall():
    pkg_ids[row[1]] = row[0]

# Second pass: create edges
for path, info in pkgs.items():
    name = path.replace('node_modules/', '').split('node_modules/')[-1]
    if not name: name = '__ROOT__'
    parent_id = pkg_ids.get(name)
    if not parent_id: continue
    deps = list(info.get('dependencies', {}).keys())
    for dep in deps:
        child_id = pkg_ids.get(dep)
        if child_id:
            cur.execute('INSERT OR IGNORE INTO edges (parent_id, child_id, repo_id) VALUES (?, ?, ?)',
                       (parent_id, child_id, repo_id))

db.commit()
db.close()
print(f'  {name}: {len(pkgs)} packages')
" 2>/dev/null
}

# ═══ Parse pnpm-lock.yaml (basic) ═══
parse_pnpm_lock() {
  local file="$1" repo_id="$2"
  # pnpm lockfiles are complex YAML — extract package names + deps
  python3 -c "
import sys, sqlite3, re

db = sqlite3.connect('$DB')
cur = db.cursor()
repo_id = $repo_id

# Simple parser: extract package names from pnpm-lock
with open('$file') as f:
    content = f.read()

# Find all package references like '/chalk@5.3.0' or 'chalk@5.3.0:'
pkgs = set(re.findall(r\"['/]?([a-z@][a-z0-9_./-]*)@(\d+\.\d+\.\d+)\", content))
for name, ver in pkgs:
    name = name.lstrip('/')
    cur.execute('INSERT OR IGNORE INTO pkgs (name, version) VALUES (?, ?)', (name, ver))

db.commit()
db.close()
print(f'  {len(pkgs)} packages from pnpm-lock')
" 2>/dev/null
}

# ═══ Build ═══
build() {
  local scan_dir="${1:-.}"
  init_db
  log "Scanning lockfiles in $scan_dir..."
  
  find "$scan_dir" -maxdepth 3 -name "package-lock.json" -o -name "pnpm-lock.yaml" | grep -v node_modules | sort | while read -r file; do
    local repo_name=$(echo "$file" | sed "s|$scan_dir/||" | cut -d'/' -f1)
    [[ -z "$repo_name" ]] && continue
    local repo_id=$(get_or_create_repo "$repo_name")
    
    printf "\r  %-30s" "$repo_name"
    case "$file" in
      *package-lock*) parse_npm_lock "$file" "$repo_id" ;;
      *pnpm-lock*) parse_pnpm_lock "$file" "$repo_id" ;;
    esac
  done
  echo ""
  
  local repos=$(sqlite3 "$DB" "SELECT COUNT(*) FROM repos;")
  local pkgs=$(sqlite3 "$DB" "SELECT COUNT(*) FROM pkgs;")
  local edges=$(sqlite3 "$DB" "SELECT COUNT(*) FROM edges;")
  ok "Built: $repos repos, $pkgs packages, $edges edges (transitive)"
}

# ═══ Trace: all paths TO a package ═══
trace_pkg() {
  local target="$1"
  log "Who depends on '$target' (transitive)?"
  echo ""
  sqlite3 "$DB" "
    WITH RECURSIVE chain(pkg_id, depth, path) AS (
      SELECT id, 0, name FROM pkgs WHERE name = '$target'
      UNION ALL
      SELECT e.parent_id, c.depth + 1, p.name || ' → ' || c.path
      FROM chain c
      JOIN edges e ON e.child_id = c.pkg_id
      JOIN pkgs p ON p.id = e.parent_id
      WHERE c.depth < 5
    )
    SELECT DISTINCT path, depth FROM chain
    WHERE depth > 0
    ORDER BY depth
    LIMIT 30;
  " | while IFS='|' read -r path depth; do
    printf "  [%d] %s\n" "$depth" "$path"
  done
}

# ═══ Chain: specific repo to specific package ═══
chain_repo_pkg() {
  local repo="$1" target="$2"
  log "Chain: $repo → ... → $target"
  echo ""
  sqlite3 "$DB" "
    WITH RECURSIVE chain(pkg_id, depth, path) AS (
      SELECT id, 0, name FROM pkgs WHERE name = '$target'
      UNION ALL
      SELECT e.parent_id, c.depth + 1, p.name || ' → ' || c.path
      FROM chain c
      JOIN edges e ON e.child_id = c.pkg_id AND e.repo_id = (SELECT id FROM repos WHERE name = '$repo')
      JOIN pkgs p ON p.id = e.parent_id
      WHERE c.depth < 8
    )
    SELECT path, depth FROM chain
    WHERE depth > 0
    ORDER BY depth DESC
    LIMIT 10;
  " | while IFS='|' read -r path depth; do
    printf "  %s\n" "$path"
  done
}

# ═══ Leaves: most-used leaf packages (no dependents) ═══
leaves() {
  log "Most-used leaf packages (deepest in tree):"
  echo ""
  printf "  %-30s %-8s %s\n" "Package" "Used by" "Version"
  printf "  %-30s %-8s %s\n" "───────" "───────" "───────"
  sqlite3 "$DB" "
    SELECT p.name, COUNT(DISTINCT e.parent_id) as users, p.version
    FROM edges e
    JOIN pkgs p ON p.id = e.child_id
    WHERE e.child_id NOT IN (SELECT DISTINCT parent_id FROM edges)
    GROUP BY e.child_id
    ORDER BY users DESC
    LIMIT 30;
  " | while IFS='|' read -r name users ver; do
    printf "  %-30s %-8s %s\n" "$name" "$users" "$ver"
  done
}

# ═══ Vuln: blast radius with full chain ═══
vuln_blast() {
  local target="$1"
  log "If '$target' has a CVE — full blast radius:"
  echo ""
  
  local affected=$(sqlite3 "$DB" "
    WITH RECURSIVE affected(pkg_id) AS (
      SELECT id FROM pkgs WHERE name = '$target'
      UNION
      SELECT e.parent_id FROM edges e JOIN affected a ON e.child_id = a.pkg_id
    )
    SELECT COUNT(DISTINCT r.name)
    FROM affected a
    JOIN edges e ON e.parent_id = a.pkg_id OR e.child_id = a.pkg_id
    JOIN repos r ON e.repo_id = r.id;
  ")
  local total=$(sqlite3 "$DB" "SELECT COUNT(*) FROM repos;")
  
  ok "Repos affected: $affected / $total"
  echo ""
  log "Affected repos:"
  sqlite3 "$DB" "
    WITH RECURSIVE affected(pkg_id) AS (
      SELECT id FROM pkgs WHERE name = '$target'
      UNION
      SELECT e.parent_id FROM edges e JOIN affected a ON e.child_id = a.pkg_id
    )
    SELECT DISTINCT r.name
    FROM affected a
    JOIN edges e ON e.parent_id = a.pkg_id OR e.child_id = a.pkg_id
    JOIN repos r ON e.repo_id = r.id
    ORDER BY r.name;
  " | while read -r repo; do
    echo "  $repo"
  done
}

# ═══ Main ═══
CMD="${1:-help}"
case "$CMD" in
  build)  build "${2:-.}" ;;
  trace)  trace_pkg "${2:?Usage: $0 trace <package>}" ;;
  chain)  chain_repo_pkg "${2:?Usage: $0 chain <repo> <pkg>}" "${3:?}" ;;
  leaves) leaves ;;
  vuln)   vuln_blast "${2:?Usage: $0 vuln <package>}" ;;
  *)
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  build <path>         Parse lockfiles → full transitive graph"
    echo "  trace <pkg>          Who depends on this? (all paths)"
    echo "  chain <repo> <pkg>   Show dependency chain from repo to package"
    echo "  leaves               Most-used leaf packages (deepest deps)"
    echo "  vuln <pkg>           Full blast radius if this has a CVE"
    ;;
esac
