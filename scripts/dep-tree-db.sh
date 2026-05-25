#!/usr/bin/env bash
#
# dep-tree-db.sh — Build a dependency graph from repos into SQLite.
# Maps: repo → framework → library → tool (full supply chain)
#
# Usage:
#   ./dep-tree-db.sh build <path>     — scan repos, build DB
#   ./dep-tree-db.sh query <pkg>      — who depends on this package?
#   ./dep-tree-db.sh tree <repo>      — show dep tree for a repo
#   ./dep-tree-db.sh popular          — most depended-on packages
#   ./dep-tree-db.sh blast <pkg>      — blast radius: all repos affected
#   ./dep-tree-db.sh stats            — DB statistics
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB="${DEP_DB:-$SCRIPT_DIR/../data/dep-tree.db}"
mkdir -p "$(dirname "$DB")"

log()  { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }

init_db() {
  sqlite3 "$DB" <<'SQL'
CREATE TABLE IF NOT EXISTS repos (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  lang TEXT,
  path TEXT
);
CREATE TABLE IF NOT EXISTS packages (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  UNIQUE(name, ecosystem)
);
CREATE TABLE IF NOT EXISTS deps (
  repo_id INTEGER REFERENCES repos(id),
  pkg_id INTEGER REFERENCES packages(id),
  version TEXT,
  dep_type TEXT DEFAULT 'runtime',
  PRIMARY KEY(repo_id, pkg_id)
);
CREATE TABLE IF NOT EXISTS pkg_deps (
  parent_id INTEGER REFERENCES packages(id),
  child_id INTEGER REFERENCES packages(id),
  version TEXT,
  PRIMARY KEY(parent_id, child_id)
);
CREATE INDEX IF NOT EXISTS idx_deps_pkg ON deps(pkg_id);
CREATE INDEX IF NOT EXISTS idx_pkgdeps_child ON pkg_deps(child_id);
SQL
}

get_or_create_repo() {
  local name="$1" lang="$2" path="$3"
  sqlite3 "$DB" "INSERT OR IGNORE INTO repos (name, lang, path) VALUES ('$name', '$lang', '$path');"
  sqlite3 "$DB" "SELECT id FROM repos WHERE name='$name';"
}

get_or_create_pkg() {
  local name="$1" eco="$2"
  sqlite3 "$DB" "INSERT OR IGNORE INTO packages (name, ecosystem) VALUES ('$name', '$eco');"
  sqlite3 "$DB" "SELECT id FROM packages WHERE name='$name' AND ecosystem='$eco';"
}

# ═══ Parse package.json ═══
parse_npm() {
  local file="$1" repo_id="$2"
  python3 -c "
import json, sys
try:
    pkg = json.load(open('$file'))
except: sys.exit(0)
deps = {}
deps.update(pkg.get('dependencies', {}))
deps.update(pkg.get('devDependencies', {}))
for name, ver in deps.items():
    # Clean version
    ver = ver.lstrip('^~>=<')
    print(f'{name}|{ver}')
" 2>/dev/null | while IFS='|' read -r name ver; do
    [[ -z "$name" ]] && continue
    local pkg_id=$(get_or_create_pkg "$name" "npm")
    sqlite3 "$DB" "INSERT OR IGNORE INTO deps (repo_id, pkg_id, version) VALUES ($repo_id, $pkg_id, '$ver');" 2>/dev/null
  done
}

# ═══ Parse requirements.txt / pyproject.toml ═══
parse_python() {
  local file="$1" repo_id="$2"
  if [[ "$file" == *"requirements"* ]]; then
    grep -v "^#\|^$\|^-" "$file" 2>/dev/null | sed 's/[>=<].*//' | tr -d ' ' | while read -r name; do
      [[ -z "$name" ]] && continue
      local pkg_id=$(get_or_create_pkg "$name" "pypi")
      sqlite3 "$DB" "INSERT OR IGNORE INTO deps (repo_id, pkg_id, version) VALUES ($repo_id, $pkg_id, '');" 2>/dev/null
    done
  elif [[ "$file" == *"pyproject"* ]]; then
    python3 -c "
import sys
try:
    import tomllib
    with open('$file', 'rb') as f: data = tomllib.load(f)
except:
    try:
        import tomli as tomllib
        with open('$file', 'rb') as f: data = tomllib.load(f)
    except: sys.exit(0)
deps = data.get('project', {}).get('dependencies', [])
deps += data.get('tool', {}).get('poetry', {}).get('dependencies', {}).keys() if isinstance(data.get('tool', {}).get('poetry', {}).get('dependencies', {}), dict) else []
for d in deps:
    name = d.split('>=')[0].split('==')[0].split('<')[0].split('>')[0].split('[')[0].strip()
    if name and name != 'python': print(name)
" 2>/dev/null | while read -r name; do
      [[ -z "$name" ]] && continue
      local pkg_id=$(get_or_create_pkg "$name" "pypi")
      sqlite3 "$DB" "INSERT OR IGNORE INTO deps (repo_id, pkg_id, version) VALUES ($repo_id, $pkg_id, '');" 2>/dev/null
    done
  fi
}

# ═══ Parse go.mod ═══
parse_go() {
  local file="$1" repo_id="$2"
  grep "^\t" "$file" 2>/dev/null | grep -v "^//" | awk '{print $1"|"$2}' | while IFS='|' read -r name ver; do
    [[ -z "$name" ]] && continue
    local pkg_id=$(get_or_create_pkg "$name" "go")
    sqlite3 "$DB" "INSERT OR IGNORE INTO deps (repo_id, pkg_id, version) VALUES ($repo_id, $pkg_id, '$ver');" 2>/dev/null
  done
}

# ═══ Parse Cargo.toml ═══
parse_rust() {
  local file="$1" repo_id="$2"
  sed -n '/\[dependencies\]/,/^\[/p' "$file" 2>/dev/null | grep -v "^\[" | grep "=" | while read -r line; do
    local name=$(echo "$line" | cut -d'=' -f1 | tr -d ' ')
    local ver=$(echo "$line" | grep -o '"[^"]*"' | head -1 | tr -d '"')
    [[ -z "$name" ]] && continue
    local pkg_id=$(get_or_create_pkg "$name" "crates")
    sqlite3 "$DB" "INSERT OR IGNORE INTO deps (repo_id, pkg_id, version) VALUES ($repo_id, $pkg_id, '$ver');" 2>/dev/null
  done
}

# ═══ Build: scan all repos ═══
build_db() {
  local scan_dir="${1:-.}"
  init_db
  log "Scanning $scan_dir for dependency files..."
  
  local count=0
  find "$scan_dir" -maxdepth 2 \( -name "package.json" -o -name "requirements*.txt" -o -name "pyproject.toml" -o -name "go.mod" -o -name "Cargo.toml" \) | grep -v node_modules | grep -v vendor | sort | while read -r file; do
    local repo_dir=$(dirname "$file")
    # Get repo name (top-level dir under scan_dir)
    local repo_name=$(echo "$repo_dir" | sed "s|$scan_dir/||" | cut -d'/' -f1)
    [[ -z "$repo_name" || "$repo_name" == "." ]] && continue
    
    count=$((count + 1))
    printf "\r  [%d] %s    " "$count" "$repo_name"
    
    local lang=""
    local repo_id
    case "$file" in
      *package.json) lang="javascript"; repo_id=$(get_or_create_repo "$repo_name" "$lang" "$repo_dir"); parse_npm "$file" "$repo_id" ;;
      *requirements*) lang="python"; repo_id=$(get_or_create_repo "$repo_name" "$lang" "$repo_dir"); parse_python "$file" "$repo_id" ;;
      *pyproject.toml) lang="python"; repo_id=$(get_or_create_repo "$repo_name" "$lang" "$repo_dir"); parse_python "$file" "$repo_id" ;;
      *go.mod) lang="go"; repo_id=$(get_or_create_repo "$repo_name" "$lang" "$repo_dir"); parse_go "$file" "$repo_id" ;;
      *Cargo.toml) lang="rust"; repo_id=$(get_or_create_repo "$repo_name" "$lang" "$repo_dir"); parse_rust "$file" "$repo_id" ;;
    esac
  done
  echo ""
  
  local repos=$(sqlite3 "$DB" "SELECT COUNT(*) FROM repos;")
  local pkgs=$(sqlite3 "$DB" "SELECT COUNT(*) FROM packages;")
  local edges=$(sqlite3 "$DB" "SELECT COUNT(*) FROM deps;")
  ok "Built: $repos repos, $pkgs packages, $edges dependency edges"
}

# ═══ Query: who depends on this? ═══
query_pkg() {
  local name="$1"
  log "Repos depending on '$name':"
  echo ""
  printf "  %-25s %-10s %s\n" "Repo" "Version" "Ecosystem"
  printf "  %-25s %-10s %s\n" "────" "───────" "─────────"
  sqlite3 "$DB" "
    SELECT r.name, d.version, p.ecosystem
    FROM deps d
    JOIN repos r ON d.repo_id = r.id
    JOIN packages p ON d.pkg_id = p.id
    WHERE p.name LIKE '%$name%'
    ORDER BY r.name;
  " | while IFS='|' read -r repo ver eco; do
    printf "  %-25s %-10s %s\n" "$repo" "${ver:-*}" "$eco"
  done
}

# ═══ Tree: show deps for a repo ═══
tree_repo() {
  local name="$1"
  log "Dependencies of '$name':"
  echo ""
  sqlite3 "$DB" "
    SELECT p.name, d.version, p.ecosystem
    FROM deps d
    JOIN repos r ON d.repo_id = r.id
    JOIN packages p ON d.pkg_id = p.id
    WHERE r.name = '$name'
    ORDER BY p.ecosystem, p.name;
  " | while IFS='|' read -r pkg ver eco; do
    printf "  [%s] %-30s %s\n" "$eco" "$pkg" "${ver:-*}"
  done
}

# ═══ Popular: most depended-on packages ═══
popular() {
  log "Most depended-on packages (blast radius):"
  echo ""
  printf "  %-30s %-8s %-8s %s\n" "Package" "Repos" "Eco" "Blast"
  printf "  %-30s %-8s %-8s %s\n" "───────" "─────" "───" "─────"
  sqlite3 "$DB" "
    SELECT p.name, COUNT(DISTINCT d.repo_id) as cnt, p.ecosystem
    FROM deps d
    JOIN packages p ON d.pkg_id = p.id
    GROUP BY p.id
    HAVING cnt > 1
    ORDER BY cnt DESC
    LIMIT 30;
  " | while IFS='|' read -r pkg cnt eco; do
    local total=$(sqlite3 "$DB" "SELECT COUNT(*) FROM repos;")
    local pct=$((cnt * 100 / total))
    printf "  %-30s %-8s %-8s %s%%\n" "$pkg" "$cnt" "$eco" "$pct"
  done
}

# ═══ Blast radius: if this package has a CVE, who's affected? ═══
blast() {
  local name="$1"
  log "Blast radius for '$name':"
  local affected=$(sqlite3 "$DB" "
    SELECT COUNT(DISTINCT r.name)
    FROM deps d
    JOIN repos r ON d.repo_id = r.id
    JOIN packages p ON d.pkg_id = p.id
    WHERE p.name = '$name';
  ")
  local total=$(sqlite3 "$DB" "SELECT COUNT(*) FROM repos;")
  echo ""
  ok "Affected repos: $affected / $total ($(( affected * 100 / total ))%)"
  echo ""
  query_pkg "$name"
}

# ═══ Stats ═══
show_stats() {
  echo ""
  echo "  ╔═══════════════════════════════════════════════╗"
  echo "  ║  Dependency Tree DB                           ║"
  echo "  ╚═══════════════════════════════════════════════╝"
  echo ""
  local repos=$(sqlite3 "$DB" "SELECT COUNT(*) FROM repos;")
  local pkgs=$(sqlite3 "$DB" "SELECT COUNT(*) FROM packages;")
  local edges=$(sqlite3 "$DB" "SELECT COUNT(*) FROM deps;")
  ok "Repos:        $repos"
  ok "Packages:     $pkgs"
  ok "Dep edges:    $edges"
  echo ""
  log "By ecosystem:"
  sqlite3 "$DB" "SELECT ecosystem, COUNT(*) FROM packages GROUP BY ecosystem ORDER BY COUNT(*) DESC;" | while IFS='|' read -r eco cnt; do
    printf "  %-10s %s packages\n" "$eco" "$cnt"
  done
  echo ""
  log "Top 10 most-used:"
  sqlite3 "$DB" "
    SELECT p.name, COUNT(DISTINCT d.repo_id), p.ecosystem
    FROM deps d JOIN packages p ON d.pkg_id = p.id
    GROUP BY p.id ORDER BY COUNT(DISTINCT d.repo_id) DESC LIMIT 10;
  " | while IFS='|' read -r pkg cnt eco; do
    printf "  %-30s %s repos (%s)\n" "$pkg" "$cnt" "$eco"
  done
}

# ═══ Main ═══
CMD="${1:-stats}"
case "$CMD" in
  build)   build_db "${2:-.}" ;;
  query)   query_pkg "${2:?Usage: $0 query <package-name>}" ;;
  tree)    tree_repo "${2:?Usage: $0 tree <repo-name>}" ;;
  popular) popular ;;
  blast)   blast "${2:?Usage: $0 blast <package-name>}" ;;
  stats)   show_stats ;;
  *)
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  build <path>    Scan repos, build dependency graph"
    echo "  query <pkg>     Who depends on this package?"
    echo "  tree <repo>     Show all deps of a repo"
    echo "  popular         Most depended-on packages (highest blast radius)"
    echo "  blast <pkg>     If this has a CVE, who's affected?"
    echo "  stats           DB statistics"
    ;;
esac
