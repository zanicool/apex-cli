#!/bin/bash
# Apex CLI — Zero-Day Pattern Scanner
# Mines top GitHub repos for vulnerability patterns derived from real CVEs.
# Strategy: variant analysis at scale.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES_DIR="$SCRIPT_DIR/../data/vuln-patterns"
WORKDIR="./output/zeroscan-$(date +%Y%m%d-%H%M%S)"
STATE="$WORKDIR/state.log"
LOG="$WORKDIR/scan.log"
MAX_REPOS="${1:-50}"
LANG_FILTER="${2:-javascript,python,java,go,php,ruby}"

mkdir -p "$WORKDIR" "$RULES_DIR"

log()  { echo -e "\033[1;34m[*]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[+]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" | tee -a "$LOG"; }
err()  { echo -e "\033[1;31m[-]\033[0m $*" | tee -a "$LOG"; }
step_done() { grep -qxF "$1" "$STATE" 2>/dev/null; }
mark_done() { echo "$1" >> "$STATE"; }

echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║  APEX — Zero-Day Pattern Scanner              ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
log "Repos:   top $MAX_REPOS per language"
log "Langs:   $LANG_FILTER"
log "Rules:   $RULES_DIR"
log "Output:  $WORKDIR"
[ -f "$STATE" ] && warn "Resuming — $(wc -l < "$STATE" | tr -d ' ') steps done"
echo ""

# ═══════════════════════════════════════════════════════
# PHASE 1: Fetch target repos from GitHub
# ═══════════════════════════════════════════════════════
if ! step_done "repos-fetched"; then
  log "Phase 1: Fetching top repos from GitHub..."
  echo ""
  IFS=',' read -ra LANGS <<< "$LANG_FILTER"
  for lang in "${LANGS[@]}"; do
    log "  Fetching top $MAX_REPOS $lang repos..."
    gh api "search/repositories?q=language:${lang}+stars:>1000&sort=stars&per_page=${MAX_REPOS}" \
      --jq '.items[] | "\(.full_name)|\(.stargazers_count)|\(.language)|\(.default_branch)"' \
      >> "$WORKDIR/repos.txt" 2>/dev/null || true
    sleep 2  # Rate limit
  done
  REPO_COUNT=$(wc -l < "$WORKDIR/repos.txt" | tr -d ' ')
  ok "Collected $REPO_COUNT repos"
  mark_done "repos-fetched"
fi
echo ""

# ═══════════════════════════════════════════════════════
# PHASE 2: Ensure vulnerability pattern rules exist
# ═══════════════════════════════════════════════════════
if ! step_done "rules-ready"; then
  log "Phase 2: Validating pattern rules..."
  # Semgrep rules (AST-aware, precise)
  if [ -d "$RULES_DIR" ]; then
    RULE_COUNT=$(find "$RULES_DIR" -name "*.yml" | wc -l | tr -d ' ')
    ok "  Semgrep: $RULE_COUNT rules"
  else
    err "  No semgrep rules in $RULES_DIR"
  fi
  # cpm zero-day patterns (grep-based, fast, broad)
  CPM_CHECK="$SCRIPT_DIR/../../cpm/checks/universal/security/check-zero-day-patterns.sh"
  if [ -f "$CPM_CHECK" ]; then
    ok "  cpm: zero-day pattern checker available"
  else
    CPM_CHECK=""
    warn "  cpm checker not found (semgrep-only mode)"
  fi
  mark_done "rules-ready"
fi
echo ""

# ═══════════════════════════════════════════════════════
# PHASE 3: Clone & scan each repo
# ═══════════════════════════════════════════════════════
log "Phase 3: Scanning repos..."
echo ""
FINDINGS_TOTAL=0
REPOS_SCANNED=0

while IFS='|' read -r repo stars lang branch; do
  [ -z "$repo" ] && continue
  step_key="scanned:$repo"
  if step_done "$step_key"; then
    continue
  fi

  REPOS_SCANNED=$((REPOS_SCANNED + 1))
  printf "  [%d] %-40s ⭐%s " "$REPOS_SCANNED" "$repo" "$stars" | tee -a "$LOG"

  # Shallow clone (depth 1, single branch)
  clone_dir="$WORKDIR/repos/$(echo "$repo" | tr '/' '_')"
  if [ ! -d "$clone_dir" ]; then
    git clone --depth 1 --single-branch -b "${branch:-main}" \
      "https://github.com/$repo.git" "$clone_dir" 2>/dev/null || {
      echo "(clone failed)" | tee -a "$LOG"
      mark_done "$step_key"
      continue
    }
  fi

  # Run semgrep with our custom rules
  results_file="$WORKDIR/findings/$(echo "$repo" | tr '/' '_').json"
  mkdir -p "$WORKDIR/findings"
  semgrep --config "$RULES_DIR" --json --quiet --timeout 30 \
    --max-target-bytes 500000 "$clone_dir" > "$results_file" 2>/dev/null || true

  # Also run cpm's grep-based zero-day patterns (faster, catches different things)
  cpm_results="$WORKDIR/findings/$(echo "$repo" | tr '/' '_').cpm.txt"
  if [ -n "${CPM_CHECK:-}" ]; then
    (cd "$clone_dir" && bash "$CPM_CHECK" > "$cpm_results" 2>/dev/null) || true
  fi

  # Count findings
  count=$(python3 -c "
import json,sys
try:
    d=json.load(open('$results_file'))
    results=d.get('results',[])
    # Filter out test files and vendor dirs
    real=[r for r in results if '/test' not in r.get('path','') and '/vendor/' not in r.get('path','') and '/node_modules/' not in r.get('path','')]
    print(len(real))
except: print(0)
" 2>/dev/null)

  if [ "${count:-0}" -gt 0 ]; then
    FINDINGS_TOTAL=$((FINDINGS_TOTAL + count))
    ok "→ $count findings!"
    echo "$repo|$stars|$lang|$count" >> "$WORKDIR/hits.txt"
  else
    echo "" | tee -a "$LOG"
  fi

  # Cleanup clone to save disk
  rm -rf "$clone_dir"
  mark_done "$step_key"
done < "$WORKDIR/repos.txt"

echo ""

# ═══════════════════════════════════════════════════════
# PHASE 4: Analyze and rank findings
# ═══════════════════════════════════════════════════════
log "Phase 4: Analyzing findings..."
echo ""

if [ -d "$WORKDIR/findings" ]; then
  python3 << 'PYTHON' "$WORKDIR"
import json, glob, sys, os
from collections import defaultdict

workdir = sys.argv[1]
findings_dir = os.path.join(workdir, "findings")
all_findings = []

for f in glob.glob(os.path.join(findings_dir, "*.json")):
    repo = os.path.basename(f).replace(".json", "").replace("_", "/", 1)
    try:
        data = json.load(open(f))
        for r in data.get("results", []):
            path = r.get("path", "")
            if "/test" in path or "/vendor/" in path or "/node_modules/" in path:
                continue
            all_findings.append({
                "repo": repo,
                "rule": r.get("check_id", "unknown"),
                "severity": r.get("extra", {}).get("severity", "WARNING"),
                "file": path,
                "line": r.get("start", {}).get("line", 0),
                "message": r.get("extra", {}).get("message", ""),
                "code": r.get("extra", {}).get("lines", "")[:200]
            })
    except:
        pass

# Sort by severity
sev_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
all_findings.sort(key=lambda x: sev_order.get(x["severity"], 9))

# Write ranked report
report_path = os.path.join(workdir, "report.txt")
with open(report_path, "w") as out:
    out.write(f"=== ZERO-DAY PATTERN SCAN RESULTS ===\n")
    out.write(f"Total findings: {len(all_findings)}\n\n")
    
    by_rule = defaultdict(list)
    for f in all_findings:
        by_rule[f["rule"]].append(f)
    
    for rule, items in sorted(by_rule.items(), key=lambda x: -len(x[1])):
        out.write(f"\n{'='*60}\n")
        out.write(f"PATTERN: {rule} ({len(items)} hits)\n")
        out.write(f"{'='*60}\n")
        for item in items[:5]:  # Top 5 per pattern
            out.write(f"\n  Repo: {item['repo']}\n")
            out.write(f"  File: {item['file']}:{item['line']}\n")
            out.write(f"  Sev:  {item['severity']}\n")
            out.write(f"  Code: {item['code']}\n")
            out.write(f"  ---\n")

# Also write JSON for further processing
json.dump(all_findings, open(os.path.join(workdir, "findings-all.json"), "w"), indent=2)

print(f"  Total findings: {len(all_findings)}")
print(f"  Unique patterns: {len(by_rule)}")
print(f"  Repos with hits: {len(set(f['repo'] for f in all_findings))}")
print(f"  Report: {report_path}")
PYTHON
fi

# ═══════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════
echo ""
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║           SCAN COMPLETE                       ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo ""
ok "Repos scanned:  $REPOS_SCANNED"
ok "Total findings: $FINDINGS_TOTAL"
ok "Results:        $WORKDIR/"
echo "    report.txt       — ranked findings"
echo "    findings-all.json— machine-readable"
echo "    hits.txt         — repos with findings"
echo ""
log "Resume: $0 $MAX_REPOS $LANG_FILTER"
log "Next: review report.txt, verify exploitability, write PoC"
