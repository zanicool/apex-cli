#!/bin/bash
# unified-scan.sh — Combined SAST+DAST pipeline (cpm + apex-cli = 1+1=3)
#
# Runs cpm (SAST) first for code intelligence, then feeds that into
# apex-cli (DAST) for targeted dynamic testing. Correlates findings.
#
# Usage: ./scripts/unified-scan.sh <target> [repo-path]

set -euo pipefail

TARGET="${1:-}"
REPO="${2:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APEX="${SCRIPT_DIR}/../build/apex-cli"
OUTPUT_DIR="unified_scan_$(date +%Y%m%d_%H%M%S)"

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target> [repo-path]"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "╔══════════════════════════════════════════╗"
echo "║  UNIFIED SCAN (SAST + DAST)              ║"
echo "╚══════════════════════════════════════════╝"

# ─── Phase 1: SAST ───────────────────────────────────────────────────
echo ""
echo "[Phase 1] SAST — Static analysis"

CPM_FINDINGS=""
if command -v cpm >/dev/null 2>&1 && [ -d "$REPO" ]; then
  (cd "$REPO" && cpm check 2>/dev/null) > "$OUTPUT_DIR/sast_output.txt" 2>&1 || true
  if [ -f "$REPO/.tmp/findings.jsonl" ]; then
    CPM_FINDINGS="$REPO/.tmp/findings.jsonl"
    echo "  -> $(wc -l < "$CPM_FINDINGS" | tr -d ' ') SAST findings"
    cp "$CPM_FINDINGS" "$OUTPUT_DIR/sast_findings.jsonl"
  fi
else
  echo "  -> [skip] cpm not available"
fi

# ─── Phase 2: DAST ───────────────────────────────────────────────────
echo ""
echo "[Phase 2] DAST — Dynamic analysis"

[ -x "$APEX" ] || (cd "$SCRIPT_DIR/.." && make build 2>/dev/null)
$APEX "$TARGET" --output "$OUTPUT_DIR/dast" --crawl-depth 2 --max-urls 200 2>&1 | tee "$OUTPUT_DIR/dast_output.txt"

# ─── Phase 3: Correlate ──────────────────────────────────────────────
echo ""
echo "[Phase 3] Correlation"

DAST_REPORT="$OUTPUT_DIR/dast/report.json"
UNIFIED="$OUTPUT_DIR/unified_findings.jsonl"

[ -f "$OUTPUT_DIR/sast_findings.jsonl" ] && cat "$OUTPUT_DIR/sast_findings.jsonl" >> "$UNIFIED" 2>/dev/null

if [ -f "$DAST_REPORT" ] && command -v jq >/dev/null 2>&1; then
  NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  jq -c ".findings[] | {ts:\"$NOW\",check:(\"dast-\" + .type),severity:.severity,file:.url,line:0,rule:.type,message:.detail}" "$DAST_REPORT" >> "$UNIFIED" 2>/dev/null

  CRIT=$(jq '[.findings[] | select(.severity=="critical")] | length' "$DAST_REPORT")
  HIGH=$(jq '[.findings[] | select(.severity=="high")] | length' "$DAST_REPORT")
  echo "  DAST: $CRIT critical, $HIGH high"

  # Correlate: secrets in code + exposed tech = high risk
  if [ -n "$CPM_FINDINGS" ] && grep -q "secret" "$CPM_FINDINGS" 2>/dev/null; then
    if [ "$CRIT" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
      echo "  ⚠ CORRELATION: Secrets in code + runtime vulnerabilities = elevated risk"
    fi
  fi
fi

# ─── PII Redaction ────────────────────────────────────────────────────
PII_FILE=".config/.pii"
if [ -f "$PII_FILE" ]; then
  while IFS= read -r pattern; do
    [[ "$pattern" =~ ^#.*$ ]] && continue
    [[ -z "$pattern" ]] && continue
    # Redact PII from all output files
    find "$OUTPUT_DIR" -type f \( -name "*.json" -o -name "*.jsonl" -o -name "*.txt" \) \
      -exec sed -i'' "s|$pattern|[REDACTED]|g" {} \; 2>/dev/null
  done < "$PII_FILE"
  echo "  -> PII patterns redacted from output"
fi

# ─── Summary ─────────────────────────────────────────────────────────
TOTAL=$(wc -l < "$UNIFIED" 2>/dev/null | tr -d ' ' || echo 0)
echo ""
echo "══════════════════════════════════════════"
echo "  Total findings: $TOTAL (SAST + DAST)"
echo "  Output: $OUTPUT_DIR/"
echo "══════════════════════════════════════════"
