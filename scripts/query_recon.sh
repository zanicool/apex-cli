#!/bin/bash
# Query JSONL recon logs

RECON_DIR="${1:-.}"

echo "=== RECON HISTORY QUERY TOOL ==="
echo ""

# CMS History
echo "📦 CMS DETECTIONS:"
if [ -f "$RECON_DIR/cms_recon.jsonl" ]; then
    echo "Total: $(wc -l < "$RECON_DIR/cms_recon.jsonl")"
    echo ""
    echo "Outdated CMS:"
    jq -r 'select(.outdated == true) | "\(.timestamp) | \(.cms) \(.version) → \(.latest) | \(.url)"' "$RECON_DIR/cms_recon.jsonl" | column -t -s'|'
    echo ""
fi

# OSINT Leaks
echo "🔴 CRITICAL LEAKS:"
if [ -f "$RECON_DIR/osint_recon.jsonl" ]; then
    jq -r 'select(.type == "leak" and .severity == "critical") | "\(.timestamp) | \(.source) | \(.leak_type) | \(.value)"' "$RECON_DIR/osint_recon.jsonl" | column -t -s'|'
    echo ""
fi

# Employee Exposure
echo "👥 EXPOSED EMPLOYEES:"
if [ -f "$RECON_DIR/osint_recon.jsonl" ]; then
    jq -r 'select(.type == "employee") | "\(.email) | \(.name)"' "$RECON_DIR/osint_recon.jsonl" | sort -u | column -t -s'|'
    echo ""
fi

# Tech Stack
echo "💻 TECHNOLOGY STACK:"
if [ -f "$RECON_DIR/osint_recon.jsonl" ]; then
    jq -r 'select(.type == "techstack") | .technology' "$RECON_DIR/osint_recon.jsonl" | sort | uniq -c | sort -rn
    echo ""
fi

# Vulnerabilities
echo "⚠️  VULNERABILITIES:"
if [ -f "$RECON_DIR/vuln_recon.jsonl" ]; then
    echo "Total: $(wc -l < "$RECON_DIR/vuln_recon.jsonl")"
    echo ""
    echo "By Severity:"
    jq -r '.severity' "$RECON_DIR/vuln_recon.jsonl" | sort | uniq -c | sort -rn
    echo ""
    echo "Critical Findings:"
    jq -r 'select(.severity == "critical") | "\(.type) | \(.url) | \(.detail)"' "$RECON_DIR/vuln_recon.jsonl" | head -10 | column -t -s'|'
fi

# Timeline
echo ""
echo "📅 TIMELINE:"
if [ -f "$RECON_DIR/vuln_recon.jsonl" ]; then
    jq -r '"\(.timestamp) | \(.type) | \(.severity)"' "$RECON_DIR/vuln_recon.jsonl" | tail -20 | column -t -s'|'
fi
