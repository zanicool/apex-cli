#!/bin/bash
# Nuclei scanner for Next.js/API endpoints with custom templates

set -e

TARGET="${1:-http://localhost:3000}"
OUTPUT_DIR="reports/nuclei"
TEMPLATES_DIR="nuclei/templates"

mkdir -p "$OUTPUT_DIR"

echo "[*] Running Nuclei security scan on $TARGET"

# Update templates
echo "[*] Updating Nuclei templates..."
nuclei -update-templates

# Run comprehensive scan
nuclei -u "$TARGET" \
  -t "$TEMPLATES_DIR" \
  -t ~/nuclei-templates/http \
  -t ~/nuclei-templates/cves \
  -t ~/nuclei-templates/exposures \
  -t ~/nuclei-templates/misconfiguration \
  -t ~/nuclei-templates/vulnerabilities \
  -severity critical,high,medium \
  -json -o "$OUTPUT_DIR/nuclei-results.json" \
  -markdown-export "$OUTPUT_DIR" \
  -stats \
  -silent

# Check for critical/high findings
CRITICAL=$(jq '[.[] | select(.info.severity=="critical")] | length' "$OUTPUT_DIR/nuclei-results.json")
HIGH=$(jq '[.[] | select(.info.severity=="high")] | length' "$OUTPUT_DIR/nuclei-results.json")

echo "[+] Scan complete"
echo "    Critical: $CRITICAL"
echo "    High: $HIGH"

if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
  echo "[!] Critical or high severity issues found"
  exit 1
fi

echo "[+] No critical/high issues found"
