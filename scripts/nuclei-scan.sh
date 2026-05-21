#!/bin/bash
# nuclei-scan.sh — Run Nuclei CVE templates based on apex-cli CMS detection.
# Usage: ./scripts/nuclei-scan.sh <target> [cms]
# Example: ./scripts/nuclei-scan.sh https://axiehuis.nl joomla

set -euo pipefail

TARGET="${1:-}"
CMS="${2:-auto}"
OUTPUT_DIR="nuclei_$(echo "$TARGET" | sed 's|https\?://||;s|[/.]|_|g')_$(date +%Y%m%d_%H%M%S)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <target> [cms]"
  echo "  cms: auto, joomla, wordpress, drupal, magento (default: auto)"
  exit 1
fi

# Check Nuclei installation.
if ! command -v nuclei &>/dev/null; then
  echo -e "${RED}[!] Nuclei not installed.${NC}"
  echo ""
  echo "Install with:"
  echo "  brew install nuclei          # macOS"
  echo "  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  # Go"
  echo ""
  echo "Then update templates:"
  echo "  nuclei -update-templates"
  exit 1
fi

# Ensure templates are up to date.
echo -e "${YELLOW}[*] Updating Nuclei templates...${NC}"
nuclei -update-templates -silent 2>/dev/null || true

# Auto-detect CMS from apex-cli output if needed.
if [ "$CMS" = "auto" ]; then
  echo -e "${YELLOW}[*] Auto-detecting CMS on $TARGET...${NC}"
  # Quick Nuclei tech detection.
  CMS_RESULT=$(nuclei -u "$TARGET" -tags tech -silent 2>/dev/null || true)
  if echo "$CMS_RESULT" | grep -qi "joomla"; then
    CMS="joomla"
  elif echo "$CMS_RESULT" | grep -qi "wordpress"; then
    CMS="wordpress"
  elif echo "$CMS_RESULT" | grep -qi "drupal"; then
    CMS="drupal"
  elif echo "$CMS_RESULT" | grep -qi "magento"; then
    CMS="magento"
  else
    CMS="generic"
  fi
  echo -e "${GREEN}[+] Detected: $CMS${NC}"
fi

mkdir -p "$OUTPUT_DIR"

echo -e "${YELLOW}[*] Running Nuclei CVE scan against $TARGET (CMS: $CMS)${NC}"
echo ""

# Build tag filter based on CMS.
case "$CMS" in
  joomla)
    TAGS="joomla,cve"
    ;;
  wordpress)
    TAGS="wordpress,cve,wp-plugin"
    ;;
  drupal)
    TAGS="drupal,cve"
    ;;
  magento)
    TAGS="magento,cve"
    ;;
  *)
    TAGS="cve"
    ;;
esac

# Run Nuclei with relevant templates.
nuclei -u "$TARGET" \
  -tags "$TAGS" \
  -severity critical,high,medium \
  -output "$OUTPUT_DIR/findings.txt" \
  -jsonl -output "$OUTPUT_DIR/findings.jsonl" \
  -silent \
  2>/dev/null || true

# Also run exposed panels/misconfig checks.
nuclei -u "$TARGET" \
  -tags "$CMS,misconfig,exposure" \
  -output "$OUTPUT_DIR/misconfig.txt" \
  -silent \
  2>/dev/null || true

# Summary.
echo ""
echo -e "${GREEN}[+] Scan complete${NC}"
echo "    Results: $OUTPUT_DIR/findings.txt"
echo "    JSONL:   $OUTPUT_DIR/findings.jsonl"
echo ""

if [ -f "$OUTPUT_DIR/findings.txt" ] && [ -s "$OUTPUT_DIR/findings.txt" ]; then
  CRIT=$(grep -c "\[critical\]" "$OUTPUT_DIR/findings.txt" 2>/dev/null || echo 0)
  HIGH=$(grep -c "\[high\]" "$OUTPUT_DIR/findings.txt" 2>/dev/null || echo 0)
  MED=$(grep -c "\[medium\]" "$OUTPUT_DIR/findings.txt" 2>/dev/null || echo 0)
  echo -e "    ${RED}Critical: $CRIT${NC}  ${YELLOW}High: $HIGH${NC}  Medium: $MED"
  echo ""
  echo "--- Findings ---"
  cat "$OUTPUT_DIR/findings.txt"
else
  echo "    No vulnerabilities found (or target not reachable)."
fi

if [ -f "$OUTPUT_DIR/misconfig.txt" ] && [ -s "$OUTPUT_DIR/misconfig.txt" ]; then
  echo ""
  echo "--- Misconfigurations ---"
  cat "$OUTPUT_DIR/misconfig.txt"
fi
