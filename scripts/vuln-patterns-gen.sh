#!/bin/bash
# Validates vuln-pattern rules exist and are valid semgrep YAML
set -uo pipefail

RULES_DIR="${1:-./data/vuln-patterns}"

if [ ! -d "$RULES_DIR" ]; then
  echo "[-] Rules directory not found: $RULES_DIR" >&2
  exit 1
fi

COUNT=$(find "$RULES_DIR" -name "*.yml" | wc -l | tr -d ' ')
echo "[+] Found $COUNT rule files in $RULES_DIR"

# Validate with semgrep
if command -v semgrep >/dev/null 2>&1; then
  if semgrep --validate --config "$RULES_DIR" 2>/dev/null; then
    echo "[+] All rules valid"
  else
    echo "[-] Some rules have errors" >&2
    exit 1
  fi
fi
