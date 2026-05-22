#!/usr/bin/env bash
# llm-plan.sh — Ask LLM to plan next attack steps based on findings.
#
# Usage:
#   echo '{"findings":[...]}' | ./scripts/llm-plan.sh
#   ./scripts/llm-plan.sh < .apex/findings.jsonl
#
# Requires: ollama (local) or OPENAI_API_KEY (remote)
set -euo pipefail

MODEL="${APEX_LLM_MODEL:-llama3}"
PROVIDER="${APEX_LLM_PROVIDER:-ollama}"  # ollama | openai

SYSTEM_PROMPT='You are an expert penetration tester analyzing scan results.
Given vulnerability findings, generate the next 5 concrete actions to:
1. Verify the vulnerability is exploitable
2. Escalate access (user → admin → RCE)
3. Prove maximum impact
4. Chain multiple findings together

Rules:
- Each action must be a concrete HTTP request (method, URL, headers, body)
- Explain WHY each step helps
- Stay within authorized scope
- Focus on the highest-severity findings first

Output valid JSON array:
[{"step":1,"method":"GET","url":"...","headers":{},"body":"","reason":"..."}]'

# Read findings from stdin
FINDINGS=$(cat)

if [ -z "$FINDINGS" ]; then
  echo "No findings provided. Pipe findings.jsonl or JSON to stdin." >&2
  exit 1
fi

USER_PROMPT="Here are the scan findings:

$FINDINGS

Generate the next attack steps to escalate these findings into proven exploits."

case "$PROVIDER" in
  ollama)
    if ! command -v ollama &>/dev/null; then
      echo "ollama not found. Install: brew install ollama" >&2
      exit 1
    fi
    ollama run "$MODEL" "$SYSTEM_PROMPT

$USER_PROMPT" 2>/dev/null
    ;;
  openai)
    if [ -z "${OPENAI_API_KEY:-}" ]; then
      echo "OPENAI_API_KEY not set" >&2
      exit 1
    fi
    curl -s https://api.openai.com/v1/chat/completions \
      -H "Authorization: Bearer $OPENAI_API_KEY" \
      -H "Content-Type: application/json" \
      -d "$(jq -n \
        --arg sys "$SYSTEM_PROMPT" \
        --arg usr "$USER_PROMPT" \
        '{model:"gpt-4o-mini",messages:[{role:"system",content:$sys},{role:"user",content:$usr}],temperature:0.3}')" | \
      jq -r '.choices[0].message.content'
    ;;
  *)
    echo "Unknown provider: $PROVIDER (use ollama or openai)" >&2
    exit 1
    ;;
esac
