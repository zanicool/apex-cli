# ADR-005: Autonomous Attack Brain

*Date*: 2026-05-22
*Status*: proposed

## Context

apex-cli vindt individuele vulnerabilities, maar kan ze niet **chainen** tot een volledige exploit. Een menselijke hacker doet:

1. Vind IDOR → lees admin reset token
2. Reset admin password → login als admin
3. Vind command exec endpoint → bypass WAF
4. Lees /etc/passwd → bewijs impact

apex-cli stopt na stap 1. Het autonome systeem moet de hele keten automatisch doorlopen.

## Decision

### LLM-Driven Attack Planner

Een lokale LLM (ollama) of API-based LLM analyseert findings en genereert vervolgacties:

```
┌─────────────────────────────────────────────────────────┐
│  APEX AUTONOMOUS BRAIN                                   │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Scanner findings                                       │
│       │                                                 │
│       ▼                                                 │
│  ┌─────────────┐    ┌──────────────┐                   │
│  │ LLM Planner │───▶│ Action Queue │                   │
│  └─────────────┘    └──────────────┘                   │
│       │                    │                            │
│       │ "Given IDOR at     │ 1. GET /api/users/1       │
│       │  /api/users/{id},  │ 2. Extract reset_token    │
│       │  try id=1 for      │ 3. POST /reset            │
│       │  admin data"       │ 4. Login as admin         │
│       │                    │ 5. Explore admin endpoints│
│       ▼                    ▼                            │
│  ┌─────────────┐    ┌──────────────┐                   │
│  │ Verify      │◀───│ HTTP Executor│                   │
│  └─────────────┘    └──────────────┘                   │
│       │                                                 │
│       ▼                                                 │
│  Finding with FULL exploit chain + impact proof         │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Components

| Component | Implementation | Priority |
|-----------|---------------|----------|
| Attack Planner | LLM prompt + findings → next actions | P0 |
| Action Executor | HTTP client with session/cookies | P0 |
| Chain Tracker | State machine: what we know, what to try | P0 |
| Headless Browser | Playwright/CDP for JS-heavy apps | P1 |
| Payload Generator | LLM generates context-aware payloads | P1 |
| Impact Prover | Auto-screenshot, data extraction proof | P2 |
| Auto-Reporter | HackerOne format report generation | P2 |

### Attack Planner Prompt

```
You are a penetration tester. Given these findings from a scan:

{findings_json}

And this application context:
- Tech stack: {tech_stack}
- Endpoints discovered: {endpoints}
- Authentication: {auth_state}

Generate the next 5 actions to escalate access or prove impact.
Each action must be a concrete HTTP request or browser action.

Output JSON:
[
  {"action": "http_get", "url": "...", "headers": {...}, "reason": "..."},
  {"action": "http_post", "url": "...", "body": "...", "reason": "..."},
  ...
]
```

### Session State Machine

```
UNAUTHENTICATED
    │ found credentials/token
    ▼
AUTHENTICATED (user)
    │ found privilege escalation
    ▼
AUTHENTICATED (admin)
    │ found code execution
    ▼
RCE_CONFIRMED
    │ read sensitive file
    ▼
IMPACT_PROVEN → generate report
```

## Implementation Plan

### Phase 1: Chain Executor (no LLM needed)

Hardcoded attack patterns that chain findings:

```cpp
// If IDOR found → try all user IDs → extract sensitive fields
// If JWT weak secret → crack → forge admin token
// If SSRF found → try cloud metadata endpoints
// If SQLi found → extract credentials table
```

### Phase 2: LLM Planner

Shell out to `ollama` or OpenAI API for reasoning:

```cpp
std::string plan = llm_plan(findings, context);
auto actions = parse_actions(plan);
for (auto& action : actions) {
    auto result = execute(action);
    update_state(result);
}
```

### Phase 3: Full Autonomy

- Continuous loop: scan → plan → execute → verify → report
- Human-in-the-loop for high-risk actions (actual exploitation)
- Auto-submit confirmed findings to HackerOne

## Consequences

### Positive
- Finds complex multi-step vulnerabilities automatically
- Proves impact (not just "might be vulnerable")
- Generates complete exploit chains for reports
- Learns from each engagement (pattern database)

### Negative
- LLM dependency (ollama local or API costs)
- Risk of unintended actions (needs guardrails)
- Legal: must stay within authorized scope
- False chains: LLM might hallucinate attack paths

### Guardrails
- `--autonomous` flag required (never default)
- Scope enforcement: only target authorized domains
- Action log: every HTTP request logged
- Human approval for: account creation, data modification, file writes
- Max chain depth: 10 steps (prevent infinite loops)
- Rate limit: max 10 requests/second in autonomous mode

## References

- HTB Headless, Sau, Clicker, Codify — real attack chains we modeled
- OWASP Testing Guide v4.2 — methodology
- Burp Suite Collaborator — OOB confirmation model
- AutoGPT/AgentGPT — autonomous agent patterns
