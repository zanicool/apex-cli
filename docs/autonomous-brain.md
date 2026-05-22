# 🧠 Autonomous Brain — Roadmap

## Wat het is

apex-cli vindt kwetsbaarheden. De Autonomous Brain **chaint** ze tot volledige exploits.

```
Zonder brain:  "IDOR gevonden op /api/users/5"
Met brain:     "IDOR → admin data gelezen → reset token gestolen → admin password gereset → RCE via exec endpoint"
```

## Status

| Component | Status | Wat het doet |
|-----------|--------|-------------|
| Chain Executor | ✅ Done | Hardcoded patterns: IDOR→enum, SSRF→metadata, SQLi→extract, LFI→read, SSTI→RCE |
| LLM Planner | ✅ Script | `scripts/llm-plan.sh` — vraag ollama/GPT om volgende stappen |
| Headless Browser | ❌ TODO | JS-heavy apps, login flows, klikken |
| Payload Generator | ❌ TODO | Context-aware payloads via LLM |
| Auto-Reporter | ❌ TODO | HackerOne format rapport genereren |
| Impact Prover | ❌ TODO | Screenshots, data extraction bewijs |

## Hoe te gebruiken

### Chain Executor (nu)

```bash
# Scan + chain findings automatisch
./build/apex-cli target.com --chain

# Alleen chainen op bestaande findings
./build/apex-cli target.com --chain --no-scan
```

### LLM Planner (nu, experimenteel)

```bash
# Laat LLM volgende stappen plannen op basis van findings
cat .apex/findings.jsonl | ./scripts/llm-plan.sh

# Met OpenAI in plaats van ollama
APEX_LLM_PROVIDER=openai OPENAI_API_KEY=sk-... cat .apex/findings.jsonl | ./scripts/llm-plan.sh
```

### Volledig autonoom (toekomst)

```bash
# De droom: scan → chain → verify → report → submit
./build/apex-cli target.com --autonomous --program shopify
```

## Volgende stappen voor Zani

1. **Test de chain executor** tegen de CTF challenges:
   ```bash
   make ctf-up
   ./build/apex-cli localhost:5010 --chain  # IDOR challenge
   ./build/apex-cli localhost:5013 --chain  # Headless (multi-step)
   ```

2. **Verbeter chain patterns** — voeg nieuwe chains toe in `src/chain.cpp`

3. **LLM integratie** — laat ollama de chain executor aansturen:
   ```bash
   ollama pull llama3
   cat findings.jsonl | ./scripts/llm-plan.sh
   ```

4. **Headless browser** — voor JS-heavy targets (Playwright/CDP)

## Architectuur

```
findings.jsonl
     │
     ▼
┌─────────────┐     ┌──────────────┐
│ Chain Exec  │────▶│ LLM Planner  │ (optional)
│ (hardcoded) │     │ (ollama/GPT) │
└─────────────┘     └──────────────┘
     │                     │
     ▼                     ▼
┌─────────────┐     ┌──────────────┐
│ HTTP Client │     │ Action Queue │
│ (sessions)  │     │ (next steps) │
└─────────────┘     └──────────────┘
     │
     ▼
┌─────────────┐
│ Impact Proof│ → report.json met volledige exploit chain
└─────────────┘
```

## De uitdaging

**Kan de Autonomous Brain de Level 5 CTF challenges oplossen?**

| Challenge | Kan chain executor het? | Wat mist? |
|-----------|------------------------|-----------|
| lvl5-headless | ❌ Nee | Moet debug page vinden + API key extracten |
| lvl5-sau | ❌ Nee | Moet JS lezen + service discovery |
| lvl5-clicker | ❌ Nee | Race condition + JWT cracking |
| lvl5-codify | ❌ Nee | Sandbox escape = creatief denken |
| lvl5-megacorp | 🟡 Deels | IDOR chain werkt, maar WAF bypass niet |

**Doel**: als de brain alle 5 kan oplossen, is het klaar voor echte bounties.
