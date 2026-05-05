# Apex CLI v9.2

**The most advanced open-source automated penetration testing tool available.**

354 scan phases, 24,000+ lines of code, browser-confirmed exploits, zero false positives, OOB exploitation platform, feedback loop attack chaining, and an intelligence engine that scores, verifies, and proves every finding — all in a single command.

> Finds what Nuclei, ZAP, Burp Suite, and Nikto miss. Free and open source.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Install](#install)
- [Usage](#usage)
- [Scan Modes](#scan-modes)
- [How It Works](#how-it-works)
- [Scanner Categories](#scanner-categories)
- [Intelligence Engine](#intelligence-engine)
- [OOB Server](#oob-server)
- [AI Integration](#ai-integration)
- [External Tools](#external-tools)
- [Output & Reports](#output--reports)
- [Configuration](#configuration)
- [Development History](#development-history)

---

## Features

### Core Capabilities
- **354 scan phases** running in parallel with adaptive concurrency (50 workers on fast targets)
- **Zero false positives** — 3-layer verification: exploitability filter → re-verification → browser confirmation
- **Browser-confirmed XSS** — Playwright/Chromium proves JavaScript actually executes
- **Safe exploitation engine** — proves criticals are real without causing harm (extracts DB version, not data)
- **Feedback loop** — findings from early phases feed into deeper attacks automatically
- **HackerOne reports auto-generated** — ready-to-submit markdown reports for every critical/high finding

### Recon & Discovery
- **Subdomain enumeration** — Subfinder, cert transparency, DNS brute-force (80+ enterprise prefixes), permutation
- **Deep crawling** — 200+ pages, JS route extraction, API endpoint inference, SPA rendering via Playwright
- **Auto-registration** — automatically creates test accounts to enable authenticated scanning
- **Historical URLs** — GAU pulls from Wayback Machine, CommonCrawl, AlienVault OTX
- **Hidden endpoint discovery** — 60+ common paths, backup files, null byte bypass, API docs

### Attack Surface
- **13 external tools integrated** — subfinder, httpx, nuclei, ffuf, nmap, sqlmap, katana, dalfox, gau, dnsx, gospider, crlfuzz, interactsh
- **All 12,958 Nuclei templates** — CVEs, exposed panels, default logins, misconfigs, DAST (auto-updates)
- **OpenAPI/Swagger fuzzing** — auto-discovers specs, fuzzes every field with type-aware payloads
- **Authenticated crawling** — logs in via JSON/form, extracts JWT, crawls behind auth

### Exploitation
- **WAF bypass engine** — 12 mutation strategies, fingerprints exact WAF (Cloudflare/AWS/Akamai/Imperva/F5/ModSec) and uses specific bypasses
- **SSRF → Cloud credential theft** — auto-escalates to AWS/GCP/Azure key extraction, internal port scan
- **JWT full attack suite** — alg:none, kid injection, HS256/RS256 confusion with public key extraction, JWKS spoofing
- **Attack chain detection** — XSS+CSRF=ATO, SSRF+cloud=cred theft, open redirect+OAuth=ATO
- **Race condition exploitation** — finds exact TOCTOU window at increasing concurrency levels
- **API Cascade Privilege Escalation** — novel attack exploiting inter-service trust in microservices

### Enterprise-Grade
- **CDN origin bypass** — finds real server IP behind Cloudflare/CloudFront/Fastly
- **Microservice discovery** — Spring Cloud Gateway routes, Kong, K8s service endpoints
- **SSO chain attack** — exploits trust between services sharing SSO
- **API gateway exploitation** — path traversal through gateway, header injection, stage enumeration
- **Internal API discovery** — Vault, Consul, Eureka, Elasticsearch, Kibana, Grafana, Prometheus

### Theoretical Limits
- **Response oracle** — behavioral anomaly detection (catches zero-days no signature knows)
- **Entropy analysis** — mathematically proves token predictability
- **Compression oracle** — BREACH-style secret extraction via response size
- **State machine inference** — finds illegal auth state transitions
- **Markov prediction** — predicts sequential IDs from observed patterns

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        APEX CLI v9.2                          │
├─────────────────────────────────────────────────────────────┤
│  apex.py (212KB)        — Main orchestrator, CLI, phases     │
│  scanners.py (772KB)    — 354 scanner functions              │
│  apex_ai.py (24KB)      — Multi-LLM AI engine               │
│  apex-auto.py (16KB)    — Bug bounty auto-scanner            │
│  oob_server.py (24KB)   — OOB exploitation platform          │
│  benchmark.py (12KB)    — Hardware auto-tuning               │
├─────────────────────────────────────────────────────────────┤
│  wordlists/ (2.7GB)     — SecLists + Assetnote + custom      │
│  nuclei-templates/ (81MB) — 12,958 vulnerability templates   │
│  ~/go/bin/ (515MB)      — 13 Go security tools               │
└─────────────────────────────────────────────────────────────┘
```

### Scan Pipeline

```
Recon → Probe → Fingerprint → Fuzz → Crawl → SPA Crawl → Katana → GAU
    → API Inference → JS Route Extraction → Auto-Registration
        → 300+ parallel attack phases (50 workers)
            → Feedback loop (pivot through confirmed findings)
                → Safe exploitation (prove impact)
                    → Intelligence engine (filter → verify → score → PoC)
                        → Reports (terminal + JSON + HTML + SARIF + H1)
```

---

## Install

```bash
git clone https://github.com/zanicool/apex-cli.git && cd apex-cli
chmod +x install.sh && sudo ./install.sh
```

This installs:
- Python dependencies (rich, jinja2, requests, beautifulsoup4, playwright, websocket-client)
- Playwright + Chromium browser
- Go runtime + 13 security tools
- SecLists wordlists
- Nuclei templates

### Manual Install

```bash
pip install -r requirements.txt
python3 -m playwright install chromium
sudo ln -sf "$(pwd)/apex.py" /usr/local/bin/apex-cli
```

---

## Usage

```bash
# Standard scan
apex-cli example.com

# Deep scan (all 354 phases, browser, max coverage)
apex-cli example.com -d

# Quick scan (high-value phases only, 3-8 min)
apex-cli example.com -q

# Authenticated scan
apex-cli example.com --auth user@email.com password

# No recon (scan target directly, useful for local/Docker targets)
apex-cli localhost:3000 --no-recon

# Resume a crashed scan
apex-cli --resume scan_example.com_20260501_123456/

# Rate limit (be gentle)
apex-cli example.com --rate 0.2

# Restrict scope
apex-cli example.com --scope api.example.com /api/v2

# Interactive menu
apex-cli
```

---

## Scan Modes

| Mode | Flag | Time | Phases | Use Case |
|------|------|------|--------|----------|
| Quick | `-q` | 3-8 min | ~280 | Fast check, high-value bugs only |
| Standard | (default) | 15-30 min | 354 | Normal scanning |
| Deep | `-d` | 45-90 min | 354 + more crawl depth | Maximum coverage |
| Dry Run | `-n` | instant | 0 | Preview what would run |

---

## How It Works

### Phase 1: Reconnaissance
- Subdomain enumeration (subfinder, cert transparency, DNS brute-force)
- 80+ enterprise-specific prefixes (jenkins, gitlab, grafana, internal, staging, etc.)
- Historical URL collection (GAU — Wayback Machine, CommonCrawl)

### Phase 2: Probing & Fingerprinting
- HTTP probing with httpx (adaptive concurrency based on response time)
- Technology fingerprinting (20+ frameworks detected)
- WAF detection and fingerprinting

### Phase 3: Crawling
- Deep HTML/JS crawl (200+ pages)
- Playwright SPA rendering (React/Vue/Angular)
- Katana headless crawl
- API endpoint inference from URL patterns
- JS route extraction from webpack bundles
- Auto-registration for authenticated crawling

### Phase 4: Active Scanning (300+ phases in parallel)
- All injection types (SQLi, XSS, SSRF, SSTI, LFI, CMDi, XXE, etc.)
- Authentication attacks (JWT, OAuth, SAML, 2FA bypass)
- Business logic (race conditions, payment bypass, IDOR)
- Infrastructure (subdomain takeover, cloud storage, exposed services)
- Browser-based (DOM XSS, postMessage, prototype pollution)

### Phase 5: Post-Scan Intelligence
- Feedback loop: pivot through confirmed findings for deeper attacks
- Safe exploitation: prove criticals without causing harm
- 3-layer false positive elimination
- CVSS scoring with exploitability rating
- PoC curl commands for every finding
- Attack chain detection

### Phase 6: Reporting
- Terminal summary with severity breakdown
- JSON report with full details
- HTML report with collapsible findings
- SARIF for CI/CD integration
- HackerOne-ready markdown reports
- Nuclei templates generated from findings
- Screenshots of all finding URLs

---

## Scanner Categories

| Category | Scanners | Examples |
|----------|----------|---------|
| Injection | 15+ | SQLi (error/boolean/time/OOB), NoSQL, LDAP, XPath, XSLT, Command, SSTI, EL, CRLF |
| XSS | 8+ | Reflected, Stored, DOM, Browser-confirmed, Markdown, SVG, CSTI, Blind XSS |
| Auth/Session | 12+ | JWT (none/kid/confusion/JWKS), OAuth2, SAML, Session fixation, 2FA bypass, Token prediction |
| SSRF | 8+ | Standard, PDF generation, Webhook, DNS rebinding, Profile image, OOB redirect, Cloud chain |
| Access Control | 10+ | IDOR (URL/body/GraphQL/authenticated), BOLA, BFLA, Privilege escalation, Mass assignment, 403 bypass |
| Business Logic | 8+ | Race condition, Payment bypass, Price manipulation, Registration abuse, Coupon stacking |
| Client-side | 8+ | Prototype pollution, postMessage, CORS, Cache poisoning, DOM clobbering, Unicode normalization |
| Infrastructure | 12+ | Subdomain takeover (40+ fingerprints), S3/GCS/Azure, Git exposure, Terraform, Docker, K8s, Jenkins |
| Crypto | 5+ | JWT confusion, Entropy analysis, Token prediction, Compression oracle, JWKS spoofing |
| File | 5+ | Upload bypass (13 techniques), Path traversal (12 encoding bypasses), LFI, Null byte, CSV injection |
| Smuggling | 4+ | CL.TE, TE.CL, CL.0, H2 desync |
| Information | 8+ | JS secrets (15 patterns), PII/sensitive data, Source maps, Backup files, Log credential leak |
| Enterprise | 8+ | WAF fingerprint+bypass, CDN origin, Microservice discovery, SSO chain, API gateway, Cloud infra |
| Novel | 3+ | API Cascade PrivEsc, Response oracle, State machine inference |

---

## Intelligence Engine

### 3-Layer False Positive Elimination

1. **`filter_exploitable_only()`** — Drops theoretical findings (missing headers, info disclosure without impact)
2. **`verify_finding()`** — 16 verification paths that re-test each finding:
   - XSS: must have executable HTML + checks CSP
   - SQLi: re-triggers DB error OR confirms boolean blind
   - SSRF: must return actual internal data
   - CORS: re-verifies credentials flag
   - Sensitive files: compares with soft-404
3. **Browser confirmation** — XSS only reported if JavaScript executes in Chromium

### Safe Exploitation Engine

After verification, proves criticals are real:
- SQLi → extracts DB version only (harmless read)
- XSS → executes `1+1=2` in browser (no alert, no cookie theft)
- SSRF → reads AWS instance-id (not credentials)
- IDOR → accesses adjacent ID, compares response size
- RCE → runs `id` only (read-only)
- JWT → documents that alg:none is accepted
- Takeover → verifies CNAME is dangling (doesn't claim)

---

## OOB Server

The OOB (Out-of-Band) server runs on a separate box and catches blind vulnerabilities:

```bash
python3 oob_server.py --domain your-oob-domain.com
```

### Services
| Service | Port | Purpose |
|---------|------|---------|
| HTTP | 9877 | Callback capture, blind XSS payload hosting, SSRF redirector |
| DNS | 5353 | DNS callbacks, data exfiltration via subdomains, DNS rebinding |
| SMTP | 2525 | Captures emails from SSRF-triggered sends |
| FTP | 2121 | Captures credentials from SSRF-triggered FTP |

### Endpoints
- `GET /<uid>` — Register callback
- `GET /poll?uid=<uid>` — Check for hits
- `GET /payload/<uid>` — Serve blind XSS payload (steals cookies+DOM+localStorage)
- `GET /redirect?url=<target>` — SSRF redirector (bypass allowlists)
- `GET /list` — View all callbacks
- `GET /dns` — View DNS queries

---

## AI Integration

Supports 3 LLM backends for post-scan analysis:

```bash
# Ollama (local, default)
export APEX_AI_BACKEND=ollama

# OpenAI API
export APEX_AI_BACKEND=openai
export OPENAI_API_KEY=sk-...

# Anthropic Claude
export APEX_AI_BACKEND=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

The AI generates:
- Bug bounty reports from findings
- Custom payloads for detected tech stack
- Attack chain analysis

---

## External Tools

| Tool | Purpose | Auto-installed |
|------|---------|---------------|
| subfinder | Subdomain enumeration | ✓ |
| httpx | HTTP probing | ✓ |
| nuclei | 12,958 vulnerability templates | ✓ |
| ffuf | Directory fuzzing | ✓ |
| nmap | Port scanning | ✓ |
| sqlmap | SQL injection exploitation | ✓ |
| katana | JS-aware headless crawling | ✓ |
| dalfox | XSS with DOM analysis + WAF bypass | ✓ |
| gau | Historical URLs (Wayback/CommonCrawl) | ✓ |
| dnsx | DNS resolution + wildcard filtering | ✓ |
| gospider | Fast web spider | ✓ |
| crlfuzz | CRLF injection scanner | ✓ |
| interactsh | OOB interaction server | ✓ |

All tools are optional — if not installed, the Python scanner handles it.

---

## Output & Reports

Each scan creates a timestamped directory:

```
scan_target.com_20260505_012345/
├── report.html          — Professional dark-themed HTML report
├── report.json          — Full scan data with CVSS scores
├── report.sarif         — CI/CD integration (GitHub Actions, Azure DevOps)
├── h1_reports/          — HackerOne-ready markdown reports
│   ├── report_1_sql_injection.md
│   ├── report_2_ssrf_cloud_credential_theft.md
│   └── ...
├── nuclei_templates/    — Reusable nuclei YAML templates from findings
├── screenshots/         — Playwright screenshots of finding URLs
├── subdomains.txt       — All discovered subdomains
├── crawl.json           — Crawled pages, forms, parameters
├── nuclei.json          — Nuclei findings
└── .apex_state.json     — Scan state for resume
```

---

## Configuration

### CLI Options

| Flag | Short | Description |
|------|-------|-------------|
| `--deep` | `-d` | All phases, max crawl depth |
| `--quick` | `-q` | High-value phases only |
| `--dry-run` | `-n` | Preview without sending packets |
| `--report FORMAT` | `-r` | Output: terminal, json, html |
| `--auth USER PASS` | | Authenticated scanning |
| `--resume DIR` | | Resume crashed scan |
| `--rate SECONDS` | | Delay between requests |
| `--workers N` | | Parallel workers (auto-tuned) |
| `--proxy URL` | | Route through Burp Suite |
| `--scope STRINGS` | | Restrict to matching targets |
| `--no-recon` | | Skip recon, scan directly |
| `--recon-only` | | Only recon, no active scanning |
| `--sarif` | | SARIF output for CI/CD |
| `--severity-filter` | | Only report specific severities |
| `--nuclei-tags` | | Filter nuclei templates |
| `--timeout SECONDS` | | Global request timeout |
| `--tools` | | Show installed tools |
| `--list-phases` | | List all scan phases |
| `--watch HOURS` | | Rescan every N hours |
| `--apk FILE` | | Scan APK for secrets |
| `--diff SCAN1 SCAN2` | | Compare two scans |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `APEX_AI_BACKEND` | LLM backend: ollama/openai/anthropic |
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `APEX_WORKERS` | Override auto-scanner worker count |
| `OOB_DOMAIN` | OOB server domain |

---

## Development History

This tool was built in a single intensive session, evolving from v8.x (157 phases) to v9.2 (354 phases):

1. **v9.0** — Added 6 new scanner modules, SARIF output, multi-LLM AI, adaptive backoff, DNS caching, connection pooling
2. **Performance** — batch_get (100 threads), 50 phase workers, 100 connection pool
3. **Browser engine** — Playwright for DOM XSS, postMessage, SPA crawling
4. **False positive elimination** — 3-layer pipeline, soft-404 detection, exploitability filter
5. **Feedback loop** — findings feed into deeper attacks (SSRF → internal port scan → credential theft)
6. **Safe exploitation** — proves criticals without causing harm
7. **Enterprise-grade** — WAF bypass, CDN origin, microservice discovery, SSO chain, API gateway
8. **Theoretical limits** — response oracle, entropy analysis, compression oracle, state machine inference
9. **OOB server v2** — HTTP + DNS + SMTP + FTP exploitation platform
10. **Docker testing** — tested against Juice Shop, found and fixed detection gaps
11. **Novel attacks** — API Cascade Privilege Escalation, JWT RS256→HS256 confusion with key fetch

### Stats
- **354 scan phases**
- **24,558 lines of code**
- **13 external tools**
- **514+ vulnerability types detected**
- **40+ subdomain takeover fingerprints**
- **6 tech-specific payload sets** (Laravel, Express, Spring, Django, Next.js, WordPress)
- **12 WAF mutation strategies**
- **100 batch worker threads**
- **3-layer false positive elimination**
- **Auto-generated HackerOne reports**
- **Auto-generated nuclei templates**

---

## License

MIT

---

## Disclaimer

This tool is for authorized security testing only. Only scan targets you have explicit permission to test. The authors are not responsible for misuse.
