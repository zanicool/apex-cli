# Apex CLI v7.0

Automated pen-test orchestrator — 157 scan phases, parallel execution, OOB confirmation, attack chain detection, and an intelligence engine that scores and verifies every finding.

## Features

- **157 scan phases** running in parallel with adaptive concurrency
- **Passive recon** — HackerTarget, AlienVault OTX, URLScan.io, Wayback Machine
- **Subdomain enumeration** — Subfinder, cert transparency, DNS brute-force, permutation
- **OpenAPI/Swagger spec parsing** — auto-discovers all endpoints and parameters
- **JSON API crawling** — extracts params from JSON responses, not just HTML
- **Authenticated crawling** — logs in via JSON/form, extracts JWT, crawls behind auth
- **OOB confirmation** — interactsh (auto-installs) with API fallback for blind SSRF/SQLi/CMDi
- **Context-aware mutation** — detects JS string / HTML attr / URL / JSON context, adapts payloads
- **All 12,958 Nuclei templates** — CVEs, exposed panels, default logins, misconfigs, DAST (auto-updates)
- **Attack chain detection** — XSS+CSRF=ATO, SSRF+cloud=cred theft, open redirect+OAuth=ATO
- **CVSS scoring + FP verification** — every finding scored and re-verified before reporting
- **Scan state persistence** — crash at phase 100, resume with `--resume`
- **Professional HTML report** — collapsible findings, PoC commands, remediation per vuln class
- **Logic bug scanners** — price manipulation, payment bypass, race conditions, parameter tampering
- **Rate limiting + scope filter** — `--rate 0.1` and `--scope api.example.com`

## Install

```bash
git clone https://github.com/zanicool/apex-cli.git && cd apex-cli
chmod +x install.sh && sudo ./install.sh
```

## Usage

```bash
# Basic scan
apex-cli example.com

# Deep scan with HTML report
apex-cli example.com --deep --report html json

# Authenticated scan
apex-cli example.com --auth user@email.com password

# Resume a crashed scan
apex-cli --resume scan_example.com_20260501_123456/

# Rate limit (be gentle on slow targets)
apex-cli example.com --rate 0.2

# Restrict to specific scope
apex-cli example.com --scope api.example.com /api/v2

# Preview without sending packets
apex-cli example.com --dry-run

# Show installed tools
apex-cli --tools
```

## Options

| Flag | Description |
|------|-------------|
| `--deep` | More tools, higher intensity, wider port range, all severities |
| `--report FORMAT` | Output formats: `terminal` `json` `html` (multiple allowed) |
| `--auth USER PASS` | Credentials for authenticated crawling and scanning |
| `--resume DIR` | Resume a previous scan from its output directory |
| `--rate SECONDS` | Delay between requests per thread (e.g. `0.1`) |
| `--scope STRINGS` | Restrict web targets to matching strings |
| `--skip PHASES` | Skip specific phases (e.g. `--skip nuclei sqli`) |
| `--dry-run` | Preview commands without executing |
| `--tools` | Show available tools and exit |

## Scan Phases (157 total)

**Recon:** Subfinder, cert transparency, passive recon (OTX/URLScan/Wayback/HackerTarget), DNS brute-force, subdomain permutation

**Probe:** httpx → nmap → curl fallback, adaptive concurrency based on response time, target prioritization

**Crawl:** HTML + JSON API + JS fetch/axios extraction, OpenAPI/Swagger spec parsing, authenticated crawl, AJAX spider (Playwright)

**Injection:** SQLi (error/boolean/time-based), XSS (context-aware), CMDi, SSTI, SSRF, LFI/RFI, XXE, EL injection, PHP object injection, NoSQL, XPath, XSLT, SSI

**Auth:** JWT alg confusion, OAuth misconfig, SAML injection, broken auth, default creds, 2FA bypass, account state manipulation, response manipulation ATO

**Logic:** Price manipulation, payment flow bypass, race conditions (registration/coupon/transfer), parameter tampering, forced browsing, IDOR (UUID prediction, pagination)

**Infrastructure:** Subdomain takeover (CNAME+NS), S3/Azure/GCS buckets, cloud metadata SSRF, DNS zone transfer, vhost fuzzing, Nginx off-by-slash, path normalization bypass

**Modern:** GraphQL (introspection/depth/mutations/batching), WebSocket injection, HTTP/2 rapid reset, H2C smuggling, TE.CL smuggling, request smuggling, cache poisoning, cache key injection, web cache deception

**Passive:** Wayback forgotten endpoints, source map exposure, dependency confusion, JS secrets, API key leakage, Next.js/React specific vulns

**OOB (confirmed):** Blind SSRF, blind CMDi, blind SQLi via interactsh DNS callbacks

## Output

Each scan creates a timestamped directory containing:
- `report.html` — Professional dark-themed report with PoC + remediation per finding
- `report.json` — Full scan data with CVSS scores
- `subdomains.txt` — All discovered subdomains
- `crawl.json` — Crawled pages, forms, parameters
- `nuclei.json` — Nuclei findings
- `.apex_state.json` — Scan state for resume

## Requirements

Python 3.10+

```bash
pip install -r requirements.txt
```

Recommended tools (auto-installed by `install.sh`): subfinder, httpx, nuclei, ffuf, nmap, sqlmap, interactsh-client

## Manual Install

```bash
pip install -r requirements.txt
sudo ln -sf "$(pwd)/apex.py" /usr/local/bin/apex-cli
chmod +x apex.py
```
