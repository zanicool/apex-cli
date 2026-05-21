# Apex CLI — Origins

## Credits

**Original author**: Zani ([@zanicool](https://github.com/zanicool))

Apex CLI was created by Zani as a Go + Python penetration testing tool that grew from a simple scanner to a 179-scanner autonomous exploitation engine. The C++ port preserves his architecture, philosophy, and payloads.

## Zani's Design Philosophy

1. **Speed first** — Single binary, 5000+ req/sec, zero dependencies
2. **Zero false positives** — Wildcard filtering, baseline comparison, OOB confirmation
3. **Real attacker simulation** — OSINT → Recon → Crawl → Scan → Exploit
4. **Adaptive** — WAF detection + payload adaptation, learning DB
5. **Autonomous** — Auto-escalation, PoC generation, exploit chains

## Evolution (by Zani)

```
v1-v3:  Python legacy (dragon.py, apex-ai.py)
v4-v6:  Go rewrite — 10-50x faster, concurrent goroutines
v7:     109 scanners — browser-confirmed XSS, DOM XSS via headless Chrome
v8:     2x finding rate — JS extraction, param brute-force (654 params)
v9:     Smart detection — boolean-blind SQLi, WAF detection, deduplication
v10:    Elite + GODLY tier — exploit chains, response fingerprinting, PoC gen
v11:    179 scanners — MITM proxy, distributed scanning, cloud security
```

## Scanner Categories (207 registered, 179 unique)

### Core Injection (7)
SQLi, XSS, SSRF, CMDi, SSTI, LFI, Open Redirect

### Advanced Injection (6)
NoSQL, XXE, LDAP, XPath, EL Injection, PHP Object Injection

### Logic Bugs (6)
Race Condition, Price Manipulation, Payment Bypass, Mass Assignment, Forced Browsing, IDOR UUID

### Infrastructure (4)
Subdomain Takeover, S3 Buckets, DNS Zone Transfer, VHost Fuzzing

### Modern Web (5)
GraphQL, HTTP Smuggling, Cache Poisoning, WebSocket, H2C Smuggling

### OOB Confirmed (4)
Blind SSRF, Blind CMDi, Blind SQLi, Log4Shell

### Passive (3)
JS Secrets, Source Maps, Dependency Confusion

### Web Common (6)
CSRF, Clickjacking, CRLF Injection, Security Headers, Cookie Security, Info Disclosure

### Exploits (9)
File Upload, RFI, Deserialization, Spring4Shell, Shellshock, SSRF Variants, HTTP Verb Tampering, 403 Bypass

### Web Advanced (4)
CORS Advanced, Open Redirect Advanced, HPP, JSONP

### Auth & Access (12+)
IDOR, JWT, OAuth, Session Fixation, 2FA Bypass, Role Diff, Account Takeover, Password Reset Poisoning

### Cloud Security
AWS metadata, Azure IMDS, GCP metadata, S3 misconfig

### Browser Automation
DOM XSS, Headless Chrome confirmation, postMessage exploitation

### Autonomous Exploitation
Auto-escalation, exploit chains (SSRF→AWS creds), PoC generation

## Payloads (from Zani)

| File | Count | Purpose |
|------|-------|---------|
| `payloads/sqli.txt` | 121 | SQL injection payloads |
| `payloads/xss.txt` | 92 | XSS payloads |
| `payloads/params.txt` | 654 | Parameter brute-force |
| `wordlists/subdomains.txt` | 484,701 | Subdomain enumeration |
| `wordlists/subdomains-10000.txt` | 10,000 | Quick subdomain enum |
| `wordlists/api-endpoints.txt` | 288 | API endpoint discovery |
| `wordlists/routes.txt` | — | Common web routes |
| `wordlists/swagger.txt` | — | Swagger/OpenAPI paths |

## Architecture (preserved in C++ port)

```
Zani's Go:                    Our C++ port:
pkg/scanner/  (38 files)  →   src/scanner.cpp (growing)
pkg/crawler/              →   src/crawler.cpp ✅
pkg/recon/                →   src/recon.cpp ✅
pkg/oob/                  →   (planned)
pkg/engine/               →   src/http.cpp + src/config.hpp ✅
pkg/reporter/             →   src/reporter.cpp ✅
pkg/proxy/                →   (planned)
pkg/distributed/          →   (planned)
pkg/tools/                →   scripts/ ✅
payloads/                 →   payloads/ ✅ (copied from Zani)
wordlists/                →   wordlists/ ✅ (copied from Zani)
```

## Key Innovations by Zani

1. **Smart filtering** — Baseline response comparison to eliminate false positives
2. **Wildcard detection** — Random subdomain test before enumeration
3. **OOB confirmation** — Blind vulns verified via callback server (jarvis.local:9877)
4. **Exploit chains** — SSRF → AWS metadata → credential extraction
5. **Response fingerprinting** — Detect tech stack from response patterns
6. **Adaptive payloads** — WAF detected? Switch to bypass payloads
7. **Learning DB** — Remember what works per target for future scans
8. **JS extraction** — Parse JavaScript for hidden API endpoints
9. **Param brute-force** — 654 common parameter names per endpoint
10. **Differential analysis** — Compare auth vs unauth responses for IDOR

## Porting Status

See [docs/zani-scanner-registry.txt](zani-scanner-registry.txt) for the full list of 207 registered scanners to port.
