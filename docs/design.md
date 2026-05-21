# Design: apex-cli Dynamic Analysis Architecture

*Date*: 2026-05-21
*ADR*: [ADR-001](adrs/adr-001-dynamic-analysis-pentest-tool.md)

## Overview

apex-cli is a gray-box penetration testing tool that combines OSINT reconnaissance, active scanning, and ZAP integration into a single C++ binary with JSONL findings output.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        apex-cli                              │
├─────────────────────────────────────────────────────────────┤
│  CLI (main.cpp)                                             │
│  ├── Config parsing (--flags, cpm.toml)                     │
│  └── Phase orchestration                                    │
├─────────────────────────────────────────────────────────────┤
│  Phase 1: OSINT         │  Phase 2: Active Recon            │
│  ├── crt.sh CT logs     │  ├── Subdomain probing            │
│  ├── DNS enumeration    │  ├── Port scanning (top 1000)     │
│  ├── WHOIS/registrant   │  ├── Tech fingerprinting          │
│  ├── Wayback Machine    │  ├── WAF detection                │
│  └── Shodan/Censys API  │  └── Live target filtering        │
├─────────────────────────┼───────────────────────────────────┤
│  Phase 3: Crawl         │  Phase 4: Scan                    │
│  ├── Recursive spider   │  ├── Built-in scanners (parallel) │
│  ├── JS endpoint extract│  ├── ZAP profiles (external)      │
│  ├── API schema (OAS)   │  ├── OOB confirmation             │
│  ├── Form discovery     │  └── Exploit verification         │
│  └── Param brute-force  │                                   │
├─────────────────────────┴───────────────────────────────────┤
│  Phase 5: Report                                            │
│  ├── .apex/findings.jsonl (append)                          │
│  ├── .apex/report.json (structured)                         │
│  ├── .apex/junit.xml (CI integration)                       │
│  └── Terminal (colored summary)                             │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure                                             │
│  ├── HttpClient (libcurl, TLS, UA rotation, rate limit)     │
│  ├── OOB Server client (blind vuln confirmation)            │
│  ├── ZAP bridge (Docker, automation framework)              │
│  └── cpm bridge (findings ↔ cpm findings command)           │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
apex-cli/
├── .kiro/agents/apex.json       — Kiro development agent
├── .github/workflows/ci.yml     — Build + test
├── cpm.toml                     — cpm quality config
├── Makefile                     — build, test, check, format, lint
├── docs/
│   ├── adrs/                    — Architecture decisions
│   └── design.md                — This file
├── src/
│   ├── main.cpp                 — CLI entry + orchestration
│   ├── config.hpp               — Config struct + TOML parsing
│   ├── http.hpp/cpp             — HTTP client (libcurl)
│   ├── osint.hpp/cpp            — Passive recon (crt.sh, DNS, WHOIS)
│   ├── recon.hpp/cpp            — Active recon (probing, fingerprint)
│   ├── crawler.hpp/cpp          — URL discovery + JS extraction
│   ├── scanner.hpp/cpp          — Scanner registry + parallel runner
│   ├── scanners/                — Individual scanner implementations
│   │   ├── sqli.cpp
│   │   ├── xss.cpp
│   │   ├── ssrf.cpp
│   │   ├── cmdi.cpp
│   │   ├── cors.cpp
│   │   ├── headers.cpp
│   │   ├── lfi.cpp
│   │   ├── redirect.cpp
│   │   └── ...                  — Port remaining from Zani's 179
│   ├── oob.hpp/cpp              — OOB callback client
│   ├── zap.hpp/cpp              — ZAP automation bridge
│   ├── reporter.hpp/cpp         — JSONL, JSON, JUnit, terminal
│   └── findings.hpp/cpp         — Unified findings contract
├── profiles/                    — ZAP scan profiles
│   ├── README.md
│   ├── wordpress/
│   ├── api/
│   └── spa/
├── payloads/                    — External payload files
│   ├── sqli.txt
│   ├── xss.txt
│   └── params.txt
├── wordlists/                   — Recon wordlists
│   ├── subdomains.txt
│   └── api-endpoints.txt
└── tests/
    ├── test_main.cpp
    └── vulnerability_battery/   — Docker targets for scanner testing
```

## Findings Flow

```
Scanner/ZAP/Recon
       │
       ▼
  Finding struct
       │
       ├──► .apex/findings.jsonl   (append, one line per finding)
       ├──► .apex/junit.xml        (generated at end)
       ├──► .apex/report.json      (full structured report)
       └──► terminal               (colored real-time output)
```

### JSONL Example

```jsonl
{"ts":"2026-05-21T18:00:00+02:00","target":"example.com","phase":"recon","scanner":"crt-sh","severity":"info","url":"https://admin.example.com","confidence":"confirmed"}
{"ts":"2026-05-21T18:00:05+02:00","target":"example.com","phase":"scan","scanner":"sqli","severity":"critical","url":"https://example.com/api/users","param":"id","payload":"' OR 1=1--","evidence":"MySQL syntax error","cwe":"CWE-89","cvss":9.8,"confidence":"confirmed"}
{"ts":"2026-05-21T18:00:10+02:00","target":"example.com","phase":"scan","scanner":"zap-active","severity":"high","url":"https://example.com/login","param":"password","evidence":"SQL injection found by ZAP","cwe":"CWE-89","confidence":"likely"}
```

### JUnit XML Mapping

```xml
<testsuites name="apex-cli" tests="3" failures="2">
  <testsuite name="scan" tests="2" failures="2">
    <testcase name="sqli: https://example.com/api/users" classname="apex.scan.sqli">
      <failure message="SQL injection (CWE-89)" type="critical">
        param: id | payload: ' OR 1=1-- | evidence: MySQL syntax error
      </failure>
    </testcase>
  </testsuite>
</testsuites>
```

## cpm Integration

### cpm.toml checks

```toml
[checks]
# DAST checks (require --target or target in cpm.toml)
network-target-vulnerability-scan = true
network-target-surface-discover = true
network-target-headers-validate = true

[checks.network-target-vulnerability-scan]
target = "staging.example.com"
deep = false
timeout = 30
```

### cpm findings bridge

apex-cli findings are compatible with cpm's unified contract:

| apex-cli field | cpm field | Mapping |
|----------------|-----------|---------|
| scanner | check | Direct (e.g., "sqli") |
| severity | severity | Direct (error=critical/high, warning=medium, info=low/info) |
| url | file | URL as "file" path |
| cwe | rule | CWE ID as rule |
| evidence | message | Evidence as message |

## Workflow: Gray-Box Pentest

```
1. Scope & Authorization
   └── Define target, get written permission, set rules of engagement

2. Passive OSINT (--osint)
   ├── crt.sh → subdomains
   ├── DNS records → mail servers, SPF, DKIM
   ├── WHOIS → registrant, admin contacts
   ├── Shodan → open ports, services, versions
   ├── GitHub → leaked secrets, internal URLs
   └── LinkedIn → tech stack, employee names

3. Active Recon (--recon)
   ├── Subdomain probing (HTTPS → HTTP fallback)
   ├── Port scan (top 1000)
   ├── Technology fingerprinting (whatweb)
   └── WAF detection

4. Crawl + Scan (default)
   ├── Spider all live targets
   ├── Extract JS endpoints
   ├── Run parallel scanners
   ├── ZAP profile if --zap-profile set
   └── OOB confirmation for blind vulns

5. Report
   ├── findings.jsonl → parseable by cpm
   ├── junit.xml → CI pipeline gates
   └── terminal → immediate feedback
```

## Kiro Agent

```json
{
  "name": "apex",
  "description": "apex-cli development agent — C++ automated penetration testing tool",
  "prompt": "...",
  "tools": ["@builtin"],
  "resources": [
    "file://README.md",
    "file://cpm.toml",
    "file://docs/adrs/adr-001-dynamic-analysis-pentest-tool.md",
    "file://docs/design.md"
  ]
}
```

## Migration Path (from Zani's Go version)

| Priority | Scanners | Count | Status |
|----------|----------|-------|--------|
| P0 | SQLi, XSS, SSRF, CMDi, CORS, Headers, LFI, Redirect | 8 | ✅ Done |
| P1 | IDOR, JWT, CSRF, Clickjack, CRLF, File Upload | 6 | Planned |
| P2 | GraphQL, WebSocket, Prototype Pollution, Race | 4 | Planned |
| P3 | WAF bypass, CDN origin, Cloud metadata | 6 | Planned |
| P4 | Remaining 155 scanners from Go version | 155 | Backlog |

## Security & Legal

- **Authorization required**: Never scan without written permission
- **Scope enforcement**: `--scope` flag restricts to matching targets
- **Rate limiting**: `--rate` prevents DoS
- **Dry-run**: `--dry-run` for preview without network traffic
- **No data exfiltration**: Findings stay local, never phoned home
- **OOB opt-in**: `--no-oob` disables callback server dependency
