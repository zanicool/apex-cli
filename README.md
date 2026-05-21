# Apex CLI — C++ Edition

![cpm score](https://img.shields.io/badge/cpm%20score-97%25-brightgreen)
![maturity](https://img.shields.io/badge/maturity-level%205%20excellent-brightgreen)

High-performance automated penetration testing tool with progressive maturity framework.

## Features

- **225+ Scanners**: Full-spectrum security testing in a single binary
- **Web Application**: SQLi, XSS, SSRF, CMDi, CORS, LFI, CSRF, SSTI, XXE, and 100+ more
- **Authentication**: JWT, OAuth, 2FA bypass, session fixation, password spray, timing oracle
- **Cloud Misconfig**: AWS S3, Azure Blob, GCP buckets, K8s dashboards, IAM
- **Modern Stack**: Supabase, Clerk, Auth0, Vercel, Neon, PostHog, Pusher
- **AI Infrastructure**: Vector DBs, LLM endpoints, prompt injection, training data exposure
- **Enterprise OSINT**: M365 tenant enum, SharePoint, Atlassian, Slack, OAuth/SSO
- **Deep Recon**: DNS brute-force, Wayback, Google dorks, CT logs, GitHub, KVK (NL)
- **Network Security**: TLS/SSL analysis, SPF/DKIM/DMARC, DNSSEC, CAA
- **Kernel/OS CVEs**: SSH-based audit for Copy Fail, Dirty Frag, Fragnesia (2026)
- **OTAP/DTAP Discovery**: Find unprotected dev/test/staging environments
- **Interactive Surface**: Login forms, file uploads, AJAX endpoints, hidden forms
- **Supply Chain**: Dependency confusion, SBOM + OSV, CI/CD artifacts
- **Progressive Maturity**: 5-level framework (learn → guide → guard → enforce)
- **Complete Audit Trail**: JSONL append-only history for trend analysis
- **Compliance Mapping**: OWASP Top 10, CWE integration

## Maturity Levels

```
Level 0: None       → No scanning
Level 1: Basic      → Core vulnerability detection (SQLi, XSS)
Level 2: Standard   → + CMS detection, OSINT basics
Level 3: Advanced   → + Deep scanning, compliance mapping
Level 4: Expert     → + Continuous monitoring, auto-remediation
Level 5: Excellent  → + Full traceability, zero tolerance
```

## Build

Requires: C++17 compiler, libcurl.

```bash
# macOS
brew install curl

# Ubuntu/Debian
sudo apt-get install libcurl4-openssl-dev

# Build
make build
```

## Usage

```bash
# Basic scan with maturity score
./build/apex-cli example.com

# Deep scan with CMS detection
./build/apex-cli example.com --deep --threads 200

# OSINT reconnaissance
./build/apex-cli example.com --osint

# SSH-based kernel/OS audit
./build/apex-cli example.com --ssh user@example.com --ssh-key ~/.ssh/id_ed25519

# Skip specific scanners
./build/apex-cli example.com --skip "DNS Brute-Force,Param Brute-Force"

# Dry run (no packets sent)
./build/apex-cli example.com --dry-run
```

# Configure maturity target
cp apex.toml.example apex.toml
# Edit apex.toml: target_level = 3
./build/apex-cli example.com
```

## Configuration

```toml
# apex.toml
[maturity]
target_level = 3        # Aim for "Advanced"

[enforcement]
mode = "guide"          # learn | guide | guard | enforce

[thresholds]
max_critical = 0
max_high = 5
max_medium = 20

[scanners]
skip = []
required = ["SQLi", "XSS", "CMS Detection"]

[compliance]
frameworks = ["OWASP", "CWE"]
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--deep` | false | More payloads, wider ports |
| `--osint` | false | OSINT mode (employees, breaches, tech stack) |
| `--threads` | 100 | Concurrent workers |
| `--rate` | 0 | Delay between requests (seconds) |
| `--timeout` | 10 | HTTP timeout (seconds) |
| `--proxy` | | HTTP proxy URL |
| `--output` | auto | Output directory |
| `--report` | json,terminal | Report formats |
| `--scope` | | Restrict to matching targets |
| `--skip` | | Skip scanners (comma-separated) |
| `--no-oob` | false | Disable OOB confirmation |
| `--dry-run` | false | Preview without sending packets |

## Scanners

### Vulnerability Detection
- SQL Injection (error-based, time-based)
- Cross-Site Scripting (reflected)
- Server-Side Request Forgery (cloud metadata)
- Command Injection (time-based)
- CORS Misconfiguration
- Security Headers
- Local File Inclusion (path traversal)
- Open Redirect

### CMS Detection (50+ platforms)
- WordPress, Drupal, Joomla, Magento
- Shopify, Wix, Squarespace, Webflow
- Ghost, TYPO3, Craft CMS, Strapi
- Version detection with outdated checks
- Exports to `cms_inventory.csv`

### OSINT Intelligence
- **Employee Exposure**: LinkedIn scraping, email discovery
- **Data Breaches**: HaveIBeenPwned integration
- **Leaked Secrets**: GitHub, Pastebin scanning
- **Tech Stack**: Job posting analysis
- **Infrastructure**: Certificate transparency, DNS
- **News Monitoring**: Breach/lawsuit mentions
- Exports to `osint_*.csv` files

## Architecture

```text
src/
  main.cpp         — CLI entry point and orchestration
  config.hpp       — Configuration types
  http.hpp/cpp     — HTTP client (libcurl, TLS, UA rotation)
  scanner.hpp/cpp  — Scanner framework and implementations
  cms_detector.hpp/cpp — CMS fingerprinting and versioning
  osint.hpp/cpp    — OSINT reconnaissance
  recon.hpp/cpp    — Subdomain enumeration and probing
  reporter.hpp/cpp — JSON and terminal reporting
tests/
  test_main.cpp    — Unit tests
```

## Output Files

After a scan, the output directory contains:

### Reports
- `report.json` — Full vulnerability report
- `cms_inventory.csv` — Detected CMS with versions and outdated status
- `osint_leaks.csv` — Data breaches and leaked credentials
- `osint_employees.csv` — Exposed employees
- `osint_techstack.csv` — Technology stack from job postings
- `osint_news.csv` — News mentions (breaches, lawsuits)

### JSONL History (append-only)
- `cms_recon.jsonl` — Complete CMS detection history with timestamps
- `osint_recon.jsonl` — OSINT findings (leaks, employees, tech stack)
- `vuln_recon.jsonl` — All vulnerability findings with evidence

**Query recon history**:
```bash
# View all findings
./scripts/query_recon.sh ./output

# Find outdated CMS
jq 'select(.outdated == true)' output/cms_recon.jsonl

# Critical leaks
jq 'select(.severity == "critical")' output/osint_recon.jsonl

# Timeline
jq -r '"\(.timestamp) | \(.type)"' output/vuln_recon.jsonl | tail -50
```

See [JSONL_FORMAT.md](docs/JSONL_FORMAT.md) for query examples.

## Development

```bash
make check    # format + lint + build + test
make format   # clang-format
make lint     # cppcheck
make test     # run tests
make clean    # remove build artifacts
```

## License

MIT
