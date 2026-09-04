# Apex CLI — C++ Edition

![detection](https://img.shields.io/badge/detection-7%2F7%20core%20classes-brightgreen)
![precision](https://img.shields.io/badge/false--positive%20rate-11%25%20%40%20confidence%E2%89%A52-brightgreen)

High-performance automated penetration testing tool. Precision-first: findings
are confirmed with differential baselines so the reportable set is signal, not
noise.

> **Measured on the bundled vulnerable target** (`tests/local_vuln_target.py`,
> scored by `tests/precision_harness.py`): 234 scanners, **100% detection of
> the 7 core vulnerability classes** (SQLi, XSS, CMDi, SSTI, LFI, Open Redirect,
> SSRF) at an **11% false-positive rate** in the reportable tier
> (`--confidence 2`). Run `python3 tests/precision_harness.py` to reproduce.

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

# Bug bounty pipeline (recommended)
./build/apex-cli example.com --pipeline

# Pipeline with HackerOne program check
./build/apex-cli example.com --pipeline --program shopify

# Smart mode (14x faster, only relevant scanners)
./build/apex-cli example.com --smart

# Only confirmed findings (no noise)
./build/apex-cli example.com --smart --confidence 3

# Continuous monitoring (diff against previous scan)
./build/apex-cli example.com --watch --watch-interval 21600

# Compare against baseline
./build/apex-cli example.com --smart --baseline scans/previous/report.json

# Deep scan with CMS detection
./build/apex-cli example.com --deep --threads 200

# Authenticated scanning
./build/apex-cli example.com --pipeline --cookie "session=abc123"
./build/apex-cli example.com --pipeline --auth-header "Bearer tok"

# OSINT reconnaissance
./build/apex-cli example.com --osint

# SSH-based kernel/OS audit
./build/apex-cli example.com --ssh user@example.com --ssh-key ~/.ssh/id_ed25519

# Skip specific scanners
./build/apex-cli example.com --skip "DNS Brute-Force,Param Brute-Force"

# Dry run (no packets sent)
./build/apex-cli example.com --dry-run
```

## Bug Bounty Workflow

```bash
# Step 1: Pre-hunt intelligence
./scripts/bounty-recon.sh shopify

# Step 2: Daily security briefing
./scripts/security-digest.sh

# Step 3: Scan with duplicate detection
./build/apex-cli https://target.com --pipeline --program shopify

# Step 4: Audit open source repos
git clone https://github.com/Shopify/hydrogen.git
cd hydrogen && cpm

# Step 5: Continuous monitoring
./build/apex-cli https://target.com --watch --watch-interval 21600
```

### Pipeline Output

```
🟢 SUBMIT THESE (3):
    [critical] SSRF → Cloud Metadata
      URL: https://app.target.com/proxy?url=
      OWASP: A10:2021 SSRF
      Impact: Internal network access, cloud credential theft
      Chain: SSRF → AWS metadata → IAM creds → full account takeover
      Ref: PortSwigger SSRF Labs, WAHH Ch.10

🟡 VERIFY FIRST (2) — check hacktivity before submitting
🔴 SKIP (5) — likely duplicates
```

### Scripts

| Script | Purpose |
|--------|---------|
| `scripts/bounty-recon.sh` | Pre-hunt intelligence (tech stack, CVEs, repos) |
| `scripts/security-digest.sh` | Daily CVE + news + YouTube digest |
| `scripts/scan-all.sh` | Parallel scan of vulnerability battery |
| `scripts/scan-battery50.sh` | 50-image validation suite |

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
| `--pipeline` | false | Full bounty pipeline: recon → scan → verify → report |
| `--bounty` | false | Novelty scoring + duplicate risk assessment |
| `--smart` | false | Smart mode: auto-select scanners from crawl intel |
| `--confidence N` | 0 | Min confidence (1=possible, 2=probable, 3=confirmed) |
| `--program NAME` | | HackerOne program handle (enables hacktivity check) |
| `--watch` | false | Continuous monitoring with diff |
| `--watch-interval N` | 3600 | Seconds between watch scans |
| `--baseline PATH` | | Compare against previous report.json |
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
| `--cookie` | | Cookie header for authenticated scanning |
| `--auth-header` | | Authorization header (e.g. 'Bearer tok') |
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
make test     # run tests (incl. precision regression suite)
make clean    # remove build artifacts
```

### Precision measurement

`tests/precision_harness.py` starts the bundled intentionally-vulnerable
target (`tests/local_vuln_target.py`, bound to 127.0.0.1 only), runs a scan,
and scores the findings against the KNOWN planted bugs — reporting detection
rate and false-positive rate. This is how "is it accurate?" is answered with
numbers rather than claims.

```bash
python3 tests/precision_harness.py                 # reportable tier (confidence>=2)
python3 tests/precision_harness.py --confidence 0  # all findings
```

The unit suite (`make test`) also includes `test_precision.cpp`, which locks in
the confirmation logic (evaluation-vs-reflection, XSS-breaker requirement,
confidence capping, scope gate, relative-URL resolution) so the noise that was
eliminated cannot silently return.

## License

MIT
