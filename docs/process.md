# Pentest Process — Gray-Box Security Assessment

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  0. Scope & Authorization                                       │
│     └── Written permission, NDA, Rules of Engagement, scope     │
├─────────────────────────────────────────────────────────────────┤
│  1. Passive OSINT (no contact with target)                      │
│     └── Public info: employees, tech, documents, breaches       │
├─────────────────────────────────────────────────────────────────┤
│  2. Attack Surface Discovery                                    │
│     └── Subdomains, ports, login portals, API endpoints         │
├─────────────────────────────────────────────────────────────────┤
│  3. Vulnerability Scanning                                      │
│     └── Automated scans: apex-cli + ZAP/Burp                   │
├─────────────────────────────────────────────────────────────────┤
│  4. Targeted Exploitation                                       │
│     └── OSINT wordlists, password spray, credential stuffing    │
├─────────────────────────────────────────────────────────────────┤
│  5. Reporting & Remediation                                     │
│     └── Findings JSONL → report → debrief → retest             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Phase 0: Scope & Authorization

**Deliverables:** NDA, Rules of Engagement, Statement of Work

| Document | Content |
|----------|---------|
| NDA | Confidentiality of findings |
| Rules of Engagement | What is allowed, time windows, escalation |
| Statement of Work | Scope, budget, schedule, deliverables |
| Communication Plan | Contacts, escalation paths |

```bash
# No tooling — this is paperwork
# Checklist:
# □ Written authorization received
# □ Scope defined (IP ranges, domains, applications)
# □ Out-of-scope documented (production data, DoS, social engineering)
# □ Time window agreed
# □ Escalation path for critical findings
# □ Contact person available during test
```

---

## Phase 1: Passive OSINT

**Goal:** Collect everything an attacker can find without touching the target.

```bash
apex-cli target.com --osint-only
```

### 1.1 Organization Intelligence

| Action | Command | Output |
|--------|---------|--------|
| Subdomains via CT logs | `curl "https://crt.sh/?q=%25.target.com&output=json"` | subdomains.txt |
| DNS records | `dig target.com ANY` | dns.txt |
| WHOIS | `whois target.com` | registrant info |
| Tech stack | Google: `site:target.com` | technologies |
| Public documents | `site:target.com filetype:pdf\|doc\|xls` | documents |
| GitHub repos | `github.com/orgs/target` | repos, secrets |
| Wayback Machine | `web.archive.org/web/*/target.com/*` | old pages |

### 1.2 Job Postings & Tech Stack Leaks

Job postings are gold mines — companies reveal exactly what they run:

| Job posting text | What an attacker learns |
|------------------|------------------------|
| "Experience with NestJS and PostgreSQL" | Backend framework + database |
| "Knowledge of AWS EKS and Terraform" | Cloud provider + orchestration + IaC |
| "Working with Jira and Confluence" | Atlassian stack → `jira.target.com` |
| "CI/CD with GitLab and ArgoCD" | Git platform + deployment tool |
| "Keycloak SSO integration" | Identity provider → attack vector |
| "React frontend with Next.js" | Frontend framework + SSR |
| "RabbitMQ message broker" | Async infra → port 5672/15672 |
| "Elasticsearch monitoring" | Kibana dashboard → port 5601/9200 |

**What this yields:**
- Targeted CVE searches (e.g. `CVE Keycloak 2024`)
- Subdomain guessing (`gitlab.target.com`, `kibana.target.com`, `argocd.target.com`)
- Default credentials for known tools (`admin/admin` on Kibana, RabbitMQ `guest/guest`)
- Version-specific exploits if version appears in posting or error page

**Direct link to exploit.cpp:**

The `exploit.cpp` module automatically performs CVE lookup via `cvedb.shodan.io` and verifies exploits for detected software. Job posting intel feeds this directly:

```
Job posting: "PHP 8.1, Joomla, nginx, WordPress"
    │
    ▼
DetectedSoftware{name:"PHP", version:"8.1"}
DetectedSoftware{name:"Joomla", version:"?"}
DetectedSoftware{name:"nginx", version:"?"}
DetectedSoftware{name:"WordPress", version:"?"}
    │
    ▼
lookup_cves() → cvedb.shodan.io → known CVEs
verify_exploits() → PHP-CGI injection, Joomla API leak, nginx traversal, WP xmlrpc
```

Even without exact versions, the tool can check:
- PHP: phpinfo exposure, CGI injection (CVE-2024-4577), EOL check
- Joomla: API credential leak (CVE-2023-23752), config backup, debug mode
- nginx: alias traversal, misconfiguration
- WordPress: xmlrpc brute-force, user enumeration, REST API
- Generic: .env exposure, .git exposure, backup files, directory listing

```bash
# Google dorks for job postings
# site:linkedin.com/jobs "Target Inc" (developer OR engineer OR devops)
# site:indeed.com "Target Inc"
# site:careers.target.com

apex-cli osint --target target.com --job-postings
```

### 1.3 Employees & Personal Information

| Source | Data | Password relevance |
|--------|------|-------------------|
| LinkedIn | Names, roles, start date | `Company2024!` patterns |
| Facebook/Instagram | Pets, children, hobbies | `Bella123!` |
| Twitter/X | Opinions, events, locations | Context |
| Public records | Zip code, address | Security questions |
| HIBP | Breach history per email | Credential reuse |

### 1.4 Wordlist Generation

```bash
apex-cli wordlist \
  --company "Target Inc" \
  --names "John Smith,Jane Doe" \
  --keywords "bella,sophie,ajax,2024,welcome" \
  --output target-wordlist.txt
```

**Findings:** `.apex/findings.jsonl`

---

## Phase 2: Attack Surface Discovery

**Goal:** Find all entry points.

```bash
apex-cli target.com --recon-only
```

| Action | Tool | Result |
|--------|------|--------|
| Subdomain probing | httpx | live-targets.txt |
| Port scan (top 1000) | nmap -sV -T4 | open-ports.txt |
| Tech fingerprinting | whatweb / wappalyzer | tech-stack.json |
| WAF detection | wafw00f | waf-info.txt |
| Login portals | gobuster/ffuf | login-endpoints.txt |
| API discovery | JS parsing + swagger | api-endpoints.txt |

**Findings:** `.apex/findings.jsonl` (severity: info)

---

## Phase 3: Vulnerability Scanning

**Goal:** Automated vulnerability discovery.

```bash
# apex-cli built-in scanners
apex-cli target.com --deep --threads 100

# ZAP profile (e.g. WordPress)
apex-cli target.com --zap-profile wordpress

# Or manual with Burp Suite for complex flows
```

| Scanner | What | Severity |
|---------|------|----------|
| SQLi | SQL injection (error + time-based) | Critical |
| XSS | Reflected + DOM XSS | High |
| SSRF | Cloud metadata, internal network | Critical |
| CMDi | Command injection (time-based) | Critical |
| IDOR | Insecure direct object references | High |
| Auth | JWT, session, OAuth misconfig | High |
| Headers | Missing CSP, HSTS, X-Frame | Low |
| CORS | Wildcard, credential leaks | Medium |

**Findings:** `.apex/findings.jsonl` (severity: critical → info)

---

## Phase 4: Targeted Exploitation

**Goal:** Prove vulnerabilities are actually exploitable.

```bash
# Password spray with OSINT wordlist
apex-cli spray \
  --target vpn.target.com \
  --users users.txt \
  --wordlist target-wordlist.txt \
  --rate 1 \
  --lockout-detect

# Credential stuffing (breach data)
apex-cli stuff \
  --target mail.target.com \
  --credentials breached-creds.txt \
  --rate 0.5
```

| Attack | Prerequisite | Rate limit |
|--------|-------------|------------|
| Password spray | Authorization + scope | 1 attempt/account/10min |
| Credential stuffing | Authorization + breach data | 1 req/2sec |
| Token brute-force | Authorization | Depends on lockout |
| Exploit verification | Authorization + non-destructive | N/A |

**Findings:** `.apex/findings.jsonl` (severity: critical if successful)

---

## Phase 5: Reporting & Remediation

### 5.1 Report Generation

```bash
apex-cli report \
  --input .apex/findings.jsonl \
  --format json,junit,html \
  --output .apex/report/
```

### 5.2 Report Structure

```
.apex/report/
├── findings.jsonl      — Raw data (machine-readable)
├── junit.xml           — CI/CD integration
├── report.json         — Structured report
├── report.html         — Management presentation
└── executive-summary   — 1-pager for executives
```

### 5.3 Debrief & Retest

| Step | When | Who |
|------|------|-----|
| Deliver report | End of test | Pentester → client |
| Debrief session | +1 week | Pentester + dev team |
| Remediation | +1-12 weeks | Dev team |
| Retest | +4-12 weeks | Pentester |
| Final report | After retest | Pentester (updated findings) |

---

## Toolchain Overview

```
┌─────────────┐     ┌──────────┐     ┌─────────────┐
│  apex-cli   │────▶│ findings │────▶│   report    │
│  (scanner)  │     │  .jsonl  │     │ json/junit  │
└─────────────┘     └──────────┘     └─────────────┘
       │                  ▲
       │                  │
┌──────▼──────┐     ┌────┴─────┐
│  ZAP/Burp   │────▶│  cpm     │
│  (profiles) │     │ findings │
└─────────────┘     └──────────┘
```

---

## cpm Integration

```toml
# cpm.toml — DAST checks as part of quality gates
[checks]
network-target-vulnerability-scan = true
network-target-surface-discover = true
network-target-headers-validate = true

[checks.network-target-vulnerability-scan]
target = "staging.example.com"
authorized = true
```

```bash
# cpm check also runs DAST checks
cpm check

# Or security only
cpm check --filter network
```
