---
summary: OSINT-driven attack simulation — gather public intelligence about a target organization and use it to build targeted wordlists for credential attacks, social engineering, and attack surface mapping.
status: proposed
---

# ADR-002: OSINT-Driven Attack Simulation

*Date*: 2026-05-21
*Related*: [ADR-001](adr-001-dynamic-analysis-pentest-tool.md)

## Context

A real attacker never starts with a vulnerability scanner. The kill chain is:

```
1. Who is the target? (company, employees, tech stack)
2. What is publicly accessible? (documents, repos, social media)
3. What can I guess? (passwords, security questions, tokens)
4. Where can I get in? (login portals, VPN, API endpoints)
5. How do I escalate? (lateral movement, privilege escalation)
```

Our tool must automate steps 1-4 to provide a realistic threat simulation.

## Decision

### Phase 0: Passive OSINT Collection

Zero packets to the target. Everything via public sources.

#### 0.1 Organization Intelligence

| Source | What we find | Tool |
|--------|-------------|------|
| LinkedIn | Employees, roles, tech stack, locations | Scraper/API |
| GitHub/GitLab | Repos, commits, leaked secrets, .env files | GitHub API + dorking |
| Job postings | Tech stack, internal tools, frameworks | Indeed/LinkedIn |
| Company website | Team page, about, contact, documents | Crawler |
| Press releases | Partnerships, acquisitions, new systems | Google |
| DNS/WHOIS | Registrant, admin email, nameservers | whois + dig |
| Certificate Transparency | All subdomains ever issued | crt.sh |
| Shodan/Censys | Open ports, services, versions, banners | API |
| Wayback Machine | Deleted pages, old configs, endpoints | web.archive.org |
| Google Dorks | Public documents, login pages, errors | `site:target.com filetype:pdf` |
| Pastebin/breach DBs | Leaked credentials, internal data | HIBP, dehashed |

#### 0.2 Personal Intelligence (for dictionary attack)

| Source | Data | Password relevance |
|--------|------|-------------------|
| Social media (FB, Insta, X) | Pets, children, birthdays, hobbies | Base for passwords |
| LinkedIn | Job title, company name, start date | `Company2024!` patterns |
| Public records | Zip code, address, license plate | Security questions |
| Sports/clubs | Club names, competitions | `Ajax2024!` patterns |
| Photo metadata (EXIF) | GPS location, camera, date | Location-based passwords |

#### 0.3 Targeted Wordlist Generation

From OSINT data → custom dictionary:

```
Input:
  company: "Acme Corp"
  employee: "John Smith"
  pet: "Bella"
  birth_year: 1985
  zip_code: "90210"
  hobby: "cycling"
  child: "Sophie"

Output (wordlist):
  Acme2024!
  Acme2025!
  AcmeCorp!
  John2024!
  JohnSmith1
  Bella123
  Bella2024!
  Sophie2024!
  Cycling1!
  90210!
  john.smith
  j.smith
  ...
```

Mutations applied:
- Leetspeak: `a→@, e→3, i→1, o→0, s→$`
- Year suffix: `2023, 2024, 2025, 2026`
- Special chars: `!, @, #, 1, 123`
- Capitalization: `bella, Bella, BELLA, bElLa`
- Combinations: `{name}{year}{special}`, `{company}{season}{year}`

### Phase 0.5: Attack Surface Mapping

Using OSINT data to find login surfaces:

| Target | How found | Attack |
|--------|-----------|--------|
| VPN portal | Subdomain enum (`vpn.target.com`) | Credential stuffing |
| Webmail | MX records + common paths (`/owa`, `/mail`) | Dictionary attack |
| Admin panels | Google dorks, common paths (`/admin`, `/wp-admin`) | Brute force |
| API endpoints | GitHub repos, JS files, Swagger | Token guessing |
| SSO/OAuth | Login redirects, SAML endpoints | Password spray |
| Cloud consoles | DNS (aws, azure subdomains) | Credential reuse |

### Phase 1: Credential Attacks

```
OSINT Wordlist + Login Endpoints → Targeted Attack

Methods:
├── Password Spray    — 1 password, all accounts (avoids lockout)
├── Credential Stuff  — Leaked user:pass pairs from breaches
├── Dictionary Attack  — OSINT wordlist per user
└── Token Guessing    — API keys, JWT secrets from patterns
```

### Tooling Integration

| Phase | Tool | apex-cli integration |
|-------|------|---------------------|
| OSINT collection | theHarvester, recon-ng, SpiderFoot | `--osint` flag |
| Wordlist generation | CeWL, CUPP, Mentalist | `apex-cli wordlist --target` |
| Login discovery | gobuster, ffuf | Built-in path brute |
| Credential attack | Hydra, Burp Intruder | `--spray` / `--dictionary` |
| Breach lookup | HIBP API, dehashed | `--breach-check` |

### CLI Interface

```bash
# Full OSINT + attack simulation
apex-cli target.com --osint --wordlist --spray

# OSINT report only (no active attack)
apex-cli target.com --osint-only --report json

# Generate wordlist from collected OSINT
apex-cli wordlist --company "Acme Corp" --employees employees.txt --output wordlist.txt

# Password spray against discovered login endpoints
apex-cli spray --target vpn.target.com --users users.txt --wordlist wordlist.txt --rate 1
```

### Findings Output

```jsonl
{"ts":"2026-05-21T18:00:00+02:00","target":"acme.com","phase":"osint","scanner":"linkedin","severity":"info","url":"https://linkedin.com/in/john-smith","evidence":"CTO, mentions NestJS + AWS","confidence":"confirmed"}
{"ts":"2026-05-21T18:00:01+02:00","target":"acme.com","phase":"osint","scanner":"github-dork","severity":"high","url":"https://github.com/acme/internal-api/blob/main/.env","evidence":"AWS_SECRET_KEY exposed in commit abc123","confidence":"confirmed","cwe":"CWE-798"}
{"ts":"2026-05-21T18:00:02+02:00","target":"acme.com","phase":"osint","scanner":"breach-check","severity":"critical","url":"https://vpn.acme.com","evidence":"3 employee credentials found in 2024 breach","confidence":"confirmed","cwe":"CWE-521"}
{"ts":"2026-05-21T18:00:10+02:00","target":"acme.com","phase":"spray","scanner":"password-spray","severity":"critical","url":"https://mail.acme.com/owa","param":"password","payload":"Acme2024!","evidence":"HTTP 302 redirect to inbox","confidence":"confirmed","cwe":"CWE-521"}
```

### Ethical Boundaries

| Action | Allowed | Condition |
|--------|---------|-----------|
| Public OSINT collection | ✅ Always | No login/auth required |
| Breach database check | ✅ | HIBP only (no raw dumps) |
| Subdomain enumeration | ✅ | Passive (DNS/CT logs) |
| Password spray | ⚠️ | Written authorization only |
| Credential stuffing | ⚠️ | Written authorization only |
| Social engineering | ⚠️ | Written authorization + scope |
| Active exploitation | ⚠️ | Written authorization only |

### `--osint-only` Mode (always safe)

Produces a report without any active contact with the target:
- Zero HTTP requests to target
- Zero login attempts
- Public sources only
- Output: who, what, where, which tech, which risks

## Consequences

### Positive

- Simulates realistic attacker (OSINT → targeted attack)
- Custom wordlists far more effective than generic lists
- Identifies weak password patterns in organization
- OSINT-only mode is legal without authorization
- Findings show what an attacker already knows before first contact

### Negative

- OSINT collection can be privacy-sensitive (GDPR)
- Password spray can lock accounts (rate limiting essential)
- Breach data access can be legally complex
- Social media scraping may violate ToS

## Acceptance Criteria

- [ ] `--osint-only` produces report without target contact
- [ ] Wordlist generator combines OSINT data with mutation rules
- [ ] Password spray respects `--rate` and stops on lockout detection
- [ ] All OSINT findings in .apex/findings.jsonl
- [ ] `--breach-check` uses HIBP API only (no raw dumps)
- [ ] Clear warning on active attacks without `--authorized` flag

## References

- @see OWASP Testing Guide: Information Gathering
- @see PTES (Penetration Testing Execution Standard): Intelligence Gathering
- @see MITRE ATT&CK: Reconnaissance (TA0043)
- @see work-epub/security/pen-testing (Pluralsight methodology)
- @see work-epub/security/comptia-security-plus (threat actors)
