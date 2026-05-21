---
summary: Expand apex-cli with a real web crawler, authenticated scanning, parameter discovery, and additional vulnerability scanners to close coverage gaps.
status: proposed
---

# ADR-003: Crawler and Scanner Expansion

*Date*: 2026-05-21
*Related*: [ADR-001](adr-001-dynamic-analysis-pentest-tool.md), [ADR-002](adr-002-osint-driven-attack-simulation.md)

## Context

De huidige scanner werkt, maar mist een cruciaal onderdeel: een echte crawler. Phase 2 (Crawl) gebruikt nu alleen de live targets uit recon als URL-lijst. Hierdoor worden parameters, forms, en diepere endpoints niet ontdekt. Daarnaast ontbreken scanners voor veelvoorkomende kwetsbaarheden (XXE, IDOR, SSTI, JWT).

**Huidige beperkingen:**

| Gap | Impact |
|-----|--------|
| Geen crawler | Alleen root-URLs worden gescand, diepere endpoints gemist |
| Geen parameter discovery | `crawl.params` en `crawl.forms` zijn leeg |
| Geen authenticated scanning | Ingelogde applicatiedelen onbereikbaar |
| Geen XXE scanner | XML-gebaseerde aanvallen niet gedetecteerd |
| Geen IDOR scanner | Broken access control niet getest |
| Geen SSTI scanner | Template injection gemist |
| Geen JWT scanner | Token-kwetsbaarheden niet gedetecteerd |
| Geen deduplicatie | Dezelfde finding kan meerdere keren voorkomen |
| Geen scope enforcement | Scanner kan buiten scope crawlen |

## Decision

### 1. Web Crawler (Phase 2 verbetering)

Een echte spider die links, forms, en parameters ontdekt:

```
Crawl Engine
├── HTML link extraction    — <a href>, <form action>, <link>
├── JavaScript parsing      — fetch(), axios, XMLHttpRequest URLs
├── Form discovery          — <form> met parameters en methods
├── API endpoint detection  — /api/*, OpenAPI/Swagger discovery
├── Sitemap parsing         — robots.txt, sitemap.xml
└── Scope enforcement       — Alleen URLs binnen --scope
```

#### CrawlResult uitbreiding

```cpp
struct CrawlResult {
  std::vector<std::string> urls;           // Alle ontdekte URLs
  std::vector<Parameter> params;           // URL params + form fields
  std::vector<Form> forms;                 // Forms met method + action
  std::vector<std::string> api_endpoints;  // /api/* endpoints
  std::vector<std::string> js_files;       // JavaScript bestanden
};

struct Parameter {
  std::string url;
  std::string name;
  std::string type;    // query, body, header, cookie
  std::string method;  // GET, POST
};

struct Form {
  std::string action;
  std::string method;
  std::vector<Parameter> fields;
};
```

#### Crawl configuratie

```bash
# Crawl depth en limits
apex-cli target.com --crawl-depth 3 --max-urls 1000

# Alleen crawlen, niet scannen
apex-cli target.com --crawl-only

# Externe URL-lijst meegeven
apex-cli target.com --urls endpoints.txt
```

### 2. Authenticated Scanning

Support voor sessie-gebaseerde scans:

```bash
# Cookie-based auth
apex-cli target.com --cookie "session=abc123; token=xyz"

# Header-based auth (Bearer token)
apex-cli target.com --header "Authorization: Bearer eyJ..."

# Login flow (form-based)
apex-cli target.com --login-url /login --login-data "user=test&pass=test"
```

#### Implementatie

```cpp
struct AuthConfig {
  std::string cookie;                           // Raw cookie string
  std::map<std::string, std::string> headers;   // Custom headers
  std::string login_url;                        // Form login endpoint
  std::string login_data;                       // POST body
  std::string logout_pattern;                   // Detect session loss
};
```

De HttpClient stuurt auth-headers mee bij elk request. Bij detectie van `logout_pattern` in een response wordt automatisch opnieuw ingelogd.

### 3. Nieuwe Scanners

| Scanner | Severity | Detectiemethode |
|---------|----------|-----------------|
| XXE | critical | XML payload met external entity → OOB callback |
| IDOR | high | Sequentiële ID's met/zonder auth vergelijken |
| SSTI | critical | Template expressions (`{{7*7}}` → `49`) |
| JWT | high | None-algorithm, weak secret, expired tokens |
| Race Condition | medium | Parallel requests op state-changing endpoints |
| GraphQL Introspection | medium | `__schema` query op /graphql |
| Prototype Pollution | medium | `__proto__` payload in JSON |
| Host Header Injection | medium | Gemanipuleerde Host header → password reset |

#### XXE Scanner

```cpp
// Payloads
"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"
"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://OOB_SERVER/xxe\">]><foo>&xxe;</foo>"
```

#### SSTI Scanner

```cpp
// Payloads per template engine
{"{{7*7}}", "49"},           // Jinja2, Twig
{"${7*7}", "49"},            // Freemarker, Velocity
{"<%= 7*7 %>", "49"},       // ERB
{"#{7*7}", "49"},           // Slim, Pug
```

#### JWT Scanner

```cpp
// Checks
1. Decode header → algorithm "none" accepted?
2. Modify payload → signature not validated?
3. Brute-force weak secrets (top 1000 JWT secrets)
4. Check exp claim → expired tokens accepted?
```

### 4. Finding Deduplicatie

Voorkom duplicate findings op basis van:

```cpp
struct FindingKey {
  std::string type;      // Scanner type
  std::string url;       // Genormaliseerde URL (zonder query params)
  std::string param;     // Kwetsbare parameter
};
// Set<FindingKey> voor deduplicatie tijdens scan
```

### 5. Scope Enforcement

Strikte scope-controle om buiten-scope targets te voorkomen:

```cpp
bool in_scope(const std::string &url, const Config &cfg) {
  // Check tegen --scope regex
  // Check tegen target domain
  // Blokkeer third-party domains
}
```

### 6. Prioriteit en Fasering

| Fase | Onderdeel | Effort | Impact |
|------|-----------|--------|--------|
| **1** | Web Crawler + parameter discovery | Medium | Hoog — alles wordt beter |
| **1** | Scope enforcement | Laag | Hoog — voorkomt problemen |
| **1** | Finding deduplicatie | Laag | Medium — schonere output |
| **2** | Authenticated scanning | Medium | Hoog — meer coverage |
| **2** | SSTI scanner | Laag | Hoog — kritieke vuln |
| **2** | XXE scanner | Laag | Hoog — kritieke vuln |
| **3** | JWT scanner | Laag | Medium |
| **3** | IDOR scanner | Medium | Hoog — vereist auth |
| **3** | GraphQL scanner | Laag | Medium |
| **3** | Race condition scanner | Medium | Medium |
| **4** | Host header injection | Laag | Laag |
| **4** | Prototype pollution | Laag | Laag |

## Consequences

### Positive

- Crawler ontdekt 10-50x meer aanvalsoppervlak
- Parameter discovery maakt bestaande scanners effectiever (SQLi, XSS testen op echte params)
- Authenticated scanning opent ingelogde applicatiedelen
- Nieuwe scanners dekken OWASP Top 10 volledig af
- Deduplicatie maakt rapporten bruikbaar
- Scope enforcement voorkomt juridische problemen

### Negative

- Crawler verhoogt scan-duur significant (mitigatie: `--crawl-depth`, `--max-urls`)
- Authenticated scanning vereist geldige credentials van opdrachtgever
- Meer scanners = meer false positives (mitigatie: confidence levels)
- IDOR scanner vereist twee sessies (auth + unauth) voor vergelijking

## Acceptance Criteria

- [ ] Crawler ontdekt links, forms, en parameters uit HTML
- [ ] Crawler respecteert `--crawl-depth` en `--scope`
- [ ] `crawl.params` bevat ontdekte parameters per URL
- [ ] `--cookie` en `--header` worden meegestuurd bij alle requests
- [ ] SSTI scanner detecteert Jinja2/Twig/Freemarker injection
- [ ] XXE scanner detecteert external entity processing
- [ ] Findings worden gededupliceerd op type+url+param
- [ ] Geen requests buiten scope (verifieerbaar via `--dry-run`)
- [ ] Alle nieuwe scanners produceren findings in JSONL format (ADR-001)

## References

- @see ADR-001: Dynamic Analysis Pentest Tool (findings contract)
- @see ADR-002: OSINT-Driven Attack Simulation (recon phase)
- @see OWASP Testing Guide v4.2: Crawling and Spidering
- @see OWASP Top 10 2021 (A01-A10)
- @see PortSwigger Web Security Academy: SSTI, XXE, JWT attacks
