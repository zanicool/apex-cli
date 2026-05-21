---
summary: Unified security ecosystem — combining SAST, DAST, CI/CD components, asset inventory, and security knowledge into one coherent posture.
status: proposed
---

# ADR-004: Unified Security Ecosystem

*Date*: 2026-05-21
*Related*: [ADR-001](adr-001-dynamic-analysis-pentest-tool.md)

## Context

We hebben meerdere tools die elk een stuk van de security puzzle oplossen:

| Laag | Tool | Functie |
|------|------|---------|
| Code | cpm (SAST) | Statische analyse, secrets, SBOM, maturity |
| Runtime | apex-cli (DAST) | Dynamische analyse, OSINT, exploit verificatie |
| Pipeline | CI/CD components | Automatische scans bij deploy |
| Inventaris | Repo/domain scanner | Welke assets bestaan er? |
| Kennis | Security docs | Methodologie, frameworks, certificeringen |

**Probleem**: ze draaien in isolatie. Geen correlatie tussen "secret in code" en "dat endpoint is live bereikbaar".

## Decision

### Security Mesh Architectuur

```
┌─────────────────────────────────────────────────────┐
│              UNIFIED FINDINGS (JSONL)                 │
└─────┬──────────┬──────────┬──────────┬──────────────┘
      │          │          │          │
  ┌───┴──┐  ┌───┴───┐  ┌──┴──┐  ┌───┴────────┐
  │ SAST │  │ DAST  │  │ ZAP │  │ Inventory  │
  └───┬──┘  └───┬───┘  └──┬──┘  └───┬────────┘
      │          │         │          │
  Source      Live      Pipeline   All repos
  Secrets     vulns     results    All domains
  SBOM        CVEs      JUnit      Lifecycle
```

### Integratiepunten

#### 1. Asset Inventory → DAST (Target Discovery)

Een scanner die alle repos/domeinen kent, voedt targets aan DAST:

```bash
# Inventory levert lijst van live domeinen
inventory-scan --output domains.txt

# DAST scant ze allemaal
while read target; do
  apex-cli "$target" --output "scans/$target"
done < domains.txt
```

#### 2. SAST → DAST (Code Intelligence)

SAST weet welke taal en frameworks een project gebruikt. Dat maakt DAST slimmer:

| SAST vindt | DAST doet |
|-----------|-----------|
| `lang = "java"` | Focus op deserialization, Log4Shell |
| `lang = "php"` | Focus op SQLi, LFI, object injection |
| Secret in code | Test of het exposed is op live URL |
| Outdated dep met CVE | Verify exploitability op runtime |

#### 3. DAST → CI/CD (Pipeline Component)

DAST als stap in de deploy pipeline:

```yaml
security-scan:
  stage: post-deploy
  script:
    - apex-cli "$DEPLOYMENT_URL" --report junit
  artifacts:
    reports:
      junit: report-junit.xml
```

#### 4. Kennis → Tooling (Methodology-Driven)

Security kennis (pen-testing methodologie, OWASP, ISO 27001) vertaald naar automatisering:

| Kennis | Implementatie |
|--------|--------------|
| PTES: Intelligence Gathering | `--osint` fase |
| OWASP Testing Guide | Scanner categorieën |
| Kill chain model | 5-phase pipeline |
| ISO 27001: Risk assessment | Maturity scoring |

#### 5. PII Detection (uit cpm)

Dezelfde aanpak als cpm's PII-check — persoonlijke patronen in een lokaal (gitignored) bestand:

```
.config/.pii          → Patronen om te detecteren in scan output
.config/.piiignore    → False positives onderdrukken
```

Dit voorkomt dat bedrijfs- of persoonsgegevens in rapporten lekken.

#### 6. Correlatie = De Echte Waarde

| Los | Gecombineerd |
|-----|-------------|
| "API key in config.js" | + "Key bereikbaar via /api/config" = **confirmed leak** |
| "Joomla 4.4.14 outdated" | + "Staat in repo X van team Y" = **weet wie fixt** |
| "XSS in pipeline scan" | + "Geen sanitization in code" = **root cause + fix** |
| "38 repos zonder pipeline" | + "12 daarvan zijn live" = **shadow IT** |

### Maturity Levels (uitgebreid)

```
Level 0: Geen security
Level 1: SAST only (secrets, lint)
Level 2: SAST + DAST (runtime scan moet passen)
Level 3: SAST + DAST + SBOM + CVE verificatie
Level 4: + Continuous monitoring
Level 5: + Full compliance mapping
```

## Consequences

### Positive

- Correlatie tussen code en runtime = confirmed risks (niet meer raden)
- Elke deploy triggert automatisch DAST
- Asset inventory + DAST = volledig aanvalsoppervlak in beeld
- Methodologie uit kennis-docs vertaald naar geautomatiseerde checks
- PII-check voorkomt data leaks in rapporten

### Negative

- Complexiteit: meerdere tools moeten samenwerken
- Performance: enterprise-scan over alle domeinen duurt lang
- Onderhoud: tools moeten compatible findings format delen

## Acceptance Criteria

- [ ] SAST kan DAST aanroepen en findings combineren in één JSONL
- [ ] DAST leest target uit project config
- [ ] CI/CD component beschikbaar voor pipeline integratie
- [ ] Asset inventory output bruikbaar als target-lijst voor DAST
- [ ] JUnit XML output voor merge request integratie
- [ ] PII-check op scan output (lokaal, gitignored)
- [ ] Maturity level 2+ vereist DAST pass
