# ADR-001: CMS & OSINT Inventory System

**Status**: Accepted  
**Date**: 2026-05-21  
**Context**: Bedrijf heeft behoefte aan geautomatiseerde inventarisatie van CMS-systemen en OSINT intelligence voor security monitoring.

## Decision

Implementeer geïntegreerde CMS detection en OSINT scanning in Apex CLI met CSV exports voor inventarisatie.

## Rationale

### Probleem
- Geen overzicht van gebruikte CMS-systemen en versies
- Outdated software wordt niet tijdig gedetecteerd
- Employee exposure en data breaches worden te laat ontdekt
- Handmatige inventarisatie is tijdrovend en foutgevoelig

### Oplossing
**CMS Detection Module**:
- Fingerprinting van 50+ CMS platforms
- Versie-extractie via regex patterns
- Outdated check tegen known latest versions
- Export naar `cms_inventory.csv`

**OSINT Scanner Module**:
- Employee exposure (LinkedIn scraping)
- Data breach monitoring (HaveIBeenPwned API)
- Leaked secrets (GitHub, Pastebin)
- Tech stack analysis (job postings)
- Infrastructure mapping (Certificate Transparency)
- News monitoring (breach/lawsuit mentions)

### Architectuur
```
┌─────────────────────────────────────────────┐
│           Apex CLI Main                     │
└──────────────┬──────────────────────────────┘
               │
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌──────▼──────────┐
│ CMS Detector│  │  OSINT Scanner  │
│             │  │                 │
│ - Fingerprint│  │ - HIBP API     │
│ - Version   │  │ - Google Dork  │
│ - Outdated  │  │ - GitHub Scan  │
└──────┬──────┘  └──────┬──────────┘
       │                │
       └───────┬────────┘
               │
        ┌──────▼──────┐
        │ CSV Export  │
        │             │
        │ - cms_inventory.csv
        │ - osint_leaks.csv
        │ - osint_employees.csv
        │ - osint_techstack.csv
        │ - osint_news.csv
        └─────────────┘
```

## Implementation

### CMS Detection
```cpp
struct CMSVersion {
    string name;
    string version;
    string latest_version;
    bool outdated;
};

CMSDetector::detect_with_version(url) → vector<CMSVersion>
```

**Fingerprints**: URL paths, headers, body patterns, version regex

### OSINT Scanner
```cpp
struct OSINTLeak {
    string source;      // hibp, github, pastebin
    string type;        // email, password, api_key
    string value;
    string breach_name;
    string severity;    // critical, high, medium
};

OSINTScanner::check_hibp(emails) → vector<OSINTLeak>
OSINTScanner::find_employees(domain) → vector<EmployeeExposure>
OSINTScanner::search_leaks(domain) → vector<OSINTLeak>
```

### CSV Output Format

**cms_inventory.csv**:
```
URL,CMS,Version,Latest Version,Status,Severity
example.com,WordPress,6.2.0,6.5.3,OUTDATED,medium
```

**osint_leaks.csv**:
```
Source,Type,Value,Breach,Date,Severity
HaveIBeenPwned,email,user@example.com,LinkedIn,2021-06-22,high
GitHub,api_key,ghp_xxxx...,repo/secrets,2024-01-15,critical
```

## Consequences

### Positief
✅ Geautomatiseerde inventarisatie (geen handmatig werk)  
✅ Real-time outdated detection  
✅ Proactieve breach monitoring  
✅ CSV format → makkelijk te importeren in Excel/database  
✅ Continuous monitoring mogelijk via cron  

### Negatief
⚠️ Google dorking kan rate-limited worden → gebruik proxy rotation  
⚠️ HIBP API heeft rate limits → batch processing nodig  
⚠️ LinkedIn scraping kan geblokkeerd worden → headless browser overwegen  

### Risico's
🔴 **False positives**: CMS detection kan fout zijn bij custom builds  
🔴 **Privacy**: Employee data scraping moet GDPR-compliant zijn  
🔴 **API dependencies**: HIBP downtime = geen breach checks  

### Mitigatie
- Versie-detectie valideren met meerdere patterns
- Employee scanning alleen op bedrijfsdomeinen
- Fallback naar lokale breach database
- Rate limiting + retry logic

## Alternatives Considered

### 1. Manual Inventory
❌ Te tijdrovend, niet schaalbaar

### 2. Commercial Tools (Shodan, SecurityScorecard)
❌ Duur, vendor lock-in, geen customization

### 3. Separate Python Scripts
❌ Langzamer, extra dependencies, moeilijker te onderhouden

### 4. Database Storage (PostgreSQL)
✅ Overwegen voor v2.0 - nu CSV voor snelheid

## Usage

```bash
# CMS inventarisatie
./build/apex-cli example.com

# OSINT scan
./build/apex-cli example.com --osint

# Continuous monitoring (cron)
0 2 * * * /path/to/apex-cli example.com --osint >> /var/log/apex.log
```

## Maintenance

**Update frequencies**:
- CMS latest versions: maandelijks updaten in `cms_detector.cpp`
- OSINT patterns: per kwartaal reviewen
- CSV exports: dagelijks archiveren

**Monitoring**:
- Track false positive rate
- Monitor API rate limits
- Alert op critical leaks

## References

- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3)
- [Certificate Transparency](https://crt.sh)
- [OWASP OSINT Guide](https://owasp.org/www-community/OSINT)

## Decision Makers

- Security Team: Approved
- DevOps Team: Approved
- Legal/Privacy: Approved (met GDPR constraints)
