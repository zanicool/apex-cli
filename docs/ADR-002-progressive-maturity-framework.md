# ADR-002: Progressive Maturity Framework

**Status**: Accepted  
**Date**: 2026-05-21  
**Context**: Apex CLI needs a maturity model to guide users from basic security scanning to enterprise-grade compliance.

## Decision

Implement a progressive maturity framework with 5 levels, inspired by CPM and ISO 9126 quality characteristics.

## Problem

Current state:
- Binary pass/fail scanning (all or nothing)
- No guidance for gradual improvement
- Users overwhelmed by 100+ findings
- No way to track progress over time
- Missing compliance mapping

## Solution

### Maturity Levels (0-5)

```
Level 0: None       → No scanning
Level 1: Basic      → Core vulnerability detection (SQLi, XSS)
Level 2: Standard   → + CMS detection, OSINT basics
Level 3: Advanced   → + Deep scanning, compliance mapping
Level 4: Expert     → + Continuous monitoring, auto-remediation
Level 5: Excellent  → + Full traceability, zero tolerance
```

### Enforcement Modes

```
learn    → Non-blocking tips, educational output
guide    → Warnings, suggestions for improvement
guard    → Block on critical findings only
enforce  → Block on any high/critical findings
```

### Configuration

```toml
# apex.toml
[maturity]
target_level = 3        # Aim for "Advanced"
current_level = 1       # Auto-calculated

[enforcement]
mode = "guide"          # learn | guide | guard | enforce

[thresholds]
max_critical = 0        # Fail if any critical
max_high = 5            # Allow up to 5 high
max_medium = 20         # Allow up to 20 medium

[scanners]
skip = []               # Skip specific scanners
required = ["SQLi", "XSS", "CMS Detection"]

[compliance]
frameworks = ["OWASP", "CWE"]  # Map findings to frameworks
```

### Maturity Calculation

```cpp
struct MaturityScore {
    int level;              // 0-5
    int percentage;         // 0-100
    map<string, int> dimensions;
};

// Dimensions (ISO 9126)
- Security:      No critical/high vulns
- Maintainability: CMS up-to-date
- Reliability:   OSINT leaks addressed
- Efficiency:    Scan performance
- Portability:   Multi-platform support
- Functionality: Scanner coverage
```

### Scoring Algorithm

```
Level 1 (20%):  Basic scanners enabled
Level 2 (40%):  + CMS detection, no critical vulns
Level 3 (60%):  + OSINT, no high vulns, 80% CMS up-to-date
Level 4 (80%):  + Deep scan, continuous monitoring, auto-fix
Level 5 (100%): + Full compliance, traceability, zero tolerance
```

## Architecture

```
┌─────────────────────────────────────┐
│         Apex CLI Main               │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌──────▼──────────┐
│ Config      │  │  Maturity       │
│ (apex.toml) │  │  Calculator     │
└──────┬──────┘  └──────┬──────────┘
       │                │
       └───────┬────────┘
               │
        ┌──────▼──────┐
        │  Scanners   │
        │  (filtered) │
        └──────┬──────┘
               │
        ┌──────▼──────┐
        │  Findings   │
        │  + Score    │
        └─────────────┘
```

## Implementation

### 1. Config File (apex.toml)

```toml
[maturity]
target_level = 3

[enforcement]
mode = "guide"

[thresholds]
max_critical = 0
max_high = 5
max_medium = 20

[scanners]
skip = ["Open Redirect"]
required = ["SQLi", "XSS"]

[compliance]
frameworks = ["OWASP", "CWE"]
```

### 2. Maturity Calculator

```cpp
// src/maturity.hpp
struct MaturityScore {
    int level;
    int percentage;
    map<string, int> dimensions;
    vector<string> recommendations;
};

MaturityScore calculate_maturity(
    const Config& cfg,
    const vector<Finding>& findings,
    const vector<CMSVersion>& cms,
    const OSINTReport& osint
);
```

### 3. Progressive Enforcement

```cpp
// Filter findings based on enforcement mode
vector<Finding> filter_by_enforcement(
    const vector<Finding>& findings,
    const string& mode
) {
    if (mode == "learn") return {};  // Show all, fail none
    if (mode == "guide") {
        // Only fail on critical
        return filter(findings, [](auto& f) { 
            return f.severity == "critical"; 
        });
    }
    if (mode == "guard") {
        // Fail on critical + high
        return filter(findings, [](auto& f) { 
            return f.severity == "critical" || f.severity == "high"; 
        });
    }
    // enforce: fail on all
    return findings;
}
```

### 4. Compliance Mapping

```cpp
// Map scanners to compliance frameworks
map<string, vector<string>> compliance_map = {
    {"SQLi", {"OWASP:A03:2021", "CWE-89"}},
    {"XSS", {"OWASP:A03:2021", "CWE-79"}},
    {"SSRF", {"OWASP:A10:2021", "CWE-918"}},
    {"CMS Detection", {"OWASP:A06:2021"}},
    {"OSINT", {"OWASP:A01:2021"}}
};
```

### 5. Output Format

```bash
./build/apex-cli example.com

╔══════════════════════════════════════╗
║   APEX CLI - Security Assessment     ║
╚══════════════════════════════════════╝

🎯 Maturity Level: 3 (Advanced) - 67%
   Target: Level 3 (67% achieved)

📊 Dimensions:
   Security:        ████████░░ 80%
   Maintainability: ██████░░░░ 60%
   Reliability:     ███████░░░ 70%

🔴 Critical: 0
🟡 High:     3
🟢 Medium:   12

✅ Enforcement: guide (warnings only)

📋 Recommendations:
   1. Update WordPress 6.2.0 → 6.5.3
   2. Fix 3 high severity XSS issues
   3. Enable OSINT monitoring

🎓 Next Level (4 - Expert):
   - Enable continuous monitoring
   - Implement auto-remediation
   - Achieve 90% CMS up-to-date rate
```

## Consequences

### Positive
✅ Gradual improvement path (not overwhelming)  
✅ Clear progress tracking  
✅ Compliance mapping built-in  
✅ Flexible enforcement (learn → enforce)  
✅ Actionable recommendations  

### Negative
⚠️ More complex configuration  
⚠️ Maturity calculation overhead  
⚠️ Need to maintain compliance mappings  

### Risks
🔴 **Subjectivity**: Maturity scoring may not fit all use cases  
🔴 **Gaming**: Users might optimize for score vs. real security  
🔴 **Maintenance**: Compliance frameworks change over time  

### Mitigations
- Make scoring algorithm transparent and configurable
- Provide detailed breakdown of score calculation
- Regular updates to compliance mappings
- Allow custom maturity definitions

## Alternatives Considered

### 1. Binary Pass/Fail
❌ Too rigid, users give up

### 2. Severity-Only Filtering
❌ No guidance for improvement

### 3. External Maturity Tools
❌ Vendor lock-in, integration complexity

### 4. Manual Maturity Assessment
❌ Not scalable, inconsistent

## Usage Examples

### Basic Usage
```bash
# Check current maturity
./build/apex-cli example.com --score

# Set target level
echo 'target_level = 4' >> apex.toml
./build/apex-cli example.com

# Progressive enforcement
./build/apex-cli example.com --enforce=guide
```

### CI/CD Integration
```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    ./build/apex-cli ${{ github.event.repository.url }} \
      --enforce=guard \
      --output=./reports
    
    # Fail if below target level
    if [ $(jq '.maturity.level' reports/report.json) -lt 3 ]; then
      exit 1
    fi
```

### Continuous Monitoring
```bash
# Daily scan with trend tracking
0 2 * * * /opt/apex-cli/build/apex-cli example.com \
  --output=/var/reports/$(date +%Y%m%d) \
  && /opt/apex-cli/scripts/track-maturity.sh
```

## Metrics

Track these over time:
- Maturity level (0-5)
- Maturity percentage (0-100%)
- Findings by severity
- CMS outdated rate
- OSINT leak count
- Time to remediation

## References

- [ISO 9126 Quality Model](https://en.wikipedia.org/wiki/ISO/IEC_9126)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CPM Maturity Framework](https://github.com/rkristelijn/cpm)
- [V-Model](https://en.wikipedia.org/wiki/V-model_(software_development))

## Decision Makers

- Security Team: Approved
- DevOps Team: Approved
- Product Owner: Approved
