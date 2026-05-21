# Maturity Patterns from CPM → Apex CLI

## 1. **Enforcement Levels** (Progressive Maturity)
```
learn    → Non-blocking tips
guide    → Warnings before push  
guard    → Block push on errors
enforce  → Block commit on errors + warnings
```

**Apply to Apex CLI**:
```toml
# apex.toml
[enforcement]
level = "guide"  # Start permissive, increase over time

[scan]
fail_on = "high"  # Only fail on high/critical vulns initially
```

## 2. **V-Model Traceability**
```
ADR → Feature → Code → Tests → Coverage
```

**Apply to Apex CLI**:
- Link JSONL findings to ADRs
- Track which scanner validates which requirement
- Bidirectional traceability matrix

## 3. **Check Registry Pattern**
```cpp
// CPM uses modular check system
struct Check {
    string id;
    string name;
    CheckFunc func;
    string level;  // learn, guide, guard, enforce
};

vector<Check> get_checks() {
    return {
        {"SEC-001", "SQL Injection", scan_sqli, "enforce"},
        {"SEC-002", "XSS", scan_xss, "guard"},
        {"CMS-001", "Outdated CMS", scan_cms, "guide"}
    };
}
```

**Apply to Apex CLI**:
```cpp
// src/scanner.hpp
struct Scanner {
    string id;           // SEC-001
    string name;
    ScanFunc func;
    string severity;     // critical, high, medium, low
    string maturity;     // learn, guide, guard, enforce
};
```

## 4. **JSONL Append-Only History**
CPM logs everything to `.cpm/findings.jsonl` for trend analysis.

**Already implemented in Apex CLI** ✅:
- `cms_recon.jsonl`
- `osint_recon.jsonl`
- `vuln_recon.jsonl`

## 5. **Maturity Scoring**
```bash
# CPM calculates maturity score
cpm score
# → 97% (level 5 - excellent)
```

**Apply to Apex CLI**:
```cpp
// src/maturity.hpp
struct MaturityScore {
    int level;        // 0-5
    int percentage;   // 0-100
    map<string, int> dimensions;  // security, docs, tests, etc.
};

MaturityScore calculate_maturity(const vector<Finding>& findings);
```

## 6. **Git Hooks Integration**
```bash
# CPM installs hooks automatically
cpm init
# → .git/hooks/pre-commit
# → .git/hooks/pre-push
# → .git/hooks/post-commit
```

**Apply to Apex CLI**:
```bash
# scripts/install-hooks.sh
#!/bin/bash
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
./build/apex-cli --quick-scan || exit 1
EOF
chmod +x .git/hooks/pre-commit
```

## 7. **Findings Database**
```cpp
// CPM stores findings in SQLite for querying
struct Finding {
    string id;
    string type;
    string severity;
    string file;
    int line;
    string message;
    string timestamp;
    bool resolved;
};
```

**Apply to Apex CLI**:
- Already have JSONL ✅
- Add SQLite for complex queries
- Track finding lifecycle (new → acknowledged → fixed)

## 8. **Auto-Fix Capability**
```bash
# CPM can auto-fix certain issues
cpm fix --type=format
cpm fix --type=outdated-deps
```

**Apply to Apex CLI**:
```cpp
// src/autofix.hpp
struct AutoFix {
    string finding_id;
    string fix_type;     // patch, upgrade, config
    string command;      // "npm update wordpress@6.5.3"
    bool safe;           // Can auto-apply?
};

vector<AutoFix> generate_fixes(const vector<Finding>& findings);
```

## 9. **Compliance Mapping**
```cpp
// CPM maps checks to compliance frameworks
struct ComplianceMapping {
    string check_id;
    vector<string> frameworks;  // OWASP, ISO27001, SOC2
    vector<string> controls;    // A1, A2, etc.
};
```

**Apply to Apex CLI**:
```cpp
// Map scanners to OWASP Top 10
{"SQLi", {"OWASP:A03:2021", "CWE-89"}},
{"XSS", {"OWASP:A03:2021", "CWE-79"}},
{"SSRF", {"OWASP:A10:2021", "CWE-918"}}
```

## 10. **Progressive Disclosure**
```bash
# CPM shows minimal output by default
cpm scan
# → ✓ 45 checks passed
# → ⚠ 3 warnings
# → ✗ 1 error

# Verbose mode for details
cpm scan --verbose
# → Full output with evidence
```

**Apply to Apex CLI**:
```cpp
// Default: summary only
./build/apex-cli example.com
# → 🔴 3 critical, 🟡 5 medium, 🟢 10 low

// Verbose: full details
./build/apex-cli example.com --verbose
# → Full evidence, payloads, responses
```

## 11. **Config-Driven Behavior**
```toml
# cpm.toml
[enforcement]
level = "guide"

[checks]
skip = ["check-todo", "check-complexity"]

[thresholds]
coverage = 80
complexity = 10
```

**Apply to Apex CLI**:
```toml
# apex.toml
[scan]
mode = "deep"
threads = 200

[scanners]
skip = ["Open Redirect", "CORS"]

[thresholds]
max_critical = 0
max_high = 5
```

## 12. **Self-Documenting**
CPM generates docs from code:
```bash
cpm docs generate
# → docs/checks/*.md (auto-generated)
```

**Apply to Apex CLI**:
```bash
./scripts/generate-scanner-docs.sh
# → docs/scanners/sqli.md
# → docs/scanners/xss.md
```

## 13. **Continuous Improvement Loop**
```
scan → findings → fix → verify → improve
```

**Apply to Apex CLI**:
1. Scan target
2. Export findings to JSONL
3. Track fixes over time
4. Show improvement metrics
5. Adjust scanner sensitivity

## 14. **Zero-Config Defaults**
CPM works out-of-the-box with sane defaults.

**Apply to Apex CLI**:
```cpp
// Default config if apex.toml missing
Config default_config() {
    return {
        .threads = 100,
        .timeout = 10,
        .deep = false,
        .osint_mode = false,
        .report = "json,terminal"
    };
}
```

## 15. **Makefile Integration**
```makefile
# CPM provides standard targets
check:    # Run all checks
test:     # Run tests
format:   # Auto-format
lint:     # Lint code
```

**Apply to Apex CLI**:
```makefile
.PHONY: check scan test format

check: format lint test scan

scan:
	./build/apex-cli localhost --dry-run

format:
	clang-format -i src/*.cpp

lint:
	cppcheck src/

test:
	./build/test_runner
```

---

## Implementation Priority

### Phase 1: Foundation
1. ✅ JSONL logging (done)
2. ✅ CSV exports (done)
3. ⬜ Config file (apex.toml)
4. ⬜ Enforcement levels

### Phase 2: Maturity
5. ⬜ Maturity scoring
6. ⬜ Compliance mapping
7. ⬜ Trend analysis
8. ⬜ Git hooks

### Phase 3: Advanced
9. ⬜ Auto-fix suggestions
10. ⬜ SQLite findings DB
11. ⬜ Self-documentation
12. ⬜ Traceability matrix

---

## Key Takeaway

**CPM's maturity comes from**:
- Progressive enforcement (learn → enforce)
- Comprehensive logging (JSONL)
- Modular check system
- Config-driven behavior
- Zero-friction integration
- Continuous improvement metrics

**Apply these to Apex CLI** to reach Level 5 maturity! 🎯
