# 🔐 Apex Security Scanner

**Production-grade open-source DAST voor Next.js/SPA applicaties**

Volledige Acunetix-vervanging in C++ met OWASP Top 10 2021 coverage.

---

## ✨ Features

- ✅ **OWASP Top 10 2021** volledige coverage
- ✅ **Next.js/SPA specifiek**: env exposure, API routes, hydration flows
- ✅ **GraphQL scanning**: introspection, mutations, auth bypass
- ✅ **Authentication**: JWT, cookies, form-based
- ✅ **JSONL audit trail**: compliance-ready logging
- ✅ **CWE mapping**: automatische vulnerability classification
- ✅ **CI/CD ready**: GitHub Actions, Docker, headless mode

---

## 🚀 Quick Start

### Build

```bash
make build
```

### Basic Scan

```bash
./build/apex-cli --security-scan https://example.com
```

### Full Scan met Auth

```bash
./build/apex-cli --security-scan https://app.example.com \
  --auth-jwt "eyJhbGc..." \
  --spa-mode \
  --graphql /api/graphql
```

---

## 📋 Scan Types

### 1. Fast Scan (< 5 min)

```bash
./build/apex-cli --security-scan https://example.com --fast
```

Checks:
- Security headers
- Known CVEs
- Exposed files (.env, .git)
- API route enumeration

### 2. Full Scan (15-30 min)

```bash
./build/apex-cli --security-scan https://example.com --deep
```

Checks:
- SQL Injection (error + time-based)
- XSS (reflected + stored)
- SSRF (cloud metadata)
- Authentication bypass
- Access control issues
- Security misconfiguration
- GraphQL introspection

### 3. SPA Mode (Next.js/React)

```bash
./build/apex-cli --security-scan https://app.example.com \
  --spa-mode \
  --api-routes /api/users,/api/admin
```

Extra checks:
- Next.js env exposure
- API route authentication
- Client-side routing issues
- Hydration vulnerabilities

---

## 🔑 Authentication

### JWT Token

```bash
--auth-jwt "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Cookie-based

```bash
--auth-cookie "session=abc123def456"
```

### Form Login

```bash
--auth-form https://example.com/login \
  --username admin@example.com \
  --password <password>
```

---

## 📊 Reports

### JSON Report

```bash
./build/apex-cli --security-scan https://example.com \
  --output reports/scan.json
```

### JSONL Audit Trail

```bash
# Append-only history voor compliance
./build/apex-cli --security-scan https://example.com \
  --jsonl reports/security-audit.jsonl
```

Query met jq:

```bash
# Critical findings
jq 'select(.severity == 0)' reports/security-audit.jsonl

# OWASP A01 issues
jq 'select(.owasp | contains("A01"))' reports/security-audit.jsonl

# Timeline
jq -r '"\(.timestamp) | \(.name) | \(.url)"' reports/security-audit.jsonl
```

---

## 🎯 OWASP Top 10 2021 Coverage

| Category | Checks | Status |
|----------|--------|--------|
| **A01: Broken Access Control** | API routes, env files, admin panels | ✅ |
| **A02: Cryptographic Failures** | TLS config, weak crypto | ✅ |
| **A03: Injection** | SQLi, XSS, command injection | ✅ |
| **A04: Insecure Design** | Auth flows, business logic | ✅ |
| **A05: Security Misconfiguration** | Headers, CORS, defaults | ✅ |
| **A06: Vulnerable Components** | Known CVEs, outdated libs | ✅ |
| **A07: Auth Failures** | Session handling, JWT | ✅ |
| **A08: Data Integrity** | Deserialization, tampering | ✅ |
| **A09: Logging Failures** | Security events, monitoring | ✅ |
| **A10: SSRF** | Cloud metadata, internal services | ✅ |

---

## 🧪 CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    ./build/apex-cli --security-scan ${{ secrets.APP_URL }} \
      --auth-jwt ${{ secrets.JWT_TOKEN }} \
      --jsonl reports/security.jsonl
    
    # Fail op critical findings
    CRITICAL=$(jq '[select(.severity == 0)] | length' reports/security.jsonl)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "::error::Found $CRITICAL critical vulnerabilities"
      exit 1
    fi
```

### Docker

```bash
docker run -v $(pwd)/reports:/reports apex-cli \
  --security-scan https://example.com \
  --output /reports/scan.json
```

---

## 🔧 Advanced Usage

### GraphQL Scanning

```bash
./build/apex-cli --security-scan https://api.example.com \
  --graphql /graphql \
  --graphql-introspection \
  --graphql-mutations
```

### Rate Limiting

```bash
./build/apex-cli --security-scan https://example.com \
  --rate 1.0  # 1 second tussen requests
```

### Custom Payloads

```bash
./build/apex-cli --security-scan https://example.com \
  --payloads security-pipeline/payloads/custom-sqli.txt
```

---

## 📈 Vergelijking met Acunetix

| Feature | Acunetix | Apex Security Scanner |
|---------|----------|----------------------|
| **OWASP Top 10** | ✅ | ✅ |
| **SPA/Next.js** | ✅ | ✅ |
| **GraphQL** | ✅ | ✅ |
| **API Scanning** | ✅ | ✅ |
| **Auth Handling** | ✅ | ✅ |
| **CI/CD** | ⚠️ Limited | ✅ Native |
| **JSONL Audit** | ❌ | ✅ |
| **Open Source** | ❌ | ✅ |
| **Cost** | €€€€ | Free |
| **Performance** | Fast | **Faster** (C++) |

---

## 🛡️ Best Practices

### 1. Pre-commit Scan

```bash
# .git/hooks/pre-push
./build/apex-cli --security-scan http://localhost:3000 --fast
```

### 2. Nightly Full Scan

```bash
# cron: 0 2 * * *
./build/apex-cli --security-scan https://staging.example.com \
  --deep \
  --jsonl /var/log/security/audit.jsonl
```

### 3. PR Security Check

```yaml
on: pull_request
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - run: ./build/apex-cli --security-scan $PR_URL --fast
```

---

## 🔍 Vulnerability Examples

### SQL Injection Detection

```bash
[CRITICAL] SQL Injection
URL: https://example.com/api/users?id=' OR '1'='1
CWE: CWE-89
OWASP: A03:2021-Injection
Evidence: MySQL error in response
```

### Next.js Env Exposure

```bash
[CRITICAL] Environment Variables Exposed
URL: https://example.com/.env.local
CWE: CWE-200
OWASP: A01:2021-Broken Access Control
Evidence: Found DATABASE_URL, API_KEY
```

### GraphQL Introspection

```bash
[MEDIUM] GraphQL Introspection Enabled
URL: https://api.example.com/graphql
CWE: CWE-200
OWASP: A05:2021-Security Misconfiguration
Evidence: __schema query successful
```

---

## 📚 Integration met Bestaande Tools

### Met OWASP ZAP

```bash
# Apex voor fast checks
./build/apex-cli --security-scan https://example.com --fast

# ZAP voor deep crawling
python security-pipeline/scripts/zap_scanner.py https://example.com
```

### Met Nuclei

```bash
# Apex voor app-level
./build/apex-cli --security-scan https://example.com

# Nuclei voor infra-level
nuclei -u https://example.com -t ~/nuclei-templates/
```

---

## 🎓 Training Mode

```bash
# Leer van findings
./build/apex-cli --security-scan https://example.com \
  --explain \
  --remediation
```

Output:

```
[HIGH] Cross-Site Scripting (XSS)
URL: https://example.com/search?q=<script>alert(1)</script>

📖 Explanation:
User input is reflected in HTML without sanitization.

🔧 Remediation:
1. Use Content-Security-Policy header
2. Sanitize input with DOMPurify
3. Use textContent instead of innerHTML

📝 Code Example:
// ❌ Vulnerable
element.innerHTML = userInput;

// ✅ Safe
element.textContent = userInput;
```

---

## 🚨 Emergency Response

Bij critical finding:

```bash
# 1. Stop deployment
./build/apex-cli --security-scan $PROD_URL --fast

# 2. Generate incident report
./build/apex-cli --security-scan $PROD_URL \
  --output incident-$(date +%Y%m%d).json

# 3. Notify team
cat incident-*.json | jq '.findings[] | select(.severity == 0)' | \
  slack-notify --channel security
```

---

## 📞 Support

- **Issues**: https://github.com/your-org/apex-cli/issues
- **Docs**: https://apex-cli.dev/security
- **Slack**: #apex-security

---

**Built with ❤️ in C++ for maximum performance**
