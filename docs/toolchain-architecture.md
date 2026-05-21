# Security Toolchain Architecture

## Core Philosophy

**Professionals use toolchains, not single tools.**

Workflow: `recon → crawl → exploit → validate → report`

---

## Recommended Stack (Next.js + Cloudflare + GraphQL)

### Layer 1: Recon
- **Amass** - subdomain discovery
- **httpx** - live service probing

### Layer 2: Fast Scan (CI/CD)
- **Nuclei** - template-based CVE/misconfig detection

### Layer 3: Deep Scan
- **OWASP ZAP** - automated DAST with SPA support
- **Playwright** - authenticated flow testing

### Layer 4: Specialized
- **InQL** - GraphQL security testing
- **sqlmap** - SQL injection validation
- **XSStrike** - XSS validation

### Layer 5: Manual
- **Caido** or **Burp Community** - intercept & modify

---

## Why This Combination?

| Need | Tool | Reason |
|------|------|--------|
| Next.js API routes | ZAP + Nuclei | Auth-aware scanning |
| GraphQL | InQL | Introspection + mutations |
| SPA crawling | ZAP AJAX spider | Client-side routing |
| CI/CD gates | Nuclei | Fast (< 2 min) |
| Attack surface | Amass + httpx | Comprehensive |

---

## Trade-offs vs Acunetix

**What we lose:**
- One-click reports
- AI correlation
- Low false positives

**What we gain:**
- $0 cost vs $5k+/year
- Full customization
- Native CI/CD

**Reality:** OSS covers 90%, commercial tools add polish.

---

## Implementation Priority

1. **Week 1**: Nuclei + ZAP basics
2. **Week 2**: Amass recon + Playwright auth
3. **Week 3**: InQL GraphQL + custom templates

---

## Performance Targets

- PR check: < 2 min (Nuclei)
- Nightly: < 15 min (ZAP)
- Weekly deep: < 2 hours (full stack)
