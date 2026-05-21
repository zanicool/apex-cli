# Security Toolchain Research & Architecture

## Executive Summary

**Key Insight**: Professional security engineers don't use "one tool" - they build **toolchains + workflows**. The real value is in the combination: recon → crawling → exploit testing → manual validation → reporting.

This document outlines a production-grade open-source security architecture specifically designed for:
- Next.js/SPA applications
- Cloudflare Workers/Pages
- GraphQL APIs
- Modern authentication (JWT/cookies)

---

## 1. Core Philosophy: Toolchains, Not Tools

### ❌ Wrong Question
"What's the best Acunetix replacement?"

### ✅ Right Question
"What combination covers 90% of OWASP + my attack surface?"

---

## 2. Industry-Standard OSS Pentest Stack (2025/2026)

### 🕷️ Web Application / DAST

| Tool | Purpose | Strength | Weakness |
|------|---------|----------|----------|
| **OWASP ZAP** | Automated scanner | SPA crawling, AJAX spider | Slow, false positives |
| **Burp Suite Community** | Manual testing | Intercept, modify requests | No automated scan |
| **Caido** | Modern alternative | Better UX, API-first | Newer, smaller community |

**Verdict**: ZAP is the only real automated open-source scanner.

---

### ⚡ Fast Vulnerability Scanning (CI/CD)

| Tool | Purpose | Use Case |
|------|---------|----------|
| **Nuclei** | Template-based scanner | GitHub Actions, GitLab CI |

**Status**: Near industry-standard for OSS CI/CD security.

**Why it matters**:
- 10,000+ community templates
- Sub-second execution
- Perfect for shift-left security

---

### 🌐 Reconnaissance / Attack Surface Discovery

| Tool | Purpose | Output |
|------|---------|--------|
| **Amass** | Subdomain enumeration | Comprehensive subdomain list |
| **Subfinder** | Fast subdomain discovery | Quick results |
| **httpx** | HTTP probing | Live services only |
| **waybackurls** | Historical endpoints | Forgotten/legacy routes |

**Critical**: This is what professionals run **before** opening ZAP.

---

### 🧪 Exploit Validation / Payload Testing

| Tool | Vulnerability Type | Notes |
|------|-------------------|-------|
| **sqlmap** | SQL injection | Industry standard |
| **XSStrike** | XSS testing | Context-aware payloads |
| **Commix** | Command injection | OS command testing |
| **Ghauri** | SQL injection | Modern sqlmap alternative |

**Purpose**: Deep validation after initial detection.

---

### 🧰 Manual Testing / Interception

| Tool | Best For | License |
|------|----------|---------|
| **Burp Suite Community** | Manual testing | Free (limited) |
| **Burp Suite Pro** | Professional pentesting | Commercial |
| **Caido** | Modern workflows | Free tier |
| **mitmproxy** | Scriptable proxy | Open source |

---

### 📡 Network / Infrastructure

| Tool | Purpose | Speed |
|------|---------|-------|
| **Nmap** | Port scanning | Standard |
| **Masscan** | Fast scanning | Very fast |
| **RustScan** | Modern Nmap accelerator | Fastest |

---

### 📦 API / Modern App Testing (Critical for Next.js)

| Tool | Purpose | Next.js Relevance |
|------|---------|-------------------|
| **Postman** | API testing | API routes |
| **Insomnia** | REST/GraphQL | GraphQL endpoints |
| **ZAP API Scanner** | Automated API scan | OpenAPI/Swagger |
| **GraphQL Voyager** | Schema visualization | GraphQL introspection |
| **InQL** | GraphQL security | Mutation testing |

**Why this matters**: Next.js API routes + GraphQL backends are primary attack surface.

---

### ☁️ Cloud / Misconfiguration Scanning

| Tool | Cloud Provider | Focus |
|------|----------------|-------|
| **ScoutSuite** | AWS/Azure/GCP | Multi-cloud |
| **Prowler** | AWS | Best practices |
| **CloudFox** | AWS | Recon |

**Cloudflare Note**: Limited tooling - mostly manual review of Workers/Pages config.

---

## 3. Professional Workflow (Real-World)

### Typical Pentest Flow

```
1. RECON
   ├─ Amass + Subfinder → subdomains
   └─ httpx → live services

2. ATTACK SURFACE MAPPING
   ├─ ZAP spider (SPA crawling)
   └─ Manual browsing (Burp/Caido)

3. FAST VULNERABILITY SWEEP
   └─ Nuclei templates

4. DEEP TESTING
   ├─ ZAP active scan
   └─ sqlmap / XSStrike

5. MANUAL VALIDATION
   └─ Burp / Caido

6. REPORTING
   ├─ Dradis (open source)
   └─ Serpico (report automation)
```

---

## 4. Where Commercial Tools Still Win

### Acunetix/Burp Pro Advantages

❌ **Open source gaps**:
- One-click professional reports
- Smart false-positive filtering
- AI-assisted vulnerability correlation
- Advanced crawl intelligence
- Integrated remediation guidance

✅ **Professional reality**:
- OSS for 80% coverage
- Commercial tools for polish & depth
- Hybrid approach is standard

---

## 5. Best-of-Breed OSS Stack (Simplified)

### Web Apps (Next.js / SPA)
- OWASP ZAP
- Nuclei
- Caido / Burp Community

### Recon
- Amass
- Subfinder
- httpx

### Exploitation
- sqlmap
- XSStrike

### Infrastructure
- Nmap
- Masscan
- Prowler / ScoutSuite

---

## 6. Recommended Stack for Next.js + Cloudflare + GraphQL

### Minimum Viable Security Toolchain

```
┌─────────────────────────────────────────────┐
│  RECON LAYER                                │
├─────────────────────────────────────────────┤
│  • Amass (subdomain discovery)              │
│  • httpx (live service probing)             │
│  • waybackurls (historical endpoints)       │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  FAST SCANNING (CI/CD)                      │
├─────────────────────────────────────────────┤
│  • Nuclei (CVE + misconfig)                 │
│  • Custom templates (Next.js specific)      │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  DEEP SCANNING                              │
├─────────────────────────────────────────────┤
│  • OWASP ZAP (auth + SPA crawling)          │
│  • Playwright (authenticated flows)         │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  SPECIALIZED TESTING                        │
├─────────────────────────────────────────────┤
│  • InQL (GraphQL security)                  │
│  • sqlmap (SQL injection validation)       │
│  • XSStrike (XSS validation)                │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│  MANUAL VALIDATION                          │
├─────────────────────────────────────────────┤
│  • Caido / Burp (intercept & modify)        │
└─────────────────────────────────────────────┘
```

---

## 7. Tool Selection Rationale

### Why This Combination?

| Requirement | Tool | Reason |
|-------------|------|--------|
| **Next.js API routes** | ZAP + Nuclei | Auth-aware, API scanning |
| **GraphQL endpoints** | InQL + ZAP | Introspection + mutation testing |
| **SPA crawling** | ZAP AJAX spider | Handles client-side routing |
| **JWT/Cookie auth** | Playwright + ZAP | Automated auth flows |
| **CI/CD gates** | Nuclei | Fast, template-based |
| **Attack surface** | Amass + httpx | Comprehensive discovery |
| **Manual testing** | Caido | Modern UX, API-first |

---

## 8. Trade-offs & Limitations

### What We Sacrifice (vs Acunetix)

| Feature | Acunetix | OSS Stack | Impact |
|---------|----------|-----------|--------|
| **Setup time** | 5 min | 2-4 hours | One-time cost |
| **Report quality** | Excellent | Good | Manual polish needed |
| **False positives** | Low | Medium | Requires validation |
| **Crawl intelligence** | Advanced | Basic | More manual work |
| **Support** | Commercial | Community | Self-service |

### What We Gain

| Benefit | Value |
|---------|-------|
| **Cost** | $0 vs $5,000+/year |
| **Customization** | Full control |
| **CI/CD integration** | Native |
| **Transparency** | Open source |
| **Learning** | Deep security knowledge |

---

## 9. Implementation Priorities

### Phase 1: Foundation (Week 1)
- [ ] Nuclei CI/CD integration
- [ ] Basic ZAP scanning
- [ ] JSONL audit logging

### Phase 2: Depth (Week 2-3)
- [ ] Amass recon pipeline
- [ ] Playwright auth flows
- [ ] GraphQL InQL integration

### Phase 3: Polish (Week 4)
- [ ] Custom Nuclei templates
- [ ] Automated reporting
- [ ] OWASP coverage matrix

---

## 10. Success Metrics

### Coverage Goals

- ✅ **OWASP Top 10**: 100% coverage
- ✅ **Next.js specific**: env exposure, API routes, SSR issues
- ✅ **GraphQL**: introspection, mutations, auth bypass
- ✅ **CI/CD**: < 5 min scan time
- ✅ **False positive rate**: < 10%

### Performance Targets

| Scan Type | Target Time | Tool |
|-----------|-------------|------|
| **Fast (PR check)** | < 2 min | Nuclei |
| **Medium (nightly)** | < 15 min | ZAP basic |
| **Deep (weekly)** | < 2 hours | Full stack |

---

## 11. Next Steps

### Immediate Actions

1. **Validate toolchain** with pilot scan
2. **Benchmark** against known vulnerabilities
3. **Document** false positive patterns
4. **Train team** on tool usage
5. **Integrate** into existing CI/CD

### Long-term Strategy

- **Quarterly**: Review new tools/templates
- **Monthly**: Update Nuclei templates
- **Weekly**: Review scan results
- **Daily**: Monitor CI/CD gates

---

## 12. References & Resources

### Official Documentation
- [OWASP ZAP](https://www.zaproxy.org/docs/)
- [Nuclei](https://docs.projectdiscovery.io/tools/nuclei/overview)
- [Amass](https://github.com/owasp-amass/amass)
- [InQL](https://github.com/doyensec/inql)

### Community Resources
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

### Training
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

---

## Conclusion

**Key Takeaway**: A well-orchestrated OSS toolchain can achieve 90% of commercial tool capabilities at 0% of the cost. The remaining 10% (polish, reporting, false-positive filtering) can be addressed through:

1. **Process**: Structured validation workflows
2. **Automation**: Custom scripts and templates
3. **Expertise**: Team training and knowledge sharing

**For Next.js + Cloudflare + GraphQL**: The recommended stack (ZAP + Nuclei + InQL + Playwright + Amass) provides comprehensive coverage with minimal overhead.

---

**Last Updated**: 2026-05-21  
**Status**: Research Complete → Ready for Implementation
