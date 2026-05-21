# ADR-003: Bug Bounty Hunter Toolchain Architecture

**Status**: Proposed  
**Date**: 2026-05-21  
**Context**: Research for ethical hacking / bug bounty hunting workflow  
**Deciders**: Security Team  

---

## Context and Problem Statement

Bug bounty hunting requires a **professional toolchain** that enables:
- Legal, ethical vulnerability discovery
- Efficient reconnaissance and attack surface mapping
- Systematic testing of modern web applications (Next.js, GraphQL, APIs)
- Compliance with platform rules (HackerOne, Bugcrowd)

**Key Question**: What is the minimal viable toolchain for successful bug bounty hunting?

---

## Decision Drivers

1. **Legal compliance** - Must operate within scope and rules
2. **Cost efficiency** - Prefer open-source over commercial tools
3. **Learning curve** - Accessible for beginners, powerful for experts
4. **Modern app support** - Next.js, React SPA, GraphQL, REST APIs
5. **ROI timeline** - Path to first payouts within 3-6 months

---

## Considered Options

### Option 1: Commercial Suite (Burp Pro + Acunetix)
- **Pros**: Professional features, low false positives, excellent support
- **Cons**: High cost ($5k+/year), overkill for beginners
- **Verdict**: ❌ Not cost-effective for learning phase

### Option 2: Single Tool Approach (OWASP ZAP only)
- **Pros**: Simple, free, automated scanning
- **Cons**: Misses recon phase, limited API testing, high false positives
- **Verdict**: ❌ Insufficient coverage

### Option 3: Best-of-Breed OSS Toolchain (Recommended)
- **Pros**: Comprehensive, free, industry-standard, teaches methodology
- **Cons**: Requires setup, steeper learning curve
- **Verdict**: ✅ **Selected**

---

## Decision Outcome

**Chosen**: Best-of-Breed OSS Toolchain

### Core Toolchain (5 Essential Tools)

| Layer | Tool | Purpose | Priority |
|-------|------|---------|----------|
| **Intercept** | Burp Community / Caido | Request/response analysis | 🔴 Critical |
| **Recon** | Subfinder + httpx | Attack surface discovery | 🔴 Critical |
| **Fast Scan** | Nuclei | CVE + misconfig detection | 🟡 High |
| **Deep Test** | OWASP ZAP | Automated DAST | 🟡 High |
| **API Test** | Postman / InQL | REST + GraphQL testing | 🟢 Medium |

### Specialized Tools (As Needed)

| Tool | Use Case | When to Use |
|------|----------|-------------|
| **sqlmap** | SQL injection validation | After initial SQLi detection |
| **XSStrike** | XSS validation | Context-aware payload testing |
| **FFUF** | Directory fuzzing | Hidden endpoint discovery |
| **Amass** | Deep recon | Large attack surfaces |
| **waybackurls** | Historical endpoints | Legacy/forgotten routes |

---

## Rationale

### Why This Combination?

**1. Recon is Where Money Lives**

Most beginners skip reconnaissance. Professionals know:
- 80% of bugs are NOT on the homepage
- High-value targets: `dev.*`, `api.*`, `staging.*`, `old.*`
- Historical endpoints often have unpatched vulnerabilities

**2. Modern Apps = API-First Testing**

Next.js/React apps require:
- API route testing (not just UI)
- GraphQL introspection
- Client-side routing awareness
- JWT/cookie session handling

**3. IDOR + Business Logic > "Hacks"**

**Where 80% of bounty payouts come from:**
- IDOR (Insecure Direct Object Reference)
- Business logic flaws
- API leaks
- Access control issues

**NOT from:**
- Automated scanner findings
- Known CVEs
- Generic XSS

---

## Professional Workflow

### Phase 1: Reconnaissance (30-40% of time)

```
1. Subfinder → discover subdomains
2. httpx → identify live services
3. waybackurls → find historical endpoints
4. Manual exploration → understand app logic
```

**Output**: Comprehensive attack surface map

### Phase 2: Fast Vulnerability Sweep (10-15% of time)

```
1. Nuclei → known CVEs, misconfigs
2. Quick wins → exposed panels, default creds
```

**Output**: Low-hanging fruit findings

### Phase 3: Deep Testing (30-40% of time)

```
1. Burp/Caido → intercept & analyze
2. OWASP ZAP → automated scan
3. Manual testing → business logic
```

**Output**: High-value vulnerabilities

### Phase 4: Validation & Reporting (10-20% of time)

```
1. Reproduce reliably
2. Assess impact
3. Write clear report
4. Submit to platform
```

**Output**: Accepted bug bounty submission

---

## Mental Model (Critical Success Factor)

### ❌ Wrong Mindset
"Which tool gives me a bug?"

### ✅ Right Mindset
"Where is the logic broken in this application?"

**Key Insight**: Tools find symptoms. Humans find root causes.

---

## Realistic Expectations

### Timeline to Profitability

| Phase | Duration | Expected Earnings | Focus |
|-------|----------|-------------------|-------|
| **Learning** | 1-3 months | €0-50 | Tool mastery, methodology |
| **First Bugs** | 3-6 months | €50-500/finding | IDOR, XSS, misconfig |
| **Consistent** | 6-18 months | €500-5000/month | Business logic, API flaws |

**Critical**: Consistency > Tools

---

## Bug Type Priority (ROI-Focused)

### Tier 1: High ROI (Focus Here)
1. **IDOR** - Insecure Direct Object Reference
2. **Broken Access Control** - Privilege escalation
3. **API Leaks** - Sensitive data exposure

### Tier 2: Medium ROI
4. **XSS** - Cross-Site Scripting (reflected/stored)
5. **CSRF** - Cross-Site Request Forgery
6. **Business Logic** - Workflow bypasses

### Tier 3: Lower ROI (Saturated)
7. **Misconfigurations** - Many duplicates
8. **Known CVEs** - Often already reported
9. **Informational** - Low/no payout

---

## Platform Strategy

### Recommended Platforms

| Platform | Best For | Difficulty |
|----------|----------|------------|
| **HackerOne** | Beginners | Medium |
| **Bugcrowd** | Variety | Medium |
| **Intigriti** | European targets | Medium-High |

### Program Selection Criteria

**Start with:**
- ✅ Small scope (easier to master)
- ✅ Active programs (fast response)
- ✅ Public programs (no NDA)
- ✅ Responsive teams (good reputation)

**Avoid initially:**
- ❌ Large scope (overwhelming)
- ❌ Private programs (harder access)
- ❌ Slow responders (demotivating)

---

## Legal & Ethical Boundaries

### ✅ Always Allowed (Within Scope)
- Testing explicitly listed domains
- Following program rules
- Reporting vulnerabilities responsibly
- Using provided test accounts

### ❌ Never Allowed
- Testing out-of-scope domains
- Social engineering
- Physical attacks
- DoS/DDoS attacks
- Accessing other users' data (unless explicitly allowed)

**Golden Rule**: When in doubt, ask program owner first.

---

## Consequences

### Positive

✅ **Cost-effective**: $0 vs $5k+/year commercial tools  
✅ **Industry-standard**: Learn tools used by professionals  
✅ **Comprehensive**: Full coverage from recon to exploitation  
✅ **Scalable**: Grow from beginner to expert with same tools  
✅ **Legal**: Designed for ethical, authorized testing  

### Negative

⚠️ **Setup time**: 2-4 hours initial configuration  
⚠️ **Learning curve**: Requires methodology understanding  
⚠️ **False positives**: Manual validation needed  
⚠️ **No hand-holding**: Community support only  

### Risks

🔴 **Legal risk**: Testing without authorization = illegal  
🟡 **Time investment**: 3-6 months before consistent payouts  
🟡 **Competition**: Popular programs have many hunters  

**Mitigation**: Start with clear scope, follow rules, focus on learning.

---

## Implementation Roadmap

### Week 1: Foundation
- [ ] Install Burp Community / Caido
- [ ] Setup Subfinder + httpx
- [ ] Create HackerOne account
- [ ] Choose 1-2 beginner programs

### Week 2-4: Tool Mastery
- [ ] Complete Burp Academy basics
- [ ] Practice recon on authorized targets
- [ ] Install Nuclei + run first scans
- [ ] Learn IDOR testing methodology

### Month 2-3: First Submissions
- [ ] Focus on IDOR + access control
- [ ] Submit first 5-10 reports
- [ ] Learn from rejections/duplicates
- [ ] Refine methodology

### Month 4-6: Consistency
- [ ] Develop personal workflow
- [ ] Expand to API testing
- [ ] Add specialized tools as needed
- [ ] Target €500-1000/month

---

## Success Metrics

### Leading Indicators (Process)
- Reports submitted per week
- Unique vulnerabilities found
- Program reputation score
- Response time from teams

### Lagging Indicators (Outcome)
- Accepted reports
- Bounty payouts
- Severity distribution
- Duplicate rate

**Target**: < 30% duplicate rate, > 50% acceptance rate

---

## Related Decisions

- [ADR-001: CMS & OSINT Inventory System](./ADR-001-cms-osint-inventory.md)
- [ADR-002: Progressive Maturity Framework](./ADR-002-progressive-maturity.md)
- [Toolchain Architecture](../TOOLCHAIN_ARCHITECTURE.md)

---

## References

### Learning Resources
- [HackerOne Hacker101](https://www.hacker101.com/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)

### Tool Documentation
- [Burp Suite](https://portswigger.net/burp/documentation)
- [Nuclei](https://docs.projectdiscovery.io/)
- [OWASP ZAP](https://www.zaproxy.org/docs/)
- [Subfinder](https://github.com/projectdiscovery/subfinder)

### Community
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [r/bugbounty](https://reddit.com/r/bugbounty)
- [Bug Bounty Forum](https://bugbountyforum.com/)

---

**Approved**: Pending  
**Review Date**: 2026-06-21  
**Next Review**: Quarterly
