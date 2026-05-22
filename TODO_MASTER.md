# Apex CLI — Ultimate TODO

## 🔴 CRITICAL — High Bounty Scanners

### Injection
- [x] SQL Injection (error + time-based + boolean blind + UNION)
- [x] OS Command Injection (time-based + output-based)
- [x] Server-Side Template Injection (Jinja2, Twig, Freemarker, EL)
- [x] LDAP Injection
- [x] XPath Injection
- [x] Expression Language Injection
- [x] NoSQL Injection
- [x] CRLF Header Injection
- [x] Email Header Injection
- [x] Server-Side Include Injection
- [x] XSLT Injection
- [x] Log Injection
- [ ] LDAP blind injection (time-based)
- [ ] NoSQL blind injection (timing)
- [ ] PDF injection (server-side PDF generation XSS)
- [ ] LaTeX injection
- [ ] CSV injection (formula injection in exports)

### XSS
- [x] Reflected XSS (context-aware)
- [x] DOM XSS (browser-confirmed)
- [x] Stored XSS (submit + check)
- [x] postMessage XSS
- [ ] Blind XSS (inject payload that calls back days later)
- [ ] mXSS (mutation XSS via innerHTML sanitizer bypass)
- [ ] XSS via file upload (SVG, HTML, XML)
- [ ] XSS via PDF (JavaScript in PDF metadata)
- [ ] XSS via image EXIF data
- [ ] Service Worker XSS (register malicious SW)

### SSRF
- [x] SSRF to cloud metadata (AWS/GCP/Azure)
- [x] SSRF via SVG upload
- [x] Blind SSRF (OOB)
- [ ] SSRF via DNS rebinding
- [ ] SSRF via PDF generation (wkhtmltopdf, Puppeteer)
- [ ] SSRF via webhook URLs
- [ ] SSRF via import/export features
- [ ] SSRF via URL preview/unfurl
- [ ] SSRF via font loading (@font-face)
- [ ] SSRF via video/image transcoding

### Authentication
- [x] JWT alg:none bypass
- [x] JWT weak secret cracking
- [x] JWT empty signature
- [x] OAuth redirect_uri bypass
- [x] Password reset poisoning
- [x] 2FA bypass
- [x] Account auto-registration + IDOR testing
- [ ] JWT key confusion (RS256 → HS256)
- [ ] JWT kid header injection (path traversal in kid)
- [ ] JWT jku/x5u header injection
- [ ] OAuth state parameter missing/predictable
- [ ] OAuth PKCE downgrade
- [ ] OAuth token in URL fragment leakage
- [ ] Session fixation
- [ ] Session puzzle (concurrent session manipulation)
- [ ] Remember-me token prediction
- [ ] Password reset token brute-force (short tokens)
- [ ] Account lockout bypass
- [ ] MFA backup code brute-force
- [ ] SSO relay attack

### Access Control
- [x] IDOR via ID enumeration
- [x] IDOR via account differential
- [x] Broken access control (auth vs unauth)
- [x] 403 bypass (8 path manipulation techniques)
- [x] HTTP method tampering
- [x] IP header spoofing bypass
- [x] Role differential scanning
- [ ] Horizontal privilege escalation (user A → user B data)
- [ ] Vertical privilege escalation (user → admin)
- [ ] Mass assignment (add role=admin to registration)
- [ ] Parameter pollution for access control bypass
- [ ] GraphQL field-level authorization bypass
- [ ] Multi-tenant isolation bypass
- [ ] API key scope escalation

### Infrastructure
- [x] Subdomain takeover (47 service fingerprints)
- [x] S3/GCS/Azure bucket enumeration
- [x] Kubernetes API/dashboard exposure
- [x] Docker API exposure
- [x] Terraform state exposure
- [x] Open ports scanning
- [ ] DNS zone transfer (AXFR)
- [ ] Dangling DNS records (NS, MX takeover)
- [ ] Cloud IAM misconfiguration detection
- [ ] Exposed Elasticsearch/MongoDB/Redis
- [ ] Exposed Jenkins/GitLab/Grafana (with default creds)
- [ ] .git directory download + secret extraction
- [ ] Exposed backup files (.bak, .old, .swp, ~)
- [ ] Server version → known CVE mapping
- [ ] SSL/TLS misconfiguration (weak ciphers, expired certs)
- [ ] DNSSEC misconfiguration

## 🟠 HIGH — Reliable Finds

### Logic Bugs
- [x] Race condition (parallel requests)
- [x] Price manipulation
- [x] Payment bypass
- [x] Coupon stacking
- [ ] Inventory manipulation (negative quantity)
- [ ] Currency rounding exploitation
- [ ] Referral/invite abuse (self-referral)
- [ ] Trial extension abuse
- [ ] Feature flag manipulation
- [ ] Workflow state machine bypass (skip steps)
- [ ] Time-of-check-time-of-use (TOCTOU)
- [ ] Integer overflow in calculations
- [ ] Discount code generation prediction

### Information Disclosure
- [x] JS secrets (API keys, tokens, passwords)
- [x] Source map exposure
- [x] Content discovery (sensitive paths)
- [x] Error stack traces
- [ ] Git history secrets (search commit history)
- [ ] Debug endpoints (/debug, /trace, /metrics with data)
- [ ] Verbose error messages with internal paths
- [ ] User enumeration via timing difference
- [ ] Email enumeration via forgot password
- [ ] Internal IP disclosure in headers/responses
- [ ] Technology stack fingerprinting → CVE lookup
- [ ] Exposed API documentation with auth tokens in examples
- [ ] Leaked credentials in JavaScript comments
- [ ] Exposed environment variables

### Client-Side
- [x] CORS misconfiguration (all subdomains)
- [x] Clickjacking
- [x] Open redirect
- [x] CSP bypass
- [x] Prototype pollution
- [ ] DOM clobbering
- [ ] CSS injection (data exfiltration via CSS)
- [ ] Dangling markup injection
- [ ] Reverse tabnabbing (target=_blank without noopener)
- [ ] Web cache deception (authenticated content cached)
- [ ] Client-side template injection (AngularJS, Vue)
- [ ] Insecure postMessage origin validation
- [ ] LocalStorage/SessionStorage sensitive data
- [ ] IndexedDB sensitive data exposure

### Network/Protocol
- [x] HTTP request smuggling (CL.TE)
- [x] Host header injection
- [x] Cache poisoning
- [ ] TE.CL smuggling
- [ ] HTTP/2 exclusive smuggling (H2.CL, H2.TE)
- [ ] WebSocket hijacking (CSWSH)
- [ ] gRPC reflection + unauthorized calls
- [ ] GraphQL subscription abuse (DoS via subscriptions)
- [ ] Server-Sent Events (SSE) injection
- [ ] HTTP/2 PUSH_PROMISE abuse
- [ ] Connection coalescing attacks

## 🟡 MEDIUM — Scanner Intelligence

### Payload Intelligence
- [x] AI payload mutation (context-aware)
- [x] WAF bypass (6 WAF fingerprints + 12 mutations)
- [x] Learning DB (stores successful payloads)
- [ ] Payload encoding chains (double encode, unicode, hex, octal)
- [ ] WAF rule inference (detect what's blocked, craft bypass)
- [ ] Polyglot payloads (work in multiple contexts)
- [ ] Payload minimization (find shortest working payload)
- [ ] Technology-specific payload selection
- [ ] Error message → payload adaptation loop
- [ ] Charset/encoding detection → appropriate payloads

### Crawling & Discovery
- [x] Deep crawler (JS-aware, form submission)
- [x] SPA route discovery
- [x] JS endpoint extraction
- [x] Wayback/OTX URL seeding
- [ ] Robots.txt/sitemap.xml parsing for hidden paths
- [ ] HTML comment extraction (developer notes, TODOs)
- [ ] JavaScript AST parsing (find all fetch/XHR calls)
- [ ] API schema inference from traffic patterns
- [ ] Hidden parameter discovery (Arjun-style)
- [ ] Content-Type fuzzing (send JSON to form endpoints, XML to JSON endpoints)
- [ ] HTTP method discovery per endpoint (OPTIONS, then test all)
- [ ] Recursive directory brute-force with smart wordlists
- [ ] Virtual host discovery (different Host headers)
- [ ] Mobile app traffic replay (from APK extraction)

### Verification & Accuracy
- [x] Evidence extraction (DB versions, file contents)
- [x] Baseline comparison (verify payload causes difference)
- [x] WAF challenge detection (Cloudflare, Akamai, etc)
- [x] Honeypot detection
- [ ] Soft-404 detection (custom error pages returning 200)
- [ ] Rate limit detection (back off before getting banned)
- [ ] Confidence scoring based on multiple verification methods
- [ ] False positive database (learn from manual review)
- [ ] Response clustering (group similar responses, detect anomalies)
- [ ] Timing-based verification (statistical significance testing)

## ⚪ RELIABILITY & PERFORMANCE

### Stability
- [x] Panic recovery on all scanners
- [x] Per-scanner timeout
- [x] Goroutine cap (max 500 jobs per scanner)
- [ ] Graceful shutdown (save state on SIGINT)
- [ ] Memory limit enforcement (prevent OOM)
- [ ] Connection pool management (prevent fd exhaustion)
- [ ] DNS cache with TTL
- [ ] Automatic retry with exponential backoff
- [ ] Circuit breaker (stop scanning target if too many errors)

### Performance
- [x] Parallel scanners (20 concurrent)
- [x] Batch HTTP requests
- [x] TLS fingerprint rotation
- [ ] HTTP/2 multiplexing
- [ ] Connection reuse optimization
- [ ] Response body streaming (don't load full body for large files)
- [ ] Incremental scanning (only scan new/changed content)
- [ ] Scan state persistence (resume interrupted scans)
- [ ] Adaptive concurrency (increase/decrease based on target response time)

### Output & Reporting
- [x] JSON report
- [x] Terminal output
- [x] H1 report generation
- [x] Raw findings written immediately
- [ ] HTML report with screenshots
- [ ] SARIF output (for CI/CD integration)
- [ ] Markdown report
- [ ] CSV export
- [ ] Severity-based filtering in output
- [ ] Real-time findings stream (WebSocket/SSE)
- [ ] Scan comparison (diff between two scans)
- [ ] Executive summary generation

## 🚀 AUTOPILOT & AUTOMATION

### Target Selection
- [x] H1 bounty program fetching
- [x] Priority queue (highest bounty first)
- [x] Discord alerts
- [ ] New program detection (alert within 1 hour of launch)
- [ ] Scope change detection (new assets added)
- [ ] Competition analysis (fewer hackers = better target)
- [ ] Program response time scoring (fast triage = submit there)
- [ ] Bounty-per-vuln-type analysis (which programs pay most for CORS?)
- [ ] Exclude programs with "automated scan" exclusion
- [ ] Target freshness scoring (recently deployed = more vulns)

### Monitoring
- [x] CT log monitoring (new subdomains)
- [x] JS bundle hash monitoring (code changes)
- [x] DNS change monitoring
- [ ] GitHub commit monitoring (new code = new vulns)
- [ ] CDN cache bust detection (new deployment)
- [ ] Certificate renewal monitoring (infrastructure changes)
- [ ] New subdomain instant-scan (scan within 5 min of discovery)
- [ ] Changelog/release notes monitoring
- [ ] Job posting monitoring (hiring security = they know they have issues)

### Distributed
- [x] File-based job queue
- [x] HTTP API for workers
- [ ] Multi-IP rotation (VPS pool)
- [ ] Proxy rotation (residential proxies)
- [ ] Geographic distribution (scan from different regions)
- [ ] Load balancing across workers
- [ ] Centralized findings database
- [ ] Worker health monitoring
- [ ] Auto-scaling (spin up VPS when queue is large)

## 💰 MONEY FEATURES

### Reporting
- [x] H1 report template generation
- [x] CVSS scoring
- [ ] Auto-generate PoC scripts (curl + Python + HTML)
- [ ] Screenshot automation for PoC
- [ ] Video recording of exploitation
- [ ] Impact assessment automation
- [ ] Remediation suggestions per vuln type
- [ ] Report quality scoring (predict acceptance rate)

### Business
- [ ] H1 API integration (submit reports programmatically)
- [ ] Bugcrowd integration
- [ ] Intigriti integration
- [ ] Earnings tracker (total bounties earned)
- [ ] ROI calculator (time spent vs bounty earned per program)
- [ ] Duplicate prediction (estimate chance of duplicate before submitting)
- [ ] Triage time prediction
- [ ] Monthly revenue forecasting

### Community
- [ ] Shared finding templates
- [ ] Payload sharing (anonymized)
- [ ] Scanner plugin marketplace
- [ ] Leaderboard integration
- [ ] Collaboration mode (share scan with team)

---

## Stats
- **Total items:** 200+
- **Completed:** ~80
- **Remaining:** ~120
- **Scanner functions:** 161
- **Lines of code:** 16,819
