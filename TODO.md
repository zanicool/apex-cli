# Quick TODO's

- [x] add weak encryption detection and exploits via rainbotables
- [x] detect web vulnerabilities, like windowdressing, css injection, and all kinds of stuff
- [ ] gather knowledge from security trainings
- [x] test uploading contaminated payloads with upper ascii malware or binary embedded stuff
- [x] scan for exploitable libs used when detected, like react/nextjs/angular are easy to detect, or jquery, or other libs 
- [x] make special exception for wordpress and vulnerable plugins

# Improvements found from live scan analysis (2026-05-11)

## Ffuf / Fuzzing
- [ ] ffuf returns 4700+ results on some targets (api.britishairways.com) — that's basically every word matching. Add auto-calibration (`-ac`) or response-size filtering to eliminate wildcard/catch-all responses
- [ ] ffuf uses only `common.txt` (4750 words) — too small for deep mode. Use `directory-list-2.3-medium.txt` when `--deep` is set
- [ ] ffuf runs sequentially on 43 targets with only 50 threads — parallelize ffuf across multiple targets simultaneously (e.g. 3-4 ffuf processes at once)
- [ ] ffuf `-t 50` is hardcoded low — the env var `APEX_FFUF_T` defaults to 100 but the running scan shows 50. Fix the default or respect the env var properly

## WAF Handling
- [ ] 4 WAFs detected (F5 BIG-IP, Akamai, AWS WAF, Unknown) but scan still runs standard payloads — WAF bypass mode is set but ffuf doesn't use any evasion (rate throttling, header rotation, path encoding)
- [ ] add ffuf delay/rate-limit when WAF is detected to avoid getting IP-banned mid-scan

## Scan Flow / Performance
- [ ] scan has 43 live web targets but fuzzes them one-by-one — the fuzz phase alone will take 40+ minutes. Batch ffuf with GNU parallel or asyncio subprocess pool
- [ ] no progress indicator for how many targets are done vs remaining in the fuzz phase (only shows elapsed time)
- [ ] the scan has been running 23+ minutes and is still on the fuzz phase (7/43 targets done) — consider skipping targets that return wildcard responses early

## Recon
- [ ] 113 subdomains found but only 43 are live — good ratio, but consider adding `dnsx` resolution before httpx to filter faster
- [ ] no amass/assetfinder used (only subfinder + CT + passive) — in non-deep mode that's fine, but document this tradeoff

## Intelligence
- [ ] wildcard detection: if ffuf returns >90% of wordlist as hits, mark target as wildcard and skip (currently wastes time scanning api.britishairways.com which returns everything)
- [ ] prioritize targets with fewer ffuf results (likely real content) over wildcard responders

## OOB Server (Critical)
- [ ] oob_server.py is using 10.6GB RAM (32% of system memory!) — likely a memory leak storing all callbacks/DNS queries without cleanup. Add TTL-based eviction or max buffer size
- [ ] oob_server.py has been running since 15:48 — no log rotation or memory cap

## Code Architecture
- [ ] scanners.py is 17,359 lines in a single file with 293 scan functions — split into modules (recon.py, injection.py, auth.py, etc.) for maintainability
- [ ] apex.py has duplicate phase method definitions (phase_jwt_alg_confusion, phase_blind_xss, etc. defined twice) — dead code that should be cleaned up
- [ ] many phase methods are copy-paste identical pattern (check dry_run, call scanner, extend vulns) — could be a decorator or generic runner

## Error Handling / Resilience
- [ ] no retry logic on individual scanner failures — if a request times out, the finding is just lost. Add retry with backoff for critical scanners (SQLi, XSS, SSRF)
- [ ] adaptive_backoff only handles 429/503 but not connection resets or DNS failures which are common with WAF-protected targets
- [ ] no per-target timeout — if one target hangs (e.g. slow API), it blocks the entire sequential phase

## Reporting
- [ ] no total scan duration tracked in report — only per-phase elapsed time from the progress bar. Add wall-clock start/end time to report.json
- [ ] no scan ETA — with 43 targets and knowing avg time per target, could show "~35 min remaining"
- [ ] ffuf results with 4700+ hits should be flagged as "wildcard — unreliable" in the report instead of being fed into nuclei/sqlmap

## apex-auto.py / Loop
- [ ] apex-loop.sh sleeps only 10s between full bounty passes — should be configurable and much longer (hours) to avoid hammering targets
- [ ] no deduplication between loop passes — same targets get rescanned every 10s if they're still in the bounty list
- [ ] no cooldown per target — should track last-scanned timestamp and skip recently scanned domains

## Performance
- [ ] fingerprint phase took 11 minutes for 43 targets — that's 15s per target. The fingerprint function makes multiple HTTP requests per target sequentially. Parallelize with batch_get()
- [ ] the scan does recon → probe → fingerprint → fuzz sequentially, but fuzz doesn't need ALL fingerprints done. Could start fuzzing first targets while fingerprinting later ones (pipeline)
- [ ] crawl_deep runs after fuzz, but fuzz results feed into crawl — this is correct, but crawl should start on already-fuzzed targets while fuzz continues on remaining ones

## Thread Safety (Bug)
- [ ] 315 calls to `self.vulnerabilities.extend()` but only 203 use `self._vuln_lock` — 112 phase methods modify the shared list without locking. These run in the parallel ThreadPoolExecutor and can cause data corruption/lost findings
- [ ] affected phases include: phase_headers, phase_xss, phase_cmdi, phase_idor, phase_ssrf, phase_ssti, phase_lfi, phase_cors, phase_graphql, etc. (all the early-defined ones)
- [ ] `self.crawl_data` is also read by all parallel phases without any lock — concurrent dict reads are safe in CPython but extending nested lists isn't

## Testing
- [ ] zero test files exist — no unit tests, no integration tests. At minimum need tests for: verify_finding(), deduplicate_findings(), score_findings(), the WAF bypass payload generators
- [ ] no CI/CD pipeline — SARIF output exists but nothing runs it automatically

## False Positive Reduction
- [ ] verify_finding() re-requests every finding URL — on a scan with 200+ findings that's 200+ extra requests at the end. Should verify inline during the scan phase instead of as a post-processing step
- [ ] verify_finding() returns True for any URL that returns <400 status as default — this means any non-404 page passes verification even if it's not actually vulnerable
- [ ] no soft-404 detection during crawl phase — many sites return 200 for everything with a custom "not found" page, inflating crawl_data

## Scan Intelligence
- [ ] no learning between scans — if britishairways.com was scanned yesterday, today's scan starts from scratch. Should cache subdomain/tech/WAF data and only re-probe
- [ ] no target fingerprint comparison — if a target hasn't changed (same hash/headers), skip re-scanning it
- [ ] DNS cache in scanners.py never expires — stale DNS entries persist for the entire scan lifetime. Add TTL

## Stealth / Evasion
- [ ] User-Agent rotation exists but all requests from same IP with same TLS fingerprint — easy to detect. Consider rotating TLS fingerprints (curl_cffi or tls-client)
- [ ] no request jitter — all threads fire at exact _RATE_DELAY intervals, creating a detectable pattern. Add random jitter (±30%)
- [ ] ffuf doesn't use the proxy setting even when --proxy is specified — only the Python scanners route through it

## Output / UX
- [ ] the progress bar only shows phase name + elapsed time — no indication of which target within a phase is being scanned
- [ ] no way to see live findings during the fuzz phase — findings only appear after the phase completes
- [ ] the rich progress bar redraws cause massive log file bloat (the /tmp/apex_ba_scan.log is full of ANSI escape sequences) — use a simpler format when output is not a TTY
- [ ] no Slack/Discord webhook for real-time findings (only ntfy for criticals)

## Security of the Tool Itself
- [ ] ntfy topic is hardcoded in apex-auto.py (`apex-a3219f8742dd`) — anyone subscribed sees your findings
- [ ] oob_server.py listens on all interfaces by default — should bind to localhost unless explicitly configured
- [ ] Gmail app password referenced in apex-auto.py via env var — good, but the email address is hardcoded

## Missing Capabilities
- [ ] no GraphQL schema introspection before fuzzing — many GraphQL scanners fire blind queries. Should introspect first, then target specific mutations/queries
- [ ] no API authentication token extraction from JS — many SPAs store tokens in localStorage/sessionStorage that could be extracted during crawl
- [ ] no differential scanning between authenticated and unauthenticated views — comparing responses would reveal access control issues more reliably than guessing
- [ ] no support for scanning WebSocket-heavy apps (e.g., chat apps, real-time dashboards) beyond basic injection

## Auto-Scanner (apex-auto.py) — Critical Issues
- [ ] **43,257 targets "scanned" but only 46 hits** — 0.1% hit rate suggests most scans are failing silently or targets are out of scope/dead
- [ ] **11,438 scan directories** created, all 4KB (empty/minimal) — the auto-scanner is creating dirs but not actually completing scans on most targets
- [ ] `advancedcustomfields.com` scanned 25+ times (every loop pass) — the dedup/cooldown is broken, same targets keep getting rescanned
- [ ] `api.portal.enterprise.uphold.com` scanned 25+ times — same issue, no per-target cooldown working
- [ ] `app.delen.be/ch/lu` scanned 7+ times each — loop is not respecting scanned.txt properly
- [ ] **login-test.portofantwerpbruges.com has 452 vulns in one hit** — likely all false positives from a test/honeypot environment. Need to detect and skip test/staging/honeypot targets
- [ ] the auto-scanner is still running xfinity.com ffuf even though I killed it — apex-auto.py respawned it

## Wildcard/False Positive in BA Scan (Confirmed)
- [ ] `api.collab.service.britishairways.com` — 4751 results, ALL status 200, ALL same size (8998 bytes). This is a wildcard/catch-all. ffuf `-ac` would have detected this instantly
- [ ] `api.britishairways.com` — 4744 results, same pattern
- [ ] `api.staging.britishairways.com` — 4742 results, same pattern  
- [ ] `api.uat-collab.service.britishairways.com` — 4741 results, same pattern
- [ ] `holiday.britishairways.com` — 4725 results, same pattern
- [ ] **5 out of 10 completed ffuf scans are pure wildcard noise** — 50% of fuzz time is completely wasted. These will also pollute nuclei/sqlmap later

## Disk Usage
- [ ] 11,438 empty scan directories in apex-cli folder — should clean up or not create dirs for targets that fail immediately
- [ ] auto-results at 350MB and growing — no rotation or cleanup policy
