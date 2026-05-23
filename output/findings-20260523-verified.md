# Verified Security Findings — 2026-05-23

## Methodology
- Semgrep AST analysis (17 custom rules from real CVE patterns)
- Manual code review and data flow tracing
- 227+ repos scanned from top GitHub projects

## VERIFIED EXPLOITABLE

### 1. 🟡 Langflow — Unsafe Pickle Deserialization in Session Cache
- **File**: `services/cache/disk.py:38` → `pickle.loads(item["value"])`
- **Data flow**: Session service stores `(graph, artifacts)` tuples via pickle
- **Cache location**: `settings.config_dir` (user-specific, NOT /tmp)
- **Exploitability**: Requires write access to cache directory
  - Multi-tenant with shared filesystem: YES
  - Standard single-user Docker: LOW
  - Shared hosting: POSSIBLE
- **Fix**: Add HMAC verification on cached values, or use `json` instead of pickle
- **Bounty**: HackerOne/IBM — worth reporting as defense-in-depth issue
- **Verdict**: VALID but limited exploitability in default deployment

### 2. 🟡 Open-WebUI — SSRF via Admin-Configurable Yandex URL
- **File**: `retrieval/web/yandex.py:77`
- **Code**: `requests.post(yandex_search_url, ...)`
- **Config path**: Admin sets via `form_data.web.YANDEX_WEB_SEARCH_URL`
- **Exploitability**: Requires admin access. Chain: XSS/CSRF → config change → SSRF
- **Verdict**: VALID — admin-to-SSRF escalation

## FALSE POSITIVES (dismissed after verification)

### ❌ Firecrawl — jobId path traversal
- **Reason**: `validateJobIdParam` middleware validates UUID BEFORE controller runs
- **Lesson**: Semgrep doesn't see middleware chains in route definitions

### ❌ ragflow — pickle.loads
- **Reason**: Uses `RestrictedUnpickler` — properly mitigated

### ❌ Dify — pickle.loads
- **Reason**: Developers aware (`# noqa: S301`), data comes from own DB only

## LOWER CONFIDENCE (need more research)

### 3. Langflow — compile() with user code
- **File**: `agentic/helpers/validation.py:254`
- **Status**: AST validation is in place. Need to research bypass techniques.

### 4. Apache Superset — SQL format string in gsheets
- **File**: `db_engine_specs/gsheets.py:272,410`
- **Status**: Uses quote escaping. Need to test dialect-specific bypasses.

## Statistics
- Repos scanned: 227+
- Initial findings: 8
- After verification: 2 confirmed, 3 dismissed, 3 need more research
- False positive rate: 37% (3/8)

## Key Learnings
1. Semgrep finds patterns but can't see middleware/route-level protections
2. Many projects are AWARE of unsafe patterns (noqa comments) but accept the risk
3. The real exploitable bugs are in DATA FLOW, not individual code lines
4. Multi-tenant deployments change the threat model significantly
