# MGE Pipeline Results — 2026-05-24

## Methodology
Maturity-Guided Exploitation: cpm maturity scoring → auth-boundary-scan → fingerprint discovery

## Batch Scan Results

| Repo | Framework | Findings | BOLA | Notable |
|------|-----------|----------|------|---------|
| **langflow** | FastAPI | 75 | 15 | build_public_tmp (CVE-2026-33017 patched), store endpoints public |
| **open-webui** | FastAPI | 38 | 11 | SCIM /Users/{id} DELETE, /Groups/{id} without auth |
| **hoppscotch** | NestJS | 12 | 12 | onboarding config POST, infra-token user-invitations |
| **code-server** | Express | 13 | 5 | /add-session, /delete-session without auth middleware |
| **dify** | FastAPI | 5 | 2 | dify-agent runs endpoint |
| **grafana** | — | 0 | 0 | Clean (mature project) |
| **immich** | — | 3 | 0 | No BOLA |
| **daytona** | — | 2 | 0 | No BOLA |

## High-Priority Findings

### 1. Hoppscotch — Infra Token + Onboarding (NestJS)
- `POST /onboarding/config` — no @UseGuards, writes config
- `POST /infra-token/user-invitations` — no @UseGuards, creates invitations
- `GET /infra-token/user-invitations` — no @UseGuards, lists invitations
- **Impact**: Unauthenticated config change + user invitation = account takeover chain
- **Bounty program**: https://github.com/hoppscotch/hoppscotch/security

### 2. Code-Server — Session Management (Express)
- `POST /add-session` — no auth middleware
- `POST /delete-session` — no auth middleware
- **Impact**: Session injection → RCE (code-server = VS Code in browser)
- **Bounty program**: https://github.com/coder/code-server/security

### 3. Open-WebUI — SCIM Endpoints (FastAPI)
- `DELETE /scim/Users/{user_id}` — no Depends(get_current_user)
- `DELETE /scim/Groups/{group_id}` — no auth
- **Impact**: Unauthenticated user/group deletion
- **Note**: SCIM may have separate auth (bearer token at app level) — needs verification

## Companies Using These Stacks

### Langflow
- **DataStax** (langflow.datastax.com) — confirmed via fingerprint
- IBM (acquired Langflow team)
- Self-hosted by many enterprises for AI workflows

### Open-WebUI
- Widely self-hosted as Ollama frontend
- No known SaaS provider (local-first)

### Hoppscotch
- hoppscotch.io (SaaS)
- Self-hosted enterprise version
- Alternative to Postman

### Code-Server
- **Coder** (coder.com) — commercial version
- Many cloud IDEs built on it
- Gitpod, Railway, various PaaS

## Discovery Script Usage
```bash
# Generate Google dorks
./scripts/fingerprint-discover.sh dorks

# Probe single target
./scripts/fingerprint-discover.sh single https://target.com

# Probe from URL list
./scripts/fingerprint-discover.sh probe urls.txt

# Shodan search (needs SHODAN_API_KEY)
SHODAN_API_KEY=xxx ./scripts/fingerprint-discover.sh shodan
```

## Next Steps
1. Verify hoppscotch findings — check if onboarding has separate guard at app level
2. Verify code-server — check if vscodeSocket routes are internal-only
3. Run fingerprint-discover with Shodan to find exposed instances
4. For confirmed findings: build PoC → report to bounty program

## False Positive Analysis
- Scanner improved from 37% → ~20% FP rate after adding CurrentActiveUser pattern
- Remaining FPs: indirect auth via Depends(get_flow), app-level middleware not visible
- Key insight: type aliases for auth deps are common in FastAPI projects

## New finding: Mozilla Taskcluster (24 mei, ochtend)

### Mozilla — GraphQL Introspection + Secret Name Enumeration
- **URL**: https://firefox-ci-tc.services.mozilla.com/graphql
- **155 types** exposed via introspection
- **Secret names readable** without auth (info disclosure)
  - GitHub tokens, SSH deploy keys, publishing credentials
  - `gecko/gfx-github-sync/token`, `project/civet/github-deploy-key`, etc.
- **Roles queryable** without auth
- Secret VALUES require auth (properly protected)
- **Impact**: Attacker can enumerate all secret paths → targeted social engineering or scope escalation
- **Program**: Mozilla bug bounty (https://www.mozilla.org/en-US/security/bug-bounty/)
- **Severity**: Medium (info disclosure of CI/CD secret inventory)

Note: Taskcluster is intentionally semi-public (open source CI), but secret name enumeration
may still be reportable as it reveals internal project structure and credential naming.

## Additional findings (24 mei, ochtend scan 2)

### Priceline — CORS with credentials
- **URL**: https://www.priceline.com/pwd/v0/pcln-graphql
- `Access-Control-Allow-Origin: https://evil.com` (reflects any origin)
- `Access-Control-Allow-Credentials: true`
- **Impact**: Critical — any website can make authenticated requests, steal user session data
- **Program**: HackerOne (priceline)
- **Severity**: High

### xvideos — GraphQL introspection
- **URL**: https://www.xvideos.com/graphql
- 61 types exposed, limited sensitive data
- **Severity**: Low/Informational
