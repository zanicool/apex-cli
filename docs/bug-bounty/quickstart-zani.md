# Bug bounty toolkit — quickstart

Zani, dit is waar we gebleven zijn. Alles staat klaar.

## Wat we gevonden hebben (24 mei 2026)

### Bevestigde findings (klaar om te reporten)

| Target | Bug | Impact | Waar reporten |
|--------|-----|--------|---------------|
| **api.hoppscotch.io** | GraphQL introspection (59 types) | Schema: User, InvitedUser, UserHistory | github.com/hoppscotch/hoppscotch/security |
| **api.hoppscotch.io** | CORS reflects any origin | Cross-origin data theft | github.com/hoppscotch/hoppscotch/security |
| **firefox-ci-tc.services.mozilla.com** | GraphQL introspection (155 types) + secret name enumeration | CI/CD secret paths leesbaar zonder auth | mozilla.org/security/bug-bounty |
| **www.priceline.com** | CORS + credentials reflects any origin | Authenticated session data theft | hackerone.com/priceline |

### Nog te onderzoeken

| Target | Wat | Hoe |
|--------|-----|-----|
| hoppscotch | Onboarding config POST zonder auth | `bash scripts/deep-fingerprint.sh validate https://api.hoppscotch.io` |
| n8n | GraphQL queries zonder auth | `bash scripts/deep-fingerprint.sh validate https://app.n8n.cloud` |
| bumble staging | geneva-staging.com GraphQL | `bash scripts/deep-fingerprint.sh validate https://gateway.geneva-staging.com` |
| unico_idtech | UAT omgeving open | `bash scripts/deep-fingerprint.sh validate https://idcash-uat.unico.io` |

---

## Jouw Tools

### 1. Validate een target (directe check)

```bash
cd ~/git/hub/apex-cli

# Test of een target kwetsbaar is (5 automatische checks)
bash scripts/deep-fingerprint.sh validate https://api.hoppscotch.io
```

Dit checkt automatisch:
- GraphQL introspection
- Onbeschermde API endpoints
- IDOR (sequential IDs)
- Debug/docs exposure
- CORS misconfiguratie

### 2. Versie detectie

```bash
# Welke stack + versie draait een target?
bash scripts/deep-fingerprint.sh version https://app.cal.com
```

### 3. Zoek targets per stack

```bash
# Welke bounty programma's draaien GraphQL?
bash scripts/bounty-stack-db.sh query graphql

# Welke draaien Express?
bash scripts/bounty-stack-db.sh query Express

# Alle gefingerprinte targets
bash scripts/bounty-stack-db.sh list

# Stats
bash scripts/bounty-stack-db.sh stats
```

### 4. Source code analyse (als repo beschikbaar is)

```bash
# Vind routes zonder auth die data accessen
bash scripts/auth-boundary-scan.sh ~/git/hub/topx/hoppscotch

# Scan een ander open-source project
bash scripts/auth-boundary-scan.sh ~/git/hub/topx/langflow
```

### 5. Nieuwe targets ontdekken

```bash
# Google dorks genereren
bash scripts/fingerprint-discover.sh dorks

# Eén target proben
bash scripts/fingerprint-discover.sh single https://target.com

# Meer targets fingerprinting (voegt toe aan DB)
bash scripts/bounty-stack-db.sh fingerprint
```

### 6. Full pipeline (alles in één)

```bash
# Scan alle topx repos op auth gaps
bash scripts/mge-pipeline.sh ~/git/hub/topx
```

---

## Hoe een report schrijven

### Template voor hoppscotch GraphQL introspection:

```
**Title:** GraphQL Introspection Enabled on Production API

**Severity:** Medium (Information Disclosure)

**URL:** https://api.hoppscotch.io/graphql

**Steps to Reproduce:**
1. Send POST to https://api.hoppscotch.io/graphql
2. Body: {"query":"{ __schema { types { name kind fields { name } } } }"}
3. Full schema is returned including User, InvitedUser, UserHistory types

**Impact:**
- Attacker can map entire API schema
- Sensitive types exposed: User, UserOrganizationMembership, InvitedUser
- Enables targeted IDOR/BOLA attacks on discovered queries/mutations

**Fix:** Disable introspection in production (set introspection: false in Apollo/GraphQL config)
```

### Template voor CORS:

```
**Title:** CORS Misconfiguration — Arbitrary Origin Reflected

**URL:** https://api.hoppscotch.io

**Steps to Reproduce:**
1. curl -H "Origin: https://evil.com" -I https://api.hoppscotch.io/api
2. Response contains: Access-Control-Allow-Origin: https://evil.com

**Impact:**
- Any website can make authenticated cross-origin requests
- If user is logged in, attacker site can steal their data

**Fix:** Whitelist specific allowed origins instead of reflecting the request origin
```

---

## Database (persisted)

Alles staat in `data/bounty-targets.db` (SQLite):
- 113 mid-tier bounty programma's
- 1142 targets
- 290 fingerprints (stack + versie)

```bash
# Direct SQL queries als je wilt:
sqlite3 data/bounty-targets.db "SELECT * FROM fingerprints WHERE stack='graphql-introspection';"
```

---

## Workflow voor vanavond

1. **Start met de bevestigde findings** → schrijf reports voor hoppscotch
2. **Validate de "nog te onderzoeken" targets** → `bash scripts/deep-fingerprint.sh validate <url>`
3. **Als je nieuwe targets wilt** → `bash scripts/bounty-stack-db.sh query graphql`
4. **Report schrijven** → gebruik templates hierboven
5. **Waar reporten:**
   - Hoppscotch: https://github.com/hoppscotch/hoppscotch/security/advisories/new
   - n8n: https://hackerone.com/n8n
   - Bumble: via HackerOne

---

## Regels

- **Alleen testen op targets met bounty programma** (check `bounty-stack-db.sh list`)
- **Geen data wijzigen of verwijderen** — alleen lezen/observeren
- **Geen DoS** — max 1 request per seconde
- **Screenshot alles** — bewijs is belangrijk
- **Bij twijfel: vraag papa of vraag Kiro**

---

## Waar staat alles?

```
~/git/hub/apex-cli/
├── scripts/
│   ├── deep-fingerprint.sh      ← versie detectie + validate
│   ├── bounty-stack-db.sh       ← target database
│   ├── auth-boundary-scan.sh    ← source code analyse
│   ├── fingerprint-discover.sh  ← nieuwe targets vinden
│   └── mge-pipeline.sh          ← full pipeline
├── data/
│   └── bounty-targets.db        ← alle targets + fingerprints
├── output/
│   ├── mge-results-20260524.md  ← resultaten vandaag
│   └── authscan-*/findings.jsonl ← scan resultaten
└── docs/
    ├── bug-bounty/              ← jouw learning kit
    └── adr/adr-008-*.md         ← hoe het werkt (technisch)
```

**Succes vanavond! 🚀 Je eerste echte bounty report is binnen handbereik.**
