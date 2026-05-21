# Security Intelligence Notes

## CVE-2025-29927: Next.js Middleware Authorization Bypass

**CVSS**: 9.1 (Critical)
**Disclosed**: 2025-03-21
**Affected**: Next.js < 14.2.25, < 15.2.3

### How it works

Next.js uses an internal header `x-middleware-subrequest` to prevent recursive middleware loops. By sending this header with specific values, an attacker can skip middleware entirely — including authentication checks.

**Exploit:**
```
curl -H "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware" https://target.com/admin
```

Variant for src-directory layouts:
```
curl -H "x-middleware-subrequest: src/middleware" https://target.com/admin
```

### Impact

- Complete auth bypass on any route protected by middleware
- CSP bypass
- Cache poisoning DoS

### Detection

- Check for `/_next/static` or `__NEXT_DATA__` in responses (confirms Next.js)
- Send request with and without the header to a protected route
- If response differs (200 vs 401/403), it's vulnerable

### Mitigation

- Update to Next.js 14.2.25+ or 15.2.3+
- Strip `x-middleware-subrequest` header at WAF/CDN level (Akamai, Cloudflare, etc.)
- Don't rely solely on middleware for authorization

---

## nginx / ingress-nginx Deprecation Status (2025-2026)

### What IS deprecated

| Component | Status | EOL |
|-----------|--------|-----|
| **ingress-nginx** (Kubernetes community controller) | Retired | March 2026 |
| No more releases, bug fixes, or security patches after EOL | | |

### What is NOT deprecated

| Component | Status |
|-----------|--------|
| **nginx** (the webserver itself) | Active, maintained by F5 |
| **NGINX Ingress Controller** (F5 commercial) | Active |
| **NGINX Gateway Fabric** | Active (successor for K8s) |
| **freenginx.org** | Community fork by original author |

### Background

- 2019: F5 acquired nginx for $670M
- 2024: Igor Sysoev (creator) left, forked as freenginx.org
- 2025-03: IngressNightmare (CVE-2025-1974) — critical RCE in ingress-nginx
- 2025-11: Kubernetes SIG Network announced ingress-nginx retirement
- 2026-03: Official EOL — no patches

### Risk assessment

- Using nginx as a **reverse proxy/webserver**: Low risk, still maintained
- Using **ingress-nginx in Kubernetes**: High risk, must migrate before March 2026
- Alternatives: NGINX Gateway Fabric, Envoy/Istio, Traefik, HAProxy

### Detection in scans

When apex-cli detects `Server: nginx`, flag:
- If target appears to be Kubernetes-hosted → warn about ingress-nginx EOL
- Check nginx version if exposed → map to known CVEs
