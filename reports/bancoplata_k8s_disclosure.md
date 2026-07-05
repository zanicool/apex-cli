# HackerOne Report: Internal Kubernetes Service URL Leaked in Client-Side HTML

## Summary

The Banco Plata website (`bancoplata.mx`) exposes an internal Kubernetes service URL in the client-side JavaScript configuration. This reveals internal infrastructure details including the cluster namespace, service name, and port.

## Severity

Low — Information Disclosure

## Affected Asset

`https://bancoplata.mx/es/creditlimit`

## Description

The server-side rendered HTML includes a Snowplow Micro collector URL that points to an internal Kubernetes service:

```
http://snowplow-micro.frontend-website-constructor-prod.svc.cluster.local:9090
```

This is embedded in the `GlobalStateProvider` configuration within the page source and is delivered to every visitor's browser.

## Steps to Reproduce

1. Navigate to `https://bancoplata.mx/es/creditlimit`
2. View page source (Ctrl+U)
3. Search for `snowplow-micro`
4. Observe the internal URL: `http://snowplow-micro.frontend-website-constructor-prod.svc.cluster.local:9090`

Alternatively, using curl:

```bash
curl -s https://bancoplata.mx/es/creditlimit | grep -o 'snowplow-micro[^"]*'
```

Output:
```
snowplow-micro.frontend-website-constructor-prod.svc.cluster.local:9090
```

## Information Disclosed

| Detail | Value |
|--------|-------|
| Service name | `snowplow-micro` |
| Namespace | `frontend-website-constructor-prod` |
| Cluster domain | `svc.cluster.local` |
| Port | `9090` |
| Protocol | HTTP (not HTTPS) |

## Impact

An attacker gains knowledge of:

1. **Internal service naming convention** — helps enumerate other services (e.g., `frontend-website-constructor-staging`, `backend-api-prod`, etc.)
2. **Kubernetes namespace structure** — reveals how the infrastructure is organized
3. **The use of Snowplow analytics** — helps target data collection infrastructure
4. **Internal service runs on HTTP** — no TLS between internal services (potential for MITM if attacker gains internal access)

This information reduces the attacker's effort when performing further attacks such as SSRF (knowing valid internal hostnames) or lateral movement after initial compromise.

## Remediation

Replace the internal Snowplow Micro URL with the production collector URL in client-facing code. The internal URL should only be used server-side or in non-production environments.

```javascript
// Before (leaks internal URL)
snowplowMicroCollectorUrl: "http://snowplow-micro.frontend-website-constructor-prod.svc.cluster.local:9090"

// After (remove from client config entirely, or use external URL)
snowplowMicroCollectorUrl: undefined // only used server-side
```

## Research Header

All requests were made with: `X-HackerOne-Research: bananahacker6969`

## References

- OWASP: Information Disclosure
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
