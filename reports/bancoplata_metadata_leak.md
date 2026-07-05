# HackerOne Report: X-Installation-ID and Sentry Metadata Leaked to Clients

## Summary

The Banco Plata website leaks an `X-Installation-ID` UUID in HTTP response headers and Sentry debugging metadata (trace IDs, release hashes, environment) in HTML meta tags. This information aids attackers in fingerprinting deployments and correlating sessions.

## Severity

Low — Information Disclosure

## Affected Asset

`https://bancoplata.mx`

## Description

### 1. X-Installation-ID Header

Every response from `bancoplata.mx` includes:

```
X-Installation-ID: 8614a739-ae99-4b9e-a8a3-d4ad2c5b768f
```

This is a static identifier that appears to identify the deployment/instance. It does not rotate between requests.

### 2. Sentry Metadata in HTML

```html
<meta name="sentry-trace" content="da0fefa1de594c0a023064ff3a268555-bff1072f5e480169-1"/>
<meta name="baggage" content="sentry-environment=production,sentry-release=c9d5c8a0f8db4584ff4f4e4373905e76a2efc5ea,sentry-public_key=bda3fe9fdce7f95166bfc88f22ec5a0f,..."/>
```

## Steps to Reproduce

```bash
# Installation ID
curl -sI https://bancoplata.mx | grep -i installation
# Output: x-installation-id: 8614a739-ae99-4b9e-a8a3-d4ad2c5b768f

# Sentry metadata
curl -s https://bancoplata.mx/es/creditlimit | grep -o 'sentry-[^"]*'
```

## Information Disclosed

| Item | Value |
|------|-------|
| Installation ID | `8614a739-ae99-4b9e-a8a3-d4ad2c5b768f` |
| Sentry environment | `production` |
| Sentry release | `c9d5c8a0f8db4584ff4f4e4373905e76a2efc5ea` (git commit) |
| Sentry public key | `bda3fe9fdce7f95166bfc88f22ec5a0f` |
| Sentry trace ID | Per-request (correlatable) |

## Impact

1. **Deployment fingerprinting** — the static installation ID allows tracking when deployments change
2. **Git commit exposure** — the Sentry release is a full SHA, revealing exact deployed code version (can be used to find known vulnerabilities in that commit)
3. **Sentry DSN reconstruction** — with the public key and project info, an attacker could potentially send fake error reports to pollute monitoring
4. **Session correlation** — trace IDs enable linking requests across the application

## Remediation

1. Remove `X-Installation-ID` from public responses (only use internally)
2. Disable Sentry browser tracing meta tags in production, or strip sensitive fields:
   ```javascript
   // sentry.config.js
   Sentry.init({
     sendDefaultPii: false,
     // Don't expose release/trace in meta tags
   });
   ```

## Research Header

All requests were made with: `X-HackerOne-Research: bananahacker6969`

## References

- CWE-200: Exposure of Sensitive Information
- CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere
