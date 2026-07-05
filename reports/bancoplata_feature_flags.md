# HackerOne Report: 50+ Internal Feature Flags Exposed in Client-Side JavaScript

## Summary

The Banco Plata website exposes over 50 internal feature flags in the client-side JavaScript bundle. These flags reveal internal development state, unreleased features, A/B test configurations, and internal URLs that should not be visible to end users.

## Severity

Low — Information Disclosure

## Affected Asset

`https://bancoplata.mx/es/creditlimit`

## Description

The `FeatureFlagsProvider` component renders all feature flags directly into the client-side HTML. This includes flags that reveal internal testing state, unreleased features, and infrastructure details.

## Steps to Reproduce

1. Navigate to `https://bancoplata.mx/es/creditlimit`
2. View page source
3. Search for `FeatureFlagsProvider` or `"flags"`
4. Observe 50+ feature flags exposed

Using curl:

```bash
curl -s https://bancoplata.mx/es/creditlimit | grep -oP '"flags":\{[^}]+' | python3 -m json.tool
```

## Sensitive Flags Disclosed

| Flag | Value | Risk |
|------|-------|------|
| `unauth_web_standalone_orig` | `"standalone"` | Reveals origination architecture |
| `pyme_empresa_webview_url` | `https://bancoplata.mx/es/empresa/pyme` | Internal URL routing |
| `unauth_web_aa_split_test` | `"test_new"` | Active A/B test (manipulable) |
| `unauth_landing_baf` | `"test"` | Test variant exposed |
| `unauth_tech_installationId_not_httpOnly` | `true` | Reveals cookie is not httpOnly (stealable via XSS) |
| `unauth_tech_form_tel_from_query` | `true` | Phone number accepted from URL query (potential phishing) |
| `unauth_tech_web_orig_data_bridge` | `true` | Data bridge enabled |
| `origination_postal_delivery` | `true` | Unreleased feature visible |
| `payments_cashin_store` | `true` | Payment feature state |

## Impact

1. **A/B test manipulation** — attacker can identify which test variant they're in and potentially force a specific variant
2. **Cookie security insight** — `installationId_not_httpOnly: true` confirms a cookie is accessible via JavaScript (XSS impact amplified)
3. **Phone injection vector** — `form_tel_from_query: true` means phone numbers are read from URL parameters (phishing vector: `?tel=attacker_number`)
4. **Feature enumeration** — reveals upcoming features before launch, giving attackers time to find bugs in unreleased code
5. **Architecture knowledge** — naming conventions reveal internal team structure and technical decisions

## Remediation

1. Only send feature flags relevant to the current user's rendering needs
2. Strip internal/debug flags before sending to client
3. Use a server-side feature flag evaluation that only sends boolean results, not flag names/metadata

## Research Header

All requests were made with: `X-HackerOne-Research: bananahacker6969`

## References

- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- CWE-1295: Debug Messages Revealing Unnecessary Information
