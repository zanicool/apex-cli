# Bounty Hunt Report: bancoplata_scope

**Date:** 2026-07-05 18:14
**Duration:** 1159s
**Targets discovered:** 580
**Targets live:** 25
**Targets scanned:** 25

## Summary

| Severity | Count |
|----------|-------|
| Critical | 5 |
| High | 3 |
| Medium | 231 |
| **Total** | **402** |

## Findings (ranked by bounty potential)

### 1. [CRITICAL] SSTI
- **URL:** https://pay-beta.bancoplata.mx
- **Detail:** Server-Side Template Injection
- **Evidence:** 49

### 2. [CRITICAL] EL Injection
- **URL:** https://3ds.bancoplata.mx
- **Detail:** Differential canary confirmed: java.lang.Runtime AND java.lang.Math
- **Evidence:** java.lang.Runtime

### 3. [CRITICAL] EL Injection
- **URL:** https://pay.bancoplata.mx
- **Detail:** Differential canary confirmed: 49 AND 64
- **Evidence:** 49

### 4. [CRITICAL] SSRF
- **URL:** https://history.bancoplata.mx
- **Detail:** SSRF to cloud metadata
- **Evidence:** <!doctype html>
<!-- Made in Framer · framer.com ✨ -->
<!-- Published May 28, 2026, 3:54 PM UTC -->
<html dir="ltr">
<head>
	<meta charset="utf-8

### 5. [CRITICAL] Auto-Escalate
- **URL:** https://history.bancoplata.mx
- **Detail:** SSRF to internal service: http://127.0.0.1:8080/
- **Evidence:** <!doctype html>
<!-- Made in Framer · framer.com ✨ -->
<!-- Published May 28, 2026, 3:54 PM UTC

### 6. [HIGH] Mutation Fuzzer Hit
- **URL:** https://3ds.bancoplata.mx?id={{7*7}}
- **Detail:** Payload '{{7*7}}' triggered detection
- **Evidence:** 49

### 7. [HIGH] gRPC Reflection Exposed
- **URL:** https://3ds.bancoplata.mx/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo
- **Detail:** gRPC reflection service accessible — all service/method names leaked
- **Evidence:** grpc-status: 7

### 8. [HIGH] Backup/Source Exposed: /backup.zip
- **URL:** https://auth.bancoplata.mx/backup.zip
- **Detail:** zip file publicly accessible
- **Evidence:** 568 bytes

### 9. [MEDIUM] Clickjacking
- **URL:** https://pay-beta.bancoplata.mx
- **Detail:** Missing frame protection

### 10. [MEDIUM] Timing Oracle
- **URL:** https://pay-beta.bancoplata.mx/login
- **Detail:** Username enumeration via timing (132ms diff)

### 11. [MEDIUM] Missing HSTS
- **URL:** pay-beta.bancoplata.mx
- **Detail:** Strict-Transport-Security header not set

### 12. [MEDIUM] Missing SPF Record
- **URL:** pay-beta.bancoplata.mx
- **Detail:** No SPF record — email spoofing possible

### 13. [MEDIUM] Missing DMARC Record
- **URL:** pay-beta.bancoplata.mx
- **Detail:** No DMARC record — no email authentication policy

### 14. [MEDIUM] M365 User Enumeration
- **URL:** pay-beta.bancoplata.mx
- **Detail:** Microsoft login reveals whether accounts exist — aids password spraying

### 15. [MEDIUM] OTAP Environment: beta.bancoplata.mx
- **URL:** https://beta.bancoplata.mx
- **Detail:** OTAP environment 'beta' is live — missing security headers

### 16. [MEDIUM] Shadow Deployment: Vercel
- **URL:** https://pay-beta.vercel.app
- **Detail:** Vercel deployment found — possibly unmanaged/forgotten

### 17. [MEDIUM] gRPC Reflection
- **URL:** https://pay-beta.bancoplata.mx
- **Detail:** gRPC server reflection may be enabled

### 18. [MEDIUM] No Rate Limiting on Login
- **URL:** https://pay-beta.bancoplata.mx/api/login
- **Detail:** 15 failed login attempts without rate limiting
- **Evidence:** No 429 response after 15 attempts

### 19. [MEDIUM] Race Condition Target — Coupon/code redemption
- **URL:** https://pay-beta.bancoplata.mx/api/redeem
- **Detail:** Endpoint likely performs state-changing operation: Coupon/code redemption. Risk: Double redemption v
- **Evidence:** Status: 403

### 20. [MEDIUM] Race Condition Target — Coupon application
- **URL:** https://pay-beta.bancoplata.mx/api/coupon/apply
- **Detail:** Endpoint likely performs state-changing operation: Coupon application. Risk: Apply same coupon multi
- **Evidence:** Status: 403

### 21. [MEDIUM] Race Condition Target — Promo code
- **URL:** https://pay-beta.bancoplata.mx/api/promo/apply
- **Detail:** Endpoint likely performs state-changing operation: Promo code. Risk: Stack promotions via race. Test
- **Evidence:** Status: 403

### 22. [MEDIUM] Race Condition Target — Money transfer
- **URL:** https://pay-beta.bancoplata.mx/api/transfer
- **Detail:** Endpoint likely performs state-changing operation: Money transfer. Risk: Double-spend via concurrent
- **Evidence:** Status: 403

### 23. [MEDIUM] Race Condition Target — Withdrawal
- **URL:** https://pay-beta.bancoplata.mx/api/withdraw
- **Detail:** Endpoint likely performs state-changing operation: Withdrawal. Risk: Withdraw more than balance. Tes
- **Evidence:** Status: 403

### 24. [MEDIUM] Race Condition Target — Voting
- **URL:** https://pay-beta.bancoplata.mx/api/vote
- **Detail:** Endpoint likely performs state-changing operation: Voting. Risk: Multiple votes via race. Test by se
- **Evidence:** Status: 403

### 25. [MEDIUM] Race Condition Target — Like/upvote
- **URL:** https://pay-beta.bancoplata.mx/api/like
- **Detail:** Endpoint likely performs state-changing operation: Like/upvote. Risk: Infinite likes via concurrent 
- **Evidence:** Status: 403

### 26. [MEDIUM] Race Condition Target — Follow action
- **URL:** https://pay-beta.bancoplata.mx/api/follow
- **Detail:** Endpoint likely performs state-changing operation: Follow action. Risk: Duplicate follow for rewards
- **Evidence:** Status: 403

### 27. [MEDIUM] Race Condition Target — Referral
- **URL:** https://pay-beta.bancoplata.mx/api/referral
- **Detail:** Endpoint likely performs state-changing operation: Referral. Risk: Self-referral or double referral 
- **Evidence:** Status: 403

### 28. [MEDIUM] Race Condition Target — Claim reward
- **URL:** https://pay-beta.bancoplata.mx/api/claim
- **Detail:** Endpoint likely performs state-changing operation: Claim reward. Risk: Claim same reward multiple ti
- **Evidence:** Status: 403

### 29. [MEDIUM] Race Condition Target — Checkout
- **URL:** https://pay-beta.bancoplata.mx/api/checkout
- **Detail:** Endpoint likely performs state-changing operation: Checkout. Risk: Double-purchase at discounted rat
- **Evidence:** Status: 403

### 30. [MEDIUM] Race Condition Target — Order placement
- **URL:** https://pay-beta.bancoplata.mx/api/order
- **Detail:** Endpoint likely performs state-changing operation: Order placement. Risk: Duplicate order exploit. T
- **Evidence:** Status: 403

### 31. [MEDIUM] Race Condition Target — Registration
- **URL:** https://pay-beta.bancoplata.mx/api/register
- **Detail:** Endpoint likely performs state-changing operation: Registration. Risk: Duplicate account creation. T
- **Evidence:** Status: 403

### 32. [MEDIUM] Race Condition Target — Free trial
- **URL:** https://pay-beta.bancoplata.mx/api/trial
- **Detail:** Endpoint likely performs state-changing operation: Free trial. Risk: Multiple free trials. Test by s
- **Evidence:** Status: 403

### 33. [MEDIUM] Race Condition Target — Invite acceptance
- **URL:** https://pay-beta.bancoplata.mx/api/invite/accept
- **Detail:** Endpoint likely performs state-changing operation: Invite acceptance. Risk: Accept same invite multi
- **Evidence:** Status: 403

### 34. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta' does not exist. If your DNS or app references this bucket, attacker can create 

### 35. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-assets.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-assets' does not exist. If your DNS or app references this bucket, attacker can 

### 36. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-backup.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-backup' does not exist. If your DNS or app references this bucket, attacker can 

### 37. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-dev.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-dev' does not exist. If your DNS or app references this bucket, attacker can cre

### 38. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-staging.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-staging' does not exist. If your DNS or app references this bucket, attacker can

### 39. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-prod.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-prod' does not exist. If your DNS or app references this bucket, attacker can cr

### 40. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-uploads.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-uploads' does not exist. If your DNS or app references this bucket, attacker can

### 41. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-media.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-media' does not exist. If your DNS or app references this bucket, attacker can c

### 42. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-static.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-static' does not exist. If your DNS or app references this bucket, attacker can 

### 43. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-data.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-data' does not exist. If your DNS or app references this bucket, attacker can cr

### 44. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-logs.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-logs' does not exist. If your DNS or app references this bucket, attacker can cr

### 45. [MEDIUM] S3 Bucket — Takeover Possible (unverified)
- **URL:** https://pay-beta-config.s3.amazonaws.com/
- **Detail:** S3 bucket 'pay-beta-config' does not exist. If your DNS or app references this bucket, attacker can 

### 46. [MEDIUM] Missing Content-Security-Policy
- **URL:** https://pay-beta.bancoplata.mx
- **Detail:** No CSP — XSS exploitation easier

### 47. [MEDIUM] 2FA — No Rate Limiting (unverified)
- **URL:** https://pay-beta.bancoplata.mx/api/auth/2fa/verify
- **Detail:** 2FA verification has no rate limiting. 6-digit code can be brute-forced in <1000 requests (10 per se

### 48. [MEDIUM] Image upload → ImageTragick (CVE-2016-3714)
- **URL:** https://pay-beta.bancoplata.mx/api/upload
- **Detail:** Upload endpoint found — test for unrestricted file types
- **Evidence:** Status: 403

### 49. [MEDIUM] No CSP Header
- **URL:** https://pay-beta.bancoplata.mx
- **Detail:** No Content-Security-Policy header — XSS not mitigated

### 50. [MEDIUM] Clickjacking (Deep)
- **URL:** https://pay-beta.bancoplata.mx
- **Detail:** No X-Frame-Options or frame-ancestors — page with forms can be framed
- **Evidence:** Page contains interactive elements

