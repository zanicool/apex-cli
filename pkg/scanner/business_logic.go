package scanner

import (
	"fmt"
	"strings"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// scanBusinessLogic detects and tests business logic vulnerabilities
func scanBusinessLogic(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := extractBaseURL(crawl.Pages[0].URL)

	findings = append(findings, testPasswordReset(h, baseURL)...)
	findings = append(findings, testSignupAbuse(h, baseURL)...)
	findings = append(findings, test2FABypass(h, baseURL, crawl)...)
	findings = append(findings, testCouponAbuse(h, baseURL, crawl)...)
	findings = append(findings, testRateLimitAbuse(h, baseURL, crawl)...)
	return findings
}

// testPasswordReset checks for host header poisoning in password reset
func testPasswordReset(h *engine.HTTPClient, baseURL string) []Finding {
	var findings []Finding
	resetPaths := []string{"/password/reset", "/forgot-password", "/api/password/reset", "/api/v1/auth/forgot", "/auth/forgot-password"}

	for _, path := range resetPaths {
		url := baseURL + path
		// Test host header injection
		items := []engine.RequestItem{
			{URL: url, Method: "POST", Body: `{"email":"test@test.com"}`, Headers: map[string]string{
				"Content-Type": "application/json",
				"Host":         "evil.com",
			}},
			{URL: url, Method: "POST", Body: `{"email":"test@test.com"}`, Headers: map[string]string{
				"Content-Type":    "application/json",
				"X-Forwarded-Host": "evil.com",
			}},
		}
		for resp := range h.BatchRequest(items, 2) {
			if resp.Err == nil && resp.StatusCode == 200 {
				findings = append(findings, Finding{
					Type: "Password Reset Poisoning", Severity: "high",
					URL: url, Detail: "Password reset accepts manipulated Host header — reset link sent to attacker domain",
					Template: "apex-reset-poison",
				})
				break
			}
		}
	}
	return findings
}

// testSignupAbuse checks for email enumeration and disposable email bypass
func testSignupAbuse(h *engine.HTTPClient, baseURL string) []Finding {
	var findings []Finding
	signupPaths := []string{"/register", "/signup", "/api/register", "/api/v1/register"}

	for _, path := range signupPaths {
		url := baseURL + path
		resp1 := h.Post(url, "application/json", `{"email":"definitely_exists_admin@`+extractDomain(baseURL)+`","password":"test123"}`)
		resp2 := h.Post(url, "application/json", `{"email":"definitely_not_exists_xyz123@`+extractDomain(baseURL)+`","password":"test123"}`)

		if resp1.Err != nil || resp2.Err != nil {
			continue
		}
		if engine.IsWAFChallenge(resp1) || engine.IsWAFChallenge(resp2) {
			continue
		}
		// Both must actually process the request
		if resp1.StatusCode == 404 || resp1.StatusCode == 403 || resp2.StatusCode == 404 || resp2.StatusCode == 403 {
			continue
		}
		// Require BOTH different status AND different size (>20 bytes diff) to confirm
		statusDiff := resp1.StatusCode != resp2.StatusCode
		sizeDiff := abs(resp1.Size-resp2.Size) > 20
		if statusDiff && sizeDiff {
			findings = append(findings, Finding{
				Type: "User Enumeration via Registration", Severity: "medium",
				URL: url, Detail: fmt.Sprintf("Existing: status %d (%d bytes) vs Non-existing: status %d (%d bytes)", resp1.StatusCode, resp1.Size, resp2.StatusCode, resp2.Size),
				Template: "apex-user-enum",
			})
			break
		}
	}
	return findings
}

// test2FABypass checks for common 2FA bypass techniques
func test2FABypass(h *engine.HTTPClient, baseURL string, crawl *crawler.Result) []Finding {
	var findings []Finding
	verifyPaths := []string{"/verify", "/2fa", "/mfa", "/otp", "/api/verify-otp", "/auth/2fa/verify"}

	for _, path := range verifyPaths {
		url := baseURL + path
		resp := h.Get(url)
		if resp.Err != nil || resp.StatusCode == 404 {
			continue
		}

		// Test: skip 2FA by directly accessing dashboard
		dashPaths := []string{"/dashboard", "/home", "/api/user/me", "/account"}
		for _, dp := range dashPaths {
			dResp := h.Get(baseURL + dp)
			if dResp.Err == nil && dResp.StatusCode == 200 && dResp.Size > 200 {
				findings = append(findings, Finding{
					Type: "2FA Bypass — Direct Navigation", Severity: "critical",
					URL: baseURL + dp, Detail: fmt.Sprintf("2FA at %s can be skipped by directly accessing %s", url, dp),
					Template: "apex-2fa-bypass",
				})
				break
			}
		}

		// Test: null/empty OTP
		for _, otp := range []string{`{"code":""}`, `{"code":"000000"}`, `{"code":null}`, `{"otp":"000000"}`} {
			otpResp := h.Post(url, "application/json", otp)
			if otpResp.Err == nil && otpResp.StatusCode == 200 && strings.Contains(otpResp.Body, "token") {
				findings = append(findings, Finding{
					Type: "2FA Bypass — Null/Default OTP", Severity: "critical",
					URL: url, Payload: otp, Detail: "2FA accepts empty or default OTP code",
					Template: "apex-2fa-null",
				})
				break
			}
		}
		break
	}
	return findings
}

// testCouponAbuse checks for coupon/discount stacking and manipulation
func testCouponAbuse(h *engine.HTTPClient, baseURL string, crawl *crawler.Result) []Finding {
	var findings []Finding
	couponPaths := []string{"/api/coupon", "/api/discount", "/api/promo", "/cart/coupon", "/api/v1/coupon/apply"}

	for _, path := range couponPaths {
		url := baseURL + path
		resp := h.Get(url)
		if resp.Err != nil || resp.StatusCode == 404 {
			continue
		}

		// Test: apply same coupon multiple times
		couponBody := `{"code":"TEST10"}`
		r1 := h.Post(url, "application/json", couponBody)
		r2 := h.Post(url, "application/json", couponBody)
		if r1.Err == nil && r2.Err == nil && r1.StatusCode == 200 && r2.StatusCode == 200 {
			findings = append(findings, Finding{
				Type: "Coupon Stacking", Severity: "medium",
				URL: url, Detail: "Same coupon code can be applied multiple times",
				Template: "apex-coupon-stack",
			})
		}

		// Test: negative quantity/price manipulation
		pricePayloads := []string{
			`{"quantity":-1}`,
			`{"price":0}`,
			`{"amount":-100}`,
			`{"discount":101}`,
		}
		for _, pp := range pricePayloads {
			pResp := h.Post(url, "application/json", pp)
			if pResp.Err == nil && pResp.StatusCode == 200 {
				findings = append(findings, Finding{
					Type: "Price/Quantity Manipulation", Severity: "high",
					URL: url, Payload: pp, Detail: "Server accepts negative/zero values for price/quantity",
					Template: "apex-price-manip",
				})
				break
			}
		}
		break
	}
	return findings
}

// testRateLimitAbuse checks if critical endpoints lack rate limiting
func testRateLimitAbuse(h *engine.HTTPClient, baseURL string, crawl *crawler.Result) []Finding {
	var findings []Finding
	criticalPaths := []string{"/login", "/api/login", "/api/auth/login", "/forgot-password", "/api/password/reset"}

	for _, path := range criticalPaths {
		url := baseURL + path
		resp := h.Post(url, "application/json", `{"email":"test@test.com","password":"wrong"}`)
		if resp.Err != nil || resp.StatusCode == 404 || resp.StatusCode == 403 || resp.StatusCode == 405 {
			continue
		}
		if engine.IsWAFChallenge(resp) {
			continue
		}
		// Endpoint must actually process the request (return 401/200/422, not WAF block)
		if resp.StatusCode != 401 && resp.StatusCode != 200 && resp.StatusCode != 422 && resp.StatusCode != 400 {
			continue
		}

		// Send 15 rapid requests
		blocked := false
		for i := 0; i < 15; i++ {
			r := h.Post(url, "application/json", `{"email":"test@test.com","password":"wrong"}`)
			if r.Err == nil && (r.StatusCode == 429 || (r.StatusCode == 403 && i > 5)) {
				blocked = true
				break
			}
		}
		if !blocked {
			findings = append(findings, Finding{
				Type: "Missing Rate Limit on Auth Endpoint", Severity: "medium",
				URL: url, Detail: "No rate limiting after 15+ failed attempts — brute force possible",
				Template: "apex-no-ratelimit",
			})
		}
		break
	}
	return findings
}

func extractDomain(baseURL string) string {
	parts := strings.SplitN(baseURL, "//", 2)
	if len(parts) < 2 {
		return baseURL
	}
	host := strings.SplitN(parts[1], "/", 2)[0]
	return strings.SplitN(host, ":", 2)[0]
}
