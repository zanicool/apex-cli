package scanner

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"regexp"
	"strings"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// AuthIntel handles session intelligence - auto-registration, token extraction, auth diffing
type AuthIntel struct {
	http     *engine.HTTPClient
	sessions map[string]*engine.Session // role -> session
}

func NewAuthIntel(h *engine.HTTPClient) *AuthIntel {
	return &AuthIntel{http: h, sessions: make(map[string]*engine.Session)}
}

// scanAuthenticated performs authenticated scanning with auto-generated accounts
func scanAuthenticated(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := extractBaseURL(crawl.Pages[0].URL)

	// Phase 1: Generate 2 accounts
	ag := NewAccountGenerator(h)
	accounts := ag.Generate(baseURL, crawl)

	if len(accounts) == 0 {
		// Fallback: extract tokens from JS
		ai := NewAuthIntel(h)
		jsTokens := ai.extractTokensFromJS(crawl)
		if len(jsTokens) > 0 {
			findings = append(findings, Finding{
				Type: "Exposed Auth Token in JS", Severity: "high",
				URL: jsTokens[0].source, Detail: fmt.Sprintf("Token type: %s", jsTokens[0].tokenType),
				Evidence: truncate(jsTokens[0].value, 20) + "...", Template: "apex-js-token",
			})
		}
		return findings
	}

	findings = append(findings, Finding{
		Type: "Auto-Registration Successful", Severity: "info",
		URL: baseURL, Detail: fmt.Sprintf("Created %d test accounts for authenticated scanning", len(accounts)),
		Template: "apex-auto-register",
	})

	// Phase 2: Find authenticated endpoints
	authPaths := []string{"/api/me", "/api/user", "/api/profile", "/api/account", "/api/settings",
		"/api/users", "/api/dashboard", "/api/orders", "/api/payments", "/api/notifications",
		"/api/v1/user", "/api/v1/me", "/api/v1/account", "/user/profile", "/account"}

	var authEndpoints []string
	session := accounts[0].Session
	for _, path := range authPaths {
		url := baseURL + path
		req, _ := http.NewRequest("GET", url, nil)
		session.ApplySession(req)
		resp := h.Do(req)
		if resp.Err == nil && resp.StatusCode == 200 && resp.Size > 50 {
			authEndpoints = append(authEndpoints, url)
		}
	}

	// Phase 3: Test IDOR between accounts
	if len(accounts) >= 2 {
		idorFindings := ag.TestIDOR(h, authEndpoints)
		findings = append(findings, idorFindings...)
	}

	// Phase 4: Auth vs Unauth differential
	for _, endpoint := range authEndpoints {
		unauthResp := h.Get(endpoint)
		if unauthResp.Err == nil && unauthResp.StatusCode == 200 && unauthResp.Size > 50 {
			findings = append(findings, Finding{
				Type: "Broken Access Control — No Auth Required", Severity: "high",
				URL: endpoint, Detail: "Authenticated endpoint accessible without any credentials",
				Template: "apex-bac-noauth",
			})
		}
	}

	return findings
}

func (ai *AuthIntel) findAuthEndpoints(baseURL string, crawl *crawler.Result) (string, string) {
	regPaths := []string{"/register", "/signup", "/api/register", "/api/v1/register", "/api/auth/register", "/create-account"}
	loginPaths := []string{"/login", "/signin", "/api/login", "/api/v1/login", "/api/auth/login"}

	var regURL, loginURL string

	// Check crawled forms first
	for _, form := range crawl.Forms {
		lower := strings.ToLower(form.Action)
		for _, p := range regPaths {
			if strings.Contains(lower, p) {
				regURL = form.Action
			}
		}
		for _, p := range loginPaths {
			if strings.Contains(lower, p) {
				loginURL = form.Action
			}
		}
	}

	// Probe common paths
	if regURL == "" {
		for _, p := range regPaths {
			resp := ai.http.Get(baseURL + p)
			if resp.Err == nil && resp.StatusCode < 404 {
				regURL = baseURL + p
				break
			}
		}
	}
	if loginURL == "" {
		for _, p := range loginPaths {
			resp := ai.http.Get(baseURL + p)
			if resp.Err == nil && resp.StatusCode < 404 {
				loginURL = baseURL + p
				break
			}
		}
	}
	return regURL, loginURL
}

func (ai *AuthIntel) tryRegister(regURL string) *engine.Session {
	email := fmt.Sprintf("apex_test_%d@protonmail.com", rand.Intn(99999))
	pass := "ApexTest!2024#Secure"

	payloads := []string{
		fmt.Sprintf(`{"email":"%s","password":"%s"}`, email, pass),
		fmt.Sprintf(`{"username":"%s","email":"%s","password":"%s","password_confirmation":"%s"}`, "apextest"+fmt.Sprint(rand.Intn(9999)), email, pass, pass),
	}

	for _, body := range payloads {
		resp := ai.http.Post(regURL, "application/json", body)
		if resp.Err != nil || resp.StatusCode >= 400 {
			continue
		}
		// Extract session from response
		session := &engine.Session{Cookies: make(map[string]string), Headers: make(map[string]string)}

		// Check for token in response body
		var respData map[string]interface{}
		if json.Unmarshal([]byte(resp.Body), &respData) == nil {
			for _, key := range []string{"token", "access_token", "jwt", "session_token", "auth_token"} {
				if tok, ok := respData[key].(string); ok {
					session.Token = tok
					return session
				}
			}
		}

		// Check Set-Cookie headers
		for _, cookie := range resp.Headers.Values("Set-Cookie") {
			parts := strings.SplitN(cookie, "=", 2)
			if len(parts) == 2 {
				name := parts[0]
				value := strings.SplitN(parts[1], ";", 2)[0]
				session.Cookies[name] = value
			}
		}
		if len(session.Cookies) > 0 {
			return session
		}
	}
	return nil
}

type jsToken struct {
	value     string
	tokenType string
	source    string
}

func (ai *AuthIntel) extractTokensFromJS(crawl *crawler.Result) []jsToken {
	var tokens []jsToken
	patterns := []struct {
		re       *regexp.Regexp
		tokType  string
	}{
		{regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|token|secret)['":\s]*[=:]\s*['"]([a-zA-Z0-9_\-]{20,})['"']`), "API Key"},
		{regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`), "JWT"},
		{regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})`), "Bearer Token"},
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key"},
		{regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), "Stripe Secret"},
	}

	for _, page := range crawl.Pages {
		if !strings.Contains(page.URL, ".js") {
			continue
		}
		resp := ai.http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		for _, p := range patterns {
			if matches := p.re.FindStringSubmatch(resp.Body); len(matches) > 0 {
				val := matches[0]
				if len(matches) > 1 {
					val = matches[1]
				}
				tokens = append(tokens, jsToken{value: val, tokenType: p.tokType, source: page.URL})
			}
		}
	}
	return tokens
}

// diffAuthUnauth compares authenticated vs unauthenticated responses to find access control bugs
func (ai *AuthIntel) diffAuthUnauth(h *engine.HTTPClient, crawl *crawler.Result) []Finding {
	var findings []Finding
	session := ai.sessions["user"]
	if session == nil {
		return findings
	}

	// Find endpoints that return different data when authenticated
	sensitivePatterns := []string{"/api/", "/user", "/account", "/admin", "/dashboard", "/profile", "/settings"}

	for _, page := range crawl.Pages {
		isSensitive := false
		for _, p := range sensitivePatterns {
			if strings.Contains(page.URL, p) {
				isSensitive = true
				break
			}
		}
		if !isSensitive {
			continue
		}

		// Get unauth response
		unauthResp := h.Get(page.URL)
		if unauthResp.Err != nil {
			continue
		}

		// Get auth response
		req, _ := http.NewRequest("GET", page.URL, nil)
		session.ApplySession(req)
		authResp := h.Do(req)
		if authResp.Err != nil {
			continue
		}

		// If unauth gets same data as auth = broken access control
		if unauthResp.StatusCode == 200 && authResp.StatusCode == 200 {
			if authResp.Size > unauthResp.Size+100 {
				// Auth returns more data - this is expected
				continue
			}
			if unauthResp.Size > 100 && authResp.Size > 100 {
				// Both return substantial data - check if unauth has sensitive info
				sensitiveFields := []string{"email", "phone", "address", "ssn", "password", "credit_card", "token"}
				for _, field := range sensitiveFields {
					if strings.Contains(unauthResp.Body, field) && strings.Contains(authResp.Body, field) {
						findings = append(findings, Finding{
							Type: "Broken Access Control", Severity: "high",
							URL: page.URL, Detail: fmt.Sprintf("Sensitive field '%s' accessible without auth", field),
							Template: "apex-bac",
						})
						break
					}
				}
			}
		}

		// If auth-required endpoint returns 200 without auth = BAC
		if unauthResp.StatusCode == 200 && strings.Contains(page.URL, "/admin") {
			findings = append(findings, Finding{
				Type: "Broken Access Control — Admin Panel", Severity: "critical",
				URL: page.URL, Detail: "Admin endpoint accessible without authentication",
				Template: "apex-admin-bac",
			})
		}
	}
	return findings
}

func extractBaseURL(pageURL string) string {
	parts := strings.SplitN(pageURL, "//", 2)
	if len(parts) < 2 {
		return pageURL
	}
	hostEnd := strings.Index(parts[1], "/")
	if hostEnd < 0 {
		return pageURL
	}
	return parts[0] + "//" + parts[1][:hostEnd]
}
