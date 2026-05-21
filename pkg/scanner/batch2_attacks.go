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

// --- Hidden Parameter Discovery (Arjun-style) ---

func scanHiddenParams(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	commonParams := []string{"debug", "test", "admin", "internal", "verbose", "dev", "staging", "api_key", "token", "secret", "callback", "redirect", "next", "return_to", "id", "user_id", "role", "format", "type", "action", "method", "view", "template", "include", "file", "path", "lang", "page", "limit", "offset", "sort", "order", "filter", "search", "q", "query", "v", "version"}

	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		baseResp := h.Get(page.URL)
		if baseResp.Err != nil || baseResp.StatusCode != 200 {
			continue
		}
		sep := "?"
		if strings.Contains(page.URL, "?") {
			sep = "&"
		}
		for _, param := range commonParams {
			testURL := page.URL + sep + param + "=apex_test_value"
			resp := h.Get(testURL)
			if resp.Err != nil {
				continue
			}
			// Significant size difference = param is processed
			if resp.StatusCode == 200 && abs(resp.Size-baseResp.Size) > 100 {
				findings = append(findings, Finding{
					Type: "Hidden Parameter Discovered", Severity: "low",
					URL: testURL, Param: param,
					Detail: fmt.Sprintf("Parameter '%s' changes response (size diff: %d bytes)", param, resp.Size-baseResp.Size),
					Template: "apex-hidden-param",
				})
			}
			// Debug/admin param returns different status
			if resp.StatusCode != baseResp.StatusCode && resp.StatusCode == 200 {
				findings = append(findings, Finding{
					Type: "Hidden Parameter — Access Change", Severity: "high",
					URL: testURL, Param: param,
					Detail: fmt.Sprintf("Parameter '%s' changes status from %d to %d", param, baseResp.StatusCode, resp.StatusCode),
					Template: "apex-hidden-param-access",
				})
			}
		}
		break
	}
	return findings
}

// --- Virtual Host Discovery ---

func scanVHostDiscovery(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	target := extractBaseURL(crawl.Pages[0].URL)
	domain := extractDomain(target)
	parts := strings.Split(domain, ".")
	baseDomain := domain
	if len(parts) > 2 {
		baseDomain = strings.Join(parts[len(parts)-2:], ".")
	}

	vhosts := []string{"admin", "api", "dev", "staging", "test", "internal", "portal", "dashboard", "app", "mail", "vpn", "git", "jenkins", "grafana", "monitor", "status", "docs", "beta", "alpha", "demo"}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, vhost := range vhosts {
		wg.Add(1)
		go func(vh string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			hostname := vh + "." + baseDomain
			req, _ := http.NewRequest("GET", target, nil)
			req.Host = hostname
			resp := h.Do(req)
			if resp.Err != nil || engine.IsWAFChallenge(resp) {
				return
			}
			if resp.StatusCode == 200 && resp.Size > 100 {
				// Compare with default response
				defaultResp := h.Get(target)
				if defaultResp.Err == nil && resp.Body != defaultResp.Body {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "Virtual Host Discovered", Severity: "medium",
						URL: target, Payload: hostname,
						Detail: fmt.Sprintf("Host header '%s' returns different content (%d bytes)", hostname, resp.Size),
						Template: "apex-vhost",
					})
					mu.Unlock()
				}
			}
		}(vhost)
	}
	wg.Wait()
	return findings
}

// --- User Enumeration via Timing ---

func scanUserEnumTiming(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := extractBaseURL(crawl.Pages[0].URL)
	loginPaths := []string{"/login", "/api/login", "/api/auth/login", "/signin"}

	for _, path := range loginPaths {
		loginURL := base + path
		// Time request with likely-existing user
		start1 := time.Now()
		h.Post(loginURL, "application/json", `{"email":"admin@`+extractDomain(base)+`","password":"wrong"}`)
		time1 := time.Since(start1)

		// Time request with non-existing user
		start2 := time.Now()
		h.Post(loginURL, "application/json", `{"email":"definitelynotexist999xyz@`+extractDomain(base)+`","password":"wrong"}`)
		time2 := time.Since(start2)

		// Significant timing difference = user enumeration
		diff := time1 - time2
		if diff < 0 {
			diff = -diff
		}
		if diff > 200*time.Millisecond {
			findings = append(findings, Finding{
				Type: "User Enumeration via Timing", Severity: "medium",
				URL: loginURL, Detail: fmt.Sprintf("Existing user: %dms, Non-existing: %dms (diff: %dms)", time1.Milliseconds(), time2.Milliseconds(), diff.Milliseconds()),
				Template: "apex-user-enum-timing",
			})
			break
		}
	}
	return findings
}

// --- Internal IP Disclosure ---

func scanInternalIPDisclosure(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	internalIPs := []string{"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127.0."}

	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		resp := h.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		// Check headers
		for _, hdr := range []string{"X-Real-IP", "X-Forwarded-For", "X-Backend-Server", "X-Host", "Via"} {
			val := resp.Headers.Get(hdr)
			for _, prefix := range internalIPs {
				if strings.Contains(val, prefix) {
					findings = append(findings, Finding{
						Type: "Internal IP Disclosure", Severity: "low",
						URL: page.URL, Detail: fmt.Sprintf("Header '%s' leaks internal IP: %s", hdr, val),
						Template: "apex-internal-ip",
					})
				}
			}
		}
		// Check body for internal IPs
		for _, prefix := range internalIPs[:3] { // Only check 10.x, 172.16.x, 192.168.x
			if strings.Contains(resp.Body, prefix) {
				findings = append(findings, Finding{
					Type: "Internal IP in Response Body", Severity: "low",
					URL: page.URL, Detail: fmt.Sprintf("Response contains internal IP starting with %s", prefix),
					Template: "apex-internal-ip-body",
				})
				break
			}
		}
	}
	return findings
}

// --- Insecure Deserialization Detection ---

func scanDeserializationAdvanced(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Check cookies for serialized objects
	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		resp := h.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		for _, cookie := range resp.Headers.Values("Set-Cookie") {
			val := strings.SplitN(cookie, "=", 2)
			if len(val) < 2 {
				continue
			}
			cookieVal := strings.SplitN(val[1], ";", 2)[0]
			// PHP serialized object
			if strings.HasPrefix(cookieVal, "a%3A") || strings.HasPrefix(cookieVal, "O%3A") || strings.Contains(cookieVal, "s:") {
				findings = append(findings, Finding{
					Type: "PHP Serialized Object in Cookie", Severity: "high",
					URL: page.URL, Param: val[0],
					Detail: "Cookie contains PHP serialized data — potential deserialization RCE",
					Template: "apex-php-deser",
				})
			}
			// Java serialized (base64 of rO0AB)
			if strings.HasPrefix(cookieVal, "rO0AB") || strings.Contains(cookieVal, "aced0005") {
				findings = append(findings, Finding{
					Type: "Java Serialized Object in Cookie", Severity: "critical",
					URL: page.URL, Param: val[0],
					Detail: "Cookie contains Java serialized data — RCE via gadget chains",
					Template: "apex-java-deser-cookie",
				})
			}
		}
	}
	return findings
}

// --- Robots.txt Secret Paths ---

func scanRobotsTxtSecrets(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := extractBaseURL(crawl.Pages[0].URL)
	resp := h.Get(base + "/robots.txt")
	if resp.Err != nil || resp.StatusCode != 200 {
		return findings
	}

	sensitiveKeywords := []string{"admin", "api", "internal", "secret", "private", "backup", "config", "debug", "staging", "test", "dashboard", "panel", "manage"}

	for _, line := range strings.Split(resp.Body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Disallow:") && !strings.HasPrefix(line, "Allow:") {
			continue
		}
		path := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		if path == "" || path == "/" {
			continue
		}
		for _, kw := range sensitiveKeywords {
			if strings.Contains(strings.ToLower(path), kw) {
				// Check if path is accessible
				pathResp := h.Get(base + path)
				if pathResp.Err == nil && pathResp.StatusCode == 200 && pathResp.Size > 100 && !engine.IsWAFChallenge(pathResp) {
					findings = append(findings, Finding{
						Type: "Sensitive Path in robots.txt", Severity: "medium",
						URL: base + path, Detail: fmt.Sprintf("Disallowed path '%s' is accessible (status 200, %d bytes)", path, pathResp.Size),
						Template: "apex-robots-secret",
					})
				}
				break
			}
		}
	}
	return findings
}

// --- Workflow/State Machine Bypass ---

func scanWorkflowBypassReal(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Look for multi-step flows and try to skip steps
	stepKeywords := []string{"step", "stage", "phase", "confirm", "verify", "complete", "finalize", "submit", "checkout"}

	for _, page := range crawl.Pages {
		urlLower := strings.ToLower(page.URL)
		for _, kw := range stepKeywords {
			if !strings.Contains(urlLower, kw) {
				continue
			}
			// Try to access "final" step directly
			parsed, _ := url.Parse(page.URL)
			if parsed == nil {
				continue
			}
			q := parsed.Query()
			// Try incrementing step number
			for _, stepParam := range []string{"step", "stage", "phase"} {
				if q.Get(stepParam) != "" {
					q.Set(stepParam, "99")
					parsed.RawQuery = q.Encode()
					resp := h.Get(parsed.String())
					if resp.Err == nil && resp.StatusCode == 200 && resp.Size > 200 && !engine.IsWAFChallenge(resp) {
						findings = append(findings, Finding{
							Type: "Workflow Step Bypass", Severity: "high",
							URL: parsed.String(), Param: stepParam,
							Detail: "Skipping to final step returns valid response — workflow bypass possible",
							Template: "apex-workflow-bypass",
						})
					}
				}
			}
			break
		}
	}
	return findings
}

// --- Client-Side Template Injection (AngularJS/Vue) ---

func scanClientSideTemplateInjection(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	payloads := []struct {
		payload string
		detect  string
		fw      string
	}{
		{"{{7*7}}", "49", "AngularJS/Vue"},
		{"${7*7}", "49", "Template Literal"},
		{"{{constructor.constructor('return 1')()}}", "1", "AngularJS sandbox bypass"},
	}

	for u, params := range crawl.Params {
		if !strings.Contains(u, "?") {
			continue
		}
		for _, p := range params[:min(3, len(params))] {
			for _, pl := range payloads {
				testURL := injectParam(u, p, pl.payload)
				resp := h.Get(testURL)
				if resp.Err != nil || engine.IsWAFChallenge(resp) {
					continue
				}
				// Check if template was evaluated (49 appears but not in baseline)
				if strings.Contains(resp.Body, pl.detect) {
					baseResp := h.Get(u)
					if baseResp.Err == nil && !strings.Contains(baseResp.Body, pl.detect) {
						findings = append(findings, Finding{
							Type: "Client-Side Template Injection (" + pl.fw + ")", Severity: "high",
							URL: testURL, Param: p, Payload: pl.payload,
							Detail: fmt.Sprintf("Template expression evaluated: %s → %s", pl.payload, pl.detect),
							Template: "apex-csti",
						})
						return findings
					}
				}
			}
		}
	}
	return findings
}

// --- Soft-404 Detection ---

func detectSoft404(h *engine.HTTPClient, baseURL string) string {
	// Request a definitely-not-existing page
	resp := h.Get(baseURL + "/apex_definitely_not_exist_" + fmt.Sprint(time.Now().UnixNano()))
	if resp.Err != nil {
		return ""
	}
	if resp.StatusCode == 200 {
		return resp.Body[:min(100, len(resp.Body))]
	}
	return ""
}

// IsSoft404 checks if a response is a soft-404 (custom error page returning 200)
func IsSoft404(resp *engine.Response, soft404Body string) bool {
	if soft404Body == "" || resp == nil {
		return false
	}
	if resp.StatusCode == 200 && len(resp.Body) > 0 {
		return strings.Contains(resp.Body[:min(100, len(resp.Body))], soft404Body[:min(50, len(soft404Body))])
	}
	return false
}
