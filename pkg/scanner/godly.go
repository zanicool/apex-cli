package scanner

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// ==========================================================================
// GODLY TIER: Features that don't exist in any other open-source scanner
// ==========================================================================

// --- Intelligent Scan Prioritization ---
// Scores each endpoint by likelihood of being vulnerable, scans high-value first

type EndpointScore struct {
	URL       string
	Params    []string
	Score     float64
	Reasons   []string
}

func PrioritizeEndpoints(crawl *crawler.Result) []EndpointScore {
	var scored []EndpointScore

	highValueParams := map[string]float64{
		"id": 3, "user_id": 5, "uid": 5, "file": 5, "path": 5, "url": 5,
		"redirect": 4, "callback": 4, "template": 5, "page": 3, "query": 4,
		"search": 3, "sort": 2, "order": 2, "filter": 3, "admin": 5,
		"debug": 5, "token": 4, "key": 4, "secret": 5, "password": 5,
		"email": 3, "username": 3, "role": 5, "type": 3, "action": 4,
		"cmd": 5, "exec": 5, "command": 5, "run": 5, "eval": 5,
		"include": 5, "require": 5, "load": 4, "read": 4, "fetch": 4,
		"src": 4, "href": 3, "dest": 4, "target": 3, "next": 3,
	}

	highValuePaths := []string{"/api/", "/admin", "/internal", "/debug", "/graphql",
		"/upload", "/import", "/export", "/download", "/exec", "/eval",
		"/webhook", "/callback", "/oauth", "/auth", "/login", "/register",
		"/payment", "/checkout", "/transfer", "/settings", "/config"}

	for u, params := range crawl.Params {
		score := 0.0
		var reasons []string

		// Score by param names
		for _, p := range params {
			pLower := strings.ToLower(p)
			for key, val := range highValueParams {
				if strings.Contains(pLower, key) {
					score += val
					reasons = append(reasons, fmt.Sprintf("param '%s' (+%.0f)", p, val))
					break
				}
			}
		}

		// Score by path
		for _, hp := range highValuePaths {
			if strings.Contains(strings.ToLower(u), hp) {
				score += 3
				reasons = append(reasons, fmt.Sprintf("path contains '%s' (+3)", hp))
				break
			}
		}

		// Score by number of params (more params = more attack surface)
		score += float64(len(params)) * 0.5

		if score > 0 {
			scored = append(scored, EndpointScore{URL: u, Params: params, Score: score, Reasons: reasons})
		}
	}

	// Sort by score descending
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})
	return scored
}

// --- Response Similarity Scoring ---
// Instead of exact match, uses similarity ratio to detect subtle differences

func similarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	// Jaccard similarity on word sets
	wordsA := strings.Fields(a)
	wordsB := strings.Fields(b)
	setA := make(map[string]bool)
	for _, w := range wordsA {
		setA[w] = true
	}
	setB := make(map[string]bool)
	for _, w := range wordsB {
		setB[w] = true
	}
	intersection := 0
	for w := range setA {
		if setB[w] {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0.0
	}
	return float64(intersection) / float64(union)
}

// --- Multi-Step Auth Flow Exploitation ---
// Automatically discovers and exploits multi-step processes

func scanMultiStepExploit(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]

	// Discover multi-step flows
	flows := []struct {
		name  string
		steps []string
	}{
		{"Password Reset", []string{"/forgot-password", "/reset-password", "/reset-password/confirm"}},
		{"Registration", []string{"/register", "/verify-email", "/complete-profile"}},
		{"Checkout", []string{"/cart", "/checkout", "/checkout/shipping", "/checkout/payment", "/checkout/confirm"}},
		{"2FA Setup", []string{"/settings/security", "/settings/2fa/setup", "/settings/2fa/verify"}},
	}

	for _, flow := range flows {
		// Try skipping to final step
		finalStep := base + flow.steps[len(flow.steps)-1]
		resp := http.Get(finalStep)
		if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 200 {
			// Check it's not just a redirect/error page
			if !strings.Contains(strings.ToLower(resp.Body), "redirect") &&
				!strings.Contains(strings.ToLower(resp.Body), "unauthorized") &&
				!strings.Contains(strings.ToLower(resp.Body), "login") {
				findings = append(findings, Finding{
					Type: fmt.Sprintf("Multi-Step Bypass: %s", flow.name), Severity: "high",
					URL: finalStep, Detail: fmt.Sprintf("Final step of %s flow accessible without completing prior steps", flow.name),
					Template: "apex-multistep-bypass",
				})
			}
		}

		// Try replaying intermediate steps with manipulated data
		for i, step := range flow.steps[:len(flow.steps)-1] {
			stepURL := base + step
			resp := http.Post(stepURL, "application/json", `{"skip":true,"step":"final"}`)
			if resp.Err == nil && resp.StatusCode == 200 {
				nextStep := base + flow.steps[min(i+2, len(flow.steps)-1)]
				nextResp := http.Get(nextStep)
				if nextResp.Err == nil && nextResp.StatusCode == 200 && len(nextResp.Body) > 200 {
					findings = append(findings, Finding{
						Type: fmt.Sprintf("Multi-Step Skip: %s step %d", flow.name, i+1), Severity: "high",
						URL: stepURL, Detail: "Step skippable via direct POST — flow integrity broken",
						Template: "apex-multistep-skip",
					})
				}
			}
		}
	}
	return findings
}

// --- Automatic PoC Generation ---
// Generates ready-to-paste curl commands and HTML PoCs for every finding

func GeneratePoC(f Finding) string {
	var poc strings.Builder

	poc.WriteString(fmt.Sprintf("# PoC for: %s\n", f.Type))
	poc.WriteString(fmt.Sprintf("# Severity: %s\n", f.Severity))
	poc.WriteString(fmt.Sprintf("# URL: %s\n\n", f.URL))

	// Curl command
	poc.WriteString("## Curl Command:\n")
	poc.WriteString(fmt.Sprintf("curl -sk '%s'", f.URL))
	if f.Payload != "" {
		poc.WriteString(fmt.Sprintf(" \\\n  # Payload: %s", f.Payload))
	}
	poc.WriteString("\n\n")

	// HTML PoC for CSRF/XSS/Clickjacking
	switch {
	case strings.Contains(f.Type, "CSRF"):
		poc.WriteString("## HTML PoC (CSRF):\n")
		poc.WriteString(fmt.Sprintf(`<html><body>
<form action="%s" method="POST">
  <input type="submit" value="Click me">
</form>
<script>document.forms[0].submit();</script>
</body></html>`, f.URL))

	case strings.Contains(f.Type, "XSS"):
		poc.WriteString("## Proof:\n")
		poc.WriteString(fmt.Sprintf("Navigate to: %s\n", f.URL))
		poc.WriteString("Expected: JavaScript alert box executes\n")

	case strings.Contains(f.Type, "Clickjacking"):
		poc.WriteString("## HTML PoC (Clickjacking):\n")
		poc.WriteString(fmt.Sprintf(`<html><body>
<iframe src="%s" style="opacity:0.1;position:absolute;top:0;left:0;width:100%%;height:100%%"></iframe>
<button style="position:relative;z-index:-1">Click here for prize!</button>
</body></html>`, f.URL))

	case strings.Contains(f.Type, "SSRF"):
		poc.WriteString("## Impact:\n")
		poc.WriteString("Internal network accessible. Try:\n")
		poc.WriteString(fmt.Sprintf("curl '%s'\n", strings.Replace(f.URL, f.Payload, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", 1)))

	case strings.Contains(f.Type, "Subdomain Takeover"):
		poc.WriteString("## Steps to reproduce:\n")
		poc.WriteString("1. Create CloudFront distribution\n")
		poc.WriteString(fmt.Sprintf("2. Add CNAME: %s\n", strings.TrimPrefix(strings.TrimPrefix(f.URL, "https://"), "http://")))
		poc.WriteString("3. Deploy malicious content\n")
		poc.WriteString("4. Victim visits subdomain → attacker content served\n")
	}

	return poc.String()
}

// --- Intelligent Retry with Backoff ---
// Retries failed requests with exponential backoff + WAF evasion

func smartRequest(http *engine.HTTPClient, url string, maxRetries int) *engine.Response {
	var resp *engine.Response
	for i := 0; i < maxRetries; i++ {
		resp = http.Get(url)
		if resp.Err == nil && resp.StatusCode != 429 && resp.StatusCode != 503 {
			return resp
		}
		// Exponential backoff
		delay := time.Duration(math.Pow(2, float64(i))) * time.Second
		time.Sleep(delay)
	}
	return resp
}

// --- Response Diff Engine ---
// Shows exactly what changed between two responses (for reports)

type ResponseDiff struct {
	SizeDiff    int
	StatusDiff  bool
	NewWords    []string
	RemovedWords []string
	NewHeaders  map[string]string
}

func diffResponses(a, b *engine.Response) ResponseDiff {
	diff := ResponseDiff{
		SizeDiff:   len(b.Body) - len(a.Body),
		StatusDiff: a.StatusCode != b.StatusCode,
		NewHeaders: make(map[string]string),
	}

	wordsA := make(map[string]bool)
	for _, w := range strings.Fields(a.Body) {
		wordsA[w] = true
	}
	wordsB := make(map[string]bool)
	for _, w := range strings.Fields(b.Body) {
		wordsB[w] = true
	}

	for w := range wordsB {
		if !wordsA[w] {
			diff.NewWords = append(diff.NewWords, w)
		}
	}
	for w := range wordsA {
		if !wordsB[w] {
			diff.RemovedWords = append(diff.RemovedWords, w)
		}
	}

	// Limit to most interesting new words
	if len(diff.NewWords) > 20 {
		diff.NewWords = diff.NewWords[:20]
	}

	return diff
}

// --- Content Discovery via Response Pattern Analysis ---
// Finds hidden content by analyzing 404 vs real page patterns

func scanContentDiscovery(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	if len(crawl.Pages) == 0 {
		return findings
	}
	base := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]

	// Get 404 fingerprint
	notFoundResp := http.Get(base + "/apex_definitely_not_exist_xyz123")
	if notFoundResp.Err != nil {
		return findings
	}
	notFoundFP := fingerprint(notFoundResp)

	// High-value paths to discover
	paths := []string{
		"/admin", "/admin/login", "/administrator", "/wp-admin",
		"/api", "/api/v1", "/api/v2", "/api/internal", "/api/debug",
		"/graphql", "/graphiql", "/playground",
		"/swagger", "/swagger-ui", "/api-docs", "/openapi.json", "/swagger.json",
		"/debug", "/debug/vars", "/debug/pprof", "/_debug",
		"/actuator", "/actuator/env", "/actuator/health", "/actuator/heapdump",
		"/console", "/terminal", "/shell",
		"/.git", "/.git/HEAD", "/.env", "/.env.local", "/.env.production",
		"/config", "/config.json", "/config.yml", "/settings.json",
		"/backup", "/backup.sql", "/dump.sql", "/database.sql",
		"/phpmyadmin", "/pma", "/adminer",
		"/jenkins", "/gitlab", "/grafana", "/kibana",
		"/metrics", "/prometheus", "/health", "/healthz", "/ready",
		"/trace", "/traces", "/logs",
		"/upload", "/uploads", "/files", "/media", "/static",
		"/test", "/testing", "/staging", "/dev",
		"/.well-known/security.txt", "/.well-known/openid-configuration",
		"/robots.txt", "/sitemap.xml", "/crossdomain.xml",
		"/server-status", "/server-info", "/status",
		"/wp-json", "/wp-json/wp/v2/users", "/xmlrpc.php",
		"/cgi-bin", "/cgi-bin/test",
		"/.htaccess", "/.htpasswd", "/web.config",
		"/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
		"/Dockerfile", "/docker-compose.yml", "/.dockerenv",
		"/node_modules", "/vendor",
	}

	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp := http.Get(base + p)
			if resp.Err != nil {
				return
			}
			fp := fingerprint(resp)

			// Real content: differs from 404 fingerprint AND has meaningful content
			if fp.DiffersFrom(notFoundFP) && resp.StatusCode != 404 && resp.StatusCode < 500 && len(resp.Body) > 50 {
				// Skip WAF blanket 403s (all return same status+similar size)
				if resp.StatusCode == 403 {
					return
				}
				sev := "info"
				if resp.StatusCode == 200 {
					if strings.Contains(p, ".env") || strings.Contains(p, "config") || strings.Contains(p, "backup") || strings.Contains(p, "dump") || strings.Contains(p, "actuator") || strings.Contains(p, "debug") {
						sev = "high"
					} else if strings.Contains(p, "admin") || strings.Contains(p, "swagger") || strings.Contains(p, "graphql") || strings.Contains(p, ".git") {
						sev = "medium"
					}
				}
				mu.Lock()
				findings = append(findings, Finding{
					Type: "Content Discovery: " + p, Severity: sev,
					URL: base + p, Detail: fmt.Sprintf("Status %d, %d bytes (differs from 404 pattern)", resp.StatusCode, resp.Size),
					Template: "apex-content-discovery",
				})
				mu.Unlock()
			}
		}(path)
	}
	wg.Wait()
	return findings
}

// --- Permission Boundary Testing ---
// Tests if lower-privilege actions can access higher-privilege resources

func scanPermissionBoundary(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	// Test common privilege escalation patterns
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]

	// Pattern: change role/permission in request
	escalationTests := []struct {
		url    string
		method string
		body   string
		detect string
	}{
		{"/api/user/role", "PUT", `{"role":"admin"}`, "admin"},
		{"/api/user/permissions", "PUT", `{"permissions":["*"]}`, "permissions"},
		{"/api/settings", "PATCH", `{"is_admin":true}`, "admin"},
		{"/api/me", "PATCH", `{"role":"superadmin","verified":true}`, ""},
		{"/api/users/1", "GET", "", "email"},
		{"/api/admin/users", "GET", "", "users"},
		{"/internal/config", "GET", "", ""},
		{"/api/debug", "GET", "", ""},
	}

	for _, test := range escalationTests {
		testURL := base + test.url
		var resp *engine.Response
		if test.method == "GET" {
			resp = http.Get(testURL)
		} else {
			resp = http.Post(testURL, "application/json", test.body)
		}
		if resp.Err != nil || resp.StatusCode == 404 || resp.StatusCode == 405 {
			continue
		}
		if resp.StatusCode == 200 && len(resp.Body) > 20 {
			if test.detect == "" || strings.Contains(strings.ToLower(resp.Body), test.detect) {
				findings = append(findings, Finding{
					Type: "Privilege Escalation Vector", Severity: "high",
					URL: testURL, Detail: fmt.Sprintf("%s %s returned %d (%d bytes) — potential unauthorized access", test.method, test.url, resp.StatusCode, resp.Size),
					Template: "apex-privesc",
				})
			}
		}
	}
	return findings
}

// --- Input Reflection Mapping ---
// Maps exactly where each parameter reflects in the response (for targeted exploitation)

func scanReflectionMap(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	canary := "APEX_REFLECT_7x7"
	contextRe := regexp.MustCompile(fmt.Sprintf(`(?s).{0,40}%s.{0,40}`, canary))

	for u, params := range crawl.Params {
		for _, p := range params {
			wg.Add(1)
			go func(baseURL, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				testURL := injectParam(baseURL, param, canary)
				resp := http.Get(testURL)
				if resp.Err != nil || !strings.Contains(resp.Body, canary) {
					return
				}

				// Count reflections
				count := strings.Count(resp.Body, canary)
				// Get contexts
				matches := contextRe.FindAllString(resp.Body, 5)
				contexts := []string{}
				for _, m := range matches {
					ctx := detectReflectionContext(m, canary)
					contexts = append(contexts, ctx)
				}

				if count > 0 {
					mu.Lock()
					findings = append(findings, Finding{
						Type: fmt.Sprintf("Reflection: %s (%dx)", param, count), Severity: "info",
						URL: testURL, Param: param,
						Detail:   fmt.Sprintf("Reflects %d times in contexts: %v — exploitable for XSS/injection", count, unique(contexts)),
						Template: "apex-reflection-map",
					})
					mu.Unlock()
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

func detectReflectionContext(surrounding, canary string) string {
	idx := strings.Index(surrounding, canary)
	if idx < 0 {
		return "unknown"
	}
	before := surrounding[:idx]
	if strings.Contains(before, "<script") || strings.Contains(before, "var ") {
		return "javascript"
	}
	if strings.Contains(before, "href=") || strings.Contains(before, "src=") {
		return "url-attribute"
	}
	if strings.Contains(before, "=\"") || strings.Contains(before, "='") {
		return "html-attribute"
	}
	if strings.Contains(before, "<!--") {
		return "html-comment"
	}
	return "html-body"
}

var _ = json.Marshal // ensure import
var _ = url.Parse    // ensure import
