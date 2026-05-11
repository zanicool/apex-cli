package scanner

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- Payload Loader ---

var (
	sqliPayloadsFile []string
	xssPayloadsFile  []string
	paramWordlist    []string
	payloadsLoaded   bool
)

func loadPayloads() {
	if payloadsLoaded {
		return
	}
	payloadsLoaded = true
	// Find payloads directory relative to binary
	dirs := []string{"./payloads", "../payloads", "/usr/share/apex-cli/payloads"}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err == nil {
			sqliPayloadsFile = loadFile(filepath.Join(dir, "sqli.txt"))
			xssPayloadsFile = loadFile(filepath.Join(dir, "xss.txt"))
			paramWordlist = loadFile(filepath.Join(dir, "params.txt"))
			break
		}
	}
}

func loadFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

// --- Deep JS Endpoint Extractor ---

func scanJSEndpoints(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Patterns that extract API routes from JS
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:"|')(/api/[a-zA-Z0-9_/\-\.]+)(?:"|')`),
		regexp.MustCompile(`(?:"|')(/v[0-9]+/[a-zA-Z0-9_/\-\.]+)(?:"|')`),
		regexp.MustCompile(`(?:fetch|axios\.\w+|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*(?:"|'|` + "`" + `)([^"'` + "`" + `\s]+)`),
		regexp.MustCompile(`(?:"|')(https?://[^"'\s]{10,})(?:"|')`),
		regexp.MustCompile(`(?:path|route|endpoint|url)\s*[:=]\s*(?:"|')([^"']+)(?:"|')`),
		regexp.MustCompile(`(?:"|')(/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-]+)*)(?:"|')`),
	}

	// Collect all JS URLs
	jsURLs := make(map[string]bool)
	for _, page := range crawl.Pages {
		if strings.HasSuffix(page.URL, ".js") || strings.Contains(page.URL, "/static/js/") || strings.Contains(page.URL, "/_next/") || strings.Contains(page.URL, "/bundle") || strings.Contains(page.URL, "/chunk") {
			jsURLs[page.URL] = true
		}
	}
	// Add common JS paths
	if len(crawl.Pages) > 0 {
		base := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
		for _, p := range []string{"/main.js", "/app.js", "/bundle.js", "/vendor.js", "/chunk.js", "/_next/static/chunks/main.js", "/static/js/main.js", "/assets/index.js", "/dist/app.js"} {
			jsURLs[base+p] = true
		}
	}

	discoveredEndpoints := make(map[string]bool)
	for jsURL := range jsURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp := http.Get(u)
			if resp.Err != nil || resp.StatusCode != 200 || len(resp.Body) < 100 {
				return
			}

			for _, pattern := range patterns {
				matches := pattern.FindAllStringSubmatch(resp.Body, -1)
				for _, m := range matches {
					if len(m) < 2 {
						continue
					}
					endpoint := m[1]
					if len(endpoint) < 3 || len(endpoint) > 200 {
						continue
					}
					// Skip static assets
					if strings.HasSuffix(endpoint, ".css") || strings.HasSuffix(endpoint, ".png") || strings.HasSuffix(endpoint, ".jpg") || strings.HasSuffix(endpoint, ".svg") || strings.HasSuffix(endpoint, ".woff") {
						continue
					}
					mu.Lock()
					discoveredEndpoints[endpoint] = true
					mu.Unlock()
				}
			}
		}(jsURL)
	}
	wg.Wait()

	// Probe discovered endpoints
	if len(crawl.Pages) > 0 && len(discoveredEndpoints) > 0 {
		base := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
		var liveEndpoints []string
		for endpoint := range discoveredEndpoints {
			fullURL := endpoint
			if !strings.HasPrefix(endpoint, "http") {
				fullURL = base + endpoint
			}
			resp := http.Get(fullURL)
			if resp.Err == nil && resp.StatusCode != 404 && resp.StatusCode < 500 {
				liveEndpoints = append(liveEndpoints, fullURL)
			}
		}
		if len(liveEndpoints) > 0 {
			findings = append(findings, Finding{
				Type: "JS Endpoint Discovery", Severity: "info",
				URL:    fmt.Sprintf("%d endpoints from %d JS files", len(liveEndpoints), len(jsURLs)),
				Detail: fmt.Sprintf("Found %d live API endpoints in JavaScript: %s", len(liveEndpoints), strings.Join(liveEndpoints[:min(10, len(liveEndpoints))], ", ")),
				Template: "apex-js-endpoints",
			})
			// Add to crawl data for other scanners to use
			for _, ep := range liveEndpoints {
				parsedURL, _ := url.Parse(ep)
				if parsedURL != nil {
					base := ep
					if parsedURL.RawQuery != "" {
						base = strings.Split(ep, "?")[0]
						for k := range parsedURL.Query() {
							crawl.Params[base] = append(crawl.Params[base], k)
						}
					}
				}
			}
		}
	}
	return findings
}

// --- Auto-Register + Authenticated Scan ---

func scanAuthenticated(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]

	// Try to auto-register
	registerPaths := []string{"/register", "/signup", "/api/register", "/api/auth/register", "/api/v1/register", "/api/users"}
	var authToken string

	testEmail := fmt.Sprintf("apex_test_%d@test.com", time.Now().Unix())
	testPass := "ApexTest123!"

	for _, path := range registerPaths {
		body := fmt.Sprintf(`{"email":"%s","password":"%s","username":"apextest%d"}`, testEmail, testPass, time.Now().Unix()%10000)
		resp := http.Post(base+path, "application/json", body)
		if resp.Err == nil && (resp.StatusCode == 200 || resp.StatusCode == 201) {
			// Extract token from response
			if strings.Contains(resp.Body, "token") {
				// Simple token extraction
				for _, part := range strings.Split(resp.Body, "\"") {
					if strings.HasPrefix(part, "eyJ") || (len(part) > 20 && !strings.Contains(part, " ")) {
						authToken = part
						break
					}
				}
			}
			if authToken == "" {
				// Try login
				loginPaths := []string{"/login", "/api/login", "/api/auth/login", "/api/v1/login"}
				for _, lp := range loginPaths {
					loginBody := fmt.Sprintf(`{"email":"%s","password":"%s"}`, testEmail, testPass)
					lr := http.Post(base+lp, "application/json", loginBody)
					if lr.Err == nil && lr.StatusCode == 200 {
						for _, part := range strings.Split(lr.Body, "\"") {
							if strings.HasPrefix(part, "eyJ") || (len(part) > 20 && !strings.Contains(part, " ") && !strings.Contains(part, ":")) {
								authToken = part
								break
							}
						}
						break
					}
				}
			}
			break
		}
	}

	if authToken == "" {
		return findings
	}

	findings = append(findings, Finding{
		Type: "Auto-Registration Successful", Severity: "info",
		URL: base, Detail: fmt.Sprintf("Registered and obtained auth token (len=%d)", len(authToken)),
		Template: "apex-auto-register",
	})

	// Now crawl authenticated endpoints and compare
	authPaths := []string{"/api/me", "/api/user", "/api/profile", "/api/account", "/api/settings", "/api/admin", "/api/users", "/api/dashboard", "/api/orders", "/api/payments", "/api/transactions"}
	for _, path := range authPaths {
		// Unauthenticated
		unauthResp := http.Get(base + path)
		// Authenticated
		items := []engine.RequestItem{{URL: base + path, Method: "GET", Headers: map[string]string{"Authorization": "Bearer " + authToken}}}
		for authResp := range http.BatchRequest(items, 1) {
			if authResp.Err != nil {
				continue
			}
			// If auth gives 200 but unauth gives 401/403 — endpoint exists behind auth
			if authResp.StatusCode == 200 && (unauthResp.StatusCode == 401 || unauthResp.StatusCode == 403) {
				findings = append(findings, Finding{
					Type: "Authenticated Endpoint Found", Severity: "info",
					URL: base + path, Detail: fmt.Sprintf("Returns data with auth (status %d, %d bytes)", authResp.StatusCode, authResp.Size),
					Template: "apex-auth-endpoint",
				})
				// Test IDOR — try accessing other users' data
				if strings.Contains(authResp.Body, "id") {
					// Modify the token or try different IDs
					idPaths := []string{base + path + "/1", base + path + "/2", base + path + "?user_id=1"}
					for _, idPath := range idPaths {
						idItems := []engine.RequestItem{{URL: idPath, Method: "GET", Headers: map[string]string{"Authorization": "Bearer " + authToken}}}
						for idResp := range http.BatchRequest(idItems, 1) {
							if idResp.Err == nil && idResp.StatusCode == 200 && idResp.Body != authResp.Body && len(idResp.Body) > 50 {
								findings = append(findings, Finding{
									Type: "IDOR via Authenticated Endpoint", Severity: "high",
									URL: idPath, Detail: "Different user data accessible with our auth token",
									Template: "apex-auth-idor",
								})
							}
						}
					}
				}
			}
		}
	}
	return findings
}

// --- Arjun-Style Param Brute-Forcer ---

func scanParamBruteforce(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	loadPayloads()
	if len(paramWordlist) == 0 {
		return findings
	}

	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Test on main pages
	targets := []string{}
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		targets = append(targets, page.URL)
	}

	for _, target := range targets {
		// Get baseline
		baseResp := http.Get(target)
		if baseResp.Err != nil || baseResp.StatusCode != 200 {
			continue
		}
		baseSize := len(baseResp.Body)
		baseHeaders := fmt.Sprintf("%v", baseResp.Headers)

		// Test params in batches of 10 (faster than one-by-one)
		for i := 0; i < len(paramWordlist); i += 10 {
			batch := paramWordlist[i:min(i+10, len(paramWordlist))]
			wg.Add(1)
			go func(params []string, baseURL string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Build URL with all params in batch
				sep := "?"
				if strings.Contains(baseURL, "?") {
					sep = "&"
				}
				paramStr := ""
				for _, p := range params {
					paramStr += p + "=apex_test&"
				}
				testURL := baseURL + sep + strings.TrimRight(paramStr, "&")
				resp := http.Get(testURL)
				if resp.Err != nil {
					return
				}

				// If response differs, test individually
				if resp.StatusCode == 200 && (len(resp.Body) != baseSize || fmt.Sprintf("%v", resp.Headers) != baseHeaders) {
					for _, p := range params {
						indivURL := baseURL + sep + p + "=apex_test"
						indivResp := http.Get(indivURL)
						if indivResp.Err == nil && indivResp.StatusCode == 200 {
							sizeDiff := len(indivResp.Body) - baseSize
							if sizeDiff > 20 || sizeDiff < -20 || indivResp.Body != baseResp.Body {
								mu.Lock()
								findings = append(findings, Finding{
									Type: "Hidden Parameter: " + p, Severity: "medium",
									URL: indivURL, Param: p,
									Detail:   fmt.Sprintf("Param '%s' changes response (size diff: %+d bytes)", p, sizeDiff),
									Template: "apex-hidden-param",
								})
								// Add to crawl data
								crawl.Params[baseURL] = append(crawl.Params[baseURL], p)
								mu.Unlock()
							}
						}
					}
				}
			}(batch, target)
		}
	}
	wg.Wait()
	return findings
}

// --- Differential Response Analyzer ---

func scanDifferential(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for _, page := range crawl.Pages[:min(20, len(crawl.Pages))] {
		wg.Add(1)
		go func(pageURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Baseline: normal request
			baseResp := http.Get(pageURL)
			if baseResp.Err != nil || baseResp.StatusCode != 200 {
				return
			}

			// Test 1: With vs without common auth headers
			authHeaders := []struct{ header, value, name string }{
				{"Authorization", "Bearer test", "auth bearer"},
				{"X-API-Key", "test", "api key"},
				{"Cookie", "admin=true; role=admin", "admin cookie"},
				{"X-Forwarded-For", "127.0.0.1", "internal IP"},
			}
			for _, ah := range authHeaders {
				items := []engine.RequestItem{{URL: pageURL, Method: "GET", Headers: map[string]string{ah.header: ah.value}}}
				for resp := range http.BatchRequest(items, 1) {
					if resp.Err == nil && resp.StatusCode == 200 && resp.Body != baseResp.Body {
						sizeDiff := len(resp.Body) - len(baseResp.Body)
						if sizeDiff > 50 { // More content with header = info leak
							mu.Lock()
							findings = append(findings, Finding{
								Type: "Differential: Extra Data with " + ah.name, Severity: "high",
								URL: pageURL, Detail: fmt.Sprintf("Header '%s: %s' reveals %d extra bytes", ah.header, ah.value, sizeDiff),
								Template: "apex-differential",
							})
							mu.Unlock()
						}
					}
				}
			}

			// Test 2: Different HTTP methods reveal different data
			for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
				items := []engine.RequestItem{{URL: pageURL, Method: method, Headers: map[string]string{"Content-Type": "application/json"}}}
				for resp := range http.BatchRequest(items, 1) {
					if resp.Err == nil && resp.StatusCode == 200 && resp.Body != baseResp.Body && len(resp.Body) > len(baseResp.Body)+50 {
						mu.Lock()
						findings = append(findings, Finding{
							Type: "Differential: " + method + " Returns Extra Data", Severity: "medium",
							URL: pageURL, Detail: fmt.Sprintf("%s returns %d more bytes than GET", method, len(resp.Body)-len(baseResp.Body)),
							Template: "apex-differential-method",
						})
						mu.Unlock()
						break
					}
				}
			}

			// Test 3: Content-Type confusion
			ctTests := []string{"application/json", "application/xml", "text/xml", "application/x-www-form-urlencoded"}
			for _, ct := range ctTests {
				resp := http.Post(pageURL, ct, "{}")
				if resp.Err == nil && resp.StatusCode == 200 && resp.Body != baseResp.Body && len(resp.Body) > 50 {
					if strings.Contains(resp.Body, "error") && (strings.Contains(resp.Body, "stack") || strings.Contains(resp.Body, "trace") || strings.Contains(resp.Body, "debug")) {
						mu.Lock()
						findings = append(findings, Finding{
							Type: "Content-Type Confusion — Debug Info Leak", Severity: "medium",
							URL: pageURL, Detail: fmt.Sprintf("Content-Type '%s' triggers debug/error output", ct),
							Template: "apex-ct-confusion",
						})
						mu.Unlock()
						break
					}
				}
			}
		}(page.URL)
	}
	wg.Wait()
	return findings
}
