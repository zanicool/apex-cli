package scanner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

func scanCSRF(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for _, form := range crawl.Forms {
		if form.Method != "POST" {
			continue
		}
		hasToken := false
		for _, inp := range form.Inputs {
			if strings.Contains(strings.ToLower(inp.Name), "csrf") || strings.Contains(strings.ToLower(inp.Name), "token") || strings.Contains(strings.ToLower(inp.Name), "_token") {
				hasToken = true
				break
			}
		}
		if !hasToken {
			findings = append(findings, Finding{Type: "Cross-Site Request Forgery (CSRF)", Severity: "medium", URL: form.Action, Detail: "POST form without CSRF token", Template: "apex-csrf"})
		}
	}
	return findings
}

func scanClickjacking(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		xfo := resp.Headers.Get("X-Frame-Options")
		csp := resp.Headers.Get("Content-Security-Policy")
		if xfo == "" && !strings.Contains(csp, "frame-ancestors") {
			findings = append(findings, Finding{Type: "Clickjacking — Missing Frame Protection", Severity: "medium", URL: page.URL, Detail: "No X-Frame-Options or CSP frame-ancestors", Template: "apex-clickjacking"})
			break
		}
	}
	return findings
}

func scanCRLF(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup
	payloads := []string{"%0d%0aInjected:header", "%0aInjected:header", "%0d%0a%0d%0a<html>injected</html>", "%%0a0aInjected:header"}
	for u, params := range crawl.Params {
		for _, p := range params {
			for _, pl := range payloads {
				wg.Add(1)
				go func(base, param, payload string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					testURL := injectParam(base, param, "value"+payload)
					resp := http.Get(testURL)
					if resp.Err == nil && resp.Headers.Get("Injected") != "" {
						mu.Lock()
						findings = append(findings, Finding{Type: "CRLF Injection", Severity: "high", URL: testURL, Param: param, Payload: payload, Template: "apex-crlf"})
						mu.Unlock()
					}
				}(u, p, pl)
			}
		}
	}
	wg.Wait()
	return dedup(findings)
}

func scanHeaders(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	resp := http.Get(crawl.Pages[0].URL)
	if resp.Err != nil {
		return findings
	}
	missing := []struct{ header, name string }{
		{"Strict-Transport-Security", "HSTS"},
		{"X-Content-Type-Options", "X-Content-Type-Options"},
		{"X-Frame-Options", "X-Frame-Options"},
		{"Content-Security-Policy", "CSP"},
		{"Referrer-Policy", "Referrer-Policy"},
		{"Permissions-Policy", "Permissions-Policy"},
	}
	for _, h := range missing {
		if resp.Headers.Get(h.header) == "" {
			findings = append(findings, Finding{Type: "Missing Security Header: " + h.name, Severity: "low", URL: crawl.Pages[0].URL, Template: "apex-header-" + strings.ToLower(h.name)})
		}
	}
	// Info leakage headers
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version"} {
		if v := resp.Headers.Get(h); v != "" {
			findings = append(findings, Finding{Type: "Information Disclosure: " + h, Severity: "info", URL: crawl.Pages[0].URL, Detail: fmt.Sprintf("%s: %s", h, v), Template: "apex-info-header"})
		}
	}
	return findings
}

func scanCookieSecurity(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	resp := http.Get(crawl.Pages[0].URL)
	if resp.Err != nil {
		return findings
	}
	cookies := resp.Headers.Values("Set-Cookie")
	for _, c := range cookies {
		cl := strings.ToLower(c)
		if !strings.Contains(cl, "httponly") {
			findings = append(findings, Finding{Type: "Cookie Missing HttpOnly", Severity: "low", URL: crawl.Pages[0].URL, Detail: c[:min(80, len(c))], Template: "apex-cookie-httponly"})
		}
		if !strings.Contains(cl, "secure") {
			findings = append(findings, Finding{Type: "Cookie Missing Secure Flag", Severity: "low", URL: crawl.Pages[0].URL, Detail: c[:min(80, len(c))], Template: "apex-cookie-secure"})
		}
		if !strings.Contains(cl, "samesite") {
			findings = append(findings, Finding{Type: "Cookie Missing SameSite", Severity: "low", URL: crawl.Pages[0].URL, Detail: c[:min(80, len(c))], Template: "apex-cookie-samesite"})
		}
	}
	return findings
}

func scanInfoDisclosure(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup
	paths := []string{"/.env", "/.git/config", "/debug", "/phpinfo.php", "/server-status", "/server-info", "/.DS_Store", "/wp-config.php.bak", "/config.yml", "/.htpasswd", "/crossdomain.xml", "/.well-known/security.txt", "/robots.txt", "/sitemap.xml", "/api-docs", "/swagger.json", "/openapi.json"}
	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
	for _, path := range paths {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resp := http.Get(u)
			if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 20 {
				bodyLower := strings.ToLower(resp.Body)
				if strings.Contains(bodyLower, "db_pass") || strings.Contains(bodyLower, "db_password") ||
					strings.Contains(bodyLower, "secret") || strings.Contains(bodyLower, "api_key") ||
					strings.Contains(bodyLower, "aws_") || strings.Contains(bodyLower, "private_key") ||
					strings.Contains(bodyLower, "[core]") || strings.Contains(bodyLower, "phpinfo") ||
					strings.Contains(bodyLower, "root:") || strings.Contains(bodyLower, "swagger") ||
					strings.Contains(bodyLower, "openapi") || strings.Contains(bodyLower, "app_key") ||
					strings.Contains(bodyLower, "token") || strings.Contains(bodyLower, "password") ||
					strings.Contains(bodyLower, "credential") {
					mu.Lock()
					findings = append(findings, Finding{Type: "Sensitive File Exposed", Severity: "high", URL: u, Detail: fmt.Sprintf("Accessible (%d bytes)", resp.Size), Template: "apex-sensitive-file"})
					mu.Unlock()
				}
			}
		}(baseURL + path)
	}
	wg.Wait()
	return findings
}
