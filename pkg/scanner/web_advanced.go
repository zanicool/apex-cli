package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

func scanCORSAdvanced(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	origins := []string{"https://evil.com", "null", "https://sub.evil.com", "https://" + cfg.Target + ".evil.com", "https://evil" + cfg.Target}
	for _, page := range crawl.Pages[:min(15, len(crawl.Pages))] {
		for _, origin := range origins {
			items := []engine.RequestItem{{URL: page.URL, Method: "GET", Headers: map[string]string{"Origin": origin}}}
			for resp := range http.BatchRequest(items, 1) {
				acao := resp.Headers.Get("Access-Control-Allow-Origin")
				if acao == origin || acao == "*" {
					creds := resp.Headers.Get("Access-Control-Allow-Credentials")
					sev := "medium"
					detail := fmt.Sprintf("Origin '%s' reflected. ACAO: %s", origin, acao)
					if creds == "true" {
						sev = "high"
						detail += " + credentials allowed"
					}
					if acao == "*" && creds == "true" {
						sev = "critical"
					}
					findings = append(findings, Finding{Type: "CORS Misconfiguration", Severity: sev, URL: page.URL, Detail: detail, Template: "apex-cors-" + origin})
					break
				}
			}
		}
	}
	return findings
}

func scanOpenRedirectAdvanced(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	redirectParams := []string{"url", "redirect", "next", "return", "rurl", "dest", "destination", "continue", "goto", "target", "link", "forward"}
	payloads := []string{"https://evil.com", "//evil.com", "/\\evil.com", "https://evil.com%00.target.com", "https://target.com@evil.com", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>"}
	for u, params := range crawl.Params {
		for _, p := range params {
			if !containsAnyStr(strings.ToLower(p), redirectParams) {
				continue
			}
			for _, pl := range payloads {
				testURL := injectParam(u, p, pl)
				resp := http.Get(testURL)
				if resp.Err != nil {
					continue
				}
				loc := resp.Headers.Get("Location")
				if resp.StatusCode >= 300 && resp.StatusCode < 400 && (strings.Contains(loc, "evil.com") || strings.HasPrefix(loc, "javascript:") || strings.HasPrefix(loc, "data:")) {
					findings = append(findings, Finding{Type: "Open Redirect", Severity: "medium", URL: testURL, Param: p, Payload: pl, Evidence: loc, Template: "apex-redirect"})
					break
				}
				if strings.Contains(resp.Body, "evil.com") && strings.Contains(resp.Body, "http-equiv=\"refresh\"") {
					findings = append(findings, Finding{Type: "Open Redirect (Meta Refresh)", Severity: "medium", URL: testURL, Param: p, Payload: pl, Template: "apex-redirect-meta"})
					break
				}
			}
		}
	}
	return findings
}

func scanHPP(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for u, params := range crawl.Params {
		if len(params) == 0 {
			continue
		}
		p := params[0]
		// Send same param twice with different values
		sep := "&"
		if !strings.Contains(u, "?") {
			sep = "?"
		}
		testURL := u + sep + p + "=value1&" + p + "=value2"
		resp := http.Get(testURL)
		if resp.Err == nil && resp.StatusCode == 200 {
			if strings.Contains(resp.Body, "value1") && strings.Contains(resp.Body, "value2") {
				findings = append(findings, Finding{Type: "HTTP Parameter Pollution", Severity: "medium", URL: testURL, Param: p, Detail: "Both parameter values reflected — HPP possible", Template: "apex-hpp"})
			}
		}
	}
	return findings
}

func scanJSONP(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	callbackParams := []string{"callback", "jsonp", "cb", "func", "jsonpcallback"}
	for u, params := range crawl.Params {
		for _, p := range params {
			if !containsAnyStr(strings.ToLower(p), callbackParams) {
				continue
			}
			testURL := injectParam(u, p, "apex_callback")
			resp := http.Get(testURL)
			if resp.Err == nil && strings.Contains(resp.Body, "apex_callback(") {
				findings = append(findings, Finding{Type: "JSONP Endpoint — Data Theft", Severity: "high", URL: testURL, Param: p, Detail: "JSONP callback reflected — cross-origin data theft possible", Template: "apex-jsonp"})
			}
		}
	}
	return findings
}

func scanCSPBypass(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	resp := http.Get(crawl.Pages[0].URL)
	if resp.Err != nil {
		return findings
	}
	csp := resp.Headers.Get("Content-Security-Policy")
	if csp == "" {
		return findings
	}
	weaknesses := []struct{ pattern, issue string }{
		{"unsafe-inline", "CSP allows unsafe-inline — XSS not mitigated"},
		{"unsafe-eval", "CSP allows unsafe-eval — eval() based XSS possible"},
		{"data:", "CSP allows data: URIs — can inject via data: scheme"},
		{"*", "CSP uses wildcard — overly permissive"},
		{"http:", "CSP allows http: — mixed content/downgrade attacks"},
	}
	for _, w := range weaknesses {
		if strings.Contains(csp, w.pattern) {
			findings = append(findings, Finding{Type: "CSP Weakness: " + w.pattern, Severity: "medium", URL: crawl.Pages[0].URL, Detail: w.issue, Template: "apex-csp-weak"})
		}
	}
	return findings
}

func scanDOMXSS(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup
	// DOM XSS sinks
	sinkPattern := regexp.MustCompile(`(?i)(document\.write|innerHTML|outerHTML|eval\(|setTimeout\(|setInterval\(|\.href\s*=|location\s*=|location\.assign|window\.open)`)
	sourcePattern := regexp.MustCompile(`(?i)(location\.hash|location\.search|location\.href|document\.URL|document\.referrer|window\.name|postMessage)`)

	for _, page := range crawl.Pages {
		if !strings.HasSuffix(page.URL, ".js") && !strings.Contains(page.URL, "javascript") {
			continue
		}
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resp := http.Get(url)
			if resp.Err != nil || resp.StatusCode != 200 {
				return
			}
			sinks := sinkPattern.FindAllString(resp.Body, -1)
			sources := sourcePattern.FindAllString(resp.Body, -1)
			if len(sinks) > 0 && len(sources) > 0 {
				mu.Lock()
				findings = append(findings, Finding{Type: "Potential DOM XSS", Severity: "medium", URL: url, Detail: fmt.Sprintf("Sources: %v → Sinks: %v", unique(sources)[:min(3, len(sources))], unique(sinks)[:min(3, len(sinks))]), Template: "apex-dom-xss"})
				mu.Unlock()
			}
		}(page.URL)
	}
	wg.Wait()
	return findings
}

func scanPostMessage(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	pmPattern := regexp.MustCompile(`(?i)addEventListener\s*\(\s*['"]message['"]`)
	noOriginCheck := regexp.MustCompile(`(?i)event\.data|e\.data`)
	originCheck := regexp.MustCompile(`(?i)event\.origin|e\.origin`)

	for _, page := range crawl.Pages[:min(20, len(crawl.Pages))] {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		if pmPattern.MatchString(resp.Body) {
			if noOriginCheck.MatchString(resp.Body) && !originCheck.MatchString(resp.Body) {
				findings = append(findings, Finding{Type: "postMessage Without Origin Check", Severity: "high", URL: page.URL, Detail: "Message event listener processes data without verifying origin — XSS/data theft via cross-origin message", Template: "apex-postmessage"})
			}
		}
	}
	return findings
}

func scanSSI(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	ssiPayloads := []struct{ payload, detect string }{
		{`<!--#exec cmd="id"-->`, "uid="},
		{`<!--#echo var="DOCUMENT_ROOT"-->`, "/"},
		{`<!--#include virtual="/etc/passwd"-->`, "root:"},
	}
	for u, params := range crawl.Params {
		for _, p := range params {
			for _, pl := range ssiPayloads {
				testURL := injectParam(u, p, pl.payload)
				resp := http.Get(testURL)
				if resp.Err == nil && strings.Contains(resp.Body, pl.detect) {
					findings = append(findings, Finding{Type: "Server-Side Include (SSI) Injection", Severity: "critical", URL: testURL, Param: p, Payload: pl.payload, Template: "apex-ssi"})
					break
				}
			}
		}
	}
	return findings
}

func unique(ss []string) []string {
	seen := make(map[string]bool)
	var r []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			r = append(r, s)
		}
	}
	return r
}
