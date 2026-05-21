package scanner

import (
	"crypto/md5"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- Boolean-Based Blind SQLi ---

func scanSQLiBlindBoolean(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	trueFalse := []struct{ truePayload, falsePayload string }{
		{"' AND '1'='1", "' AND '1'='2"},
		{"' AND 1=1--", "' AND 1=2--"},
		{"\" AND \"1\"=\"1", "\" AND \"1\"=\"2"},
		{" AND 1=1", " AND 1=2"},
		{"') AND ('1'='1", "') AND ('1'='2"},
		{" OR 1=1--", " OR 1=2--"},
	}

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
				baseHash := hashBody(baseResp.Body)
				baseSize := len(baseResp.Body)

				for _, tf := range trueFalse {
					trueURL := injectParam(baseURL, param, tf.truePayload)
					falseURL := injectParam(baseURL, param, tf.falsePayload)

					trueResp := http.Get(trueURL)
					falseResp := http.Get(falseURL)

					if trueResp.Err != nil || falseResp.Err != nil {
						continue
					}

					trueHash := hashBody(trueResp.Body)
					falseHash := hashBody(falseResp.Body)

					// Boolean blind: true condition matches baseline, false differs
					if trueHash == baseHash && falseHash != baseHash {
						mu.Lock()
						findings = append(findings, Finding{
							Type: "SQL Injection (Boolean-Based Blind)", Severity: "critical",
							URL: trueURL, Param: param,
							Payload: fmt.Sprintf("TRUE: %s | FALSE: %s", tf.truePayload, tf.falsePayload),
							Detail:  fmt.Sprintf("True response matches baseline (%d bytes), false differs (%d bytes)", baseSize, len(falseResp.Body)),
							Template: "apex-sqli-boolean",
						})
						mu.Unlock()
						return
					}

					// Also check: true differs from false (both differ from baseline but differently)
					trueSize := len(trueResp.Body)
					falseSize := len(falseResp.Body)
					if trueHash != falseHash && abs(trueSize-baseSize) < 50 && abs(falseSize-baseSize) > 100 {
						mu.Lock()
						findings = append(findings, Finding{
							Type: "SQL Injection (Boolean-Based Blind)", Severity: "critical",
							URL: trueURL, Param: param,
							Payload: fmt.Sprintf("TRUE: %s | FALSE: %s", tf.truePayload, tf.falsePayload),
							Detail:  fmt.Sprintf("True=%d bytes (≈baseline), False=%d bytes (differs)", trueSize, falseSize),
							Template: "apex-sqli-boolean",
						})
						mu.Unlock()
						return
					}
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

// --- Context-Aware XSS ---

func scanXSSContextAware(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	canary := "apex7x7z"

	for u, params := range crawl.Params {
		for _, p := range params {
			wg.Add(1)
			go func(baseURL, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Inject canary to find reflection context
				canaryURL := injectParam(baseURL, param, canary)
				resp := http.Get(canaryURL)
				if resp.Err != nil || !strings.Contains(resp.Body, canary) {
					return // Not reflected
				}

				// Determine context
				ctx := detectContext(resp.Body, canary)
				payloads := getContextPayloads(ctx)

				for _, payload := range payloads {
					testURL := injectParam(baseURL, param, payload.value)
					testResp := http.Get(testURL)
					if testResp.Err != nil {
						continue
					}
					if strings.Contains(testResp.Body, payload.detect) {
						mu.Lock()
						findings = append(findings, Finding{
							Type: fmt.Sprintf("XSS (%s context)", ctx), Severity: "high",
							URL: testURL, Param: param, Payload: payload.value,
							Evidence: payload.detect,
							Detail:   fmt.Sprintf("Reflected in %s context — payload breaks out and executes", ctx),
							Template: "apex-xss-context",
						})
						mu.Unlock()
						return
					}
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

type xssPayload struct {
	value  string
	detect string
}

func detectContext(body, canary string) string {
	idx := strings.Index(body, canary)
	if idx < 0 {
		return "html"
	}
	// Look at surrounding characters
	before := ""
	if idx > 50 {
		before = body[idx-50 : idx]
	} else if idx > 0 {
		before = body[:idx]
	}

	if strings.Contains(before, "<script") || strings.Contains(before, "var ") || strings.Contains(before, "= '") || strings.Contains(before, "= \"") {
		if strings.Contains(before, "'") {
			return "js-single"
		}
		return "js-double"
	}
	if regexp.MustCompile(`\w+\s*=\s*"[^"]*$`).MatchString(before) {
		return "attr-double"
	}
	if regexp.MustCompile(`\w+\s*=\s*'[^']*$`).MatchString(before) {
		return "attr-single"
	}
	if strings.Contains(before, "href=") || strings.Contains(before, "src=") {
		return "url"
	}
	return "html"
}

func getContextPayloads(ctx string) []xssPayload {
	switch ctx {
	case "js-single":
		return []xssPayload{
			{"'-alert(1)-'", "-alert(1)-"},
			{"';alert(1)//", ";alert(1)"},
			{"\\'-alert(1)//", "-alert(1)"},
		}
	case "js-double":
		return []xssPayload{
			{"\"-alert(1)-\"", "-alert(1)-"},
			{"\";alert(1)//", ";alert(1)"},
		}
	case "attr-double":
		return []xssPayload{
			{"\" onmouseover=alert(1) \"", "onmouseover=alert(1)"},
			{"\" onfocus=alert(1) autofocus=\"", "onfocus=alert(1)"},
			{"\"><script>alert(1)</script>", "<script>alert(1)</script>"},
			{"\"><img src=x onerror=alert(1)>", "onerror=alert(1)"},
		}
	case "attr-single":
		return []xssPayload{
			{"' onmouseover=alert(1) '", "onmouseover=alert(1)"},
			{"' onfocus=alert(1) autofocus='", "onfocus=alert(1)"},
			{"'><img src=x onerror=alert(1)>", "onerror=alert(1)"},
		}
	case "url":
		return []xssPayload{
			{"javascript:alert(1)", "javascript:alert(1)"},
			{"data:text/html,<script>alert(1)</script>", "data:text/html"},
		}
	default: // html
		return []xssPayload{
			{"<script>alert(1)</script>", "<script>alert(1)</script>"},
			{"<img src=x onerror=alert(1)>", "onerror=alert(1)"},
			{"<svg onload=alert(1)>", "onload=alert(1)"},
			{"<details open ontoggle=alert(1)>", "ontoggle=alert(1)"},
		}
	}
}

// --- WAF Detection (run before scanning to adapt strategy) ---

func DetectWAF(http *engine.HTTPClient, targets []string) []string {
	var wafs []string
	if len(targets) == 0 {
		return wafs
	}

	// Send obvious attack payload and check response
	testURL := targets[0] + "/?test=<script>alert(1)</script>&id=1' OR 1=1--"
	resp := http.Get(testURL)
	if resp.Err != nil {
		return wafs
	}

	wafSigs := map[string][]string{
		"Cloudflare":  {"cf-ray", "cloudflare", "__cfduid"},
		"AWS WAF":     {"awselb", "x-amzn-requestid", "aws"},
		"Akamai":      {"akamai", "x-akamai"},
		"Imperva":     {"incapsula", "imperva", "x-iinfo"},
		"F5 BIG-IP":   {"bigip", "f5", "ts="},
		"Sucuri":      {"sucuri", "x-sucuri"},
		"ModSecurity": {"mod_security", "modsecurity"},
		"Fortinet":    {"fortigate", "fortiweb"},
	}

	headerStr := strings.ToLower(fmt.Sprintf("%v", resp.Headers))
	bodyLower := strings.ToLower(resp.Body[:min(2000, len(resp.Body))])
	combined := headerStr + bodyLower

	for name, sigs := range wafSigs {
		for _, sig := range sigs {
			if strings.Contains(combined, sig) {
				wafs = append(wafs, name)
				break
			}
		}
	}

	// Also detect by status code pattern
	if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
		if len(wafs) == 0 {
			wafs = append(wafs, "Unknown WAF")
		}
	}

	return wafs
}

// --- Smart Deduplication ---

func DeduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var result []Finding

	for _, f := range findings {
		// Deduplicate by type + base URL (ignore query params for dedup)
		baseURL := f.URL
		if parsed, err := url.Parse(f.URL); err == nil {
			baseURL = parsed.Scheme + "://" + parsed.Host + parsed.Path
		}
		key := f.Type + "|" + baseURL + "|" + f.Param

		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}

// --- Wildcard Detection ---

func IsWildcard(http *engine.HTTPClient, target string) bool {
	// Request 3 random non-existent paths
	randoms := []string{"/apex_random_8f3k2j", "/apex_nonexist_9x7m4p", "/apex_test_2w5n8q"}
	var hashes []string

	for _, path := range randoms {
		resp := http.Get(target + path)
		if resp.Err != nil || resp.StatusCode == 404 {
			return false // Proper 404 = not wildcard
		}
		if resp.StatusCode == 200 {
			hashes = append(hashes, hashBody(resp.Body))
		}
	}

	// If all 3 random paths return same content = wildcard
	if len(hashes) == 3 && hashes[0] == hashes[1] && hashes[1] == hashes[2] {
		return true
	}
	return false
}

// --- Helpers ---

func hashBody(body string) string {
	// Normalize: strip whitespace-only differences
	normalized := strings.TrimSpace(body)
	h := md5.Sum([]byte(normalized))
	return fmt.Sprintf("%x", h)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// IsCloudflareChallenge checks if a target returns a Cloudflare challenge/block page
func IsCloudflareChallenge(http *engine.HTTPClient, target string) bool {
	resp := http.Get(target)
	if resp.Err != nil {
		return false
	}
	body := resp.Body
	// Cloudflare managed challenge markers
	cfMarkers := []string{
		"challenges.cloudflare.com",
		"cf-chl-bypass",
		"_cf_chl_opt",
		"Just a moment...",
		"cf-error-details",
		"cdn-cgi/challenge-platform",
	}
	for _, marker := range cfMarkers {
		if strings.Contains(body, marker) {
			return true
		}
	}
	return false
}

// IsSPACatchAll checks if a target returns identical responses for any path (SPA with client-side routing)
func IsSPACatchAll(http *engine.HTTPClient, target string) bool {
	paths := []string{"/", "/apex_fake_path_x9k2m", "/apex_fake_path_q7w3n", "/checkout/complete", "/api/upload"}
	var bodies []string
	for _, p := range paths {
		resp := http.Get(target + p)
		if resp.Err != nil {
			return false
		}
		if resp.StatusCode == 404 || resp.StatusCode == 403 || resp.StatusCode == 301 || resp.StatusCode == 302 {
			return false
		}
		bodies = append(bodies, hashBody(resp.Body))
	}
	// If all paths return identical content, it's a SPA catch-all
	if len(bodies) >= 4 {
		for i := 1; i < len(bodies); i++ {
			if bodies[i] != bodies[0] {
				return false
			}
		}
		return true
	}
	return false
}
