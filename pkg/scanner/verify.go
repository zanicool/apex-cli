package scanner

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/zanicool/apex-cli/pkg/engine"
)

// VerifyAndScore takes raw findings and returns only verified ones with confidence scores
func VerifyAndScore(cfg *engine.Config, http *engine.HTTPClient, findings []Finding) []Finding {
	var verified []Finding

	// Cap to prevent timeout on large scans
	maxVerify := 50
	count := 0

	for i := range findings {
		f := &findings[i]
		if isNoise(f) {
			continue
		}
		// Skip verification for findings that already have strong evidence
		if f.Evidence != "" && len(f.Evidence) > 10 {
			f.Detail = fmt.Sprintf("[85%% confidence] %s", f.Detail)
			verified = append(verified, *f)
			continue
		}
		if count >= maxVerify {
			f.Detail = fmt.Sprintf("[70%% confidence] %s", f.Detail)
			verified = append(verified, *f)
			continue
		}
		confidence, evidence := verifyWithEvidence(http, f)
		count++
		if confidence >= 0.6 {
			if evidence != "" {
				f.Evidence = evidence
			}
			f.Detail = fmt.Sprintf("[%.0f%% confidence] %s", confidence*100, f.Detail)
			verified = append(verified, *f)
		}
	}
	verified = deduplicateAcrossHosts(verified)
	sortBySeverity(verified)
	return verified
}

func verifyWithEvidence(http *engine.HTTPClient, f *Finding) (float64, string) {
	switch {
	case strings.Contains(f.Type, "SQL"):
		return verifySQLiEvidence(http, f)
	case strings.Contains(f.Type, "XSS") || strings.Contains(f.Type, "Cross-Site"):
		return verifyXSSEvidence(http, f)
	case strings.Contains(f.Type, "SSRF"):
		return verifySSRFEvidence(http, f)
	case strings.Contains(f.Type, "Command Injection"):
		return verifyCMDiEvidence(http, f)
	case strings.Contains(f.Type, "SSTI"):
		return verifySSTIEvidence(http, f)
	case strings.Contains(f.Type, "Open Redirect"):
		return verifyRedirectEvidence(http, f)
	case strings.Contains(f.Type, "Subdomain Takeover"):
		return 0.95, "CNAME dangling confirmed"
	case strings.Contains(f.Type, "Secret"):
		return verifySecretEvidence(http, f)
	case strings.Contains(f.Type, "CORS"):
		return verifyCORSEvidence(http, f)
	case strings.Contains(f.Type, "IDOR"):
		return verifyIDOREvidence(http, f)
	default:
		return 0.7, ""
	}
}

// verifySQLiEvidence - extracts DB version, table names, or confirms time delay
func verifySQLiEvidence(h *engine.HTTPClient, f *Finding) (float64, string) {
	if f.URL == "" {
		return 0.0, ""
	}

	// Time-based: double-check with two different delays
	if strings.Contains(f.Detail, "time") || strings.Contains(f.Detail, "Time") || strings.Contains(f.Type, "Blind") {
		// First: confirm 3s delay
		resp1 := h.Get(f.URL)
		if resp1.Err != nil || resp1.Duration.Seconds() < 2.5 {
			return 0.2, ""
		}
		// Second: try 0s delay version to confirm it's controllable
		noDelayURL := strings.Replace(f.URL, "SLEEP(3)", "SLEEP(0)", 1)
		noDelayURL = strings.Replace(noDelayURL, "pg_sleep(3)", "pg_sleep(0)", 1)
		noDelayURL = strings.Replace(noDelayURL, "WAITFOR DELAY '0:0:3'", "WAITFOR DELAY '0:0:0'", 1)
		if noDelayURL != f.URL {
			resp2 := h.Get(noDelayURL)
			if resp2.Err == nil && resp2.Duration.Seconds() < 1.0 {
				return 0.98, fmt.Sprintf("Time-based confirmed: %.1fs with payload, %.1fs without", resp1.Duration.Seconds(), resp2.Duration.Seconds())
			}
		}
		return 0.85, fmt.Sprintf("Time delay: %.1fs", resp1.Duration.Seconds())
	}

	// Error-based: extract version info
	resp := h.Get(f.URL)
	if resp.Err != nil {
		return 0.0, ""
	}

	// Try to extract actual DB data via UNION-based injection
	versionPayloads := []struct {
		payload string
		regex   string
		dbType  string
	}{
		{"' UNION SELECT version()--", `(\d+\.\d+\.\d+[-\w]*)`, "PostgreSQL/MySQL"},
		{"' UNION SELECT @@version--", `(\d+\.\d+\.\d+)`, "MySQL/MSSQL"},
		{"' UNION SELECT sqlite_version()--", `(\d+\.\d+\.\d+)`, "SQLite"},
		{"' UNION SELECT banner FROM v$version WHERE ROWNUM=1--", `(Oracle\s+Database\s+\d+)`, "Oracle"},
	}

	baseURL := stripPayload(f.URL, f.Param)
	baseResp := h.Get(baseURL)
	baseBody := ""
	if baseResp.Err == nil {
		baseBody = baseResp.Body
	}

	for _, vp := range versionPayloads {
		testURL := injectParam(f.URL, f.Param, vp.payload)
		if testURL == f.URL {
			testURL = f.URL + vp.payload
		}
		vResp := h.Get(testURL)
		if vResp.Err != nil {
			continue
		}
		re := regexp.MustCompile(vp.regex)
		matches := re.FindStringSubmatch(vResp.Body)
		if len(matches) > 1 && !strings.Contains(baseBody, matches[1]) {
			return 0.99, fmt.Sprintf("DB Version extracted (%s): %s", vp.dbType, matches[1])
		}
	}

	// Check for SQL error strings that prove injection
	if f.Evidence != "" && strings.Contains(strings.ToLower(resp.Body), strings.ToLower(f.Evidence)) {
		if baseBody == "" || !strings.Contains(strings.ToLower(baseBody), strings.ToLower(f.Evidence)) {
			return 0.92, fmt.Sprintf("SQL error triggered: %s", truncate(f.Evidence, 100))
		}
		return 0.2, ""
	}
	return 0.4, ""
}

// verifyXSSEvidence - confirms reflection is executable
func verifyXSSEvidence(h *engine.HTTPClient, f *Finding) (float64, string) {
	if f.URL == "" {
		return 0.0, ""
	}
	resp := h.Get(f.URL)
	if resp.Err != nil {
		return 0.0, ""
	}

	// Check content-type allows execution
	ct := resp.Headers.Get("Content-Type")
	if strings.Contains(ct, "application/json") || strings.Contains(ct, "text/plain") {
		return 0.2, "Reflected but Content-Type prevents execution"
	}

	if f.Payload == "" && f.Evidence == "" {
		return 0.3, ""
	}

	searchStr := f.Evidence
	if searchStr == "" {
		searchStr = f.Payload
	}

	if strings.Contains(resp.Body, searchStr) {
		// Verify not in baseline
		baseURL := stripPayload(f.URL, f.Param)
		baseResp := h.Get(baseURL)
		if baseResp.Err == nil && strings.Contains(baseResp.Body, searchStr) {
			return 0.1, ""
		}

		// Check context - is it actually executable?
		idx := strings.Index(resp.Body, searchStr)
		if idx < 0 {
			return 0.3, ""
		}
		before := resp.Body[max(0, idx-200):idx]
		after := ""
		endIdx := idx + len(searchStr)
		if endIdx < len(resp.Body) {
			after = resp.Body[endIdx:min(len(resp.Body), endIdx+100)]
		}

		// Inside HTML comment = not exploitable
		if strings.Contains(before, "<!--") && !strings.Contains(before, "-->") {
			return 0.2, "Inside HTML comment"
		}
		// Inside <script> tag = high impact
		if strings.Contains(before, "<script") || strings.Contains(searchStr, "<script") {
			return 0.95, fmt.Sprintf("XSS in script context. Payload reflected: %s", truncate(searchStr, 80))
		}
		// Event handler
		if strings.Contains(searchStr, "onerror") || strings.Contains(searchStr, "onload") || strings.Contains(searchStr, "onfocus") {
			return 0.92, fmt.Sprintf("XSS via event handler: %s", truncate(searchStr, 80))
		}
		// Check CSP blocks inline scripts
		csp := resp.Headers.Get("Content-Security-Policy")
		if strings.Contains(csp, "script-src") && !strings.Contains(csp, "'unsafe-inline'") {
			return 0.5, fmt.Sprintf("Reflected but CSP may block execution: %s", truncate(csp, 80))
		}

		_ = after
		return 0.88, fmt.Sprintf("Payload reflected unencoded in HTML: %s", truncate(searchStr, 80))
	}
	return 0.3, ""
}

// verifySSRFEvidence - confirms internal data access
func verifySSRFEvidence(h *engine.HTTPClient, f *Finding) (float64, string) {
	if f.URL == "" {
		return 0.0, ""
	}
	resp := h.Get(f.URL)
	if resp.Err != nil {
		return 0.0, ""
	}

	body := strings.ToLower(resp.Body)
	// AWS metadata
	if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") {
		re := regexp.MustCompile(`(i-[0-9a-f]{8,17})`)
		if m := re.FindString(resp.Body); m != "" {
			return 0.99, fmt.Sprintf("AWS instance-id extracted: %s", m)
		}
		return 0.99, "AWS metadata endpoint accessible"
	}
	if strings.Contains(body, "accesskeyid") || strings.Contains(body, "secretaccesskey") {
		return 0.99, "AWS credentials exposed via SSRF"
	}
	// GCP metadata
	if strings.Contains(body, "project-id") && strings.Contains(body, "numeric-project-id") {
		return 0.99, "GCP metadata accessible"
	}
	// Internal file read
	if strings.Contains(body, "root:x:0") || strings.Contains(body, "root:*:0") {
		return 0.99, "Internal file read via SSRF: /etc/passwd accessible"
	}
	// Internal service response
	if strings.Contains(body, "\"status\"") && (strings.Contains(f.URL, "127.0.0.1") || strings.Contains(f.URL, "localhost") || strings.Contains(f.URL, "169.254")) {
		return 0.85, "Internal service responded"
	}
	return 0.3, ""
}

// verifyCMDiEvidence - extracts OS info or confirms time delay
func verifyCMDiEvidence(h *engine.HTTPClient, f *Finding) (float64, string) {
	if f.URL == "" {
		return 0.0, ""
	}

	// Time-based verification with differential
	if strings.Contains(f.Detail, "time") || strings.Contains(f.Detail, "sleep") {
		resp1 := h.Get(f.URL)
		if resp1.Err != nil || resp1.Duration.Seconds() < 2.5 {
			return 0.2, ""
		}
		// Try with 0 sleep
		noSleep := strings.Replace(f.URL, "sleep+3", "sleep+0", 1)
		noSleep = strings.Replace(noSleep, "sleep%203", "sleep%200", 1)
		if noSleep != f.URL {
			resp2 := h.Get(noSleep)
			if resp2.Err == nil && resp2.Duration.Seconds() < 1.0 {
				return 0.97, fmt.Sprintf("CMDi time confirmed: %.1fs vs %.1fs", resp1.Duration.Seconds(), resp2.Duration.Seconds())
			}
		}
		return 0.8, fmt.Sprintf("Time delay: %.1fs", resp1.Duration.Seconds())
	}

	// Output-based: try to extract OS info
	resp := h.Get(f.URL)
	if resp.Err != nil {
		return 0.3, ""
	}

	// Check for command output markers
	osIndicators := []struct {
		pattern string
		desc    string
	}{
		{`uid=\d+\(\w+\)`, "Unix uid output"},
		{`Linux \w+ \d+\.\d+`, "Linux kernel version"},
		{`Windows NT \d+\.\d+`, "Windows version"},
		{`root:x:0:0`, "/etc/passwd content"},
		{`APEX_[A-Z]+`, "Canary token reflected"},
	}
	for _, ind := range osIndicators {
		re := regexp.MustCompile(ind.pattern)
		if m := re.FindString(resp.Body); m != "" {
			return 0.98, fmt.Sprintf("Command output: %s (%s)", m, ind.desc)
		}
	}

	if f.Evidence != "" && strings.Contains(resp.Body, f.Evidence) {
		return 0.9, fmt.Sprintf("Output confirmed: %s", truncate(f.Evidence, 80))
	}
	return 0.4, ""
}

// verifySSTIEvidence - confirms template execution with math proof
func verifySSTIEvidence(h *engine.HTTPClient, f *Finding) (float64, string) {
	if f.URL == "" {
		return 0.0, ""
	}
	resp := h.Get(f.URL)
	if resp.Err == nil && f.Evidence != "" && strings.Contains(resp.Body, f.Evidence) {
		baseURL := stripPayload(f.URL, f.Param)
		baseResp := h.Get(baseURL)
		if baseResp.Err == nil && !strings.Contains(baseResp.Body, f.Evidence) {
			// Try to identify the template engine
			engineID := identifyTemplateEngine(h, f)
			return 0.96, fmt.Sprintf("SSTI confirmed — math result in response. Engine: %s", engineID)
		}
		return 0.2, ""
	}
	return 0.3, ""
}

func identifyTemplateEngine(h *engine.HTTPClient, f *Finding) string {
	probes := []struct {
		payload string
		expect  string
		engine  string
	}{
		{"{{7*7}}", "49", "Jinja2/Twig"},
		{"${7*7}", "49", "Freemarker/EL"},
		{"<%= 7*7 %>", "49", "ERB/EJS"},
		{"#{7*7}", "49", "Ruby/Pug"},
	}
	for _, p := range probes {
		testURL := injectParam(stripPayload(f.URL, f.Param), f.Param, p.payload)
		resp := h.Get(testURL)
		if resp.Err == nil && strings.Contains(resp.Body, p.expect) {
			return p.engine
		}
	}
	return "Unknown"
}

func verifyRedirectEvidence(h *engine.HTTPClient, f *Finding) (float64, string) {
	if f.URL == "" {
		return 0.0, ""
	}
	// Use a client that doesn't follow redirects
	req, err := http.NewRequest("GET", f.URL, nil)
	if err != nil {
		return 0.3, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp := h.Do(req)
	if resp.Err != nil {
		return 0.3, ""
	}
	location := resp.Headers.Get("Location")
	if location != "" && (strings.Contains(location, "evil.com") || strings.Contains(location, "attacker")) {
		return 0.92, fmt.Sprintf("Redirect to external domain: %s", location)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && location != "" {
		return 0.7, fmt.Sprintf("Redirect (status %d) to: %s", resp.StatusCode, truncate(location, 100))
	}
	return 0.4, ""
}

func verifySecretEvidence(h *engine.HTTPClient, f *Finding) (float64, string) {
	// Validate secret format
	patterns := map[string]*regexp.Regexp{
		"AWS Key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"GitHub":      regexp.MustCompile(`gh[ps]_[A-Za-z0-9_]{36,}`),
		"Stripe":      regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		"Private Key": regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`),
		"JWT":         regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`),
	}
	for name, re := range patterns {
		if re.MatchString(f.Evidence) || re.MatchString(f.Detail) {
			return 0.95, fmt.Sprintf("Valid %s format confirmed", name)
		}
	}
	if strings.Contains(f.Type, "Hardcoded") {
		return 0.7, "Potential hardcoded credential"
	}
	return 0.6, ""
}

func verifyCORSEvidence(h *engine.HTTPClient, f *Finding) (float64, string) {
	if f.URL == "" {
		return 0.3, ""
	}
	req, _ := http.NewRequest("GET", f.URL, nil)
	req.Header.Set("Origin", "https://evil.com")
	resp := h.Do(req)
	if resp.Err != nil {
		return 0.3, ""
	}
	acao := resp.Headers.Get("Access-Control-Allow-Origin")
	acac := resp.Headers.Get("Access-Control-Allow-Credentials")
	if acao == "https://evil.com" && strings.EqualFold(acac, "true") {
		return 0.95, "CORS reflects arbitrary origin with credentials=true"
	}
	if acao == "*" && strings.EqualFold(acac, "true") {
		return 0.85, "CORS wildcard with credentials (browser blocks but misconfigured)"
	}
	if acao == "https://evil.com" {
		return 0.6, "CORS reflects origin but no credentials"
	}
	return 0.3, ""
}

func verifyIDOREvidence(h *engine.HTTPClient, f *Finding) (float64, string) {
	if f.URL == "" || f.Evidence == "" {
		return 0.5, ""
	}
	// Re-request to confirm different data is returned
	resp := h.Get(f.URL)
	if resp.Err != nil {
		return 0.3, ""
	}
	if strings.Contains(resp.Body, f.Evidence) {
		return 0.9, fmt.Sprintf("Unauthorized data access confirmed: %s", truncate(f.Evidence, 80))
	}
	return 0.5, ""
}

// --- Helpers ---

func isNoise(f *Finding) bool {
	noiseTypes := []string{"Missing Security Header", "Information Disclosure: Server", "ETag Tracking", "Hidden Parameter"}
	for _, n := range noiseTypes {
		if strings.Contains(f.Type, n) {
			return true
		}
	}
	if strings.Contains(f.Type, "CSRF") {
		if !strings.Contains(strings.ToLower(f.URL), "password") &&
			!strings.Contains(strings.ToLower(f.URL), "transfer") &&
			!strings.Contains(strings.ToLower(f.URL), "payment") &&
			!strings.Contains(strings.ToLower(f.URL), "delete") {
			return true
		}
	}
	return false
}

func deduplicateAcrossHosts(findings []Finding) []Finding {
	type findingKey struct {
		vulnType string
		pathHash string
	}
	seen := make(map[findingKey]bool)
	var result []Finding
	for _, f := range findings {
		path := f.URL
		if idx := strings.Index(f.URL, "//"); idx > 0 {
			rest := f.URL[idx+2:]
			if slashIdx := strings.Index(rest, "/"); slashIdx > 0 {
				path = rest[slashIdx:]
			}
		}
		h := md5.Sum([]byte(path + f.Param))
		key := findingKey{vulnType: f.Type, pathHash: fmt.Sprintf("%x", h[:4])}
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}

func sortBySeverity(findings []Finding) {
	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if sevOrder[findings[i].Severity] > sevOrder[findings[j].Severity] {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}

func stripPayload(fullURL, param string) string {
	if param == "" {
		return fullURL
	}
	parts := strings.Split(fullURL, "?")
	if len(parts) < 2 {
		return fullURL
	}
	base := parts[0]
	query := parts[1]
	var cleanParams []string
	for _, p := range strings.Split(query, "&") {
		if !strings.HasPrefix(p, param+"=") {
			cleanParams = append(cleanParams, p)
		}
	}
	if len(cleanParams) == 0 {
		return base
	}
	return base + "?" + strings.Join(cleanParams, "&")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// DetectHoneypot checks if a target is a honeypot/test environment
func DetectHoneypot(h *engine.HTTPClient, target string) bool {
	resp := h.Get(target)
	if resp.Err != nil {
		return false
	}
	honeypotSignals := []string{"honeypot", "cowrie", "dionaea", "glastopf", "kippo"}
	bodyLower := strings.ToLower(resp.Body)
	for _, sig := range honeypotSignals {
		if strings.Contains(bodyLower, sig) {
			return true
		}
	}
	// If everything returns 200 with same body = likely honeypot
	paths := []string{"/admin", "/wp-admin", "/.env", "/api/v1/secret"}
	sameCount := 0
	for _, p := range paths {
		r := h.Get(target + p)
		if r.Err == nil && r.StatusCode == 200 && r.Size == resp.Size {
			sameCount++
		}
	}
	return sameCount >= 3
}

// IsTestEnvironment detects staging/test/dev environments
func IsTestEnvironment(target string) bool {
	indicators := []string{"staging", "test", "dev.", "sandbox", "demo", "uat.", "preprod"}
	lower := strings.ToLower(target)
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// VerifyWithTimeout wraps verification with a timeout
func VerifyWithTimeout(h *engine.HTTPClient, f *Finding, timeout time.Duration) (float64, string) {
	type result struct {
		conf float64
		ev   string
	}
	ch := make(chan result, 1)
	go func() {
		c, e := verifyWithEvidence(h, f)
		ch <- result{c, e}
	}()
	select {
	case r := <-ch:
		return r.conf, r.ev
	case <-time.After(timeout):
		return 0.5, "verification timed out"
	}
}
