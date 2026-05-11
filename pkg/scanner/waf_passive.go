package scanner

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- WAF Bypass Engine (12 mutation strategies) ---

type WAFMutation func(string) string

var wafMutations = []struct {
	name string
	fn   WAFMutation
}{
	{"Case Randomize", mutCaseRandomize},
	{"Double URL Encode", mutDoubleEncode},
	{"Unicode Escape", mutUnicodeEscape},
	{"Null Byte Insert", mutNullByte},
	{"Comment Injection", mutCommentInject},
	{"Whitespace Variants", mutWhitespace},
	{"Concat Split", mutConcatSplit},
	{"Hex Encode", mutHexEncode},
	{"HTML Entity", mutHTMLEntity},
	{"Tab/Newline", mutTabNewline},
	{"Overlong UTF-8", mutOverlongUTF8},
	{"Parameter Pollution", mutParamPollution},
}

func mutCaseRandomize(s string) string {
	var b strings.Builder
	for _, c := range s {
		if rand.Intn(2) == 0 {
			b.WriteRune(unicode.ToUpper(c))
		} else {
			b.WriteRune(unicode.ToLower(c))
		}
	}
	return b.String()
}

func mutDoubleEncode(s string) string {
	first := url.QueryEscape(s)
	return url.QueryEscape(first)
}

func mutUnicodeEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c == '<' {
			b.WriteString("\\u003c")
		} else if c == '>' {
			b.WriteString("\\u003e")
		} else if c == '\'' {
			b.WriteString("\\u0027")
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func mutNullByte(s string) string { return s + "%00" }

func mutCommentInject(s string) string {
	return strings.ReplaceAll(s, " ", "/**/")
}

func mutWhitespace(s string) string {
	return strings.ReplaceAll(s, " ", "\t")
}

func mutConcatSplit(s string) string {
	if strings.Contains(s, "SELECT") {
		return strings.ReplaceAll(s, "SELECT", "SEL"+"ECT")
	}
	if strings.Contains(s, "alert") {
		return strings.ReplaceAll(s, "alert", "al\\x65rt")
	}
	return s
}

func mutHexEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c == '\'' || c == '"' || c == '<' || c == '>' {
			b.WriteString(fmt.Sprintf("%%%02x", c))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func mutHTMLEntity(s string) string {
	r := strings.NewReplacer("<", "&lt;", ">", "&gt;", "'", "&#39;", "\"", "&quot;")
	return r.Replace(s)
}

func mutTabNewline(s string) string {
	return strings.ReplaceAll(s, " ", "\n")
}

func mutOverlongUTF8(s string) string {
	return strings.ReplaceAll(s, "<", "\xc0\xbc")
}

func mutParamPollution(s string) string { return s + "&" + s }

// ApplyWAFBypass takes a blocked payload and tries all 12 mutations
func ApplyWAFBypass(http *engine.HTTPClient, targetURL, param, payload string) *Finding {
	for _, mut := range wafMutations {
		mutated := mut.fn(payload)
		testURL := injectParam(targetURL, param, mutated)
		resp := http.Get(testURL)
		if resp.Err == nil && resp.StatusCode != 403 && resp.StatusCode != 429 {
			// Check if payload executed
			if strings.Contains(resp.Body, "alert") || strings.Contains(resp.Body, "49") ||
				strings.Contains(resp.Body, "root:") {
				return &Finding{
					Type: fmt.Sprintf("WAF Bypass (%s)", mut.name), Severity: "critical",
					URL: testURL, Param: param, Payload: mutated,
					Detail:   fmt.Sprintf("WAF bypassed using %s mutation strategy", mut.name),
					Template: "apex-waf-bypass",
				}
			}
		}
	}
	return nil
}

// --- Passive Scanners: JS Secrets, Source Maps, Dependency Confusion ---

var secretPatterns = map[string]*regexp.Regexp{
	"AWS Access Key":       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"AWS Secret Key":       regexp.MustCompile(`(?i)(?:aws_secret|secret_key|secretAccessKey)['":\s=]+([A-Za-z0-9/+=]{40})`),
	"Google API Key":       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"Stripe Secret":        regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
	"Stripe Publishable":   regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
	"GitHub Token":         regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`),
	"Slack Token":          regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,}`),
	"Firebase Key":         regexp.MustCompile(`(?i)apiKey['":\s]*['"]AIza[0-9A-Za-z\-_]{35}['"]`),
	"Private Key":          regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`),
	"JWT Token":            regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	"Twilio SID":           regexp.MustCompile(`AC[a-f0-9]{32}`),
	"SendGrid Key":         regexp.MustCompile(`SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`),
	"Mailgun Key":          regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
	"Heroku API Key":       regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	"OAuth Client Secret":  regexp.MustCompile(`(?i)client[_-]?secret['":\s=]+['"]([a-zA-Z0-9_\-]{20,})['"]`),
	"Internal URL":         regexp.MustCompile(`(?i)['"]https?://(?:internal|staging|dev|admin|localhost)[^'"]{5,}['"]`),
	"Base64 Credentials":   regexp.MustCompile(`(?i)(?:auth|token|cred)['":\s=]+['"]([A-Za-z0-9+/]{20,}={0,2})['"]`),
}

func scanJSSecrets(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	jsURLs := make(map[string]bool)
	for _, page := range crawl.Pages {
		if strings.HasSuffix(page.URL, ".js") || strings.Contains(page.URL, "/static/js/") ||
			strings.Contains(page.URL, "/_next/") || strings.Contains(page.URL, "/bundle") {
			jsURLs[page.URL] = true
		}
	}
	// Add common JS paths
	for _, page := range crawl.Pages[:min(3, len(crawl.Pages))] {
		parsed, _ := url.Parse(page.URL)
		if parsed == nil {
			continue
		}
		base := parsed.Scheme + "://" + parsed.Host
		for _, p := range []string{"/main.js", "/app.js", "/bundle.js", "/vendor.js",
			"/_next/static/chunks/main.js", "/static/js/main.js"} {
			jsURLs[base+p] = true
		}
	}

	for jsURL := range jsURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp := http.Get(u)
			if resp.Err != nil || resp.StatusCode != 200 || len(resp.Body) < 100 {
				return
			}
			for name, pattern := range secretPatterns {
				matches := pattern.FindAllString(resp.Body, 3)
				if len(matches) > 0 {
					// Validate — skip false positives
					if name == "Base64 Credentials" {
						decoded, err := base64.StdEncoding.DecodeString(matches[0])
						if err != nil || len(decoded) < 5 {
							continue
						}
					}
					sev := "medium"
					if strings.Contains(name, "Private") || strings.Contains(name, "Secret") ||
						strings.Contains(name, "AWS") {
						sev = "critical"
					} else if strings.Contains(name, "Token") || strings.Contains(name, "Key") {
						sev = "high"
					}
					mu.Lock()
					findings = append(findings, Finding{
						Type: "JS Secret Exposure: " + name, Severity: sev,
						URL: u, Evidence: truncateStr(matches[0], 80),
						Detail:   fmt.Sprintf("Found %d instance(s) of %s", len(matches), name),
						Template: "apex-js-secret",
					})
					mu.Unlock()
				}
			}
		}(jsURL)
	}
	wg.Wait()
	return findings
}

// --- Source Map Exposure ---

func scanSourceMaps(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for _, page := range crawl.Pages {
		if !strings.HasSuffix(page.URL, ".js") {
			continue
		}
		wg.Add(1)
		go func(jsURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			mapURL := jsURL + ".map"
			resp := http.Get(mapURL)
			if resp.Err == nil && resp.StatusCode == 200 &&
				(strings.Contains(resp.Body, "\"sources\"") || strings.Contains(resp.Body, "\"mappings\"")) {
				mu.Lock()
				findings = append(findings, Finding{
					Type: "Source Map Exposed", Severity: "medium",
					URL: mapURL, Detail: "JavaScript source map accessible — reveals original source code",
					Template: "apex-sourcemap",
				})
				mu.Unlock()
			}
		}(page.URL)
	}
	wg.Wait()
	return findings
}

// --- Dependency Confusion ---

func scanDependencyConfusion(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Look for package.json or similar manifests
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		parsed, _ := url.Parse(page.URL)
		if parsed == nil {
			continue
		}
		base := parsed.Scheme + "://" + parsed.Host
		for _, path := range []string{"/package.json", "/composer.json", "/Gemfile", "/requirements.txt"} {
			resp := http.Get(base + path)
			if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 20 {
				findings = append(findings, Finding{
					Type: "Package Manifest Exposed", Severity: "medium",
					URL: base + path, Detail: "Dependency manifest accessible — check for internal/private packages for dependency confusion",
					Template: "apex-dependency-confusion",
				})
			}
		}
	}
	return findings
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
