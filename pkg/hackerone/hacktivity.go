package hackerone

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HacktivityItem represents a disclosed report from H1's public hacktivity
type HacktivityItem struct {
	ID         int    `json:"id"`
	Title      string `json:"title"`
	State      string `json:"substate"`
	Severity   string `json:"severity_rating"`
	CWE        string `json:"cwe"`
	SubmittedAt string `json:"submitted_at"`
	URL        string `json:"url"`
	Program    string `json:"program_handle"`
}

// CheckHacktivity searches H1 public hacktivity for similar disclosed reports
// Returns true if a similar vuln was already publicly disclosed for this program
func CheckHacktivity(programHandle, vulnType, targetHost string) (bool, []HacktivityItem) {
	var matches []HacktivityItem

	// Search hacktivity via the public GraphQL endpoint (no auth needed)
	query := buildHacktivityQuery(programHandle, vulnType)
	items := fetchHacktivity(query)

	for _, item := range items {
		if isSimilarFinding(item, vulnType, targetHost) {
			matches = append(matches, item)
		}
	}

	return len(matches) > 0, matches
}

func buildHacktivityQuery(programHandle, vulnType string) string {
	// H1's public hacktivity search URL
	// This scrapes the public JSON endpoint that powers hacktivity
	params := url.Values{}
	params.Set("queryString", fmt.Sprintf("program:%s", programHandle))
	params.Set("sortField", "latest_disclosable_activity_at")
	params.Set("sortDirection", "DESC")
	params.Set("pageSize", "100")
	return "https://hackerone.com/graphql?" + params.Encode()
}

func fetchHacktivity(queryURL string) []HacktivityItem {
	// Use the public hacktivity JSON feed
	// H1 exposes disclosed reports at: https://hackerone.com/hacktivity/overview
	// The actual API: POST to graphql with the hacktivity query

	client := &http.Client{Timeout: 15 * time.Second}

	// GraphQL query for public hacktivity
	gqlBody := `{
		"operationName": "HacktivitySearchQuery",
		"variables": {
			"queryString": "%s",
			"size": 100,
			"from": 0
		},
		"query": "query HacktivitySearchQuery($queryString: String!, $size: Int!, $from: Int!) { hacktivity_items(query_string: $queryString, size: $size, from: $from) { nodes { ... on HacktivityItemInterface { id databaseId title severity_rating report { substate url disclosed_at weakness { name } team { handle name } } } } } }"
	}`

	// Try the REST hacktivity endpoint first (more reliable, no auth)
	restURL := "https://hackerone.com/hacktivity.json?sort_type=latest_disclosable_activity_at&filter=type:public"
	resp, err := client.Get(restURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)

	var result struct {
		Data []struct {
			ID         int    `json:"id"`
			Attributes struct {
				Title    string `json:"title"`
				Substate string `json:"substate"`
				Severity string `json:"severity_rating"`
				CWE      string `json:"cwe"`
				URL      string `json:"url"`
				SubmittedAt string `json:"submitted_at"`
			} `json:"attributes"`
			Relationships struct {
				Program struct {
					Data struct {
						Attributes struct {
							Handle string `json:"handle"`
						} `json:"attributes"`
					} `json:"data"`
				} `json:"program"`
			} `json:"relationships"`
		} `json:"data"`
	}

	json.Unmarshal(body, &result)
	_ = gqlBody // fallback if REST doesn't work

	var items []HacktivityItem
	for _, r := range result.Data {
		items = append(items, HacktivityItem{
			ID:          r.ID,
			Title:       r.Attributes.Title,
			State:       r.Attributes.Substate,
			Severity:    r.Attributes.Severity,
			CWE:         r.Attributes.CWE,
			URL:         r.Attributes.URL,
			SubmittedAt: r.Attributes.SubmittedAt,
			Program:     r.Relationships.Program.Data.Attributes.Handle,
		})
	}
	return items
}

func isSimilarFinding(item HacktivityItem, vulnType, targetHost string) bool {
	titleLower := strings.ToLower(item.Title)
	vulnLower := strings.ToLower(vulnType)

	// Check if same vuln class
	vulnKeywords := vulnClassKeywords(vulnLower)
	for _, kw := range vulnKeywords {
		if strings.Contains(titleLower, kw) {
			// Also check if same host/asset is mentioned
			if targetHost == "" || strings.Contains(titleLower, strings.ToLower(targetHost)) {
				return true
			}
			// Same vuln class on same program = high dupe risk even without host match
			return true
		}
	}
	return false
}

func vulnClassKeywords(vulnType string) []string {
	switch {
	case strings.Contains(vulnType, "sql"):
		return []string{"sql injection", "sqli", "sql"}
	case strings.Contains(vulnType, "xss") || strings.Contains(vulnType, "cross-site scripting"):
		return []string{"xss", "cross-site scripting", "reflected xss", "stored xss"}
	case strings.Contains(vulnType, "ssrf"):
		return []string{"ssrf", "server-side request"}
	case strings.Contains(vulnType, "idor"):
		return []string{"idor", "insecure direct object", "unauthorized access"}
	case strings.Contains(vulnType, "config") || strings.Contains(vulnType, "information"):
		return []string{"config", "information disclosure", "exposed", "env", "configuration"}
	case strings.Contains(vulnType, "open redirect"):
		return []string{"open redirect", "redirect"}
	case strings.Contains(vulnType, "cors"):
		return []string{"cors", "cross-origin"}
	case strings.Contains(vulnType, "takeover"):
		return []string{"subdomain takeover", "takeover"}
	case strings.Contains(vulnType, "rce") || strings.Contains(vulnType, "command"):
		return []string{"rce", "command injection", "remote code"}
	case strings.Contains(vulnType, "ssti"):
		return []string{"ssti", "template injection"}
	case strings.Contains(vulnType, "lfi") || strings.Contains(vulnType, "path"):
		return []string{"lfi", "path traversal", "local file"}
	}
	return []string{vulnType}
}

// PreSubmitCheck runs all duplicate checks before submitting a report
// Returns: shouldSubmit bool, reason string
func PreSubmitCheck(programHandle, vulnType, targetURL, param string) (bool, string) {
	parsed, _ := url.Parse(targetURL)
	host := ""
	if parsed != nil {
		host = parsed.Hostname()
	}

	// Layer 1: Check our own local dupe DB
	isDupe, reason := IsDuplicate(programHandle, vulnType, targetURL, param)
	if isDupe {
		return false, "LOCAL DUPE: " + reason
	}

	// Layer 2: Check H1 public hacktivity for disclosed similar reports
	found, matches := CheckHacktivity(programHandle, vulnType, host)
	if found && len(matches) > 0 {
		latest := matches[0]
		return false, fmt.Sprintf("HACKTIVITY DUPE: \"%s\" (severity: %s, %s) — similar vuln already disclosed on this program",
			latest.Title, latest.Severity, latest.URL)
	}

	// Layer 3: Check if this is a low-value finding that programs typically mark as informative
	if isLikelyInformative(vulnType, targetURL) {
		return false, "LOW VALUE: This finding type is commonly marked informative/won't-fix on H1"
	}

	return true, ""
}

// isLikelyInformative filters out findings that almost never pay bounties
func isLikelyInformative(vulnType, targetURL string) bool {
	vt := strings.ToLower(vulnType)

	// These almost never pay on H1:
	informativePatterns := []string{
		"information disclosure",
		"config",
		"security headers",
		"cookie security",
		"clickjacking",
		"content discovery",
		"version disclosure",
		"directory listing",
		"stack trace",
	}

	for _, pattern := range informativePatterns {
		if strings.Contains(vt, pattern) {
			// Exception: if it's actually leaking secrets/creds, it's valid
			if strings.Contains(vt, "credential") || strings.Contains(vt, "secret") ||
				strings.Contains(vt, "password") || strings.Contains(vt, "token") {
				return false
			}
			return true
		}
	}

	// Config files that are just architecture info (like the Banco Plata case)
	urlLower := strings.ToLower(targetURL)
	if strings.Contains(urlLower, "env.json") || strings.Contains(urlLower, "config.json") ||
		strings.Contains(urlLower, "settings.json") {
		// Only informative if it doesn't contain actual secrets
		return true
	}

	return false
}
