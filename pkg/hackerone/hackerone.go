package hackerone

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Program represents a HackerOne program's scope
type Program struct {
	Handle    string   `json:"handle"`
	InScope   []Asset  `json:"in_scope"`
	OutScope  []Asset  `json:"out_scope"`
	MaxBounty int      `json:"max_bounty,omitempty"`
	Updated   time.Time `json:"updated"`
}

type Asset struct {
	Type       string `json:"type"` // URL, WILDCARD, CIDR, APP
	Identifier string `json:"identifier"`
}

// Report formats a finding for HackerOne submission
type Report struct {
	Title           string `json:"title"`
	VulnType        string `json:"weakness"`
	Severity        string `json:"severity_rating"`
	Description     string `json:"description"`
	Impact          string `json:"impact"`
	StepsToReproduce string `json:"steps_to_reproduce"`
	POC             string `json:"poc,omitempty"`
}

// ValidateScope checks if a target URL is in-scope for a program
func ValidateScope(target string, program *Program) (bool, string) {
	if program == nil {
		return true, ""
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return false, "invalid URL"
	}
	host := parsed.Hostname()

	// Check out-of-scope first (takes priority)
	for _, asset := range program.OutScope {
		if matchAsset(host, asset) {
			return false, fmt.Sprintf("out-of-scope: matches %s", asset.Identifier)
		}
	}

	// Check in-scope
	for _, asset := range program.InScope {
		if matchAsset(host, asset) {
			return true, ""
		}
	}
	return false, "not in program scope"
}

func matchAsset(host string, asset Asset) bool {
	id := strings.ToLower(asset.Identifier)
	host = strings.ToLower(host)

	switch asset.Type {
	case "URL":
		// Extract host from URL identifier
		if parsed, err := url.Parse(id); err == nil {
			id = parsed.Hostname()
		}
		return host == id
	case "WILDCARD":
		// *.example.com matches sub.example.com
		id = strings.TrimPrefix(id, "*.")
		return host == id || strings.HasSuffix(host, "."+id)
	default:
		return strings.Contains(host, id)
	}
}

// FormatReport converts a scanner finding into H1 report format
func FormatReport(vulnType, severity, targetURL, param, payload, evidence string) Report {
	title := fmt.Sprintf("%s on %s", vulnType, extractHost(targetURL))
	if param != "" {
		title = fmt.Sprintf("%s via `%s` parameter on %s", vulnType, param, extractHost(targetURL))
	}

	impact := severityImpact(severity)
	steps := formatSteps(targetURL, param, payload)

	return Report{
		Title:            title,
		VulnType:         mapToH1Weakness(vulnType),
		Severity:         mapToH1Severity(severity),
		Description:      fmt.Sprintf("A %s vulnerability was identified at `%s`.", vulnType, targetURL),
		Impact:           impact,
		StepsToReproduce: steps,
		POC:              formatPOC(targetURL, param, payload, evidence),
	}
}

// LoadProgram loads a saved program scope from disk
func LoadProgram(handle string) *Program {
	path := filepath.Join(programDir(), handle+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var p Program
	if json.Unmarshal(data, &p) != nil {
		return nil
	}
	return &p
}

// SaveProgram persists program scope
func SaveProgram(p *Program) error {
	dir := programDir()
	os.MkdirAll(dir, 0755)
	p.Updated = time.Now()
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, p.Handle+".json"), data, 0644)
}

func programDir() string {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}
	return filepath.Join(home, ".apex-cache", "programs")
}

func extractHost(rawURL string) string {
	if parsed, err := url.Parse(rawURL); err == nil {
		return parsed.Host
	}
	return rawURL
}

func mapToH1Severity(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func mapToH1Weakness(vulnType string) string {
	vt := strings.ToLower(vulnType)
	switch {
	case strings.Contains(vt, "sql"):
		return "SQL Injection"
	case strings.Contains(vt, "xss") || strings.Contains(vt, "cross-site scripting"):
		return "Cross-site Scripting (XSS) - Reflected"
	case strings.Contains(vt, "ssrf"):
		return "Server-Side Request Forgery (SSRF)"
	case strings.Contains(vt, "command") || strings.Contains(vt, "cmdi"):
		return "OS Command Injection"
	case strings.Contains(vt, "ssti"):
		return "Server-Side Template Injection"
	case strings.Contains(vt, "lfi") || strings.Contains(vt, "file inclusion"):
		return "Path Traversal"
	case strings.Contains(vt, "idor"):
		return "Insecure Direct Object Reference (IDOR)"
	case strings.Contains(vt, "redirect"):
		return "Open Redirect"
	case strings.Contains(vt, "cors"):
		return "CORS Misconfiguration"
	case strings.Contains(vt, "csrf"):
		return "Cross-Site Request Forgery (CSRF)"
	default:
		return "Other"
	}
}

func severityImpact(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "An attacker can fully compromise the application, access sensitive data, or execute arbitrary code on the server."
	case "high":
		return "An attacker can access unauthorized data or perform actions on behalf of other users."
	case "medium":
		return "An attacker can leverage this to escalate attacks or access limited sensitive information."
	default:
		return "This issue provides information that could aid further attacks."
	}
}

func formatSteps(targetURL, param, payload string) string {
	var sb strings.Builder
	sb.WriteString("1. Navigate to the target URL\n")
	if param != "" && payload != "" {
		sb.WriteString(fmt.Sprintf("2. Inject the following payload in the `%s` parameter:\n", param))
		sb.WriteString(fmt.Sprintf("   ```\n   %s\n   ```\n", payload))
		sb.WriteString("3. Observe the vulnerable behavior in the response\n")
	} else {
		sb.WriteString(fmt.Sprintf("2. Send a request to: `%s`\n", targetURL))
		sb.WriteString("3. Observe the vulnerable behavior\n")
	}
	return sb.String()
}

func formatPOC(targetURL, param, payload, evidence string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**URL:** `%s`\n\n", targetURL))
	if param != "" {
		sb.WriteString(fmt.Sprintf("**Parameter:** `%s`\n\n", param))
	}
	if payload != "" {
		sb.WriteString(fmt.Sprintf("**Payload:**\n```\n%s\n```\n\n", payload))
	}
	if evidence != "" {
		sb.WriteString(fmt.Sprintf("**Evidence:**\n```\n%s\n```\n", evidence))
	}
	return sb.String()
}
