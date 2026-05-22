package reporter

import (
	"fmt"
	"net/url"
	"strings"
)

// GenerateH1Report creates a ready-to-paste HackerOne report from a finding
func GenerateH1Report(vulnType, severity, targetURL, param, payload, evidence, detail string) string {
	var sb strings.Builder

	title := generateTitle(vulnType, targetURL, param)
	sb.WriteString(fmt.Sprintf("## Title\n%s\n\n", title))
	sb.WriteString(fmt.Sprintf("## Severity\n%s\n\n", strings.Title(severity)))
	sb.WriteString("## Summary\n")
	sb.WriteString(generateSummary(vulnType, targetURL, param) + "\n\n")
	sb.WriteString("## Steps to Reproduce\n")
	sb.WriteString(generateSteps(vulnType, targetURL, param, payload) + "\n\n")
	sb.WriteString("## PoC\n")
	sb.WriteString(generateCurlPoC(targetURL, param, payload) + "\n\n")
	if evidence != "" {
		sb.WriteString("## Evidence\n```\n" + evidence + "\n```\n\n")
	}
	sb.WriteString("## Impact\n")
	sb.WriteString(generateImpact(vulnType, severity) + "\n")

	return sb.String()
}

func generateTitle(vulnType, targetURL, param string) string {
	host := extractHost(targetURL)
	if param != "" {
		return fmt.Sprintf("%s via `%s` parameter on %s", vulnType, param, host)
	}
	return fmt.Sprintf("%s on %s", vulnType, host)
}

func generateSummary(vulnType, targetURL, param string) string {
	host := extractHost(targetURL)
	vt := strings.ToLower(vulnType)

	switch {
	case strings.Contains(vt, "sql"):
		return fmt.Sprintf("A SQL Injection vulnerability exists at `%s` that allows an attacker to extract, modify, or delete data from the backend database.", host)
	case strings.Contains(vt, "xss"):
		return fmt.Sprintf("A Cross-Site Scripting vulnerability at `%s` allows an attacker to execute arbitrary JavaScript in the context of a victim's browser session, potentially stealing session tokens or performing actions on their behalf.", host)
	case strings.Contains(vt, "ssrf"):
		return fmt.Sprintf("A Server-Side Request Forgery vulnerability at `%s` allows an attacker to make the server perform requests to internal services, potentially accessing cloud metadata credentials or internal APIs.", host)
	case strings.Contains(vt, "command") || strings.Contains(vt, "cmdi"):
		return fmt.Sprintf("An OS Command Injection vulnerability at `%s` allows an attacker to execute arbitrary system commands on the server, leading to full system compromise.", host)
	case strings.Contains(vt, "idor"):
		return fmt.Sprintf("An Insecure Direct Object Reference at `%s` allows an attacker to access or modify resources belonging to other users by manipulating object identifiers.", host)
	case strings.Contains(vt, "takeover"):
		return fmt.Sprintf("A subdomain takeover vulnerability exists on `%s` where a DNS record points to an unclaimed external service. An attacker can claim this service and serve malicious content on the organization's subdomain.", host)
	case strings.Contains(vt, "ssti"):
		return fmt.Sprintf("A Server-Side Template Injection at `%s` allows an attacker to inject template directives that execute on the server, potentially leading to Remote Code Execution.", host)
	default:
		return fmt.Sprintf("A %s vulnerability was identified at `%s` that could be exploited by an attacker to compromise the security of the application and its users.", vulnType, host)
	}
}

func generateSteps(vulnType, targetURL, param, payload string) string {
	var sb strings.Builder
	sb.WriteString("1. Navigate to the target endpoint\n")

	if payload != "" && param != "" {
		sb.WriteString(fmt.Sprintf("2. Inject the following payload in the `%s` parameter:\n", param))
		sb.WriteString(fmt.Sprintf("```\n%s\n```\n", payload))
		sb.WriteString("3. Observe the vulnerable behavior in the response\n")
		sb.WriteString("4. Run the curl command below to reproduce:\n")
	} else if targetURL != "" {
		sb.WriteString(fmt.Sprintf("2. Access the following URL:\n```\n%s\n```\n", targetURL))
		sb.WriteString("3. Observe the vulnerable response\n")
	}
	return sb.String()
}

func generateCurlPoC(targetURL, param, payload string) string {
	if targetURL == "" {
		return ""
	}
	// Escape single quotes in the URL for shell
	escaped := strings.ReplaceAll(targetURL, "'", "'\\''")
	return fmt.Sprintf("```bash\ncurl -sk '%s' -H 'X-HackerOne-Bugbounty: HackerOne-YOUR_USERNAME'\n```", escaped)
}

func generateImpact(vulnType, severity string) string {
	vt := strings.ToLower(vulnType)
	switch {
	case strings.Contains(vt, "sql"):
		return "An attacker can extract sensitive data from the database including user credentials, personal information, and financial data. In some cases, this can be escalated to Remote Code Execution via database functions (e.g., `xp_cmdshell`, `INTO OUTFILE`)."
	case strings.Contains(vt, "xss"):
		return "An attacker can steal session cookies, redirect users to phishing pages, modify page content, or perform actions on behalf of authenticated users. This can lead to full account takeover."
	case strings.Contains(vt, "ssrf"):
		return "An attacker can access internal services, read cloud metadata credentials (AWS IAM keys, GCP service accounts), scan internal networks, and potentially pivot to other internal systems."
	case strings.Contains(vt, "command") || strings.Contains(vt, "cmdi"):
		return "An attacker can execute arbitrary commands on the server with the privileges of the web application. This leads to full server compromise, data exfiltration, and lateral movement."
	case strings.Contains(vt, "idor"):
		return "An attacker can access, modify, or delete data belonging to other users. On a financial platform, this could mean accessing other users' transactions, balances, or personal information."
	case strings.Contains(vt, "takeover"):
		return "An attacker can serve arbitrary content on the organization's subdomain. This enables: phishing attacks with a trusted domain, cookie theft (if cookies are scoped to parent domain), and bypassing CSP/CORS restrictions."
	case strings.Contains(vt, "ssti"):
		return "An attacker can execute arbitrary code on the server through template injection. This typically leads to Remote Code Execution and full server compromise."
	default:
		if severity == "critical" {
			return "This vulnerability allows an attacker to fully compromise the application, access sensitive data, or execute arbitrary code."
		}
		return "This vulnerability can be leveraged by an attacker to access unauthorized data or perform actions that impact the security of the application and its users."
	}
}

func extractHost(rawURL string) string {
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Host != "" {
		return parsed.Host
	}
	return rawURL
}
