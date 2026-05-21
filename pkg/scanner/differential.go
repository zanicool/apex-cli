package scanner

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// scanDifferential sends the same request with varied headers/methods to find access control bugs
func scanDifferential(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}

	// Focus on endpoints likely to have access control
	var targets []string
	for _, page := range crawl.Pages {
		lower := strings.ToLower(page.URL)
		if strings.Contains(lower, "/api/") || strings.Contains(lower, "/admin") ||
			strings.Contains(lower, "/user") || strings.Contains(lower, "/internal") ||
			strings.Contains(lower, "/manage") || strings.Contains(lower, "/dashboard") {
			targets = append(targets, page.URL)
		}
	}
	if len(targets) == 0 {
		for _, p := range crawl.Pages[:min(10, len(crawl.Pages))] {
			targets = append(targets, p.URL)
		}
	}

	for _, target := range targets[:min(20, len(targets))] {
		// Get baseline
		baseline := h.Get(target)
		if baseline.Err != nil {
			continue
		}

		// Test 1: IP header spoofing (bypass IP-based auth)
		if baseline.StatusCode == 403 || baseline.StatusCode == 401 {
			findings = append(findings, diffIPHeaders(h, target, baseline)...)
		}

		// Test 2: Method tampering on restricted endpoints
		if baseline.StatusCode == 403 || baseline.StatusCode == 405 {
			findings = append(findings, diffMethods(h, target, baseline)...)
		}

		// Test 3: User-Agent differential (mobile vs desktop access)
		findings = append(findings, diffUserAgent(h, target, baseline)...)

		// Test 4: Path manipulation to bypass access control
		if baseline.StatusCode == 403 || baseline.StatusCode == 401 {
			findings = append(findings, diffPathBypass(h, target)...)
		}
	}
	return findings
}

func diffIPHeaders(h *engine.HTTPClient, target string, baseline *engine.Response) []Finding {
	var findings []Finding
	ipHeaders := map[string]string{
		"X-Forwarded-For":   "127.0.0.1",
		"X-Real-IP":         "127.0.0.1",
		"X-Originating-IP":  "127.0.0.1",
		"X-Client-IP":       "127.0.0.1",
		"X-Custom-IP-Authorization": "127.0.0.1",
		"X-Forwarded-Host":  "localhost",
		"True-Client-IP":    "127.0.0.1",
	}
	for header, value := range ipHeaders {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set(header, value)
		resp := h.Do(req)
		if resp.Err == nil && resp.StatusCode == 200 && baseline.StatusCode != 200 {
			findings = append(findings, Finding{
				Type: "Access Control Bypass via IP Header", Severity: "high",
				URL: target, Payload: fmt.Sprintf("%s: %s", header, value),
				Detail:   fmt.Sprintf("403 → 200 with %s header. Server trusts client-supplied IP.", header),
				Template: "apex-ip-bypass",
			})
			break
		}
	}
	return findings
}

func diffMethods(h *engine.HTTPClient, target string, baseline *engine.Response) []Finding {
	var findings []Finding
	methods := []string{"PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT"}
	for _, method := range methods {
		req, _ := http.NewRequest(method, target, nil)
		resp := h.Do(req)
		if resp.Err == nil && resp.StatusCode == 200 && baseline.StatusCode >= 400 {
			findings = append(findings, Finding{
				Type: "HTTP Method Bypass", Severity: "high",
				URL: target, Payload: method,
				Detail:   fmt.Sprintf("%d → 200 with %s method", baseline.StatusCode, method),
				Template: "apex-method-bypass",
			})
			break
		}
	}
	return findings
}

func diffUserAgent(h *engine.HTTPClient, target string, baseline *engine.Response) []Finding {
	var findings []Finding
	agents := map[string]string{
		"mobile":  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
		"bot":     "Googlebot/2.1 (+http://www.google.com/bot.html)",
		"curl":    "curl/8.0",
		"empty":   "",
	}
	for name, ua := range agents {
		req, _ := http.NewRequest("GET", target, nil)
		req.Header.Set("User-Agent", ua)
		resp := h.Do(req)
		if resp.Err != nil {
			continue
		}
		// Significant size difference = different content served
		sizeDiff := resp.Size - baseline.Size
		if sizeDiff > 500 || sizeDiff < -500 {
			// Check if more sensitive data is exposed
			if resp.Size > baseline.Size+200 {
				findings = append(findings, Finding{
					Type: "Response Differential: User-Agent", Severity: "medium",
					URL: target, Payload: fmt.Sprintf("User-Agent: %s (%s)", name, ua),
					Detail:   fmt.Sprintf("Different content served to %s UA (size diff: %+d bytes)", name, sizeDiff),
					Template: "apex-ua-diff",
				})
				break
			}
		}
		// Status code difference
		if resp.StatusCode != baseline.StatusCode && resp.StatusCode == 200 {
			findings = append(findings, Finding{
				Type: "Access Control Bypass via User-Agent", Severity: "high",
				URL: target, Payload: ua,
				Detail:   fmt.Sprintf("%d → 200 with %s User-Agent", baseline.StatusCode, name),
				Template: "apex-ua-bypass",
			})
			break
		}
	}
	return findings
}

func diffPathBypass(h *engine.HTTPClient, target string) []Finding {
	var findings []Finding
	// Path manipulation techniques to bypass 403
	mutations := []struct {
		name    string
		mutate  func(string) string
	}{
		{"trailing dot", func(u string) string { return u + "." }},
		{"double slash", func(u string) string { return strings.Replace(u, "//", "///", 1) }},
		{"path traversal", func(u string) string {
			parts := strings.SplitN(u, "?", 2)
			return parts[0] + "/..;/" + parts[0][strings.LastIndex(parts[0], "/")+1:]
		}},
		{"url encode", func(u string) string {
			parts := strings.SplitN(u, "?", 2)
			path := parts[0]
			lastSlash := strings.LastIndex(path, "/")
			if lastSlash < 0 { return u }
			return path[:lastSlash] + "/%2e/" + path[lastSlash+1:]
		}},
		{"case swap", func(u string) string {
			parts := strings.SplitN(u, "?", 2)
			path := parts[0]
			lastSlash := strings.LastIndex(path, "/")
			if lastSlash < 0 { return u }
			segment := path[lastSlash+1:]
			swapped := strings.ToUpper(segment[:1]) + segment[1:]
			return path[:lastSlash+1] + swapped
		}},
		{"add extension", func(u string) string { return u + ".json" }},
		{"null byte", func(u string) string { return u + "%00" }},
		{"semicolon", func(u string) string { return u + ";.css" }},
	}

	for _, m := range mutations {
		mutated := m.mutate(target)
		if mutated == target {
			continue
		}
		resp := h.Get(mutated)
		if resp.Err == nil && resp.StatusCode == 200 {
			findings = append(findings, Finding{
				Type: "403 Bypass via Path Manipulation", Severity: "high",
				URL: mutated, Payload: m.name,
				Detail:   fmt.Sprintf("403 bypassed using %s technique", m.name),
				Template: "apex-403-bypass",
			})
			break
		}
	}
	return findings
}
