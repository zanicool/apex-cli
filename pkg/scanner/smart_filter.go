package scanner

import (
	"strings"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
)

// SmartFilter decides which scanners to run based on target fingerprint
type SmartFilter struct {
	tech       map[string]bool // detected technologies
	hasAuth    bool            // has login/register
	hasAPI     bool            // has API endpoints
	hasGraphQL bool            // has GraphQL
	hasForms   bool            // has forms
	hasUpload  bool            // has file upload
	hasWS      bool            // has WebSocket
	waf        string          // detected WAF
	framework  string          // detected framework
}

// AnalyzeTarget fingerprints the target and returns which scanner categories to run
func AnalyzeTarget(h *engine.HTTPClient, crawl *crawler.Result) *SmartFilter {
	sf := &SmartFilter{tech: make(map[string]bool)}

	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		resp := h.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		body := strings.ToLower(resp.Body)
		headers := resp.Headers

		// Detect framework
		if strings.Contains(body, "wp-content") || strings.Contains(body, "wordpress") {
			sf.tech["wordpress"] = true
			sf.framework = "WordPress"
		}
		if strings.Contains(body, "__next") || strings.Contains(body, "_next/static") {
			sf.tech["nextjs"] = true
			sf.framework = "Next.js"
		}
		if strings.Contains(body, "ng-app") || strings.Contains(body, "angular") {
			sf.tech["angular"] = true
			sf.framework = "Angular"
		}
		if strings.Contains(body, "__nuxt") || strings.Contains(body, "nuxt") {
			sf.tech["nuxt"] = true
			sf.framework = "Nuxt"
		}
		if strings.Contains(body, "react") || strings.Contains(body, "reactroot") {
			sf.tech["react"] = true
		}
		if headers.Get("X-Powered-By") != "" {
			powered := strings.ToLower(headers.Get("X-Powered-By"))
			if strings.Contains(powered, "php") {
				sf.tech["php"] = true
			}
			if strings.Contains(powered, "express") {
				sf.tech["nodejs"] = true
			}
			if strings.Contains(powered, "asp") {
				sf.tech["aspnet"] = true
			}
		}
		if strings.Contains(headers.Get("Server"), "nginx") {
			sf.tech["nginx"] = true
		}
		if strings.Contains(headers.Get("Server"), "Apache") {
			sf.tech["apache"] = true
		}

		// Detect features
		if strings.Contains(body, "login") || strings.Contains(body, "signin") || strings.Contains(body, "register") {
			sf.hasAuth = true
		}
		if strings.Contains(page.URL, "/api/") || strings.Contains(body, "/api/") {
			sf.hasAPI = true
		}
		if strings.Contains(body, "graphql") || strings.Contains(body, "__schema") {
			sf.hasGraphQL = true
		}
		if strings.Contains(body, "upload") || strings.Contains(body, "multipart") {
			sf.hasUpload = true
		}
		if strings.Contains(body, "websocket") || strings.Contains(body, "socket.io") || strings.Contains(body, "ws://") {
			sf.hasWS = true
		}

		// WAF detection
		if strings.Contains(headers.Get("Server"), "cloudflare") {
			sf.waf = "Cloudflare"
		}
	}

	sf.hasForms = len(crawl.Forms) > 0
	return sf
}

// ShouldRunScanner returns true if a scanner is relevant for this target
func (sf *SmartFilter) ShouldRunScanner(name string) bool {
	nameLower := strings.ToLower(name)

	// Always run these
	alwaysRun := []string{"security header", "cors", "clickjacking", "js secret", "content discovery", "subdomain", "cloud", "backup", "git", "header"}
	for _, a := range alwaysRun {
		if strings.Contains(nameLower, a) {
			return true
		}
	}

	// Only run if target has forms
	if strings.Contains(nameLower, "stored xss") || strings.Contains(nameLower, "csrf") || strings.Contains(nameLower, "email") || strings.Contains(nameLower, "csv") {
		return sf.hasForms
	}

	// Only run if target has auth
	if strings.Contains(nameLower, "jwt") || strings.Contains(nameLower, "oauth") || strings.Contains(nameLower, "password reset") || strings.Contains(nameLower, "2fa") || strings.Contains(nameLower, "session") || strings.Contains(nameLower, "account") || strings.Contains(nameLower, "auth") {
		return sf.hasAuth
	}

	// Only run if target has GraphQL
	if strings.Contains(nameLower, "graphql") {
		return sf.hasGraphQL
	}

	// Only run if target has file upload
	if strings.Contains(nameLower, "file upload") {
		return sf.hasUpload
	}

	// Only run if target has WebSocket
	if strings.Contains(nameLower, "websocket") {
		return sf.hasWS
	}

	// Only run PHP-specific if PHP detected
	if strings.Contains(nameLower, "php") || strings.Contains(nameLower, "deserialization") {
		return sf.tech["php"] || sf.tech["aspnet"]
	}

	// Run everything else
	return true
}

// PrioritizeParams sorts params by likelihood of being injectable
func PrioritizeParams(params map[string][]string) map[string][]string {
	prioritized := make(map[string][]string)

	for u, ps := range params {
		// Skip static assets entirely
		if isStaticAsset(u) {
			continue
		}

		var high, low []string
		for _, p := range ps {
			pLower := strings.ToLower(p)
			// High priority: params that commonly accept user input
			if isHighPriorityParam(pLower) {
				high = append(high, p)
			} else {
				low = append(low, p)
			}
		}
		// Put high priority first, cap at 20 params per URL
		combined := append(high, low...)
		if len(combined) > 20 {
			combined = combined[:20]
		}
		if len(combined) > 0 {
			prioritized[u] = combined
		}
	}
	return prioritized
}

func isHighPriorityParam(p string) bool {
	highPriority := []string{"url", "uri", "redirect", "next", "return", "callback", "path", "file", "page", "id", "user", "email", "search", "q", "query", "name", "cmd", "exec", "template", "include", "src", "dest", "target", "data", "input", "value", "content"}
	for _, hp := range highPriority {
		if strings.Contains(p, hp) {
			return true
		}
	}
	return false
}

func isStaticAsset(u string) bool {
	exts := []string{".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico", ".map", ".ttf", ".eot"}
	uLower := strings.ToLower(u)
	for _, ext := range exts {
		if strings.HasSuffix(uLower, ext) || strings.Contains(uLower, ext+"?") {
			return true
		}
	}
	return false
}
