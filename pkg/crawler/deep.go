package crawler

import (
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/engine"
)

// DeepCrawl performs stateful, JS-aware crawling with form submission and SPA support
func DeepCrawl(cfg *engine.Config, h *engine.HTTPClient, targets []string) *Result {
	dc := &deepCrawler{
		cfg:     cfg,
		http:    h,
		visited: make(map[string]bool),
		result:  &Result{Params: make(map[string][]string)},
		maxDepth: 5,
	}
	if cfg.Deep {
		dc.maxDepth = 10
	}

	for _, target := range targets {
		dc.crawl(target, 0)
	}
	return dc.result
}

type deepCrawler struct {
	cfg      *engine.Config
	http     *engine.HTTPClient
	visited  map[string]bool
	result   *Result
	mu       sync.Mutex
	maxDepth int
}

func (dc *deepCrawler) crawl(targetURL string, depth int) {
	if depth > dc.maxDepth {
		return
	}
	dc.mu.Lock()
	if dc.visited[targetURL] || len(dc.visited) > 500 {
		dc.mu.Unlock()
		return
	}
	dc.visited[targetURL] = true
	dc.mu.Unlock()

	// Get page
	resp := dc.http.Get(targetURL)
	if resp.Err != nil || resp.StatusCode >= 400 {
		return
	}

	dc.mu.Lock()
	dc.result.Pages = append(dc.result.Pages, Page{URL: targetURL, StatusCode: resp.StatusCode, Size: resp.Size})
	dc.mu.Unlock()

	body := resp.Body

	// Try rendered DOM if page looks like SPA
	if isSPA(body) {
		rendered := dc.getRenderedDOM(targetURL)
		if rendered != "" {
			body = rendered
		}
	}

	// Extract links
	parsed, _ := url.Parse(targetURL)
	if parsed == nil {
		return
	}
	links := extractLinks(body, parsed)
	for _, link := range links {
		if dc.inScope(link, targetURL) {
			go dc.crawl(link, depth+1)
		}
	}

	// Extract and submit forms
	forms := extractForms(body, parsed, targetURL)
	dc.mu.Lock()
	dc.result.Forms = append(dc.result.Forms, forms...)
	dc.mu.Unlock()

	for _, form := range forms {
		dc.submitForm(form, depth)
	}

	// Extract params from URL
	for k := range parsed.Query() {
		dc.mu.Lock()
		dc.result.Params[targetURL] = appendUnique(dc.result.Params[targetURL], k)
		dc.mu.Unlock()
	}

	// Extract JS endpoints
	jsEndpoints := deepExtractJSEndpoints(body, targetURL)
	for _, ep := range jsEndpoints {
		if dc.inScope(ep, targetURL) && !dc.visited[ep] {
			go dc.crawl(ep, depth+1)
		}
	}

	// Extract params from forms
	for _, form := range forms {
		for _, input := range form.Inputs {
			if input.Name != "" {
				dc.mu.Lock()
				dc.result.Params[form.Action] = appendUnique(dc.result.Params[form.Action], input.Name)
				dc.mu.Unlock()
			}
		}
	}
}

func (dc *deepCrawler) submitForm(form Form, depth int) {
	if depth > dc.maxDepth-1 {
		return
	}
	// Build form data with test values
	values := url.Values{}
	for _, input := range form.Inputs {
		if input.Value != "" {
			values.Set(input.Name, input.Value)
		} else {
			values.Set(input.Name, getTestValue(input.Type, input.Name))
		}
	}

	var resp *engine.Response
	if strings.ToUpper(form.Method) == "POST" {
		resp = dc.http.Post(form.Action, "application/x-www-form-urlencoded", values.Encode())
	} else {
		resp = dc.http.Get(form.Action + "?" + values.Encode())
	}

	if resp.Err == nil && resp.StatusCode < 400 {
		parsed, _ := url.Parse(form.Action)
		if parsed != nil {
			newLinks := extractLinks(resp.Body, parsed)
			for _, link := range newLinks {
				if dc.inScope(link, form.Action) && !dc.visited[link] {
					dc.crawl(link, depth+1)
				}
			}
		}
	}
}

func (dc *deepCrawler) getRenderedDOM(targetURL string) string {
	paths := []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"}
	var chromePath string
	for _, p := range paths {
		if path, err := exec.LookPath(p); err == nil {
			chromePath = path
			break
		}
	}
	if chromePath == "" {
		return ""
	}
	cmd := exec.Command(chromePath, "--headless", "--disable-gpu", "--no-sandbox", "--virtual-time-budget=5000", "--dump-dom", targetURL)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(output)
}

func (dc *deepCrawler) inScope(link, base string) bool {
	parsedLink, err := url.Parse(link)
	if err != nil {
		return false
	}
	parsedBase, _ := url.Parse(base)
	if parsedBase == nil {
		return false
	}
	// Same host or subdomain
	return parsedLink.Host == parsedBase.Host || strings.HasSuffix(parsedLink.Host, "."+parsedBase.Host)
}

// --- Extraction helpers (unique to deep crawler) ---

func deepExtractJSEndpoints(body, baseURL string) []string {
	var endpoints []string
	parsed, _ := url.Parse(baseURL)
	if parsed == nil {
		return endpoints
	}
	// API paths in JS
	re := regexp.MustCompile(`["'](/api/[^"'?\s]{2,60})["']`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		endpoints = append(endpoints, parsed.Scheme+"://"+parsed.Host+m[1])
	}
	// Full URLs in JS
	urlRe := regexp.MustCompile(`["'](https?://[^"'\s]{10,100})["']`)
	for _, m := range urlRe.FindAllStringSubmatch(body, -1) {
		endpoints = append(endpoints, m[1])
	}
	// fetch/axios patterns
	fetchRe := regexp.MustCompile(`(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["']([^"']+)["']`)
	for _, m := range fetchRe.FindAllStringSubmatch(body, -1) {
		ep := m[1]
		if strings.HasPrefix(ep, "/") {
			ep = parsed.Scheme + "://" + parsed.Host + ep
		}
		if strings.HasPrefix(ep, "http") {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints
}

func isSPA(html string) bool {
	indicators := []string{"<div id=\"root\"", "<div id=\"app\"", "ng-app", "__NEXT_DATA__", "window.__NUXT__", "data-reactroot"}
	for _, ind := range indicators {
		if strings.Contains(html, ind) {
			return true
		}
	}
	return false
}

func getTestValue(inputType, name string) string {
	switch strings.ToLower(inputType) {
	case "email":
		return "test@apex.local"
	case "number":
		return "1"
	case "password":
		return "TestPass123!"
	case "tel":
		return "+1234567890"
	case "url":
		return "https://apex.local"
	}
	nameLower := strings.ToLower(name)
	if strings.Contains(nameLower, "email") {
		return "test@apex.local"
	}
	if strings.Contains(nameLower, "pass") {
		return "TestPass123!"
	}
	if strings.Contains(nameLower, "search") || strings.Contains(nameLower, "q") {
		return "test"
	}
	return "apex_test"
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
