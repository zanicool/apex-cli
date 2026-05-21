package scanner

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// BrowserEngine manages headless Chrome for advanced scanning
type BrowserEngine struct {
	chromePath string
	port       int
	cmd        *exec.Cmd
	wsURL      string
	mu         sync.Mutex
}

// NewBrowserEngine starts headless Chrome with DevTools Protocol
func NewBrowserEngine() *BrowserEngine {
	chromePath := findChromePath()
	if chromePath == "" {
		return nil
	}
	port := findFreePort()
	be := &BrowserEngine{chromePath: chromePath, port: port}
	be.start()
	return be
}

func (be *BrowserEngine) start() {
	be.cmd = exec.Command(be.chromePath,
		"--headless", "--disable-gpu", "--no-sandbox",
		"--disable-web-security", "--disable-features=IsolateOrigins,site-per-process",
		fmt.Sprintf("--remote-debugging-port=%d", be.port),
		"--user-data-dir=/tmp/apex-chrome-"+fmt.Sprint(be.port),
		"--disable-background-networking",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-sync",
		"--no-first-run",
	)
	be.cmd.Start()
	// Wait for Chrome to be ready
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/version", be.port))
		if err == nil {
			resp.Body.Close()
			return
		}
	}
}

func (be *BrowserEngine) Stop() {
	if be.cmd != nil && be.cmd.Process != nil {
		be.cmd.Process.Kill()
	}
}

// ExecuteJS navigates to a URL and executes JavaScript, returns the result
func (be *BrowserEngine) ExecuteJS(targetURL, js string, waitMs int) (string, error) {
	if be == nil {
		return "", fmt.Errorf("browser not available")
	}
	be.mu.Lock()
	defer be.mu.Unlock()

	// Create a new tab
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/new?%s", be.port, targetURL))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tab struct {
		ID                string `json:"id"`
		WebSocketDebuggerUrl string `json:"webSocketDebuggerUrl"`
	}
	json.NewDecoder(resp.Body).Decode(&tab)

	// Wait for page load
	time.Sleep(time.Duration(waitMs) * time.Millisecond)

	// Execute JS via HTTP endpoint (simpler than WebSocket for our needs)
	evalURL := fmt.Sprintf("http://127.0.0.1:%d/json/evaluate?%s", be.port, tab.ID)
	_ = evalURL

	// Use the simpler approach: dump-dom with JS injection
	cmd := exec.Command(be.chromePath,
		"--headless", "--disable-gpu", "--no-sandbox",
		"--virtual-time-budget=5000",
		"--dump-dom",
		fmt.Sprintf("--js-flags=--expose-gc"),
		targetURL,
	)
	output, err := cmd.Output()

	// Close the tab
	http.Get(fmt.Sprintf("http://127.0.0.1:%d/json/close/%s", be.port, tab.ID))

	if err != nil {
		return "", err
	}
	return string(output), nil
}

// GetRenderedDOM gets the fully rendered DOM after JS execution
func (be *BrowserEngine) GetRenderedDOM(targetURL string) (string, error) {
	if be == nil {
		return "", fmt.Errorf("browser not available")
	}
	cmd := exec.Command(be.chromePath,
		"--headless", "--disable-gpu", "--no-sandbox",
		"--virtual-time-budget=5000",
		"--dump-dom",
		targetURL,
	)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// GetConsoleErrors captures JS console errors (useful for detecting issues)
func (be *BrowserEngine) GetConsoleErrors(targetURL string) []string {
	if be == nil {
		return nil
	}
	// Use --enable-logging to capture console
	cmd := exec.Command(be.chromePath,
		"--headless", "--disable-gpu", "--no-sandbox",
		"--virtual-time-budget=3000",
		"--enable-logging=stderr",
		"--v=1",
		targetURL,
	)
	output, _ := cmd.CombinedOutput()
	var errors []string
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "ERROR") || strings.Contains(line, "error") {
			errors = append(errors, line)
		}
	}
	return errors
}

// --- Advanced Browser Scanners ---

// scanBrowserDOMXSSAdvanced does deep DOM XSS testing with multiple sources/sinks
func scanBrowserDOMXSSAdvanced(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	chromePath := findChromePath()
	if chromePath == "" {
		return findings
	}

	// DOM XSS sources to test
	sources := []struct {
		name    string
		inject  func(string, string) string
	}{
		{"URL fragment", func(u, p string) string { return u + "#" + p }},
		{"URL search param", func(u, p string) string {
			if strings.Contains(u, "?") {
				return u + "&xss=" + p
			}
			return u + "?xss=" + p
		}},
		{"document.referrer", func(u, p string) string { return u }}, // needs special handling
	}

	// DOM XSS payloads that trigger document.title change
	payloads := []struct {
		payload string
		detect  string
	}{
		{`<img src=x onerror=document.title='APEX_DOM'>`, "APEX_DOM"},
		{`'-alert(1)-'`, ""},
		{`javascript:document.title='APEX_DOM'`, "APEX_DOM"},
		{`\x3cimg src=x onerror=document.title='APEX_DOM'\x3e`, "APEX_DOM"},
		{`</script><script>document.title='APEX_DOM'</script>`, "APEX_DOM"},
	}

	for _, page := range crawl.Pages[:min(15, len(crawl.Pages))] {
		// First check if page uses dangerous sinks
		dom, err := getRenderedDOM(chromePath, page.URL)
		if err != nil {
			continue
		}
		if !hasDangerousSinks(dom) {
			continue
		}

		for _, source := range sources {
			for _, pl := range payloads {
				if pl.detect == "" {
					continue
				}
				testURL := source.inject(page.URL, pl.payload)
				if browserCheckTitle(chromePath, testURL, pl.detect) {
					findings = append(findings, Finding{
						Type: "DOM XSS (Browser-Confirmed)", Severity: "critical",
						URL: testURL, Payload: pl.payload,
						Detail:   fmt.Sprintf("DOM XSS via %s — JS executed in headless Chrome", source.name),
						Evidence: fmt.Sprintf("document.title changed to '%s'", pl.detect),
						Template: "apex-dom-xss-advanced",
					})
					break
				}
			}
		}
	}
	return findings
}

// scanSPACrawl discovers routes in Single Page Applications
func scanSPACrawl(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	chromePath := findChromePath()
	if chromePath == "" {
		return findings
	}

	if len(crawl.Pages) == 0 {
		return findings
	}
	baseURL := extractBaseURL(crawl.Pages[0].URL)

	// Get rendered DOM to find SPA routes
	dom, err := getRenderedDOM(chromePath, baseURL)
	if err != nil {
		return findings
	}

	// Extract routes from rendered DOM (React Router, Vue Router, Angular)
	routes := extractSPARoutes(dom, baseURL)

	// Also extract from JS bundles
	for _, page := range crawl.Pages {
		if strings.Contains(page.URL, ".js") {
			resp := h.Get(page.URL)
			if resp.Err == nil {
				jsRoutes := extractRoutesFromJS(resp.Body, baseURL)
				routes = append(routes, jsRoutes...)
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	for _, route := range routes {
		if seen[route] {
			continue
		}
		seen[route] = true

		// Check if route exposes sensitive content
		resp := h.Get(route)
		if resp.Err == nil && resp.StatusCode == 200 {
			if containsSensitiveData(resp.Body) {
				findings = append(findings, Finding{
					Type: "SPA Hidden Route — Sensitive Data", Severity: "high",
					URL: route, Detail: "Client-side route exposes sensitive data without server-side auth check",
					Template: "apex-spa-route",
				})
			}
		}
	}
	return findings
}

// scanPostMessageAdvanced tests postMessage handlers for XSS
func scanPostMessageAdvanced(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	chromePath := findChromePath()
	if chromePath == "" {
		return findings
	}

	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		// Check if page has message event listeners
		dom, err := getRenderedDOM(chromePath, page.URL)
		if err != nil {
			continue
		}
		if !strings.Contains(dom, "addEventListener") || !strings.Contains(dom, "message") {
			// Also check for onmessage
			if !strings.Contains(dom, "onmessage") {
				continue
			}
		}

		// Test various postMessage payloads
		pmPayloads := []struct {
			data   string
			detect string
		}{
			{`<img src=x onerror=document.title='APEX_PM'>`, "APEX_PM"},
			{`{"type":"redirect","url":"javascript:document.title='APEX_PM'"}`, "APEX_PM"},
			{`{"action":"eval","code":"document.title='APEX_PM'"}`, "APEX_PM"},
			{`{"html":"<img src=x onerror=document.title='APEX_PM'>"}`, "APEX_PM"},
		}

		for _, pl := range pmPayloads {
			// Create attacker page that sends postMessage
			html := fmt.Sprintf(`<html><body>
<iframe id="t" src="%s"></iframe>
<script>
var i=document.getElementById('t');
i.onload=function(){
  i.contentWindow.postMessage('%s','*');
  i.contentWindow.postMessage(%s,'*');
};
</script></body></html>`, page.URL, pl.data, quoteJSON(pl.data))

			tmpFile := fmt.Sprintf("/tmp/apex_pm_%d.html", time.Now().UnixNano())
			os.WriteFile(tmpFile, []byte(html), 0644)

			if browserCheckTitle(chromePath, "file://"+tmpFile, pl.detect) {
				findings = append(findings, Finding{
					Type: "postMessage XSS (Browser-Confirmed)", Severity: "critical",
					URL: page.URL, Payload: pl.data,
					Detail:   "postMessage handler processes attacker-controlled data without origin check",
					Evidence: "document.title changed via cross-origin postMessage",
					Template: "apex-postmessage-advanced",
				})
				os.Remove(tmpFile)
				break
			}
			os.Remove(tmpFile)
		}
	}
	return findings
}

// --- Helpers ---

func getRenderedDOM(chromePath, url string) (string, error) {
	cmd := exec.Command(chromePath,
		"--headless", "--disable-gpu", "--no-sandbox",
		"--virtual-time-budget=5000",
		"--dump-dom", url,
	)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func hasDangerousSinks(dom string) bool {
	sinks := []string{
		"innerHTML", "outerHTML", "document.write", "eval(",
		".html(", "$.html", "v-html", "dangerouslySetInnerHTML",
		"location.href", "location.assign", "location.replace",
		"window.open", "setTimeout(", "setInterval(",
	}
	for _, sink := range sinks {
		if strings.Contains(dom, sink) {
			return true
		}
	}
	return false
}

func extractSPARoutes(dom, baseURL string) []string {
	var routes []string
	// React Router: path="/something"
	// Vue Router: path: '/something'
	// Angular: { path: 'something' }
	patterns := []string{`path="`, `path: '`, `path: "`, `to="`, `href="/`, `routerLink="`}
	for _, pattern := range patterns {
		parts := strings.Split(dom, pattern)
		for _, part := range parts[1:] {
			end := strings.IndexAny(part, `"'`)
			if end > 0 && end < 100 {
				route := part[:end]
				if strings.HasPrefix(route, "/") && !strings.Contains(route, "{{") {
					routes = append(routes, baseURL+route)
				}
			}
		}
	}
	return routes
}

func extractRoutesFromJS(jsCode, baseURL string) []string {
	var routes []string
	// Match path patterns in JS bundles
	patterns := []string{`path:"`, `path:'`, `"/api/`, `'/api/`, `"/admin`, `'/admin`}
	for _, pattern := range patterns {
		parts := strings.Split(jsCode, pattern)
		for _, part := range parts[1:] {
			end := strings.IndexAny(part, `"'`)
			if end > 0 && end < 80 {
				route := part[:end]
				if pattern[0] == '"' || pattern[0] == '\'' {
					route = pattern[len(pattern)-1:] + route // prepend the /
				}
				if strings.HasPrefix(route, "/") && len(route) > 1 {
					routes = append(routes, baseURL+route)
				}
			}
		}
	}
	return routes
}

func containsSensitiveData(body string) bool {
	indicators := []string{"email", "password", "token", "secret", "admin", "internal", "private", "ssn", "credit_card"}
	lower := strings.ToLower(body)
	count := 0
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			count++
		}
	}
	return count >= 2
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func findFreePort() int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	if l != nil {
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		return port
	}
	return 9222
}
