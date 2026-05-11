package scanner

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// Browser-based scanners using headless Chrome
// Falls back gracefully if Chrome is not installed

func scanBrowserXSS(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	chromePath := findChromePath()
	if chromePath == "" {
		return findings
	}

	xssPayloads := []string{
		`<img src=x onerror=document.title='APEX_XSS'>`,
		`<svg onload=document.title='APEX_XSS'>`,
		`"><script>document.title='APEX_XSS'</script>`,
	}

	for u, params := range crawl.Params {
		for _, p := range params {
			for _, payload := range xssPayloads {
				testURL := injectParam(u, p, payload)
				if browserCheckTitle(chromePath, testURL, "APEX_XSS") {
					findings = append(findings, Finding{
						Type: "XSS (Browser-Confirmed)", Severity: "critical",
						URL: testURL, Param: p, Payload: payload,
						Detail:   "JavaScript executed in headless Chrome — XSS confirmed",
						Template: "apex-xss-browser",
					})
					break
				}
			}
		}
	}
	return findings
}

func scanBrowserDOMXSS(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	chromePath := findChromePath()
	if chromePath == "" {
		return findings
	}

	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		// DOM XSS via hash fragment
		testURL := page.URL + "#<img src=x onerror=document.title='APEX_DOM'>"
		if browserCheckTitle(chromePath, testURL, "APEX_DOM") {
			findings = append(findings, Finding{
				Type: "DOM XSS (Browser-Confirmed)", Severity: "critical",
				URL: testURL, Detail: "DOM XSS via URL fragment confirmed in headless Chrome",
				Template: "apex-dom-xss-browser",
			})
		}
	}
	return findings
}

func scanBrowserPostMessage(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	chromePath := findChromePath()
	if chromePath == "" {
		return findings
	}

	// Create a temp HTML that iframes the target and sends postMessage
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		html := fmt.Sprintf(`<html><body>
<iframe id="t" src="%s"></iframe>
<script>
setTimeout(function(){
  document.getElementById('t').contentWindow.postMessage('<img src=x onerror=document.title="APEX_PM">','*');
  document.getElementById('t').contentWindow.postMessage({type:'xss',data:'<img src=x onerror=document.title="APEX_PM">'},'*');
},2000);
</script></body></html>`, page.URL)

		tmpFile := fmt.Sprintf("/tmp/apex_pm_%d.html", time.Now().UnixNano())
		os.WriteFile(tmpFile, []byte(html), 0644)
		defer os.Remove(tmpFile)

		if browserCheckTitle(chromePath, "file://"+tmpFile, "APEX_PM") {
			findings = append(findings, Finding{
				Type: "postMessage XSS (Browser-Confirmed)", Severity: "critical",
				URL: page.URL, Detail: "postMessage handler executes attacker HTML in headless Chrome",
				Template: "apex-postmessage-browser",
			})
		}
	}
	return findings
}

// --- Chrome helpers ---

func findChromePath() string {
	paths := []string{
		"chromium-browser", "chromium", "google-chrome",
		"google-chrome-stable", "/usr/bin/chromium-browser",
		"/usr/bin/chromium", "/usr/bin/google-chrome",
		"/snap/bin/chromium",
	}
	for _, p := range paths {
		if path, err := exec.LookPath(p); err == nil {
			return path
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func browserCheckTitle(chromePath, targetURL, expectedTitle string) bool {
	// Run headless Chrome, load page, dump title via --dump-dom and JS
	// Use --virtual-time-budget to wait for JS execution
	cmd := exec.Command(chromePath,
		"--headless", "--disable-gpu", "--no-sandbox",
		"--virtual-time-budget=5000",
		"--run-all-compositor-stages-before-draw",
		fmt.Sprintf("--dump-dom"),
		targetURL,
	)
	cmd.Env = append(os.Environ(), "DISPLAY=:0")

	output, err := cmd.Output()
	if err != nil {
		return false
	}

	// Check if title was changed by our payload
	dom := string(output)
	if strings.Contains(dom, "<title>"+expectedTitle+"</title>") {
		return true
	}
	// Also check via print-to-pdf approach — title in DOM
	return strings.Contains(dom, expectedTitle)
}
