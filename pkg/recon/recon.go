package recon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/engine"
)

type Result struct {
	Subdomains  []string
	LiveTargets []string
	Techs       map[string][]string // target -> detected technologies
	WAFs        []string
}

func Run(cfg *engine.Config, httpClient *engine.HTTPClient) *Result {
	result := &Result{
		Techs: make(map[string][]string),
	}

	// Subdomain enumeration
	var subs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	sources := []func(string) []string{
		subfinderEnum,
		crtshEnum,
		hackertargetEnum,
	}

	for _, fn := range sources {
		wg.Add(1)
		go func(f func(string) []string) {
			defer wg.Done()
			results := f(cfg.Target)
			mu.Lock()
			subs = append(subs, results...)
			mu.Unlock()
		}(fn)
	}
	wg.Wait()

	// Deduplicate
	seen := make(map[string]bool)
	for _, s := range subs {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" && !seen[s] {
			seen[s] = true
			result.Subdomains = append(result.Subdomains, s)
		}
	}

	// Always include the target itself
	if !seen[cfg.Target] {
		result.Subdomains = append(result.Subdomains, cfg.Target)
	}

	// Probe live targets (httpx-style)
	result.LiveTargets = probeLive(cfg, httpClient, result.Subdomains)

	// Fingerprint + WAF detection
	for _, target := range result.LiveTargets {
		techs, waf := fingerprint(httpClient, target)
		if len(techs) > 0 {
			result.Techs[target] = techs
		}
		if waf != "" {
			result.WAFs = append(result.WAFs, waf)
		}
	}

	return result
}

func subfinderEnum(target string) []string {
	cmd := exec.Command("subfinder", "-d", target, "-silent")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var results []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		results = append(results, scanner.Text())
	}
	return results
}

func crtshEnum(target string) []string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	json.NewDecoder(resp.Body).Decode(&entries)

	var results []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimPrefix(name, "*.")
			if strings.Contains(name, target) {
				results = append(results, name)
			}
		}
	}
	return results
}

func hackertargetEnum(target string) []string {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", target))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var results []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		if len(parts) > 0 {
			results = append(results, parts[0])
		}
	}
	return results
}

func probeLive(cfg *engine.Config, httpClient *engine.HTTPClient, subdomains []string) []string {
	var live []string
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	schemes := []string{"https://", "http://"}

	for _, sub := range subdomains {
		for _, scheme := range schemes {
			wg.Add(1)
			go func(target string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				resp := httpClient.Get(target)
				if resp.Err == nil && resp.StatusCode > 0 && resp.StatusCode < 500 {
					mu.Lock()
					live = append(live, target)
					// Also add redirect targets
					loc := resp.Headers.Get("Location")
					if loc != "" && strings.HasPrefix(loc, "http") {
						live = append(live, loc)
					}
					mu.Unlock()
				}
			}(scheme + sub)
		}
	}
	wg.Wait()

	// Deduplicate (prefer https)
	seen := make(map[string]bool)
	var deduped []string
	for _, t := range live {
		host := strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://")
		if !seen[host] {
			seen[host] = true
			deduped = append(deduped, t)
		}
	}
	return deduped
}

func fingerprint(httpClient *engine.HTTPClient, target string) (techs []string, waf string) {
	resp := httpClient.Get(target)
	if resp.Err != nil {
		return
	}

	// Technology detection from headers
	server := resp.Headers.Get("Server")
	powered := resp.Headers.Get("X-Powered-By")
	if server != "" {
		techs = append(techs, server)
	}
	if powered != "" {
		techs = append(techs, powered)
	}

	// WAF detection
	wafSigs := map[string]string{
		"cloudflare":  "Cloudflare",
		"akamai":     "Akamai",
		"incapsula":  "Imperva",
		"sucuri":     "Sucuri",
		"f5":         "F5 BIG-IP",
		"barracuda":  "Barracuda",
		"aws":        "AWS WAF",
		"fortiweb":   "FortiWeb",
	}
	headerStr := strings.ToLower(fmt.Sprintf("%v", resp.Headers))
	for sig, name := range wafSigs {
		if strings.Contains(headerStr, sig) {
			waf = name
			break
		}
	}

	// Body-based tech detection
	bodyLower := strings.ToLower(resp.Body[:min(5000, len(resp.Body))])
	techSigs := map[string]string{
		"wp-content":    "WordPress",
		"next/static":   "Next.js",
		"__nuxt":        "Nuxt.js",
		"react":         "React",
		"angular":       "Angular",
		"vue.js":        "Vue.js",
		"jquery":        "jQuery",
		"laravel":       "Laravel",
		"django":        "Django",
		"express":       "Express.js",
	}
	for sig, name := range techSigs {
		if strings.Contains(bodyLower, sig) {
			techs = append(techs, name)
		}
	}
	return
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
