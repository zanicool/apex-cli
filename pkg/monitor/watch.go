package monitor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Monitor watches targets for changes and triggers rescans
type Monitor struct {
	stateDir string
	webhook  string
	client   *http.Client
	mu       sync.Mutex
}

type Change struct {
	Domain string `json:"domain"`
	Type   string `json:"type"` // "new_subdomain", "js_change", "dns_change"
	Detail string `json:"detail"`
	Time   time.Time `json:"time"`
}

func New(stateDir, discordWebhook string) *Monitor {
	os.MkdirAll(stateDir, 0755)
	return &Monitor{
		stateDir: stateDir,
		webhook:  discordWebhook,
		client:   &http.Client{Timeout: 15 * time.Second},
	}
}

// WatchCTLogs checks Certificate Transparency for new subdomains
func (m *Monitor) WatchCTLogs(domain string) []Change {
	var changes []Change
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := m.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var certs []struct {
		NameValue string `json:"name_value"`
	}
	json.Unmarshal(body, &certs)

	// Load known subdomains
	knownFile := filepath.Join(m.stateDir, safeName(domain)+"_subs.json")
	known := m.loadSet(knownFile)

	var newSubs []string
	for _, c := range certs {
		for _, name := range strings.Split(c.NameValue, "\n") {
			name = strings.TrimSpace(strings.TrimPrefix(name, "*."))
			if name != "" && !known[name] {
				known[name] = true
				newSubs = append(newSubs, name)
			}
		}
	}

	if len(newSubs) > 0 {
		m.saveSet(knownFile, known)
		for _, sub := range newSubs {
			changes = append(changes, Change{Domain: sub, Type: "new_subdomain", Detail: fmt.Sprintf("New cert issued for %s", sub), Time: time.Now()})
		}
	}
	return changes
}

// WatchJSBundles detects JavaScript file changes (new endpoints, new code)
func (m *Monitor) WatchJSBundles(targets []string) []Change {
	var changes []Change
	hashFile := filepath.Join(m.stateDir, "js_hashes.json")
	hashes := m.loadMap(hashFile)

	for _, target := range targets {
		resp, err := m.client.Get(target)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		// Find JS URLs in the page
		jsURLs := extractJSURLs(string(body), target)
		for _, jsURL := range jsURLs {
			jsResp, err := m.client.Get(jsURL)
			if err != nil || jsResp.StatusCode != 200 {
				continue
			}
			jsBody, _ := io.ReadAll(jsResp.Body)
			jsResp.Body.Close()

			hash := fmt.Sprintf("%x", sha256.Sum256(jsBody))
			oldHash, exists := hashes[jsURL]
			if exists && oldHash != hash {
				changes = append(changes, Change{Domain: target, Type: "js_change", Detail: fmt.Sprintf("JS bundle changed: %s", jsURL), Time: time.Now()})
			}
			hashes[jsURL] = hash
		}
	}
	m.saveMap(hashFile, hashes)
	return changes
}

// WatchDNS detects DNS record changes (new IPs, CNAME changes)
func (m *Monitor) WatchDNS(domains []string) []Change {
	var changes []Change
	dnsFile := filepath.Join(m.stateDir, "dns_state.json")
	state := m.loadMap(dnsFile)

	for _, domain := range domains {
		ips, err := net.LookupHost(domain)
		if err != nil {
			continue
		}
		current := strings.Join(ips, ",")
		old, exists := state[domain]
		if exists && old != current {
			changes = append(changes, Change{Domain: domain, Type: "dns_change", Detail: fmt.Sprintf("DNS changed: %s → %s", old, current), Time: time.Now()})
		}
		state[domain] = current

		// Check CNAME for takeover opportunities
		cname, err := net.LookupCNAME(domain)
		if err == nil && cname != "" {
			cnameKey := domain + "_cname"
			if old, exists := state[cnameKey]; exists && old != cname {
				changes = append(changes, Change{Domain: domain, Type: "dns_change", Detail: fmt.Sprintf("CNAME changed: %s → %s", old, cname), Time: time.Now()})
			}
			state[cnameKey] = cname
		}
	}
	m.saveMap(dnsFile, state)
	return changes
}

// NotifyChanges sends changes to Discord
func (m *Monitor) NotifyChanges(changes []Change) {
	if m.webhook == "" || len(changes) == 0 {
		return
	}
	desc := ""
	for _, c := range changes[:min(10, len(changes))] {
		desc += fmt.Sprintf("• [%s] %s: %s\n", c.Type, c.Domain, c.Detail)
	}
	if len(changes) > 10 {
		desc += fmt.Sprintf("...and %d more\n", len(changes)-10)
	}
	payload := fmt.Sprintf(`{"embeds":[{"title":"🔔 Target Changes Detected","description":"%s","color":16776960}]}`, strings.ReplaceAll(desc, "\"", "\\\""))
	req, _ := http.NewRequest("POST", m.webhook, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	m.client.Do(req)
}

// --- Helpers ---

func extractJSURLs(html, baseURL string) []string {
	var urls []string
	// Simple regex-free extraction
	for _, part := range strings.Split(html, "src=\"") {
		if idx := strings.Index(part, "\""); idx > 0 {
			src := part[:idx]
			if strings.HasSuffix(src, ".js") || strings.Contains(src, ".js?") {
				if strings.HasPrefix(src, "http") {
					urls = append(urls, src)
				} else if strings.HasPrefix(src, "//") {
					urls = append(urls, "https:"+src)
				} else if strings.HasPrefix(src, "/") {
					urls = append(urls, baseURL+src)
				}
			}
		}
	}
	return urls
}

func (m *Monitor) loadSet(path string) map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := make(map[string]bool)
	data, err := os.ReadFile(path)
	if err != nil {
		return set
	}
	var items []string
	json.Unmarshal(data, &items)
	for _, item := range items {
		set[item] = true
	}
	return set
}

func (m *Monitor) saveSet(path string, set map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var items []string
	for k := range set {
		items = append(items, k)
	}
	data, _ := json.Marshal(items)
	os.WriteFile(path, data, 0644)
}

func (m *Monitor) loadMap(path string) map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m2 := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return m2
	}
	json.Unmarshal(data, &m2)
	return m2
}

func (m *Monitor) saveMap(path string, m2 map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, _ := json.Marshal(m2)
	os.WriteFile(path, data, 0644)
}

func safeName(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, ".", "_"), "/", "_")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
