package scanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- Race Condition ---

func scanRaceCondition(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	raceKeywords := []string{"coupon", "redeem", "transfer", "vote", "like", "follow",
		"apply", "claim", "register", "withdraw", "purchase", "checkout",
		"add", "create", "submit", "confirm", "verify", "activate"}

	// Test forms
	for _, form := range crawl.Forms {
		action := form.Action
		isRaceTarget := false
		for _, kw := range raceKeywords {
			if strings.Contains(strings.ToLower(action), kw) {
				isRaceTarget = true
				break
			}
		}
		if !isRaceTarget {
			continue
		}

		data := ""
		for _, inp := range form.Inputs {
			if data != "" {
				data += "&"
			}
			val := inp.Value
			if val == "" {
				val = "test"
			}
			data += inp.Name + "=" + val
		}

		result := raceTest(http, "POST", action, "application/x-www-form-urlencoded", data)
		if result != nil {
			findings = append(findings, *result)
		}
	}

	// Test API endpoints from crawl
	for _, page := range crawl.Pages {
		urlLower := strings.ToLower(page.URL)
		for _, kw := range raceKeywords {
			if strings.Contains(urlLower, kw) && strings.Contains(urlLower, "/api") {
				result := raceTest(http, "POST", page.URL, "application/json", "{}")
				if result != nil {
					findings = append(findings, *result)
				}
				break
			}
		}
	}

	return findings
}

func raceTest(http *engine.HTTPClient, method, url, contentType, body string) *Finding {
	// Fire 20 parallel requests simultaneously
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	responses := make([]int, 0, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := http.Post(url, contentType, body)
			if resp.Err == nil {
				mu.Lock()
				responses = append(responses, resp.StatusCode)
				if resp.StatusCode >= 200 && resp.StatusCode < 400 {
					successes++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// If multiple succeeded AND we got consistent 200s, it's likely a race condition
	if successes > 1 {
		return &Finding{
			Type: "Race Condition — Limit Bypass", Severity: "high",
			URL: url, Detail: fmt.Sprintf("%d/20 parallel requests succeeded — duplicate action possible", successes),
			Template: "apex-race-condition",
		}
	}
	return nil
}

// --- Price Manipulation ---

func scanPriceManipulation(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	priceParams := []string{"price", "amount", "total", "cost", "value", "quantity", "qty", "discount"}

	for u, params := range crawl.Params {
		for _, p := range params {
			pLower := strings.ToLower(p)
			isPriceParam := false
			for _, pp := range priceParams {
				if strings.Contains(pLower, pp) {
					isPriceParam = true
					break
				}
			}
			if !isPriceParam {
				continue
			}

			// Test negative values
			for _, val := range []string{"-1", "0", "0.01", "99999999"} {
				testURL := injectParam(u, p, val)
				resp := http.Get(testURL)
				if resp.Err == nil && resp.StatusCode == 200 &&
					!strings.Contains(strings.ToLower(resp.Body), "invalid") &&
					!strings.Contains(strings.ToLower(resp.Body), "error") {
					findings = append(findings, Finding{
						Type: "Price/Amount Manipulation", Severity: "high",
						URL: testURL, Param: p, Payload: val,
						Detail:   fmt.Sprintf("Server accepted %s=%s without validation", p, val),
						Template: "apex-price-manipulation",
					})
					break
				}
			}
		}
	}
	return findings
}

// --- Payment Flow Bypass ---

func scanPaymentBypass(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	paymentPaths := []string{"/checkout/complete", "/order/confirm", "/payment/success",
		"/api/order/complete", "/api/payment/verify", "/purchase/finalize"}

	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		baseURL := strings.Split(page.URL, "/")[0] + "//" + strings.Split(page.URL, "/")[2]
		for _, path := range paymentPaths {
			url := baseURL + path
			// Try accessing payment success directly
			resp := http.Get(url)
			if resp.Err == nil && resp.StatusCode == 200 &&
				(strings.Contains(resp.Body, "success") || strings.Contains(resp.Body, "confirmed") ||
					strings.Contains(resp.Body, "order")) {
				findings = append(findings, Finding{
					Type: "Payment Flow Bypass — Direct Access", Severity: "critical",
					URL: url, Detail: "Payment confirmation endpoint accessible without completing payment",
					Template: "apex-payment-bypass",
				})
			}
			// Try POST with manipulated status
			resp2 := http.Post(url, "application/json", `{"status":"paid","amount":0}`)
			if resp2.Err == nil && resp2.StatusCode == 200 {
				findings = append(findings, Finding{
					Type: "Payment Flow Bypass — Status Manipulation", Severity: "critical",
					URL: url, Payload: `{"status":"paid","amount":0}`,
					Template: "apex-payment-status",
				})
			}
		}
	}
	return findings
}

// --- Mass Assignment ---

func scanMassAssignment(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	dangerousFields := []string{"role", "admin", "is_admin", "isAdmin", "privilege",
		"permissions", "user_type", "verified", "is_verified", "balance", "credits", "plan"}

	for _, form := range crawl.Forms {
		action := form.Action
		if !strings.Contains(strings.ToLower(action), "register") &&
			!strings.Contains(strings.ToLower(action), "signup") &&
			!strings.Contains(strings.ToLower(action), "profile") &&
			!strings.Contains(strings.ToLower(action), "update") &&
			!strings.Contains(strings.ToLower(action), "user") {
			continue
		}

		existingFields := make(map[string]bool)
		baseData := make(map[string]string)
		for _, inp := range form.Inputs {
			existingFields[inp.Name] = true
			val := inp.Value
			if val == "" {
				val = "test"
			}
			baseData[inp.Name] = val
		}

		for _, field := range dangerousFields {
			if existingFields[field] {
				continue
			}
			testData := make(map[string]string)
			for k, v := range baseData {
				testData[k] = v
			}
			testData[field] = "true"

			// Build JSON body
			parts := []string{}
			for k, v := range testData {
				parts = append(parts, fmt.Sprintf(`"%s":"%s"`, k, v))
			}
			body := "{" + strings.Join(parts, ",") + "}"

			resp := http.Post(action, "application/json", body)
			if resp.Err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 &&
				strings.Contains(resp.Body, field) {
				findings = append(findings, Finding{
					Type: "Mass Assignment — " + field, Severity: "high",
					URL: action, Param: field, Payload: field + "=true",
					Detail:   fmt.Sprintf("Server accepted undocumented field '%s'. Privilege escalation possible.", field),
					Template: "apex-mass-assignment",
				})
				break
			}
		}
	}
	return findings
}

// --- Forced Browsing ---

func scanForcedBrowsing(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	adminPaths := []string{
		"/admin", "/admin/", "/administrator", "/dashboard", "/panel",
		"/manage", "/management", "/internal", "/debug", "/console",
		"/api/admin", "/api/internal", "/api/debug", "/graphql",
		"/_debug", "/actuator", "/actuator/env", "/actuator/health",
		"/swagger-ui.html", "/api-docs", "/swagger.json",
		"/.env", "/config", "/phpinfo.php", "/server-status",
		"/wp-admin", "/wp-json/wp/v2/users", "/.git/config",
		"/api/v1/admin", "/api/users", "/metrics", "/health",
	}

	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		baseURL := strings.Split(page.URL, "/")[0] + "//" + strings.Split(page.URL, "/")[2]
		for _, path := range adminPaths {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				resp := http.Get(url)
				if resp.Err != nil || resp.StatusCode == 404 || resp.StatusCode == 403 || resp.StatusCode == 401 {
					return
				}
				if engine.IsWAFChallenge(resp) {
					return
				}
				// Reject redirects to login/auth pages
				if resp.StatusCode >= 300 && resp.StatusCode < 400 {
					return
				}
				if resp.StatusCode == 200 && len(resp.Body) > 100 {
					// Reject if it's actually a login/auth page
					bodyLower := strings.ToLower(resp.Body)
					if strings.Contains(bodyLower, "sign in") || strings.Contains(bodyLower, "log in") || strings.Contains(bodyLower, "login") {
						return
					}
					// Verify it's not a generic page
					if strings.Contains(strings.ToLower(resp.Body), "admin") ||
						strings.Contains(strings.ToLower(resp.Body), "dashboard") ||
						strings.Contains(strings.ToLower(resp.Body), "actuator") ||
						strings.Contains(resp.Body, "SECRET") ||
						strings.Contains(resp.Body, "password") {
						mu.Lock()
						findings = append(findings, Finding{
							Type: "Forced Browsing — Sensitive Endpoint", Severity: "high",
							URL: url, Detail: fmt.Sprintf("Accessible without auth (status %d, %d bytes)", resp.StatusCode, resp.Size),
							Template: "apex-forced-browsing",
						})
						mu.Unlock()
					}
				}
			}(baseURL + path)
		}
	}
	wg.Wait()
	return findings
}

// --- IDOR via UUID Prediction ---

func scanIDORUUID(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	// Already covered in scanner.go scanIDOR, this adds UUID-specific logic
	// Look for sequential UUIDs (v1 UUIDs are time-based and predictable)
	for u := range crawl.Params {
		if strings.Contains(u, "-") {
			parts := strings.Split(u, "/")
			for _, part := range parts {
				if len(part) == 36 && strings.Count(part, "-") == 4 {
					// UUID v1 check (first 8 chars are time-based)
					if part[14] == '1' { // Version 1
						findings = append(findings, Finding{
							Type: "IDOR Risk — UUID v1 (Predictable)", Severity: "medium",
							URL: u, Detail: "UUID v1 detected — time-based and predictable. Adjacent UUIDs can be guessed.",
							Template: "apex-idor-uuid-v1",
						})
					}
					break
				}
			}
		}
	}
	return findings
}

// Placeholder for timing
var _ = time.Second
