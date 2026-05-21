package scanner

import (
	"fmt"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// ==========================================================================
// DIFFERENTIAL ROLE ENGINE
// Replays every request as a different user to find IDOR + privilege escalation
// Usage: provide two sessions via environment:
//   APEX_SESSION_A=session_a.json (higher privilege)
//   APEX_SESSION_B=session_b.json (lower privilege)
// ==========================================================================

// RoleDiffConfig holds two sessions for comparison
type RoleDiffConfig struct {
	SessionA *engine.Session // Higher privilege (admin/owner)
	SessionB *engine.Session // Lower privilege (regular user)
}

// scanRoleDifferential replays requests from session A as session B
// to find broken access control and IDOR
func scanRoleDifferential(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	// Load sessions from environment
	sessionA := loadSessionFromEnv("APEX_SESSION_A")
	sessionB := loadSessionFromEnv("APEX_SESSION_B")

	if sessionA == nil || sessionB == nil {
		return findings // Need both sessions for differential testing
	}

	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Test every crawled page: request as A, then as B
	for _, page := range crawl.Pages {
		wg.Add(1)
		go func(pageURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Request as privileged user A
			respA := http.AuthGet(pageURL, sessionA)
			if respA.Err != nil || respA.StatusCode == 404 || respA.StatusCode == 301 {
				return
			}

			// Skip public pages (same response without auth)
			respNoAuth := http.Get(pageURL)
			if respNoAuth.Err == nil && respNoAuth.Body == respA.Body {
				return // Public page, no access control
			}

			// Request same page as lower-privilege user B
			respB := http.AuthGet(pageURL, sessionB)
			if respB.Err != nil {
				return
			}

			// CASE 1: B gets same data as A → Broken Access Control
			if respB.StatusCode == 200 && respA.StatusCode == 200 {
				if similarContent(respA.Body, respB.Body) && len(respA.Body) > 100 {
					mu.Lock()
					findings = append(findings, Finding{
						Type:     "Broken Access Control — Privilege Escalation",
						Severity: "critical",
						URL:      pageURL,
						Detail:   fmt.Sprintf("Low-privilege user can access admin content (%d bytes, same as admin response)", len(respB.Body)),
						Template: "apex-bac-privesc",
					})
					mu.Unlock()
				}
			}

			// CASE 2: B gets 200 where they should get 403 → Missing Auth Check
			if respA.StatusCode == 200 && respB.StatusCode == 200 &&
				(respNoAuth.StatusCode == 401 || respNoAuth.StatusCode == 403) {
				mu.Lock()
				findings = append(findings, Finding{
					Type:     "Broken Access Control — Missing Authorization",
					Severity: "high",
					URL:      pageURL,
					Detail:   "Endpoint requires authentication but doesn't check authorization level",
					Template: "apex-bac-missing-authz",
				})
				mu.Unlock()
			}
		}(page.URL)
	}

	// Test API endpoints with ID manipulation
	for u, params := range crawl.Params {
		for _, p := range params {
			if !isIDParam(p) {
				continue
			}
			wg.Add(1)
			go func(baseURL, param string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Get resource as user A (owner)
				respA := http.AuthGet(baseURL, sessionA)
				if respA.Err != nil || respA.StatusCode != 200 || len(respA.Body) < 50 {
					return
				}

				// Try same resource as user B (not owner)
				respB := http.AuthGet(baseURL, sessionB)
				if respB.Err != nil {
					return
				}

				if respB.StatusCode == 200 && similarContent(respA.Body, respB.Body) {
					mu.Lock()
					findings = append(findings, Finding{
						Type:     "IDOR — Cross-User Data Access",
						Severity: "critical",
						URL:      baseURL,
						Param:    param,
						Detail:   fmt.Sprintf("User B can access User A's resource via '%s' parameter (%d bytes returned)", param, len(respB.Body)),
						Template: "apex-idor-cross-user",
					})
					mu.Unlock()
				}
			}(u, p)
		}
	}
	wg.Wait()
	return findings
}

func isIDParam(p string) bool {
	pLower := strings.ToLower(p)
	idParams := []string{"id", "uid", "user_id", "userid", "account", "order",
		"invoice", "doc", "file", "report", "ticket", "message", "conversation"}
	for _, id := range idParams {
		if strings.Contains(pLower, id) {
			return true
		}
	}
	return false
}

func similarContent(a, b string) bool {
	if a == b {
		return true
	}
	// Allow small differences (timestamps, CSRF tokens)
	lenDiff := len(a) - len(b)
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}
	return float64(lenDiff)/float64(max(len(a), 1)) < 0.05 // <5% size difference
}

func loadSessionFromEnv(envVar string) *engine.Session {
	path := getEnv(envVar)
	if path == "" {
		return nil
	}
	session, err := engine.LoadSession(path)
	if err != nil {
		return nil
	}
	return session
}

func getEnv(key string) string {
	// Use os.Getenv at runtime
	val, _ := osLookupEnv(key)
	return val
}

// osLookupEnv is a variable so it can be used without importing os in this file
// (os is already imported elsewhere in the package)
var osLookupEnv = func(key string) (string, bool) {
	// Will be replaced at init time
	return "", false
}
