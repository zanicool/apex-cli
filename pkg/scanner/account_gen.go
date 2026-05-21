package scanner

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
)

// AccountGenerator creates test accounts on targets for authenticated scanning
type AccountGenerator struct {
	http     *engine.HTTPClient
	accounts []*Account
}

type Account struct {
	Email    string          `json:"email"`
	Username string          `json:"username"`
	Password string          `json:"password"`
	Session  *engine.Session `json:"session"`
	Role     string          `json:"role"` // "user", "admin", etc.
}

func NewAccountGenerator(h *engine.HTTPClient) *AccountGenerator {
	return &AccountGenerator{http: h}
}

// Generate creates 2 accounts on the target for IDOR testing
func (ag *AccountGenerator) Generate(baseURL string, crawl *crawler.Result) []*Account {
	regURL, loginURL := ag.findEndpoints(baseURL, crawl)
	if regURL == "" {
		return nil
	}

	// Create 2 accounts for differential testing
	for i := 0; i < 2; i++ {
		acc := ag.createAccount(regURL, loginURL, i)
		if acc != nil {
			ag.accounts = append(ag.accounts, acc)
		}
	}
	return ag.accounts
}

func (ag *AccountGenerator) findEndpoints(baseURL string, crawl *crawler.Result) (string, string) {
	regPaths := []string{"/register", "/signup", "/api/register", "/api/v1/register", "/api/v1/auth/register", "/api/auth/register", "/api/users", "/create-account", "/join"}
	loginPaths := []string{"/login", "/signin", "/api/login", "/api/v1/login", "/api/v1/auth/login", "/api/auth/login", "/api/auth/signin"}

	var regURL, loginURL string

	// Check crawled forms
	for _, form := range crawl.Forms {
		lower := strings.ToLower(form.Action)
		if regURL == "" {
			for _, p := range regPaths {
				if strings.Contains(lower, p) {
					regURL = form.Action
				}
			}
		}
		if loginURL == "" {
			for _, p := range loginPaths {
				if strings.Contains(lower, p) {
					loginURL = form.Action
				}
			}
		}
	}

	// Probe paths
	if regURL == "" {
		for _, p := range regPaths {
			resp := ag.http.Get(baseURL + p)
			if resp.Err == nil && resp.StatusCode < 405 && resp.StatusCode != 404 {
				regURL = baseURL + p
				break
			}
		}
	}
	if loginURL == "" {
		for _, p := range loginPaths {
			resp := ag.http.Get(baseURL + p)
			if resp.Err == nil && resp.StatusCode < 405 && resp.StatusCode != 404 {
				loginURL = baseURL + p
				break
			}
		}
	}
	return regURL, loginURL
}

func (ag *AccountGenerator) createAccount(regURL, loginURL string, idx int) *Account {
	ts := time.Now().UnixNano() / 1000000
	acc := &Account{
		Email:    fmt.Sprintf("apex.sec.%d.%d@proton.me", ts, idx),
		Username: fmt.Sprintf("apextest%d%d", rand.Intn(9999), idx),
		Password: fmt.Sprintf("Apex!%dSecure#%d", rand.Intn(9999), ts%10000),
		Role:     "user",
	}

	// Try JSON registration first (most modern APIs)
	session := ag.tryJSONRegister(regURL, acc)
	if session != nil {
		acc.Session = session
		return acc
	}

	// Try form-based registration
	session = ag.tryFormRegister(regURL, acc)
	if session != nil {
		acc.Session = session
		return acc
	}

	// Try login if registration seemed to work but no token returned
	if loginURL != "" {
		session = ag.tryLogin(loginURL, acc)
		if session != nil {
			acc.Session = session
			return acc
		}
	}
	return nil
}

func (ag *AccountGenerator) tryJSONRegister(regURL string, acc *Account) *engine.Session {
	// Try multiple JSON body formats (different APIs expect different fields)
	bodies := []string{
		fmt.Sprintf(`{"email":"%s","password":"%s"}`, acc.Email, acc.Password),
		fmt.Sprintf(`{"email":"%s","password":"%s","username":"%s"}`, acc.Email, acc.Password, acc.Username),
		fmt.Sprintf(`{"email":"%s","password":"%s","password_confirmation":"%s","name":"%s"}`, acc.Email, acc.Password, acc.Password, acc.Username),
		fmt.Sprintf(`{"user":{"email":"%s","password":"%s","username":"%s"}}`, acc.Email, acc.Password, acc.Username),
	}

	for _, body := range bodies {
		resp := ag.http.Post(regURL, "application/json", body)
		if resp.Err != nil || resp.StatusCode >= 400 {
			continue
		}
		session := ag.extractSession(resp)
		if session != nil {
			return session
		}
	}
	return nil
}

func (ag *AccountGenerator) tryFormRegister(regURL string, acc *Account) *engine.Session {
	// First GET the form to find CSRF token and field names
	getResp := ag.http.Get(regURL)
	if getResp.Err != nil {
		return nil
	}

	csrfToken := extractCSRFToken(getResp.Body)
	fieldNames := detectFormFields(getResp.Body)

	// Build form data
	data := url.Values{}
	if csrfToken != "" {
		data.Set("_token", csrfToken)
		data.Set("csrf_token", csrfToken)
		data.Set("authenticity_token", csrfToken)
	}
	data.Set(fieldNames.email, acc.Email)
	data.Set(fieldNames.password, acc.Password)
	if fieldNames.passwordConfirm != "" {
		data.Set(fieldNames.passwordConfirm, acc.Password)
	}
	if fieldNames.username != "" {
		data.Set(fieldNames.username, acc.Username)
	}

	resp := ag.http.Post(regURL, "application/x-www-form-urlencoded", data.Encode())
	if resp.Err != nil || resp.StatusCode >= 400 {
		return nil
	}
	return ag.extractSession(resp)
}

func (ag *AccountGenerator) tryLogin(loginURL string, acc *Account) *engine.Session {
	bodies := []string{
		fmt.Sprintf(`{"email":"%s","password":"%s"}`, acc.Email, acc.Password),
		fmt.Sprintf(`{"username":"%s","password":"%s"}`, acc.Email, acc.Password),
	}
	for _, body := range bodies {
		resp := ag.http.Post(loginURL, "application/json", body)
		if resp.Err != nil || resp.StatusCode >= 400 {
			continue
		}
		session := ag.extractSession(resp)
		if session != nil {
			return session
		}
	}
	// Try form login
	data := url.Values{}
	data.Set("email", acc.Email)
	data.Set("password", acc.Password)
	resp := ag.http.Post(loginURL, "application/x-www-form-urlencoded", data.Encode())
	if resp.Err == nil && resp.StatusCode < 400 {
		return ag.extractSession(resp)
	}
	return nil
}

func (ag *AccountGenerator) extractSession(resp *engine.Response) *engine.Session {
	session := &engine.Session{Cookies: make(map[string]string), Headers: make(map[string]string)}

	// Extract token from JSON body
	var respData map[string]interface{}
	if json.Unmarshal([]byte(resp.Body), &respData) == nil {
		token := findToken(respData, "")
		if token != "" {
			session.Token = token
			return session
		}
	}

	// Extract from Set-Cookie
	for _, cookie := range resp.Headers.Values("Set-Cookie") {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			value := strings.SplitN(parts[1], ";", 2)[0]
			if value != "" && value != "deleted" && len(value) > 5 {
				session.Cookies[name] = value
			}
		}
	}
	if len(session.Cookies) > 0 {
		return session
	}

	// Extract from Authorization header in response
	if auth := resp.Headers.Get("Authorization"); auth != "" {
		session.Token = strings.TrimPrefix(auth, "Bearer ")
		return session
	}

	return nil
}

// findToken recursively searches JSON for token-like values
func findToken(data map[string]interface{}, prefix string) string {
	tokenKeys := []string{"token", "access_token", "accessToken", "jwt", "session_token", "auth_token", "id_token", "bearer"}
	for _, key := range tokenKeys {
		if val, ok := data[key]; ok {
			if s, ok := val.(string); ok && len(s) > 10 {
				return s
			}
		}
	}
	// Check nested objects (e.g. {"data": {"token": "..."}})
	for _, val := range data {
		if nested, ok := val.(map[string]interface{}); ok {
			if t := findToken(nested, ""); t != "" {
				return t
			}
		}
	}
	return ""
}

func extractCSRFToken(html string) string {
	patterns := []string{
		`name="csrf_token"\s+value="([^"]+)"`,
		`name="_token"\s+value="([^"]+)"`,
		`name="authenticity_token"\s+value="([^"]+)"`,
		`name="csrfmiddlewaretoken"\s+value="([^"]+)"`,
		`content="([^"]+)"\s+name="csrf-token"`,
		`meta\s+name="csrf-token"\s+content="([^"]+)"`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		if m := re.FindStringSubmatch(html); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

type formFields struct {
	email           string
	password        string
	passwordConfirm string
	username        string
}

func detectFormFields(html string) formFields {
	f := formFields{email: "email", password: "password"}
	// Look for actual field names in the HTML
	nameRe := regexp.MustCompile(`name="([^"]+)"`)
	matches := nameRe.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		name := strings.ToLower(m[1])
		switch {
		case strings.Contains(name, "email") || strings.Contains(name, "mail"):
			f.email = m[1]
		case strings.Contains(name, "password_confirm") || strings.Contains(name, "password2") || strings.Contains(name, "confirm"):
			f.passwordConfirm = m[1]
		case strings.Contains(name, "password") || strings.Contains(name, "passwd"):
			if f.password == "password" {
				f.password = m[1]
			}
		case strings.Contains(name, "username") || strings.Contains(name, "user_name") || strings.Contains(name, "login"):
			f.username = m[1]
		}
	}
	return f
}

// TestIDOR uses 2 accounts to test for IDOR between them
func (ag *AccountGenerator) TestIDOR(h *engine.HTTPClient, endpoints []string) []Finding {
	var findings []Finding
	if len(ag.accounts) < 2 || ag.accounts[0].Session == nil || ag.accounts[1].Session == nil {
		return findings
	}

	accA := ag.accounts[0]
	accB := ag.accounts[1]

	for _, endpoint := range endpoints {
		// Get response as user A
		reqA, _ := http.NewRequest("GET", endpoint, nil)
		accA.Session.ApplySession(reqA)
		respA := h.Do(reqA)
		if respA.Err != nil || respA.StatusCode != 200 {
			continue
		}

		// Get same endpoint as user B
		reqB, _ := http.NewRequest("GET", endpoint, nil)
		accB.Session.ApplySession(reqB)
		respB := h.Do(reqB)
		if respB.Err != nil || respB.StatusCode != 200 {
			continue
		}

		// If both get 200 with SAME data = broken access control
		// If both get 200 with DIFFERENT data = properly isolated
		if respA.Body == respB.Body && respA.Size > 50 {
			// Same response = might be public data, check if it contains user-specific info
			if strings.Contains(respA.Body, accA.Email) || strings.Contains(respA.Body, accA.Username) {
				findings = append(findings, Finding{
					Type: "IDOR — Cross-Account Data Access", Severity: "critical",
					URL: endpoint, Detail: "User B can access User A's personal data",
					Evidence: fmt.Sprintf("Both accounts see same user-specific data (size: %d)", respA.Size),
					Template: "apex-idor-accounts",
				})
			}
		}

		// Try accessing A's resources with B's token by manipulating IDs
		idPatterns := regexp.MustCompile(`/(\d+)(?:/|$|\?)`)
		if m := idPatterns.FindStringSubmatch(endpoint); len(m) > 1 {
			// Increment/decrement the ID
			id := m[1]
			for _, newID := range []string{"1", "2", "0", id + "1"} {
				newURL := strings.Replace(endpoint, "/"+id, "/"+newID, 1)
				reqIDOR, _ := http.NewRequest("GET", newURL, nil)
				accB.Session.ApplySession(reqIDOR)
				respIDOR := h.Do(reqIDOR)
				if respIDOR.Err == nil && respIDOR.StatusCode == 200 && respIDOR.Size > 50 && respIDOR.Body != respB.Body {
					findings = append(findings, Finding{
						Type: "IDOR — ID Enumeration", Severity: "high",
						URL: newURL, Detail: fmt.Sprintf("Changing ID from %s to %s returns different user's data", id, newID),
						Template: "apex-idor-enum",
					})
					break
				}
			}
		}
	}
	return findings
}
