package engine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SessionHandler manages complex authentication flows
type SessionHandler struct {
	http       *HTTPClient
	sessions   map[string]*Session
	cookieJar  map[string]map[string]string // host -> cookie name -> value
	tokenExpiry time.Time
	refreshURL string
	refreshBody string
	mu         sync.RWMutex
	macros     []Macro
}

// Macro records a sequence of requests to replay (like Burp macros)
type Macro struct {
	Name     string       `json:"name"`
	Steps    []MacroStep  `json:"steps"`
	Extract  []Extraction `json:"extract"`
}

type MacroStep struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type Extraction struct {
	Name    string `json:"name"`   // variable name
	From    string `json:"from"`   // "header", "body", "cookie"
	Pattern string `json:"pattern"` // regex
}

func NewSessionHandler(h *HTTPClient) *SessionHandler {
	return &SessionHandler{
		http:      h,
		sessions:  make(map[string]*Session),
		cookieJar: make(map[string]map[string]string),
	}
}

// --- OAuth 2.0 ---

type OAuthConfig struct {
	AuthURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scope        string
	Username     string
	Password     string
}

// OAuthPasswordGrant performs Resource Owner Password Credentials flow
func (sh *SessionHandler) OAuthPasswordGrant(cfg OAuthConfig) (*Session, error) {
	data := url.Values{
		"grant_type": {"password"},
		"username":   {cfg.Username},
		"password":   {cfg.Password},
		"client_id":  {cfg.ClientID},
		"scope":      {cfg.Scope},
	}
	if cfg.ClientSecret != "" {
		data.Set("client_secret", cfg.ClientSecret)
	}

	resp := sh.http.Post(cfg.TokenURL, "application/x-www-form-urlencoded", data.Encode())
	if resp.Err != nil {
		return nil, resp.Err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OAuth failed: status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	json.Unmarshal([]byte(resp.Body), &tokenResp)

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in response")
	}

	session := &Session{
		Token:   tokenResp.AccessToken,
		Headers: map[string]string{"Authorization": tokenResp.TokenType + " " + tokenResp.AccessToken},
		Cookies: make(map[string]string),
	}

	// Store refresh info
	if tokenResp.RefreshToken != "" {
		sh.refreshURL = cfg.TokenURL
		sh.refreshBody = fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s", tokenResp.RefreshToken, cfg.ClientID)
		sh.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	sh.mu.Lock()
	sh.sessions["oauth"] = session
	sh.mu.Unlock()
	return session, nil
}

// OAuthClientCredentials performs Client Credentials flow
func (sh *SessionHandler) OAuthClientCredentials(cfg OAuthConfig) (*Session, error) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"scope":         {cfg.Scope},
	}

	resp := sh.http.Post(cfg.TokenURL, "application/x-www-form-urlencoded", data.Encode())
	if resp.Err != nil {
		return nil, resp.Err
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	json.Unmarshal([]byte(resp.Body), &tokenResp)

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("no access_token")
	}

	session := &Session{
		Token:   tokenResp.AccessToken,
		Headers: map[string]string{"Authorization": tokenResp.TokenType + " " + tokenResp.AccessToken},
		Cookies: make(map[string]string),
	}
	sh.mu.Lock()
	sh.sessions["oauth"] = session
	sh.mu.Unlock()
	return session, nil
}

// RefreshToken refreshes an expired OAuth token
func (sh *SessionHandler) RefreshToken() error {
	if sh.refreshURL == "" {
		return fmt.Errorf("no refresh token configured")
	}

	resp := sh.http.Post(sh.refreshURL, "application/x-www-form-urlencoded", sh.refreshBody)
	if resp.Err != nil {
		return resp.Err
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	json.Unmarshal([]byte(resp.Body), &tokenResp)

	if tokenResp.AccessToken == "" {
		return fmt.Errorf("refresh failed")
	}

	sh.mu.Lock()
	if s, ok := sh.sessions["oauth"]; ok {
		s.Token = tokenResp.AccessToken
		s.Headers["Authorization"] = tokenResp.TokenType + " " + tokenResp.AccessToken
	}
	sh.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	sh.mu.Unlock()
	return nil
}

// EnsureValid checks if token is expired and refreshes if needed
func (sh *SessionHandler) EnsureValid() {
	if !sh.tokenExpiry.IsZero() && time.Now().After(sh.tokenExpiry.Add(-30*time.Second)) {
		sh.RefreshToken()
	}
}

// --- Cookie Jar ---

// UpdateCookies extracts and stores cookies from a response
func (sh *SessionHandler) UpdateCookies(resp *Response, host string) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.cookieJar[host] == nil {
		sh.cookieJar[host] = make(map[string]string)
	}
	for _, cookie := range resp.Headers.Values("Set-Cookie") {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			value := strings.SplitN(parts[1], ";", 2)[0]
			sh.cookieJar[host][name] = value
		}
	}
}

// ApplyCookies adds stored cookies to a request
func (sh *SessionHandler) ApplyCookies(req *http.Request) {
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	cookies := sh.cookieJar[req.URL.Host]
	for name, value := range cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
}

// --- Macro System ---

// RecordMacro records a sequence of requests
func (sh *SessionHandler) RecordMacro(name string, steps []MacroStep, extractions []Extraction) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.macros = append(sh.macros, Macro{Name: name, Steps: steps, Extract: extractions})
}

// PlayMacro replays a recorded macro and returns extracted values
func (sh *SessionHandler) PlayMacro(name string) map[string]string {
	sh.mu.RLock()
	var macro *Macro
	for i := range sh.macros {
		if sh.macros[i].Name == name {
			macro = &sh.macros[i]
			break
		}
	}
	sh.mu.RUnlock()

	if macro == nil {
		return nil
	}

	extracted := make(map[string]string)
	for _, step := range macro.Steps {
		// Replace variables in URL and body
		stepURL := step.URL
		stepBody := step.Body
		for k, v := range extracted {
			stepURL = strings.ReplaceAll(stepURL, "{{"+k+"}}", v)
			stepBody = strings.ReplaceAll(stepBody, "{{"+k+"}}", v)
		}

		var resp *Response
		if step.Body != "" {
			resp = sh.http.Post(stepURL, step.Headers["Content-Type"], stepBody)
		} else {
			resp = sh.http.Get(stepURL)
		}
		if resp.Err != nil {
			continue
		}

		// Extract values
		for _, ext := range macro.Extract {
			re := regexp.MustCompile(ext.Pattern)
			var source string
			switch ext.From {
			case "body":
				source = resp.Body
			case "header":
				source = fmt.Sprintf("%v", resp.Headers)
			case "cookie":
				source = resp.Headers.Get("Set-Cookie")
			}
			if m := re.FindStringSubmatch(source); len(m) > 1 {
				extracted[ext.Name] = m[1]
			}
		}

		// Update cookie jar
		sh.UpdateCookies(resp, req_host(stepURL))
	}
	return extracted
}

// --- SAML ---

// SAMLLogin performs a basic SAML SSO flow
func (sh *SessionHandler) SAMLLogin(spURL string) (*Session, error) {
	// Step 1: Hit the SP, get redirected to IdP
	resp := sh.http.Get(spURL)
	if resp.Err != nil {
		return nil, resp.Err
	}

	// Extract SAMLRequest from redirect or form
	samlReqRe := regexp.MustCompile(`SAMLRequest=([^&"]+)`)
	actionRe := regexp.MustCompile(`action="([^"]+)"`)

	var idpURL string
	if resp.Headers.Get("Location") != "" {
		idpURL = resp.Headers.Get("Location")
	} else if m := actionRe.FindStringSubmatch(resp.Body); len(m) > 1 {
		idpURL = m[1]
	}

	if idpURL == "" {
		return nil, fmt.Errorf("no SAML redirect found")
	}

	_ = samlReqRe // used for extraction if needed

	// Step 2: Follow the IdP redirect, extract session cookies
	idpResp := sh.http.Get(idpURL)
	if idpResp.Err != nil {
		return nil, idpResp.Err
	}

	session := &Session{Cookies: make(map[string]string), Headers: make(map[string]string)}
	for _, cookie := range idpResp.Headers.Values("Set-Cookie") {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 {
			session.Cookies[strings.TrimSpace(parts[0])] = strings.SplitN(parts[1], ";", 2)[0]
		}
	}

	sh.mu.Lock()
	sh.sessions["saml"] = session
	sh.mu.Unlock()
	return session, nil
}

// GetSession returns the active session
func (sh *SessionHandler) GetSession(name string) *Session {
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	return sh.sessions[name]
}

func req_host(rawURL string) string {
	parsed, _ := url.Parse(rawURL)
	if parsed != nil {
		return parsed.Host
	}
	return ""
}
