package engine

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// Session represents an authenticated session that can be replayed
type Session struct {
	Cookies map[string]string `json:"cookies"`
	Headers map[string]string `json:"headers"`
	Token   string            `json:"token"`
}

// LoadSession loads a session from a JSON file (exported from browser)
func LoadSession(path string) (*Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ApplySession injects session credentials into an HTTP request
func (s *Session) ApplySession(req *http.Request) {
	if s == nil {
		return
	}
	// Apply cookies
	for name, value := range s.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	// Apply headers (Authorization, X-CSRF-Token, etc.)
	for name, value := range s.Headers {
		req.Header.Set(name, value)
	}
	// Apply bearer token
	if s.Token != "" && req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
}

// AuthenticatedGet performs a GET with session credentials
func (h *HTTPClient) AuthGet(targetURL string, session *Session) *Response {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return &Response{URL: targetURL, Err: err}
	}
	session.ApplySession(req)
	return h.Do(req)
}

// AuthenticatedPost performs a POST with session credentials
func (h *HTTPClient) AuthPost(targetURL, contentType, body string, session *Session) *Response {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body))
	if err != nil {
		return &Response{URL: targetURL, Err: err}
	}
	req.Header.Set("Content-Type", contentType)
	session.ApplySession(req)
	return h.Do(req)
}
