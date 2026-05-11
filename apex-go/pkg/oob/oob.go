package oob

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/apex-go/pkg/engine"
)

type Client struct {
	serverURL string
	domain    string
	active    bool
	client    *http.Client
	mu        sync.Mutex
}

type PollResponse struct {
	Hit   bool          `json:"hit"`
	Count int           `json:"count"`
	Data  []interface{} `json:"data"`
}

func NewClient(serverURL string) *Client {
	c := &Client{
		serverURL: serverURL,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
	// Health check
	resp, err := c.client.Get(serverURL + "/oob_health_check")
	if err == nil && resp.StatusCode == 200 {
		c.active = true
		c.domain = serverURL
	}
	return c
}

func (c *Client) Active() bool {
	return c.active
}

func (c *Client) Domain() string {
	return c.domain
}

func (c *Client) GenerateUID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())[4:16]
}

func (c *Client) PayloadURL(uid string) string {
	return fmt.Sprintf("%s/%s", c.serverURL, uid)
}

func (c *Client) Poll(uid string, timeout time.Duration) bool {
	if !c.active {
		return false
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := c.client.Get(fmt.Sprintf("%s/poll?uid=%s", c.serverURL, uid))
		if err == nil {
			defer resp.Body.Close()
			var pr PollResponse
			if json.NewDecoder(resp.Body).Decode(&pr) == nil && pr.Hit {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// DNSPayload generates a DNS-based OOB payload
func (c *Client) DNSPayload(uid string) string {
	return fmt.Sprintf("%s.dns.%s", uid, c.domain)
}

// Unused but matches interface expected by scanner
func (c *Client) GetConfig() *engine.Config { return nil }
