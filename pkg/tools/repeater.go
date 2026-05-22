package tools

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/engine"
)

// Repeater replays HTTP requests with modifications
type Repeater struct {
	http    *engine.HTTPClient
	History []RepeaterEntry
	mu      sync.Mutex
}

type RepeaterEntry struct {
	ID       int             `json:"id"`
	Request  RequestDef      `json:"request"`
	Response *engine.Response `json:"response"`
	Time     time.Time       `json:"time"`
}

type RequestDef struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func NewRepeater(h *engine.HTTPClient) *Repeater {
	return &Repeater{http: h}
}

// Send sends a request and logs it
func (r *Repeater) Send(req RequestDef) *engine.Response {
	httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		return &engine.Response{Err: err}
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	resp := r.http.Do(httpReq)

	r.mu.Lock()
	r.History = append(r.History, RepeaterEntry{
		ID: len(r.History) + 1, Request: req, Response: resp, Time: time.Now(),
	})
	r.mu.Unlock()
	return resp
}

// Modify creates a modified copy of a request
func (r *Repeater) Modify(base RequestDef, param, value string) RequestDef {
	modified := RequestDef{
		Method:  base.Method,
		URL:     base.URL,
		Headers: make(map[string]string),
		Body:    base.Body,
	}
	for k, v := range base.Headers {
		modified.Headers[k] = v
	}

	// Replace in URL query
	if strings.Contains(modified.URL, param+"=") {
		parts := strings.SplitN(modified.URL, "?", 2)
		if len(parts) == 2 {
			params := strings.Split(parts[1], "&")
			for i, p := range params {
				if strings.HasPrefix(p, param+"=") {
					params[i] = param + "=" + value
				}
			}
			modified.URL = parts[0] + "?" + strings.Join(params, "&")
		}
	}

	// Replace in body
	if strings.Contains(modified.Body, param) {
		modified.Body = strings.Replace(modified.Body, param+"="+getParamValue(base.Body, param), param+"="+value, 1)
		// JSON body
		modified.Body = strings.Replace(modified.Body, `"`+param+`":"`, `"`+param+`":"`+value+`"`, 1)
	}

	return modified
}

// --- Intruder: automated parameter fuzzing ---

// Intruder performs automated fuzzing of parameters with payloads
type Intruder struct {
	http    *engine.HTTPClient
	Results []IntruderResult
	mu      sync.Mutex
}

type IntruderResult struct {
	Payload    string           `json:"payload"`
	Status     int              `json:"status"`
	Size       int              `json:"size"`
	Duration   time.Duration    `json:"duration"`
	Anomaly    bool             `json:"anomaly"`
	Response   *engine.Response `json:"-"`
}

type IntruderConfig struct {
	Request    RequestDef
	Param      string   // parameter to fuzz
	Payloads   []string // payload list
	Workers    int
	MatchCodes []int    // status codes to flag
	MatchSize  int      // flag if size differs by this much from baseline
}

func NewIntruder(h *engine.HTTPClient) *Intruder {
	return &Intruder{http: h}
}

// Attack runs the intruder attack
func (i *Intruder) Attack(cfg IntruderConfig) []IntruderResult {
	if cfg.Workers == 0 {
		cfg.Workers = 20
	}

	// Get baseline
	repeater := NewRepeater(i.http)
	baseResp := repeater.Send(cfg.Request)
	baseSize := 0
	baseStatus := 0
	if baseResp != nil {
		baseSize = baseResp.Size
		baseStatus = baseResp.StatusCode
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Workers)

	for _, payload := range cfg.Payloads {
		wg.Add(1)
		go func(pl string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Inject payload
			modified := repeater.Modify(cfg.Request, cfg.Param, pl)
			resp := repeater.Send(modified)
			if resp == nil {
				return
			}

			// Detect anomalies
			anomaly := false
			if resp.StatusCode != baseStatus {
				anomaly = true
			}
			if cfg.MatchSize > 0 && abs(resp.Size-baseSize) > cfg.MatchSize {
				anomaly = true
			}
			for _, code := range cfg.MatchCodes {
				if resp.StatusCode == code {
					anomaly = true
				}
			}
			// Time-based anomaly
			if resp.Duration > 3*time.Second && baseResp.Duration < 1*time.Second {
				anomaly = true
			}

			result := IntruderResult{
				Payload:  pl,
				Status:   resp.StatusCode,
				Size:     resp.Size,
				Duration: resp.Duration,
				Anomaly:  anomaly,
				Response: resp,
			}

			i.mu.Lock()
			i.Results = append(i.Results, result)
			i.mu.Unlock()
		}(payload)
	}
	wg.Wait()
	return i.Results
}

// GetAnomalies returns only results that differ from baseline
func (i *Intruder) GetAnomalies() []IntruderResult {
	i.mu.Lock()
	defer i.mu.Unlock()
	var anomalies []IntruderResult
	for _, r := range i.Results {
		if r.Anomaly {
			anomalies = append(anomalies, r)
		}
	}
	return anomalies
}

// --- Payload generators ---

// ClusterBomb generates all combinations of multiple payload positions
func ClusterBomb(positions [][]string) [][]string {
	if len(positions) == 0 {
		return nil
	}
	result := [][]string{{}}
	for _, pos := range positions {
		var newResult [][]string
		for _, existing := range result {
			for _, payload := range pos {
				combo := make([]string, len(existing)+1)
				copy(combo, existing)
				combo[len(existing)] = payload
				newResult = append(newResult, combo)
			}
		}
		result = newResult
	}
	return result
}

// Sniper iterates one payload at a time through each position
func Sniper(baseReq RequestDef, params []string, payloads []string) []RequestDef {
	var requests []RequestDef
	repeater := &Repeater{}
	for _, param := range params {
		for _, payload := range payloads {
			requests = append(requests, repeater.Modify(baseReq, param, payload))
		}
	}
	return requests
}

// BatteringRam uses same payload in all positions simultaneously
func BatteringRam(baseReq RequestDef, params []string, payloads []string) []RequestDef {
	var requests []RequestDef
	repeater := &Repeater{}
	for _, payload := range payloads {
		req := baseReq
		for _, param := range params {
			req = repeater.Modify(req, param, payload)
		}
		requests = append(requests, req)
	}
	return requests
}

// --- Built-in payload lists ---

func SQLiPayloads() []string {
	return []string{
		"'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
		"1' AND SLEEP(3)--", "1 AND 1=1", "1 AND 1=2",
		"' UNION SELECT NULL--", "admin'--", "1; DROP TABLE users--",
	}
}

func XSSPayloads() []string {
	return []string{
		"<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
		"\"><svg onload=alert(1)>", "'-alert(1)-'",
		"javascript:alert(1)", "<details open ontoggle=alert(1)>",
	}
}

func AuthBypassPayloads() []string {
	return []string{
		"admin", "administrator", "root", "test", "guest",
		"' OR '1'='1'--", "admin'--", "\" OR 1=1--",
		"true", "1", "null", "undefined",
	}
}

func IDORPayloads() []string {
	return []string{"0", "1", "2", "100", "999", "1000", "-1", "null", "undefined", "admin"}
}

// --- Helpers ---

func getParamValue(body, param string) string {
	idx := strings.Index(body, param+"=")
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(param)+1:]
	end := strings.IndexAny(rest, "&\n\r")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// PrintResults displays intruder results in a table format
func PrintResults(results []IntruderResult) {
	fmt.Printf("%-5s %-6s %-8s %-10s %s\n", "CODE", "SIZE", "TIME", "ANOMALY", "PAYLOAD")
	fmt.Println(strings.Repeat("-", 70))
	for _, r := range results {
		flag := ""
		if r.Anomaly {
			flag = "⚠️"
		}
		fmt.Printf("%-5d %-6d %-8s %-10s %s\n", r.Status, r.Size, r.Duration.Round(time.Millisecond), flag, r.Payload)
	}
}
