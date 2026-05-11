package engine

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Target    string
	Deep      bool
	Rate      float64
	Threads   int
	Timeout   time.Duration
	Proxy     string
	OutputDir string
	Report    string
	Scope     string
	Skip      string
	DryRun    bool
	OOBServer string
	NoOOB     bool
}

type HTTPClient struct {
	clients  []*http.Client
	cfg      *Config
	mu       sync.Mutex
	idx      int
	reqCount atomic.Int64
	jitter   float64
}

type Response struct {
	URL        string
	StatusCode int
	Body       string
	Headers    http.Header
	Size       int
	Duration   time.Duration
	Err        error
}

// TLS fingerprint configs to rotate through
var tlsConfigs = []*tls.Config{
	{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true},
	{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, InsecureSkipVerify: true,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384}},
	{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true},
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
}

func NewHTTPClient(cfg *Config) *HTTPClient {
	h := &HTTPClient{cfg: cfg, jitter: 0.3}
	for _, tlsCfg := range tlsConfigs {
		transport := &http.Transport{
			TLSClientConfig:     tlsCfg,
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     100,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
		if cfg.Proxy != "" {
			if proxyURL, err := url.Parse(cfg.Proxy); err == nil {
				transport.Proxy = http.ProxyURL(proxyURL)
			}
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
		h.clients = append(h.clients, client)
	}
	return h
}

func (h *HTTPClient) getClient() *http.Client {
	h.mu.Lock()
	c := h.clients[h.idx%len(h.clients)]
	h.idx++
	h.mu.Unlock()
	return c
}

func (h *HTTPClient) Do(req *http.Request) *Response {
	if h.cfg.DryRun {
		return &Response{URL: req.URL.String(), StatusCode: 0}
	}
	// Rate limiting with jitter
	if h.cfg.Rate > 0 {
		jitter := h.cfg.Rate * h.jitter * (rand.Float64()*2 - 1)
		time.Sleep(time.Duration((h.cfg.Rate + jitter) * float64(time.Second)))
	}
	// Rotate User-Agent
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	}

	start := time.Now()
	resp, err := h.getClient().Do(req)
	duration := time.Since(start)
	h.reqCount.Add(1)

	if err != nil {
		return &Response{URL: req.URL.String(), Err: err, Duration: duration}
	}
	defer resp.Body.Close()

	// Read body with size limit (10MB)
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	total := 0
	for total < 10*1024*1024 {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			total += n
		}
		if err != nil {
			break
		}
	}

	return &Response{
		URL:        req.URL.String(),
		StatusCode: resp.StatusCode,
		Body:       string(buf),
		Headers:    resp.Header,
		Size:       total,
		Duration:   duration,
	}
}

func (h *HTTPClient) Get(targetURL string) *Response {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return &Response{URL: targetURL, Err: err}
	}
	return h.Do(req)
}

func (h *HTTPClient) Post(targetURL, contentType, body string) *Response {
	req, err := http.NewRequest("POST", targetURL, strings.NewReader(body))
	if err != nil {
		return &Response{URL: targetURL, Err: err}
	}
	req.Header.Set("Content-Type", contentType)
	return h.Do(req)
}

// BatchGet fires concurrent GET requests and returns results via channel
func (h *HTTPClient) BatchGet(urls []string, workers int) <-chan *Response {
	ch := make(chan *Response, len(urls))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, u := range urls {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ch <- h.Get(target)
		}(u)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}

// BatchRequest fires concurrent custom requests
type RequestItem struct {
	URL     string
	Method  string
	Body    string
	Headers map[string]string
}

func (h *HTTPClient) BatchRequest(items []RequestItem, workers int) <-chan *Response {
	ch := make(chan *Response, len(items))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, item := range items {
		wg.Add(1)
		go func(it RequestItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var req *http.Request
			var err error
			if it.Body != "" {
				req, err = http.NewRequest(it.Method, it.URL, strings.NewReader(it.Body))
			} else {
				req, err = http.NewRequest(it.Method, it.URL, nil)
			}
			if err != nil {
				ch <- &Response{URL: it.URL, Err: err}
				return
			}
			for k, v := range it.Headers {
				req.Header.Set(k, v)
			}
			ch <- h.Do(req)
		}(item)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}

func (h *HTTPClient) RequestCount() int64 {
	return h.reqCount.Load()
}

func SafeName(s string) string {
	re := regexp.MustCompile(`[^\w]`)
	return re.ReplaceAllString(s, "_")
}

func InScope(target, scope string) bool {
	if scope == "" {
		return true
	}
	for _, s := range strings.Split(scope, ",") {
		if strings.Contains(target, strings.TrimSpace(s)) {
			return true
		}
	}
	return false
}

func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}
