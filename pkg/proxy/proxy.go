package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Proxy is a MITM HTTP/HTTPS proxy that intercepts and logs all traffic
type Proxy struct {
	Port       int
	CACert     *x509.Certificate
	CAKey      *ecdsa.PrivateKey
	History    []*RequestEntry
	mu         sync.RWMutex
	logDir     string
	onRequest  func(*RequestEntry)
	certCache  map[string]*tls.Certificate
	certMu     sync.Mutex
	intercepting bool
	interceptCh  chan *RequestEntry // for interactive intercept mode
}

type RequestEntry struct {
	ID        int               `json:"id"`
	Time      time.Time         `json:"time"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Host      string            `json:"host"`
	Path      string            `json:"path"`
	Headers   map[string]string `json:"req_headers"`
	Body      string            `json:"req_body"`
	Status    int               `json:"status"`
	RespSize  int               `json:"resp_size"`
	RespBody  string            `json:"resp_body"`
	RespHeaders map[string]string `json:"resp_headers"`
	Duration  time.Duration     `json:"duration"`
	TLS       bool              `json:"tls"`
	Params    map[string]string `json:"params"`
}

// New creates a new MITM proxy
func New(port int, logDir string) *Proxy {
	p := &Proxy{
		Port:      port,
		logDir:    logDir,
		certCache: make(map[string]*tls.Certificate),
		interceptCh: make(chan *RequestEntry, 100),
	}
	os.MkdirAll(logDir, 0755)
	p.generateCA()
	return p
}

// Start begins listening for proxy connections
func (p *Proxy) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.Port))
	if err != nil {
		return err
	}
	fmt.Printf("[proxy] MITM proxy listening on :%d\n", p.Port)
	fmt.Printf("[proxy] CA cert: %s/apex-ca.pem (install in browser)\n", p.logDir)

	server := &http.Server{Handler: p}
	go server.Serve(listener)
	return nil
}

// ServeHTTP handles both HTTP and CONNECT (HTTPS) requests
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// handleConnect handles HTTPS CONNECT tunneling with MITM
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", 500)
		return
	}

	// Accept the CONNECT
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Generate cert for this host
	host := strings.Split(r.Host, ":")[0]
	tlsCert := p.getCertForHost(host)

	// TLS handshake with client using our fake cert
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*tlsCert}}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		clientConn.Close()
		return
	}
	defer tlsConn.Close()

	// Read requests from the TLS connection
	buf := make([]byte, 65536)
	for {
		tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := tlsConn.Read(buf)
		if err != nil {
			return
		}

		// Parse the request
		reqData := string(buf[:n])
		lines := strings.Split(reqData, "\r\n")
		if len(lines) < 1 {
			return
		}

		parts := strings.Fields(lines[0])
		if len(parts) < 3 {
			return
		}

		method := parts[0]
		path := parts[1]
		fullURL := "https://" + r.Host + path

		// Extract headers and body
		headers := make(map[string]string)
		bodyStart := 0
		for i, line := range lines[1:] {
			if line == "" {
				bodyStart = i + 2
				break
			}
			kv := strings.SplitN(line, ": ", 2)
			if len(kv) == 2 {
				headers[kv[0]] = kv[1]
			}
		}
		body := ""
		if bodyStart > 0 && bodyStart < len(lines) {
			body = strings.Join(lines[bodyStart:], "\r\n")
		}

		// Forward to real server
		entry := p.forwardAndLog(method, fullURL, headers, body, true)

		// Send response back to client
		if entry != nil {
			resp := fmt.Sprintf("HTTP/1.1 %d OK\r\n", entry.Status)
			for k, v := range entry.RespHeaders {
				resp += fmt.Sprintf("%s: %s\r\n", k, v)
			}
			resp += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(entry.RespBody), entry.RespBody)
			tlsConn.Write([]byte(resp))
		}
		return // one request per connection for simplicity
	}
}

// handleHTTP handles plain HTTP requests
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Read body
	var body string
	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		body = string(bodyBytes)
	}

	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = strings.Join(v, ", ")
	}

	targetURL := r.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + r.Host + r.URL.RequestURI()
	}

	entry := p.forwardAndLog(r.Method, targetURL, headers, body, false)
	if entry == nil {
		http.Error(w, "proxy error", 502)
		return
	}

	// Write response
	for k, v := range entry.RespHeaders {
		w.Header().Set(k, v)
	}
	w.WriteHeader(entry.Status)
	w.Write([]byte(entry.RespBody))
}

func (p *Proxy) forwardAndLog(method, targetURL string, headers map[string]string, body string, isTLS bool) *RequestEntry {
	start := time.Now()

	// Build request
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, targetURL, reqBody)
	if err != nil {
		return nil
	}
	for k, v := range headers {
		if k != "Proxy-Connection" && k != "Proxy-Authorization" {
			req.Header.Set(k, v)
		}
	}

	// Send request
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB max

	duration := time.Since(start)

	// Parse URL for params
	parsed, _ := url.Parse(targetURL)
	params := make(map[string]string)
	if parsed != nil {
		for k, v := range parsed.Query() {
			params[k] = strings.Join(v, ",")
		}
	}

	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		respHeaders[k] = strings.Join(v, ", ")
	}

	// Create entry
	p.mu.Lock()
	entry := &RequestEntry{
		ID:       len(p.History) + 1,
		Time:     start,
		Method:   method,
		URL:      targetURL,
		Host:     parsed.Host,
		Path:     parsed.Path,
		Headers:  headers,
		Body:     body,
		Status:   resp.StatusCode,
		RespSize: len(respBody),
		RespBody: string(respBody),
		RespHeaders: respHeaders,
		Duration: duration,
		TLS:      isTLS,
		Params:   params,
	}
	p.History = append(p.History, entry)
	p.mu.Unlock()

	// Callback
	if p.onRequest != nil {
		p.onRequest(entry)
	}

	// Log to file
	p.logEntry(entry)

	return entry
}

// OnRequest sets a callback for each proxied request
func (p *Proxy) OnRequest(fn func(*RequestEntry)) {
	p.onRequest = fn
}

// GetHistory returns all logged requests
func (p *Proxy) GetHistory() []*RequestEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.History
}

// GetParams returns all discovered parameters across all requests
func (p *Proxy) GetParams() map[string][]string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make(map[string][]string)
	for _, entry := range p.History {
		for param := range entry.Params {
			result[entry.URL] = append(result[entry.URL], param)
		}
	}
	return result
}

// ExportForScanner converts proxy history into crawler-compatible format
func (p *Proxy) ExportForScanner() (pages []map[string]interface{}, params map[string][]string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	params = make(map[string][]string)
	seen := make(map[string]bool)

	for _, entry := range p.History {
		if !seen[entry.URL] {
			seen[entry.URL] = true
			pages = append(pages, map[string]interface{}{
				"url":    entry.URL,
				"status": entry.Status,
				"size":   entry.RespSize,
			})
		}
		for param := range entry.Params {
			params[entry.URL] = append(params[entry.URL], param)
		}
		// Also extract params from POST body
		if entry.Body != "" && strings.Contains(entry.Headers["Content-Type"], "form") {
			vals, _ := url.ParseQuery(entry.Body)
			for k := range vals {
				params[entry.URL] = append(params[entry.URL], k)
			}
		}
	}
	return
}

func (p *Proxy) logEntry(entry *RequestEntry) {
	data, _ := json.Marshal(entry)
	f, err := os.OpenFile(filepath.Join(p.logDir, "proxy.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(data)
	f.Write([]byte("\n"))
}

// --- TLS Certificate Generation ---

func (p *Proxy) generateCA() {
	caKeyPath := filepath.Join(p.logDir, "apex-ca.key")
	caCertPath := filepath.Join(p.logDir, "apex-ca.pem")

	// Check if CA already exists
	if _, err := os.Stat(caCertPath); err == nil {
		p.loadCA(caKeyPath, caCertPath)
		return
	}

	// Generate new CA
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Apex CLI"}, CommonName: "Apex MITM CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(certDER)

	// Save
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(caKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600)
	os.WriteFile(caCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0644)

	p.CAKey = key
	p.CACert = cert
}

func (p *Proxy) loadCA(keyPath, certPath string) {
	keyPEM, _ := os.ReadFile(keyPath)
	certPEM, _ := os.ReadFile(certPath)

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock != nil {
		p.CAKey, _ = x509.ParseECPrivateKey(keyBlock.Bytes)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock != nil {
		p.CACert, _ = x509.ParseCertificate(certBlock.Bytes)
	}
}

func (p *Proxy) getCertForHost(host string) *tls.Certificate {
	p.certMu.Lock()
	defer p.certMu.Unlock()

	if cert, ok := p.certCache[host]; ok {
		return cert
	}

	// Generate cert signed by our CA
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, p.CACert, &key.PublicKey, p.CAKey)
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	p.certCache[host] = tlsCert
	return tlsCert
}
