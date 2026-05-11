package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- Subdomain Takeover ---

var takeoverFingerprints = map[string]string{
	"There is no app configured at that hostname":                    "Heroku",
	"NoSuchBucket":                                                   "AWS S3",
	"No such app":                                                    "Heroku",
	"You're Almost There":                                            "Tumblr",
	"There isn't a GitHub Pages site here":                           "GitHub Pages",
	"The request could not be satisfied":                             "CloudFront",
	"Sorry, this shop is currently unavailable":                      "Shopify",
	"Do you want to register":                                        "WordPress.com",
	"The feed has not been found":                                    "Feedpress",
	"project not found":                                              "Surge.sh",
	"With GetResponse, landing pages, webinars":                      "GetResponse",
	"Unrecognized domain":                                            "Helpjuice",
	"No settings were found for this company":                        "Help Scout",
	"is not a registered InCloud YouTrack":                           "JetBrains",
	"Trying to access your account":                                  "Kajabi",
	"It looks like you may have taken a wrong turn somewhere":        "LaunchRock",
	"The gods are wise":                                              "Pantheon",
}

func scanSubdomainTakeover(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for _, page := range crawl.Pages {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp := http.Get(url)
			if resp.Err != nil {
				return
			}
			for fingerprint, service := range takeoverFingerprints {
				if strings.Contains(resp.Body, fingerprint) {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "Subdomain Takeover — " + service, Severity: "critical",
						URL: url, Detail: fmt.Sprintf("Dangling %s resource. Register to take over this subdomain.", service),
						Template: "apex-subdomain-takeover",
					})
					mu.Unlock()
					break
				}
			}
		}(page.URL)
	}
	wg.Wait()
	return findings
}

// --- S3 Bucket Misconfiguration ---

func scanS3Buckets(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	// Extract bucket names from URLs
	buckets := make(map[string]bool)
	for _, page := range crawl.Pages {
		if strings.Contains(page.URL, "s3.amazonaws.com") ||
			strings.Contains(page.URL, ".s3.") {
			parts := strings.Split(page.URL, "/")
			for _, p := range parts {
				if strings.Contains(p, "s3") && strings.Contains(p, ".") {
					bucket := strings.Split(p, ".s3")[0]
					if bucket != "" {
						buckets[bucket] = true
					}
				}
			}
		}
	}

	// Also try target-based bucket names
	target := strings.Split(cfg.Target, ".")[0]
	guesses := []string{target, target + "-assets", target + "-backup", target + "-dev",
		target + "-staging", target + "-prod", target + "-uploads", target + "-data"}
	for _, g := range guesses {
		buckets[g] = true
	}

	for bucket := range buckets {
		wg.Add(1)
		go func(b string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check listing
			url := fmt.Sprintf("https://%s.s3.amazonaws.com/", b)
			resp := http.Get(url)
			if resp.Err != nil {
				return
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Body, "<ListBucketResult") {
				mu.Lock()
				findings = append(findings, Finding{
					Type: "S3 Bucket — Public Listing", Severity: "high",
					URL: url, Detail: fmt.Sprintf("Bucket '%s' allows public listing of all objects", b),
					Template: "apex-s3-listing",
				})
				mu.Unlock()
			}
			// Check write access
			putResp := http.Post(url+"apex-test.txt", "text/plain", "apex-security-test")
			if putResp.Err == nil && putResp.StatusCode == 200 {
				mu.Lock()
				findings = append(findings, Finding{
					Type: "S3 Bucket — Public Write", Severity: "critical",
					URL: url, Detail: fmt.Sprintf("Bucket '%s' allows public write — full compromise possible", b),
					Template: "apex-s3-write",
				})
				mu.Unlock()
			}
		}(bucket)
	}
	wg.Wait()
	return findings
}

// --- DNS Zone Transfer ---

func scanDNSZoneTransfer(cfg *engine.Config, _ *engine.HTTPClient, _ *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding

	// Get NS records
	nss, err := net.LookupNS(cfg.Target)
	if err != nil {
		return findings
	}

	for _, ns := range nss {
		// Try AXFR
		conn, err := net.DialTimeout("tcp", ns.Host+":53", 5*time.Second)
		if err != nil {
			continue
		}
		// Build minimal AXFR query
		domain := cfg.Target
		query := buildAXFRQuery(domain)
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		conn.Write(query)

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil && n > 12 {
			// Check if response contains answer records (not REFUSED)
			flags := int(buf[2])<<8 | int(buf[3])
			rcode := flags & 0x0F
			ancount := int(buf[6])<<8 | int(buf[7])
			if rcode == 0 && ancount > 0 {
				findings = append(findings, Finding{
					Type: "DNS Zone Transfer (AXFR)", Severity: "high",
					URL: fmt.Sprintf("NS: %s", ns.Host),
					Detail:   fmt.Sprintf("Zone transfer allowed on %s — all DNS records exposed", ns.Host),
					Template: "apex-zone-transfer",
				})
			}
		}
	}
	return findings
}

func buildAXFRQuery(domain string) []byte {
	// Transaction ID + flags + questions + AXFR type
	query := []byte{0x00, 0x1c} // length prefix for TCP
	query = append(query, 0xAA, 0xBB) // txid
	query = append(query, 0x00, 0x00) // flags (standard query)
	query = append(query, 0x00, 0x01) // 1 question
	query = append(query, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // 0 answer/auth/additional

	// Encode domain name
	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0x00)       // null terminator
	query = append(query, 0x00, 0xFC) // type AXFR (252)
	query = append(query, 0x00, 0x01) // class IN

	// Fix length prefix
	length := len(query) - 2
	query[0] = byte(length >> 8)
	query[1] = byte(length & 0xFF)
	return query
}

// --- VHost Fuzzing ---

func scanVHostFuzzing(cfg *engine.Config, http *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	vhostPrefixes := []string{"admin", "dev", "staging", "test", "internal", "api",
		"portal", "dashboard", "monitor", "grafana", "jenkins", "gitlab",
		"jira", "confluence", "kibana", "elastic", "redis", "mongo"}

	// Get baseline response for comparison
	baseTarget := ""
	if len(crawl.Pages) > 0 {
		baseTarget = crawl.Pages[0].URL
	} else {
		return findings
	}
	baseResp := http.Get(baseTarget)
	if baseResp.Err != nil {
		return findings
	}

	for _, prefix := range vhostPrefixes {
		wg.Add(1)
		go func(vhost string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			hostname := vhost + "." + cfg.Target
			items := []engine.RequestItem{{
				URL:     baseTarget,
				Method:  "GET",
				Headers: map[string]string{"Host": hostname},
			}}
			for resp := range http.BatchRequest(items, 1) {
				if resp.Err == nil && resp.StatusCode == 200 &&
					resp.Body != baseResp.Body && len(resp.Body) > 100 {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "Virtual Host Discovered — " + hostname, Severity: "medium",
						URL: baseTarget, Detail: fmt.Sprintf("VHost '%s' returns different content (%d bytes)", hostname, resp.Size),
						Template: "apex-vhost",
					})
					mu.Unlock()
				}
			}
		}(prefix)
	}
	wg.Wait()
	return findings
}
