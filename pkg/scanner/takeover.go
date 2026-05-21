package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// Subdomain takeover fingerprints — CNAME points to service that returns error page
var takeoverFingerprints = []struct {
	cname   string // CNAME contains this
	body    string // Response body contains this (proves unclaimed)
	service string
}{
	{"herokuapp.com", "No such app", "Heroku"},
	{"herokuapp.com", "There is no app configured at that hostname", "Heroku"},
	{"github.io", "There isn't a GitHub Pages site here", "GitHub Pages"},
	{"github.io", "For root URLs (like http://example.com/) you must provide an index.html", "GitHub Pages"},
	{"s3.amazonaws.com", "NoSuchBucket", "AWS S3"},
	{"s3-website", "NoSuchBucket", "AWS S3"},
	{"cloudfront.net", "Bad request", "AWS CloudFront"},
	{"shopify.com", "Sorry, this shop is currently unavailable", "Shopify"},
	{"myshopify.com", "Sorry, this shop is currently unavailable", "Shopify"},
	{"fastly.net", "Fastly error: unknown domain", "Fastly"},
	{"ghost.io", "The thing you were looking for is no longer here", "Ghost"},
	{"pantheonsite.io", "404 error unknown site", "Pantheon"},
	{"domains.tumblr.com", "There's nothing here", "Tumblr"},
	{"tumblr.com", "Whatever you were looking for doesn't currently exist at this address", "Tumblr"},
	{"wordpress.com", "Do you want to register", "WordPress.com"},
	{"wpengine.com", "The site you were looking for couldn't be found", "WP Engine"},
	{"surge.sh", "project not found", "Surge.sh"},
	{"bitbucket.io", "Repository not found", "Bitbucket"},
	{"zendesk.com", "Help Center Closed", "Zendesk"},
	{"zendesk.com", "Oops, this help center no longer exists", "Zendesk"},
	{"teamwork.com", "Oops - We didn't find your site", "Teamwork"},
	{"unbounce.com", "The requested URL was not found on this server", "Unbounce"},
	{"helpjuice.com", "We could not find what you're looking for", "HelpJuice"},
	{"helpscoutdocs.com", "No settings were found for this company", "HelpScout"},
	{"statuspage.io", "You are being redirected", "StatusPage"},
	{"statuspage.io", "Status page pushed a DNS", "StatusPage"},
	{"uservoice.com", "This UserVoice subdomain is currently available", "UserVoice"},
	{"smugmug.com", "Page Not Found", "SmugMug"},
	{"strikingly.com", "But if you're looking to build your own website", "Strikingly"},
	{"uptimerobot.com", "page not found", "UptimeRobot"},
	{"freshdesk.com", "There is no helpdesk here", "Freshdesk"},
	{"readme.io", "Project doesnt exist", "Readme.io"},
	{"azurewebsites.net", "404 Web Site not found", "Azure"},
	{"cloudapp.net", "404 Web Site not found", "Azure"},
	{"trafficmanager.net", "404 Web Site not found", "Azure"},
	{"blob.core.windows.net", "BlobNotFound", "Azure Blob"},
	{"cargocollective.com", "404 Not Found", "Cargo"},
	{"feedpress.me", "The feed has not been found", "FeedPress"},
	{"fly.dev", "404 Not Found", "Fly.io"},
	{"netlify.app", "Not Found - Request ID", "Netlify"},
	{"vercel.app", "The deployment could not be found", "Vercel"},
	{"render.com", "not found", "Render"},
	{"ngrok.io", "Tunnel not found", "Ngrok"},
	{"agilecrm.com", "Sorry, this page is no longer available", "AgileCRM"},
	{"aha.io", "There is no portal here", "Aha"},
	{"tilda.ws", "Please renew your subscription", "Tilda"},
	{"landingi.com", "It looks like you're lost", "Landingi"},
}

// scanSubdomainTakeoverReal does actual CNAME resolution + fingerprint matching
func scanSubdomainTakeoverReal(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	// Get all subdomains from recon (stored in pages)
	subdomains := make(map[string]bool)
	for _, page := range crawl.Pages {
		host := extractHostFromURL(page.URL)
		if host != "" {
			subdomains[host] = true
		}
	}

	for subdomain := range subdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Resolve CNAME
			cname, err := net.LookupCNAME(sub)
			if err != nil || cname == "" || cname == sub+"." {
				return
			}
			cname = strings.TrimSuffix(cname, ".")

			// Check if CNAME matches any vulnerable service
			for _, fp := range takeoverFingerprints {
				if !strings.Contains(strings.ToLower(cname), fp.cname) {
					continue
				}

				// Verify: does the service return the "unclaimed" fingerprint?
				resp := h.Get("http://" + sub)
				if resp.Err != nil {
					resp = h.Get("https://" + sub)
				}
				if resp.Err != nil {
					continue
				}

				if strings.Contains(resp.Body, fp.body) {
					mu.Lock()
					findings = append(findings, Finding{
						Type:     "Subdomain Takeover — " + fp.service,
						Severity: "critical",
						URL:      "https://" + sub,
						Detail:   fmt.Sprintf("CNAME %s → %s. Service returns '%s' (unclaimed)", sub, cname, fp.body[:min(50, len(fp.body))]),
						Evidence: fmt.Sprintf("CNAME: %s | Fingerprint: %s", cname, fp.service),
						Template: "apex-subdomain-takeover",
					})
					mu.Unlock()
					return
				}
			}
		}(subdomain)
	}
	wg.Wait()
	return findings
}

func extractHostFromURL(rawURL string) string {
	// Extract host from URL like https://sub.domain.com/path
	if idx := strings.Index(rawURL, "//"); idx >= 0 {
		rest := rawURL[idx+2:]
		if slashIdx := strings.IndexAny(rest, "/:"); slashIdx > 0 {
			return rest[:slashIdx]
		}
		return rest
	}
	return ""
}
