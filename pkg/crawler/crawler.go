package crawler

import (
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/zanicool/apex-cli/pkg/engine"
)

type Page struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status"`
	Size       int    `json:"size"`
}

type Form struct {
	URL    string  `json:"url"`
	Action string  `json:"action"`
	Method string  `json:"method"`
	Inputs []Input `json:"inputs"`
}

type Input struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Result struct {
	Pages  []Page
	Forms  []Form
	Params map[string][]string // url -> param names
}

var (
	hrefRe   = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)
	srcRe    = regexp.MustCompile(`(?i)src=["']([^"']+)["']`)
	actionRe = regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*?)["'][^>]*>`)
	methodRe = regexp.MustCompile(`(?i)<form[^>]*method=["']([^"']*?)["']`)
	inputRe  = regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'][^>]*/?>`)
	paramRe  = regexp.MustCompile(`[?&]([^=&]+)=`)
	jsURLRe  = regexp.MustCompile(`(?:fetch|axios\.get|axios\.post|XMLHttpRequest|\.open)\s*\(\s*["']([^"']+)["']`)
)

func Run(cfg *engine.Config, http *engine.HTTPClient, targets []string) *Result {
	result := &Result{
		Params: make(map[string][]string),
	}

	visited := &sync.Map{}
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	maxPages := 200
	if cfg.Deep {
		maxPages = 1000
	}
	pageCount := 0

	// Seed with targets
	queue := make(chan string, 10000)
	for _, t := range targets {
		queue <- t
	}

	// Worker pool
	for i := 0; i < cfg.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				var target string
				select {
				case t, ok := <-queue:
					if !ok {
						return
					}
					target = t
				default:
					return
				}

				if _, loaded := visited.LoadOrStore(target, true); loaded {
					continue
				}

				mu.Lock()
				if pageCount >= maxPages {
					mu.Unlock()
					return
				}
				pageCount++
				mu.Unlock()

				sem <- struct{}{}
				resp := http.Get(target)
				<-sem

				if resp.Err != nil || resp.StatusCode == 0 {
					continue
				}

				mu.Lock()
				result.Pages = append(result.Pages, Page{
					URL: target, StatusCode: resp.StatusCode, Size: resp.Size,
				})
				mu.Unlock()

				// Extract links
				baseURL, _ := url.Parse(target)
				links := extractLinks(resp.Body, baseURL)
				forms := extractForms(resp.Body, baseURL, target)
				params := extractParams(target, resp.Body)

				mu.Lock()
				result.Forms = append(result.Forms, forms...)
				for u, ps := range params {
					result.Params[u] = append(result.Params[u], ps...)
				}
				// Add form actions as crawl targets with their inputs as params
				for _, form := range forms {
					action := form.Action
					if action == "" {
						action = target
					}
					var formParams []string
					for _, inp := range form.Inputs {
						if inp.Name != "" {
							formParams = append(formParams, inp.Name)
						}
					}
					if len(formParams) > 0 {
						result.Params[action] = append(result.Params[action], formParams...)
					}
				}
				mu.Unlock()

				// Queue new links (same host or related domains)
				for _, link := range links {
					linkURL, err := url.Parse(link)
					if err != nil || linkURL.Host == "" {
						continue
					}
					// Allow same host OR subdomains of target
					sameOrg := linkURL.Host == baseURL.Host ||
						strings.HasSuffix(linkURL.Host, "."+baseURL.Host) ||
						strings.HasSuffix(baseURL.Host, "."+linkURL.Host)
					if sameOrg && engine.InScope(link, cfg.Scope) {
						select {
						case queue <- link:
						default:
						}
					}
				}
			}
		}()
	}

	// Wait a bit for initial crawl, then close
	wg.Wait()
	close(queue)

	// Deduplicate params
	for u, ps := range result.Params {
		result.Params[u] = dedupStrings(ps)
	}

	return result
}

func extractLinks(body string, base *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	for _, re := range []*regexp.Regexp{hrefRe, srcRe, jsURLRe} {
		matches := re.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			link := m[1]
			if strings.HasPrefix(link, "#") || strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") {
				continue
			}
			resolved := resolveURL(link, base)
			if resolved != "" && !seen[resolved] {
				seen[resolved] = true
				links = append(links, resolved)
			}
		}
	}
	return links
}

func extractForms(body string, base *url.URL, pageURL string) []Form {
	var forms []Form
	actionMatches := actionRe.FindAllStringSubmatch(body, -1)
	methodMatches := methodRe.FindAllStringSubmatch(body, -1)
	inputMatches := inputRe.FindAllStringSubmatch(body, -1)

	for i, am := range actionMatches {
		action := resolveURL(am[1], base)
		if action == "" {
			action = pageURL
		}
		method := "GET"
		if i < len(methodMatches) {
			method = strings.ToUpper(methodMatches[i][1])
		}
		var inputs []Input
		for _, im := range inputMatches {
			inputs = append(inputs, Input{Name: im[1], Type: "text"})
		}
		forms = append(forms, Form{URL: pageURL, Action: action, Method: method, Inputs: inputs})
	}
	return forms
}

func extractParams(pageURL, body string) map[string][]string {
	params := make(map[string][]string)
	// From URL
	matches := paramRe.FindAllStringSubmatch(pageURL, -1)
	baseURL := strings.Split(pageURL, "?")[0]
	for _, m := range matches {
		params[baseURL] = append(params[baseURL], m[1])
	}
	// From body links
	for _, m := range paramRe.FindAllStringSubmatch(body, -1) {
		params[baseURL] = append(params[baseURL], m[1])
	}
	// From form inputs — extract input names as params for the form action
	formActions := actionRe.FindAllStringSubmatch(body, -1)
	inputNames := inputRe.FindAllStringSubmatch(body, -1)
	if len(inputNames) > 0 {
		actionURL := baseURL
		if len(formActions) > 0 && formActions[0][1] != "" {
			actionURL = formActions[0][1]
			if !strings.HasPrefix(actionURL, "http") {
				actionURL = baseURL
			}
		}
		for _, m := range inputNames {
			params[actionURL] = append(params[actionURL], m[1])
		}
		// Also add to the page URL itself (for GET forms)
		if actionURL != baseURL {
			for _, m := range inputNames {
				params[baseURL] = append(params[baseURL], m[1])
			}
		}
	}
	// Extract params from href links in body
	for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
		if len(m) >= 2 && strings.Contains(m[1], "?") {
			linkParams := paramRe.FindAllStringSubmatch(m[1], -1)
			linkBase := strings.Split(m[1], "?")[0]
			if !strings.HasPrefix(linkBase, "http") {
				linkBase = baseURL
			}
			for _, p := range linkParams {
				params[linkBase] = append(params[linkBase], p[1])
			}
		}
	}
	return params
}

func resolveURL(href string, base *url.URL) string {
	if href == "" {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	return base.ResolveReference(ref).String()
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
