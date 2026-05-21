package templates

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zanicool/apex-cli/pkg/engine"
)

// Template defines a reusable vulnerability check
type Template struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Severity string    `json:"severity"`
	Tags     []string  `json:"tags"`
	Requests []Request `json:"requests"`
}

type Request struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	Matchers []Matcher         `json:"matchers"`
}

type Matcher struct {
	Type      string   `json:"type"` // status, word, regex
	Words     []string `json:"words,omitempty"`
	Status    []int    `json:"status,omitempty"`
	Regex     []string `json:"regex,omitempty"`
	Condition string   `json:"condition"` // and, or
	Negative  bool     `json:"negative"`
}

type Result struct {
	TemplateID string
	Name       string
	Severity   string
	URL        string
	Matched    string
}

// RunTemplate executes a template against a target
func RunTemplate(tmpl *Template, baseURL string, httpClient *engine.HTTPClient) *Result {
	for _, req := range tmpl.Requests {
		testURL := baseURL + req.Path

		var resp *engine.Response
		switch strings.ToUpper(req.Method) {
		case "POST":
			resp = httpClient.Post(testURL, "application/x-www-form-urlencoded", req.Body)
		default:
			r, err := http.NewRequest(req.Method, testURL, nil)
			if err != nil {
				continue
			}
			for k, v := range req.Headers {
				r.Header.Set(k, v)
			}
			resp = httpClient.Do(r)
		}

		if resp.Err != nil {
			continue
		}

		if matchResponse(resp, req.Matchers) {
			return &Result{
				TemplateID: tmpl.ID,
				Name:       tmpl.Name,
				Severity:   tmpl.Severity,
				URL:        testURL,
				Matched:    extractMatch(resp, req.Matchers),
			}
		}
	}
	return nil
}

func matchResponse(resp *engine.Response, matchers []Matcher) bool {
	for _, m := range matchers {
		matched := false
		switch m.Type {
		case "status":
			for _, s := range m.Status {
				if resp.StatusCode == s {
					matched = true
					break
				}
			}
		case "word":
			bodyLower := strings.ToLower(resp.Body)
			if m.Condition == "and" {
				matched = true
				for _, w := range m.Words {
					if !strings.Contains(bodyLower, strings.ToLower(w)) {
						matched = false
						break
					}
				}
			} else {
				for _, w := range m.Words {
					if strings.Contains(bodyLower, strings.ToLower(w)) {
						matched = true
						break
					}
				}
			}
		case "regex":
			for _, pattern := range m.Regex {
				re, err := regexp.Compile(pattern)
				if err == nil && re.MatchString(resp.Body) {
					matched = true
					break
				}
			}
		}
		if m.Negative {
			matched = !matched
		}
		if !matched {
			return false
		}
	}
	return len(matchers) > 0
}

func extractMatch(resp *engine.Response, matchers []Matcher) string {
	for _, m := range matchers {
		if m.Type == "word" && len(m.Words) > 0 {
			return m.Words[0]
		}
		if m.Type == "regex" && len(m.Regex) > 0 {
			re, _ := regexp.Compile(m.Regex[0])
			if re != nil {
				if match := re.FindString(resp.Body); match != "" {
					return match
				}
			}
		}
	}
	return fmt.Sprintf("status:%d", resp.StatusCode)
}

// LoadTemplates loads all JSON templates from a directory
func LoadTemplates(dir string) ([]*Template, error) {
	var templates []*Template
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var tmpl Template
		if json.Unmarshal(data, &tmpl) == nil && tmpl.ID != "" {
			templates = append(templates, &tmpl)
		}
		return nil
	})
	return templates, err
}
