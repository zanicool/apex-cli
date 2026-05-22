package hackerone

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FetchScope retrieves in-scope assets from a HackerOne program
func FetchScope(programHandle string) ([]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	// H1 public program page exposes structured scopes
	url := fmt.Sprintf("https://hackerone.com/%s", programHandle)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch program: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Try parsing the JSON response for scope
	targets := parseScope(body, programHandle)
	if len(targets) > 0 {
		return targets, nil
	}

	// Fallback: try the policy page
	return fetchScopeFromPolicy(client, programHandle)
}

func parseScope(body []byte, handle string) []string {
	var targets []string

	// H1 embeds program data in JSON
	var data struct {
		Relationships struct {
			StructuredScopes struct {
				Data []struct {
					Attributes struct {
						AssetType       string `json:"asset_type"`
						AssetIdentifier string `json:"asset_identifier"`
						EligibleForBounty bool  `json:"eligible_for_bounty"`
					} `json:"attributes"`
				} `json:"data"`
			} `json:"structured_scopes"`
		} `json:"relationships"`
	}

	if json.Unmarshal(body, &data) == nil {
		for _, scope := range data.Relationships.StructuredScopes.Data {
			if scope.Attributes.EligibleForBounty {
				id := scope.Attributes.AssetIdentifier
				if scope.Attributes.AssetType == "URL" || scope.Attributes.AssetType == "WILDCARD" {
					// Clean up the identifier
					id = strings.TrimPrefix(id, "https://")
					id = strings.TrimPrefix(id, "http://")
					id = strings.TrimPrefix(id, "*.")
					id = strings.TrimSuffix(id, "/")
					if id != "" {
						targets = append(targets, id)
					}
				}
			}
		}
	}

	// Also try to find scope in HTML/JSON blob
	bodyStr := string(body)
	if strings.Contains(bodyStr, "asset_identifier") {
		// Extract domains from the page content
		lines := strings.Split(bodyStr, "asset_identifier")
		for _, line := range lines[1:] {
			if idx := strings.Index(line, "\":\""); idx >= 0 {
				rest := line[idx+3:]
				if end := strings.IndexAny(rest, "\""); end > 0 {
					domain := rest[:end]
					domain = strings.TrimPrefix(domain, "https://")
					domain = strings.TrimPrefix(domain, "http://")
					domain = strings.TrimPrefix(domain, "*.")
					domain = strings.TrimSuffix(domain, "/")
					if strings.Contains(domain, ".") && len(domain) > 3 && len(domain) < 100 {
						targets = append(targets, domain)
					}
				}
			}
		}
	}

	return dedupStrings(targets)
}

func fetchScopeFromPolicy(client *http.Client, handle string) ([]string, error) {
	// Try the bounty-targets-data GitHub repo as fallback
	url := fmt.Sprintf("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json")
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var programs []struct {
		Handle string `json:"handle"`
		Targets struct {
			InScope []struct {
				AssetIdentifier string `json:"asset_identifier"`
				AssetType       string `json:"asset_type"`
			} `json:"in_scope"`
		} `json:"targets"`
	}

	if json.Unmarshal(body, &programs) != nil {
		return nil, fmt.Errorf("failed to parse bounty targets data")
	}

	for _, p := range programs {
		if strings.EqualFold(p.Handle, handle) {
			var targets []string
			for _, t := range p.Targets.InScope {
				if t.AssetType == "URL" || t.AssetType == "WILDCARD" {
					id := t.AssetIdentifier
					id = strings.TrimPrefix(id, "https://")
					id = strings.TrimPrefix(id, "http://")
					id = strings.TrimPrefix(id, "*.")
					id = strings.TrimSuffix(id, "/")
					if id != "" {
						targets = append(targets, id)
					}
				}
			}
			return targets, nil
		}
	}
	return nil, fmt.Errorf("program '%s' not found", handle)
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
