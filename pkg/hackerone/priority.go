package hackerone

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Target represents a prioritized scan target
type Target struct {
	Handle   string  `json:"handle"`
	Domain   string  `json:"domain"`
	Score    float64 `json:"score"`
	MaxBounty int    `json:"max_bounty"`
	Reports  int     `json:"reports"`
	Age      int     `json:"age_days"` // days since program launched
}

// PrioritizeTargets fetches all H1 bounty programs and ranks them
func PrioritizeTargets() ([]Target, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var programs []struct {
		Handle        string `json:"handle"`
		OffersBounties bool  `json:"offers_bounties"`
		MaxBounty     int    `json:"max_bounty"`
		Targets       struct {
			InScope []struct {
				AssetIdentifier string `json:"asset_identifier"`
				AssetType       string `json:"asset_type"`
			} `json:"in_scope"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(body, &programs); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	var targets []Target
	for _, p := range programs {
		if !p.OffersBounties {
			continue
		}
		for _, t := range p.Targets.InScope {
			if t.AssetType != "URL" && t.AssetType != "WILDCARD" {
				continue
			}
			domain := cleanDomain(t.AssetIdentifier)
			if domain == "" {
				continue
			}
			score := scoreTarget(p.MaxBounty, len(p.Targets.InScope))
			targets = append(targets, Target{
				Handle:    p.Handle,
				Domain:    domain,
				Score:     score,
				MaxBounty: p.MaxBounty,
			})
		}
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Score > targets[j].Score
	})
	return targets, nil
}

// scoreTarget: high bounty + few assets (less competition) = higher score
func scoreTarget(maxBounty, assetCount int) float64 {
	bountyScore := float64(maxBounty) / 10000.0 // normalize to 0-1 range for most programs
	if bountyScore > 1.0 {
		bountyScore = 1.0 + (bountyScore-1.0)*0.1 // diminishing returns above 10k
	}
	// Fewer assets = less competition (more researchers per asset on big programs)
	competitionPenalty := 1.0
	if assetCount > 50 {
		competitionPenalty = 0.7
	} else if assetCount > 20 {
		competitionPenalty = 0.85
	}
	return bountyScore * competitionPenalty
}

func cleanDomain(id string) string {
	id = strings.TrimPrefix(id, "https://")
	id = strings.TrimPrefix(id, "http://")
	id = strings.TrimPrefix(id, "*.")
	id = strings.TrimSuffix(id, "/")
	if strings.Contains(id, ".") && len(id) > 3 && len(id) < 100 && !strings.Contains(id, " ") {
		return id
	}
	return ""
}
