package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const cacheDir = ".apex-cache"

type TargetCache struct {
	Target     string    `json:"target"`
	Subdomains []string  `json:"subdomains,omitempty"`
	LiveHosts  []string  `json:"live_hosts,omitempty"`
	Techs      []string  `json:"techs,omitempty"`
	WAFs       []string  `json:"wafs,omitempty"`
	Wildcard   bool      `json:"wildcard,omitempty"`
	LastScan   time.Time `json:"last_scan"`
	BodyHash   string    `json:"body_hash,omitempty"`
}

// Load returns cached data for a target, or nil if stale/missing
func Load(target string, maxAge time.Duration) *TargetCache {
	path := cachePath(target)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var tc TargetCache
	if json.Unmarshal(data, &tc) != nil {
		return nil
	}
	if time.Since(tc.LastScan) > maxAge {
		return nil
	}
	return &tc
}

// Save persists target scan data
func Save(tc *TargetCache) error {
	tc.LastScan = time.Now()
	dir := filepath.Join(homeDir(), cacheDir)
	os.MkdirAll(dir, 0755)
	data, err := json.Marshal(tc)
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath(tc.Target), data, 0644)
}

// HasChanged checks if a target's response has changed since last scan
func HasChanged(target, currentBodyHash string) bool {
	tc := Load(target, 7*24*time.Hour) // 7 day max
	if tc == nil {
		return true // no cache = treat as changed
	}
	return tc.BodyHash != currentBodyHash
}

// Hash returns a stable hash for response body comparison
func Hash(body string) string {
	h := sha256.Sum256([]byte(body))
	return fmt.Sprintf("%x", h[:8])
}

// IsRecentlyScan checks if target was scanned within cooldown period
func IsRecentlyScanned(target string, cooldown time.Duration) bool {
	tc := Load(target, cooldown)
	return tc != nil
}

func cachePath(target string) string {
	h := sha256.Sum256([]byte(target))
	name := fmt.Sprintf("%x.json", h[:8])
	return filepath.Join(homeDir(), cacheDir, name)
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/tmp"
}
