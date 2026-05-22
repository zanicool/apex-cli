package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// IntelDB is the collaborative intelligence database that learns across scans
type IntelDB struct {
	mu   sync.RWMutex
	path string
	Data IntelData
}

type IntelData struct {
	// Successful payloads per tech stack
	Payloads map[string][]PayloadRecord `json:"payloads"`
	// Target fingerprints (skip unchanged targets)
	Fingerprints map[string]TargetFingerprint `json:"fingerprints"`
	// Known false positive patterns
	FalsePositives []string `json:"false_positives"`
	// Scan history
	History []ScanRecord `json:"history"`
}

type PayloadRecord struct {
	Payload  string    `json:"payload"`
	VulnType string    `json:"vuln_type"`
	Tech     string    `json:"tech"`
	WAF      string    `json:"waf"`
	Success  int       `json:"success_count"`
	LastUsed time.Time `json:"last_used"`
}

type TargetFingerprint struct {
	Domain      string    `json:"domain"`
	Hash        string    `json:"hash"` // response hash
	Tech        []string  `json:"tech"`
	WAF         string    `json:"waf"`
	LastScanned time.Time `json:"last_scanned"`
	Findings    int       `json:"findings"`
}

type ScanRecord struct {
	Domain   string    `json:"domain"`
	Time     time.Time `json:"time"`
	Findings int       `json:"findings"`
	Duration string    `json:"duration"`
}

var globalIntel *IntelDB

func GetIntelDB() *IntelDB {
	if globalIntel == nil {
		dbPath := filepath.Join(os.Getenv("HOME"), ".apex-autopilot", "intel.json")
		globalIntel = &IntelDB{path: dbPath}
		globalIntel.load()
	}
	return globalIntel
}

func (db *IntelDB) load() {
	db.mu.Lock()
	defer db.mu.Unlock()
	data, err := os.ReadFile(db.path)
	if err != nil {
		db.Data = IntelData{
			Payloads:     make(map[string][]PayloadRecord),
			Fingerprints: make(map[string]TargetFingerprint),
		}
		return
	}
	json.Unmarshal(data, &db.Data)
	if db.Data.Payloads == nil {
		db.Data.Payloads = make(map[string][]PayloadRecord)
	}
	if db.Data.Fingerprints == nil {
		db.Data.Fingerprints = make(map[string]TargetFingerprint)
	}
}

func (db *IntelDB) Save() {
	db.mu.RLock()
	defer db.mu.RUnlock()
	os.MkdirAll(filepath.Dir(db.path), 0755)
	data, _ := json.MarshalIndent(db.Data, "", "  ")
	os.WriteFile(db.path, data, 0644)
}

// RecordPayload stores a successful payload
func (db *IntelDB) RecordPayload(vulnType, payload, tech, waf string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	key := vulnType + ":" + tech
	if waf != "" {
		key += ":" + waf
	}
	// Check if already exists, increment count
	for i, p := range db.Data.Payloads[key] {
		if p.Payload == payload {
			db.Data.Payloads[key][i].Success++
			db.Data.Payloads[key][i].LastUsed = time.Now()
			return
		}
	}
	db.Data.Payloads[key] = append(db.Data.Payloads[key], PayloadRecord{
		Payload: payload, VulnType: vulnType, Tech: tech, WAF: waf,
		Success: 1, LastUsed: time.Now(),
	})
	// Cap at 100 per key
	if len(db.Data.Payloads[key]) > 100 {
		db.Data.Payloads[key] = db.Data.Payloads[key][len(db.Data.Payloads[key])-100:]
	}
}

// GetBestPayloads returns top payloads for a given context, sorted by success count
func (db *IntelDB) GetBestPayloads(vulnType, tech, waf string) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var candidates []PayloadRecord
	// Exact match
	key := vulnType + ":" + tech
	if waf != "" {
		key += ":" + waf
	}
	candidates = append(candidates, db.Data.Payloads[key]...)
	// Fallback: just vuln type + tech
	if waf != "" {
		candidates = append(candidates, db.Data.Payloads[vulnType+":"+tech]...)
	}
	// Fallback: just vuln type
	candidates = append(candidates, db.Data.Payloads[vulnType+":"]...)

	// Sort by success count (simple bubble sort, small list)
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].Success < candidates[j].Success {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	seen := make(map[string]bool)
	var result []string
	for _, c := range candidates {
		if !seen[c.Payload] {
			seen[c.Payload] = true
			result = append(result, c.Payload)
		}
		if len(result) >= 20 {
			break
		}
	}
	return result
}

// UpdateFingerprint stores target state for change detection
func (db *IntelDB) UpdateFingerprint(domain, hash string, tech []string, waf string, findings int) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.Data.Fingerprints[domain] = TargetFingerprint{
		Domain: domain, Hash: hash, Tech: tech, WAF: waf,
		LastScanned: time.Now(), Findings: findings,
	}
}

// ShouldRescan checks if a target has changed since last scan
func (db *IntelDB) ShouldRescan(domain, currentHash string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	fp, exists := db.Data.Fingerprints[domain]
	if !exists {
		return true // never scanned
	}
	if fp.Hash != currentHash {
		return true // target changed
	}
	// Rescan if older than 7 days
	return time.Since(fp.LastScanned) > 7*24*time.Hour
}

// RecordScan stores scan history
func (db *IntelDB) RecordScan(domain string, findings int, duration time.Duration) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.Data.History = append(db.Data.History, ScanRecord{
		Domain: domain, Time: time.Now(), Findings: findings, Duration: duration.String(),
	})
	// Keep last 1000 scans
	if len(db.Data.History) > 1000 {
		db.Data.History = db.Data.History[len(db.Data.History)-1000:]
	}
}

// AddFalsePositive records a known false positive pattern
func (db *IntelDB) AddFalsePositive(pattern string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	for _, fp := range db.Data.FalsePositives {
		if fp == pattern {
			return
		}
	}
	db.Data.FalsePositives = append(db.Data.FalsePositives, pattern)
}

// IsFalsePositive checks if a finding matches known FP patterns
func (db *IntelDB) IsFalsePositive(finding Finding) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, fp := range db.Data.FalsePositives {
		if strings.Contains(finding.URL, fp) || strings.Contains(finding.Detail, fp) {
			return true
		}
	}
	return false
}

// Stats returns intelligence stats
func (db *IntelDB) Stats() (payloads int, targets int, scans int) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, v := range db.Data.Payloads {
		payloads += len(v)
	}
	return payloads, len(db.Data.Fingerprints), len(db.Data.History)
}
