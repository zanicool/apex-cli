package hackerone

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SubmittedReport tracks a previously reported finding
type SubmittedReport struct {
	Program   string    `json:"program"`
	VulnType  string    `json:"vuln_type"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Param     string    `json:"param,omitempty"`
	Submitted time.Time `json:"submitted"`
	ReportID  string    `json:"report_id,omitempty"`
	Status    string    `json:"status,omitempty"` // new, triaged, duplicate, resolved
}

type DupeDB struct {
	Reports []SubmittedReport `json:"reports"`
}

// IsDuplicate checks if a finding was already reported (by us or likely by others)
func IsDuplicate(program, vulnType, targetURL, param string) (bool, string) {
	db := loadDupeDB()

	parsed, _ := url.Parse(targetURL)
	host := ""
	path := ""
	if parsed != nil {
		host = parsed.Hostname()
		path = parsed.Path
	}

	for _, r := range db.Reports {
		if !strings.EqualFold(r.Program, program) {
			continue
		}
		// Same vuln type + same host + same path/param = duplicate
		if strings.EqualFold(r.VulnType, vulnType) && strings.EqualFold(r.Host, host) {
			if r.Path == path || (r.Param != "" && r.Param == param) {
				return true, fmt.Sprintf("already reported on %s (report: %s, status: %s)",
					r.Submitted.Format("2006-01-02"), r.ReportID, r.Status)
			}
		}
		// Same host + same vuln class = likely duplicate even on different path
		if sameVulnClass(r.VulnType, vulnType) && strings.EqualFold(r.Host, host) {
			return true, fmt.Sprintf("similar vuln on same host reported %s (report: %s)",
				r.Submitted.Format("2006-01-02"), r.ReportID)
		}
	}
	return false, ""
}

// MarkReported adds a finding to the duplicate database
func MarkReported(program, vulnType, targetURL, param, reportID string) error {
	db := loadDupeDB()

	parsed, _ := url.Parse(targetURL)
	host := ""
	path := ""
	if parsed != nil {
		host = parsed.Hostname()
		path = parsed.Path
	}

	db.Reports = append(db.Reports, SubmittedReport{
		Program:   program,
		VulnType:  vulnType,
		Host:      host,
		Path:      path,
		Param:     param,
		Submitted: time.Now(),
		ReportID:  reportID,
		Status:    "new",
	})
	return saveDupeDB(db)
}

// UpdateStatus updates a report's status (e.g., when H1 marks it as duplicate)
func UpdateStatus(reportID, status string) {
	db := loadDupeDB()
	for i := range db.Reports {
		if db.Reports[i].ReportID == reportID {
			db.Reports[i].Status = status
			break
		}
	}
	saveDupeDB(db)
}

// sameVulnClass groups similar vuln types to catch broader duplicates
func sameVulnClass(a, b string) bool {
	return vulnClass(a) != "" && vulnClass(a) == vulnClass(b)
}

func vulnClass(vt string) string {
	vt = strings.ToLower(vt)
	switch {
	case strings.Contains(vt, "sql"):
		return "sqli"
	case strings.Contains(vt, "xss") || strings.Contains(vt, "cross-site scripting"):
		return "xss"
	case strings.Contains(vt, "ssrf"):
		return "ssrf"
	case strings.Contains(vt, "command") || strings.Contains(vt, "cmdi"):
		return "cmdi"
	case strings.Contains(vt, "ssti"):
		return "ssti"
	case strings.Contains(vt, "lfi") || strings.Contains(vt, "path traversal") || strings.Contains(vt, "file inclusion"):
		return "lfi"
	case strings.Contains(vt, "idor"):
		return "idor"
	case strings.Contains(vt, "redirect"):
		return "redirect"
	}
	return ""
}

func dupeDBPath() string {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/tmp"
	}
	return filepath.Join(home, ".apex-cache", "reported.json")
}

func loadDupeDB() *DupeDB {
	data, err := os.ReadFile(dupeDBPath())
	if err != nil {
		return &DupeDB{}
	}
	var db DupeDB
	json.Unmarshal(data, &db)
	return &db
}

func saveDupeDB(db *DupeDB) error {
	dir := filepath.Dir(dupeDBPath())
	os.MkdirAll(dir, 0755)
	data, _ := json.MarshalIndent(db, "", "  ")
	return os.WriteFile(dupeDBPath(), data, 0644)
}
