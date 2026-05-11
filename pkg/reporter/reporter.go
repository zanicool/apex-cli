package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/recon"
	"github.com/zanicool/apex-cli/pkg/scanner"
)

type Report struct {
	Target     string            `json:"target"`
	StartTime  string            `json:"start_time"`
	Duration   string            `json:"duration"`
	Subdomains int               `json:"subdomains"`
	LiveHosts  int               `json:"live_hosts"`
	Pages      int               `json:"pages_crawled"`
	Forms      int               `json:"forms_found"`
	Params     int               `json:"params_found"`
	Findings   []scanner.Finding `json:"findings"`
	Summary    Summary           `json:"summary"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

func Generate(cfg *engine.Config, findings []scanner.Finding, reconResult *recon.Result, crawlResult *crawler.Result, elapsed time.Duration) {
	formats := strings.Split(cfg.Report, ",")

	summary := Summary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Info++
		}
	}

	report := Report{
		Target:     cfg.Target,
		StartTime:  time.Now().Add(-elapsed).Format(time.RFC3339),
		Duration:   engine.FormatDuration(elapsed),
		Subdomains: len(reconResult.Subdomains),
		LiveHosts:  len(reconResult.LiveTargets),
		Pages:      len(crawlResult.Pages),
		Forms:      len(crawlResult.Forms),
		Params:     len(crawlResult.Params),
		Findings:   findings,
		Summary:    summary,
	}

	for _, format := range formats {
		switch strings.TrimSpace(format) {
		case "json":
			writeJSON(cfg.OutputDir, report)
		case "terminal":
			writeTerminal(report)
		case "html":
			writeHTML(cfg.OutputDir, report)
		}
	}
}

func writeJSON(dir string, report Report) {
	path := filepath.Join(dir, "report.json")
	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(path, data, 0644)
	fmt.Printf("  → JSON: %s\n", path)
}

func writeTerminal(report Report) {
	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Printf("║  APEX CLI SCAN RESULTS — %s\n", report.Target)
	fmt.Printf("║  Duration: %s | Findings: %d\n", report.Duration, report.Summary.Total)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  🔴 Critical: %d  🟠 High: %d  🟡 Medium: %d  🔵 Low: %d\n",
		report.Summary.Critical, report.Summary.High, report.Summary.Medium, report.Summary.Low)
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	if len(report.Findings) > 0 {
		fmt.Println("\nFindings:")
		for i, f := range report.Findings {
			icon := "🔵"
			switch f.Severity {
			case "critical":
				icon = "🔴"
			case "high":
				icon = "🟠"
			case "medium":
				icon = "🟡"
			}
			fmt.Printf("  %s [%d] %s\n", icon, i+1, f.Type)
			fmt.Printf("       URL: %s\n", f.URL)
			if f.Param != "" {
				fmt.Printf("       Param: %s | Payload: %s\n", f.Param, truncate(f.Payload, 60))
			}
			if f.Detail != "" {
				fmt.Printf("       Detail: %s\n", truncate(f.Detail, 100))
			}
			fmt.Println()
		}
	}
}

func writeHTML(dir string, report Report) {
	path := filepath.Join(dir, "report.html")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><title>Apex CLI Report — %s</title>
<style>
body{background:#0d1117;color:#c9d1d9;font-family:monospace;padding:2em}
h1{color:#ff4444} .critical{color:#ff4444} .high{color:#ff8c00} .medium{color:#ffcc00}
.finding{border:1px solid #30363d;padding:1em;margin:1em 0;border-radius:8px}
</style></head><body>
<h1>⚡ Apex CLI Scan Report</h1>
<p>Target: %s | Duration: %s | Findings: %d</p>
<p><span class="critical">Critical: %d</span> | <span class="high">High: %d</span> | <span class="medium">Medium: %d</span></p>
`, report.Target, report.Target, report.Duration, report.Summary.Total,
		report.Summary.Critical, report.Summary.High, report.Summary.Medium)

	for _, f := range report.Findings {
		html += fmt.Sprintf(`<div class="finding"><b class="%s">[%s]</b> %s<br>URL: %s<br>`,
			f.Severity, strings.ToUpper(f.Severity), f.Type, f.URL)
		if f.Payload != "" {
			html += fmt.Sprintf("Payload: <code>%s</code><br>", f.Payload)
		}
		if f.Detail != "" {
			html += fmt.Sprintf("Detail: %s<br>", f.Detail)
		}
		html += "</div>\n"
	}
	html += "</body></html>"
	os.WriteFile(path, []byte(html), 0644)
	fmt.Printf("  → HTML: %s\n", path)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
