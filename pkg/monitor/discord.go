package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DiscordAlert sends a finding to a Discord webhook
func DiscordAlert(webhookURL string, vulnType, severity, targetURL, detail string) error {
	color := severityColor(severity)
	embed := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("%s %s", severityEmoji(severity), vulnType),
				"description": detail,
				"color":       color,
				"fields": []map[string]string{
					{"name": "URL", "value": truncate(targetURL, 200), "inline": "false"},
					{"name": "Severity", "value": strings.ToUpper(severity), "inline": "true"},
					{"name": "Time", "value": time.Now().Format("15:04:05"), "inline": "true"},
				},
				"footer": map[string]string{
					"text": "Apex CLI v10.0 — BFG 9000",
				},
			},
		},
	}

	body, _ := json.Marshal(embed)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// AlertBatch sends a summary of all findings from a scan
func AlertBatch(webhookURL, target string, criticals, highs, mediums, lows int, topFindings []string) error {
	desc := fmt.Sprintf("**Target:** `%s`\n**Results:** 🔴 %d critical, 🟠 %d high, 🟡 %d medium, 🔵 %d low",
		target, criticals, highs, mediums, lows)

	if len(topFindings) > 0 {
		desc += "\n\n**Top Findings:**\n"
		for _, f := range topFindings[:min(5, len(topFindings))] {
			desc += "• " + f + "\n"
		}
	}

	embed := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("🎯 Scan Complete: %s", target),
				"description": desc,
				"color":       0x00ff00,
				"timestamp":   time.Now().Format(time.RFC3339),
			},
		},
	}

	body, _ := json.Marshal(embed)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func severityColor(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 0xff0000
	case "high":
		return 0xff8c00
	case "medium":
		return 0xffff00
	case "low":
		return 0x0000ff
	default:
		return 0x808080
	}
}

func severityEmoji(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	default:
		return "🔵"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
