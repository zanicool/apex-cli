package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	version = "1.0.0"
	server  = "https://api.example.com:9000"
)

var client = &http.Client{
	Timeout: 15 * time.Minute,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

type Config struct {
	APIKey string `json:"api_key"`
}

type ScanResp struct {
	ScanID       string        `json:"scan_id"`
	Status       string        `json:"status"`
	Target       string        `json:"target"`
	FindingCount int           `json:"finding_count"`
	Duration     *float64      `json:"duration"`
	Findings     []interface{} `json:"findings"`
	Error        string        `json:"error"`
}

type UsageResp struct {
	ScansToday      int `json:"scans_today"`
	DailyLimit      int `json:"daily_limit"`
	ConcurrentRun   int `json:"concurrent_running"`
	ConcurrentLimit int `json:"concurrent_limit"`
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".apex", "config.json")
}

func loadConfig() Config {
	data, err := os.ReadFile(configPath())
	if err != nil {
		fmt.Println("\033[31m[✗]\033[0m Not logged in. Run: apex login <api_key>")
		os.Exit(1)
	}
	var cfg Config
	json.Unmarshal(data, &cfg)
	return cfg
}

func saveConfig(cfg Config) {
	dir := filepath.Dir(configPath())
	os.MkdirAll(dir, 0700)
	data, _ := json.Marshal(cfg)
	os.WriteFile(configPath(), data, 0600)
}

func api(method, path string, body interface{}) ([]byte, error) {
	cfg := loadConfig()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, server+path, r)
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "apex-cli/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Connection failed: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		var errResp map[string]string
		json.Unmarshal(data, &errResp)
		if msg, ok := errResp["error"]; ok {
			return nil, fmt.Errorf(msg)
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

func cmdLogin(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: apex login <api_key>")
		os.Exit(1)
	}
	saveConfig(Config{APIKey: args[0]})
	// Verify key
	_, err := api("GET", "/health", nil)
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m Connection failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\033[32m[✓]\033[0m Logged in successfully")
}

func cmdScan(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: apex scan <target> [--deep] [--threads N]")
		os.Exit(1)
	}
	target := args[0]
	options := args[1:]

	body := map[string]interface{}{"target": target, "options": options}
	resp, err := api("POST", "/scan", body)
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m %v\n", err)
		os.Exit(1)
	}
	var sr ScanResp
	json.Unmarshal(resp, &sr)

	fmt.Printf("\033[36m[*]\033[0m Scanning %s (id: %s)\n", target, sr.ScanID)
	fmt.Print("\033[36m[*]\033[0m Waiting for results")

	for {
		time.Sleep(3 * time.Second)
		fmt.Print(".")
		resp, err = api("GET", "/scan/"+sr.ScanID, nil)
		if err != nil {
			fmt.Printf("\n\033[31m[✗]\033[0m %v\n", err)
			os.Exit(1)
		}
		json.Unmarshal(resp, &sr)
		if sr.Status != "running" {
			break
		}
	}
	fmt.Println()

	if sr.Error != "" {
		fmt.Printf("\033[31m[✗]\033[0m %s\n", sr.Error)
		os.Exit(1)
	}

	dur := ""
	if sr.Duration != nil {
		dur = fmt.Sprintf(" in %.1fs", *sr.Duration)
	}
	fmt.Printf("\033[32m[✓]\033[0m Done — %d findings%s\n\n", sr.FindingCount, dur)

	if sr.FindingCount == 0 {
		fmt.Println("  No vulnerabilities found.")
		return
	}

	for _, f := range sr.Findings {
		b, _ := json.MarshalIndent(f, "  ", "  ")
		fmt.Println("  " + string(b))
	}
}

func cmdStatus(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: apex status <scan_id>")
		os.Exit(1)
	}
	resp, err := api("GET", "/scan/"+args[0], nil)
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m %v\n", err)
		os.Exit(1)
	}
	var sr ScanResp
	json.Unmarshal(resp, &sr)
	fmt.Printf("  ID: %s\n  Target: %s\n  Status: %s\n  Findings: %d\n", sr.ScanID, sr.Target, sr.Status, sr.FindingCount)
}

func cmdList() {
	resp, err := api("GET", "/scans", nil)
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m %v\n", err)
		os.Exit(1)
	}
	var scans []ScanResp
	json.Unmarshal(resp, &scans)
	if len(scans) == 0 {
		fmt.Println("  No scans yet. Run: apex scan <target>")
		return
	}
	fmt.Printf("  %-10s %-10s %-8s %s\n", "ID", "STATUS", "FINDS", "TARGET")
	fmt.Printf("  %-10s %-10s %-8s %s\n", "──────────", "──────────", "────────", "──────")
	for _, s := range scans {
		fmt.Printf("  %-10s %-10s %-8d %s\n", s.ScanID, s.Status, s.FindingCount, s.Target)
	}
}

func cmdUsage() {
	resp, err := api("GET", "/usage", nil)
	if err != nil {
		fmt.Printf("\033[31m[✗]\033[0m %v\n", err)
		os.Exit(1)
	}
	var u UsageResp
	json.Unmarshal(resp, &u)
	fmt.Printf("  Scans today:    %d / %d\n", u.ScansToday, u.DailyLimit)
	fmt.Printf("  Running now:    %d / %d\n", u.ConcurrentRun, u.ConcurrentLimit)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf(`
  \033[1mapex\033[0m v%s — Automated Vulnerability Scanner
  
  \033[1mUsage:\033[0m
    apex login <api_key>         Authenticate
    apex scan <target> [opts]    Start a scan
    apex status <scan_id>        Check scan result
    apex list                    List all scans
    apex usage                   Show usage limits

  \033[1mScan options:\033[0m
    --deep          Deep scan (slower, more thorough)
    --threads N     Concurrency (default: 30)

  \033[1mExamples:\033[0m
    apex scan example.com
    apex scan example.com --deep --threads 50

`, version)
		os.Exit(0)
	}

	cmd := strings.ToLower(os.Args[1])
	args := os.Args[2:]

	switch cmd {
	case "login":
		cmdLogin(args)
	case "scan":
		cmdScan(args)
	case "status":
		cmdStatus(args)
	case "list":
		cmdList()
	case "usage":
		cmdUsage()
	case "version":
		fmt.Printf("apex v%s\n", version)
	default:
		fmt.Printf("\033[31m[✗]\033[0m Unknown command: %s\n", cmd)
		os.Exit(1)
	}
}
