package ffuf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Result struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Size   int    `json:"length"`
	Words  int    `json:"words"`
	Lines  int    `json:"lines"`
}

type TargetResult struct {
	Target   string
	Results  []Result
	Wildcard bool
	Error    error
	Duration time.Duration
}

type Config struct {
	Threads       int
	Timeout       int
	Proxy         string
	Deep          bool
	WAFs          []string
	OutputDir     string
	MaxParallel   int // concurrent ffuf processes
	RatePerTarget int // requests/sec per target (0 = unlimited)
}

// Run executes ffuf against multiple targets in parallel with auto-calibration
func Run(cfg *Config, targets []string) []TargetResult {
	if len(targets) == 0 {
		return nil
	}

	parallel := cfg.MaxParallel
	if parallel <= 0 {
		parallel = 4
	}

	// Reduce parallelism if WAF detected
	if len(cfg.WAFs) > 0 && parallel > 2 {
		parallel = 2
	}

	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []TargetResult

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := fuzzTarget(cfg, t)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(target)
	}
	wg.Wait()
	return results
}

func fuzzTarget(cfg *Config, target string) TargetResult {
	start := time.Now()
	wordlist := selectWordlist(cfg.Deep)

	// Build ffuf command with auto-calibration
	args := []string{
		"-u", target + "/FUZZ",
		"-w", wordlist,
		"-ac",              // auto-calibrate: eliminates wildcard/catch-all noise
		"-s",               // silent mode
		"-o", "/dev/stdout",
		"-of", "json",
		"-t", fmt.Sprintf("%d", effectiveThreads(cfg)),
		"-timeout", fmt.Sprintf("%d", max(cfg.Timeout, 10)),
		"-mc", "200,201,202,204,301,302,307,308,401,403,405",
		"-recursion", "-recursion-depth", "1",
	}

	// WAF evasion
	if len(cfg.WAFs) > 0 {
		rate := cfg.RatePerTarget
		if rate <= 0 {
			rate = wafRate(cfg.WAFs)
		}
		args = append(args, "-rate", fmt.Sprintf("%d", rate))
		// Header rotation for WAF bypass
		args = append(args, "-H", randomWAFBypassHeader())
	} else if cfg.RatePerTarget > 0 {
		args = append(args, "-rate", fmt.Sprintf("%d", cfg.RatePerTarget))
	}

	if cfg.Proxy != "" {
		args = append(args, "-x", cfg.Proxy)
	}

	// Additional filters: ignore responses that are all the same size (wildcard backup)
	args = append(args, "-fl", "0") // filter 0-line responses

	cmd := exec.Command("ffuf", args...)
	out, err := cmd.Output()
	duration := time.Since(start)

	if err != nil {
		// Check if it's just "no results" (exit code 1 with -ac)
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return TargetResult{Target: target, Duration: duration}
		}
		return TargetResult{Target: target, Error: err, Duration: duration}
	}

	// Parse JSON output
	var ffufOutput struct {
		Results []Result `json:"results"`
	}
	if err := json.Unmarshal(out, &ffufOutput); err != nil {
		// Try line-by-line JSON
		results := parseLineJSON(out)
		return classifyResults(target, results, duration)
	}

	return classifyResults(target, ffufOutput.Results, duration)
}

func classifyResults(target string, results []Result, duration time.Duration) TargetResult {
	// Post-filter: if >90% of results have same size, it's a wildcard that -ac missed
	if len(results) > 50 {
		sizeCount := make(map[int]int)
		for _, r := range results {
			sizeCount[r.Size]++
		}
		for _, count := range sizeCount {
			if float64(count)/float64(len(results)) > 0.9 {
				return TargetResult{Target: target, Wildcard: true, Duration: duration}
			}
		}
	}
	return TargetResult{Target: target, Results: results, Duration: duration}
}

func parseLineJSON(data []byte) []Result {
	var results []Result
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		var r Result
		if json.Unmarshal(scanner.Bytes(), &r) == nil && r.URL != "" {
			results = append(results, r)
		}
	}
	return results
}

func selectWordlist(deep bool) string {
	if deep {
		// Prefer larger wordlist for deep mode
		candidates := []string{
			"/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
			"/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	// Default: common.txt or bundled
	candidates := []string{
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		filepath.Join(os.Getenv("HOME"), "git/apex-cli/wordlist.txt"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "wordlist.txt"
}

func effectiveThreads(cfg *Config) int {
	t := cfg.Threads
	if t <= 0 {
		t = 100
	}
	// Reduce threads when WAF detected
	if len(cfg.WAFs) > 0 && t > 40 {
		t = 40
	}
	return t
}

func wafRate(wafs []string) int {
	// Conservative rates per WAF type
	for _, w := range wafs {
		switch strings.ToLower(w) {
		case "cloudflare":
			return 20
		case "aws waf":
			return 30
		case "akamai":
			return 15
		case "imperva":
			return 10
		case "f5 big-ip":
			return 25
		}
	}
	return 30 // default WAF rate
}

func randomWAFBypassHeader() string {
	headers := []string{
		"X-Forwarded-For: 127.0.0.1",
		"X-Original-URL: /",
		"X-Rewrite-URL: /",
		"X-Custom-IP-Authorization: 127.0.0.1",
		"X-Forwarded-Host: localhost",
	}
	return headers[time.Now().UnixNano()%int64(len(headers))]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
