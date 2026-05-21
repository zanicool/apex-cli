package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/zanicool/apex-cli/pkg/crawler"
	"github.com/zanicool/apex-cli/pkg/engine"
	"github.com/zanicool/apex-cli/pkg/oob"
	"github.com/zanicool/apex-cli/pkg/recon"
	"github.com/zanicool/apex-cli/pkg/reporter"
	"github.com/zanicool/apex-cli/pkg/scanner"
)

var (
	version = "10.0-go"
	banner  = `
 █████╗ ██████╗ ███████╗██╗  ██╗     ██████╗██╗     ██╗
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║     ██║
███████║██████╔╝█████╗   ╚███╔╝     ██║     ██║     ██║
██╔══██║██╔═══╝ ██╔══╝   ██╔██╗     ██║     ██║     ██║
██║  ██║██║     ███████╗██╔╝ ██╗    ╚██████╗███████╗██║
╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝     ╚═════╝╚══════╝╚═╝
                    v%s — Go Edition (10-50x faster)
`
)

func main() {
	// Flags
	deep := flag.Bool("deep", false, "Deep scan mode — more payloads, wider ports, all severities")
	rate := flag.Float64("rate", 0, "Delay between requests in seconds (0 = max speed)")
	threads := flag.Int("threads", 100, "Concurrent workers")
	timeout := flag.Int("timeout", 10, "HTTP timeout in seconds")
	proxy := flag.String("proxy", "", "HTTP proxy (e.g. http://127.0.0.1:8080)")
	output := flag.String("output", "", "Output directory (default: auto-generated)")
	report := flag.String("report", "json,terminal", "Report formats: json,html,terminal")
	scope := flag.String("scope", "", "Restrict targets to matching strings")
	skip := flag.String("skip", "", "Skip phases (comma-separated)")
	noOOB := flag.Bool("no-oob", false, "Disable OOB server")
	oobServer := flag.String("oob-server", "http://roz:1234@jarvis.local:9877", "Custom OOB server URL")
	dryRun := flag.Bool("dry-run", false, "Preview without sending packets")
	_ = flag.String("session", "", "Session file (JSON) for authenticated scanning")
	_ = flag.String("templates", "", "Custom templates directory")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Printf(banner, version)
		fmt.Println("Usage: apex-cli [flags] <target>")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	target := flag.Arg(0)
	fmt.Printf(banner, version)
	fmt.Printf("\n[*] Target: %s\n", target)
	start := time.Now()

	// Build config
	cfg := &engine.Config{
		Target:    target,
		Deep:      *deep,
		Rate:      *rate,
		Threads:   *threads,
		Timeout:   time.Duration(*timeout) * time.Second,
		Proxy:     *proxy,
		OutputDir: *output,
		Report:    *report,
		Scope:     *scope,
		Skip:      *skip,
		DryRun:    *dryRun,
		OOBServer: *oobServer,
		NoOOB:     *noOOB,
	}

	if cfg.OutputDir == "" {
		cfg.OutputDir = fmt.Sprintf("scan_%s_%s", engine.SafeName(target), time.Now().Format("20060102_150405"))
	}
	os.MkdirAll(cfg.OutputDir, 0755)

	// Initialize HTTP engine
	http := engine.NewHTTPClient(cfg)

	// Phase 1: Recon
	fmt.Println("\n[Phase 1] Recon — Subdomain enumeration + passive intel")
	reconResult := recon.Run(cfg, http)
	fmt.Printf("  → %d subdomains, %d live targets\n", len(reconResult.Subdomains), len(reconResult.LiveTargets))

	// Pre-filter: skip Cloudflare challenge and SPA catch-all targets
	var filteredTargets []string
	for _, t := range reconResult.LiveTargets {
		if scanner.IsCloudflareChallenge(http, t) {
			fmt.Printf("  ⚠ Cloudflare challenge: %s — skipped\n", t)
		} else if scanner.IsSPACatchAll(http, t) {
			fmt.Printf("  ⚠ SPA catch-all: %s — skipped\n", t)
		} else {
			filteredTargets = append(filteredTargets, t)
		}
	}
	reconResult.LiveTargets = filteredTargets
	if len(filteredTargets) == 0 {
		fmt.Println("\n[!] All targets filtered (Cloudflare/SPA) — nothing to scan.")
		os.Exit(0)
	}

	// Phase 2: Crawl
	fmt.Println("\n[Phase 2] Crawl — Recursive + JS-aware URL extraction")
	crawlResult := crawler.Run(cfg, http, reconResult.LiveTargets)
	fmt.Printf("  → %d pages, %d forms, %d params\n", len(crawlResult.Pages), len(crawlResult.Forms), len(crawlResult.Params))

	// Phase 3: OOB setup
	var oobClient *oob.Client
	if !*noOOB {
		fmt.Println("\n[Phase 3] OOB — Starting callback server")
		oobClient = oob.NewClient(*oobServer)
		if oobClient.Active() {
			fmt.Printf("  → OOB active: %s\n", oobClient.Domain())
		}
	}

	// Phase 4: Scan
	fmt.Println("\n[Phase 4] Scan — 302 injection/logic/auth scanners")

	// Detect WAFs first
	wafs := scanner.DetectWAF(http, reconResult.LiveTargets)
	if len(wafs) > 0 {
		fmt.Printf("  ⚠ WAF detected: %v — adapting payloads\n", wafs)
	}

	// Filter wildcard targets
	var realTargets []string
	for _, t := range reconResult.LiveTargets {
		if !scanner.IsWildcard(http, t) {
			realTargets = append(realTargets, t)
		} else {
			fmt.Printf("  ⚠ Wildcard: %s — skipped\n", t)
		}
	}

	findings := scanner.Run(cfg, http, crawlResult, oobClient)
	fmt.Printf("  → %d findings\n", len(findings))

	// Write raw findings immediately (in case report phase is slow)
	rawPath := cfg.OutputDir + "/findings_raw.json"
	if rawData, err := json.MarshalIndent(findings, "", "  "); err == nil {
		os.WriteFile(rawPath, rawData, 0644)
	}

	// Phase 5: Report
	fmt.Println("\n[Phase 5] Report")
	reporter.Generate(cfg, findings, reconResult, crawlResult, time.Since(start))

	elapsed := time.Since(start)
	fmt.Printf("\n[✓] Scan complete in %s — %d findings\n", elapsed.Round(time.Second), len(findings))
}
