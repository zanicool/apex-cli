/// @file main.cpp
/// @brief Apex CLI entry point — CLI parsing and scan orchestration.
#include "brain.hpp"
#include "chain.hpp"
#include "cms_export.hpp"
#include "confidence.hpp"
#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "impact.hpp"
#include "maturity.hpp"
#include "novelty.hpp"
#include "owasp_intel.hpp"
#include "pipeline.hpp"
#include "profile_generator.hpp"
#include "recon.hpp"
#include "recon_logger.hpp"
#include "reporter.hpp"
#include "sbom.hpp"
#include "scanner.hpp"
#include "smart_mode.hpp"
#include "toolchain.hpp"
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <thread>

namespace {

const char *kVersion = "11.0-cpp";

const char *kBanner = R"(
 █████╗ ██████╗ ███████╗██╗  ██╗     ██████╗██╗     ██╗
██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║     ██║
███████║██████╔╝█████╗   ╚███╔╝     ██║     ██║     ██║
██╔══██║██╔═══╝ ██╔══╝   ██╔██╗     ██║     ██║     ██║
██║  ██║██║     ███████╗██╔╝ ██╗    ╚██████╗███████╗██║
╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝     ╚═════╝╚══════╝╚═╝
)";

/// Print usage information.
void print_usage() {
  std::cout << kBanner;
  std::cout << "                    v" << kVersion
            << " — C++ Edition (high performance)\n\n";
  std::cout << "Usage: apex-cli [flags] <target>\n\n";
  std::cout << "Flags:\n";
  std::cout << "  --deep         Deep scan mode\n";
  std::cout << "  --threads N    Concurrent workers (default: 100)\n";
  std::cout << "  --rate N       Delay between requests in seconds\n";
  std::cout << "  --timeout N    HTTP timeout in seconds (default: 10)\n";
  std::cout << "  --proxy URL    HTTP proxy\n";
  std::cout << "  --output DIR   Output directory\n";
  std::cout << "  --report FMT   Report formats: json,terminal (default)\n";
  std::cout << "  --scope STR    Restrict to matching targets\n";
  std::cout << "  --skip LIST    Skip scanners (comma-separated)\n";
  std::cout << "  --no-oob       Disable OOB confirmation\n";
  std::cout << "  --crawl-depth N  Crawl depth (default: 3)\n";
  std::cout << "  --max-urls N   Max URLs to crawl (default: 500)\n";
  std::cout << "  --ssh TARGET   SSH target (user@host) for kernel/OS audit\n";
  std::cout << "  --ssh-key PATH SSH private key path\n";
  std::cout << "  --cookie STR   Cookie header for authenticated scanning\n";
  std::cout << "  --auth USER:PASS  HTTP Basic authentication\n";
  std::cout << "  --auth-header STR Authorization header (e.g. 'Bearer tok')\n";
  std::cout << "  --dry-run      Preview without sending packets\n";
  std::cout << "  --smart        Smart mode: auto-select scanners from crawl\n";
  std::cout << "  --watch        Watch mode: continuous monitoring\n";
  std::cout
      << "  --watch-interval N  Seconds between watch scans (default: 3600)\n";
  std::cout << "  --baseline PATH  Compare against previous scan report\n";
  std::cout << "  --confidence N   Min confidence (1=possible 2=probable "
               "3=confirmed)\n";
  std::cout
      << "  --bounty       Bug bounty mode: novelty scoring + dupe risk\n";
  std::cout << "  --pipeline     Full pipeline: recon → scan → chain → verify "
               "→ report\n";
  std::cout << "  --chain        Escalate findings into full exploit chains\n";
  std::cout << "  --program NAME HackerOne program handle (enables hacktivity "
               "check)\n";
  std::cout << "  --help         Show this help\n";
}

/// Generate a timestamped output directory name.
std::string make_output_dir(const std::string &target) {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  std::ostringstream ss;
  ss << "scans/scan_" << apex::safe_name(target) << "_"
     << std::put_time(std::localtime(&t), "%Y%m%d_%H%M%S");
  return ss.str();
}

/// Split a comma-separated string.
std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> parts;
  std::istringstream stream(s);
  std::string item;
  while (std::getline(stream, item, delim)) {
    if (!item.empty()) {
      parts.push_back(item);
    }
  }
  return parts;
}

} // namespace

int main(int argc, char *argv[]) {
  std::ios_base::sync_with_stdio(false);
  std::cout << std::unitbuf; // Flush after every output.

  apex::Config cfg;

  // Parse arguments.
  std::string target;
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      print_usage();
      return 0;
    } else if (arg == "--deep") {
      cfg.deep = true;
    } else if (arg == "--dry-run") {
      cfg.dry_run = true;
    } else if (arg == "--no-oob") {
      cfg.no_oob = true;
    } else if (arg == "--quick") {
      cfg.quick = true;
    } else if (arg == "--smart") {
      cfg.smart = true;
    } else if (arg == "--watch") {
      cfg.watch = true;
    } else if (arg == "--watch-interval" && i + 1 < argc) {
      cfg.watch_interval = std::stoi(argv[++i]);
    } else if (arg == "--baseline" && i + 1 < argc) {
      cfg.watch_baseline = argv[++i];
    } else if (arg == "--confidence" && i + 1 < argc) {
      cfg.confidence_min = std::stoi(argv[++i]);
    } else if (arg == "--bounty") {
      cfg.bounty = true;
      if (cfg.confidence_min == 0)
        cfg.confidence_min = 2; // auto-filter noise
      if (!cfg.smart)
        cfg.smart = true; // auto-enable smart mode
    } else if (arg == "--pipeline") {
      cfg.pipeline = true;
      cfg.bounty = true;
      cfg.smart = true;
      cfg.chain = true;
      if (cfg.confidence_min == 0)
        cfg.confidence_min = 2;
    } else if (arg == "--chain") {
      cfg.chain = true;
    } else if (arg == "--program" && i + 1 < argc) {
      cfg.h1_program = argv[++i];
      cfg.bounty = true;
      if (cfg.confidence_min == 0)
        cfg.confidence_min = 2;
      if (!cfg.smart)
        cfg.smart = true;
    } else if (arg == "--wf-key" && i + 1 < argc) {
      cfg.wf_api_key = argv[++i];
    } else if (arg == "--threads" && i + 1 < argc) {
      cfg.threads = std::stoi(argv[++i]);
    } else if (arg == "--rate" && i + 1 < argc) {
      cfg.rate = std::stod(argv[++i]);
    } else if (arg == "--timeout" && i + 1 < argc) {
      cfg.timeout = std::stoi(argv[++i]);
    } else if (arg == "--proxy" && i + 1 < argc) {
      cfg.proxy = argv[++i];
    } else if (arg == "--output" && i + 1 < argc) {
      cfg.output_dir = argv[++i];
    } else if (arg == "--report" && i + 1 < argc) {
      cfg.report = argv[++i];
    } else if (arg == "--scope" && i + 1 < argc) {
      cfg.scope = argv[++i];
    } else if (arg == "--skip" && i + 1 < argc) {
      cfg.skip = split(argv[++i], ',');
    } else if (arg == "--crawl-depth" && i + 1 < argc) {
      cfg.crawl_depth = std::stoi(argv[++i]);
    } else if (arg == "--max-urls" && i + 1 < argc) {
      cfg.max_urls = std::stoi(argv[++i]);
    } else if (arg == "--ssh" && i + 1 < argc) {
      cfg.ssh_target = argv[++i];
    } else if (arg == "--ssh-key" && i + 1 < argc) {
      cfg.ssh_key = argv[++i];
    } else if (arg == "--cookie" && i + 1 < argc) {
      cfg.auth_cookie = argv[++i];
    } else if (arg == "--auth-header" && i + 1 < argc) {
      cfg.auth_header = argv[++i];
    } else if (arg == "--auth" && i + 1 < argc) {
      cfg.auth_basic = argv[++i];
    } else if (arg[0] != '-') {
      target = arg;
    }
  }

  if (target.empty()) {
    print_usage();
    return 1;
  }

  cfg.target = target;
  if (cfg.wf_api_key.empty()) {
    const char *env = std::getenv("WORDFENCE_API_KEY");
    if (env)
      cfg.wf_api_key = env;
  }
  if (cfg.output_dir.empty()) {
    cfg.output_dir = make_output_dir(target);
  }
  std::filesystem::create_directories(cfg.output_dir);

  // Banner.
  if (cfg.pipeline) {
    apex::print_pipeline_banner(target);
  } else {
    std::cout << kBanner;
    std::cout << "                    v" << kVersion
              << " — C++ Edition (high performance)\n";
  }
  std::cout << "\n[*] Target: " << target << "\n";
  if (cfg.dry_run) {
    std::cout << "[*] Mode: DRY RUN\n";
  }

  // Detect external tools.
  auto tools = apex::detect_tools();
  bool has_httpx = false, has_katana = false, has_sqlmap = false;
  bool has_dalfox = false, has_nuclei = false, has_ffuf = false;
  for (const auto &t : tools) {
    if (t.name == "httpx" && t.available)
      has_httpx = true;
    if (t.name == "katana" && t.available)
      has_katana = true;
    if (t.name == "sqlmap" && t.available)
      has_sqlmap = true;
    if (t.name == "dalfox" && t.available)
      has_dalfox = true;
    if (t.name == "nuclei" && t.available)
      has_nuclei = true;
    if (t.name == "ffuf" && t.available)
      has_ffuf = true;
  }
  apex::print_tool_status(tools);

  auto start = std::chrono::steady_clock::now();

  // Initialize HTTP client and JSONL logger
  apex::HttpClient http(cfg);
  apex::ReconLogger logger(cfg.output_dir);

  // Phase 1: Recon.
  std::cout << "\n[Phase 1] Recon — Subdomain enumeration + probing\n";
  auto recon = apex::run_recon(cfg, http);

  // Phase 2: Crawl.
  std::cout << "\n[Phase 2] Crawl — Spider + parameter discovery\n";
  auto seeds = recon.live_targets;
  if (seeds.empty()) {
    if (cfg.target.find("://") != std::string::npos)
      seeds.push_back(cfg.target);
    else
      seeds.push_back("https://" + cfg.target);
  }
  auto crawl = apex::run_crawler(cfg, http, seeds);
  std::cout << "  -> " << crawl.urls.size() << " URLs, " << crawl.params.size()
            << " params, " << crawl.forms.size() << " forms\n";

  // Phase 3: Scan.
  std::cout << "\n[Phase 3] Scan — ";
  if (cfg.smart) {
    auto intel = apex::analyze_crawl(crawl, http);
    auto selected = apex::smart_select_scanners(intel);
    std::cout << selected.size() << " smart-selected scanners\n";
    std::cout << "  -> Intel: params=" << intel.has_params
              << " forms=" << intel.has_forms << " login=" << intel.has_login
              << " api=" << intel.has_api << " graphql=" << intel.has_graphql
              << " ids=" << intel.has_ids << " cms=" << intel.has_cms << "\n";
    // Set skip list to everything NOT in selected
    auto all = apex::get_scanners();
    for (const auto &s : all) {
      if (selected.find(s.name) == selected.end())
        cfg.skip.push_back(s.name);
    }
  } else {
    std::cout << apex::get_scanners().size() << " scanners\n";
  }
  auto findings = apex::run_scanners(cfg, http, crawl);

  // Apply confidence filtering
  if (cfg.confidence_min > 0) {
    auto before = findings.size();
    findings = apex::filter_by_confidence(findings, cfg.confidence_min);
    std::cout << "  -> " << findings.size() << " findings (filtered from "
              << before << " by confidence >= " << cfg.confidence_min << ")\n";
  } else {
    std::cout << "  -> " << findings.size() << " findings\n";
  }

  // Confidence summary
  auto conf = apex::summarize_confidence(findings);
  std::cout << "  -> Confidence: " << conf.confirmed << " confirmed, "
            << conf.probable << " probable, " << conf.possible << " possible\n";

  // Bug bounty mode: novelty scoring
  if (cfg.bounty) {
    auto novelty_report = apex::assess_novelty(findings);
    std::cout << "\n[Bounty] Novelty assessment — duplicate risk analysis\n";
    std::cout << "  -> " << novelty_report.high_novelty
              << " high novelty (submit) | " << novelty_report.medium_novelty
              << " medium (verify) | " << novelty_report.low_novelty
              << " low (skip)\n";

    // Show top reportable findings
    std::cout << "\n  📋 REPORTABLE FINDINGS (sorted by novelty):\n\n";
    int shown = 0;
    for (const auto &[f, n] : novelty_report.scored) {
      if (static_cast<int>(n) < 2)
        continue; // skip low novelty
      std::cout << "  " << apex::novelty_icon(n) << " [" << f.severity << "] "
                << f.type << "\n";
      std::cout << "     URL: " << f.url << "\n";
      if (!f.param.empty())
        std::cout << "     Param: " << f.param << "\n";
      if (!f.evidence.empty())
        std::cout << "     Evidence: " << f.evidence.substr(0, 80) << "\n";
      std::cout << "     Novelty: " << apex::novelty_str(n) << "\n\n";
      if (++shown >= 15) {
        auto remaining =
            novelty_report.high_novelty + novelty_report.medium_novelty - shown;
        if (remaining > 0)
          std::cout << "     ... and " << remaining << " more\n\n";
        break;
      }
    }

    // Dupe warnings
    if (novelty_report.low_novelty > 0) {
      std::cout << "  ⚠ LIKELY DUPLICATES (don't report these):\n";
      int dupe_shown = 0;
      for (const auto &[f, n] : novelty_report.scored) {
        if (n != apex::Novelty::Low)
          continue;
        std::cout << "     🔴 " << f.type << " — " << f.url << "\n";
        if (++dupe_shown >= 5)
          break;
      }
      std::cout << "\n";
    }

    // Hacktivity check if program specified
    if (!cfg.h1_program.empty()) {
      std::cout << "  🔍 Checking hacktivity for " << cfg.h1_program << "...\n";
      std::set<std::string> checked_types;
      for (const auto &[f, n] : novelty_report.scored) {
        if (static_cast<int>(n) < 2)
          continue;
        if (!checked_types.insert(f.type).second)
          continue;
        auto matches = apex::check_hacktivity(http, cfg.h1_program, f.type);
        if (!matches.empty()) {
          std::cout << "     ⚠ " << f.type << ": " << matches.size()
                    << " similar disclosed reports found\n";
        }
      }
    }
  }

  // Log all findings to JSONL
  for (const auto &f : findings) {
    logger.log_finding(f);
  }

  // Phase 4: Report.
  auto end = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end - start);
  std::cout << "\n[Phase 4] Report\n";
  apex::generate_report(cfg, findings, elapsed);

  // Phase 4b: Verify — reproduce high/critical findings with baseline
  // comparison.
  int verify_count = 0;
  for (const auto &f : findings) {
    if (f.severity != "high" && f.severity != "critical")
      continue;
    if (f.payload.empty())
      continue;
    ++verify_count;
  }
  if (verify_count > 0 && !cfg.dry_run) {
    std::cout << "\n[Phase 4b] Verify — reproducing " << verify_count
              << " high/critical findings\n";
    std::string proof_path = cfg.output_dir + "/proof.jsonl";
    std::ofstream proof_out(proof_path);

    // Get baseline responses per URL (what does the page normally return?).
    std::map<std::string, std::string> baselines;
    for (auto &f : findings) {
      if (f.severity != "high" && f.severity != "critical")
        continue;
      if (f.payload.empty())
        continue;
      if (baselines.find(f.url) == baselines.end()) {
        auto bl = http.get(f.url);
        baselines[f.url] = bl.body.substr(0, 500);
      }
    }

    int confirmed_count = 0;
    for (auto &f : findings) {
      if (f.severity != "high" && f.severity != "critical")
        continue;
      if (f.payload.empty())
        continue;

      // Reproduce the request with payload.
      std::string test_url = f.url;
      if (!f.param.empty())
        test_url += (f.url.find('?') != std::string::npos ? "&" : "?") +
                    f.param + "=" + f.payload;
      else
        test_url += "?id=" + f.payload;
      auto resp = http.get(test_url);

      // Smart confirmation: evidence must NOT be in baseline.
      bool confirmed = false;
      std::string baseline = baselines[f.url];

      if (!f.evidence.empty() && !f.evidence.empty()) {
        bool in_response = resp.body.find(f.evidence) != std::string::npos;
        bool in_baseline = baseline.find(f.evidence) != std::string::npos;
        confirmed = in_response && !in_baseline;
      } else if (f.type.find("SSRF") != std::string::npos ||
                 f.type.find("Escalate") != std::string::npos ||
                 f.type.find("Metadata") != std::string::npos) {
        // SSRF/escalation: response must differ significantly from baseline.
        bool same_page = resp.body.substr(0, 500) == baseline;
        bool has_internal_data =
            resp.body.find("ami-id") != std::string::npos ||
            resp.body.find("AccessKey") != std::string::npos ||
            resp.body.find("redis_version") != std::string::npos ||
            resp.body.find("127.0.0.1") != std::string::npos;
        confirmed = !same_page && has_internal_data;
      }

      std::string status = confirmed ? "confirmed" : "unconfirmed";
      if (confirmed)
        ++confirmed_count;

      if (proof_out.is_open()) {
        proof_out << "{\"type\":\"" << f.type << "\",\"severity\":\""
                  << f.severity << "\",\"url\":\"" << f.url << "\",\"param\":\""
                  << f.param << "\",\"payload\":\"" << f.payload
                  << "\",\"status\":\"" << status
                  << "\",\"response_code\":" << resp.status_code
                  << ",\"response_size\":" << resp.body.size() << "}\n";
      }
      std::cout << "    [" << status << "] " << f.type << " — " << f.url
                << "\n";
      if (!confirmed)
        f.severity = "low"; // Downgrade unconfirmed.
    }
    std::cout << "  -> " << confirmed_count << "/" << verify_count
              << " confirmed\n";
    std::cout << "  -> Proof log: " << proof_path << "\n";
  }

  // Phase 4c: Deep verify with external tools (sqlmap, dalfox).
  if (!cfg.dry_run) {
    bool ran_deep = false;
    for (auto &f : findings) {
      if (f.severity != "high" && f.severity != "critical")
        continue;
      if (f.param.empty())
        continue;

      if (f.type.find("SQLi") != std::string::npos && has_sqlmap) {
        if (!ran_deep) {
          std::cout << "\n[Phase 4c] Deep verify — external tools\n";
          ran_deep = true;
        }
        std::cout << "    [sqlmap] " << f.url << " param=" << f.param << "\n";
        std::string result = apex::run_sqlmap(f);
        if (result.find("injectable") != std::string::npos) {
          f.evidence = "sqlmap confirmed: " + result.substr(0, 200);
          std::cout << "      → CONFIRMED by sqlmap\n";
        } else {
          std::cout << "      → not confirmed\n";
        }
      }
      if (f.type.find("XSS") != std::string::npos && has_dalfox) {
        if (!ran_deep) {
          std::cout << "\n[Phase 4c] Deep verify — external tools\n";
          ran_deep = true;
        }
        std::cout << "    [dalfox] " << f.url << " param=" << f.param << "\n";
        std::string result = apex::run_dalfox(f);
        if (result.find("POC") != std::string::npos ||
            result.find("Verified") != std::string::npos) {
          f.evidence = "dalfox confirmed: " + result.substr(0, 200);
          std::cout << "      → CONFIRMED by dalfox\n";
        } else {
          std::cout << "      → not confirmed\n";
        }
      }
    }
  }

  // Export CMS inventory if any CMS findings exist.
  bool has_cms = false;
  for (const auto &f : findings) {
    if (f.type == "CMS Detection") {
      has_cms = true;
      break;
    }
  }
  if (has_cms) {
    std::string csv_path = cfg.output_dir + "/cms_inventory.csv";
    apex::write_cms_inventory(findings, csv_path);
    std::cout << "  -> CMS inventory: " << csv_path << "\n";
  }

  // SBOM: generate and check for vulnerabilities.
  auto sbom_components = apex::extract_sbom(findings);
  if (!sbom_components.empty()) {
    std::string sbom_path = cfg.output_dir + "/sbom.cdx.json";
    apex::write_sbom(sbom_components, cfg.target, sbom_path);
    std::cout << "  -> SBOM (" << sbom_components.size()
              << " components): " << sbom_path << "\n";

    if (!cfg.dry_run) {
      std::cout << "  -> Checking OSV.dev for known vulnerabilities...\n";
      auto sbom_vulns = apex::check_osv(http, sbom_components);
      if (!sbom_vulns.empty()) {
        std::cout << "  -> " << sbom_vulns.size()
                  << " vulnerabilities found:\n";
        for (const auto &v : sbom_vulns) {
          std::cout << "    [" << v.severity << "] " << v.id << " — "
                    << v.component;
          if (!v.fixed_version.empty())
            std::cout << " (fix: " << v.fixed_version << ")";
          std::cout << "\n";
          // Add as finding.
          findings.push_back({"SBOM-CVE", v.severity, cfg.target,
                              v.id + ": " + v.summary, "", "", v.component});
        }
      } else {
        std::cout << "  -> No known vulnerabilities in OSV.dev\n";
      }
    }
  }

  // Phase 4d: Chain — escalate findings into full exploit chains.
  if (cfg.chain && !cfg.dry_run && !findings.empty()) {
    std::cout
        << "\n[Phase 4d] Chain — escalating findings into exploit chains\n";
    apex::ChainExecutor chain_exec(cfg, http);
    auto chains = chain_exec.execute(findings);

    int complete = 0;
    for (const auto &c : chains) {
      if (c.complete)
        ++complete;
      std::cout << "    [" << (c.complete ? "✓" : "…") << "] "
                << c.initial_finding.type << " → " << c.steps.size()
                << " steps";
      if (c.complete)
        std::cout << " → " << c.impact;
      std::cout << "\n";
    }
    std::cout << "  -> " << complete << "/" << chains.size()
              << " chains completed\n";

    // Write chain results to JSONL
    std::string chain_path = cfg.output_dir + "/chains.jsonl";
    std::ofstream chain_out(chain_path);
    if (chain_out.is_open()) {
      for (const auto &c : chains) {
        chain_out << "{\"type\":\"" << c.initial_finding.type << "\",\"url\":\""
                  << c.initial_finding.url << "\",\"depth\":" << c.depth
                  << ",\"complete\":" << (c.complete ? "true" : "false")
                  << ",\"impact\":\"" << c.impact
                  << "\",\"steps\":" << c.steps.size() << "}\n";
      }
      std::cout << "  -> Chain log: " << chain_path << "\n";
    }

    // Phase 4e: Brain — LLM-guided exploitation (requires ollama).
    if (system("command -v ollama >/dev/null 2>&1") == 0) {
      std::cout << "\n[Phase 4e] Brain — LLM-guided attack planning\n";
      apex::Brain brain(cfg, http);
      auto brain_result = brain.think_and_act(findings, cfg.target);
      std::cout << "  -> " << brain_result.actions_executed << " actions executed, "
                << brain_result.chains_completed << " new chains\n";
      for (auto &c : brain_result.chains)
        chains.push_back(std::move(c));
    }

    // Phase 4f: Impact — generate exploitation proof + H1 report.
    auto proofs = apex::prove_impact(chains);
    if (!proofs.empty()) {
      std::cout << "\n[Phase 4f] Impact — generating exploitation proof\n";
      std::cout << "  -> " << proofs.size() << " proven exploits\n";
      std::string h1 = apex::generate_h1_report(proofs, cfg.target, cfg.h1_program);
      std::string h1_path = cfg.output_dir + "/h1_report.md";
      std::ofstream h1_out(h1_path);
      if (h1_out.is_open()) {
        h1_out << h1;
        std::cout << "  -> HackerOne report: " << h1_path << "\n";
      }
      for (const auto &p : proofs)
        std::cout << "    [" << p.severity << "] " << p.chain_type
                  << " — " << p.owasp << "\n";
    }
  }

  // Phase 5: Nuclei CVE scan (if available and CMS detected).
  if (has_cms && !cfg.dry_run) {
    std::string nuclei_path = "nuclei";
    if (system("command -v nuclei >/dev/null 2>&1") == 0) {
      std::cout << "\n[Phase 5] Nuclei — CVE verification\n";
      // Detect CMS name from findings.
      std::string cms_name = "generic";
      for (const auto &f : findings) {
        if (f.type == "CMS Detection") {
          std::string d = f.detail;
          if (d.find("Joomla") != std::string::npos)
            cms_name = "joomla";
          else if (d.find("WordPress") != std::string::npos)
            cms_name = "wordpress";
          else if (d.find("Drupal") != std::string::npos)
            cms_name = "drupal";
          else if (d.find("Magento") != std::string::npos)
            cms_name = "magento";
          break;
        }
      }
      std::string nuclei_out = cfg.output_dir + "/nuclei_findings.jsonl";
      std::string cmd = "nuclei -u https://" + cfg.target + " -tags " +
                        cms_name + ",cve" + " -severity critical,high,medium" +
                        " -jsonl -output " + nuclei_out +
                        " -silent 2>/dev/null";
      int ret = system(cmd.c_str());
      if (ret == 0 && std::filesystem::exists(nuclei_out) &&
          std::filesystem::file_size(nuclei_out) > 0) {
        std::cout << "  -> Nuclei findings: " << nuclei_out << "\n";
      } else {
        std::cout << "  -> No additional CVEs found by Nuclei\n";
      }
    }
  }

  // Close logger
  logger.close();
  std::cout << "  -> JSONL logs: cms_recon.jsonl, osint_recon.jsonl, "
               "vuln_recon.jsonl\n";

  // Phase 6: ZAP — generate config from recon and launch active scan.
  if (!cfg.dry_run && system("command -v zap-cli >/dev/null 2>&1 || command -v "
                             "zap.sh >/dev/null 2>&1") == 0) {
    std::cout << "\n[Phase 6] ZAP — Active scan with targeted policy\n";

    // Generate ZAP automation YAML from our findings.
    std::string zap_config = cfg.output_dir + "/zap-automation.yaml";
    std::ofstream zap_out(zap_config);
    if (zap_out.is_open()) {
      // Determine scan policy based on detected tech.
      bool is_wordpress = false, has_forms = !crawl.forms.empty();
      bool has_api = false;
      for (const auto &f : findings) {
        if (f.detail.find("WordPress") != std::string::npos)
          is_wordpress = true;
        if (f.type == "API Schema Inference" || f.type == "GraphQL")
          has_api = true;
      }

      zap_out << "---\nenv:\n";
      zap_out << "  contexts:\n";
      zap_out << "    - name: \"apex-generated\"\n";
      zap_out << "      urls:\n";
      zap_out << "        - \"https://" << cfg.target << "\"\n";
      for (const auto &url : crawl.urls) {
        if (url.find(cfg.target) != std::string::npos)
          zap_out << "        - \"" << url << "\"\n";
      }
      zap_out << "      includePaths:\n";
      zap_out << "        - \"https://" << cfg.target << "/.*\"\n";
      zap_out << "      excludePaths:\n";
      zap_out << "        - \".*logout.*\"\n";
      zap_out << "        - \".*signout.*\"\n";

      // Authentication if login form detected.
      for (const auto &form : crawl.forms) {
        if (form.action.find("login") != std::string::npos ||
            form.action.find("inlog") != std::string::npos) {
          zap_out << "      authentication:\n";
          zap_out << "        method: \"form\"\n";
          zap_out << "        parameters:\n";
          zap_out << "          loginPageUrl: \"" << form.action << "\"\n";
          zap_out << "          loginRequestUrl: \"" << form.action << "\"\n";
          break;
        }
      }

      zap_out << "\njobs:\n";
      // Spider with discovered URLs as seeds.
      zap_out << "  - type: spider\n";
      zap_out << "    parameters:\n";
      zap_out << "      maxDuration: 5\n";
      zap_out << "      maxDepth: 5\n";
      zap_out << "      url: \"https://" << cfg.target << "\"\n";

      // AJAX spider for SPAs.
      zap_out << "  - type: spiderAjax\n";
      zap_out << "    parameters:\n";
      zap_out << "      maxDuration: 3\n";
      zap_out << "      url: \"https://" << cfg.target << "\"\n";

      // Active scan with targeted policy.
      zap_out << "  - type: activeScan\n";
      zap_out << "    parameters:\n";
      zap_out << "      maxRuleDurationInMins: 5\n";
      zap_out << "      maxScanDurationInMins: 15\n";
      zap_out << "    policyDefinition:\n";
      zap_out << "      defaultStrength: medium\n";
      zap_out << "      defaultThreshold: medium\n";
      zap_out << "      rules:\n";
      // Enable specific rules based on our findings.
      if (is_wordpress) {
        zap_out << "        - id: 90034  # WordPress\n";
        zap_out << "          strength: high\n";
      }
      if (has_forms) {
        zap_out << "        - id: 40012  # XSS Reflected\n";
        zap_out << "          strength: high\n";
        zap_out << "        - id: 40014  # XSS Persistent\n";
        zap_out << "          strength: high\n";
        zap_out << "        - id: 40018  # SQL Injection\n";
        zap_out << "          strength: high\n";
      }
      if (has_api) {
        zap_out << "        - id: 40035  # SSRF\n";
        zap_out << "          strength: high\n";
      }

      // Report output.
      zap_out << "  - type: report\n";
      zap_out << "    parameters:\n";
      zap_out << "      template: \"traditional-json\"\n";
      zap_out << "      reportDir: \"" << cfg.output_dir << "\"\n";
      zap_out << "      reportFile: \"zap-report\"\n";

      zap_out.close();
      std::cout << "  -> ZAP config: " << zap_config << "\n";

      // Check if we have a learned profile for the detected CMS/framework.
      std::string profile_config;
      for (const auto &f : findings) {
        if (f.type != "CMS Detection")
          continue;
        std::string fw = f.detail;
        size_t pos = fw.find("Detected: ");
        if (pos != std::string::npos)
          fw = fw.substr(pos + 10);
        pos = fw.find(" v");
        if (pos != std::string::npos)
          fw = fw.substr(0, pos);
        // Normalize to directory name.
        std::string slug;
        for (char c : fw)
          slug += (c == ' ' || c == '/') ? '-' : std::tolower(c);
        std::string profile_path = "profiles/" + slug + "/scan.yaml";
        if (std::filesystem::exists(profile_path)) {
          profile_config = profile_path;
          std::cout << "  -> Using learned profile: " << profile_path << "\n";
          break;
        }
      }

      // Launch ZAP: prefer learned profile, fallback to generated config.
      std::string active_config =
          profile_config.empty() ? zap_config : profile_config;
      std::string zap_cmd = "zap.sh -cmd -autorun " + active_config +
                            " -config target.url=https://" + cfg.target +
                            " -config api.disablekey=true 2>/dev/null";
      if (system("command -v zap-cli >/dev/null 2>&1") == 0) {
        zap_cmd = "zap-cli --zap-path $(which zap.sh) quick-scan -s xss,sqli "
                  "https://" +
                  cfg.target + " --output " + cfg.output_dir +
                  "/zap-report.json 2>/dev/null";
      }
      std::cout << "  -> Launching ZAP active scan...\n";
      int ret = system(zap_cmd.c_str());
      if (ret == 0) {
        std::cout << "  -> ZAP scan complete: " << cfg.output_dir
                  << "/zap-report.json\n";
      } else {
        std::cout << "  -> ZAP automation config generated (run manually with: "
                     "zap.sh -cmd -autorun "
                  << active_config << ")\n";
      }
    }
  }

  // Phase 7: Learn — auto-generate/update ZAP profiles for detected frameworks.
  {
    apex::ProfileGenerator profgen("profiles");
    auto intel =
        apex::ProfileGenerator::build_intel(cfg.target, crawl, findings);

    // Check each CMS/framework detection finding.
    for (const auto &f : findings) {
      if (f.type != "CMS Detection")
        continue;
      // Extract framework name from detail (e.g., "Detected: WordPress v6.4")
      std::string fw = f.detail;
      size_t pos = fw.find("Detected: ");
      if (pos != std::string::npos)
        fw = fw.substr(pos + 10);
      pos = fw.find(" v");
      if (pos != std::string::npos)
        fw = fw.substr(0, pos);
      if (fw.empty())
        continue;

      if (!profgen.has_profile(fw)) {
        std::cout << "\n[Phase 7] Learn — New framework detected: " << fw
                  << "\n";
        profgen.generate_profile(fw, intel);
      } else {
        profgen.update_profile(fw, intel);
      }
    }

    // Also learn from tech detected in headers/JS.
    for (const auto &f : findings) {
      if (f.type != "Technology Disclosure" &&
          f.type != "Server Banner Disclosure")
        continue;
      for (const auto &tech :
           {"Next.js", "Nuxt", "Laravel", "Django", "Rails", "Spring",
            "Express", "Flask", "FastAPI", "Symfony"}) {
        if (f.detail.find(tech) != std::string::npos &&
            !profgen.has_profile(tech)) {
          std::cout << "\n[Phase 7] Learn — New framework detected: " << tech
                    << "\n";
          profgen.generate_profile(tech, intel);
        }
      }
    }
  }

  // Watch mode: diff against baseline
  if (!cfg.watch_baseline.empty()) {
    auto baseline = apex::load_baseline(cfg.watch_baseline);
    if (!baseline.empty()) {
      auto diff = apex::compute_diff(findings, baseline);
      std::cout << "\n[Watch] Diff against " << cfg.watch_baseline << "\n";
      std::cout << "  -> " << diff.new_findings.size() << " NEW findings\n";
      std::cout << "  -> " << diff.unchanged << " unchanged\n";
      if (!diff.new_findings.empty()) {
        std::cout << "\n  ⚠ NEW FINDINGS:\n";
        for (const auto &f : diff.new_findings) {
          std::cout << "    [" << f.severity << "] " << f.type << " — " << f.url
                    << "\n";
        }
      }
    }
  }

  // Calculate maturity score
  std::cout << "\n[Maturity] Calculating score...\n";
  apex::MaturityCalculator maturity_calc;

  // Collect CMS versions from findings
  std::vector<CMSVersion> cms_versions;
  for (const auto &f : findings) {
    if (f.type == "CMS Detection" && !f.evidence.empty()) {
      // Parse evidence: "CMS|version|latest"
      size_t pos1 = f.evidence.find('|');
      size_t pos2 = f.evidence.find('|', pos1 + 1);
      if (pos1 != std::string::npos && pos2 != std::string::npos) {
        CMSVersion cms_ver;
        cms_ver.name = f.evidence.substr(0, pos1);
        cms_ver.version = f.evidence.substr(pos1 + 1, pos2 - pos1 - 1);
        cms_ver.latest_version = f.evidence.substr(pos2 + 1);
        cms_ver.outdated = (f.severity == "medium");
        cms_versions.push_back(cms_ver);
      }
    }
  }

  // Empty OSINT report for now (TODO: integrate when --osint flag is used)
  apex::OSINTReport osint_report;

  auto maturity = maturity_calc.calculate(findings, cms_versions, osint_report);

  std::cout << "\n╔══════════════════════════════════════╗\n";
  std::cout << "║   MATURITY SCORE                     ║\n";
  std::cout << "╚══════════════════════════════════════╝\n\n";
  std::cout << "🎯 Level: " << maturity.level << " (" << maturity.percentage
            << "%)\n\n";

  std::cout << "📊 Dimensions:\n";
  for (const auto &[name, dim] : maturity.dimensions) {
    std::cout << "   " << name << ": ";
    int bars = dim.score / 10;
    for (int i = 0; i < 10; i++) {
      std::cout << (i < bars ? "█" : "░");
    }
    std::cout << " " << dim.score << "% (" << dim.status << ")\n";
  }

  if (!maturity.recommendations.empty()) {
    std::cout << "\n📋 Recommendations:\n";
    for (size_t i = 0; i < maturity.recommendations.size() && i < 5; i++) {
      std::cout << "   " << (i + 1) << ". " << maturity.recommendations[i]
                << "\n";
    }
  }

  if (!maturity.next_level_requirements.empty()) {
    std::cout << "\n🎓 Next Level (" << (maturity.level + 1) << "):\n";
    for (const auto &req : maturity.next_level_requirements) {
      std::cout << "   - " << req << "\n";
    }
  }

  // Pipeline final report
  if (cfg.pipeline) {
    apex::PipelineResult pipeline_result;
    pipeline_result.total_findings = findings.size();
    pipeline_result.total_seconds = elapsed.count();
    pipeline_result.stages = {
        {"Recon", (int)recon.live_targets.size(), 0},
        {"Crawl", (int)crawl.urls.size(), 0},
        {"Scan", (int)findings.size(), (double)elapsed.count()},
    };

    // Categorize by novelty
    for (const auto &f : findings) {
      auto n = apex::score_novelty(f);
      auto c = apex::score_confidence(f);
      if (n == apex::Novelty::High && c == apex::Confidence::Confirmed)
        pipeline_result.reportable.push_back(f);
      else if (static_cast<int>(n) >= 2)
        pipeline_result.verify_first.push_back(f);
      else
        pipeline_result.skip.push_back(f);
    }

    apex::print_pipeline_report(pipeline_result);
  }

  std::cout << "\n[done] Scan complete in " << elapsed.count() << "s — "
            << findings.size() << " findings\n";

  // Watch mode: loop
  if (cfg.watch) {
    std::string prev_report = cfg.output_dir + "/report.json";
    std::cout << "\n[watch] Monitoring every " << cfg.watch_interval
              << "s. Ctrl+C to stop.\n";
    while (true) {
      std::this_thread::sleep_for(std::chrono::seconds(cfg.watch_interval));
      std::cout << "\n[watch] Re-scanning at "
                << std::put_time(
                       std::localtime(
                           &(*reinterpret_cast<const time_t *>(&elapsed))),
                       "%H:%M:%S")
                << "...\n";
      // Load baseline from previous run
      auto baseline = apex::load_baseline(prev_report);
      // Re-crawl and re-scan
      auto new_crawl = apex::run_crawler(cfg, http, seeds);
      auto new_findings = apex::run_scanners(cfg, http, new_crawl);
      if (cfg.confidence_min > 0)
        new_findings =
            apex::filter_by_confidence(new_findings, cfg.confidence_min);
      // Diff
      auto diff = apex::compute_diff(new_findings, baseline);
      if (diff.new_findings.empty()) {
        std::cout << "  -> No new findings (unchanged: " << diff.unchanged
                  << ")\n";
      } else {
        std::cout << "  -> ⚠ " << diff.new_findings.size()
                  << " NEW findings:\n";
        for (const auto &f : diff.new_findings) {
          std::cout << "    [" << f.severity << "] " << f.type << " — " << f.url
                    << "\n";
        }
      }
      // Update report for next iteration
      apex::generate_report(cfg, new_findings, elapsed);
    }
  }

  return 0;
}
