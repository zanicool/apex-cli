/// @file main.cpp
/// @brief Apex CLI entry point — CLI parsing and scan orchestration.
#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "recon.hpp"
#include "reporter.hpp"
#include "sbom.hpp"
#include "scanner.hpp"
#include "cms_export.hpp"
#include "recon_logger.hpp"
#include "maturity.hpp"
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>

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
  std::cout << "  --dry-run      Preview without sending packets\n";
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
    } else if (arg[0] != '-') {
      target = arg;
    }
  }

  if (target.empty()) {
    print_usage();
    return 1;
  }

  cfg.target = target;
  if (cfg.output_dir.empty()) {
    cfg.output_dir = make_output_dir(target);
  }
  std::filesystem::create_directories(cfg.output_dir);

  // Banner.
  std::cout << kBanner;
  std::cout << "                    v" << kVersion
            << " — C++ Edition (high performance)\n";
  std::cout << "\n[*] Target: " << target << "\n";
  if (cfg.dry_run) {
    std::cout << "[*] Mode: DRY RUN\n";
  }

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
    seeds.push_back("https://" + cfg.target);
  }
  auto crawl = apex::run_crawler(cfg, http, seeds);
  std::cout << "  -> " << crawl.urls.size() << " URLs, "
            << crawl.params.size() << " params, "
            << crawl.forms.size() << " forms\n";

  // Phase 3: Scan.
  std::cout << "\n[Phase 3] Scan — " << apex::get_scanners().size()
            << " scanners\n";
  auto findings = apex::run_scanners(cfg, http, crawl);
  std::cout << "  -> " << findings.size() << " findings\n";

  // Log all findings to JSONL
  for (const auto& f : findings) {
    logger.log_finding(f);
  }

  // Phase 4: Report.
  auto end = std::chrono::steady_clock::now();
  auto elapsed =
      std::chrono::duration_cast<std::chrono::seconds>(end - start);
  std::cout << "\n[Phase 4] Report\n";
  apex::generate_report(cfg, findings, elapsed);

  // Phase 4b: Verify — reproduce high/critical findings with baseline comparison.
  int verify_count = 0;
  for (const auto &f : findings) {
    if (f.severity != "high" && f.severity != "critical") continue;
    if (f.payload.empty()) continue;
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
      if (f.severity != "high" && f.severity != "critical") continue;
      if (f.payload.empty()) continue;
      if (baselines.find(f.url) == baselines.end()) {
        auto bl = http.get(f.url);
        baselines[f.url] = bl.body.substr(0, 500);
      }
    }

    int confirmed_count = 0;
    for (auto &f : findings) {
      if (f.severity != "high" && f.severity != "critical") continue;
      if (f.payload.empty()) continue;

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
      if (confirmed) ++confirmed_count;

      if (proof_out.is_open()) {
        proof_out << "{\"type\":\"" << f.type << "\",\"severity\":\""
                  << f.severity << "\",\"url\":\"" << f.url
                  << "\",\"param\":\"" << f.param << "\",\"payload\":\""
                  << f.payload << "\",\"status\":\"" << status
                  << "\",\"response_code\":" << resp.status_code
                  << ",\"response_size\":" << resp.body.size()
                  << "}\n";
      }
      std::cout << "    [" << status << "] " << f.type << " — " << f.url
                << "\n";
      if (!confirmed) f.severity = "low"; // Downgrade unconfirmed.
    }
    std::cout << "  -> " << confirmed_count << "/" << verify_count
              << " confirmed\n";
    std::cout << "  -> Proof log: " << proof_path << "\n";
  }

  // Export CMS inventory if any CMS findings exist.
  bool has_cms = false;
  for (const auto& f : findings) {
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
    std::cout << "  -> SBOM (" << sbom_components.size() << " components): "
              << sbom_path << "\n";

    if (!cfg.dry_run) {
      std::cout << "  -> Checking OSV.dev for known vulnerabilities...\n";
      auto sbom_vulns = apex::check_osv(http, sbom_components);
      if (!sbom_vulns.empty()) {
        std::cout << "  -> " << sbom_vulns.size() << " vulnerabilities found:\n";
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
          if (d.find("Joomla") != std::string::npos) cms_name = "joomla";
          else if (d.find("WordPress") != std::string::npos) cms_name = "wordpress";
          else if (d.find("Drupal") != std::string::npos) cms_name = "drupal";
          else if (d.find("Magento") != std::string::npos) cms_name = "magento";
          break;
        }
      }
      std::string nuclei_out = cfg.output_dir + "/nuclei_findings.jsonl";
      std::string cmd = "nuclei -u https://" + cfg.target +
                        " -tags " + cms_name + ",cve" +
                        " -severity critical,high,medium" +
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
  std::cout << "  -> JSONL logs: cms_recon.jsonl, osint_recon.jsonl, vuln_recon.jsonl\n";

  // Phase 6: ZAP — generate config from recon and launch active scan.
  if (!cfg.dry_run && system("command -v zap-cli >/dev/null 2>&1 || command -v zap.sh >/dev/null 2>&1") == 0) {
    std::cout << "\n[Phase 6] ZAP — Active scan with targeted policy\n";

    // Generate ZAP automation YAML from our findings.
    std::string zap_config = cfg.output_dir + "/zap-automation.yaml";
    std::ofstream zap_out(zap_config);
    if (zap_out.is_open()) {
      // Determine scan policy based on detected tech.
      bool is_wordpress = false, has_forms = !crawl.forms.empty();
      bool has_api = false;
      for (const auto &f : findings) {
        if (f.detail.find("WordPress") != std::string::npos) is_wordpress = true;
        if (f.type == "API Schema Inference" || f.type == "GraphQL") has_api = true;
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

      // Launch ZAP automation framework.
      std::string zap_cmd = "zap.sh -cmd -autorun " + zap_config +
                            " -config api.disablekey=true 2>/dev/null";
      // Try zap-cli first, then zap.sh.
      if (system("command -v zap-cli >/dev/null 2>&1") == 0) {
        zap_cmd = "zap-cli --zap-path $(which zap.sh) quick-scan -s xss,sqli "
                  "https://" + cfg.target + " --output " + cfg.output_dir +
                  "/zap-report.json 2>/dev/null";
      }
      std::cout << "  -> Launching ZAP active scan...\n";
      int ret = system(zap_cmd.c_str());
      if (ret == 0) {
        std::cout << "  -> ZAP scan complete: " << cfg.output_dir << "/zap-report.json\n";
      } else {
        std::cout << "  -> ZAP automation config generated (run manually with: zap.sh -cmd -autorun " << zap_config << ")\n";
      }
    }
  }

  // Calculate maturity score
  std::cout << "\n[Maturity] Calculating score...\n";
  apex::MaturityCalculator maturity_calc;
  
  // Collect CMS versions from findings
  std::vector<CMSVersion> cms_versions;
  for (const auto& f : findings) {
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
  std::cout << "🎯 Level: " << maturity.level << " (" << maturity.percentage << "%)\n\n";
  
  std::cout << "📊 Dimensions:\n";
  for (const auto& [name, dim] : maturity.dimensions) {
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
      std::cout << "   " << (i + 1) << ". " << maturity.recommendations[i] << "\n";
    }
  }
  
  if (!maturity.next_level_requirements.empty()) {
    std::cout << "\n🎓 Next Level (" << (maturity.level + 1) << "):\n";
    for (const auto& req : maturity.next_level_requirements) {
      std::cout << "   - " << req << "\n";
    }
  }

  std::cout << "\n[done] Scan complete in " << elapsed.count() << "s — "
            << findings.size() << " findings\n";
  return 0;
}
