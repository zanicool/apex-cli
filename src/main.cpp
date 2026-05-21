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
#include <iomanip>
#include <iostream>
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
  std::cout << "  --dry-run      Preview without sending packets\n";
  std::cout << "  --help         Show this help\n";
}

/// Generate a timestamped output directory name.
std::string make_output_dir(const std::string &target) {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  std::ostringstream ss;
  ss << "scan_" << apex::safe_name(target) << "_"
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
