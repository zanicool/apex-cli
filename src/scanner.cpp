/// @file scanner.cpp
/// @brief Scanner orchestrator: registers all feature modules, runs scanners
///        concurrently, deduplicates findings.
#include "scanner.hpp"
#include "scanners/scanner_base.hpp"
#include <algorithm>
#include <future>
#include <iostream>
#include <mutex>
#include <set>

namespace apex {

std::vector<Scanner> get_scanners() {
  std::vector<Scanner> all;
  auto append = [&](std::vector<Scanner> &&scanners) {
    all.insert(all.end(), std::make_move_iterator(scanners.begin()),
               std::make_move_iterator(scanners.end()));
  };

  append(register_core_scanners());
  append(register_smart_scanners());
  append(register_elite_scanners());
  append(register_godly_scanners());
  append(register_autonomous_scanners());
  append(register_browser_scanners());
  append(register_auth_scanners());
  append(register_injection_scanners());
  append(register_logic_scanners());
  append(register_modern_scanners());
  append(register_infrastructure_scanners());
  append(register_oob_scanners());
  append(register_recon_scanners());
  append(register_web_scanners());
  append(register_exploit_scanners());
  append(register_extra_scanners());
  append(register_waf_scanners());
  append(register_supply_chain_scanners());
  append(register_advanced_auth_scanners());
  append(register_power_scanners());
  append(register_oob_confirmed_scanners());
  append(register_remaining_web_scanners());
  append(register_cloud_misconfig_scanners());
  append(register_secrets_scanners());
  append(register_ai_infra_scanners());
  append(register_version_cve_scanners());
  append(register_ssh_audit_scanners());
  append(register_cloud_stack_scanners());
  append(register_deep_recon_scanners());
  append(register_network_security_scanners());
  append(register_enterprise_osint_scanners());
  append(register_interactive_surface_scanners());
  append(register_otap_scanners());
  append(register_kvk_scanners());
  append(register_kev_scanners());
  append(register_cms_misconfig_scanners());
  append(register_contact_intel_scanners());
  append(register_leak_intel_scanners());
  append(register_shadow_it_scanners());
  append(register_document_intel_scanners());
  append(register_version_fingerprint_scanners());

  return all;
}

std::vector<Finding> run_scanners(const Config &cfg, HttpClient &http,
                                  const CrawlResult &crawl) {
  auto scanners = get_scanners();
  std::vector<Finding> all_findings;
  std::mutex mu;

  auto should_skip = [&](const std::string &name) {
    if (std::any_of(cfg.skip.begin(), cfg.skip.end(),
                    [&](const std::string &s) { return s == name; }))
      return true;
    // Quick mode: only run high-value scanners.
    if (cfg.quick) {
      static const std::vector<std::string> quick_scanners = {
          "CMS Detection", "SQLi", "XSS", "SSRF", "CMDi", "LFI",
          "Security Headers", "Open Redirect", "SSTI", "XXE",
          "CORS", "Clickjacking", "Info Disclosure",
          "WAF Detection", "Login Security", "Header Analysis",
          "Content Discovery", "Forced Browsing",
          "Supply Chain: Self-Hosted Tools", "Supply Chain: Cloud Storage",
          "Supply Chain: Integrations", "Supply Chain: Management Panels",
          "Supply Chain: SSO Config", "Supply Chain: API Keys",
          "WP Plugin", "WP Theme"};
      return std::none_of(quick_scanners.begin(), quick_scanners.end(),
                          [&](const std::string &q) { return q == name; });
    }
    return false;
  };

  std::vector<std::future<std::vector<Finding>>> futures;
  for (const auto &scanner : scanners) {
    if (should_skip(scanner.name)) {
      std::cout << "    [skip] " << scanner.name << "\n";
      continue;
    }
    std::cout << "    [->] " << scanner.name << "\n";
    futures.push_back(
        std::async(std::launch::async, scanner.func, std::cref(cfg),
                   std::ref(http), std::cref(crawl)));
  }

  for (auto &f : futures) {
    auto results = f.get();
    std::lock_guard<std::mutex> lock(mu);
    all_findings.insert(all_findings.end(), results.begin(), results.end());
  }

  // Deduplicate on type+url+param.
  std::set<std::string> seen;
  std::vector<Finding> deduped;
  for (auto &f : all_findings) {
    std::string key = f.type + "|" + f.url + "|" + f.param;
    if (seen.insert(key).second)
      deduped.push_back(std::move(f));
  }

  return deduped;
}

} // namespace apex
