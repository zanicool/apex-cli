/// @file scanner.cpp
/// @brief Scanner orchestrator: registers all feature modules, runs scanners
///        concurrently, deduplicates findings.
#include "scanner.hpp"
#include "scanners/scanner_base.hpp"
#include "wildcard.hpp"
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
  append(register_api_discovery_scanners());
  append(register_advanced_web_scanners());
  append(register_recon_extra_scanners());
  append(register_nuclei_scanners());
  append(register_wordpress_deep_scanners());
  append(register_graphql_hunter());
  append(register_detection_gap_scanners());
  append(register_bounty_hunter_scanners());
  append(register_mobile_api_scanners());
  append(register_app_discovery_scanners());
  append(register_infra_misconfig_scanners());
  append(register_advanced_injection_scanners());
  append(register_auth_advanced2_scanners());
  append(register_modern_stack_scanners());
  append(register_business_logic_scanners());
  append(register_compliance_scanners());
  append(register_recon_advanced_scanners());

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
          "CMS Detection",
          "SQLi",
          "XSS",
          "SSRF",
          "CMDi",
          "LFI",
          "Security Headers",
          "Open Redirect",
          "SSTI",
          "XXE",
          "CORS",
          "Clickjacking",
          "Info Disclosure",
          "WAF Detection",
          "Login Security",
          "Header Analysis",
          "Content Discovery",
          "Forced Browsing",
          "GraphQL Hunter",
          "IDOR",
          "JWT",
          "OAuth Misconfig",
          "Password Reset",
          "Race Condition",
          "API Version Bypass",
          "Secrets Exposure",
          "Supply Chain: Self-Hosted Tools",
          "Supply Chain: Cloud Storage",
          "Supply Chain: Integrations",
          "Supply Chain: Management Panels",
          "Supply Chain: SSO Config",
          "Supply Chain: API Keys",
          "WP Plugin",
          "WP Theme",
          "Password Reset Poisoning",
          "Account Takeover (Email Change)",
          "JWT Key Confusion",
          "GraphQL Abuse",
          "Rate Limit Bypass",
          "File Upload Abuse",
          "HTTP Parameter Pollution",
          "CRLF Response Splitting",
          "Method Override Bypass",
          "API Version Bypass"};
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
    futures.push_back(std::async(std::launch::async, scanner.func,
                                 std::cref(cfg), std::ref(http),
                                 std::cref(crawl)));
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

  // Filter wildcard/SPA false positives.
  // Get baseline for each unique host.
  std::map<std::string, BaselineFingerprint> baselines;
  auto get_host = [](const std::string &url) -> std::string {
    auto pos = url.find("://");
    if (pos == std::string::npos)
      return url;
    auto start = pos + 3;
    auto end = url.find('/', start);
    return url.substr(0, end != std::string::npos ? end : url.size());
  };

  std::vector<Finding> filtered;
  for (auto &f : deduped) {
    std::string host = get_host(f.url);
    if (baselines.find(host) == baselines.end()) {
      baselines[host] = get_baseline(http, host);
    }
    auto &bp = baselines[host];
    // Skip findings on wildcard hosts unless they have specific evidence
    if (bp.is_wildcard && f.evidence.empty()) {
      continue;
    }
    filtered.push_back(std::move(f));
  }

  // Quality filter: downgrade critical/high findings that lack evidence
  for (auto &f : filtered) {
    if ((f.severity == "critical" || f.severity == "high") &&
        f.evidence.empty()) {
      // No evidence = unverified = downgrade to medium
      f.severity = "medium";
      f.type += " (unverified)";
    }
  }

  // AI Verification: use qwen3:14b to filter false positives
  {
    int ai_checked = 0;
    for (auto &f : filtered) {
      if (f.severity != "critical" && f.severity != "high")
        continue;
      if (ai_checked >= 5)
        break;
      std::string ev = f.evidence.substr(0, 80);
      for (auto &c : ev) {
        if (c == '"' || c == '\\' || c == '\n')
          c = ' ';
      }
      std::string type_clean = f.type;
      for (auto &c : type_clean) {
        if (c == '"')
          c = ' ';
      }
      std::string body = "{\"model\":\"qwen3:14b\",\"prompt\":\"/no_think REAL "
                         "or FALSE_POSITIVE? " +
                         type_clean + " " + ev +
                         "\",\"stream\":false,\"options\":{\"num_predict\":5}}";
      std::string cmd = "curl -s http://127.0.0.1:11434/api/generate -d '" +
                        body + "' 2>/dev/null";
      FILE *fp = popen(cmd.c_str(), "r");
      if (fp) {
        char buf[2048] = {};
        fread(buf, 1, sizeof(buf) - 1, fp);
        pclose(fp);
        std::string resp(buf);
        if (resp.find("FALSE") != std::string::npos) {
          f.severity = "info";
          f.type += " (AI:FP)";
        }
        ai_checked++;
      }
    }
  }

  // Remove pure noise findings that add no value
  std::vector<Finding> final_filtered;
  for (auto &f : filtered) {
    // Skip Cloud Metadata findings without actual metadata in evidence
    if (f.type.find("Cloud Metadata") != std::string::npos) {
      if (f.evidence.find("ami-id") == std::string::npos &&
          f.evidence.find("instance-id") == std::string::npos &&
          f.evidence.find("AccessKeyId") == std::string::npos) {
        continue;
      }
    }
    // Skip XSLT/Deserialization without evidence
    if ((f.type.find("XSLT") != std::string::npos ||
         f.type.find("Deserialization") != std::string::npos) &&
        f.evidence.empty()) {
      continue;
    }
    final_filtered.push_back(std::move(f));
  }

  return final_filtered;
}

} // namespace apex
