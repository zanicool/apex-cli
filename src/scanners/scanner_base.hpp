/// @file scanners/scanner_base.hpp
/// @brief Shared types and helpers for scanner feature modules.
#ifndef APEX_SCANNERS_BASE_HPP
#define APEX_SCANNERS_BASE_HPP

#include "../config.hpp"
#include "../crawler.hpp"
#include "../http.hpp"
#include "../scanner.hpp"
#include <algorithm>
#include <regex>
#include <string>
#include <vector>

namespace apex {

/// Helper: extract base URL from a full URL.
inline std::string base_url_from(const std::string &url) {
  size_t pos = url.find("://");
  if (pos != std::string::npos) {
    pos = url.find("/", pos + 3);
    if (pos != std::string::npos) return url.substr(0, pos);
  }
  return url;
}

/// Helper: get parameter injection targets for a URL.
inline std::vector<std::pair<std::string, std::string>>
get_targets(const CrawlResult &crawl, const std::string &url,
            const std::string &default_param = "id") {
  std::vector<std::pair<std::string, std::string>> targets;
  for (const auto &p : crawl.params) {
    if (p.url == url) targets.push_back({p.url + "?" + p.name + "=", p.name});
  }
  if (targets.empty())
    targets.push_back({url + "?" + default_param + "=", default_param});
  return targets;
}

/// Helper: check if string contains any of the given substrings.
inline bool contains_any(const std::string &s,
                         const std::vector<std::string> &substrs) {
  return std::any_of(substrs.begin(), substrs.end(),
                     [&](const std::string &sub) {
                       return s.find(sub) != std::string::npos;
                     });
}

/// Registration functions — each module provides one.
std::vector<Scanner> register_core_scanners();
std::vector<Scanner> register_smart_scanners();
std::vector<Scanner> register_elite_scanners();
std::vector<Scanner> register_godly_scanners();
std::vector<Scanner> register_autonomous_scanners();
std::vector<Scanner> register_browser_scanners();
std::vector<Scanner> register_auth_scanners();
std::vector<Scanner> register_injection_scanners();
std::vector<Scanner> register_logic_scanners();
std::vector<Scanner> register_modern_scanners();
std::vector<Scanner> register_infrastructure_scanners();
std::vector<Scanner> register_oob_scanners();
std::vector<Scanner> register_recon_scanners();
std::vector<Scanner> register_web_scanners();
std::vector<Scanner> register_exploit_scanners();
std::vector<Scanner> register_extra_scanners();
std::vector<Scanner> register_waf_scanners();
std::vector<Scanner> register_supply_chain_scanners();
std::vector<Scanner> register_advanced_auth_scanners();
std::vector<Scanner> register_power_scanners();
std::vector<Scanner> register_oob_confirmed_scanners();
std::vector<Scanner> register_remaining_web_scanners();
std::vector<Scanner> register_cloud_misconfig_scanners();
std::vector<Scanner> register_secrets_scanners();
std::vector<Scanner> register_ai_infra_scanners();
std::vector<Scanner> register_version_cve_scanners();
std::vector<Scanner> register_ssh_audit_scanners();
std::vector<Scanner> register_cloud_stack_scanners();
std::vector<Scanner> register_deep_recon_scanners();
std::vector<Scanner> register_network_security_scanners();
std::vector<Scanner> register_enterprise_osint_scanners();
std::vector<Scanner> register_interactive_surface_scanners();
std::vector<Scanner> register_otap_scanners();
std::vector<Scanner> register_kvk_scanners();
std::vector<Scanner> register_kev_scanners();
std::vector<Scanner> register_cms_misconfig_scanners();
std::vector<Scanner> register_contact_intel_scanners();
std::vector<Scanner> register_leak_intel_scanners();
std::vector<Scanner> register_shadow_it_scanners();
std::vector<Scanner> register_document_intel_scanners();
std::vector<Scanner> register_version_fingerprint_scanners();
std::vector<Scanner> register_api_discovery_scanners();
std::vector<Scanner> register_remaining_web_scanners();

} // namespace apex

#endif // APEX_SCANNERS_BASE_HPP
