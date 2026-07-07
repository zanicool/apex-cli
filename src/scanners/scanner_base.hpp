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
  // Strip query string for comparison (crawl.params stores base URL only)
  std::string base_url = url;
  auto qpos = base_url.find('?');
  if (qpos != std::string::npos) base_url = base_url.substr(0, qpos);
  for (const auto &p : crawl.params) {
    if (p.url == base_url) targets.push_back({p.url + "?" + p.name + "=", p.name});
  }
  if (targets.empty())
    targets.push_back({base_url + "?" + default_param + "=", default_param});
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
std::vector<Scanner> register_advanced_web_scanners();
std::vector<Scanner> register_recon_extra_scanners();
std::vector<Scanner> register_nuclei_scanners();
std::vector<Scanner> register_graphql_hunter();
std::vector<Scanner> register_remaining_web_scanners();
std::vector<Scanner> register_detection_gap_scanners();
std::vector<Scanner> register_bounty_hunter_scanners();
std::vector<Scanner> register_mobile_api_scanners();
std::vector<Scanner> register_infra_misconfig_scanners();
std::vector<Scanner> register_advanced_injection_scanners();
std::vector<Scanner> register_auth_advanced2_scanners();
std::vector<Scanner> register_modern_stack_scanners();
std::vector<Scanner> register_business_logic_scanners();
std::vector<Scanner> register_compliance_scanners();
std::vector<Scanner> register_recon_advanced_scanners();

} // namespace apex

#endif // APEX_SCANNERS_BASE_HPP
namespace apex { std::vector<Scanner> register_wordpress_deep_scanners(); }
namespace apex { std::vector<Scanner> register_app_discovery_scanners(); }
namespace apex { std::vector<Scanner> register_ssrf_deep_scanners(); }
namespace apex { std::vector<Scanner> register_file_upload_scanners(); }
namespace apex { std::vector<Scanner> register_race_condition_scanners(); }
namespace apex { std::vector<Scanner> register_request_smuggling_scanners(); }
namespace apex { std::vector<Scanner> register_cache_poison_scanners(); }
namespace apex { std::vector<Scanner> register_jwt_attack_scanners(); }
namespace apex { std::vector<Scanner> register_graphql_deep_scanners(); }
namespace apex { std::vector<Scanner> register_subdomain_takeover_scanners(); }
namespace apex { std::vector<Scanner> register_oauth_sso_scanners(); }
namespace apex { std::vector<Scanner> register_injection_advanced_scanners(); }
namespace apex { std::vector<Scanner> register_info_disclosure_scanners(); }
namespace apex { std::vector<Scanner> register_attack_chain_scanners(); }
namespace apex { std::vector<Scanner> register_waf_evasion_scanners(); }
namespace apex { std::vector<Scanner> register_exploit_gen_scanners(); }
namespace apex { std::vector<Scanner> register_payload_mutator_scanners(); }
namespace apex { std::vector<Scanner> register_behavioral_analysis_scanners(); }
namespace apex { std::vector<Scanner> register_path_traversal_scanners(); }
namespace apex { std::vector<Scanner> register_browser_engine_scanners(); }
namespace apex { std::vector<Scanner> register_critical_hunter_scanners(); }
namespace apex { std::vector<Scanner> register_cms_specific_scanners(); }
namespace apex { std::vector<Scanner> register_api_protocol_scanners(); }
namespace apex { std::vector<Scanner> register_cloud_attack_scanners(); }
namespace apex { std::vector<Scanner> register_ecommerce_scanners(); }
namespace apex { std::vector<Scanner> register_network_service_scanners(); }
namespace apex { std::vector<Scanner> register_recon_deep2_scanners(); }
namespace apex { std::vector<Scanner> register_auth_scanner_scanners(); }
namespace apex { std::vector<Scanner> register_prototype_pollution_deep_scanners(); }
namespace apex { std::vector<Scanner> register_api_protocol_scanners(); }
namespace apex { std::vector<Scanner> register_ecommerce_scanners(); }namespace apex { std::vector<Scanner> register_autogen_authentication_account_takeover_25_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_idor_broken_access_control_30_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_injection_30_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_business_logic_30_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_file_upload_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_api_specific_25_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_infrastructure_cloud_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_mobile_client_side_10_scanners(); }
