/// @file scanner.cpp
/// @brief Scanner orchestrator: registers all feature modules, runs scanners
///        concurrently, deduplicates findings.
#include "scanner.hpp"

#include <algorithm>
#include <atomic>
#include <future>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>

#include "scanners/scanner_base.hpp"
#include "targeting.hpp"
#include "wildcard.hpp"

namespace apex {

// Global findings accessible by the Attack Chain Engine
std::vector<Finding> g_all_findings;

std::vector<Scanner> get_scanners() {
  std::vector<Scanner> all;
  auto append = [&](std::vector<Scanner>&& scanners) {
    all.insert(all.end(), std::make_move_iterator(scanners.begin()), std::make_move_iterator(scanners.end()));
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
  append(register_ssrf_deep_scanners());
  append(register_file_upload_scanners());
  append(register_race_condition_scanners());
  append(register_request_smuggling_scanners());
  append(register_cache_poison_scanners());
  append(register_jwt_attack_scanners());
  append(register_graphql_deep_scanners());
  append(register_subdomain_takeover_scanners());
  append(register_oauth_sso_scanners());
  append(register_injection_advanced_scanners());
  append(register_info_disclosure_scanners());
  append(register_waf_evasion_scanners());
  append(register_payload_mutator_scanners());
  append(register_behavioral_analysis_scanners());
  append(register_path_traversal_scanners());
  append(register_browser_engine_scanners());
  append(register_critical_hunter_scanners());
  append(register_cms_specific_scanners());
  append(register_api_protocol_scanners());
  append(register_cloud_attack_scanners());
  append(register_ecommerce_scanners());
  append(register_network_service_scanners());
  append(register_recon_deep2_scanners());
  append(register_auth_scanner_scanners());
  append(register_prototype_pollution_deep_scanners());
  append(register_autogen_azure_ad_microsoft_365_20_scanners());
  append(register_autogen_sso_identity_provider_20_scanners());
  append(register_autogen_payment_financial_25_scanners());
  append(register_autogen_email_security_15_scanners());
  append(register_autogen_dns_domain_20_scanners());
  append(register_autogen_api_authentication_20_scanners());
  append(register_autogen_session_management_20_scanners());
  append(register_autogen_input_validation_25_scanners());
  append(register_autogen_file_operations_20_scanners());
  append(register_autogen_cloud_storage_20_scanners());
  append(register_autogen_container_orchestration_15_scanners());
  append(register_autogen_ci_cd_security_15_scanners());
  append(register_autogen_serverless_edge_15_scanners());
  append(register_autogen_mobile_app_security_20_scanners());
  append(register_autogen_rate_limiting_dos_15_scanners());
  append(register_autogen_information_disclosure_extended_25_scanners());
  append(register_autogen_cryptography_15_scanners());
  append(register_autogen_business_logic_extended_25_scanners());
  append(register_autogen_privacy_compliance_15_scanners());
  append(register_autogen_third_party_integration_12_scanners());
  append(register_autogen_wordpress_deep_20_scanners());
  append(register_autogen_next_js_react_deep_15_scanners());
  append(register_autogen_laravel_php_deep_15_scanners());
  append(register_autogen_django_python_deep_15_scanners());
  append(register_autogen_spring_java_deep_15_scanners());
  append(register_autogen_node_js_express_deep_15_scanners());
  append(register_autogen_oauth_2_0_oidc_deep_15_scanners());
  append(register_autogen_cache_cdn_deep_15_scanners());
  append(register_autogen_http_protocol_15_scanners());
  append(register_autogen_subdomain_dns_extended_15_scanners());
  append(register_autogen_encoding_parser_differential_15_scanners());
  append(register_autogen_monitoring_observability_10_scanners());
  append(register_autogen_ai_llm_security_20_scanners());
  append(register_js_secrets_scanners());
  append(register_autogen_authentication_account_takeover_25_scanners());
  append(register_autogen_idor_broken_access_control_30_scanners());
  append(register_autogen_injection_30_scanners());
  append(register_autogen_business_logic_30_scanners());
  append(register_autogen_file_upload_15_scanners());
  append(register_autogen_api_specific_25_scanners());
  append(register_autogen_infrastructure_cloud_20_scanners());
  append(register_autogen_mobile_client_side_10_scanners());
  append(register_infra_misconfig_scanners());
  append(register_advanced_injection_scanners());
  append(register_auth_advanced2_scanners());
  append(register_modern_stack_scanners());
  append(register_business_logic_scanners());
  append(register_compliance_scanners());
  append(register_recon_advanced_scanners());

  return all;
}

std::vector<Finding> run_scanners(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  auto all_scanners = get_scanners();

  // Intelligent Targeting: build asset profile and select relevant modules
  auto profile = build_profile(crawl, http);
  auto scanners = cfg.full_scan ? all_scanners : select_modules(all_scanners, profile, 0.3);

  // Log targeting decision
  if (!cfg.full_scan && scanners.size() < all_scanners.size()) {
    std::cerr << "  [targeting] " << scanners.size() << "/" << all_scanners.size() << " modules selected (";
    for (const auto& t : profile.technologies) std::cerr << t << " ";
    if (profile.has_graphql) std::cerr << "graphql ";
    if (profile.has_jwt) std::cerr << "jwt ";
    if (profile.has_oauth) std::cerr << "oauth ";
    std::cerr << ")\n";
  }

  std::vector<Finding> all_findings;
  std::mutex mu;

  auto should_skip = [&](const std::string& name) {
    if (std::any_of(cfg.skip.begin(), cfg.skip.end(), [&](const std::string& s) { return s == name; })) return true;
    // Quick mode: only run high-value scanners.
    if (cfg.blitz) {
      // Ultra-fast: only the 20 checks most likely to find bounty-worthy bugs
      static const std::vector<std::string> blitz_scanners = {
        "Open Redirect", "SSRF", "IDOR", "Secrets Exposure", "GraphQL Hunter",
        "JWT", "Security Headers", "CORS", "SQLi", "XSS",
        "SSTI", "Default Credentials", "Git Exposure", "Env File Exposed",
        "S3 Buckets", "Subdomain Takeover", "Hidden Admin Panel",
        "OAuth Misconfig", "Password Reset Poisoning", "CRLF Response Splitting"
      };
      return std::none_of(blitz_scanners.begin(), blitz_scanners.end(), [&](const std::string& q) { return name.find(q) != std::string::npos; });
    }
    if (cfg.quick) {
      static const std::vector<std::string> quick_scanners = {"CMS Detection",
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
      return std::none_of(quick_scanners.begin(), quick_scanners.end(), [&](const std::string& q) { return q == name; });
    }
    return false;
  };

  std::vector<std::future<std::vector<Finding>>> futures;
  std::atomic<int> active_threads{0};
  int max_concurrent = std::min(cfg.threads, 100); // Cap at 100 concurrent HTTP operations

  for (const auto& scanner : scanners) {
    if (should_skip(scanner.name)) {
      std::cout << "    [skip] " << scanner.name << "\n";
      continue;
    }
    std::cout << "    [->] " << scanner.name << "\n";
    futures.push_back(std::async(std::launch::async, [&, scanner]() {
      // Wait until slot available
      while (active_threads.load() >= max_concurrent) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
      }
      active_threads.fetch_add(1);
      auto result = scanner.func(cfg, http, crawl);
      active_threads.fetch_sub(1);
      return result;
    }));
  }

  for (auto& f : futures) {
    auto results = f.get();
    std::lock_guard<std::mutex> lock(mu);
    all_findings.insert(all_findings.end(), results.begin(), results.end());
  }

  // Deduplicate on type+url+param.
  std::set<std::string> seen;
  std::vector<Finding> deduped;
  for (auto& f : all_findings) {
    std::string key = f.type + "|" + f.url + "|" + f.param;
    if (seen.insert(key).second) deduped.push_back(std::move(f));
  }

  // Filter wildcard/SPA false positives.
  // Get baseline for each unique host.
  std::map<std::string, BaselineFingerprint> baselines;
  auto get_host = [](const std::string& url) -> std::string {
    auto pos = url.find("://");
    if (pos == std::string::npos) return url;
    auto start = pos + 3;
    auto end = url.find('/', start);
    return url.substr(0, end != std::string::npos ? end : url.size());
  };

  std::vector<Finding> filtered;
  for (auto& f : deduped) {
    std::string host = get_host(f.url);
    if (baselines.find(host) == baselines.end()) {
      baselines[host] = get_baseline(http, host);
    }
    auto& bp = baselines[host];
    // Skip findings on wildcard hosts unless they have specific evidence
    if (bp.is_wildcard && f.evidence.empty()) {
      continue;
    }
    filtered.push_back(std::move(f));
  }

  // Quality filter: downgrade critical/high findings that lack evidence
  for (auto& f : filtered) {
    if ((f.severity == "critical" || f.severity == "high") && f.evidence.empty()) {
      // No evidence = unverified = downgrade to medium
      f.severity = "medium";
      f.type += " (unverified)";
    }
  }

  // AI Verification: use qwen3:14b to filter false positives
  {
    int ai_checked = 0;
    for (auto& f : filtered) {
      if (f.severity != "critical" && f.severity != "high") continue;
      if (ai_checked >= 5) break;
      std::string ev = f.evidence.substr(0, 80);
      for (auto& c : ev) {
        if (c == '"' || c == '\\' || c == '\n') c = ' ';
      }
      std::string type_clean = f.type;
      for (auto& c : type_clean) {
        if (c == '"') c = ' ';
      }
      std::string body =
          "{\"model\":\"qwen3:14b\",\"prompt\":\"/no_think REAL "
          "or FALSE_POSITIVE? " +
          type_clean + " " + ev + "\",\"stream\":false,\"options\":{\"num_predict\":5}}";
      std::string cmd = "curl -s http://127.0.0.1:11434/api/generate -d '" + body + "' 2>/dev/null";
      FILE* fp = popen(cmd.c_str(), "r");
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
  for (auto& f : filtered) {
    // Skip Cloud Metadata findings without actual metadata in evidence
    if (f.type.find("Cloud Metadata") != std::string::npos) {
      if (f.evidence.find("ami-id") == std::string::npos && f.evidence.find("instance-id") == std::string::npos &&
          f.evidence.find("AccessKeyId") == std::string::npos) {
        continue;
      }
    }
    // Skip XSLT/Deserialization without evidence
    if ((f.type.find("XSLT") != std::string::npos || f.type.find("Deserialization") != std::string::npos) && f.evidence.empty()) {
      continue;
    }
    // Skip findings whose evidence contains WAF/CDN generic responses
    if (!f.evidence.empty() &&
        (f.evidence.find("Access Denied") != std::string::npos || f.evidence.find("<!DOCTYPE html>") != std::string::npos ||
         f.evidence.find("Just a moment") != std::string::npos || f.evidence.find("Checking your browser") != std::string::npos ||
         f.evidence.find("Attention Required") != std::string::npos || f.evidence.find("cf-browser-verification") != std::string::npos ||
         f.evidence.find("Page Not Found") != std::string::npos)) {
      continue;
    }
    // Skip high/critical findings that only matched based on status code 200
    // without meaningful content validation (common CDN false positive)
    if ((f.severity == "critical" || f.severity == "high") && f.evidence.empty() && f.payload.empty()) {
      continue;
    }
    // Skip race condition targets that are just guessed paths (not from crawl)
    if (f.type.find("Race Condition Target") != std::string::npos && f.evidence.empty()) {
      continue;
    }
    // Skip subdomain takeover without actual CNAME/dangling DNS evidence
    if (f.type.find("Subdomain Takeover") != std::string::npos) {
      if (f.evidence.find("CNAME") == std::string::npos && f.evidence.find("NXDOMAIN") == std::string::npos &&
          f.evidence.find("dangling") == std::string::npos && f.evidence.find("NoSuchBucket") == std::string::npos &&
          f.evidence.find("There isn't a GitHub Pages") == std::string::npos &&
          f.evidence.find("ENOTFOUND") == std::string::npos) {
        continue;
      }
    }
    // Skip business logic findings that target guessed API paths without evidence
    // (coupon, cart, refund, discount endpoints that don't actually exist)
    if ((f.type.find("Coupon") != std::string::npos || f.type.find("Refund") != std::string::npos ||
         f.type.find("Cart") != std::string::npos || f.type.find("Discount") != std::string::npos ||
         f.type.find("Shipping") != std::string::npos || f.type.find("Gift Card") != std::string::npos ||
         f.type.find("Inventory") != std::string::npos || f.type.find("Quantity") != std::string::npos) &&
        f.evidence.find("JSON") == std::string::npos && f.evidence.find("response") == std::string::npos &&
        f.evidence.find("applied") == std::string::npos && f.evidence.find("success") == std::string::npos) {
      // Only keep if we have evidence it's a real e-commerce API
      if (f.evidence.empty() || f.evidence.find("No ") == 0) continue;
    }
    // Skip LDAP/Mass Assignment findings without injection proof
    if ((f.type.find("LDAP") != std::string::npos || f.type.find("Mass Assignment") != std::string::npos) &&
        f.evidence.empty()) {
      continue;
    }
    // Skip Auto-Escalate findings (chain engine speculative)
    if (f.type.find("Auto-Escalate") != std::string::npos && f.confidence < 0.7) {
      continue;
    }
    final_filtered.push_back(std::move(f));
  }


































  // Run Attack Chain Engine — combines findings into multi-step exploits

  // ============================================================
  // INTELLIGENCE LAYER: Enrich findings with metadata + filter by similarity
  // ============================================================

  // 1. Response Similarity Filter: get baseline 404/default response
  //    and remove findings whose evidence matches it (same page for everything = FP)
  {
    std::map<std::string, size_t> host_baseline_sizes;
    for (auto it = final_filtered.begin(); it != final_filtered.end();) {
      if (it->url.empty() || it->severity == "info") {
        ++it;
        continue;
      }

      std::string host = it->url.substr(0, it->url.find("/", 8));
      if (host_baseline_sizes.find(host) == host_baseline_sizes.end()) {
        auto bl = http.get(host + "/apex_nonexistent_baseline_" + std::to_string(time(nullptr)));
        host_baseline_sizes[host] = bl.body.size();
      }

      // If evidence is empty AND it's a high/critical finding, reduce confidence
      if (it->evidence.empty() && (it->severity == "critical" || it->severity == "high")) {
        it->confidence = 20;
      }
      ++it;
    }
  }

  // 2. CWE/CVSS/OWASP Enrichment
  {
    struct VulnMeta {
      std::string pattern;
      std::string cwe;
      std::string owasp;
      double cvss;
      int base_confidence;
    };

    const std::vector<VulnMeta> meta_map = {
        {"SQL Injection", "CWE-89", "A03:2021 Injection", 9.8, 90},
        {"SQLi", "CWE-89", "A03:2021 Injection", 9.8, 90},
        {"XSS", "CWE-79", "A03:2021 Injection", 6.1, 70},
        {"Cross-Site Scripting", "CWE-79", "A03:2021 Injection", 6.1, 70},
        {"SSRF", "CWE-918", "A10:2021 SSRF", 9.1, 80},
        {"SSTI", "CWE-1336", "A03:2021 Injection", 9.8, 90},
        {"Template Injection", "CWE-1336", "A03:2021 Injection", 9.8, 90},
        {"Command Injection", "CWE-78", "A03:2021 Injection", 9.8, 95},
        {"Path Traversal", "CWE-22", "A01:2021 Broken Access Control", 7.5, 80},
        {"LFI", "CWE-98", "A03:2021 Injection", 7.5, 80},
        {"RFI", "CWE-98", "A03:2021 Injection", 9.8, 85},
        {"IDOR", "CWE-639", "A01:2021 Broken Access Control", 6.5, 70},
        {"BOLA", "CWE-639", "A01:2021 Broken Access Control", 6.5, 70},
        {"BFLA", "CWE-285", "A01:2021 Broken Access Control", 8.0, 75},
        {"JWT", "CWE-347", "A02:2021 Cryptographic Failures", 7.5, 75},
        {"Prototype Pollution", "CWE-1321", "A03:2021 Injection", 8.0, 70},
        {"Request Smuggling", "CWE-444", "A05:2021 Security Misconfiguration", 9.1, 80},
        {"Cache Poisoning", "CWE-349", "A05:2021 Security Misconfiguration", 7.5, 70},
        {"CORS", "CWE-942", "A05:2021 Security Misconfiguration", 7.5, 70},
        {"Open Redirect", "CWE-601", "A01:2021 Broken Access Control", 4.7, 80},
        {"CSRF", "CWE-352", "A01:2021 Broken Access Control", 4.3, 60},
        {"Subdomain Takeover", "CWE-284", "A05:2021 Security Misconfiguration", 7.5, 75},
        {"Information Disclosure", "CWE-200", "A01:2021 Broken Access Control", 5.3, 80},
        {"S3 Bucket", "CWE-284", "A05:2021 Security Misconfiguration", 7.5, 85},
        {"Firebase", "CWE-284", "A05:2021 Security Misconfiguration", 7.5, 80},
        {"Admin", "CWE-284", "A01:2021 Broken Access Control", 9.1, 70},
        {"Auth Bypass", "CWE-287", "A07:2021 Authentication Failures", 9.8, 85},
        {"Password Reset", "CWE-640", "A07:2021 Authentication Failures", 8.0, 80},
        {"2FA Bypass", "CWE-308", "A07:2021 Authentication Failures", 8.0, 80},
        {"Race Condition", "CWE-362", "A04:2021 Insecure Design", 8.0, 60},
        {"Deserialization", "CWE-502", "A08:2021 Software Integrity", 9.8, 80},
        {"XXE", "CWE-611", "A05:2021 Security Misconfiguration", 7.5, 80},
        {"CRLF", "CWE-93", "A03:2021 Injection", 6.1, 75},
        {"GraphQL", "CWE-200", "A01:2021 Broken Access Control", 5.3, 70},
        {"Docker", "CWE-284", "A05:2021 Security Misconfiguration", 9.1, 85},
        {"Kubernetes", "CWE-284", "A05:2021 Security Misconfiguration", 9.8, 85},
        {"Terraform", "CWE-200", "A05:2021 Security Misconfiguration", 9.1, 90},
        {"Missing Header", "CWE-693", "A05:2021 Security Misconfiguration", 3.7, 95},
        {"Missing HSTS", "CWE-319", "A02:2021 Cryptographic Failures", 4.3, 95},
        {"Missing CSP", "CWE-693", "A05:2021 Security Misconfiguration", 3.7, 95},
    };

    for (auto& f : final_filtered) {
      for (const auto& meta : meta_map) {
        if (f.type.find(meta.pattern) != std::string::npos) {
          if (f.cwe_id.empty()) f.cwe_id = meta.cwe;
          if (f.owasp_category.empty()) f.owasp_category = meta.owasp;
          if (f.cvss_score == 0.0) f.cvss_score = meta.cvss;
          if (f.confidence == 0) f.confidence = meta.base_confidence;
          break;
        }
      }
      // Boost confidence if evidence is present
      if (!f.evidence.empty() && f.confidence > 0) {
        f.confidence = std::min(100, f.confidence + 15);
      }
      // Reduce confidence for unverified high/critical
      if (f.type.find("unverified") != std::string::npos) {
        f.confidence = std::max(10, f.confidence - 30);
      }
    }
  }

  // 3. Sort by confidence * cvss (practical exploitability ranking)
  std::sort(final_filtered.begin(), final_filtered.end(), [](const Finding& a, const Finding& b) {
    double score_a = a.confidence * a.cvss_score;
    double score_b = b.confidence * b.cvss_score;
    return score_a > score_b;
  });

  // ============================================================

  g_all_findings = final_filtered;
  auto chain_scanners = register_attack_chain_scanners();
  for (const auto& cs : chain_scanners) {
    auto chains = cs.func(cfg, http, crawl);
    for (auto& c : chains) {
      final_filtered.push_back(std::move(c));
    }
  }

  // Run Exploit Generator — creates PoC scripts for confirmed vulns
  g_all_findings = final_filtered;
  auto exploit_scanners = register_exploit_gen_scanners();
  for (const auto& es : exploit_scanners) {
    auto pocs = es.func(cfg, http, crawl);
    for (auto& p : pocs) {
      final_filtered.push_back(std::move(p));
    }
  }

  return final_filtered;
}

}  // namespace apex
