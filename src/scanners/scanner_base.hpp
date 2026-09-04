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

  // Strip any existing query string / fragment from the iterated URL so we
  // match against the same base that extract_query_params() stored, and so we
  // never build malformed URLs like "/users?id=1?name=payload".
  std::string base = url;
  auto qpos = base.find('?');
  if (qpos != std::string::npos) base = base.substr(0, qpos);
  auto fpos = base.find('#');
  if (fpos != std::string::npos) base = base.substr(0, fpos);

  // Collect the real parameters discovered for this base URL.
  for (const auto &p : crawl.params) {
    std::string pbase = p.url;
    auto pq = pbase.find('?');
    if (pq != std::string::npos) pbase = pbase.substr(0, pq);
    if (pbase == base)
      targets.push_back({base + "?" + p.name + "=", p.name});
  }

  // Also derive targets from discovered FORMS. A search box like
  // <form action="/search.jsp"><input name="query"> exposes the "query"
  // parameter only as a form field — it never appears as a "?query=" URL, so
  // extract_query_params() misses it. Without this, reflected XSS / injection
  // in form-driven endpoints (e.g. AltoroMutual's /search.jsp) is never tested.
  // We map GET-form fields to "action?field=" targets. The form action is
  // matched against either the iterated URL's base or treated as a sibling
  // path on the same origin.
  for (const auto &form : crawl.forms) {
    // Resolve the form action to an absolute base.
    std::string action = form.action;
    std::string action_base;
    if (action.rfind("http", 0) == 0) {
      action_base = action;
    } else {
      // Build origin from the iterated URL.
      std::string origin = base;
      auto scheme = origin.find("://");
      if (scheme != std::string::npos) {
        auto slash = origin.find('/', scheme + 3);
        origin = (slash != std::string::npos) ? origin.substr(0, slash) : origin;
      }
      if (!action.empty() && action[0] == '/')
        action_base = origin + action;
      else if (!action.empty())
        action_base = origin + "/" + action;
      else
        action_base = base; // self-submitting form
    }
    auto aq = action_base.find('?');
    if (aq != std::string::npos) action_base = action_base.substr(0, aq);

    // Bound the work: only attach this form's fields when the form's action
    // targets the URL we are currently iterating, OR when we are iterating the
    // origin root (so a homepage search form is still reached exactly once).
    std::string origin = base;
    {
      auto scheme = origin.find("://");
      if (scheme != std::string::npos) {
        auto slash = origin.find('/', scheme + 3);
        origin = (slash != std::string::npos) ? origin.substr(0, slash) : origin;
      }
    }
    bool at_root = (base == origin || base == origin + "/");
    if (action_base != base && !at_root) continue;

    // GET forms turn fields into query params; POST forms are also worth
    // probing via query (many handlers accept both), but we keep GET behaviour
    // primary and only add fields we haven't already recorded.
    for (const auto &field : form.fields) {
      if (field.name.empty()) continue;
      std::string t = action_base + "?" + field.name + "=";
      bool dup = false;
      for (const auto &[et, en] : targets)
        if (et == t) { dup = true; break; }
      if (!dup) targets.push_back({t, field.name});
    }
  }

  // Only fabricate a synthetic parameter when NO real params exist for this
  // URL. Testing a guessed param against a page that has none is the single
  // largest source of false positives, so we gate it: skip synthetic probing
  // entirely for URLs that already exposed real parameters.
  if (targets.empty())
    targets.push_back({base + "?" + default_param + "=", default_param});
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

/// Percent-encode a payload for safe use as a query-string VALUE. The HTTP
/// client passes URLs to curl verbatim (no encoding), so a payload containing
/// spaces or other reserved characters — e.g. "<img src=x onerror=alert(1)>" —
/// would otherwise produce a malformed request that the server mishandles
/// (this caused a real reflected-XSS miss on form-driven endpoints). Unreserved
/// characters (RFC 3986) are left as-is so the payload still reflects verbatim
/// where it is echoed back decoded.
inline std::string url_encode(const std::string &s) {
  static const char hex[] = "0123456789ABCDEF";
  std::string out;
  out.reserve(s.size() * 3);
  for (unsigned char c : s) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
        c == '~') {
      out += static_cast<char>(c);
    } else {
      out += '%';
      out += hex[c >> 4];
      out += hex[c & 0x0F];
    }
  }
  return out;
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
std::vector<Scanner> register_nuclei_scanners();
std::vector<Scanner> register_graphql_hunter();
std::vector<Scanner> register_remaining_web_scanners();
std::vector<Scanner> register_detection_gap_scanners();

} // namespace apex

#endif // APEX_SCANNERS_BASE_HPP
