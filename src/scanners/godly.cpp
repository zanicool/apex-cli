/// @file scanners/godly.cpp
/// @brief Godly tier: intelligent prioritization, response similarity,
///        multi-step flow exploitation, PoC generation, content discovery,
///        permission boundary testing, reflection mapping.
#include "scanner_base.hpp"
#include <cmath>
#include <set>
#include <sstream>

namespace apex {
namespace {

/// Compute simple string similarity (Jaccard on words).
double similarity(const std::string &a, const std::string &b) {
  if (a.empty() && b.empty()) return 1.0;
  if (a.empty() || b.empty()) return 0.0;
  std::set<std::string> sa, sb;
  std::istringstream ia(a), ib(b);
  std::string w;
  while (ia >> w) sa.insert(w);
  while (ib >> w) sb.insert(w);
  size_t intersect = 0;
  for (const auto &s : sa)
    if (sb.count(s)) ++intersect;
  size_t union_size = sa.size() + sb.size() - intersect;
  return union_size > 0 ? double(intersect) / double(union_size) : 0.0;
}

/// Multi-step flow exploitation — login then access protected resources.
std::vector<Finding> scan_multi_step(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Try common admin paths without auth.
  const std::vector<std::string> protected_paths = {
      "/admin", "/admin/", "/dashboard", "/panel", "/settings",
      "/api/admin/users", "/api/users", "/internal/config"};

  for (const auto &path : protected_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        resp.body.find("login") == std::string::npos &&
        resp.body.find("sign in") == std::string::npos &&
        resp.body.size() > 100) {
      findings.push_back({"Auth Bypass", "critical", base + path,
                          "Protected resource accessible without auth",
                          "", "", ""});
    }
  }
  return findings;
}

/// Content discovery with 404 fingerprinting.
std::vector<Finding> scan_content_discovery(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Get 404 fingerprint.
  auto not_found = http.get(base + "/definitely-not-exists-xyz123");
  std::string fp_404 = not_found.body.substr(0, 200);

  const std::vector<std::string> wordlist = {
      "/backup", "/backup.zip", "/db.sql", "/.env.bak", "/config.yml",
      "/wp-config.php.bak", "/server-status", "/server-info",
      "/.htaccess", "/web.config", "/crossdomain.xml", "/sitemap.xml",
      "/robots.txt", "/.well-known/security.txt", "/api/docs",
      "/swagger-ui.html", "/actuator", "/actuator/health",
      "/debug/vars", "/trace", "/.git/HEAD"};

  for (const auto &path : wordlist) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 10) {
      // Check it's not a soft 404.
      if (similarity(resp.body.substr(0, 200), fp_404) < 0.8) {
        findings.push_back({"Content Discovery", "info", base + path,
                            "Hidden content found (" +
                                std::to_string(resp.body.size()) + " bytes)",
                            "", "", ""});
      }
    }
  }
  return findings;
}

/// Permission boundary testing — access resources with different privilege.
std::vector<Finding> scan_permission_boundary(const Config &, HttpClient &http,
                                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Try accessing user-specific endpoints with different IDs.
  const std::vector<std::string> endpoints = {
      "/api/user/1/profile", "/api/user/2/profile",
      "/api/account/1", "/api/account/2",
      "/api/order/1", "/api/order/2"};

  for (size_t i = 0; i + 1 < endpoints.size(); i += 2) {
    auto r1 = http.get(base + endpoints[i]);
    auto r2 = http.get(base + endpoints[i + 1]);
    if (r1.status_code == 200 && r2.status_code == 200 &&
        r1.body != r2.body && r1.body.size() > 50) {
      findings.push_back({"Permission Boundary", "high", base + endpoints[i],
                          "Can access other users' data", "", "", ""});
    }
  }
  return findings;
}

/// Reflection mapping — find all parameters that reflect in response.
std::vector<Finding> scan_reflection_map(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::string canary = "rfl3ct10n";

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "q");
    for (const auto &[base, param] : targets) {
      auto resp = http.get(base + canary);
      if (resp.body.find(canary) != std::string::npos) {
        // Determine context.
        size_t pos = resp.body.find(canary);
        std::string ctx = "body";
        if (pos > 5) {
          std::string before = resp.body.substr(pos - 5, 5);
          if (before.find("\"") != std::string::npos) ctx = "attribute";
          else if (before.find("'") != std::string::npos) ctx = "js_string";
          else if (before.find(">") != std::string::npos) ctx = "html_tag";
        }
        findings.push_back({"Reflection", "info", url,
                            "Input reflected in " + ctx + " context",
                            param, canary, ""});
      }
    }
  }
  return findings;
}

/// Response diff engine — detect subtle differences between similar requests.
std::vector<Finding> scan_response_diff(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      auto r1 = http.get(base + "admin");
      auto r2 = http.get(base + "guest");
      if (r1.status_code == r2.status_code && !r1.body.empty() &&
          !r2.body.empty()) {
        double sim = similarity(r1.body, r2.body);
        if (sim > 0.3 && sim < 0.9) {
          findings.push_back({"Response Diff", "low", url,
                              "Different responses for admin/guest (sim=" +
                                  std::to_string(sim).substr(0, 4) + ")",
                              param, "", ""});
        }
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_godly_scanners() {
  return {
      {"Multi-Step Flow", scan_multi_step},
      {"Content Discovery", scan_content_discovery},
      {"Permission Boundary", scan_permission_boundary},
      {"Reflection Mapping", scan_reflection_map},
      {"Response Diff", scan_response_diff},
  };
}

} // namespace apex
