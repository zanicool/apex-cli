/// @file scanners/mobile_api.cpp
/// @brief Mobile/API specific scanners: certificate pinning bypass,
///        deeplink hijacking, API key in URL, insecure data storage indicators,
///        broken object level auth, excessive data exposure.
#include "scanner_base.hpp"
#include <regex>

namespace apex {
namespace {

/// Check for API keys leaked in URLs (query params).
std::vector<Finding> scan_api_key_in_url(const Config &, HttpClient &,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::regex key_re(R"([\?&](api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret|key)=([A-Za-z0-9_\-]{16,}))");

  for (const auto &url : crawl.urls) {
    std::smatch m;
    if (std::regex_search(url, m, key_re)) {
      findings.push_back({"API Key in URL", "medium", url,
                          "Sensitive token in query string — logged in server/proxy logs",
                          m[1].str(), m[2].str().substr(0, 10) + "...",
                          "Key param found in crawled URL"});
    }
  }
  return findings;
}

/// Excessive data exposure — API returns more fields than needed.
std::vector<Finding> scan_excessive_data(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> sensitive_fields = {
      "\"password\"", "\"password_hash\"", "\"secret\"", "\"ssn\"",
      "\"credit_card\"", "\"card_number\"", "\"cvv\"", "\"internal_id\"",
      "\"private_key\"", "\"salt\"", "\"token\"", "\"refresh_token\""};

  for (const auto &url : crawl.urls) {
    if (url.find("api") == std::string::npos) continue;
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;
    for (const auto &field : sensitive_fields) {
      if (resp.body.find(field) != std::string::npos) {
        findings.push_back({"Excessive Data Exposure", "high", url,
                            "API response contains sensitive field: " + field,
                            "", field,
                            "Found in " + std::to_string(resp.body.size()) + " byte response"});
        break;
      }
    }
  }
  return findings;
}

/// Broken Object Level Auth — access objects by manipulating IDs in API.
std::vector<Finding> scan_bola(const Config &, HttpClient &http,
                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::regex api_id_re(R"(/api/[^/]+/(\d+))");
  const std::vector<std::string> pii = {"\"email\"", "\"phone\"", "\"name\"", "\"address\""};

  for (const auto &url : crawl.urls) {
    std::smatch m;
    if (!std::regex_search(url, m, api_id_re)) continue;
    int id = std::stoi(m[1].str());
    std::string base = url.substr(0, m.position(1));

    auto r1 = http.get(base + std::to_string(id));
    auto r2 = http.get(base + std::to_string(id + 1));
    if (r1.status_code == 200 && r2.status_code == 200 &&
        r1.body != r2.body && contains_any(r2.body, pii)) {
      findings.push_back({"BOLA (Broken Object Level Auth)", "high", url,
                          "Different user objects accessible by incrementing ID",
                          "path_id", std::to_string(id + 1),
                          "Response contains PII for adjacent ID"});
      break;
    }
  }
  return findings;
}

/// Insecure HTTP methods enabled (PUT, DELETE, PATCH without auth).
std::vector<Finding> scan_dangerous_methods(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  for (const auto &url : crawl.urls) {
    if (url.find("api") == std::string::npos) continue;
    // OPTIONS request to check allowed methods
    auto resp = http.get(url, {{"Access-Control-Request-Method", "DELETE"}});
    auto allow = resp.headers.find("Allow");
    if (allow != resp.headers.end()) {
      if (allow->second.find("DELETE") != std::string::npos ||
          allow->second.find("PUT") != std::string::npos) {
        findings.push_back({"Dangerous HTTP Methods", "medium", url,
                            "PUT/DELETE methods allowed: " + allow->second,
                            "", "", "Allow: " + allow->second});
        break;
      }
    }
  }
  return findings;
}

/// Deeplink/Universal link hijack — check .well-known/assetlinks.json.
std::vector<Finding> scan_deeplink_hijack(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/.well-known/assetlinks.json");
  if (resp.status_code == 200 && resp.body.find("target") != std::string::npos) {
    // Check if it allows any package
    if (resp.body.find("*") != std::string::npos) {
      findings.push_back({"Deeplink Hijack — Wildcard", "high", base + "/.well-known/assetlinks.json",
                          "assetlinks.json allows wildcard package — any app can claim links",
                          "", "*", resp.body.substr(0, 200)});
    }
  }

  auto apple = http.get(base + "/.well-known/apple-app-site-association");
  if (apple.status_code == 200 && apple.body.find("applinks") != std::string::npos) {
    if (apple.body.find("\"*\"") != std::string::npos) {
      findings.push_back({"Universal Link Hijack", "medium",
                          base + "/.well-known/apple-app-site-association",
                          "Apple app-site-association has overly broad path matching",
                          "", "", apple.body.substr(0, 200)});
    }
  }
  return findings;
}

/// Server-Side Request Forgery via URL params.
std::vector<Finding> scan_ssrf_params(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::regex url_param_re(R"([\?&](url|uri|link|next|redirect|path|src|dest|target|return)=)");

  for (const auto &url : crawl.urls) {
    std::smatch m;
    if (!std::regex_search(url, m, url_param_re)) continue;
    std::string param = m[1].str();
    std::string base = url.substr(0, url.find(param + "=") + param.size() + 1);

    // Try internal URL
    auto resp = http.get(base + "http://127.0.0.1:80");
    if (resp.status_code == 200 && resp.body.size() > 50 &&
        resp.body.find("error") == std::string::npos) {
      findings.push_back({"SSRF via URL Parameter", "high", url,
                          "Server fetches attacker-controlled URL",
                          param, "http://127.0.0.1:80",
                          "Got " + std::to_string(resp.body.size()) + " bytes from internal URL"});
      break;
    }
  }
  return findings;
}

/// Unprotected admin actions — state-changing without CSRF token.
std::vector<Finding> scan_missing_csrf(const Config &, HttpClient &,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.forms.empty()) return findings;

  for (const auto &form : crawl.forms) {
    if (form.method != "POST") continue;
    // Check if form has CSRF token
    bool has_csrf = false;
    for (const auto &field : form.fields) {
      std::string lower = field.name;
      std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
      if (lower.find("csrf") != std::string::npos ||
          lower.find("token") != std::string::npos ||
          lower.find("_token") != std::string::npos ||
          lower.find("nonce") != std::string::npos) {
        has_csrf = true;
        break;
      }
    }
    if (!has_csrf && (form.action.find("delete") != std::string::npos ||
                      form.action.find("update") != std::string::npos ||
                      form.action.find("admin") != std::string::npos ||
                      form.action.find("settings") != std::string::npos)) {
      findings.push_back({"Missing CSRF Token", "medium", form.action,
                          "State-changing form without CSRF protection",
                          "", "", "POST form to " + form.action + " has no token field"});
    }
  }
  return findings;
}

/// Broken Function Level Auth — admin endpoints accessible to regular users.
std::vector<Finding> scan_bfla(const Config &, HttpClient &http,
                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> admin_apis = {
      "/api/admin/users", "/api/admin/config", "/api/admin/settings",
      "/api/admin/logs", "/api/admin/stats", "/api/internal/debug",
      "/api/v1/admin/export", "/api/management/users"};

  for (const auto &path : admin_apis) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 100 &&
        resp.body.find("error") == std::string::npos &&
        resp.body.find("unauthorized") == std::string::npos &&
        contains_any(resp.body, {"\"email\"", "\"users\"", "\"config\"", "\"logs\""})) {
      findings.push_back({"BFLA (Broken Function Level Auth)", "critical",
                          base + path,
                          "Admin API accessible without elevated privileges",
                          "", "",
                          "Response contains sensitive data (" +
                              std::to_string(resp.body.size()) + " bytes)"});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_mobile_api_scanners() {
  return {
      {"API Key in URL", scan_api_key_in_url},
      {"Excessive Data Exposure", scan_excessive_data},
      {"BOLA", scan_bola},
      {"Dangerous HTTP Methods", scan_dangerous_methods},
      {"Deeplink Hijack", scan_deeplink_hijack},
      {"SSRF via Params", scan_ssrf_params},
      {"Missing CSRF", scan_missing_csrf},
      {"BFLA", scan_bfla},
  };
}

} // namespace apex
