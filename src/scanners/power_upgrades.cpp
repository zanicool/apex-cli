/// @file scanners/power_upgrades.cpp
/// @brief Power upgrades: JS endpoint extraction, auto-register + auth scan,
///        param brute-force, differential response analysis.
#include "scanner_base.hpp"
#include "../payloads.hpp"
#include <fstream>
#include <set>
#include <sstream>

namespace apex {
namespace {

/// Load lines from a file, skipping comments and blanks.
std::vector<std::string> load_wordlist(const std::string &filename) {
  std::vector<std::string> lines;
  // Iterate over targets.
  for (const auto &dir : {"./payloads", "../payloads", "/usr/share/apex-cli/payloads"}) {
    std::string path = std::string(dir) + "/" + filename;
    std::ifstream f(path);
    if (!f.is_open()) continue;
    std::string line;
    while (std::getline(f, line)) {
      if (!line.empty() && line[0] != '#') lines.push_back(line);
    }
    break;
  }
  return lines;
}

/// JS endpoint extraction — find API routes in JavaScript files.
/// Scanner implementation.
std::vector<Finding> scan_js_endpoints(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::set<std::string> js_urls;
  // Iterate over targets.
  for (const auto &url : crawl.urls) {
    if (url.find(".js") != std::string::npos ||
        url.find("/static/js/") != std::string::npos ||
        url.find("/_next/") != std::string::npos)
      js_urls.insert(url);
  }
  // Iterate over targets.
  for (const auto &p : {"/main.js", "/app.js", "/bundle.js", "/vendor.js",
                         "/_next/static/chunks/main.js", "/static/js/main.js"})
    js_urls.insert(base + p);

  std::vector<std::regex> patterns = {
      std::regex(R"(["'](/api/[a-zA-Z0-9_/\-\.]+)["'])"),
      std::regex(R"(["'](/v[0-9]+/[a-zA-Z0-9_/\-\.]+)["'])"),
      std::regex(R"((?:fetch|axios)\s*\(\s*["'`]([^"'`\s]+))"),
      std::regex(R"((?:path|route|endpoint|url)\s*[:=]\s*["']([^"']+)["'])"),
  };

  std::set<std::string> discovered;
  // Iterate over targets.
  for (const auto &js_url : js_urls) {
    auto resp = http.get(js_url);
    if (resp.status_code != 200 || resp.body.size() < 100) continue;
    for (const auto &pat : patterns) {
      auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), pat);
      auto end = std::sregex_iterator();
      for (auto it = begin; it != end; ++it) {
        std::string ep = (*it)[1].str();
        if (ep.size() >= 3 && ep.size() <= 200 &&
            ep.find(".css") == std::string::npos &&
            ep.find(".png") == std::string::npos)
          discovered.insert(ep);
      }
    }
  }

  // Probe discovered endpoints.
  std::vector<std::string> live;
  // Iterate over targets.
  for (const auto &ep : discovered) {
    std::string full = ep.find("http") == 0 ? ep : base + ep;
    auto resp = http.get(full);
    if (resp.status_code != 404 && resp.status_code < 500)
      live.push_back(full);
    if (live.size() >= 20) break;
  }

  if (!live.empty()) {
    std::string detail = "Found " + std::to_string(live.size()) +
                         " live API endpoints in JavaScript";
    findings.push_back({"JS Endpoint Discovery", "info",
                        std::to_string(live.size()) + " endpoints from " +
                            std::to_string(js_urls.size()) + " JS files",
                        detail, "", "", ""});
  }
  return findings;
}

/// Auto-register and scan authenticated endpoints.
/// Scanner implementation.
std::vector<Finding> scan_authenticated(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> reg_paths = {
      "/register", "/signup", "/api/register", "/api/auth/register", "/api/v1/register"};

  std::string auth_token;
  std::string test_email = "apex_test_" + std::to_string(time(nullptr)) + "@test.com";

  // Iterate over targets.
  for (const auto &path : reg_paths) {
    std::string body = R"({"email":")" + test_email +
                       R"(","password":"ApexTest123!","username":"apextest"})";
    auto resp = http.post(base + path, body, "application/json");
    if (resp.status_code == 200 || resp.status_code == 201) {
      // Extract token.
      std::regex tok_re(R"(eyJ[A-Za-z0-9_-]{20,})");
      std::smatch m;
      if (std::regex_search(resp.body, m, tok_re)) {
        auth_token = m[0].str();
        break;
      }
    }
  }

  if (auth_token.empty()) return findings;

  findings.push_back({"Auto-Registration Successful", "info", base,
                      "Registered and obtained auth token (len=" +
                          std::to_string(auth_token.size()) + ")",
                      "", "", ""});

  // Probe authenticated endpoints.
  const std::vector<std::string> auth_paths = {
      "/api/me", "/api/user", "/api/profile", "/api/account",
      "/api/admin", "/api/users", "/api/dashboard"};

  // Iterate over targets.
  for (const auto &path : auth_paths) {
    auto unauth = http.get(base + path);
    auto authed = http.get(base + path, {{"Authorization", "Bearer " + auth_token}});
    if (authed.status_code == 200 &&
        (unauth.status_code == 401 || unauth.status_code == 403)) {
      findings.push_back({"Authenticated Endpoint Found", "info", base + path,
                          "Returns data with auth (" + std::to_string(authed.body.size()) + " bytes)",
                          "", "", ""});
      // IDOR check.
      for (const auto &id_path : {path + "/1", path + "/2", path + "?user_id=1"}) {
        auto id_resp = http.get(base + id_path, {{"Authorization", "Bearer " + auth_token}});
        if (id_resp.status_code == 200 && id_resp.body != authed.body &&
            id_resp.body.size() > 50) {
          findings.push_back({"IDOR via Authenticated Endpoint", "high", base + id_path,
                              "Different user data accessible with our auth token",
                              "", "", ""});
        }
      }
    }
  }
  return findings;
}

/// Arjun-style param brute-force.
/// Scanner implementation.
std::vector<Finding> scan_param_bruteforce(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  auto params = load_wordlist("params.txt");
  if (params.empty() || crawl.urls.empty()) return findings;

  size_t limit = std::min(crawl.urls.size(), size_t(5));
  for (size_t i = 0; i < limit; ++i) {
    auto base_resp = http.get(crawl.urls[i]);
    if (base_resp.status_code != 200) continue;
    int base_size = (int)base_resp.body.size();

    // Test in batches of 10.
    for (size_t j = 0; j < params.size(); j += 10) {
      std::string param_str;
      size_t end = std::min(j + 10, params.size());
      for (size_t k = j; k < end; ++k)
        param_str += params[k] + "=apex_test&";
      if (!param_str.empty()) param_str.pop_back();

      std::string sep = crawl.urls[i].find('?') != std::string::npos ? "&" : "?";
      auto resp = http.get(crawl.urls[i] + sep + param_str);
      if (resp.status_code != 200) continue;

      int diff = (int)resp.body.size() - base_size;
      if (std::abs(diff) <= 20) continue;

      // Narrow down which param caused it.
      for (size_t k = j; k < end; ++k) {
        auto indiv = http.get(crawl.urls[i] + sep + params[k] + "=apex_test");
        if (indiv.status_code == 200) {
          int idiff = (int)indiv.body.size() - base_size;
          if (std::abs(idiff) > 20) {
            findings.push_back({"Hidden Parameter: " + params[k], "medium",
                                crawl.urls[i] + sep + params[k] + "=apex_test",
                                "Param '" + params[k] + "' changes response (size diff: " +
                                    std::to_string(idiff) + " bytes)",
                                params[k], "", ""});
          }
        }
      }
    }
  }
  return findings;
}

/// Differential response analysis.
/// Scanner implementation.
std::vector<Finding> scan_differential(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  size_t limit = std::min(crawl.urls.size(), size_t(20));

  for (size_t i = 0; i < limit; ++i) {
    auto base_resp = http.get(crawl.urls[i]);
    if (base_resp.status_code != 200) continue;

    // Test auth headers that might reveal extra data.
    struct AH { const char *header; const char *value; const char *name; };
    const AH auth_headers[] = {
        {"Authorization", "Bearer test", "auth bearer"},
        {"X-API-Key", "test", "api key"},
        {"Cookie", "admin=true; role=admin", "admin cookie"},
        {"X-Forwarded-For", "127.0.0.1", "internal IP"},
    };

    for (const auto &ah : auth_headers) {
      auto resp = http.get(crawl.urls[i], {{ah.header, ah.value}});
      if (resp.status_code == 200 && resp.body != base_resp.body) {
        int diff = (int)resp.body.size() - (int)base_resp.body.size();
        if (diff > 50) {
          findings.push_back({"Differential: Extra Data with " + std::string(ah.name),
                              "high", crawl.urls[i],
                              std::string("Header '") + ah.header + ": " + ah.value +
                                  "' reveals " + std::to_string(diff) + " extra bytes",
                              "", "", ""});
        }
      }
    }

    // Test different HTTP methods.
    for (const auto &method : {"POST", "PUT", "PATCH", "DELETE"}) {
      auto resp = http.post(crawl.urls[i], "{}", "application/json");
      if (resp.status_code == 200 && resp.body != base_resp.body &&
          (int)resp.body.size() > (int)base_resp.body.size() + 50) {
        findings.push_back({"Differential: " + std::string(method) + " Returns Extra Data",
                            "medium", crawl.urls[i],
                            std::string(method) + " returns " +
                                std::to_string(resp.body.size() - base_resp.body.size()) +
                                " more bytes than GET",
                            "", "", ""});
        break;
      }
    }

    // Content-Type confusion.
    for (const auto &ct : {"application/json", "application/xml", "text/xml"}) {
      auto resp = http.post(crawl.urls[i], "{}", ct);
      if (resp.status_code == 200 && resp.body != base_resp.body &&
          (resp.body.find("stack") != std::string::npos ||
           resp.body.find("trace") != std::string::npos ||
           resp.body.find("debug") != std::string::npos)) {
        findings.push_back({"Content-Type Confusion — Debug Info Leak", "medium",
                            crawl.urls[i],
                            std::string("Content-Type '") + ct + "' triggers debug output",
                            "", "", ""});
        break;
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_power_scanners() {
  return {
      {"JS Endpoints", scan_js_endpoints},
      {"Authenticated Scan", scan_authenticated},
      {"Param Brute-Force", scan_param_bruteforce},
      {"Differential Analysis", scan_differential},
  };
}

} // namespace apex
