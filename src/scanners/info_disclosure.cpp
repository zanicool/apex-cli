/// @file scanners/info_disclosure.cpp
/// @brief Information disclosure: stack traces, verbose errors, path disclosure,
///        internal IP leaks, technology fingerprinting, and HTTP security headers.
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Trigger verbose errors to extract internal paths, stack traces, DB info.
std::vector<Finding> scan_error_disclosure(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Trigger errors with malformed input
  std::vector<std::pair<std::string, std::string>> error_triggers = {
      {base + "/'+OR+1=1--", "SQL error"},
      {base + "/%00", "null byte"},
      {base + "/{{", "template error"},
      {base + "/?id='+AND+1=CONVERT(int,@@version)--", "MSSQL version"},
      {base + "/AAAA" + std::string(5000, 'A'), "buffer overflow"},
      {base + "/?id[]=-1", "type juggling"},
      {base + "/api/v1/../../../etc/passwd", "path traversal"},
  };

  for (const auto& [url, trigger_type] : error_triggers) {
    auto resp = http.get(url);
    if (resp.status_code >= 400 && resp.body.size() > 100) {
      // Check for stack traces
      if (resp.body.find("Traceback") != std::string::npos || resp.body.find("at ") != std::string::npos ||
          resp.body.find("Exception") != std::string::npos || resp.body.find("stack trace") != std::string::npos) {
        findings.push_back(Finding{"Stack Trace Exposed", "medium", url,
                                   "Error response contains stack trace. Reveals: "
                                   "internal file paths, framework version, code structure.",
                                   "", trigger_type, resp.body.substr(0, 500)});
      }

      // Check for DB errors
      if (resp.body.find("SQL") != std::string::npos || resp.body.find("mysql") != std::string::npos ||
          resp.body.find("postgres") != std::string::npos || resp.body.find("ORA-") != std::string::npos ||
          resp.body.find("SQLSTATE") != std::string::npos) {
        findings.push_back(Finding{"Database Error Exposed", "high", url,
                                   "Error reveals database technology and possibly query structure. "
                                   "Aids SQL injection exploitation.",
                                   "", trigger_type, resp.body.substr(0, 300)});
      }

      // Check for internal paths
      std::regex path_re(R"x((/home/[^\s<"']+|/var/[^\s<"']+|/usr/[^\s<"']+|/app/[^\s<"']+|C:\\[^\s<"']+))x");
      std::smatch m;
      if (std::regex_search(resp.body, m, path_re)) {
        findings.push_back(
            Finding{"Internal Path Disclosed", "low", url, "Server error reveals internal file system path: " + m[0].str(), "", "", ""});
      }

      break;  // One error disclosure is enough
    }
  }
  return findings;
}

/// Detect internal IP addresses leaked in headers/body.
std::vector<Finding> scan_internal_ip_leak(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);

  // Check headers for internal IPs
  std::regex internal_ip_re(
      R"x(\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b)x");

  for (const auto& [key, val] : resp.headers) {
    std::smatch m;
    if (std::regex_search(val, m, internal_ip_re)) {
      findings.push_back(Finding{"Internal IP Leak — Header", "low", base,
                                 "HTTP header '" + key + "' leaks internal IP: " + m[0].str() +
                                     ". "
                                     "Reveals network topology for targeted attacks.",
                                 key, m[0].str(), ""});
      break;
    }
  }

  // Check body for internal IPs
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), internal_ip_re);
  std::sregex_iterator end;
  if (it != end) {
    findings.push_back(
        Finding{"Internal IP Leak — Body", "low", base, "Response body contains internal IP: " + (*it).str(), "", (*it).str(), ""});
  }

  return findings;
}

/// Comprehensive HTTP security headers check.
std::vector<Finding> scan_security_headers(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);

  struct HeaderCheck {
    std::string header;
    std::string missing_msg;
    std::string severity;
  };

  std::vector<HeaderCheck> checks = {
      // Only check headers not covered by core.cpp or modern_stack.cpp
      {"Referrer-Policy", "No Referrer-Policy — URL leakage to third parties", "low"},
      {"Cross-Origin-Opener-Policy", "No COOP — cross-origin window access possible", "low"},
      {"Cross-Origin-Embedder-Policy", "No COEP — Spectre-style attacks possible", "low"},
  };

  for (const auto& check : checks) {
    bool found = false;
    for (const auto& [key, val] : resp.headers) {
      std::string lower = key;
      std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
      std::string check_lower = check.header;
      std::transform(check_lower.begin(), check_lower.end(), check_lower.begin(), ::tolower);
      if (lower == check_lower) {
        found = true;
        break;
      }
    }
    if (!found) {
      findings.push_back(Finding{"Missing " + check.header, check.severity, base, check.missing_msg, "", "", ""});
    }
  }

  // Check for weak CSP
  for (const auto& [key, val] : resp.headers) {
    std::string lower = key;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "content-security-policy") {
      if (val.find("unsafe-inline") != std::string::npos && val.find("unsafe-eval") != std::string::npos) {
        findings.push_back(Finding{"CSP — unsafe-inline + unsafe-eval", "medium", base,
                                   "CSP allows both unsafe-inline and unsafe-eval. "
                                   "Effectively no XSS protection from CSP.",
                                   "CSP", val.substr(0, 200), ""});
      }
      if (val.find("*") != std::string::npos) {
        findings.push_back(Finding{"CSP — Wildcard Source", "medium", base,
                                   "CSP contains wildcard (*) source. Allows loading from any domain.", "CSP", val.substr(0, 200), ""});
      }
      break;
    }
  }

  return findings;
}

/// Technology fingerprinting — exact versions for CVE lookup.
std::vector<Finding> scan_tech_fingerprint(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);

  // Server header
  auto server = resp.headers.find("Server");
  if (server != resp.headers.end() && !server->second.empty()) {
    findings.push_back(Finding{"Server Version Disclosed", "low", base,
                               "Server header reveals: " + server->second +
                                   ". "
                                   "Helps attacker target specific CVEs.",
                               "Server", server->second, ""});
  }

  // X-Powered-By
  auto powered = resp.headers.find("X-Powered-By");
  if (powered != resp.headers.end()) {
    findings.push_back(
        Finding{"X-Powered-By Disclosed", "low", base, "X-Powered-By reveals: " + powered->second, "X-Powered-By", powered->second, ""});
  }

  // Framework detection from HTML
  struct FrameworkSig {
    std::string indicator;
    std::string name;
  };
  std::vector<FrameworkSig> sigs = {
      {"__next", "Next.js"},          {"__nuxt", "Nuxt.js"},       {"ng-version", "Angular"},   {"data-reactroot", "React"},
      {"data-svelte", "Svelte"},      {"wp-content", "WordPress"}, {"Joomla", "Joomla"},        {"Drupal", "Drupal"},
      {"laravel_session", "Laravel"}, {"csrftoken", "Django"},     {"_rails", "Ruby on Rails"}, {"express", "Express.js"},
  };

  for (const auto& sig : sigs) {
    if (resp.body.find(sig.indicator) != std::string::npos) {
      findings.push_back(Finding{"Framework Detected — " + sig.name, "info", base,
                                 "Application uses " + sig.name + " (detected via '" + sig.indicator +
                                     "'). "
                                     "Check for framework-specific vulnerabilities.",
                                 "", sig.name, ""});
      break;
    }
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_info_disclosure_scanners() {
  return {
      {"Error Disclosure", scan_error_disclosure},
      {"Internal IP Leak", scan_internal_ip_leak},
      {"Security Headers", scan_security_headers},
      {"Tech Fingerprint", scan_tech_fingerprint},
  };
}

}  // namespace apex
