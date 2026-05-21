/// @file scanners/version_cve.cpp
/// @brief Version fingerprinting and CVE lookup: server banners, SSH version,
///        technology detection, known CVE matching for detected versions.
#include "scanner_base.hpp"
#include <map>

///
/// @details This scanner module is part of the apex-cli security scanning
/// framework. Each scanner function follows the standard signature:
///   std::vector<Finding>(const Config&, HttpClient&, const CrawlResult&)
///
/// Findings are categorized by severity: critical, high, medium, low, info.
/// All scanners run concurrently and results are deduplicated by the
/// scanner orchestrator (scanner.cpp).
///
/// @see scanner_base.hpp for shared types and helper functions.
/// @see scanner.hpp for the Finding struct and Scanner registration.
/// @note Scanners should be non-destructive and respect rate limits.

namespace apex {
namespace {

/// Known CVEs for common software versions (subset — high-impact only).
struct CVEEntry { const char *product; const char *version_prefix; const char *cve; const char *severity; const char *desc; };
const CVEEntry known_cves[] = {
    // Linux kernel 2026 bugs from the Tweakers article
    {"Linux", "5.", "CVE-2026-31431", "high", "Copy Fail — local privilege escalation"},
    {"Linux", "5.", "CVE-2026-43284", "high", "Dirty Frag — root via single command"},
    {"Linux", "5.", "CVE-2026-46300", "high", "Fragnesia — kernel memory corruption"},
    {"Linux", "5.", "CVE-2026-46333", "high", "ssh-keysign-pwn — local priv esc"},
    {"Linux", "6.", "CVE-2026-31431", "high", "Copy Fail — local privilege escalation"},
    {"Linux", "6.", "CVE-2026-43284", "high", "Dirty Frag — root via single command"},
    {"Linux", "6.", "CVE-2026-46300", "high", "Fragnesia — kernel memory corruption"},
    {"Linux", "6.", "CVE-2026-46333", "high", "ssh-keysign-pwn — local priv esc"},
    // Apache
    {"Apache", "2.4.49", "CVE-2021-41773", "critical", "Path traversal + RCE"},
    {"Apache", "2.4.50", "CVE-2021-42013", "critical", "Path traversal bypass"},
    // Nginx
    {"nginx", "1.17", "CVE-2021-23017", "high", "DNS resolver heap overflow"},
    // OpenSSH
    {"OpenSSH", "8.", "CVE-2024-6387", "critical", "regreSSHion — unauthenticated RCE"},
    {"OpenSSH", "9.0", "CVE-2024-6387", "critical", "regreSSHion — unauthenticated RCE"},
    {"OpenSSH", "9.1", "CVE-2024-6387", "critical", "regreSSHion — unauthenticated RCE"},
    {"OpenSSH", "9.2", "CVE-2024-6387", "critical", "regreSSHion — unauthenticated RCE"},
    {"OpenSSH", "9.3", "CVE-2024-6387", "critical", "regreSSHion — unauthenticated RCE"},
    {"OpenSSH", "9.4", "CVE-2024-6387", "critical", "regreSSHion — unauthenticated RCE"},
    {"OpenSSH", "9.5", "CVE-2024-6387", "critical", "regreSSHion — unauthenticated RCE"},
    {"OpenSSH", "9.6", "CVE-2024-6387", "critical", "regreSSHion — unauthenticated RCE"},
    {"OpenSSH", "9.7", "CVE-2024-6387", "critical", "regreSSHion — unauthenticated RCE"},
    // PHP
    {"PHP", "8.1", "CVE-2024-4577", "critical", "CGI argument injection RCE"},
    // Node.js
    {"Express", "4.", "CVE-2024-29041", "medium", "Open redirect"},
};

/// Scanner implementation.
/// @brief Scan for server_banner vulnerabilities.
std::vector<Finding> scan_server_banner(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);

  // Collect version info from headers.
  std::map<std::string, std::string> detected;

  auto server_it = resp.headers.find("Server");
  if (server_it != resp.headers.end() && server_it->second.size() > 2) {
    detected["Server"] = server_it->second;
    findings.push_back({"Server Banner Disclosure", "low", crawl.urls[0],
                        "Server: " + server_it->second, "", "", ""});
  }

  auto powered_it = resp.headers.find("X-Powered-By");
  if (powered_it != resp.headers.end()) {
    detected["X-Powered-By"] = powered_it->second;
    findings.push_back({"Technology Disclosure", "low", crawl.urls[0],
                        "X-Powered-By: " + powered_it->second, "", "", ""});
  }

  // Match against known CVEs.
  // Iterate over targets.
  for (const auto &[key, value] : detected) {
    for (const auto &cve : known_cves) {
      if (value.find(cve.product) != std::string::npos &&
          value.find(cve.version_prefix) != std::string::npos) {
        findings.push_back({std::string(cve.cve) + " (" + cve.product + ")",
                            cve.severity, crawl.urls[0],
                            std::string(cve.desc) + " — detected: " + value,
                            "", "", ""});
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for ssh_version vulnerabilities.
std::vector<Finding> scan_ssh_version(const Config &cfg, HttpClient &http,
                                      const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));
  if (domain.find(':') != std::string::npos)
    domain = domain.substr(0, domain.find(':'));

  // Try SSH banner grab via HTTP (some proxies expose it) or direct.
  // We use a trick: connect to port 22 via our HTTP client timeout.
  // This won't work for all targets but catches exposed SSH.
  auto resp = http.get("http://" + domain + ":22/");
  if (resp.body.find("SSH-") != std::string::npos) {
    std::string banner = resp.body.substr(0, resp.body.find('\n'));
    findings.push_back({"SSH Version Detected", "info", domain + ":22",
                        "SSH banner: " + banner, "", "", ""});

    // Check against known CVEs.
    for (const auto &cve : known_cves) {
      if (banner.find(cve.product) != std::string::npos &&
          banner.find(cve.version_prefix) != std::string::npos) {
        findings.push_back({std::string(cve.cve), cve.severity, domain + ":22",
                            std::string(cve.desc) + " — " + banner, "", "", ""});
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for version_endpoints vulnerabilities.
std::vector<Finding> scan_version_endpoints(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Endpoints that commonly leak version info.
  const std::vector<std::string> paths = {
      "/version", "/api/version", "/api/v1/version", "/status",
      "/health", "/info", "/api/info", "/server-info",
      "/.well-known/security.txt", "/humans.txt",
  };

  // Iterate over targets.
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code != 200 || resp.body.size() < 5) continue;

    // Look for version patterns.
    std::regex ver_re(R"((\d+\.\d+\.\d+))");
    std::smatch m;
    if (std::regex_search(resp.body, m, ver_re)) {
      findings.push_back({"Version Endpoint", "info", base + path,
                          "Version info exposed: " + m[0].str(), "", "", ""});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_version_cve_scanners() {
  return {
      {"Server Banner/CVE", scan_server_banner},
      {"SSH Version", scan_ssh_version},
      {"Version Endpoints", scan_version_endpoints},
  };
}

} // namespace apex
