/// @file scanners/version_cve.cpp
/// @brief Version fingerprinting and CVE lookup: server banners, SSH version,
///        technology detection, known CVE matching for detected versions.
#include <map>

#include "scanner_base.hpp"

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
struct CVEEntry {
  const char* product;
  const char* version_prefix;
  const char* cve;
  const char* severity;
  const char* desc;
};
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
    // === 2025-2026 HIGH IMPACT CVEs ===
    // Spring
    {"Spring", "5.", "CVE-2022-22965", "critical", "Spring4Shell — RCE via ClassLoader"},
    {"Spring Boot", "2.", "CVE-2022-22963", "critical", "Spring Cloud Function SpEL RCE"},
    {"Spring Boot", "3.", "CVE-2024-38816", "high", "Path traversal in static resources"},
    // Log4j
    {"Log4j", "2.", "CVE-2021-44228", "critical", "Log4Shell — JNDI RCE"},
    {"Log4j", "2.15", "CVE-2021-45046", "critical", "Log4Shell bypass"},
    // WordPress
    {"WordPress", "5.", "CVE-2024-6386", "critical", "WPML plugin RCE"},
    {"WordPress", "6.0", "CVE-2023-2982", "high", "Auth bypass via Social Login"},
    {"WordPress", "6.1", "CVE-2024-10924", "critical", "Really Simple Security auth bypass"},
    {"WordPress", "6.", "CVE-2025-39380", "critical", "Bricks Builder RCE"},
    // jQuery
    {"jQuery", "1.", "CVE-2020-11022", "medium", "XSS via HTML passed to DOM methods"},
    {"jQuery", "2.", "CVE-2020-11022", "medium", "XSS via HTML passed to DOM methods"},
    {"jQuery", "3.0", "CVE-2020-11023", "medium", "XSS in jQuery.htmlPrefilter"},
    {"jQuery", "3.1", "CVE-2020-11023", "medium", "XSS in jQuery.htmlPrefilter"},
    {"jQuery", "3.2", "CVE-2020-11023", "medium", "XSS in jQuery.htmlPrefilter"},
    {"jQuery", "3.3", "CVE-2020-11023", "medium", "XSS in jQuery.htmlPrefilter"},
    {"jQuery", "3.4", "CVE-2020-11023", "medium", "XSS in jQuery.htmlPrefilter"},
    // Next.js
    {"Next.js", "13.", "CVE-2024-34351", "high", "SSRF via Server Actions"},
    {"Next.js", "14.0", "CVE-2024-34351", "high", "SSRF via Server Actions"},
    {"Next.js", "14.", "CVE-2025-29927", "critical", "Middleware auth bypass via x-middleware-subrequest"},
    // React
    {"React", "16.", "CVE-2020-7919", "medium", "XSS via dangerouslySetInnerHTML"},
    // Angular
    {"Angular", "14.", "CVE-2023-26116", "medium", "ReDoS in angular-expressions"},
    {"Angular", "15.", "CVE-2023-26116", "medium", "ReDoS in angular-expressions"},
    // Laravel
    {"Laravel", "8.", "CVE-2021-3129", "critical", "Ignition RCE"},
    {"Laravel", "9.", "CVE-2024-52301", "high", "Env manipulation via query string"},
    {"Laravel", "10.", "CVE-2024-52301", "high", "Env manipulation via query string"},
    // Django
    {"Django", "3.", "CVE-2024-39329", "medium", "User enumeration via password reset"},
    {"Django", "4.", "CVE-2024-38875", "medium", "DoS via urlize/urlizetrunc"},
    {"Django", "5.", "CVE-2024-45230", "medium", "DoS via urlize"},
    // Ruby on Rails
    {"Rails", "6.", "CVE-2023-22795", "high", "ReDoS in Action Dispatch"},
    {"Rails", "7.", "CVE-2024-26143", "medium", "XSS via accept header"},
    // Struts
    {"Struts", "2.", "CVE-2023-50164", "critical", "Path traversal → RCE"},
    {"Struts", "6.", "CVE-2024-53677", "critical", "File upload path traversal"},
    // Confluence
    {"Confluence", "7.", "CVE-2023-22515", "critical", "Broken access control → admin"},
    {"Confluence", "8.", "CVE-2024-21683", "critical", "Authenticated RCE"},
    // GitLab
    {"GitLab", "16.", "CVE-2023-7028", "critical", "Account takeover via password reset"},
    {"GitLab", "17.", "CVE-2024-45409", "critical", "SAML auth bypass"},
    // Grafana
    {"Grafana", "8.", "CVE-2023-6152", "medium", "Email change without confirmation"},
    {"Grafana", "9.", "CVE-2024-1313", "medium", "Snapshot BOLA"},
    {"Grafana", "10.", "CVE-2024-1313", "medium", "Snapshot BOLA"},
    // Jenkins
    {"Jenkins", "2.", "CVE-2024-23897", "critical", "Arbitrary file read via CLI"},
    // Ivanti
    {"Ivanti", "", "CVE-2024-21887", "critical", "Connect Secure auth bypass + RCE"},
    {"Ivanti", "", "CVE-2025-0282", "critical", "Connect Secure unauthenticated RCE"},
    // Fortinet
    {"FortiOS", "7.", "CVE-2024-21762", "critical", "Out-of-bound write → RCE"},
    {"FortiOS", "7.", "CVE-2024-47575", "critical", "FortiManager unauthenticated RCE"},
    // PAN-OS
    {"PAN-OS", "10.", "CVE-2024-3400", "critical", "GlobalProtect command injection"},
    {"PAN-OS", "11.", "CVE-2024-3400", "critical", "GlobalProtect command injection"},
    // Citrix
    {"Citrix", "", "CVE-2023-4966", "critical", "Citrix Bleed — session token leak"},
    // MOVEit
    {"MOVEit", "", "CVE-2023-34362", "critical", "SQLi → RCE (Cl0p ransomware)"},
    // Telerik
    {"Telerik", "", "CVE-2024-4358", "critical", "Auth bypass in Report Server"},
    // Veeam
    {"Veeam", "", "CVE-2024-40711", "critical", "Unauthenticated RCE"},
    // CMS
    {"Drupal", "9.", "CVE-2024-45440", "medium", "Full path disclosure"},
    {"Drupal", "10.", "CVE-2024-45440", "medium", "Full path disclosure"},
    {"Joomla", "4.", "CVE-2023-23752", "medium", "Unauthenticated info disclosure"},
    {"Joomla", "5.", "CVE-2024-21726", "medium", "XSS via mail template"},
    // Docker/K8s
    {"Docker", "24.", "CVE-2024-21626", "critical", "Leaky Vessels — container escape"},
    {"Docker", "25.", "CVE-2024-21626", "critical", "Leaky Vessels — container escape"},
    {"Kubernetes", "1.27", "CVE-2024-9042", "high", "Command injection via node logs"},
    {"Kubernetes", "1.28", "CVE-2024-9042", "high", "Command injection via node logs"},
    // Database
    {"PostgreSQL", "14.", "CVE-2024-7348", "high", "Privilege escalation via pg_dump"},
    {"PostgreSQL", "15.", "CVE-2024-7348", "high", "Privilege escalation via pg_dump"},
    {"PostgreSQL", "16.", "CVE-2024-7348", "high", "Privilege escalation via pg_dump"},
    {"MySQL", "8.0", "CVE-2024-20985", "medium", "Privilege escalation"},
    {"Redis", "7.", "CVE-2024-31449", "high", "Heap overflow via Lua scripting"},
    // JS libraries
    {"lodash", "4.", "CVE-2021-23337", "high", "Prototype pollution → RCE in template"},
    {"axios", "0.", "CVE-2023-45857", "medium", "SSRF via server-side requests"},
    {"json-web-token", "", "CVE-2022-23539", "high", "JWT key confusion attack"},
    // Python
    {"Flask", "2.", "CVE-2023-30861", "high", "Session cookie leak on redirect"},
    {"Werkzeug", "2.", "CVE-2023-23934", "high", "Cookie injection via crafted names"},
    {"Tornado", "6.", "CVE-2023-28370", "medium", "Open redirect"},
    // Go
    {"Go", "1.21", "CVE-2024-24790", "critical", "net/netip — incorrect IPv4/IPv6 handling"},
    {"Go", "1.22", "CVE-2024-24790", "critical", "net/netip — incorrect IPv4/IPv6 handling"},
    // Proxy/LB
    {"HAProxy", "2.8", "CVE-2023-45539", "medium", "Request smuggling via # in URI"},
    {"Envoy", "1.28", "CVE-2024-23322", "high", "Ext_authz bypass via path manipulation"},
    {"Traefik", "2.", "CVE-2024-28869", "medium", "Header injection via ACME"},
};

/// Scanner implementation.
/// @brief Scan for server_banner vulnerabilities.
std::vector<Finding> scan_server_banner(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);

  // Collect version info from headers.
  std::map<std::string, std::string> detected;

  auto server_it = resp.headers.find("Server");
  if (server_it != resp.headers.end() && server_it->second.size() > 2) {
    detected["Server"] = server_it->second;
    findings.push_back({"Server Banner Disclosure", "low", crawl.urls[0], "Server: " + server_it->second, "", "", ""});
  }

  auto powered_it = resp.headers.find("X-Powered-By");
  if (powered_it != resp.headers.end()) {
    detected["X-Powered-By"] = powered_it->second;
    findings.push_back({"Technology Disclosure", "low", crawl.urls[0], "X-Powered-By: " + powered_it->second, "", "", ""});
  }

  // Match against known CVEs.
  // Iterate over targets.
  for (const auto& [key, value] : detected) {
    for (const auto& cve : known_cves) {
      if (value.find(cve.product) != std::string::npos && value.find(cve.version_prefix) != std::string::npos) {
        findings.push_back({std::string(cve.cve) + " (" + cve.product + ")", cve.severity, crawl.urls[0],
                            std::string(cve.desc) + " — detected: " + value, "", "", ""});
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for ssh_version vulnerabilities.
std::vector<Finding> scan_ssh_version(const Config& cfg, HttpClient& http, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos) domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos) domain = domain.substr(0, domain.find('/'));
  if (domain.find(':') != std::string::npos) domain = domain.substr(0, domain.find(':'));

  // Try SSH banner grab via HTTP (some proxies expose it) or direct.
  // We use a trick: connect to port 22 via our HTTP client timeout.
  // This won't work for all targets but catches exposed SSH.
  auto resp = http.get("http://" + domain + ":22/");
  if (resp.body.find("SSH-") != std::string::npos) {
    std::string banner = resp.body.substr(0, resp.body.find('\n'));
    findings.push_back({"SSH Version Detected", "info", domain + ":22", "SSH banner: " + banner, "", "", ""});

    // Check against known CVEs.
    for (const auto& cve : known_cves) {
      if (banner.find(cve.product) != std::string::npos && banner.find(cve.version_prefix) != std::string::npos) {
        findings.push_back({std::string(cve.cve), cve.severity, domain + ":22", std::string(cve.desc) + " — " + banner, "", "", ""});
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for version_endpoints vulnerabilities.
std::vector<Finding> scan_version_endpoints(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Endpoints that commonly leak version info.
  const std::vector<std::string> paths = {
      "/version",  "/api/version", "/api/v1/version",           "/status",     "/health", "/info",
      "/api/info", "/server-info", "/.well-known/security.txt", "/humans.txt",
  };

  // Iterate over targets.
  for (const auto& path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code != 200 || resp.body.size() < 5) continue;

    // Look for version patterns.
    std::regex ver_re(R"((\d+\.\d+\.\d+))");
    std::smatch m;
    if (std::regex_search(resp.body, m, ver_re)) {
      findings.push_back({"Version Endpoint", "info", base + path, "Version info exposed: " + m[0].str(), "", "", ""});
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_version_cve_scanners() {
  return {
      {"Server Banner/CVE", scan_server_banner},
      {"SSH Version", scan_ssh_version},
      {"Version Endpoints", scan_version_endpoints},
  };
}

}  // namespace apex
