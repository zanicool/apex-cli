/// @file scanners/infra_misconfig.cpp
/// @brief Infrastructure misconfiguration scanners: DNS zone transfer,
///        exposed debug endpoints, default credentials, backup files,
///        source code disclosure, path traversal, directory listing,
///        server info disclosure, cookie manipulation.
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// DNS Zone Transfer attempt.
std::vector<Finding> scan_zone_transfer(const Config& cfg, HttpClient&, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string cmd = "dig @$(dig +short NS " + cfg.target + " | head -1) " + cfg.target + " AXFR +short 2>/dev/null | head -5";
  FILE* fp = popen(cmd.c_str(), "r");
  if (!fp) return findings;
  char buf[4096] = {};
  fread(buf, 1, sizeof(buf) - 1, fp);
  pclose(fp);
  std::string output(buf);
  if (!output.empty() && output.find("failed") == std::string::npos && output.find("Transfer failed") == std::string::npos &&
      output.size() > 10) {
    findings.push_back(
        {"DNS Zone Transfer", "high", cfg.target, "AXFR zone transfer allowed — full DNS records exposed", "", "", output.substr(0, 200)});
  }
  return findings;
}

/// Exposed debug/profiler endpoints.
std::vector<Finding> scan_debug_endpoints(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::pair<std::string, std::string>> debug_paths = {
      {"/debug/pprof/", "Go pprof"},
      {"/debug/vars", "Go expvar"},
      {"/_debugbar", "Laravel Debugbar"},
      {"/__debug__/", "Django Debug Toolbar"},
      {"/elmah.axd", "ELMAH (.NET)"},
      {"/_profiler/latest", "Symfony Profiler"},
      {"/actuator/heapdump", "Spring Heap Dump"},
      {"/actuator/threaddump", "Spring Thread Dump"},
      {"/actuator/loggers", "Spring Loggers"},
      {"/metrics", "Prometheus Metrics"},
      {"/health", "Health endpoint"},
      {"/.well-known/openid-configuration", "OpenID Config"},
      {"/info", "Spring Info"},
      {"/jolokia/", "Jolokia JMX"},
      {"/console", "H2/Debug Console"},
  };

  for (const auto& [path, name] : debug_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 100) {
      std::string sev = "medium";
      if (path.find("heapdump") != std::string::npos || path.find("jolokia") != std::string::npos ||
          path.find("console") != std::string::npos)
        sev = "critical";
      findings.push_back({"Debug Endpoint Exposed: " + name, sev, base + path, name + " accessible without authentication", "", "",
                          std::to_string(resp.body.size()) + " bytes"});
    }
  }
  return findings;
}

/// Default credentials on known services.
std::vector<Finding> scan_default_creds(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct DefaultCred {
    std::string path;
    std::string body;
    std::string content_type;
    std::string name;
  };

  std::vector<DefaultCred> creds = {
      {"/api/login", R"({"username":"admin","password":"admin"})", "application/json", "admin:admin"},
      {"/api/login", R"({"username":"admin","password":"password"})", "application/json", "admin:password"},
      {"/api/login", R"({"username":"root","password":"root"})", "application/json", "root:root"},
      {"/wp-login.php", "log=admin&pwd=admin&wp-submit=Log+In", "application/x-www-form-urlencoded", "WP admin:admin"},
  };

  for (const auto& cred : creds) {
    auto resp = http.post(base + cred.path, cred.body, cred.content_type);
    if (resp.status_code == 200 &&
        (resp.body.find("token") != std::string::npos || resp.body.find("session") != std::string::npos ||
         resp.body.find("success") != std::string::npos || resp.body.find("dashboard") != std::string::npos) &&
        resp.body.find("invalid") == std::string::npos && resp.body.find("error") == std::string::npos) {
      findings.push_back({"Default Credentials", "critical", base + cred.path, "Login succeeded with " + cred.name, "", cred.name,
                          "Authentication successful with default creds"});
      break;
    }
  }
  return findings;
}

/// Backup and source code files exposed.
std::vector<Finding> scan_backup_files(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::pair<std::string, std::string>> backup_paths = {
      {"/backup.zip", "zip"},         {"/backup.tar.gz", "gzip"},     {"/db.sql", "SQL"},
      {"/dump.sql", "SQL"},           {"/database.sql", "SQL"},       {"/.env", "dotenv"},
      {"/.env.production", "dotenv"}, {"/.env.local", "dotenv"},      {"/config.yml", "yaml"},
      {"/config.json", "json"},       {"/wp-config.php.bak", "PHP"},  {"/web.config.bak", "ASP.NET"},
      {"/.htpasswd", "htpasswd"},     {"/.DS_Store", "macOS"},        {"/.git/config", "git"},
      {"/composer.json", "PHP deps"}, {"/package.json", "Node deps"},
  };

  for (const auto& [path, type] : backup_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 20) {
      // Verify it's not a soft 404
      if (resp.body.find("<html") != std::string::npos && resp.body.find("not found") != std::string::npos) continue;

      std::string sev = "high";
      if (path.find(".sql") != std::string::npos || path.find(".env") != std::string::npos || path.find("htpasswd") != std::string::npos)
        sev = "critical";

      findings.push_back({"Backup/Source Exposed: " + path, sev, base + path, type + " file publicly accessible", "", "",
                          std::to_string(resp.body.size()) + " bytes"});
    }
  }
  return findings;
}

/// Directory listing enabled.
std::vector<Finding> scan_directory_listing(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> dirs = {"/images/", "/uploads/", "/static/", "/assets/", "/files/", "/media/", "/tmp/", "/backup/"};

  for (const auto& dir : dirs) {
    auto resp = http.get(base + dir);
    if (resp.status_code == 200 &&
        (resp.body.find("Index of") != std::string::npos || resp.body.find("Directory listing") != std::string::npos ||
         resp.body.find("<pre>") != std::string::npos)) {
      findings.push_back({"Directory Listing", "low", base + dir, "Directory contents exposed to public", "", "", ""});
    }
  }
  return findings;
}

/// Cookie security issues.
std::vector<Finding> scan_cookie_security(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);
  for (const auto& [header, value] : resp.headers) {
    if (header != "Set-Cookie") continue;

    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    bool is_session =
        lower.find("session") != std::string::npos || lower.find("token") != std::string::npos || lower.find("auth") != std::string::npos;
    if (!is_session) continue;

    if (lower.find("httponly") == std::string::npos) {
      findings.push_back(
          {"Cookie Missing HttpOnly", "medium", crawl.urls[0], "Session cookie accessible via JavaScript", "", "", value.substr(0, 60)});
    }
    if (lower.find("secure") == std::string::npos) {
      findings.push_back(
          {"Cookie Missing Secure Flag", "medium", crawl.urls[0], "Session cookie sent over HTTP", "", "", value.substr(0, 60)});
    }
    if (lower.find("samesite") == std::string::npos) {
      findings.push_back(
          {"Cookie Missing SameSite", "low", crawl.urls[0], "Session cookie vulnerable to CSRF", "", "", value.substr(0, 60)});
    }
  }
  return findings;
}

/// Path traversal via common file include params.
std::vector<Finding> scan_path_traversal(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> traversal_params = {"file", "path", "page", "include", "template", "doc", "folder", "lang"};
  const std::string payload = "....//....//....//etc/passwd";
  const std::string win_payload = "....\\\\....\\\\....\\\\windows\\\\win.ini";

  for (const auto& url : crawl.urls) {
    for (const auto& param : traversal_params) {
      std::string sep = url.find('?') != std::string::npos ? "&" : "?";
      auto resp = http.get(url + sep + param + "=" + payload);
      if (resp.status_code == 200 &&
          (resp.body.find("root:") != std::string::npos || resp.body.find("[extensions]") != std::string::npos)) {
        findings.push_back(
            {"Path Traversal", "critical", url, "Local file read via " + param + " parameter", param, payload, resp.body.substr(0, 100)});
        return findings;
      }
    }
  }
  return findings;
}

/// Server version disclosure.
std::vector<Finding> scan_server_disclosure(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);
  auto server = resp.headers.find("Server");
  if (server != resp.headers.end() && server->second.size() > 3) {
    // Check if version number is included
    std::regex ver_re(R"(\d+\.\d+)");
    if (std::regex_search(server->second, ver_re)) {
      findings.push_back({"Server Version Disclosure", "low", crawl.urls[0], "Server header exposes version: " + server->second, "", "",
                          "Server: " + server->second});
    }
  }
  auto powered = resp.headers.find("X-Powered-By");
  if (powered != resp.headers.end()) {
    findings.push_back({"Technology Disclosure", "low", crawl.urls[0], "X-Powered-By header exposes: " + powered->second, "", "",
                        "X-Powered-By: " + powered->second});
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_infra_misconfig_scanners() {
  return {
      {"DNS Zone Transfer", scan_zone_transfer},      {"Debug Endpoints", scan_debug_endpoints},
      {"Default Credentials", scan_default_creds},    {"Backup Files", scan_backup_files},
      {"Directory Listing", scan_directory_listing},  {"Cookie Security", scan_cookie_security},
      {"Path Traversal (Deep)", scan_path_traversal}, {"Server Disclosure", scan_server_disclosure},
  };
}

}  // namespace apex
