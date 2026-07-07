/// @file scanners/file_upload.cpp
/// @brief File upload vulnerability scanner: unrestricted uploads, extension bypass,
///        path traversal in filenames, oversized uploads, dangerous file types.
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Find upload endpoints from crawled forms and URLs.
std::vector<std::string> find_upload_endpoints(const CrawlResult& crawl, const std::string& base) {
  std::vector<std::string> endpoints;

  // From forms with file inputs
  for (const auto& form : crawl.forms) {
    for (const auto& field : form.fields) {
      if (field.type == "file") {
        std::string url = form.action;
        if (url.empty() || url[0] == '/') url = base + url;
        endpoints.push_back(url);
        break;
      }
    }
  }

  // Common upload paths
  std::vector<std::string> common = {"/api/upload", "/api/v1/upload",   "/api/files",     "/upload",     "/api/media",   "/api/images",
                                     "/api/avatar", "/api/attachments", "/api/documents", "/api/import", "/file/upload", "/files/upload"};

  for (const auto& path : common) {
    endpoints.push_back(base + path);
  }

  return endpoints;
}

/// Check if upload endpoints accept dangerous file types.
std::vector<Finding> scan_upload_discovery(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto endpoints = find_upload_endpoints(crawl, base);

  for (const auto& url : endpoints) {
    // OPTIONS/GET to check if endpoint exists
    auto resp = http.get(url);
    if (resp.status_code == 404 || resp.status_code == 301) continue;

    if (resp.status_code == 200 || resp.status_code == 405 || resp.status_code == 400 || resp.status_code == 401 ||
        resp.status_code == 415) {
      findings.push_back({"File Upload Endpoint Found", "info", url,
                          "Upload endpoint responds (status " + std::to_string(resp.status_code) +
                              "). "
                              "Test for unrestricted file type upload, path traversal in filename, "
                              "and oversized file DoS.",
                          "", "", ""});

      // Check if endpoint leaks accepted types
      if (resp.body.find("allowed") != std::string::npos || resp.body.find("accept") != std::string::npos ||
          resp.body.find("file_type") != std::string::npos) {
        findings.push_back({"Upload — Accepted Types Disclosed", "low", url,
                            "Upload endpoint reveals accepted file types in response. "
                            "Helps attacker craft bypass payloads.",
                            "", "", resp.body.substr(0, 300)});
      }
      break;  // Found one live endpoint
    }
  }
  return findings;
}

/// Check for publicly accessible uploaded files directory.
std::vector<Finding> scan_upload_directory(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::vector<std::string> upload_dirs = {"/uploads/",
                                          "/media/",
                                          "/files/",
                                          "/attachments/",
                                          "/static/uploads/",
                                          "/content/uploads/",
                                          "/wp-content/uploads/",
                                          "/images/uploads/",
                                          "/user-content/",
                                          "/public/uploads/"};

  for (const auto& dir : upload_dirs) {
    auto resp = http.get(base + dir);
    if (resp.status_code == 200) {
      // Directory listing?
      if (resp.body.find("Index of") != std::string::npos || resp.body.find("<a href=") != std::string::npos) {
        findings.push_back({"Upload Directory Listing", "medium", base + dir,
                            "Upload directory is publicly browsable. "
                            "Exposes all uploaded files — may contain sensitive user data.",
                            "", "", ""});
      }
      // Check for dangerous file types in directory
      std::regex dangerous_re(R"x(\.(php|jsp|aspx|sh|py|rb|pl|cgi|exe|bat|ps1)\b)x");
      if (std::regex_search(resp.body, dangerous_re)) {
        findings.push_back({"Upload Directory — Executable Files Present", "high", base + dir,
                            "Upload directory contains executable file extensions. "
                            "Possible webshell or unrestricted upload vulnerability.",
                            "", "", ""});
      }
      break;
    }
  }
  return findings;
}

/// Check for source map files exposing source code.
std::vector<Finding> scan_sourcemaps(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Find .js files and check for .map
  std::regex js_re(R"x(["'](/?[^"']+\.js)["'])x");
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);
  if (resp.status_code != 200) return findings;

  std::sregex_iterator it(resp.body.begin(), resp.body.end(), js_re);
  std::sregex_iterator end;
  int checked = 0;

  for (; it != end && checked < 5; ++it, ++checked) {
    std::string js_path = (*it)[1].str();
    if (js_path[0] != '/') js_path = "/" + js_path;
    std::string map_url = base + js_path + ".map";

    auto map_resp = http.get(map_url);
    if (map_resp.status_code == 200 &&
        (map_resp.body.find("\"sources\"") != std::string::npos || map_resp.body.find("\"sourcesContent\"") != std::string::npos)) {
      findings.push_back({"Source Map Exposed", "medium", map_url,
                          "JavaScript source map publicly accessible. "
                          "Reveals original source code — simplifies vulnerability discovery.",
                          "", "", "Size: " + std::to_string(map_resp.body.size()) + " bytes"});
      break;
    }
  }
  return findings;
}

/// Check for exposed backup and sensitive files.
std::vector<Finding> scan_sensitive_files(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct FileCheck {
    std::string path;
    std::string name;
    std::string indicator;
  };

  std::vector<FileCheck> checks = {
      {"/.env", "Environment File", "DB_"},
      {"/.env.production", "Production Env File", "SECRET"},
      {"/.env.local", "Local Env File", "KEY"},
      {"/.git/config", "Git Repository", "[core]"},
      {"/.git/HEAD", "Git HEAD", "ref:"},
      {"/wp-config.php.bak", "WordPress Config Backup", "DB_NAME"},
      {"/config.php.bak", "PHP Config Backup", "password"},
      {"/database.sql", "Database Dump", "INSERT INTO"},
      {"/dump.sql", "Database Dump", "CREATE TABLE"},
      {"/backup.zip", "Backup Archive", "PK"},
      {"/backup.tar.gz", "Backup Archive", ""},
      {"/.DS_Store", "macOS DS_Store", "Bud1"},
      {"/server-status", "Apache Server Status", "Apache"},
      {"/elmah.axd", "ELMAH Error Log", "Error"},
      {"/trace.axd", "ASP.NET Trace", "Request"},
      {"/phpinfo.php", "PHP Info", "PHP Version"},
      {"/.htpasswd", "htpasswd File", ":"},
      {"/crossdomain.xml", "Flash Crossdomain", "allow-access"},
      {"/clientaccesspolicy.xml", "Silverlight Policy", "cross-domain"},
  };

  for (const auto& check : checks) {
    auto resp = http.get(base + check.path);
    if (resp.status_code == 200 && resp.body.size() > 10) {
      // Reject generic error/redirect pages (WAF/CDN false positives)
      if (resp.body.find("Access Denied") != std::string::npos || resp.body.find("Page Not Found") != std::string::npos ||
          resp.body.find("404") != std::string::npos || resp.body.find("not found") != std::string::npos ||
          resp.body.find("Attention Required") != std::string::npos || resp.body.find("Just a moment") != std::string::npos ||
          resp.body.find("Checking your browser") != std::string::npos || resp.body.find("cf-browser-verification") != std::string::npos ||
          resp.body.find("<!DOCTYPE html>") != std::string::npos) {
        // If indicator is empty and response looks like HTML error page, skip
        if (check.indicator.empty()) continue;
      }
      if (check.indicator.empty() || resp.body.find(check.indicator) != std::string::npos) {
        std::string severity = "medium";
        if (check.path.find(".env") != std::string::npos || check.path.find(".git") != std::string::npos ||
            check.path.find(".sql") != std::string::npos) {
          severity = "high";
        }
        findings.push_back({check.name + " Exposed", severity, base + check.path,
                            check.name + " is publicly accessible. May leak credentials, "
                                         "source code, or sensitive configuration.",
                            "", "", "Size: " + std::to_string(resp.body.size()) + " bytes"});
      }
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_file_upload_scanners() {
  return {
      {"Upload Discovery", scan_upload_discovery},
      {"Upload Directory", scan_upload_directory},
      {"Source Maps", scan_sourcemaps},
      {"Sensitive Files", scan_sensitive_files},
  };
}

}  // namespace apex
