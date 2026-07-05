/// @file smart_mode.hpp
/// @brief Smart mode: crawl-first intelligence that selects relevant scanners.
#ifndef APEX_SMART_MODE_HPP
#define APEX_SMART_MODE_HPP

#include "crawler.hpp"
#include "http.hpp"
#include <set>
#include <string>
#include <vector>

namespace apex {

/// Intelligence gathered from crawl phase to select scanners.
struct CrawlIntel {
  bool has_params = false;      // URL parameters found
  bool has_forms = false;       // HTML forms found
  bool has_login = false;       // Login form detected
  bool has_upload = false;      // File upload form
  bool has_graphql = false;     // GraphQL endpoint
  bool has_api = false;         // REST API (JSON responses)
  bool has_xml = false;         // XML endpoints
  bool has_redirect = false;    // Redirect parameters
  bool has_ids = false;         // Numeric IDs in URLs
  bool has_cms = false;         // CMS detected (wp-content, etc.)
  bool has_cookies = false;     // Set-Cookie headers
  bool has_cors = false;        // CORS headers present
  bool has_ssti_params = false; // Template-like params (name, msg, template)
  std::set<std::string> techs;  // Detected technologies
};

/// Analyze crawl results to build intelligence.
inline CrawlIntel analyze_crawl(const CrawlResult &crawl, HttpClient &http) {
  CrawlIntel intel;
  intel.has_params = !crawl.params.empty();
  intel.has_forms = !crawl.forms.empty();

  for (const auto &form : crawl.forms) {
    for (const auto &f : form.fields) {
      if (f.name.find("pass") != std::string::npos ||
          f.name.find("login") != std::string::npos ||
          f.name.find("user") != std::string::npos)
        intel.has_login = true;
      if (f.type == "file")
        intel.has_upload = true;
    }
  }

  for (const auto &p : crawl.params) {
    if (p.name == "url" || p.name == "next" || p.name == "redirect" ||
        p.name == "return" || p.name == "goto" || p.name == "fetch" ||
        p.name == "path" || p.name == "src" || p.name == "dest")
      intel.has_redirect = true;
    if (p.name == "name" || p.name == "template" || p.name == "msg" ||
        p.name == "text" || p.name == "input")
      intel.has_ssti_params = true;
  }

  for (const auto &url : crawl.urls) {
    if (url.find("graphql") != std::string::npos)
      intel.has_graphql = true;
    if (url.find("/api/") != std::string::npos)
      intel.has_api = true;
    if (url.find("id=") != std::string::npos)
      intel.has_ids = true;
    if (url.find("wp-content") != std::string::npos ||
        url.find("wp-admin") != std::string::npos)
      intel.has_cms = true;
  }

  // Sample first page for tech detection
  if (!crawl.urls.empty()) {
    auto resp = http.get(crawl.urls[0]);
    if (resp.headers.count("Set-Cookie"))
      intel.has_cookies = true;
    if (resp.headers.count("Access-Control-Allow-Origin"))
      intel.has_cors = true;
    if (resp.body.find("wp-content") != std::string::npos)
      intel.has_cms = true;
    if (resp.headers.count("Content-Type")) {
      auto ct = resp.headers.at("Content-Type");
      if (ct.find("json") != std::string::npos)
        intel.has_api = true;
      if (ct.find("xml") != std::string::npos)
        intel.has_xml = true;
    }
  }

  return intel;
}

/// Get scanner names that are relevant based on crawl intelligence.
inline std::set<std::string> smart_select_scanners(const CrawlIntel &intel) {
  std::set<std::string> selected;

  // Always run these (fast, high-value)
  selected.insert("Security Headers");
  selected.insert("Clickjacking");
  selected.insert("Cookie Security");
  selected.insert("Info Disclosure");
  selected.insert("Content Discovery");
  selected.insert("Server Banner Disclosure");
  selected.insert("CMS Detection");

  // Conditional scanners based on intelligence
  if (intel.has_params) {
    selected.insert("SQLi");
    selected.insert("XSS");
    selected.insert("LFI");
    selected.insert("SSTI");
    selected.insert("SSTI Deep");
    selected.insert("NoSQL Injection");
    selected.insert("CRLF");
    selected.insert("CMDi");
  }

  if (intel.has_ssti_params) {
    selected.insert("SSTI");
    selected.insert("SSTI Deep");
  }

  if (intel.has_forms) {
    selected.insert("CSRF");
    selected.insert("XSS");
    selected.insert("SQLi");
  }

  if (intel.has_login) {
    selected.insert("Login Security");
    selected.insert("JWT None Alg");
    selected.insert("Timing Oracle");
  }

  if (intel.has_upload) {
    selected.insert("XXE");
    selected.insert("File Upload");
  }

  if (intel.has_graphql) {
    selected.insert("GraphQL Introspection");
    selected.insert("GraphQL Depth");
  }

  if (intel.has_api) {
    selected.insert("IDOR");
    selected.insert("API Enumeration");
    selected.insert("Secrets Exposure");
    selected.insert("NoSQL Injection");
  }

  if (intel.has_xml) {
    selected.insert("XXE");
  }

  if (intel.has_redirect) {
    selected.insert("Open Redirect");
    selected.insert("SSRF");
  }

  if (intel.has_ids) {
    selected.insert("IDOR");
    selected.insert("SQLi");
  }

  if (intel.has_cms) {
    selected.insert("CMS Detection");
    selected.insert("WP Plugin");
    selected.insert("WP Theme");
    selected.insert("Forced Browsing");
  }

  if (intel.has_cors) {
    selected.insert("CORS");
    selected.insert("CORS Deep");
  }

  if (intel.has_cookies) {
    selected.insert("Cookie Security");
    selected.insert("CSRF");
  }

  // Always include SSRF and cloud metadata (fast, high-impact)
  selected.insert("SSRF");
  selected.insert("Cloud Metadata");
  selected.insert("CORS Deep");
  selected.insert("Secrets Exposure");

  return selected;
}

} // namespace apex

#endif // APEX_SMART_MODE_HPP
