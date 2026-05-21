/// @file scanners/version_fingerprint.cpp
/// @brief Passive version fingerprinting: infers exact software versions from
///        default files, ETags, error pages, changelog hashes, response
///        behavior, and feature detection — without relying on banners.
#include "scanner_base.hpp"
#include <map>
#include <set>

namespace apex {
namespace {

struct VersionHint {
  const char *path;
  const char *match;
  const char *product;
  const char *version;
};

// Known file hashes/content that pin exact versions.
const VersionHint hints[] = {
    // === Apache (default pages, icons, CHANGELOG) ===
    {"/icons/apache_pb2.gif", "", "Apache", "2.4.x"},
    {"/server-status", "Apache/2.4.49", "Apache", "2.4.49"},
    {"/server-status", "Apache/2.4.50", "Apache", "2.4.50"},
    {"/server-status", "Apache/2.4.51", "Apache", "2.4.51"},
    {"/server-status", "Apache/2.4.57", "Apache", "2.4.57"},
    {"/server-status", "Apache/2.4.58", "Apache", "2.4.58"},
    {"/server-status", "Apache/2.4.59", "Apache", "2.4.59"},
    // === Nginx (default error pages change per version) ===
    {"/nonexistent_apex_test", "nginx/1.24", "nginx", "1.24.x"},
    {"/nonexistent_apex_test", "nginx/1.25", "nginx", "1.25.x"},
    {"/nonexistent_apex_test", "nginx/1.26", "nginx", "1.26.x"},
    {"/nonexistent_apex_test", "nginx/1.27", "nginx", "1.27.x"},
    // === PHP (exposed info endpoints) ===
    {"/phpinfo.php", "PHP Version 8.0", "PHP", "8.0.x"},
    {"/phpinfo.php", "PHP Version 8.1", "PHP", "8.1.x"},
    {"/phpinfo.php", "PHP Version 8.2", "PHP", "8.2.x"},
    {"/phpinfo.php", "PHP Version 8.3", "PHP", "8.3.x"},
    {"/phpinfo.php", "PHP Version 8.4", "PHP", "8.4.x"},
    // === WordPress (readme, version files) ===
    {"/readme.html", "Version 6.4", "WordPress", "6.4.x"},
    {"/readme.html", "Version 6.5", "WordPress", "6.5.x"},
    {"/readme.html", "Version 6.6", "WordPress", "6.6.x"},
    {"/wp-includes/js/jquery/jquery.min.js", "jQuery v3.7.1", "WordPress", "6.4+"},
    {"/wp-includes/js/jquery/jquery.min.js", "jQuery v3.6.0", "WordPress", "5.9-6.0"},
    // === Next.js (/_next/ build manifest) ===
    {"/_next/static/chunks/main.js", "next/dist", "Next.js", "detected"},
    {"/_next/data/", "", "Next.js", "detected"},
    // === Drupal ===
    {"/core/misc/drupal.js", "Drupal.throwError", "Drupal", "10.x"},
    {"/core/misc/drupal.js", "Drupal.behaviors", "Drupal", "8.x/9.x"},
    {"/CHANGELOG.txt", "Drupal 10.2", "Drupal", "10.2.x"},
    {"/CHANGELOG.txt", "Drupal 10.1", "Drupal", "10.1.x"},
    {"/CHANGELOG.txt", "Drupal 9.5", "Drupal", "9.5.x"},
    // === Joomla ===
    {"/administrator/manifests/files/joomla.xml", "<version>5.1", "Joomla", "5.1.x"},
    {"/administrator/manifests/files/joomla.xml", "<version>5.0", "Joomla", "5.0.x"},
    {"/administrator/manifests/files/joomla.xml", "<version>4.4", "Joomla", "4.4.x"},
    // === jQuery (very common, pins frontend era) ===
    {"/jquery.min.js", "jQuery v3.7", "jQuery", "3.7.x"},
    {"/jquery.min.js", "jQuery v3.6", "jQuery", "3.6.x"},
    {"/jquery.min.js", "jQuery v3.5", "jQuery", "3.5.x"},
    {"/jquery.min.js", "jQuery v2.", "jQuery", "2.x (EOL)"},
    {"/jquery.min.js", "jQuery v1.", "jQuery", "1.x (EOL)"},
};

/// Fingerprint via known file content.
std::vector<Finding> scan_file_fingerprint(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  std::set<std::string> found;

  for (const auto &h : hints) {
    auto resp = http.get(base + h.path);
    if (resp.status_code != 200) continue;
    if (h.match[0] == '\0' || resp.body.find(h.match) != std::string::npos) {
      std::string key = std::string(h.product) + h.version;
      if (found.count(key)) continue;
      found.insert(key);
      findings.push_back({"Version Fingerprint", "info", base + h.path,
                          std::string(h.product) + " " + h.version +
                              " (detected via file content)",
                          "", "", ""});
    }
  }
  return findings;
}

/// ETag-based version fingerprinting.
/// Many servers use inode-size-timestamp ETags that reveal OS/version info.
std::vector<Finding> scan_etag_fingerprint(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/");
  auto etag_it = resp.headers.find("ETag");
  if (etag_it == resp.headers.end()) return findings;
  std::string etag = etag_it->second;

  // Apache-style ETag: "inode-size-mtime" (hex values).
  std::regex apache_etag(R"re("([0-9a-f]+)-([0-9a-f]+)-([0-9a-f]+)")re");  if (std::regex_match(etag, apache_etag)) {
    findings.push_back({"ETag Fingerprint (Apache)", "low", base,
                        "Apache inode-based ETag: " + etag +
                            " — reveals file metadata, aids cache poisoning",
                        "", "", ""});
  }

  // Nginx weak ETag: W/"timestamp-size".
  if (etag.find("W/\"") == 0) {
    findings.push_back({"ETag Fingerprint (Weak)", "info", base,
                        "Weak ETag detected: " + etag, "", "", ""});
  }

  return findings;
}

/// Error page fingerprinting — default error pages reveal exact versions.
std::vector<Finding> scan_error_fingerprint(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/apex_nonexistent_" +
                       std::to_string(time(nullptr)));

  // Extract version from error page.
  struct ErrorSig {
    const char *pattern;
    const char *product;
  };
  const ErrorSig sigs[] = {
      {"Apache/", "Apache"},
      {"nginx/", "nginx"},
      {"Microsoft-IIS/", "IIS"},
      {"LiteSpeed", "LiteSpeed"},
      {"openresty/", "OpenResty"},
      {"Caddy", "Caddy"},
      {"Tomcat/", "Apache Tomcat"},
      {"Jetty(", "Eclipse Jetty"},
      {"GlassFish", "GlassFish"},
      {"WildFly/", "WildFly"},
      {"Kestrel", "ASP.NET Kestrel"},
  };

  for (const auto &sig : sigs) {
    size_t pos = resp.body.find(sig.pattern);
    if (pos == std::string::npos) continue;
    // Extract version number after the pattern.
    std::string after = resp.body.substr(pos, 50);
    std::regex ver_re(R"([\w/]+(\d+\.\d+[\.\d]*))");
    std::smatch m;
    if (std::regex_search(after, m, ver_re)) {
      findings.push_back({"Error Page Version", "low", base,
                          std::string(sig.product) + " " + m[1].str() +
                              " (leaked via error page)",
                          "", "", ""});
    }
    break;
  }

  // Also check headers on the error response.
  auto srv = resp.headers.find("Server");
  if (srv != resp.headers.end() && srv->second.size() > 2) {
    std::regex ver_re(R"((\d+\.\d+[\.\d]*))");
    std::smatch m;
    if (std::regex_search(srv->second, m, ver_re)) {
      findings.push_back({"Server Header Version", "low", base,
                          "Server: " + srv->second + " (from 404 response)",
                          "", "", ""});
    }
  }

  return findings;
}

/// Feature-based fingerprinting — detect versions by supported features.
std::vector<Finding> scan_feature_fingerprint(const Config &, HttpClient &http,
                                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/");

  // === Header ordering fingerprint ===
  // Different servers return headers in characteristic orders.
  std::string header_order;
  for (const auto &[name, val] : resp.headers)
    header_order += name.substr(0, 3) + ",";

  // === Framework detection via behavioral signals ===

  // Next.js (build artifacts + runtime behavior)
  if (resp.body.find("/_next/static") != std::string::npos) {
    std::string ver = "unknown";
    if (resp.body.find("_next/static/chunks/app/") != std::string::npos)
      ver = "13.4+ (App Router)";
    else if (resp.body.find("_next/static/chunks/pages/") != std::string::npos)
      ver = "12.x-13.x (Pages Router)";
    else if (resp.body.find("_next/static/") != std::string::npos)
      ver = "11+ (detected)";
    // Check for RSC payload (React Server Components = Next 13.4+)
    if (resp.body.find("__next_f") != std::string::npos)
      ver = "14+ (RSC flight data)";
    // x-nextjs-cache header
    for (const auto &[h, v] : resp.headers) {
      if (h == "x-nextjs-cache") { ver += " + edge caching"; break; }
    }
    findings.push_back({"Next.js Fingerprint", "info", base,
                        "Next.js " + ver, "", "", ""});
  }

  // React version via react-dom or __NEXT_DATA__
  std::regex react_re(R"(react[.-]dom[./](\d+\.\d+))");
  std::smatch rm;
  if (std::regex_search(resp.body, rm, react_re)) {
    findings.push_back({"React Version", "info", base,
                        "React " + rm[1].str() + ".x", "", "", ""});
  }

  // Vue.js
  if (resp.body.find("__vue__") != std::string::npos ||
      resp.body.find("Vue.js v") != std::string::npos ||
      resp.body.find("__VUE__") != std::string::npos) {
    std::string ver = "detected";
    std::regex vue_re(R"(Vue\.js v(\d+\.\d+))");
    std::smatch vm;
    if (std::regex_search(resp.body, vm, vue_re)) ver = vm[1].str() + ".x";
    else if (resp.body.find("__VUE_HMR_RUNTIME__") != std::string::npos) ver = "3.x (HMR)";
    findings.push_back({"Vue.js Fingerprint", "info", base, "Vue.js " + ver, "", "", ""});
  }

  // Angular (ng-version attribute)
  if (resp.body.find("ng-version=\"") != std::string::npos) {
    std::regex ng_re(R"(ng-version="(\d+\.\d+))");
    std::smatch nm;
    if (std::regex_search(resp.body, nm, ng_re))
      findings.push_back({"Angular Fingerprint", "info", base,
                          "Angular " + nm[1].str() + ".x", "", "", ""});
  }

  // Nuxt.js
  if (resp.body.find("__NUXT__") != std::string::npos ||
      resp.body.find("/_nuxt/") != std::string::npos) {
    std::string ver = resp.body.find("_payload.json") != std::string::npos ? "3.x" : "2.x";
    findings.push_back({"Nuxt.js Fingerprint", "info", base, "Nuxt.js " + ver, "", "", ""});
  }

  // Svelte/SvelteKit
  if (resp.body.find("__sveltekit") != std::string::npos ||
      resp.body.find("/_app/") != std::string::npos) {
    findings.push_back({"SvelteKit Fingerprint", "info", base, "SvelteKit detected", "", "", ""});
  }

  // Laravel (XSRF-TOKEN cookie + specific header patterns)
  for (const auto &[name, value] : resp.headers) {
    if (name == "Set-Cookie" && value.find("XSRF-TOKEN") != std::string::npos) {
      // Laravel XSRF tokens are base64-encoded JSON with specific length
      std::string ver = "detected";
      if (value.find("samesite=lax") != std::string::npos) ver = "7+ (SameSite default)";
      findings.push_back({"Laravel Fingerprint", "info", base, "Laravel " + ver, "", "", ""});
      break;
    }
  }

  // Django (csrfmiddlewaretoken pattern, admin URL)
  if (resp.body.find("csrfmiddlewaretoken") != std::string::npos) {
    findings.push_back({"Django Fingerprint", "info", base, "Django detected", "", "", ""});
  }

  // Express.js
  auto xpb = resp.headers.find("X-Powered-By");
  if (xpb != resp.headers.end() && xpb->second.find("Express") != std::string::npos)
    findings.push_back({"Express.js Detected", "info", base, "Express.js", "", "", ""});

  // ASP.NET
  auto aspnet = resp.headers.find("X-AspNet-Version");
  if (aspnet != resp.headers.end())
    findings.push_back({"ASP.NET Version", "low", base, "ASP.NET " + aspnet->second, "", "", ""});
  auto aspnetmvc = resp.headers.find("X-AspNetMvc-Version");
  if (aspnetmvc != resp.headers.end())
    findings.push_back({"ASP.NET MVC Version", "low", base, "MVC " + aspnetmvc->second, "", "", ""});

  // Spring Boot (Whitelabel error page, actuator)
  auto err = http.get(base + "/error");
  if (err.body.find("Whitelabel Error Page") != std::string::npos)
    findings.push_back({"Spring Boot Fingerprint", "info", base, "Spring Boot (Whitelabel error)", "", "", ""});

  // Ruby on Rails (X-Request-Id format, cookie naming)
  auto xrid = resp.headers.find("X-Request-Id");
  if (xrid != resp.headers.end() && xrid->second.size() == 36 &&
      xrid->second[8] == '-') { // UUID format typical of Rails
    if (resp.headers.find("X-Runtime") != resp.headers.end())
      findings.push_back({"Rails Fingerprint", "info", base,
                          "Ruby on Rails (X-Request-Id + X-Runtime)", "", "", ""});
  }

  // PHP behavioral detection (session cookie naming)
  for (const auto &[name, value] : resp.headers) {
    if (name == "Set-Cookie" && value.find("PHPSESSID") != std::string::npos) {
      findings.push_back({"PHP Detected", "info", base, "PHP (PHPSESSID cookie)", "", "", ""});
      break;
    }
  }

  // Cloudflare / CDN detection
  auto cf_ray = resp.headers.find("CF-RAY");
  if (cf_ray != resp.headers.end())
    findings.push_back({"Cloudflare CDN", "info", base, "Behind Cloudflare", "", "", ""});
  auto cf_cache = resp.headers.find("CF-Cache-Status");
  if (cf_cache != resp.headers.end())
    findings.push_back({"Cloudflare Cache", "info", base, "CF-Cache: " + cf_cache->second, "", "", ""});

  return findings;
}

} // namespace

std::vector<Scanner> register_version_fingerprint_scanners() {
  return {
      {"File-Based Fingerprint", scan_file_fingerprint},
      {"ETag Fingerprint", scan_etag_fingerprint},
      {"Error Page Fingerprint", scan_error_fingerprint},
      {"Feature Fingerprint", scan_feature_fingerprint},
  };
}

} // namespace apex
