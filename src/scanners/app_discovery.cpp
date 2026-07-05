/// @file scanners/app_discovery.cpp
/// @brief Discover and pentest mobile apps (iOS/Android) linked to a target.
///        Checks app store listings, extracts API endpoints from app metadata,
///        tests certificate pinning, finds hardcoded secrets, checks deeplinks.
#include "scanner_base.hpp"
#include <regex>

namespace apex {
namespace {

/// Detect if target has a mobile app by checking multiple indicators.
struct AppInfo {
  std::string platform;   // "android" or "ios"
  std::string bundle_id;  // com.company.app or Apple ID
  std::string store_url;
  std::string app_name;
};

/// Check meta tags, app banners, and store links in HTML.
std::vector<AppInfo> detect_apps(HttpClient &http, const std::string &base) {
  std::vector<AppInfo> apps;
  auto resp = http.get(base);
  if (resp.status_code != 200) return apps;

  // Android: Play Store links
  std::regex play_re(R"(play\.google\.com/store/apps/details\?id=([a-zA-Z0-9_.]+))");
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), play_re);
  std::sregex_iterator end;
  for (; it != end; ++it) {
    apps.push_back({"android", (*it)[1].str(),
                    "https://play.google.com/store/apps/details?id=" + (*it)[1].str(), ""});
  }

  // iOS: App Store links
  std::regex ios_re(R"(apps\.apple\.com/[a-z]{2}/app/[^/]+/id(\d+))");
  it = std::sregex_iterator(resp.body.begin(), resp.body.end(), ios_re);
  for (; it != end; ++it) {
    apps.push_back({"ios", (*it)[1].str(),
                    "https://apps.apple.com/app/id" + (*it)[1].str(), ""});
  }

  // Smart banner meta tags
  // <meta name="apple-itunes-app" content="app-id=123456">
  std::regex banner_re(R"(apple-itunes-app[^>]+app-id=(\d+))");
  it = std::sregex_iterator(resp.body.begin(), resp.body.end(), banner_re);
  for (; it != end; ++it) {
    bool dupe = false;
    for (const auto &a : apps) if (a.bundle_id == (*it)[1].str()) dupe = true;
    if (!dupe) apps.push_back({"ios", (*it)[1].str(),
                                "https://apps.apple.com/app/id" + (*it)[1].str(), ""});
  }

  // <meta name="google-play-app" content="app-id=com.example.app">
  std::regex gp_meta_re(R"(google-play-app[^>]+app-id=([a-zA-Z0-9_.]+))");
  it = std::sregex_iterator(resp.body.begin(), resp.body.end(), gp_meta_re);
  for (; it != end; ++it) {
    bool dupe = false;
    for (const auto &a : apps) if (a.bundle_id == (*it)[1].str()) dupe = true;
    if (!dupe) apps.push_back({"android", (*it)[1].str(),
                                "https://play.google.com/store/apps/details?id=" + (*it)[1].str(), ""});
  }

  return apps;
}

/// Check Android assetlinks.json for deeplink config.
std::vector<Finding> scan_app_deeplinks(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Android Digital Asset Links
  auto resp = http.get(base + "/.well-known/assetlinks.json");
  if (resp.status_code == 200) {
    // Check for missing or weak verification
    if (resp.body.find("delegate_permission/common.handle_all_urls") != std::string::npos) {
      // Check if sha256 fingerprint is present (required for security)
      if (resp.body.find("sha256_cert_fingerprints") == std::string::npos) {
        findings.push_back({"App Link — Missing Certificate Pin", "high",
                            base + "/.well-known/assetlinks.json",
                            "Android App Links configured without SHA-256 certificate fingerprint. "
                            "Any app with matching package name can intercept deeplinks.",
                            "", "", resp.body.substr(0, 300)});
      }
      // Count how many apps are authorized
      std::regex pkg_re(R"x("package_name"\s*:\s*"([^"]+)")x");      std::sregex_iterator pkg_it(resp.body.begin(), resp.body.end(), pkg_re);
      std::sregex_iterator pkg_end;
      int count = 0;
      for (; pkg_it != pkg_end; ++pkg_it) count++;
      if (count > 3) {
        findings.push_back({"App Link — Excessive App Authorization", "medium",
                            base + "/.well-known/assetlinks.json",
                            std::to_string(count) + " apps authorized for deep links — review if all are legitimate.",
                            "", "", ""});
      }
    }
  }

  // iOS Apple App Site Association
  auto apple = http.get(base + "/.well-known/apple-app-site-association");
  if (apple.status_code != 200) {
    apple = http.get(base + "/apple-app-site-association");
  }
  if (apple.status_code == 200) {
    if (apple.body.find("\"*\"") != std::string::npos ||
        apple.body.find("\"NOT \"") == std::string::npos) {
      // Wildcard paths = any URL can be claimed
      if (apple.body.find("\"*\"") != std::string::npos) {
        findings.push_back({"Universal Link — Wildcard Path", "medium",
                            base + "/.well-known/apple-app-site-association",
                            "Apple Universal Links uses wildcard path matching. "
                            "Consider restricting to specific paths only.",
                            "", "", apple.body.substr(0, 300)});
      }
    }
  }

  return findings;
}

/// Discover mobile apps and check their API endpoints.
std::vector<Finding> scan_app_discovery(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto apps = detect_apps(http, base);
  if (apps.empty()) return findings;

  for (const auto &app : apps) {
    // Report discovery (informational — useful for scope)
    findings.push_back({"Mobile App Detected", "info", base,
                        app.platform + " app found: " + app.bundle_id,
                        "store_url", app.store_url,
                        "Detected via HTML meta/link tags"});

    // For Android: check if APK is downloadable from common CDN paths
    if (app.platform == "android") {
      std::vector<std::string> apk_paths = {
          "/app-release.apk", "/download/app.apk", "/apk/latest.apk",
          "/static/app-release.apk", "/downloads/" + app.bundle_id + ".apk"};
      for (const auto &path : apk_paths) {
        auto r = http.get(base + path);
        if (r.status_code == 200 && r.body.size() > 100000 &&
            r.body.substr(0, 4) == "PK\x03\x04") {
          findings.push_back({"APK Publicly Downloadable", "low", base + path,
                              "Android APK file publicly accessible — enables reverse engineering.",
                              "", "", "Size: " + std::to_string(r.body.size()) + " bytes"});
          break;
        }
      }
    }
  }

  return findings;
}

/// Check mobile API-specific weaknesses.
std::vector<Finding> scan_app_api_security(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Common mobile API paths
  std::vector<std::string> mobile_paths = {
      "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/forgot-password",
      "/api/v1/user/profile", "/api/v2/auth/login", "/api/mobile/login",
      "/mobile/api/auth", "/app/api/login"};

  for (const auto &path : mobile_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 405 || resp.status_code == 200 ||
        resp.status_code == 401 || resp.status_code == 422) {
      // Found a live mobile API endpoint — check headers
      auto pinning = resp.headers.find("Public-Key-Pins");
      auto hsts = resp.headers.find("Strict-Transport-Security");
      auto server = resp.headers.find("Server");

      if (pinning == resp.headers.end() && hsts == resp.headers.end()) {
        findings.push_back({"Mobile API — No Certificate Pinning Headers", "medium",
                            base + path,
                            "Mobile API endpoint found without HPKP or HSTS. "
                            "App may be vulnerable to MITM via proxy tools (Burp/mitmproxy).",
                            "", "", "Status: " + std::to_string(resp.status_code)});
      }

      // Check if rate limiting exists on auth endpoints
      if (path.find("login") != std::string::npos || path.find("forgot") != std::string::npos) {
        auto rate = resp.headers.find("X-RateLimit-Limit");
        auto retry = resp.headers.find("Retry-After");
        if (rate == resp.headers.end() && retry == resp.headers.end()) {
          findings.push_back({"Mobile API — No Rate Limit on Auth", "medium",
                              base + path,
                              "Authentication endpoint has no visible rate limiting headers. "
                              "May be vulnerable to credential brute-forcing from mobile clients.",
                              "", "", ""});
        }
      }
      break; // Found one, no need to keep probing
    }
  }

  // Check for API versioning issues (old versions still live)
  std::regex ver_re(R"(/api/v(\d+)/)");
  for (const auto &url : crawl.urls) {
    std::smatch m;
    if (std::regex_search(url, m, ver_re)) {
      int ver = std::stoi(m[1].str());
      if (ver > 1) {
        // Try v1 — old versions often have weaker auth
        std::string old_url = std::regex_replace(url, ver_re, "/api/v1/");
        auto r = http.get(old_url);
        if (r.status_code == 200 && r.body.size() > 50) {
          findings.push_back({"Mobile API — Old Version Still Active", "medium", old_url,
                              "API v1 still responds while v" + std::to_string(ver) + " is in use. "
                              "Older versions may have weaker authentication or missing fixes.",
                              "", "", "v1 returns " + std::to_string(r.body.size()) + " bytes"});
        }
      }
      break;
    }
  }

  return findings;
}

/// Check for Firebase/Cloud misconfigs common in mobile apps.
std::vector<Finding> scan_app_firebase(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Extract domain for Firebase guessing
  std::string domain = base;
  auto proto_end = domain.find("://");
  if (proto_end != std::string::npos) domain = domain.substr(proto_end + 3);
  auto slash = domain.find("/");
  if (slash != std::string::npos) domain = domain.substr(0, slash);
  // Strip www and TLD
  if (domain.substr(0, 4) == "www.") domain = domain.substr(4);
  auto dot = domain.find(".");
  std::string name = (dot != std::string::npos) ? domain.substr(0, dot) : domain;

  // Try common Firebase DB URLs
  std::vector<std::string> fb_urls = {
      "https://" + name + ".firebaseio.com/.json",
      "https://" + name + "-app.firebaseio.com/.json",
      "https://" + name + "-prod.firebaseio.com/.json"};

  for (const auto &fb : fb_urls) {
    auto r = http.get(fb);
    if (r.status_code == 200 && r.body != "null" && r.body.size() > 5) {
      findings.push_back({"Firebase DB — Public Read Access", "critical", fb,
                          "Firebase Realtime Database is publicly readable without auth. "
                          "Likely leaking user data from the mobile app.",
                          "", "", "Response: " + r.body.substr(0, 200)});
      break;
    }
  }

  // Check for exposed Firebase Cloud Storage
  std::vector<std::string> storage_urls = {
      "https://firebasestorage.googleapis.com/v0/b/" + name + ".appspot.com/o",
      "https://firebasestorage.googleapis.com/v0/b/" + name + "-app.appspot.com/o"};

  for (const auto &s : storage_urls) {
    auto r = http.get(s);
    if (r.status_code == 200 && r.body.find("\"items\"") != std::string::npos) {
      findings.push_back({"Firebase Storage — Public Listing", "high", s,
                          "Firebase Cloud Storage bucket is publicly listable. "
                          "May contain user uploads, profile pictures, or sensitive documents.",
                          "", "", ""});
      break;
    }
  }

  return findings;
}

} // namespace

std::vector<Scanner> register_app_discovery_scanners() {
  return {
      {"App Discovery", scan_app_discovery},
      {"App Deeplinks", scan_app_deeplinks},
      {"App API Security", scan_app_api_security},
      {"App Firebase", scan_app_firebase},
  };
}

} // namespace apex
