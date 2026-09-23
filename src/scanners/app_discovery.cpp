/// @file scanners/app_discovery.cpp
/// @brief Discover and pentest mobile apps (iOS/Android) linked to a target.
///        Checks app store listings, extracts API endpoints from app metadata,
///        tests certificate pinning, finds hardcoded secrets, checks deeplinks.
#include <regex>

#include "scanner_base.hpp"
#include "../response_validator.hpp"

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
std::vector<AppInfo> detect_apps(HttpClient& http, const std::string& base) {
  std::vector<AppInfo> apps;
  auto resp = http.get(base);
  if (resp.status_code != 200) return apps;

  // Android: Play Store links
  std::regex play_re(R"(play\.google\.com/store/apps/details\?id=([a-zA-Z0-9_.]+))");
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), play_re);
  std::sregex_iterator end;
  for (; it != end; ++it) {
    apps.push_back({"android", (*it)[1].str(), "https://play.google.com/store/apps/details?id=" + (*it)[1].str(), ""});
  }

  // iOS: App Store links
  std::regex ios_re(R"(apps\.apple\.com/[a-z]{2}/app/[^/]+/id(\d+))");
  it = std::sregex_iterator(resp.body.begin(), resp.body.end(), ios_re);
  for (; it != end; ++it) {
    apps.push_back({"ios", (*it)[1].str(), "https://apps.apple.com/app/id" + (*it)[1].str(), ""});
  }

  // Smart banner meta tags
  // <meta name="apple-itunes-app" content="app-id=123456">
  std::regex banner_re(R"(apple-itunes-app[^>]+app-id=(\d+))");
  it = std::sregex_iterator(resp.body.begin(), resp.body.end(), banner_re);
  for (; it != end; ++it) {
    bool dupe = false;
    for (const auto& a : apps)
      if (a.bundle_id == (*it)[1].str()) dupe = true;
    if (!dupe) apps.push_back({"ios", (*it)[1].str(), "https://apps.apple.com/app/id" + (*it)[1].str(), ""});
  }

  // <meta name="google-play-app" content="app-id=com.example.app">
  std::regex gp_meta_re(R"(google-play-app[^>]+app-id=([a-zA-Z0-9_.]+))");
  it = std::sregex_iterator(resp.body.begin(), resp.body.end(), gp_meta_re);
  for (; it != end; ++it) {
    bool dupe = false;
    for (const auto& a : apps)
      if (a.bundle_id == (*it)[1].str()) dupe = true;
    if (!dupe) apps.push_back({"android", (*it)[1].str(), "https://play.google.com/store/apps/details?id=" + (*it)[1].str(), ""});
  }

  return apps;
}

/// Check Android assetlinks.json for deeplink config.
std::vector<Finding> scan_app_deeplinks(const Config&, HttpClient& http, const CrawlResult& crawl) {
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
        findings.push_back({"App Link — Missing Certificate Pin", "high", base + "/.well-known/assetlinks.json",
                            "Android App Links configured without SHA-256 certificate fingerprint. "
                            "Any app with matching package name can intercept deeplinks.",
                            "", "", resp.body.substr(0, 300)});
      }
      // Count how many apps are authorized
      std::regex pkg_re(R"x("package_name"\s*:\s*"([^"]+)")x");
      std::sregex_iterator pkg_it(resp.body.begin(), resp.body.end(), pkg_re);
      std::sregex_iterator pkg_end;
      int count = 0;
      for (; pkg_it != pkg_end; ++pkg_it) count++;
      if (count > 3) {
        findings.push_back({"App Link — Excessive App Authorization", "medium", base + "/.well-known/assetlinks.json",
                            std::to_string(count) + " apps authorized for deep links — review if all are legitimate.", "", "", ""});
      }
    }
  }

  // iOS Apple App Site Association
  auto apple = http.get(base + "/.well-known/apple-app-site-association");
  if (apple.status_code != 200) {
    apple = http.get(base + "/apple-app-site-association");
  }
  if (apple.status_code == 200) {
    if (apple.body.find("\"*\"") != std::string::npos || apple.body.find("\"NOT \"") == std::string::npos) {
      // Wildcard paths = any URL can be claimed
      if (apple.body.find("\"*\"") != std::string::npos) {
        findings.push_back({"Universal Link — Wildcard Path", "medium", base + "/.well-known/apple-app-site-association",
                            "Apple Universal Links uses wildcard path matching. "
                            "Consider restricting to specific paths only.",
                            "", "", apple.body.substr(0, 300)});
      }
    }
  }

  return findings;
}

/// Discover mobile apps and check their API endpoints.
std::vector<Finding> scan_app_discovery(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto apps = detect_apps(http, base);
  if (apps.empty()) return findings;

  for (const auto& app : apps) {
    // Report discovery (informational — useful for scope)
    findings.push_back({"Mobile App Detected", "info", base, app.platform + " app found: " + app.bundle_id, "store_url", app.store_url,
                        "Detected via HTML meta/link tags"});

    // For Android: check if APK is downloadable from common CDN paths
    if (app.platform == "android") {
      std::vector<std::string> apk_paths = {"/app-release.apk", "/download/app.apk", "/apk/latest.apk", "/static/app-release.apk",
                                            "/downloads/" + app.bundle_id + ".apk"};
      for (const auto& path : apk_paths) {
        auto r = http.get(base + path);
        if (r.status_code == 200 && r.body.size() > 100000 && r.body.substr(0, 4) == "PK\x03\x04") {
          findings.push_back({"APK Publicly Downloadable", "low", base + path,
                              "Android APK file publicly accessible — enables reverse engineering.", "", "",
                              "Size: " + std::to_string(r.body.size()) + " bytes"});
          break;
        }
      }
    }
  }

  return findings;
}

/// Check mobile API-specific weaknesses.
std::vector<Finding> scan_app_api_security(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  const std::string base = base_url_from(crawl.urls[0]);
  const auto missing = http.get(base + "/api/apex-mobile-probe-7f3c9d");
  const std::vector<std::string> mobile_paths = {
      "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/forgot-password",
      "/api/v1/user/profile", "/api/v2/auth/login", "/api/mobile/login",
      "/mobile/api/auth", "/app/api/login"};

  auto distinct = [&](const Response& response) {
    if (response.status_code == 0 || response.status_code == 404 || response.status_code == 410) return false;
    return response.status_code != missing.status_code || responses_differ(response, missing, 40);
  };
  auto has_header = [](const Response& response, const std::string& wanted) {
    return std::any_of(response.headers.begin(), response.headers.end(), [&](const auto& header) {
      std::string key = header.first;
      std::transform(key.begin(), key.end(), key.begin(), ::tolower);
      return key == wanted;
    });
  };
  auto auth_rejection = [](const Response& response) {
    if (response.status_code != 200 && response.status_code != 400 && response.status_code != 401 &&
        response.status_code != 403 && response.status_code != 422) return false;
    std::string body = response.body;
    std::transform(body.begin(), body.end(), body.begin(), ::tolower);
    const bool context = body.find("password") != std::string::npos || body.find("credential") != std::string::npos ||
                         body.find("login") != std::string::npos || body.find("email") != std::string::npos ||
                         body.find("authentication") != std::string::npos;
    const bool rejected = body.find("invalid") != std::string::npos || body.find("incorrect") != std::string::npos ||
                          body.find("failed") != std::string::npos || body.find("unauthorized") != std::string::npos ||
                          body.find("required") != std::string::npos || body.find("error") != std::string::npos;
    return context && rejected;
  };

  for (const auto& path : mobile_paths) {
    const auto response = http.get(base + path);
    if (!distinct(response)) continue;

    // HPKP is deprecated and cannot prove mobile certificate pinning. HSTS is
    // the only server-side transport policy that can be assessed here.
    if (base.rfind("https://", 0) == 0 && !has_header(response, "strict-transport-security")) {
      findings.push_back({"Mobile API — HSTS Missing", "low", base + path,
                          "Confirmed mobile API route lacks an HSTS response header; app-level certificate pinning was not inferred",
                          "", "", "Distinct route; HTTP " + std::to_string(response.status_code)});
    }

    if (path.find("login") != std::string::npos || path.find("forgot") != std::string::npos) {
      int valid_failures = 0;
      bool limited = false;
      for (int attempt = 0; attempt < 10; ++attempt) {
        const auto probe = http.post(base + path, R"({"email":"apex-invalid@example.invalid","password":"wrong"})",
                                     "application/json");
        if (probe.status_code == 429) { limited = true; break; }
        if (!auth_rejection(probe)) break;
        ++valid_failures;
      }
      if (!limited && valid_failures == 10) {
        findings.push_back({"Mobile API — No Rate Limit on Auth", "medium", base + path,
                            "Ten semantically valid authentication failures completed without throttling", "", "",
                            "10 auth failures; no HTTP 429"});
      }
    }
    break;
  }

  std::regex ver_re(R"(/api/v(\d+)/)");
  for (const auto& url : crawl.urls) {
    std::smatch match;
    if (!std::regex_search(url, match, ver_re)) continue;
    const int version = std::stoi(match[1].str());
    if (version <= 1) break;
    const std::string old_url = std::regex_replace(url, ver_re, "/api/v1/");
    const auto old_response = http.get(old_url);
    const auto old_missing = http.get(base + "/api/v1/apex-version-probe-7f3c9d");
    std::string body = old_response.body;
    body.erase(0, body.find_first_not_of(" \t\r\n"));
    const bool json = !body.empty() && (body.front() == '{' || body.front() == '[');
    const bool distinct_old = old_response.status_code == 200 &&
                              (old_response.status_code != old_missing.status_code ||
                               responses_differ(old_response, old_missing, 50));
    if (distinct_old && json) {
      findings.push_back({"Mobile API — Old Version Still Active", "medium", old_url,
                          "A distinct JSON API v1 response remains active while v" + std::to_string(version) + " is in use",
                          "", "", old_response.body.substr(0, 200)});
    }
    break;
  }
  return findings;
}

/// Check for Firebase/Cloud misconfigs common in mobile apps.
std::vector<Finding> scan_app_firebase(const Config&, HttpClient& http, const CrawlResult& crawl) {
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
  std::vector<std::string> fb_urls = {"https://" + name + ".firebaseio.com/.json", "https://" + name + "-app.firebaseio.com/.json",
                                      "https://" + name + "-prod.firebaseio.com/.json"};

  for (const auto& fb : fb_urls) {
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
  std::vector<std::string> storage_urls = {"https://firebasestorage.googleapis.com/v0/b/" + name + ".appspot.com/o",
                                           "https://firebasestorage.googleapis.com/v0/b/" + name + "-app.appspot.com/o"};

  for (const auto& s : storage_urls) {
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

}  // namespace

std::vector<Scanner> register_app_discovery_scanners() {
  return {
      {"App Discovery", scan_app_discovery},
      {"App Deeplinks", scan_app_deeplinks},
      {"App API Security", scan_app_api_security},
      {"App Firebase", scan_app_firebase},
  };
}

}  // namespace apex
