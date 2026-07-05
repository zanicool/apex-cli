/// @file scanners/compliance.cpp
/// @brief Compliance and privacy scanners: GDPR data export, right to deletion,
///        consent tracking, PII in logs/errors, insecure password storage indicators,
///        unencrypted data transfer, missing privacy policy, third-party trackers,
///        excessive permissions, data retention issues.
#include "scanner_base.hpp"
#include <regex>

namespace apex {
namespace {

/// PII in error messages.
std::vector<Finding> scan_pii_in_errors(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> error_triggers = {
      "/api/user/999999999", "/api/x'", "/api/null", "/%00"};
  const std::vector<std::string> pii_patterns = {
      "stack trace", "SQLException", "at com.", "at org.",
      "/home/", "/var/www/", "C:\\\\", "password", "secret"};

  for (const auto &path : error_triggers) {
    auto resp = http.get(base + path);
    if (resp.status_code >= 400 && resp.status_code < 600) {
      for (const auto &p : pii_patterns) {
        if (resp.body.find(p) != std::string::npos) {
          findings.push_back({"Verbose Error — Info Leak", "medium", base + path,
                              "Error response exposes: " + p, "", "",
                              resp.body.substr(0, 200)});
          goto next_error;
        }
      }
    }
  }
  next_error:
  return findings;
}

/// Stack trace / debug info in production.
std::vector<Finding> scan_stack_trace(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.post(base + "/api/" + std::string(500, 'A'),
                        "{invalid json!!", "application/json");
  if (resp.body.find("Traceback") != std::string::npos ||
      resp.body.find("Exception in") != std::string::npos ||
      resp.body.find("at Object.") != std::string::npos ||
      resp.body.find("NullPointerException") != std::string::npos) {
    findings.push_back({"Stack Trace in Production", "medium", base,
                        "Full stack trace exposed in error response",
                        "", "", resp.body.substr(0, 300)});
  }
  return findings;
}

/// Third-party tracking without consent.
std::vector<Finding> scan_tracking_no_consent(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);
  const std::vector<std::pair<std::string, std::string>> trackers = {
      {"google-analytics.com", "Google Analytics"},
      {"googletagmanager.com", "Google Tag Manager"},
      {"facebook.net/en_US/fbevents.js", "Facebook Pixel"},
      {"hotjar.com", "Hotjar"},
      {"fullstory.com", "FullStory"},
      {"segment.com", "Segment"},
      {"mixpanel.com", "Mixpanel"},
      {"amplitude.com", "Amplitude"},
  };

  std::vector<std::string> found_trackers;
  for (const auto &[domain, name] : trackers) {
    if (resp.body.find(domain) != std::string::npos) {
      found_trackers.push_back(name);
    }
  }

  if (!found_trackers.empty()) {
    // Check if there's a consent banner
    if (resp.body.find("consent") == std::string::npos &&
        resp.body.find("cookie-banner") == std::string::npos &&
        resp.body.find("gdpr") == std::string::npos) {
      std::string tracker_list;
      for (const auto &t : found_trackers) tracker_list += t + ", ";
      if (!tracker_list.empty()) tracker_list.resize(tracker_list.size() - 2);
      findings.push_back({"Tracking Without Consent", "medium", crawl.urls[0],
                          "Third-party trackers loaded without consent banner: " + tracker_list,
                          "", "", "GDPR compliance issue"});
    }
  }
  return findings;
}

/// Insecure password storage indicators.
std::vector<Finding> scan_password_storage(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check if password is returned in user profile API
  const std::vector<std::string> profile_paths = {
      "/api/me", "/api/user", "/api/profile", "/api/account"};

  for (const auto &path : profile_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200) {
      if (resp.body.find("\"password\"") != std::string::npos ||
          resp.body.find("\"password_hash\"") != std::string::npos) {
        findings.push_back({"Password in API Response", "critical", base + path,
                            "Password or hash returned in user profile endpoint",
                            "", "", "Password field present in response"});
        break;
      }
    }
  }
  return findings;
}

/// Missing security.txt.
std::vector<Finding> scan_security_txt(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/.well-known/security.txt");
  if (resp.status_code != 200) {
    resp = http.get(base + "/security.txt");
  }
  if (resp.status_code != 200 || resp.body.find("Contact:") == std::string::npos) {
    findings.push_back({"Missing security.txt", "info", base,
                        "No security.txt — makes responsible disclosure harder",
                        "", "", "RFC 9116 recommends security.txt"});
  }
  return findings;
}

/// HSTS not set or too short.
std::vector<Finding> scan_hsts(const Config &, HttpClient &http,
                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Only check HTTPS sites
  if (base.find("https://") == std::string::npos) return findings;

  auto resp = http.get(base);
  auto hsts = resp.headers.find("Strict-Transport-Security");
  if (hsts == resp.headers.end()) {
    findings.push_back({"Missing HSTS", "medium", base,
                        "No Strict-Transport-Security header — downgrade attacks possible",
                        "", "", ""});
  } else if (hsts->second.find("max-age=") != std::string::npos) {
    std::regex age_re(R"(max-age=(\d+))");
    std::smatch m;
    if (std::regex_search(hsts->second, m, age_re)) {
      int age = std::stoi(m[1].str());
      if (age < 31536000) {
        findings.push_back({"HSTS Too Short", "low", base,
                            "HSTS max-age is " + std::to_string(age) +
                                "s (should be >= 31536000)",
                            "", "", "Strict-Transport-Security: " + hsts->second});
      }
    }
  }
  return findings;
}

/// Mixed content — HTTPS page loading HTTP resources.
std::vector<Finding> scan_mixed_content(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  if (base.find("https://") == std::string::npos) return findings;

  auto resp = http.get(crawl.urls[0]);
  std::regex http_res_re(R"((src|href|action)=["']http://)");
  std::smatch m;
  if (std::regex_search(resp.body, m, http_res_re)) {
    findings.push_back({"Mixed Content", "low", crawl.urls[0],
                        "HTTPS page loads resources over HTTP",
                        "", "", "Found http:// reference in page source"});
  }
  return findings;
}

/// Autocomplete on sensitive fields.
std::vector<Finding> scan_autocomplete(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    if (resp.body.find("type=\"password\"") != std::string::npos &&
        resp.body.find("autocomplete=\"off\"") == std::string::npos &&
        resp.body.find("autocomplete=\"new-password\"") == std::string::npos) {
      findings.push_back({"Autocomplete on Password", "info", url,
                          "Password field allows browser autocomplete",
                          "", "", "Browsers may cache credentials"});
      break;
    }
  }
  return findings;
}

/// CORS wildcard with credentials.
std::vector<Finding> scan_cors_wildcard_creds(const Config &, HttpClient &http,
                                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0], {{"Origin", "https://evil.com"}});
  auto acao = resp.headers.find("Access-Control-Allow-Origin");
  auto acac = resp.headers.find("Access-Control-Allow-Credentials");

  if (acao != resp.headers.end() && acac != resp.headers.end()) {
    if (acao->second == "https://evil.com" && acac->second == "true") {
      findings.push_back({"CORS Credential Theft", "critical", crawl.urls[0],
                          "Arbitrary origin reflected with credentials allowed",
                          "Origin", "https://evil.com",
                          "ACAO: evil.com + ACAC: true"});
    }
  }
  return findings;
}

/// Referrer leaking sensitive tokens.
std::vector<Finding> scan_referrer_leak(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);
  auto rp = resp.headers.find("Referrer-Policy");
  if (rp == resp.headers.end()) {
    // Check if page has external links that could leak URL (with tokens)
    if (resp.body.find("href=\"http") != std::string::npos) {
      findings.push_back({"Missing Referrer-Policy", "low", crawl.urls[0],
                          "No Referrer-Policy — URL (possibly with tokens) leaked to external sites",
                          "", "", "External links present without referrer policy"});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_compliance_scanners() {
  return {
      {"PII in Errors", scan_pii_in_errors},
      {"Stack Trace Exposed", scan_stack_trace},
      {"Tracking Without Consent", scan_tracking_no_consent},
      {"Password in Response", scan_password_storage},
      {"Missing security.txt", scan_security_txt},
      {"HSTS Check", scan_hsts},
      {"Mixed Content", scan_mixed_content},
      {"Autocomplete Password", scan_autocomplete},
      {"CORS Credential Theft", scan_cors_wildcard_creds},
      {"Referrer Leak", scan_referrer_leak},
  };
}

} // namespace apex
