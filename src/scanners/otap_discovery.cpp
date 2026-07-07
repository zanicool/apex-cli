/// @file scanners/otap_discovery.cpp
/// @brief OTAP/DTAP environment discovery: find development, test, acceptance,
///        staging, preview environments that are often less protected.
#include <set>

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

/// Scanner implementation.
/// @brief Scan for otap_environments vulnerabilities.
std::vector<Finding> scan_otap_environments(const Config& cfg, HttpClient& http, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos) domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos) domain = domain.substr(0, domain.find('/'));

  // Split domain: "example.com" or "app.example.com"
  std::string base_domain = domain;
  std::string subdomain_prefix;
  size_t dots = 0;
  for (char c : domain)
    if (c == '.') dots++;
  if (dots >= 2) {
    size_t first_dot = domain.find('.');
    subdomain_prefix = domain.substr(0, first_dot);
    base_domain = domain.substr(first_dot + 1);
  }

  // OTAP patterns: prefix-based, subdomain-based, and path-based.
  const std::vector<std::string> env_prefixes = {
      // Dutch OTAP
      "ontwikkel",
      "test",
      "acceptatie",
      "productie",
      "ont",
      "tst",
      "acc",
      "prd",
      // English DTAP
      "dev",
      "development",
      "test",
      "testing",
      "staging",
      "stage",
      "stg",
      "accept",
      "acceptance",
      "uat",
      "qa",
      "qas",
      "preprod",
      "pre-prod",
      "pre",
      "demo",
      "sandbox",
      "preview",
      "beta",
      "alpha",
      "canary",
      "nightly",
      "edge",
      "next",
      "rc",
      // CI/CD
      "ci",
      "cd",
      "build",
      "deploy",
      "release",
      // Internal
      "internal",
      "corp",
      "intranet",
      "local",
      "debug",
      "perf",
      "load",
      "stress",
  };

  std::set<std::string> live_envs;

  // Iterate over targets.
  for (const auto& env : env_prefixes) {
    std::vector<std::string> candidates;

    // Pattern 1: env.domain.com
    candidates.push_back(env + "." + base_domain);
    // Pattern 2: env-app.domain.com (if subdomain exists)
    if (!subdomain_prefix.empty()) {
      candidates.push_back(env + "-" + subdomain_prefix + "." + base_domain);
      candidates.push_back(env + "." + subdomain_prefix + "." + base_domain);
      candidates.push_back(subdomain_prefix + "-" + env + "." + base_domain);
    }
    // Pattern 3: app-env.domain.com
    std::string org = base_domain.substr(0, base_domain.find('.'));
    candidates.push_back(org + "-" + env + "." + base_domain);

    for (const auto& candidate : candidates) {
      if (candidate == domain) continue;
      auto resp = http.get("https://" + candidate + "/");
      if (resp.status_code > 0 && resp.status_code < 500 && resp.error.empty()) {
        if (live_envs.count(candidate)) continue;
        live_envs.insert(candidate);

        // Check security posture of discovered environment.
        std::string severity = "medium";
        std::string detail = "OTAP environment '" + env + "' is live";

        // Check for missing auth.
        if (resp.status_code == 200 && resp.body.size() > 200 && resp.body.find("login") == std::string::npos) {
          severity = "high";
          detail += " — accessible without authentication";
        }

        // Check for debug headers/info.
        if (resp.headers.find("X-Debug") != resp.headers.end() || resp.headers.find("X-Debug-Token") != resp.headers.end() ||
            resp.body.find("debug") != std::string::npos) {
          severity = "high";
          detail += " — debug mode detected";
        }

        // Check for missing security headers (common on non-prod).
        if (resp.headers.find("Strict-Transport-Security") == resp.headers.end() &&
            resp.headers.find("X-Frame-Options") == resp.headers.end()) {
          detail += " — missing security headers";
        }

        findings.push_back({"OTAP Environment: " + candidate, severity, "https://" + candidate, detail, "", "", ""});
      }
    }
  }

  // Also check path-based environments on the same host.
  std::string base = "https://" + domain;
  const std::vector<std::string> env_paths = {
      "/dev", "/test", "/staging", "/uat", "/qa", "/demo", "/sandbox", "/beta", "/preview", "/internal",
  };
  // Iterate over targets.
  for (const auto& path : env_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 200 && resp.body.find("404") == std::string::npos) {
      findings.push_back({"OTAP Path: " + path, "low", base + path, "Environment path accessible on production host", "", "", ""});
    }
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_otap_scanners() {
  return {
      {"OTAP/DTAP Environments", scan_otap_environments},
  };
}

}  // namespace apex
