/// @file scanner.hpp
/// @brief Scanner framework: finding types and scanner registry.
#ifndef APEX_SCANNER_HPP
#define APEX_SCANNER_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include <functional>
#include <string>
#include <vector>

namespace apex {

/// A vulnerability finding.
struct Finding {
  std::string type;
  std::string severity; // critical, high, medium, low, info
  std::string url;
  std::string detail;
  std::string param;
  std::string payload;
  std::string evidence;
};

/// Scanner function signature.
using ScanFunc = std::function<std::vector<Finding>(
    const Config &, HttpClient &, const CrawlResult &)>;

/// A registered scanner with name and function.
struct Scanner {
  std::string name;
  ScanFunc func;
};

/// Get all registered scanners.
std::vector<Scanner> get_scanners();

/// Run all scanners concurrently and return findings.
std::vector<Finding> run_scanners(const Config &cfg, HttpClient &http,
                                  const CrawlResult &crawl);

/// Drop universally out-of-scope / non-rewardable noise findings (missing
/// email-DNS records, TLS/banner best-practices, fabricated info findings).
/// Findings with concrete evidence are preserved. Exposed for unit testing.
std::vector<Finding> apply_scope_gate(const std::vector<Finding> &findings);

} // namespace apex

#endif // APEX_SCANNER_HPP
