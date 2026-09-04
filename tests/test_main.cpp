/// @file test_main.cpp
/// @brief Unit tests for Apex CLI core components.
#include "../src/config.hpp"
#include "../src/http.hpp"
#include "../src/scanner.hpp"
#include <cassert>
#include <iostream>

namespace {

/// Test safe_name sanitization.
void test_safe_name() {
  assert(apex::safe_name("example.com") == "example_com");
  assert(apex::safe_name("sub.domain.io") == "sub_domain_io");
  assert(apex::safe_name("a-b_c") == "a_b_c");
  assert(apex::safe_name("simple") == "simple");
  std::cout << "  [pass] safe_name\n";
}

/// Test config defaults.
void test_config_defaults() {
  apex::Config cfg;
  assert(cfg.threads == 100);
  assert(cfg.timeout == 10);
  assert(cfg.deep == false);
  assert(cfg.dry_run == false);
  assert(cfg.rate == 0.0);
  assert(cfg.report == "json,terminal");
  std::cout << "  [pass] config_defaults\n";
}

/// Test scanner registry.
void test_scanner_registry() {
  auto scanners = apex::get_scanners();
  assert(!scanners.empty());
  assert(scanners.size() >= 80); // 17 modules, 80+ scanners total
  assert(scanners[0].name == "CMS Detection");
  std::cout << "  [pass] scanner_registry (" << scanners.size()
            << " scanners)\n";
}

/// Test dry-run produces no network-based findings.
void test_dry_run_no_network() {
  apex::Config cfg;
  cfg.target = "example.com";
  cfg.dry_run = true;
  cfg.quick = true;
  apex::HttpClient http(cfg);
  apex::CrawlResult crawl;
  crawl.urls = {"https://example.com"};

  auto findings = apex::run_scanners(cfg, http, crawl);
  // In dry-run, HTTP returns empty responses (status 0).
  // Only passive checks (headers) may fire on empty responses.
  // Injection scanners should find nothing since body is empty.
  bool has_injection = false;
  for (const auto &f : findings) {
    if (f.type == "SQLi" || f.type == "XSS" || f.type == "SSRF" ||
        f.type == "CMDi" || f.type == "LFI") {
      has_injection = true;
    }
  }
  assert(!has_injection);
  std::cout << "  [pass] dry_run_no_injection_findings\n";
}

/// Test HTTP client in dry-run mode.
void test_http_dry_run() {
  apex::Config cfg;
  cfg.dry_run = true;
  cfg.timeout = 5;
  apex::HttpClient http(cfg);

  auto resp = http.get("https://example.com");
  assert(resp.status_code == 0);
  assert(resp.error.empty());
  assert(resp.body.empty());
  assert(http.request_count() == 0);
  std::cout << "  [pass] http_dry_run\n";
}

} // namespace

// Defined in test_precision.cpp — regression tests locking in the precision
// (false-positive-reduction) fixes.
void run_precision_tests();

int main() {
  std::cout << "Running tests...\n";
  test_safe_name();
  test_config_defaults();
  test_scanner_registry();
  test_dry_run_no_network();
  test_http_dry_run();
  run_precision_tests();
  std::cout << "\nAll tests passed.\n";
  return 0;
}
