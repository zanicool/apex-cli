/// @file test_main.cpp
/// @brief Unit tests for Apex CLI core components.
#include "../src/config.hpp"
#include "../src/http.hpp"
#include "../src/scanner.hpp"
#include "../src/scanners/counterfactual.hpp"
#include <algorithm>
#include <cassert>
#include <iostream>

namespace {

void test_safe_name() {
  assert(apex::safe_name("example.com") == "example_com");
  assert(apex::safe_name("sub.domain.io") == "sub_domain_io");
  assert(apex::safe_name("a-b_c") == "a_b_c");
  assert(apex::safe_name("simple") == "simple");
  std::cout << "  [pass] safe_name\n";
}

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

void test_scanner_registry() {
  const auto scanners = apex::get_scanners();
  assert(scanners.size() >= 2734);
  assert(scanners[0].name == "CMS Detection");
  assert(std::any_of(scanners.begin(), scanners.end(), [](const apex::Scanner& scanner) {
    return scanner.name == "Counterfactual Template Consensus";
  }));
  std::cout << "  [pass] scanner_registry (" << scanners.size() << " scanners)\n";
}

void test_counterfactual_consensus() {
  apex::Response baseline;
  baseline.status_code = 200;
  baseline.body = "Hello apex_ctc_control";
  apex::Response positive_a = baseline;
  positive_a.body = "Hello 44461";
  apex::Response positive_b = baseline;
  positive_b.body = "Hello 47603";
  apex::Response negative = baseline;
  negative.status_code = 500;
  negative.body = "Template parse error";

  assert(apex::confirms_counterfactual_template_consensus(
      baseline, positive_a, positive_b, negative, "44461", "47603"));

  // One matching number is insufficient.
  apex::Response missing_second = positive_b;
  missing_second.body = "Hello unchanged";
  assert(!apex::confirms_counterfactual_template_consensus(
      baseline, positive_a, missing_second, negative, "44461", "47603"));

  // A negative control containing either canary invalidates the proof.
  apex::Response colliding_negative = negative;
  colliding_negative.body = "Generic dynamic page 44461 and 47603";
  assert(!apex::confirms_counterfactual_template_consensus(
      baseline, positive_a, positive_b, colliding_negative, "44461", "47603"));

  // Numeric substrings inside larger numbers do not count as evaluation.
  positive_a.body = "value=1444619";
  assert(!apex::confirms_counterfactual_template_consensus(
      baseline, positive_a, positive_b, negative, "44461", "47603"));
  std::cout << "  [pass] counterfactual_consensus\n";
}

void test_dry_run_no_network() {
  apex::Config cfg;
  cfg.target = "example.com";
  cfg.dry_run = true;
  cfg.quick = true;
  apex::HttpClient http(cfg);
  apex::CrawlResult crawl;
  crawl.urls = {"https://example.com"};

  const auto findings = apex::run_scanners(cfg, http, crawl);
  assert(findings.empty());
  assert(http.request_count() == 0);
  std::cout << "  [pass] dry_run_no_findings\n";
}

void test_http_dry_run() {
  apex::Config cfg;
  cfg.dry_run = true;
  cfg.timeout = 5;
  apex::HttpClient http(cfg);
  const auto response = http.get("https://example.com");
  assert(response.status_code == 0);
  assert(response.error.empty());
  assert(response.body.empty());
  assert(http.request_count() == 0);
  std::cout << "  [pass] http_dry_run\n";
}

} // namespace

int main() {
  std::cout << "Running tests...\n";
  test_safe_name();
  test_config_defaults();
  test_scanner_registry();
  test_counterfactual_consensus();
  test_dry_run_no_network();
  test_http_dry_run();
  std::cout << "\nAll tests passed.\n";
  return 0;
}
