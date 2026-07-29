#pragma once
/// @file workflow_tester.hpp
/// @brief Multi-step workflow and business logic vulnerability tester.
#ifndef APEX_WORKFLOW_TESTER_HPP
#define APEX_WORKFLOW_TESTER_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Tests business logic flaws: step skipping, race conditions,
/// parameter manipulation, and discount stacking.
class WorkflowTester {
public:
  explicit WorkflowTester(HttpClient &http, const Config &cfg);

  /// Test all discovered workflows for logic flaws.
  std::vector<Finding> test_workflows(const CrawlResult &crawl);

private:
  struct WorkflowStep {
    std::string url;
    std::string method;
    std::string body;
    int step_number = 0;
  };

  std::vector<Finding> test_step_skipping(const CrawlResult &crawl);
  std::vector<Finding> test_race_conditions(const CrawlResult &crawl);
  std::vector<Finding> test_parameter_manipulation(const CrawlResult &crawl);
  std::vector<Finding> test_discount_stacking(const CrawlResult &crawl);
  bool is_multi_step_form(const Form &form);
  bool is_payment_related(const std::string &url);
  bool is_coupon_related(const std::string &url);

  HttpClient &http_;
  const Config &cfg_;
};

} // namespace apex

#endif // APEX_WORKFLOW_TESTER_HPP
