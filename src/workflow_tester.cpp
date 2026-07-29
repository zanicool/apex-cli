/// @file workflow_tester.cpp
/// @brief Multi-step workflow tester: step skipping, race conditions,
///        parameter manipulation, and discount stacking.
#include "workflow_tester.hpp"

#include <algorithm>
#include <chrono>
#include <future>
#include <regex>
#include <set>
#include <sstream>
#include <thread>

namespace apex {

WorkflowTester::WorkflowTester(HttpClient &http, const Config &cfg)
    : http_(http), cfg_(cfg) {}

std::vector<Finding> WorkflowTester::test_workflows(const CrawlResult &crawl) {
  std::vector<Finding> findings;

  auto skip_findings = test_step_skipping(crawl);
  findings.insert(findings.end(), skip_findings.begin(), skip_findings.end());

  auto race_findings = test_race_conditions(crawl);
  findings.insert(findings.end(), race_findings.begin(), race_findings.end());

  auto param_findings = test_parameter_manipulation(crawl);
  findings.insert(findings.end(), param_findings.begin(), param_findings.end());

  auto discount_findings = test_discount_stacking(crawl);
  findings.insert(findings.end(), discount_findings.begin(),
                  discount_findings.end());

  return findings;
}

std::vector<Finding>
WorkflowTester::test_step_skipping(const CrawlResult &crawl) {
  std::vector<Finding> findings;

  // Identify multi-step workflows by URL patterns
  static const std::regex step_pattern(
      R"((.*)(step|stage|phase|wizard|checkout)[/-]?(\d+)(.*))");
  static const std::regex final_step_keywords(
      R"((confirm|submit|complete|finalize|payment|pay|process|finish))");

  std::map<std::string, std::vector<std::string>> workflows;

  for (const auto &url : crawl.urls) {
    std::smatch m;
    if (std::regex_match(url, m, step_pattern)) {
      std::string base = m[1].str() + m[2].str();
      workflows[base].push_back(url);
    }
  }

  // For each workflow, try to skip to the final step
  for (const auto &[base, steps] : workflows) {
    if (steps.size() < 2) continue;

    // Find the highest step number
    int max_step = 0;
    std::string final_url;
    for (const auto &step_url : steps) {
      std::smatch m;
      if (std::regex_match(step_url, m, step_pattern)) {
        int step_num = std::stoi(m[3].str());
        if (step_num > max_step) {
          max_step = step_num;
          final_url = step_url;
        }
      }
    }

    if (final_url.empty() || max_step <= 1) continue;

    // Try to access final step directly
    auto resp = http_.get(final_url);
    if (resp.status_code == 200 && resp.body.size() > 100) {
      // Check if the response doesn't contain "redirect" or "error"
      std::string lower_body = resp.body.substr(0, 2000);
      std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(),
                     ::tolower);
      if (lower_body.find("error") == std::string::npos &&
          lower_body.find("redirect") == std::string::npos &&
          lower_body.find("not allowed") == std::string::npos) {
        Finding f;
        f.type = "Workflow Bypass";
        f.severity = "high";
        f.url = final_url;
        f.detail = "Multi-step workflow can be bypassed: step " +
                   std::to_string(max_step) +
                   " accessible without completing prior steps";
        f.evidence = "Direct access returned HTTP " +
                     std::to_string(resp.status_code) + " with " +
                     std::to_string(resp.body.size()) + " bytes";
        f.confidence = 65;
        f.cwe_id = "CWE-841";
        f.owasp_category = "A04:2021 Insecure Design";
        f.cvss_score = 7.1;
        findings.push_back(f);
      }
    }
  }

  // Test payment without address / confirm without verification
  for (const auto &form : crawl.forms) {
    if (!is_payment_related(form.action)) continue;

    // Try submitting payment form with empty/minimal data
    std::string minimal_body;
    for (const auto &field : form.fields) {
      if (!minimal_body.empty()) minimal_body += "&";
      if (field.name.find("amount") != std::string::npos ||
          field.name.find("price") != std::string::npos) {
        minimal_body += field.name + "=0.01";
      } else if (field.name.find("quantity") != std::string::npos ||
                 field.name.find("qty") != std::string::npos) {
        minimal_body += field.name + "=1";
      } else {
        minimal_body += field.name + "=test";
      }
    }

    auto resp = http_.post(form.action, minimal_body,
                           "application/x-www-form-urlencoded");
    if (resp.status_code == 200 || resp.status_code == 302) {
      std::string lower_body = resp.body.substr(0, 1000);
      std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(),
                     ::tolower);
      if (lower_body.find("success") != std::string::npos ||
          lower_body.find("confirmed") != std::string::npos ||
          lower_body.find("thank") != std::string::npos) {
        Finding f;
        f.type = "Payment Bypass";
        f.severity = "critical";
        f.url = form.action;
        f.detail = "Payment form accepts submission without required "
                   "address/verification steps";
        f.payload = minimal_body;
        f.evidence = "Response indicates success: " +
                     resp.body.substr(0, 200);
        f.confidence = 55;
        f.cwe_id = "CWE-841";
        f.owasp_category = "A04:2021 Insecure Design";
        f.cvss_score = 9.1;
        findings.push_back(f);
      }
    }
  }

  return findings;
}

std::vector<Finding>
WorkflowTester::test_race_conditions(const CrawlResult &crawl) {
  std::vector<Finding> findings;

  // Identify race-condition-prone endpoints
  static const std::regex race_target(
      R"((redeem|claim|transfer|withdraw|purchase|apply|vote|like|follow|bonus|reward|coupon|promo))");

  for (const auto &form : crawl.forms) {
    std::string lower_action = form.action;
    std::transform(lower_action.begin(), lower_action.end(),
                   lower_action.begin(), ::tolower);

    if (!std::regex_search(lower_action, race_target)) continue;

    // Build form body
    std::string body;
    for (const auto &field : form.fields) {
      if (!body.empty()) body += "&";
      body += field.name + "=test_value";
    }

    std::string content_type = "application/x-www-form-urlencoded";

    // Send N concurrent requests
    const int RACE_COUNT = 10;
    std::vector<std::future<Response>> futures;
    futures.reserve(RACE_COUNT);

    for (int i = 0; i < RACE_COUNT; ++i) {
      futures.push_back(std::async(std::launch::async, [&]() {
        return http_.post(form.action, body, content_type);
      }));
    }

    int success_count = 0;
    for (auto &fut : futures) {
      try {
        auto resp = fut.get();
        if (resp.status_code == 200 || resp.status_code == 201 ||
            resp.status_code == 302) {
          ++success_count;
        }
      } catch (...) {
      }
    }

    // If more than 1 succeeded, potential race condition
    if (success_count > 1) {
      Finding f;
      f.type = "Race Condition";
      f.severity = "high";
      f.url = form.action;
      f.detail = "Potential race condition: " + std::to_string(success_count) +
                 "/" + std::to_string(RACE_COUNT) +
                 " concurrent requests succeeded on action that should "
                 "be single-use";
      f.payload = body;
      f.evidence = std::to_string(success_count) + " successful responses";
      f.confidence = 50;
      f.cwe_id = "CWE-362";
      f.owasp_category = "A04:2021 Insecure Design";
      f.cvss_score = 7.5;
      findings.push_back(f);
    }
  }

  return findings;
}

std::vector<Finding>
WorkflowTester::test_parameter_manipulation(const CrawlResult &crawl) {
  std::vector<Finding> findings;

  static const std::regex price_param(
      R"((price|amount|cost|total|subtotal|fee|charge))");
  static const std::regex quantity_param(
      R"((quantity|qty|count|num|number|units))");

  for (const auto &param : crawl.params) {
    std::string lower_name = param.name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                   ::tolower);

    std::vector<std::pair<std::string, std::string>> tests;

    if (std::regex_search(lower_name, price_param)) {
      tests = {{"0", "Zero price"}, {"-1", "Negative price"},
               {"0.01", "Minimal price"}, {"99999999", "Overflow price"}};
    } else if (std::regex_search(lower_name, quantity_param)) {
      tests = {{"0", "Zero quantity"}, {"-1", "Negative quantity"},
               {"999999999", "Overflow quantity"},
               {"-999999999", "Large negative quantity"}};
    } else {
      continue;
    }

    for (const auto &[value, desc] : tests) {
      std::string test_url = param.url;
      std::string sep = (test_url.find('?') != std::string::npos) ? "&" : "?";
      test_url += sep + param.name + "=" + value;

      Response resp;
      if (param.method == "POST") {
        std::string body = param.name + "=" + value;
        resp = http_.post(param.url, body, "application/x-www-form-urlencoded");
      } else {
        resp = http_.get(test_url);
      }

      if (resp.status_code == 200) {
        std::string lower_body = resp.body.substr(0, 1000);
        std::transform(lower_body.begin(), lower_body.end(),
                       lower_body.begin(), ::tolower);

        // Check for signs the manipulation was accepted
        if (lower_body.find("error") == std::string::npos &&
            lower_body.find("invalid") == std::string::npos &&
            lower_body.find("must be") == std::string::npos &&
            resp.body.size() > 50) {
          Finding f;
          f.type = "Parameter Manipulation";
          f.severity = "high";
          f.url = param.url;
          f.param = param.name;
          f.payload = value;
          f.detail = desc + " accepted for parameter '" + param.name +
                     "' — no server-side validation";
          f.evidence = "Status " + std::to_string(resp.status_code) +
                       ", no error in response";
          f.confidence = 50;
          f.cwe_id = "CWE-20";
          f.owasp_category = "A03:2021 Injection";
          f.cvss_score = 7.5;
          findings.push_back(f);
          break; // One finding per param is sufficient
        }
      }
    }
  }

  return findings;
}

std::vector<Finding>
WorkflowTester::test_discount_stacking(const CrawlResult &crawl) {
  std::vector<Finding> findings;

  for (const auto &form : crawl.forms) {
    if (!is_coupon_related(form.action)) continue;

    // Find the coupon field
    std::string coupon_field;
    for (const auto &field : form.fields) {
      std::string lower = field.name;
      std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
      if (lower.find("coupon") != std::string::npos ||
          lower.find("promo") != std::string::npos ||
          lower.find("discount") != std::string::npos ||
          lower.find("code") != std::string::npos ||
          lower.find("voucher") != std::string::npos) {
        coupon_field = field.name;
        break;
      }
    }

    if (coupon_field.empty()) continue;

    // Try applying the same code twice
    std::string body = coupon_field + "=TESTCODE";
    auto resp1 = http_.post(form.action, body,
                            "application/x-www-form-urlencoded");
    auto resp2 = http_.post(form.action, body,
                            "application/x-www-form-urlencoded");

    if (resp1.status_code == 200 && resp2.status_code == 200) {
      // If both succeed without error, potential stacking
      std::string lower_body = resp2.body.substr(0, 1000);
      std::transform(lower_body.begin(), lower_body.end(), lower_body.begin(),
                     ::tolower);
      if (lower_body.find("already") == std::string::npos &&
          lower_body.find("duplicate") == std::string::npos &&
          lower_body.find("used") == std::string::npos &&
          lower_body.find("invalid") == std::string::npos &&
          resp2.body.size() > 50) {
        Finding f;
        f.type = "Discount Stacking";
        f.severity = "medium";
        f.url = form.action;
        f.param = coupon_field;
        f.detail = "Coupon/discount code can potentially be applied multiple "
                   "times without rejection";
        f.payload = body;
        f.evidence = "Second application returned HTTP " +
                     std::to_string(resp2.status_code) +
                     " without error indication";
        f.confidence = 45;
        f.cwe_id = "CWE-841";
        f.owasp_category = "A04:2021 Insecure Design";
        f.cvss_score = 6.5;
        findings.push_back(f);
      }
    }
  }

  return findings;
}

bool WorkflowTester::is_multi_step_form(const Form &form) {
  std::string lower = form.action;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
  return lower.find("step") != std::string::npos ||
         lower.find("wizard") != std::string::npos ||
         lower.find("stage") != std::string::npos ||
         lower.find("phase") != std::string::npos;
}

bool WorkflowTester::is_payment_related(const std::string &url) {
  std::string lower = url;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
  return lower.find("payment") != std::string::npos ||
         lower.find("checkout") != std::string::npos ||
         lower.find("pay") != std::string::npos ||
         lower.find("purchase") != std::string::npos ||
         lower.find("order") != std::string::npos ||
         lower.find("billing") != std::string::npos;
}

bool WorkflowTester::is_coupon_related(const std::string &url) {
  std::string lower = url;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
  return lower.find("coupon") != std::string::npos ||
         lower.find("promo") != std::string::npos ||
         lower.find("discount") != std::string::npos ||
         lower.find("voucher") != std::string::npos ||
         lower.find("redeem") != std::string::npos ||
         lower.find("apply") != std::string::npos;
}

} // namespace apex
