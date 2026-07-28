/// @file scanners/injection.cpp
/// @brief Advanced injection: NoSQL, LDAP, XPath, Expression Language,
///        PHP object injection.
#include "scanner_base.hpp"

namespace apex {
namespace {

/// NoSQL injection scanner.
std::vector<Finding> scan_nosql(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {"{\"$ne\":\"\"}", "[$ne]=1", "{\"$gt\":\"\"}", "{\"$regex\":\".*\"}"};

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto& [base, param] : targets) {
      auto baseline = http.get(base + "test");
      int anomaly_trials = 0;
      for (const auto& payload : payloads) {
        auto resp = http.get(base + payload);
        if (resp.body.size() > baseline.body.size() + 50) {
          anomaly_trials++;
          if (anomaly_trials >= 2) {
            // Multiple trials confirm size anomaly — not a single-shot FP
            findings.push_back({"NoSQL Injection", "high", url, "Response size anomaly confirmed across multiple trials", param, payload, ""});
            break;
          }
        }
      }
    }
  }
  return findings;
}

/// LDAP injection scanner.
std::vector<Finding> scan_ldap(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {"*)(&", "*)(|(&", "*()|%26'", "admin)(&)"};
  const std::vector<std::string> errors = {"LDAP", "ldap_search", "Invalid DN", "Bad search filter"};

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "username");
    for (const auto& [base, param] : targets) {
      auto baseline = http.get(base + "safe_test_ldap_baseline");
      for (const auto& payload : payloads) {
        auto resp = http.get(base + payload);
        // Differential check: error string must appear in response but NOT in baseline
        if (contains_any(resp.body, errors) && !contains_any(baseline.body, errors)) {
          findings.push_back({"LDAP Injection", "high", url, "LDAP error appears only with malicious input", param, payload, ""});
          break;
        }
      }
    }
  }
  return findings;
}

/// XPath injection scanner.
std::vector<Finding> scan_xpath(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {"' or '1'='1", "' or ''='", "1 or 1=1", "'] | //*['"};
  const std::vector<std::string> errors = {"XPath", "xpath", "XPATH", "xmlXPathEval", "SimpleXMLElement"};

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto& [base, param] : targets) {
      auto baseline = http.get(base + "safe_test_xpath_baseline");
      for (const auto& payload : payloads) {
        auto resp = http.get(base + payload);
        // Differential check: error string must appear in response but NOT in baseline
        if (contains_any(resp.body, errors) && !contains_any(baseline.body, errors)) {
          findings.push_back({"XPath Injection", "high", url, "XPath error appears only with malicious input", param, payload, ""});
          break;
        }
      }
    }
  }
  return findings;
}

/// Expression Language injection (Java EL, Spring SpEL).
/// Uses differential canary: two different math expressions must both resolve.
std::vector<Finding> scan_el_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Pairs: {payload_a, expect_a, payload_b, expect_b}
  const std::vector<std::tuple<std::string, std::string, std::string, std::string>> canaries = {
      {"${7*7}", "49", "${8*8}", "64"},
      {"#{7*7}", "49", "#{8*8}", "64"},
      {"${T(java.lang.Runtime)}", "java.lang.Runtime", "${T(java.lang.Math)}", "java.lang.Math"}};

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto& [base, param] : targets) {
      for (const auto& [payload_a, expect_a, payload_b, expect_b] : canaries) {
        // Baseline: check if expected values already exist in normal response
        auto baseline = http.get(base + "safe_test_string_12345");
        if (baseline.body.find(expect_a) != std::string::npos) continue;  // Already in page = FP

        auto resp_a = http.get(base + payload_a);
        if (resp_a.body.find(expect_a) == std::string::npos) continue;
        // First canary matched — now verify with second
        auto resp_b = http.get(base + payload_b);
        if (resp_b.body.find(expect_b) != std::string::npos && baseline.body.find(expect_b) == std::string::npos) {
          // Both canaries confirmed AND not in baseline — real injection
          findings.push_back({"EL Injection", "critical", url, "Differential canary confirmed: " + expect_a + " AND " + expect_b, param,
                              payload_a, expect_a});
          break;
        }
      }
    }
  }
  return findings;
}

/// PHP object injection via unserialize.
std::vector<Finding> scan_php_object(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::string payload = "O:8:\"stdClass\":0:{}";
  const std::vector<std::string> errors = {"unserialize()", "__wakeup", "__destruct", "Object of class"};

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "data");
    for (const auto& [base, param] : targets) {
      auto baseline = http.get(base + "safe_test_php_baseline");
      auto resp = http.get(base + payload);
      // Differential check: error string must appear only with payload, not in baseline
      if (contains_any(resp.body, errors) && !contains_any(baseline.body, errors)) {
        findings.push_back({"PHP Object Injection", "high", url, "PHP deserialization detected — error only with payload", param, payload, ""});
      }
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_injection_scanners() {
  return {
      {"NoSQL Injection", scan_nosql},           {"LDAP Injection", scan_ldap},
      {"XPath Injection", scan_xpath},           {"EL Injection", scan_el_injection},
      {"PHP Object Injection", scan_php_object},
  };
}

}  // namespace apex
