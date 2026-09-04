/// @file scanners/injection.cpp
/// @brief Advanced injection: NoSQL, LDAP, XPath, Expression Language,
///        PHP object injection.
#include "scanner_base.hpp"
#include "confirm.hpp"

namespace apex {
namespace {

/// NoSQL Injection is implemented once, canonically, in detection_gap.cpp
/// (indicator-confirmed, evidence-capturing). The duplicate copy that used to
/// live here was removed during dedup so exactly one hardened scanner runs.

/// LDAP injection scanner.
std::vector<Finding> scan_ldap(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {
      "*)(&", "*)(|(&", "*()|%26'", "admin)(&)"};
  const std::vector<std::string> errors = {
      "LDAP", "ldap_search", "Invalid DN", "Bad search filter"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "username");
    for (const auto &[base, param] : targets) {
      for (const auto &payload : payloads) {
        auto resp = http.get(base + payload);
        if (contains_any(resp.body, errors)) {
          findings.push_back({"LDAP Injection", "high", url,
                              "LDAP error in response", param, payload, ""});
          break;
        }
      }
    }
  }
  return findings;
}

/// XPath injection scanner.
std::vector<Finding> scan_xpath(const Config &, HttpClient &http,
                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {
      "' or '1'='1", "' or ''='", "1 or 1=1", "'] | //*['"};
  const std::vector<std::string> errors = {
      "XPath", "xpath", "XPATH", "xmlXPathEval", "SimpleXMLElement"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      for (const auto &payload : payloads) {
        auto resp = http.get(base + payload);
        if (contains_any(resp.body, errors)) {
          findings.push_back({"XPath Injection", "high", url,
                              "XPath error in response", param, payload, ""});
          break;
        }
      }
    }
  }
  return findings;
}

/// Expression Language injection (Java EL, Spring SpEL).
/// Uses differential canary: two different math expressions must both resolve.
std::vector<Finding> scan_el_injection(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Pairs: {payload_a, expect_a, payload_b, expect_b}
  // Arithmetic canaries only. The Runtime/Math reflection canary was removed:
  // its detect string ("java.lang.Runtime") is a substring of the payload, so
  // an app that merely reflects input unescaped produced a false "critical".
  const std::vector<std::tuple<std::string, std::string, std::string, std::string>> canaries = {
      {"${7*7}", "49", "${8*8}", "64"},
      {"#{7*7}", "49", "#{8*8}", "64"}};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      auto baseline = http.get(base + "apexbenign123");
      for (const auto &[payload_a, expect_a, payload_b, expect_b] : canaries) {
        // Both differential canaries must prove EVALUATION (centralized
        // invariant: result absent from payload, present in body, absent from
        // baseline). This rejects apps that merely reflect the payload.
        auto resp_a = http.get(base + payload_a);
        if (!confirm::is_evaluation_match(payload_a, expect_a, resp_a.body,
                                          baseline.body))
          continue;
        auto resp_b = http.get(base + payload_b);
        if (confirm::is_evaluation_match(payload_b, expect_b, resp_b.body,
                                         baseline.body)) {
          findings.push_back({"EL Injection", "critical", url,
                              "Differential canary confirmed: " + expect_a +
                                  " AND " + expect_b,
                              param, payload_a, expect_a});
          break;
        }
      }
    }
  }
  return findings;
}

/// PHP object injection via unserialize.
std::vector<Finding> scan_php_object(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::string payload = "O:8:\"stdClass\":0:{}";
  const std::vector<std::string> errors = {
      "unserialize()", "__wakeup", "__destruct", "Object of class"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "data");
    for (const auto &[base, param] : targets) {
      auto resp = http.get(base + payload);
      if (contains_any(resp.body, errors)) {
        findings.push_back({"PHP Object Injection", "high", url,
                            "PHP deserialization detected", param, payload, ""});
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_injection_scanners() {
  return {
      // NOTE: NoSQL Injection is registered once, canonically, in
      // detection_gap.cpp. The duplicate injection-module copy was removed so a
      // single hardened scanner runs.
      {"LDAP Injection", scan_ldap},
      {"XPath Injection", scan_xpath},
      {"EL Injection", scan_el_injection},
      {"PHP Object Injection", scan_php_object},
  };
}

} // namespace apex
