/// @file scanners/injection.cpp
/// @brief Advanced injection: NoSQL, LDAP, XPath, Expression Language,
///        PHP object injection.
#include "scanner_base.hpp"

namespace apex {
namespace {

/// NoSQL injection scanner.
std::vector<Finding> scan_nosql(const Config &, HttpClient &http,
                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {
      "{\"$ne\":\"\"}", "[$ne]=1", "{\"$gt\":\"\"}", "{\"$regex\":\".*\"}"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      auto baseline = http.get(base + "test");
      for (const auto &payload : payloads) {
        auto resp = http.get(base + payload);
        if (resp.body.size() > baseline.body.size() + 50) {
          findings.push_back({"NoSQL Injection", "high", url,
                              "Response size anomaly", param, payload, ""});
          break;
        }
      }
    }
  }
  return findings;
}

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
std::vector<Finding> scan_el_injection(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::pair<std::string, std::string>> payloads = {
      {"${7*7}", "49"},
      {"#{7*7}", "49"},
      {"${T(java.lang.Runtime)}", "java.lang.Runtime"},
      {"${applicationScope}", "applicationScope"}};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      auto baseline = http.get(base + "test");
      for (const auto &[payload, detect] : payloads) {
        auto resp = http.get(base + payload);
        if (resp.body.find(detect) != std::string::npos &&
            baseline.body.find(detect) == std::string::npos) {
          findings.push_back({"EL Injection", "critical", url,
                              "Expression Language injection", param,
                              payload, detect});
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
      {"NoSQL Injection", scan_nosql},
      {"LDAP Injection", scan_ldap},
      {"XPath Injection", scan_xpath},
      {"EL Injection", scan_el_injection},
      {"PHP Object Injection", scan_php_object},
  };
}

} // namespace apex
