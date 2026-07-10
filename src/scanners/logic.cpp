/// @file scanners/logic.cpp
/// @brief Business logic flaws: race condition, price manipulation, payment
///        bypass, mass assignment, forced browsing, IDOR UUID.
#include <future>
#include <thread>

#include "scanner_base.hpp"
#include "../response_validator.hpp"

namespace apex {
namespace {

/// Race condition — send concurrent requests to exploit TOCTOU.
std::vector<Finding> scan_race_condition(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> race_paths = {"/api/transfer", "/api/redeem", "/api/coupon", "/api/withdraw"};

  for (const auto& path : race_paths) {
    auto check = http.get(base + path);
    if (check.status_code == 404) continue;

    // Send 5 concurrent requests.
    std::vector<std::future<Response>> futures;
    for (int i = 0; i < 5; ++i) {
      futures.push_back(std::async(std::launch::async, [&]() { return http.post(base + path, "{\"amount\":1}", "application/json"); }));
    }
    int success = 0;
    for (auto& f : futures) {
      auto resp = f.get();
      if (resp.status_code == 200) ++success;
    }
    if (success > 1) {
      findings.push_back({"Race Condition", "high", base + path,
                          "Multiple concurrent requests succeeded (" + std::to_string(success) + "/5)", "", "", ""});
    }
  }
  return findings;
}

/// Price manipulation — modify price parameters.
std::vector<Finding> scan_price_manipulation(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  for (const auto& url : crawl.urls) {
    for (const auto& p : crawl.params) {
      if (p.url != url) continue;
      if (p.name.find("price") == std::string::npos && p.name.find("amount") == std::string::npos &&
          p.name.find("cost") == std::string::npos && p.name.find("total") == std::string::npos)
        continue;

      auto resp = http.get(p.url + "?" + p.name + "=0.01");
      if (resp.status_code == 200 && resp.body.find("error") == std::string::npos) {
        findings.push_back({"Price Manipulation", "high", url, "Price parameter accepted modified value", p.name, "0.01", ""});
      }
    }
  }
  return findings;
}

/// Mass assignment — inject extra fields in requests.
std::vector<Finding> scan_mass_assignment(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> api_paths = {"/api/user", "/api/profile", "/api/account", "/api/settings"};
  const std::string normal_payload = R"({"name":"test"})";
  const std::string escalation_payload = R"({"name":"test","role":"admin","is_admin":true,"verified":true})";

  for (const auto& path : api_paths) {
    // First: send a baseline request without privilege fields
    auto baseline = http.post(base + path, normal_payload, "application/json");
    if (baseline.status_code == 404 || baseline.status_code == 405) continue;

    // Then: send request with privilege escalation fields
    auto resp = http.post(base + path, escalation_payload, "application/json");
    if (resp.status_code != 200) continue;

    // Only flag if the response DIFFERS from baseline AND contains escalated privileges
    // The response must show the server actually applied the role change
    bool has_escalation =
        (resp.body.find("\"role\":\"admin\"") != std::string::npos || resp.body.find("\"is_admin\":true") != std::string::npos);
    bool baseline_has_it =
        (baseline.body.find("\"role\":\"admin\"") != std::string::npos || baseline.body.find("\"is_admin\":true") != std::string::npos);

    // Only a real finding if the escalation fields appear in response
    // AND they weren't already there in the baseline
    if (has_escalation && !baseline_has_it && resp.body != baseline.body) {
      findings.push_back({"Mass Assignment", "critical", base + path, "Privilege escalation via mass assignment — role changed in response",
                          "", escalation_payload, "Baseline lacks admin role, escalated request shows it"});
    }
  }
  return findings;
}

/// Forced browsing — access admin/debug paths directly.
std::vector<Finding> scan_forced_browsing(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/admin",   "/admin/",   "/debug",   "/debug/",       "/console",   "/phpmyadmin",
                                          "/adminer", "/wp-admin", "/manager", "/actuator/env", "/elmah.axd", "/_profiler"};

  for (const auto& path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 100 && resp.body.find("login") == std::string::npos) {
      findings.push_back({"Forced Browsing", "high", base + path, "Admin/debug path accessible", "", "", ""});
    }
  }
  return findings;
}

/// IDOR with UUID — test if UUIDs are predictable or enumerable.
std::vector<Finding> scan_idor_uuid(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Look for UUID patterns in URLs.
  std::regex uuid_re(R"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", std::regex::icase);

  for (const auto& url : crawl.urls) {
    std::smatch match;
    if (!std::regex_search(url, match, uuid_re)) continue;

    // Try replacing UUID with a different one.
    std::string modified = url;
    modified.replace(match.position(), match.length(), "00000000-0000-0000-0000-000000000001");
    auto resp = http.get(modified);
    if (resp.status_code == 200 && resp.body.size() > 50) {
      findings.push_back(
          {"IDOR (UUID)", "high", url, "UUID-based resource accessible with different ID", "", "00000000-0000-0000-0000-000000000001", ""});
    }
  }
  return findings;
}

/// Payment bypass — skip payment step.
std::vector<Finding> scan_payment_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Try accessing post-payment pages directly.
  const std::vector<std::string> post_payment = {"/order/confirm", "/checkout/success", "/payment/complete", "/api/order/complete",
                                                 "/thank-you"};

  for (const auto& path : post_payment) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 100 && resp.body.find("error") == std::string::npos) {
      findings.push_back({"Payment Bypass", "high", base + path, "Post-payment page accessible without payment", "", "", ""});
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_logic_scanners() {
  return {
      {"Race Condition", scan_race_condition},   {"Price Manipulation", scan_price_manipulation},
      {"Mass Assignment", scan_mass_assignment}, {"Forced Browsing", scan_forced_browsing},
      {"IDOR (UUID)", scan_idor_uuid},           {"Payment Bypass", scan_payment_bypass},
  };
}

}  // namespace apex
