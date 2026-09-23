/// @file scanners/logic.cpp
/// @brief Business logic flaws with differential, endpoint-specific evidence.
#include <future>
#include <thread>

#include "scanner_base.hpp"
#include "../response_validator.hpp"

namespace apex {
namespace {

std::string lower_body(const Response& response) {
  std::string value = response.body;
  std::transform(value.begin(), value.end(), value.begin(), ::tolower);
  return value;
}

bool distinct_success(const Response& response, const Response& soft404, int threshold = 80) {
  return response.status_code >= 200 && response.status_code < 300 &&
         (response.status_code != soft404.status_code || responses_differ(response, soft404, threshold));
}

std::vector<Finding> scan_race_condition(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  const std::string base = base_url_from(crawl.urls[0]);
  const std::string probe_path = "/api/apex-race-probe-7f3c9d";
  const auto get_probe = http.get(base + probe_path);
  const auto post_probe = http.post(base + probe_path, R"({"amount":1})", "application/json");
  const std::vector<std::string> paths = {"/api/transfer", "/api/redeem", "/api/coupon", "/api/withdraw"};

  for (const auto& path : paths) {
    const auto discovery = http.get(base + path);
    if (discovery.status_code == 0 || discovery.status_code == 404 ||
        (discovery.status_code == get_probe.status_code && !responses_differ(discovery, get_probe, 50))) continue;

    std::vector<std::future<Response>> futures;
    for (int i = 0; i < 5; ++i) {
      futures.push_back(std::async(std::launch::async, [&http, base, path]() {
        return http.post(base + path, R"({"amount":1})", "application/json");
      }));
    }
    int confirmed_success = 0;
    std::string evidence;
    for (auto& future : futures) {
      const auto response = future.get();
      const std::string body = lower_body(response);
      const bool success_semantics = body.find("success") != std::string::npos || body.find("completed") != std::string::npos ||
                                     body.find("transaction") != std::string::npos || body.find("redeemed") != std::string::npos ||
                                     body.find("transfer_id") != std::string::npos || body.find("order_id") != std::string::npos;
      if (distinct_success(response, post_probe) && success_semantics) {
        ++confirmed_success;
        if (evidence.empty()) evidence = response.body.substr(0, 200);
      }
    }
    if (confirmed_success > 1) {
      findings.push_back({"Race Condition", "high", base + path,
                          "Multiple concurrent requests produced endpoint-specific success responses (" +
                              std::to_string(confirmed_success) + "/5)",
                          "", "", evidence});
    }
  }
  return findings;
}

std::vector<Finding> scan_price_manipulation(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  for (const auto& url : crawl.urls) {
    for (const auto& parameter : crawl.params) {
      if (parameter.url != url) continue;
      const std::string name = parameter.name;
      if (name.find("price") == std::string::npos && name.find("amount") == std::string::npos &&
          name.find("cost") == std::string::npos && name.find("total") == std::string::npos) continue;
      const auto baseline = http.get(parameter.url + "?" + name + "=19.99");
      const auto response = http.get(parameter.url + "?" + name + "=0.01");
      const std::string body = lower_body(response);
      const bool accepted = body.find("0.01") != std::string::npos &&
                            (body.find("total") != std::string::npos || body.find("price") != std::string::npos ||
                             body.find("amount") != std::string::npos || body.find("accepted") != std::string::npos);
      if (response.status_code == 200 && baseline.status_code == 200 && accepted && responses_differ(response, baseline, 10)) {
        findings.push_back({"Price Manipulation", "high", url,
                            "Modified price was reflected in transaction-specific response data", name, "0.01",
                            response.body.substr(0, 200)});
      }
    }
  }
  return findings;
}

std::vector<Finding> scan_mass_assignment(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  const std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> paths = {"/api/user", "/api/profile", "/api/account", "/api/settings"};
  const std::string normal = R"({"name":"test","role":"user","is_admin":false})";
  const std::string echo_marker = "apex_unknown_assignment_control_7f3c9d";
  const std::string escalation =
      R"({"name":"test","role":"admin","is_admin":true,"verified":true,"apex_control":"apex_unknown_assignment_control_7f3c9d"})";
  for (const auto& path : paths) {
    const auto baseline = http.post(base + path, normal, "application/json");
    if (baseline.status_code == 404 || baseline.status_code == 405) continue;
    const auto response = http.post(base + path, escalation, "application/json");
    const bool escalated = response.body.find("\"role\":\"admin\"") != std::string::npos ||
                           response.body.find("\"is_admin\":true") != std::string::npos;
    const bool baseline_admin = baseline.body.find("\"role\":\"admin\"") != std::string::npos ||
                                baseline.body.find("\"is_admin\":true") != std::string::npos;
    if (response.status_code == 200 && escalated && !baseline_admin &&
        response.body.find(echo_marker) == std::string::npos && responses_differ(response, baseline, 10)) {
      findings.push_back({"Mass Assignment", "critical", base + path,
                          "Privilege fields were applied only in the escalated request", "", escalation,
                          "Baseline lacks admin role; escalated response contains applied admin role"});
    }
  }
  return findings;
}

std::vector<Finding> scan_forced_browsing(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  const std::string base = base_url_from(crawl.urls[0]);
  const auto soft404 = http.get(base + "/apex-admin-probe-7f3c9d");
  const std::vector<std::string> paths = {"/admin", "/admin/", "/debug", "/debug/", "/console", "/phpmyadmin",
                                          "/adminer", "/wp-admin", "/manager", "/actuator/env", "/elmah.axd", "/_profiler"};
  for (const auto& path : paths) {
    const auto response = http.get(base + path);
    const std::string body = lower_body(response);
    const bool admin_content = body.find("admin dashboard") != std::string::npos || body.find("phpmyadmin") != std::string::npos ||
                               body.find("adminer") != std::string::npos || body.find("propertysources") != std::string::npos ||
                               body.find("debug toolbar") != std::string::npos || body.find("server information") != std::string::npos;
    const bool login_page = body.find("password") != std::string::npos || body.find("sign in") != std::string::npos ||
                            body.find("log in") != std::string::npos;
    if (distinct_success(response, soft404, 100) && response.body.size() > 100 && admin_content && !login_page) {
      findings.push_back({"Forced Browsing", "high", base + path,
                          "Distinct administrative/debug content accessible without an authentication challenge", "", "",
                          response.body.substr(0, 200)});
    }
  }
  return findings;
}

std::vector<Finding> scan_idor_uuid(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::regex uuid_re(R"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", std::regex::icase);
  const std::vector<std::string> private_markers = {"\"email\"", "\"phone\"", "\"address\"", "\"account\"", "\"order\"", "\"billing\""};
  for (const auto& url : crawl.urls) {
    std::smatch match;
    if (!std::regex_search(url, match, uuid_re)) continue;
    const auto baseline = http.get(url);
    std::string modified = url;
    modified.replace(match.position(), match.length(), "00000000-0000-0000-0000-000000000001");
    const auto response = http.get(modified);
    if (response.status_code == 200 && baseline.status_code == 200 && responses_differ(response, baseline, 20) &&
        contains_any(response.body, private_markers)) {
      findings.push_back({"IDOR (UUID)", "high", url,
                          "A different UUID returned distinct private resource data", "", "00000000-0000-0000-0000-000000000001",
                          response.body.substr(0, 200)});
    }
  }
  return findings;
}

std::vector<Finding> scan_payment_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  const std::string base = base_url_from(crawl.urls[0]);
  const auto soft404 = http.get(base + "/apex-payment-complete-probe-7f3c9d");
  const std::vector<std::string> paths = {"/order/confirm", "/checkout/success", "/payment/complete", "/api/order/complete", "/thank-you"};
  for (const auto& path : paths) {
    const auto response = http.get(base + path);
    const std::string body = lower_body(response);
    const bool transaction_data = body.find("order_id") != std::string::npos || body.find("order number") != std::string::npos ||
                                  body.find("payment_status") != std::string::npos || body.find("transaction id") != std::string::npos ||
                                  body.find("receipt") != std::string::npos;
    const bool completion = body.find("paid") != std::string::npos || body.find("payment complete") != std::string::npos ||
                            body.find("order confirmed") != std::string::npos || body.find("thank you for your order") != std::string::npos;
    if (distinct_success(response, soft404, 100) && transaction_data && completion) {
      findings.push_back({"Payment Bypass", "high", base + path,
                          "Post-payment route exposed transaction-specific completion data without a verified payment flow", "", "",
                          response.body.substr(0, 250)});
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_logic_scanners() {
  return {{"Race Condition", scan_race_condition}, {"Price Manipulation", scan_price_manipulation},
          {"Mass Assignment", scan_mass_assignment}, {"Forced Browsing", scan_forced_browsing},
          {"IDOR (UUID)", scan_idor_uuid}, {"Payment Bypass", scan_payment_bypass}};
}

}  // namespace apex
