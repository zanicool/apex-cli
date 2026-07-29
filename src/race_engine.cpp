/// @file race_engine.cpp
/// @brief Race Condition Exploitation Engine — detects TOCTOU and double-spend.
#include "race_engine.hpp"

#include <algorithm>
#include <atomic>
#include <future>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <thread>

namespace apex {

bool RaceEngine::indicates_success(const Response &resp) {
  if (resp.status_code >= 200 && resp.status_code < 300)
    return true;
  if (resp.status_code == 302 || resp.status_code == 303)
    return true;
  return false;
}

RaceEngine::RaceResult
RaceEngine::fire_concurrent(HttpClient &http, const std::string &url,
                            const std::string &body,
                            const std::string &content_type, int count) {
  RaceResult result;
  result.total_sent = count;
  result.success_count = 0;
  result.unique_responses = 0;

  std::vector<std::future<Response>> futures;
  futures.reserve(count);

  // Fire all requests as simultaneously as possible
  std::atomic<bool> go{false};

  for (int i = 0; i < count; ++i) {
    futures.push_back(std::async(std::launch::async, [&]() -> Response {
      // Spin-wait for synchronization (maximizes concurrency)
      while (!go.load(std::memory_order_acquire)) {
        std::this_thread::yield();
      }
      if (body.empty()) {
        return http.get(url);
      }
      return http.post(url, body, content_type);
    }));
  }

  // Release all threads simultaneously
  go.store(true, std::memory_order_release);

  // Collect results
  std::set<std::string> unique_bodies;
  for (auto &fut : futures) {
    try {
      auto resp = fut.get();
      result.status_codes.push_back(resp.status_code);
      result.bodies.push_back(resp.body);
      if (indicates_success(resp))
        result.success_count++;
      // Track unique responses (by first 200 chars)
      std::string key =
          std::to_string(resp.status_code) + ":" +
          resp.body.substr(0, std::min(resp.body.size(), (size_t)200));
      unique_bodies.insert(key);
    } catch (...) {
      result.status_codes.push_back(0);
    }
  }

  result.unique_responses = static_cast<int>(unique_bodies.size());
  return result;
}

std::vector<Finding> RaceEngine::test_races(const CrawlResult &crawl,
                                            HttpClient &http,
                                            const Config &cfg) {
  std::vector<Finding> findings;

  auto f1 = test_form_races(crawl, http, cfg);
  findings.insert(findings.end(), f1.begin(), f1.end());

  auto f2 = test_account_creation_race(http, cfg);
  findings.insert(findings.end(), f2.begin(), f2.end());

  return findings;
}

std::vector<Finding> RaceEngine::test_form_races(const CrawlResult &crawl,
                                                 HttpClient &http,
                                                 const Config &cfg) {
  std::vector<Finding> findings;

  // Keywords that indicate race-sensitive operations
  std::vector<std::string> sensitive_keywords = {
      "coupon",  "discount", "redeem",   "transfer", "send",
      "payment", "vote",     "like",     "follow",   "subscribe",
      "apply",   "claim",    "withdraw", "purchase", "checkout",
      "order",   "book",     "reserve",  "confirm",  "submit",
  };

  int concurrent_count = cfg.blitz ? 10 : 25;
  std::set<std::string> tested_forms;

  for (const auto &form : crawl.forms) {
    if (form.method != "POST" && form.method != "post")
      continue;
    if (tested_forms.count(form.action))
      continue;
    tested_forms.insert(form.action);

    // Check if form action/fields hint at sensitive operations
    std::string action_lower = form.action;
    std::transform(action_lower.begin(), action_lower.end(),
                   action_lower.begin(), ::tolower);

    bool is_sensitive = false;
    std::string matched_keyword;
    for (const auto &kw : sensitive_keywords) {
      if (action_lower.find(kw) != std::string::npos) {
        is_sensitive = true;
        matched_keyword = kw;
        break;
      }
      for (const auto &field : form.fields) {
        std::string field_lower = field.name;
        std::transform(field_lower.begin(), field_lower.end(),
                       field_lower.begin(), ::tolower);
        if (field_lower.find(kw) != std::string::npos) {
          is_sensitive = true;
          matched_keyword = kw;
          break;
        }
      }
      if (is_sensitive)
        break;
    }

    // Build form body
    std::string body;
    for (const auto &field : form.fields) {
      if (!body.empty())
        body += "&";
      body += field.name + "=test123";
    }

    // First, send a single request to get baseline
    auto baseline = http.post(form.action, body,
                              "application/x-www-form-urlencoded");
    if (baseline.status_code == 0)
      continue;

    // Fire concurrent requests
    auto race_result = fire_concurrent(
        http, form.action, body, "application/x-www-form-urlencoded",
        concurrent_count);

    // Analysis: if multiple requests succeeded where only 1 should
    if (race_result.success_count > 1 && is_sensitive) {
      Finding f;
      f.type = "race-condition-double-spend";
      f.severity = "critical";
      f.url = form.action;
      f.detail = "Race condition detected on '" + matched_keyword +
                 "' operation: " + std::to_string(race_result.success_count) +
                 "/" + std::to_string(race_result.total_sent) +
                 " concurrent requests succeeded";
      f.payload = body;
      f.evidence = "Sent " + std::to_string(concurrent_count) +
                   " concurrent requests, " +
                   std::to_string(race_result.success_count) +
                   " succeeded (expected: 1)";
      f.confidence = 70;
      f.cwe_id = "CWE-362";
      f.owasp_category = "A04:2021 Insecure Design";
      f.cvss_score = 8.1;
      findings.push_back(f);
    }

    // Check for TOCTOU: different responses suggest state inconsistency
    if (race_result.unique_responses > 3 &&
        race_result.success_count > 1) {
      Finding f;
      f.type = "race-condition-toctou";
      f.severity = "high";
      f.url = form.action;
      f.detail = "Possible TOCTOU vulnerability: " +
                 std::to_string(race_result.unique_responses) +
                 " different responses from identical concurrent requests";
      f.payload = body;
      f.evidence = std::to_string(race_result.unique_responses) +
                   " unique responses from " +
                   std::to_string(race_result.total_sent) +
                   " identical requests";
      f.confidence = 55;
      f.cwe_id = "CWE-367";
      f.owasp_category = "A04:2021 Insecure Design";
      f.cvss_score = 6.5;
      findings.push_back(f);
    }

    // Limit bypass: check if rate limiting is missing
    if (race_result.success_count == concurrent_count &&
        concurrent_count >= 10) {
      Finding f;
      f.type = "race-condition-limit-bypass";
      f.severity = "medium";
      f.url = form.action;
      f.detail = "No rate limiting detected: all " +
                 std::to_string(concurrent_count) +
                 " concurrent requests succeeded";
      f.payload = body;
      f.evidence = "All " + std::to_string(concurrent_count) +
                   " concurrent requests returned success";
      f.confidence = 50;
      f.cwe_id = "CWE-770";
      f.owasp_category = "A04:2021 Insecure Design";
      f.cvss_score = 5.3;
      findings.push_back(f);
    }

    if (cfg.quick && findings.size() >= 3)
      break;
  }

  // Also test GET endpoints that look like they perform actions
  std::vector<std::string> action_patterns = {
      "confirm", "activate", "verify", "approve", "delete", "remove",
  };

  for (const auto &url : crawl.urls) {
    std::string url_lower = url;
    std::transform(url_lower.begin(), url_lower.end(), url_lower.begin(),
                   ::tolower);

    bool is_action = false;
    std::string action_type;
    for (const auto &pat : action_patterns) {
      if (url_lower.find(pat) != std::string::npos) {
        is_action = true;
        action_type = pat;
        break;
      }
    }
    if (!is_action)
      continue;

    auto race_result = fire_concurrent(http, url, "", "", concurrent_count);

    if (race_result.success_count > 1 && race_result.unique_responses > 2) {
      Finding f;
      f.type = "race-condition-action-replay";
      f.severity = "high";
      f.url = url;
      f.detail = "Action endpoint '" + action_type +
                 "' vulnerable to race condition replay";
      f.evidence = std::to_string(race_result.success_count) +
                   " successful concurrent executions of " + action_type +
                   " action";
      f.confidence = 60;
      f.cwe_id = "CWE-362";
      f.owasp_category = "A04:2021 Insecure Design";
      f.cvss_score = 7.5;
      findings.push_back(f);
    }

    if (cfg.quick && findings.size() >= 5)
      break;
  }

  return findings;
}

std::vector<Finding>
RaceEngine::test_account_creation_race(HttpClient &http, const Config &cfg) {
  std::vector<Finding> findings;
  std::string base = cfg.target;
  if (!base.empty() && base.back() == '/')
    base.pop_back();

  // Try common registration endpoints
  std::vector<std::string> reg_paths = {
      "/register",    "/signup",     "/api/register",    "/api/signup",
      "/api/v1/register", "/api/v1/users", "/users/create", "/account/create",
  };

  std::string test_email = "racetest@example.com";
  std::string body_form =
      "email=" + test_email + "&password=RaceTest123!&username=racetest";
  std::string body_json = "{\"email\":\"" + test_email +
                          "\",\"password\":\"RaceTest123!\",\"username\":"
                          "\"racetest\"}";

  for (const auto &path : reg_paths) {
    std::string url = base + path;

    // Check if endpoint exists
    auto probe = http.post(url, body_form,
                           "application/x-www-form-urlencoded");
    if (probe.status_code == 404 || probe.status_code == 0)
      continue;

    // Fire concurrent registration attempts with same email
    int count = cfg.blitz ? 5 : 15;
    auto result = fire_concurrent(http, url, body_json, "application/json",
                                  count);

    // If multiple registrations succeeded with same email → race condition
    if (result.success_count > 1) {
      Finding f;
      f.type = "race-condition-duplicate-account";
      f.severity = "high";
      f.url = url;
      f.detail = "Parallel account creation race: " +
                 std::to_string(result.success_count) +
                 " accounts created with same email";
      f.payload = body_json;
      f.evidence = std::to_string(result.success_count) + "/" +
                   std::to_string(count) +
                   " concurrent registrations succeeded with identical email";
      f.confidence = 72;
      f.cwe_id = "CWE-362";
      f.owasp_category = "A04:2021 Insecure Design";
      f.cvss_score = 7.5;
      findings.push_back(f);
    }

    if (cfg.quick)
      break;
  }

  return findings;
}

} // namespace apex
