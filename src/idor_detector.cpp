/// @file idor_detector.cpp
/// @brief IDOR auto-detection: swaps numeric/UUID IDs and compares responses.
#include "idor_detector.hpp"

#include <algorithm>
#include <cmath>
#include <functional>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

IDORDetector::IDORDetector(HttpClient &http, const Config &cfg)
    : http_(http), cfg_(cfg) {}

std::vector<Finding> IDORDetector::detect(const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::set<std::string> tested_patterns;

  for (const auto &url : crawl.urls) {
    auto ids = extract_ids(url);
    if (ids.empty()) continue;

    for (const auto &id_match : ids) {
      // Create a pattern key to avoid testing same URL pattern twice
      std::string pattern_key = url.substr(0, id_match.start_pos) + "ID" +
                                url.substr(id_match.start_pos + id_match.length);
      if (tested_patterns.count(pattern_key)) continue;
      tested_patterns.insert(pattern_key);

      // Get baseline response with original ID
      auto baseline = http_.get(url);
      if (baseline.status_code == 0 || baseline.status_code >= 400) continue;

      // Generate test IDs
      std::vector<std::string> test_ids;
      if (id_match.is_uuid) {
        // For UUIDs, try common test patterns
        test_ids = {
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111"};
      } else {
        // For numeric IDs, try adjacent and common values
        long orig_val = 0;
        try {
          orig_val = std::stol(id_match.original_id);
        } catch (...) {
          continue;
        }
        test_ids.push_back(std::to_string(orig_val + 1));
        test_ids.push_back(std::to_string(orig_val - 1));
        if (orig_val != 1) test_ids.push_back("1");
        if (orig_val != 2) test_ids.push_back("2");
        test_ids.push_back(std::to_string(orig_val + 100));
      }

      for (const auto &test_id : test_ids) {
        std::string test_url = replace_id(url, id_match, test_id);
        auto test_resp = http_.get(test_url);

        // Skip if we get 404/403 (properly protected)
        if (test_resp.status_code == 404 || test_resp.status_code == 403 ||
            test_resp.status_code == 401 || test_resp.status_code == 0)
          continue;

        // If we get a 200 with different content, potential IDOR
        if (test_resp.status_code == 200 &&
            responses_differ_significantly(baseline, test_resp)) {
          Finding f;
          f.type = "IDOR";
          f.severity = "high";
          f.url = url;
          f.detail = "Possible IDOR: accessing " + test_url +
                     " returns different user data without auth change. "
                     "Original ID: " + id_match.original_id +
                     ", Test ID: " + test_id;
          f.param = id_match.original_id;
          f.payload = test_id;
          f.evidence = "Status: " + std::to_string(test_resp.status_code) +
                       ", Response size: " + std::to_string(test_resp.body.size()) +
                       " vs " + std::to_string(baseline.body.size());
          f.confidence = 70;
          f.cwe_id = "CWE-639";
          f.owasp_category = "A01:2021 Broken Access Control";
          f.cvss_score = 7.5;
          findings.push_back(f);
          break; // One finding per pattern is enough
        }
      }
    }
  }

  // Also test parameters that look like IDs
  for (const auto &param : crawl.params) {
    if (param.name == "id" || param.name == "user_id" || param.name == "uid" ||
        param.name == "userId" || param.name == "account_id" ||
        param.name == "order_id" || param.name == "orderId" ||
        param.name == "profile_id") {
      // Test with different ID values via the URL
      std::string test_url = param.url;
      // Append or modify the parameter
      std::string sep = (test_url.find('?') != std::string::npos) ? "&" : "?";

      auto baseline = http_.get(test_url);
      if (baseline.status_code == 0 || baseline.status_code >= 400) continue;

      std::vector<std::string> test_vals = {"1", "2", "999", "0"};
      for (const auto &val : test_vals) {
        std::string modified = test_url + sep + param.name + "=" + val;
        auto resp = http_.get(modified);
        if (resp.status_code == 200 &&
            responses_differ_significantly(baseline, resp)) {
          Finding f;
          f.type = "IDOR";
          f.severity = "high";
          f.url = test_url;
          f.detail = "IDOR via parameter '" + param.name +
                     "': changing value to " + val +
                     " returns different data without authorization check";
          f.param = param.name;
          f.payload = val;
          f.evidence = "Size diff: " + std::to_string(baseline.body.size()) +
                       " → " + std::to_string(resp.body.size());
          f.confidence = 65;
          f.cwe_id = "CWE-639";
          f.owasp_category = "A01:2021 Broken Access Control";
          f.cvss_score = 7.5;
          findings.push_back(f);
          break;
        }
      }
    }
  }

  return findings;
}

std::vector<IDORDetector::IDMatch>
IDORDetector::extract_ids(const std::string &url) {
  std::vector<IDMatch> matches;

  // Numeric IDs in path segments: /users/123, /api/v1/orders/456
  static const std::regex numeric_id(R"(/(\d{1,10})(?:/|$|\?))");
  std::sregex_iterator it(url.begin(), url.end(), numeric_id);
  std::sregex_iterator end;
  for (; it != end; ++it) {
    IDMatch m;
    m.url = url;
    m.original_id = (*it)[1].str();
    m.start_pos = static_cast<size_t>((*it).position(1));
    m.length = m.original_id.length();
    m.is_uuid = false;
    // Skip common non-ID patterns like /v1/, /v2/, /api/
    if (m.original_id.length() == 1 && m.start_pos > 0) {
      size_t slash_before = url.rfind('/', m.start_pos - 1);
      if (slash_before != std::string::npos) {
        std::string segment = url.substr(slash_before + 1,
                                         m.start_pos - slash_before - 1);
        if (segment == "v" || segment == "api") continue;
      }
    }
    matches.push_back(m);
  }

  // UUID patterns: /users/550e8400-e29b-41d4-a716-446655440000
  static const std::regex uuid_pattern(
      R"(([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))");
  std::sregex_iterator uid_it(url.begin(), url.end(), uuid_pattern);
  for (; uid_it != end; ++uid_it) {
    IDMatch m;
    m.url = url;
    m.original_id = (*uid_it)[1].str();
    m.start_pos = static_cast<size_t>((*uid_it).position(1));
    m.length = m.original_id.length();
    m.is_uuid = true;
    matches.push_back(m);
  }

  return matches;
}

std::string IDORDetector::replace_id(const std::string &url,
                                     const IDMatch &match,
                                     const std::string &new_id) {
  return url.substr(0, match.start_pos) + new_id +
         url.substr(match.start_pos + match.length);
}

bool IDORDetector::responses_differ_significantly(const Response &r1,
                                                  const Response &r2) {
  // Same response = no IDOR (same data for different IDs)
  if (r1.body == r2.body) return false;

  // Completely different sizes suggest different objects
  if (r1.body.empty() || r2.body.empty()) return true;

  double size_ratio = static_cast<double>(r1.body.size()) /
                      static_cast<double>(r2.body.size());
  // If sizes are very similar (within 5%), content might just be timestamps
  // If sizes are very different, likely different objects
  if (size_ratio < 0.5 || size_ratio > 2.0) return true;

  // Hash comparison — different hashes with similar size = different data
  size_t h1 = hash_body(r1.body);
  size_t h2 = hash_body(r2.body);
  if (h1 != h2) {
    // Check if it's just dynamic content (timestamps, nonces)
    // If more than 20% of content differs, likely IDOR
    size_t diff_count = 0;
    size_t min_len = std::min(r1.body.size(), r2.body.size());
    size_t check_len = std::min(min_len, static_cast<size_t>(2048));
    for (size_t i = 0; i < check_len; ++i) {
      if (r1.body[i] != r2.body[i]) ++diff_count;
    }
    double diff_ratio = static_cast<double>(diff_count) / static_cast<double>(check_len);
    return diff_ratio > 0.15;
  }

  return false;
}

size_t IDORDetector::hash_body(const std::string &body) {
  return std::hash<std::string>{}(body);
}

} // namespace apex
