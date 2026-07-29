#pragma once
/// @file race_engine.hpp
/// @brief Race Condition Exploitation Engine — detects TOCTOU and double-spend.
#ifndef APEX_RACE_ENGINE_HPP
#define APEX_RACE_ENGINE_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Sends concurrent identical requests to detect race conditions:
/// double-spend, limit bypass, TOCTOU vulnerabilities.
class RaceEngine {
public:
  /// Test all forms/POST endpoints for race conditions.
  std::vector<Finding> test_races(const CrawlResult &crawl, HttpClient &http,
                                  const Config &cfg);

private:
  struct RaceResult {
    int total_sent;
    int success_count;
    int unique_responses;
    std::vector<int> status_codes;
    std::vector<std::string> bodies;
  };

  RaceResult fire_concurrent(HttpClient &http, const std::string &url,
                             const std::string &body,
                             const std::string &content_type, int count);
  std::vector<Finding> test_form_races(const CrawlResult &crawl,
                                       HttpClient &http, const Config &cfg);
  std::vector<Finding> test_account_creation_race(HttpClient &http,
                                                  const Config &cfg);
  bool indicates_success(const Response &resp);
};

} // namespace apex

#endif // APEX_RACE_ENGINE_HPP
