#pragma once
/// @file param_miner.hpp
/// @brief Hidden Parameter Discovery Engine (like Burp Param Miner).
#ifndef APEX_PARAM_MINER_HPP
#define APEX_PARAM_MINER_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Discovers hidden/debug parameters by injecting common param names and
/// detecting response changes (size, status, headers).
class ParamMiner {
public:
  /// Mine hidden parameters across all crawled URLs.
  std::vector<Finding> mine(const CrawlResult &crawl, HttpClient &http,
                            const Config &cfg);

private:
  struct BaselineResponse {
    int status_code;
    size_t body_size;
    std::string content_type;
    std::map<std::string, std::string> headers;
  };

  static std::vector<std::string> get_param_wordlist();
  BaselineResponse capture_baseline(HttpClient &http, const std::string &url);
  bool response_differs(const BaselineResponse &baseline, const Response &resp);
  std::vector<Finding> mine_query_params(const std::string &url,
                                         HttpClient &http);
  std::vector<Finding> mine_json_params(const std::string &url,
                                        HttpClient &http);
  std::vector<Finding> mine_header_params(const std::string &url,
                                          HttpClient &http);
};

} // namespace apex

#endif // APEX_PARAM_MINER_HPP
