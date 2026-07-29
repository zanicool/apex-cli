#pragma once
/// @file auth_bypass.hpp
/// @brief Authentication Bypass Engine — tests auth weaknesses.
#ifndef APEX_AUTH_BYPASS_HPP
#define APEX_AUTH_BYPASS_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Tests authentication bypass vectors: JWT manipulation, verb tampering,
/// parameter pollution, IP spoofing, forced browsing.
class AuthBypass {
public:
  /// Run all auth bypass tests against crawled endpoints.
  std::vector<Finding> test(const CrawlResult &crawl, HttpClient &http,
                            const Config &cfg);

private:
  std::vector<Finding> test_forced_browsing(HttpClient &http, const Config &cfg);
  std::vector<Finding> test_verb_tampering(const CrawlResult &crawl,
                                           HttpClient &http, const Config &cfg);
  std::vector<Finding> test_param_pollution(const CrawlResult &crawl,
                                            HttpClient &http, const Config &cfg);
  std::vector<Finding> test_ip_spoofing(const CrawlResult &crawl,
                                        HttpClient &http, const Config &cfg);
  std::vector<Finding> test_jwt_bypass(const CrawlResult &crawl,
                                       HttpClient &http, const Config &cfg);
  std::vector<Finding> test_path_traversal_bypass(const CrawlResult &crawl,
                                                  HttpClient &http,
                                                  const Config &cfg);

  std::string extract_base_url(const std::string &url);
  bool is_protected_response(const Response &resp);
};

} // namespace apex

#endif // APEX_AUTH_BYPASS_HPP
