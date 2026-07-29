#pragma once
/// @file header_inject.hpp
/// @brief HTTP Header Injection & Smuggling Engine.
#ifndef APEX_HEADER_INJECT_HPP
#define APEX_HEADER_INJECT_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Tests CRLF injection, host header attacks, request smuggling indicators,
/// and cache poisoning via unkeyed headers.
class HeaderInjector {
public:
  /// Run all header injection tests.
  std::vector<Finding> test(const CrawlResult &crawl, HttpClient &http,
                            const Config &cfg);

private:
  std::vector<Finding> test_crlf_injection(const CrawlResult &crawl,
                                           HttpClient &http, const Config &cfg);
  std::vector<Finding> test_host_header_injection(const CrawlResult &crawl,
                                                  HttpClient &http,
                                                  const Config &cfg);
  std::vector<Finding> test_request_smuggling(const CrawlResult &crawl,
                                              HttpClient &http,
                                              const Config &cfg);
  std::vector<Finding> test_cache_poisoning(const CrawlResult &crawl,
                                            HttpClient &http, const Config &cfg);

  bool header_reflected(const Response &resp, const std::string &header_name,
                        const std::string &header_value);
};

} // namespace apex

#endif // APEX_HEADER_INJECT_HPP
