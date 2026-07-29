#pragma once
/// @file spa_crawler.hpp
/// @brief Deep SPA/JavaScript crawler for route and API endpoint discovery.
#ifndef APEX_SPA_CRAWLER_HPP
#define APEX_SPA_CRAWLER_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include <string>
#include <vector>

namespace apex {

/// Parses JavaScript files for client-side routes (React Router, Vue Router,
/// Angular), API endpoint calls, and webpack chunk manifests.
class SPACrawler {
public:
  explicit SPACrawler(HttpClient &http, const Config &cfg);

  /// Deep crawl a SPA application, extending initial crawl results.
  CrawlResult deep_crawl(const std::string &base_url,
                         const CrawlResult &initial);

private:
  struct RouteInfo {
    std::string path;
    std::string component;
    std::string framework; // react, vue, angular
  };

  std::vector<RouteInfo> extract_routes(const std::string &js_content);
  std::vector<std::string> extract_api_calls(const std::string &js_content);
  std::vector<std::string> extract_webpack_chunks(const std::string &js_content,
                                                  const std::string &base_url);
  std::vector<std::string> find_js_urls(const CrawlResult &crawl,
                                        const std::string &base_url);
  std::string normalize_url(const std::string &base, const std::string &path);

  HttpClient &http_;
  const Config &cfg_;
};

} // namespace apex

#endif // APEX_SPA_CRAWLER_HPP
