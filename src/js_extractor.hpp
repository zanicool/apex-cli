#pragma once
/// @file js_extractor.hpp
/// @brief JavaScript secret and sensitive data extractor.
#ifndef APEX_JS_EXTRACTOR_HPP
#define APEX_JS_EXTRACTOR_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Downloads JavaScript files and scans for hardcoded secrets,
/// API keys, internal URLs, credentials, and source maps.
class JSExtractor {
public:
  explicit JSExtractor(HttpClient &http, const Config &cfg);

  /// Extract secrets from all JS files found in crawl results.
  std::vector<Finding> extract(const CrawlResult &crawl);

private:
  struct SecretPattern {
    std::string name;
    std::string regex;
    std::string severity;
    std::string cwe;
  };

  std::vector<std::string> find_js_urls(const CrawlResult &crawl);
  std::vector<std::string> find_webpack_chunks(const std::string &js_content,
                                               const std::string &base_url);
  std::vector<Finding> scan_js_content(const std::string &url,
                                       const std::string &content);
  std::string resolve_url(const std::string &base, const std::string &relative);

  HttpClient &http_;
  const Config &cfg_;

  static const std::vector<SecretPattern> patterns_;
};

} // namespace apex

#endif // APEX_JS_EXTRACTOR_HPP
