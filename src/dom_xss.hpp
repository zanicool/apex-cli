#pragma once
/// @file dom_xss.hpp
/// @brief DOM-based XSS detection engine via source-sink analysis.
#ifndef APEX_DOM_XSS_HPP
#define APEX_DOM_XSS_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Analyzes JavaScript source code for DOM XSS vulnerabilities by
/// identifying dangerous sources flowing to sinks without sanitization.
class DOMXSSDetector {
public:
  explicit DOMXSSDetector(HttpClient &http, const Config &cfg);

  /// Detect DOM XSS vulnerabilities in JS files from crawl results.
  std::vector<Finding> detect(const CrawlResult &crawl);

private:
  struct SourceMatch {
    std::string source_type;
    size_t line_number;
    std::string context;
  };

  struct SinkMatch {
    std::string sink_type;
    size_t line_number;
    std::string context;
  };

  struct DOMXSSFlow {
    SourceMatch source;
    SinkMatch sink;
    std::string function_context;
  };

  std::vector<std::string> find_js_urls(const CrawlResult &crawl);
  std::vector<SourceMatch> find_sources(const std::string &js_content);
  std::vector<SinkMatch> find_sinks(const std::string &js_content);
  std::vector<DOMXSSFlow> correlate_flows(const std::vector<SourceMatch> &sources,
                                          const std::vector<SinkMatch> &sinks,
                                          const std::string &js_content);
  bool has_sanitization(const std::string &content, size_t source_line,
                        size_t sink_line);

  HttpClient &http_;
  const Config &cfg_;
};

} // namespace apex

#endif // APEX_DOM_XSS_HPP
