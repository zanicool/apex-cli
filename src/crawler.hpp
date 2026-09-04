/// @file crawler.hpp
/// @brief Web crawler: link extraction, form/parameter discovery, scope enforcement.
#ifndef APEX_CRAWLER_HPP
#define APEX_CRAWLER_HPP

#include "config.hpp"
#include "http.hpp"
#include <string>
#include <vector>

namespace apex {

/// A discovered parameter (query string or form field).
struct Parameter {
  std::string url;
  std::string name;
  std::string type;   // query, body
  std::string method; // GET, POST
};

/// A discovered HTML form.
struct Form {
  std::string action;
  std::string method;
  std::vector<Parameter> fields;
};

/// Full crawl result passed to scanners.
struct CrawlResult {
  std::vector<std::string> urls;
  std::vector<Parameter> params;
  std::vector<Form> forms;
};

/// Run the crawler starting from seed URLs.
CrawlResult run_crawler(const Config &cfg, HttpClient &http,
                         const std::vector<std::string> &seeds);

/// Check if a URL is within the configured scope.
bool in_scope(const std::string &url, const Config &cfg);

/// Resolve a possibly-relative href against a page URL. Exposed for testing:
/// correctly treats "/fetch?url=http://x" as RELATIVE (":// only counts as a
/// scheme when it precedes the first '/','?','#').
std::string resolve_url(const std::string &href, const std::string &page_url);

} // namespace apex

#endif // APEX_CRAWLER_HPP
