#pragma once
/// @file api_schema.hpp
/// @brief API Schema Exploiter — discovers and tests OpenAPI/Swagger endpoints.
#ifndef APEX_API_SCHEMA_HPP
#define APEX_API_SCHEMA_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Fetches API schema definitions (Swagger/OpenAPI) and tests endpoints
/// for unauthorized access, mass assignment, and hidden functionality.
class APISchemaExploiter {
public:
  explicit APISchemaExploiter(HttpClient &http, const Config &cfg);

  /// Exploit discovered API schemas.
  std::vector<Finding> exploit(const CrawlResult &crawl);

private:
  struct Endpoint {
    std::string path;
    std::string method;
    std::vector<std::string> parameters;
    bool requires_auth = false;
  };

  std::vector<Endpoint> parse_schema(const std::string &json_body,
                                     const std::string &base_url);
  std::vector<Finding> test_endpoint(const Endpoint &ep,
                                     const std::string &base_url);
  std::string extract_base_url(const std::string &url);
  std::string simple_json_value(const std::string &json, const std::string &key);

  HttpClient &http_;
  const Config &cfg_;

  static const std::vector<std::string> schema_paths_;
};

} // namespace apex

#endif // APEX_API_SCHEMA_HPP
