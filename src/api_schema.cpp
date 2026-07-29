/// @file api_schema.cpp
/// @brief API Schema Exploiter: fetches Swagger/OpenAPI and tests endpoints.
#include "api_schema.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

const std::vector<std::string> APISchemaExploiter::schema_paths_ = {
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/swagger.json",
    "/docs/api.json",
    "/.well-known/openapi.json",
    "/swagger-ui/swagger.json",
    "/api/v1/swagger.json",
    "/swagger/docs/v1"};

APISchemaExploiter::APISchemaExploiter(HttpClient &http, const Config &cfg)
    : http_(http), cfg_(cfg) {}

std::vector<Finding> APISchemaExploiter::exploit(const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::set<std::string> tested_endpoints;

  // Extract base URL from crawl
  std::string base_url;
  if (!crawl.urls.empty()) {
    base_url = extract_base_url(crawl.urls[0]);
  } else {
    base_url = cfg_.target;
  }
  // Normalize: remove trailing slash
  if (!base_url.empty() && base_url.back() == '/') base_url.pop_back();

  // Try to fetch API schema from known paths
  std::vector<Endpoint> all_endpoints;

  for (const auto &path : schema_paths_) {
    std::string schema_url = base_url + path;
    auto resp = http_.get(schema_url);

    if (resp.status_code == 200 && !resp.body.empty()) {
      // Found a schema! Report it as info finding
      Finding schema_found;
      schema_found.type = "API Schema Exposed";
      schema_found.severity = "medium";
      schema_found.url = schema_url;
      schema_found.detail = "API schema/documentation publicly accessible at " +
                            path + " (" + std::to_string(resp.body.size()) + " bytes)";
      schema_found.evidence = resp.body.substr(0, 200);
      schema_found.confidence = 95;
      schema_found.cwe_id = "CWE-200";
      schema_found.owasp_category = "A01:2021 Broken Access Control";
      schema_found.cvss_score = 5.3;
      findings.push_back(schema_found);

      // Parse endpoints from schema
      auto endpoints = parse_schema(resp.body, base_url);
      all_endpoints.insert(all_endpoints.end(), endpoints.begin(),
                           endpoints.end());
    }
  }

  // Test each discovered endpoint
  for (const auto &ep : all_endpoints) {
    std::string ep_key = ep.method + ":" + ep.path;
    if (tested_endpoints.count(ep_key)) continue;
    tested_endpoints.insert(ep_key);

    auto ep_findings = test_endpoint(ep, base_url);
    findings.insert(findings.end(), ep_findings.begin(), ep_findings.end());
  }

  return findings;
}

std::vector<APISchemaExploiter::Endpoint>
APISchemaExploiter::parse_schema(const std::string &json_body,
                                 const std::string &base_url) {
  std::vector<Endpoint> endpoints;

  // Simple JSON path extraction using regex (no JSON library dependency)
  // Look for "paths" object entries like "/api/users": { "get": {}, "post": {} }

  // Extract path entries
  static const std::regex path_regex(
      R"re("(/[^"]*)"[\s]*:[\s]*\{([^}]*(?:\{[^}]*\}[^}]*)*)\})re");
  static const std::regex method_regex(
      R"re("(get|post|put|delete|patch|options|head)"[\s]*:)re");
  static const std::regex param_regex(
      R"re("name"[\s]*:[\s]*"([^"]+)")re");
  static const std::regex security_regex(
      R"re("security"[\s]*:)re");

  std::sregex_iterator path_it(json_body.begin(), json_body.end(), path_regex);
  std::sregex_iterator end;

  for (; path_it != end; ++path_it) {
    std::string path = (*path_it)[1].str();
    std::string path_body = (*path_it)[2].str();

    // Find methods within this path
    std::sregex_iterator method_it(path_body.begin(), path_body.end(),
                                   method_regex);
    for (; method_it != end; ++method_it) {
      Endpoint ep;
      ep.path = path;
      ep.method = (*method_it)[1].str();
      std::transform(ep.method.begin(), ep.method.end(), ep.method.begin(),
                     ::toupper);

      // Extract parameters
      std::sregex_iterator param_it(path_body.begin(), path_body.end(),
                                    param_regex);
      for (; param_it != end; ++param_it) {
        ep.parameters.push_back((*param_it)[1].str());
      }

      // Check if security is required
      ep.requires_auth = std::regex_search(path_body, security_regex);

      endpoints.push_back(ep);
    }

    // If no explicit methods found, assume GET
    if (!std::regex_search(path_body, method_regex)) {
      Endpoint ep;
      ep.path = path;
      ep.method = "GET";
      ep.requires_auth = std::regex_search(path_body, security_regex);
      endpoints.push_back(ep);
    }
  }

  // Also try to find paths in a flat format: "paths": { ... }
  // Look for simple endpoint patterns
  static const std::regex simple_path(R"re("(/api[^"]+)")re");  if (endpoints.empty()) {
    std::sregex_iterator sp_it(json_body.begin(), json_body.end(), simple_path);
    for (; sp_it != end; ++sp_it) {
      Endpoint ep;
      ep.path = (*sp_it)[1].str();
      ep.method = "GET";
      endpoints.push_back(ep);
    }
  }

  return endpoints;
}

std::vector<Finding>
APISchemaExploiter::test_endpoint(const Endpoint &ep,
                                  const std::string &base_url) {
  std::vector<Finding> findings;

  // Replace path parameters with test values
  std::string test_path = ep.path;
  static const std::regex param_placeholder(R"re(\{([^}]+)\})re");
  test_path = std::regex_replace(test_path, param_placeholder, "1");

  std::string full_url = base_url + test_path;

  // Test 1: Access without authentication
  if (ep.requires_auth) {
    Response resp;
    if (ep.method == "GET") {
      resp = http_.get(full_url);
    } else if (ep.method == "POST") {
      resp = http_.post(full_url, "{}", "application/json");
    } else if (ep.method == "PUT") {
      resp = http_.post(full_url, "{}", "application/json");
    } else if (ep.method == "DELETE") {
      resp = http_.get(full_url); // Simplified
    } else {
      resp = http_.get(full_url);
    }

    if (resp.status_code == 200 || resp.status_code == 201) {
      Finding f;
      f.type = "Broken Authentication";
      f.severity = "high";
      f.url = full_url;
      f.detail = "Endpoint " + ep.method + " " + ep.path +
                 " marked as requiring auth but accessible without credentials";
      f.evidence = "Status: " + std::to_string(resp.status_code) +
                   ", Body: " + resp.body.substr(0, 200);
      f.confidence = 80;
      f.cwe_id = "CWE-306";
      f.owasp_category = "A07:2021 Identification and Authentication Failures";
      f.cvss_score = 7.5;
      findings.push_back(f);
    }
  }

  // Test 2: Mass assignment — POST with extra fields
  if (ep.method == "POST" || ep.method == "PUT") {
    std::string mass_assign_body =
        R"({"role":"admin","is_admin":true,"isAdmin":true,"admin":1,"privilege":"superuser"})";
    auto resp = http_.post(full_url, mass_assign_body, "application/json");

    if (resp.status_code == 200 || resp.status_code == 201) {
      // Check if response contains our injected fields
      if (resp.body.find("admin") != std::string::npos &&
          resp.body.find("true") != std::string::npos) {
        Finding f;
        f.type = "Mass Assignment";
        f.severity = "high";
        f.url = full_url;
        f.detail = "Endpoint " + ep.method + " " + ep.path +
                   " may accept privilege escalation fields (role, is_admin)";
        f.payload = mass_assign_body;
        f.evidence = resp.body.substr(0, 300);
        f.confidence = 55;
        f.cwe_id = "CWE-915";
        f.owasp_category = "A04:2021 Insecure Design";
        f.cvss_score = 8.1;
        findings.push_back(f);
      }
    }
  }

  // Test 3: Hidden/undocumented HTTP methods
  if (ep.method == "GET") {
    auto del_resp = http_.get(full_url); // Would need DELETE support
    auto post_resp = http_.post(full_url, "{}", "application/json");

    if (post_resp.status_code == 200 || post_resp.status_code == 201 ||
        post_resp.status_code == 204) {
      Finding f;
      f.type = "Undocumented Method";
      f.severity = "medium";
      f.url = full_url;
      f.detail = "Endpoint documented as GET-only but accepts POST requests";
      f.evidence = "POST returned status " + std::to_string(post_resp.status_code);
      f.confidence = 60;
      f.cwe_id = "CWE-749";
      f.owasp_category = "A04:2021 Insecure Design";
      f.cvss_score = 5.3;
      findings.push_back(f);
    }
  }

  return findings;
}

std::string APISchemaExploiter::extract_base_url(const std::string &url) {
  // Extract scheme + host from URL
  static const std::regex base_regex(R"((https?://[^/]+))");
  std::smatch m;
  if (std::regex_search(url, m, base_regex)) {
    return m[1].str();
  }
  return url;
}

std::string APISchemaExploiter::simple_json_value(const std::string &json,
                                                  const std::string &key) {
  std::string search = "\"" + key + "\"";
  auto pos = json.find(search);
  if (pos == std::string::npos) return "";

  pos = json.find(':', pos + search.size());
  if (pos == std::string::npos) return "";

  pos = json.find('"', pos + 1);
  if (pos == std::string::npos) return "";

  auto end = json.find('"', pos + 1);
  if (end == std::string::npos) return "";

  return json.substr(pos + 1, end - pos - 1);
}

} // namespace apex
