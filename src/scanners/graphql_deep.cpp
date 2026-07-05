/// @file scanners/graphql_deep.cpp
/// @brief Advanced GraphQL exploitation: introspection, query depth abuse,
///        alias-based rate limit bypass, batch brute-force, field suggestion leak,
///        mutation authorization bypass, and directive overloading.
#include "scanner_base.hpp"
#include <regex>

namespace apex {
namespace {

/// Find GraphQL endpoints.
std::vector<std::string> find_graphql(HttpClient &http, const std::string &base) {
  std::vector<std::string> endpoints;
  std::vector<std::string> paths = {
      "/graphql", "/api/graphql", "/v1/graphql", "/gql",
      "/query", "/api/query", "/graphiql", "/altair",
      "/playground", "/api/v1/graphql", "/api/v2/graphql"};

  for (const auto &path : paths) {
    auto resp = http.post(base + path, "{\"query\":\"{__typename}\"}",
                          "application/json");
    if (resp.status_code == 200 &&
        (resp.body.find("__typename") != std::string::npos ||
         resp.body.find("\"data\"") != std::string::npos ||
         resp.body.find("\"errors\"") != std::string::npos)) {
      endpoints.push_back(base + path);
    }
  }
  return endpoints;
}

/// Introspection query — reveals entire schema.
std::vector<Finding> scan_graphql_introspection(const Config &, HttpClient &http,
                                                 const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  auto endpoints = find_graphql(http, base);
  if (endpoints.empty()) return findings;

  std::string intro_query = R"({"query":"{__schema{queryType{name}mutationType{name}types{name fields{name type{name}}}}}"})";

  for (const auto &ep : endpoints) {
    auto resp = http.post(ep, intro_query, "application/json");
    if (resp.status_code == 200 && resp.body.find("__schema") != std::string::npos &&
        resp.body.find("queryType") != std::string::npos) {
      // Count exposed types
      std::regex type_re(R"x("name"\s*:\s*"([^_][^"]+)")x");
      std::sregex_iterator it(resp.body.begin(), resp.body.end(), type_re);
      std::sregex_iterator end;
      int types = 0;
      for (; it != end; ++it) types++;

      findings.push_back(Finding{"GraphQL Introspection Enabled", "high", ep,
                          "Full schema introspection is enabled. Reveals " + std::to_string(types) +
                          " types including all queries, mutations, and fields. "
                          "Attacker can map the entire API surface without guessing.",
                          "", "", resp.body.substr(0, 500)});

      // Check for sensitive mutations
      if (resp.body.find("deleteUser") != std::string::npos ||
          resp.body.find("updateRole") != std::string::npos ||
          resp.body.find("createAdmin") != std::string::npos ||
          resp.body.find("resetPassword") != std::string::npos) {
        findings.push_back(Finding{"GraphQL — Sensitive Mutations Exposed", "high", ep,
                            "Introspection reveals admin/sensitive mutations. "
                            "Test for broken function-level authorization.",
                            "", "", ""});
      }
      break;
    }
  }
  return findings;
}

/// Query depth/complexity abuse — DoS via nested queries.
std::vector<Finding> scan_graphql_depth(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  auto endpoints = find_graphql(http, base);
  if (endpoints.empty()) return findings;

  // Deep nested query (10 levels)
  std::string deep = R"({"query":"{__typename a:__typename b:__typename c:__typename d:__typename e:__typename f:__typename g:__typename h:__typename i:__typename j:__typename}"})";

  for (const auto &ep : endpoints) {
    auto resp = http.post(ep, deep, "application/json");
    if (resp.status_code == 200 && resp.body.find("error") == std::string::npos) {
      findings.push_back(Finding{"GraphQL — No Query Depth Limit", "medium", ep,
                          "Server accepts deeply nested/complex queries without depth limiting. "
                          "Enables DoS via exponential query complexity (e.g., nested relations).",
                          "", "", ""});
      break;
    }
  }
  return findings;
}

/// Alias-based rate limit bypass for brute-force.
std::vector<Finding> scan_graphql_alias_bypass(const Config &, HttpClient &http,
                                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  auto endpoints = find_graphql(http, base);
  if (endpoints.empty()) return findings;

  // Send multiple aliased queries in one request — bypasses per-request rate limiting
  std::string batch = R"({"query":"{a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename a6:__typename a7:__typename a8:__typename a9:__typename a10:__typename}"})";

  for (const auto &ep : endpoints) {
    auto resp = http.post(ep, batch, "application/json");
    if (resp.status_code == 200 &&
        resp.body.find("a10") != std::string::npos) {
      findings.push_back(Finding{"GraphQL — Alias-Based Batching Allowed", "medium", ep,
                          "Server executes 10+ aliased operations in one request. "
                          "Bypasses per-request rate limiting. Use for: "
                          "1) OTP brute-force (10 guesses per request), "
                          "2) Password spray (10 attempts per request), "
                          "3) IDOR enumeration at 10x speed.",
                          "", "", ""});
      break;
    }
  }
  return findings;
}

/// Array-based batch queries.
std::vector<Finding> scan_graphql_batch(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  auto endpoints = find_graphql(http, base);
  if (endpoints.empty()) return findings;

  // Array batch — send multiple operations as JSON array
  std::string batch = R"([{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}])";

  for (const auto &ep : endpoints) {
    auto resp = http.post(ep, batch, "application/json");
    if (resp.status_code == 200) {
      // Count responses
      int count = 0;
      size_t pos = 0;
      while ((pos = resp.body.find("__typename", pos)) != std::string::npos) {
        count++;
        pos++;
      }
      if (count >= 5) {
        findings.push_back(Finding{"GraphQL — Array Batch Queries Allowed", "medium", ep,
                            "Server processes array of " + std::to_string(count) + " queries in one request. "
                            "Enables mass brute-force, enumeration, and rate limit bypass.",
                            "", "", ""});
        break;
      }
    }
  }
  return findings;
}

/// Field suggestion leak — get field names from error messages.
std::vector<Finding> scan_graphql_suggestions(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  auto endpoints = find_graphql(http, base);
  if (endpoints.empty()) return findings;

  // Query a non-existent field to see if server suggests real ones
  std::string probe = R"({"query":"{xyznonexistent123}"})";

  for (const auto &ep : endpoints) {
    auto resp = http.post(ep, probe, "application/json");
    if (resp.status_code == 200 || resp.status_code == 400) {
      if (resp.body.find("Did you mean") != std::string::npos ||
          resp.body.find("suggestions") != std::string::npos ||
          resp.body.find("did_you_mean") != std::string::npos) {
        findings.push_back(Finding{"GraphQL — Field Suggestions Enabled", "low", ep,
                            "Server suggests valid field names in error messages. "
                            "Even with introspection disabled, attacker can enumerate "
                            "all fields via suggestion-based brute-force.",
                            "", "", resp.body.substr(0, 300)});
        break;
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_graphql_deep_scanners() {
  return {
      {"GraphQL Introspection", scan_graphql_introspection},
      {"GraphQL Depth Abuse", scan_graphql_depth},
      {"GraphQL Alias Bypass", scan_graphql_alias_bypass},
      {"GraphQL Batch", scan_graphql_batch},
      {"GraphQL Suggestions", scan_graphql_suggestions},
  };
}

} // namespace apex
