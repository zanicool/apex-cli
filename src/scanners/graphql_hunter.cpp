/// @file graphql_hunter.cpp
/// @brief Auto-discover GraphQL endpoints, enumerate schema via errors, fuzz mutations.
#include <set>
#include <string>
#include <vector>

#include "scanner_base.hpp"

namespace apex {

static std::vector<Finding> scan_graphql_hunter(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;

  // Generate subdomain prefixes to try
  std::vector<std::string> prefixes = {
      "api.", "api.dev.", "api.stage.", "api.staging.", "api.test.", "graphql.", "gql.", "dev.", "staging.", "stage.", "internal.",
  };

  // GraphQL paths to try on each host
  std::vector<std::string> gql_paths = {
      "/graphql/", "/graphql", "/api/graphql/", "/api/graphql", "/gql/", "/gql", "/query", "/v1/graphql",
  };

  std::set<std::string> tested;

  // Test main domain + subdomain prefixes
  std::vector<std::string> hosts;
  hosts.push_back(domain);
  for (const auto& prefix : prefixes) {
    hosts.push_back(prefix + domain);
  }

  for (const auto& host : hosts) {
    for (const auto& path : gql_paths) {
      std::string url = "https://" + host + path;
      if (!tested.insert(url).second) continue;

      // Send a simple query
      auto resp = http.post(url, "{\"query\":\"{ __typename }\"}", "application/json");
      if (resp.status_code == 0 || resp.status_code == 404 || resp.status_code == 403) continue;
      if (resp.body.find("__typename") == std::string::npos && resp.body.find("errors") == std::string::npos &&
          resp.body.find("data") == std::string::npos && resp.body.find("invalid") == std::string::npos)
        continue;

      // GraphQL endpoint found!
      bool has_introspection = false;
      bool has_unauth_queries = false;
      std::vector<std::string> exposed_mutations;

      // Test introspection
      auto intro_resp = http.post(url, "{\"query\":\"{ __schema { queryType { name } } }\"}", "application/json");
      if (intro_resp.body.find("queryType") != std::string::npos) {
        has_introspection = true;
        findings.push_back({"GraphQL Introspection Enabled", "high", url, "", "Full schema exposed via introspection", "", ""});
      }

      // Test unauthenticated user query
      auto users_resp = http.post(url, "{\"query\":\"{ users(first:1) { edges { node { id username } } } }\"}", "application/json");
      if (users_resp.body.find("\"data\"") != std::string::npos && users_resp.body.find("username") != std::string::npos) {
        has_unauth_queries = true;
        findings.push_back({"GraphQL User Enumeration (No Auth)", "medium", url, "Users query returns data without authentication", "", "",
                            users_resp.body.substr(0, 200)});
      }

      // Fuzz mutations
      std::vector<std::string> mutations = {
          "createListing", "updateListing", "deleteListing", "createOrder",   "cancelOrder",    "updateOrder",
          "followUser",    "unfollowUser",  "blockUser",     "updateProfile", "changePassword", "resetPassword",
          "createAuction", "placeBid",      "cancelBid",     "withdraw",      "transfer",       "addPaymentMethod",
          "sendMessage",   "deleteMessage", "createStream",  "startStream",   "endStream",
      };

      for (const auto& mut : mutations) {
        std::string query = "{\"query\":\"mutation { " + mut + " }\"}";
        auto mut_resp = http.post(url, query, "application/json");
        // If it doesn't say "Cannot query field" it exists
        if (mut_resp.body.find("Cannot query field") == std::string::npos &&
            mut_resp.body.find("must have a selection") != std::string::npos) {
          exposed_mutations.push_back(mut);
        }
      }

      if (!exposed_mutations.empty()) {
        std::string detail = "Mutations accessible without auth: ";
        for (size_t i = 0; i < exposed_mutations.size(); i++) {
          if (i > 0) detail += ", ";
          detail += exposed_mutations[i];
        }
        std::string sev = "high";
        // Critical if financial mutations exposed
        for (const auto& m : exposed_mutations) {
          if (m == "withdraw" || m == "transfer" || m == "changePassword" || m == "createOrder") {
            sev = "critical";
            break;
          }
        }
        findings.push_back({"GraphQL Mutations Without Auth", sev, url, detail, "", "", ""});
      }

      // If we found anything, report the endpoint itself
      if (!has_introspection && !has_unauth_queries && exposed_mutations.empty()) {
        // Just report the endpoint exists
        findings.push_back({"GraphQL Endpoint Discovered", "info", url, "GraphQL endpoint responds to queries", "", "", ""});
      }
    }
  }

  return findings;
}

std::vector<Scanner> register_graphql_hunter() { return {{"GraphQL Hunter", scan_graphql_hunter}}; }

}  // namespace apex
