/// @file scanners/api_discovery.cpp
/// @brief API surface discovery: finds exposed Swagger/OpenAPI docs, GraphQL
///        introspection, gRPC reflection, dev portals, API gateways, and
///        self-documenting endpoints that leak full API schemas.
#include "scanner_base.hpp"
#include <set>

namespace apex {
namespace {

/// Discover exposed OpenAPI/Swagger documentation endpoints.
std::vector<Finding> scan_openapi_exposure(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct DocEndpoint {
    const char *path;
    const char *indicator;
    const char *name;
  };
  const DocEndpoint endpoints[] = {
      // Swagger UI
      {"/swagger-ui.html", "swagger-ui", "Swagger UI"},
      {"/swagger-ui/", "swagger-ui", "Swagger UI"},
      {"/swagger/", "swagger-ui", "Swagger UI"},
      {"/api-docs", "swagger", "Swagger UI"},
      {"/api/docs", "swagger", "API Docs"},
      {"/docs", "openapi", "API Docs"},
      {"/docs/", "swagger", "API Docs"},
      // OpenAPI JSON/YAML specs
      {"/swagger.json", "\"paths\"", "OpenAPI Spec (JSON)"},
      {"/swagger.yaml", "paths:", "OpenAPI Spec (YAML)"},
      {"/openapi.json", "\"paths\"", "OpenAPI Spec (JSON)"},
      {"/openapi.yaml", "paths:", "OpenAPI Spec (YAML)"},
      {"/api/openapi.json", "\"paths\"", "OpenAPI Spec"},
      {"/v1/swagger.json", "\"paths\"", "OpenAPI v1 Spec"},
      {"/v2/swagger.json", "\"paths\"", "OpenAPI v2 Spec"},
      {"/v3/api-docs", "\"paths\"", "SpringDoc OpenAPI"},
      {"/api-docs/swagger.json", "\"paths\"", "Swagger Spec"},
      // Redoc
      {"/redoc", "redoc", "Redoc"},
      {"/api/redoc", "redoc", "Redoc"},
      // Scalar
      {"/scalar", "scalar", "Scalar API Docs"},
      {"/reference", "scalar", "Scalar API Reference"},
      // FastAPI
      {"/docs", "fastapi", "FastAPI Docs"},
      {"/redoc", "ReDoc", "FastAPI Redoc"},
      {"/openapi.json", "\"openapi\"", "FastAPI OpenAPI"},
      // Django REST Framework
      {"/api/", "api-root", "DRF Browsable API"},
      {"/api/schema/", "openapi", "DRF Schema"},
      // Laravel
      {"/api/documentation", "swagger", "Laravel Swagger"},
      // ASP.NET
      {"/swagger/v1/swagger.json", "\"paths\"", "ASP.NET Swagger"},
      // Spring Boot Actuator (bonus: exposes mappings)
      {"/actuator/mappings", "dispatcherServlet", "Spring Mappings"},
      {"/actuator/configprops", "contexts", "Spring Config Props"},
  };

  for (const auto &ep : endpoints) {
    auto resp = http.get(base + ep.path);
    if (resp.status_code == 200 && resp.body.size() > 100 &&
        resp.body.find(ep.indicator) != std::string::npos) {
      // Count endpoints if it's a spec file.
      std::string detail = std::string(ep.name) + " exposed";
      if (resp.body.find("\"paths\"") != std::string::npos) {
        size_t count = 0, pos = 0;
        while ((pos = resp.body.find("\"/", pos)) != std::string::npos) {
          count++; pos++;
        }
        if (count > 0) detail += " — ~" + std::to_string(count) + " endpoints mapped";
      }
      findings.push_back({"API Docs Exposed: " + std::string(ep.name), "high",
                          base + ep.path, detail, "", "", ""});
    }
  }
  return findings;
}

/// Discover exposed GraphQL endpoints and introspection.
std::vector<Finding> scan_graphql_discovery(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> gql_paths = {
      "/graphql", "/graphql/", "/api/graphql", "/v1/graphql",
      "/gql", "/query", "/graphql/v1", "/api/v1/graphql",
      "/graphql/console", "/playground", "/graphiql",
      "/altair", "/voyager", "/graphql-explorer",
  };

  const std::string introspection_query =
      R"({"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"})";

  for (const auto &path : gql_paths) {
    auto resp = http.post(base + path, introspection_query, "application/json");
    if (resp.status_code == 200 && resp.body.find("__schema") != std::string::npos) {
      // Count types.
      size_t types = 0, pos = 0;
      while ((pos = resp.body.find("\"name\"", pos)) != std::string::npos) {
        types++; pos++;
      }
      findings.push_back({"GraphQL Introspection", "high", base + path,
                          "Full schema exposed via introspection — " +
                              std::to_string(types) + " types discovered",
                          "", "", ""});
      break;
    }
    // Also check GET-based GraphQL explorers.
    auto get_resp = http.get(base + path);
    if (get_resp.status_code == 200 &&
        (get_resp.body.find("graphiql") != std::string::npos ||
         get_resp.body.find("GraphQL Playground") != std::string::npos ||
         get_resp.body.find("apollo-sandbox") != std::string::npos ||
         get_resp.body.find("voyager") != std::string::npos)) {
      findings.push_back({"GraphQL Explorer Exposed", "high", base + path,
                          "Interactive GraphQL explorer publicly accessible",
                          "", "", ""});
      break;
    }
  }
  return findings;
}

/// Discover API gateway and developer portal endpoints.
std::vector<Finding> scan_api_gateway(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct GatewayEndpoint {
    const char *path;
    const char *indicator;
    const char *gateway;
  };
  const GatewayEndpoint gateways[] = {
      // Kong
      {"/:8001/", "tagline", "Kong Admin API"},
      {"/:8001/routes", "data", "Kong Routes"},
      {"/:8001/services", "data", "Kong Services"},
      // Tyk
      {"/tyk/apis", "api_id", "Tyk API List"},
      // Gravitee
      {"/management/", "gravitee", "Gravitee Management"},
      // KrakenD
      {"/__debug/", "krakend", "KrakenD Debug"},
      {"/__health", "ok", "KrakenD Health"},
      // WSO2
      {"/carbon/", "WSO2", "WSO2 Admin"},
      {"/devportal/", "wso2", "WSO2 Dev Portal"},
      // Generic
      {"/portal/", "developer", "Developer Portal"},
      {"/developer/", "api", "Developer Portal"},
      {"/api-portal/", "api", "API Portal"},
      {"/api/explorer", "api", "API Explorer"},
  };

  for (const auto &gw : gateways) {
    std::string url = base + gw.path;
    // Handle port-based paths.
    if (gw.path[0] == '/' && gw.path[1] == ':') {
      std::string port_path = gw.path;
      size_t slash = port_path.find('/', 2);
      std::string port = port_path.substr(1, slash - 1);
      std::string path = port_path.substr(slash);
      // Reconstruct URL with port.
      size_t proto_end = base.find("://") + 3;
      size_t host_end = base.find('/', proto_end);
      std::string host = (host_end != std::string::npos)
                             ? base.substr(0, host_end)
                             : base;
      url = host + port + path;
    }
    auto resp = http.get(url);
    if (resp.status_code == 200 && resp.body.size() > 50 &&
        resp.body.find(gw.indicator) != std::string::npos) {
      findings.push_back({"API Gateway Exposed: " + std::string(gw.gateway),
                          "critical", url,
                          std::string(gw.gateway) + " management interface accessible",
                          "", "", ""});
    }
  }
  return findings;
}

/// Discover API versioning and hidden API endpoints.
std::vector<Finding> scan_api_enumeration(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Try common API version prefixes.
  const std::vector<std::string> api_bases = {
      "/api", "/api/v1", "/api/v2", "/api/v3",
      "/v1", "/v2", "/v3", "/rest", "/rest/v1",
  };
  const std::vector<std::string> discovery_paths = {
      "/", "/health", "/status", "/info", "/version",
      "/users", "/me", "/config", "/settings",
  };

  std::set<std::string> found_apis;
  for (const auto &api : api_bases) {
    for (const auto &path : discovery_paths) {
      auto resp = http.get(base + api + path);
      if (resp.status_code == 200 && resp.body.size() > 20 &&
          (resp.body[0] == '{' || resp.body[0] == '[')) {
        found_apis.insert(api);
        break;
      }
      if (resp.status_code == 401 || resp.status_code == 403) {
        found_apis.insert(api + " (auth required)");
        break;
      }
    }
  }

  if (!found_apis.empty()) {
    std::string detail = "API endpoints found:";
    for (const auto &a : found_apis) detail += " " + a + ",";
    findings.push_back({"API Enumeration", "info", base,
                        detail, "", "", ""});
  }

  // Check for OData metadata.
  auto odata = http.get(base + "/odata/$metadata");
  if (odata.status_code == 200 && odata.body.find("edmx") != std::string::npos) {
    findings.push_back({"OData Metadata Exposed", "medium", base + "/odata/$metadata",
                        "OData $metadata endpoint exposes full entity model",
                        "", "", ""});
  }

  // Check for WSDL (SOAP).
  auto wsdl = http.get(base + "/service?wsdl");
  if (wsdl.status_code == 200 && wsdl.body.find("definitions") != std::string::npos) {
    findings.push_back({"WSDL Exposed", "medium", base + "/service?wsdl",
                        "SOAP WSDL exposes all operations and types",
                        "", "", ""});
  }

  // Check for gRPC reflection.
  auto grpc = http.get(base + "/grpc.reflection.v1alpha.ServerReflection");
  if (grpc.status_code != 404 && grpc.body.size() > 0) {
    findings.push_back({"gRPC Reflection", "medium", base,
                        "gRPC server reflection may be enabled",
                        "", "", ""});
  }

  return findings;
}

} // namespace

std::vector<Scanner> register_api_discovery_scanners() {
  return {
      {"OpenAPI/Swagger Discovery", scan_openapi_exposure},
      {"GraphQL Discovery", scan_graphql_discovery},
      {"API Gateway Discovery", scan_api_gateway},
      {"API Enumeration", scan_api_enumeration},
  };
}

} // namespace apex
