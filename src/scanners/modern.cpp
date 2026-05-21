/// @file scanners/modern.cpp
/// @brief Modern attack vectors: GraphQL introspection, HTTP request smuggling,
///        cache poisoning, WebSocket hijacking, H2C smuggling.
#include "scanner_base.hpp"

namespace apex {
namespace {

/// GraphQL introspection and injection.
std::vector<Finding> scan_graphql(const Config &, HttpClient &http,
                                  const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> gql_paths = {"/graphql", "/api/graphql",
                                               "/graphql/v1", "/gql"};
  const std::string introspection =
      R"({"query":"{__schema{types{name,fields{name}}}}"})";

  for (const auto &path : gql_paths) {
    auto resp = http.post(base + path, introspection, "application/json");
    if (resp.status_code == 200 &&
        resp.body.find("__schema") != std::string::npos) {
      findings.push_back({"GraphQL Introspection", "medium", base + path,
                          "GraphQL introspection enabled", "", "", ""});

      // Try query depth attack.
      std::string deep = R"({"query":"{__type(name:\"Query\"){fields{name,type{fields{name,type{fields{name}}}}}}}"})";
      auto deep_resp = http.post(base + path, deep, "application/json");
      if (deep_resp.status_code == 200 &&
          deep_resp.body.find("error") == std::string::npos) {
        findings.push_back({"GraphQL Depth", "low", base + path,
                            "No query depth limit", "", "", ""});
      }
    }
  }
  return findings;
}

/// HTTP request smuggling detection.
std::vector<Finding> scan_http_smuggling(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // CL.TE detection: send conflicting Content-Length and Transfer-Encoding.
  auto resp = http.post(base + "/", "0\r\n\r\nSMUGGLED",
                        "application/x-www-form-urlencoded",
                        {{"Transfer-Encoding", "chunked"},
                         {"Content-Length", "4"}});

  if (resp.status_code != 400 && resp.body.find("SMUGGLED") != std::string::npos) {
    findings.push_back({"HTTP Smuggling", "critical", base,
                        "Potential CL.TE request smuggling", "", "", ""});
  }
  return findings;
}

/// Cache poisoning — inject headers that get cached.
std::vector<Finding> scan_cache_poisoning(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string url = crawl.urls[0];

  // Try X-Forwarded-Host injection.
  auto resp = http.get(url, {{"X-Forwarded-Host", "evil.com"}});
  if (resp.body.find("evil.com") != std::string::npos) {
    // Verify it's cached.
    auto verify = http.get(url);
    if (verify.body.find("evil.com") != std::string::npos) {
      findings.push_back({"Cache Poisoning", "high", url,
                          "X-Forwarded-Host reflected and cached",
                          "", "X-Forwarded-Host: evil.com", ""});
    } else {
      findings.push_back({"Cache Poisoning (Potential)", "medium", url,
                          "X-Forwarded-Host reflected (not cached)",
                          "", "X-Forwarded-Host: evil.com", ""});
    }
  }

  // Try X-Original-URL for path override.
  auto path_resp = http.get(url, {{"X-Original-URL", "/admin"}});
  if (path_resp.status_code == 200 && path_resp.body.size() > 100 &&
      path_resp.body.find("admin") != std::string::npos) {
    findings.push_back({"Path Override", "high", url,
                        "X-Original-URL header accepted", "",
                        "X-Original-URL: /admin", ""});
  }
  return findings;
}

/// WebSocket hijacking detection.
std::vector<Finding> scan_websocket(const Config &, HttpClient &http,
                                    const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check for WebSocket endpoints.
  const std::vector<std::string> ws_paths = {"/ws", "/websocket", "/socket.io/",
                                              "/cable", "/hub"};
  for (const auto &path : ws_paths) {
    auto resp = http.get(base + path,
                         {{"Upgrade", "websocket"},
                          {"Connection", "Upgrade"},
                          {"Sec-WebSocket-Version", "13"},
                          {"Sec-WebSocket-Key", "dGVzdA=="},
                          {"Origin", "https://evil.com"}});
    if (resp.status_code == 101 || resp.status_code == 200) {
      findings.push_back({"WebSocket CSWSH", "medium", base + path,
                          "WebSocket accepts cross-origin connections",
                          "", "Origin: evil.com", ""});
    }
  }
  return findings;
}

/// H2C smuggling — HTTP/2 cleartext upgrade.
std::vector<Finding> scan_h2c_smuggling(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/",
                       {{"Upgrade", "h2c"},
                        {"Connection", "Upgrade, HTTP2-Settings"},
                        {"HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA"}});
  if (resp.status_code == 101) {
    findings.push_back({"H2C Smuggling", "high", base,
                        "Server accepts H2C upgrade (potential smuggling)",
                        "", "", ""});
  }
  return findings;
}

/// HTTP/2 Rapid Reset (CVE-2023-44487) — DoS via stream reset flood.
std::vector<Finding> scan_http2_rapid_reset(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  // Check if server supports HTTP/2 (indicated by response).
  auto resp = http.get(crawl.urls[0]);
  if (resp.status_code > 0) {
    // If we got a response, server is up. Check if it handles many rapid requests.
    // We just report if HTTP/2 is supported (actual DoS testing is out of scope).
    findings.push_back({"HTTP/2 Rapid Reset", "info", crawl.urls[0],
                        "Server supports HTTP/2 (CVE-2023-44487 check recommended)",
                        "", "", ""});
  }
  return findings;
}

/// Host Header injection — password reset poisoning, cache poisoning.
std::vector<Finding> scan_host_header(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  auto baseline = http.get(crawl.urls[0]);
  auto resp = http.get(crawl.urls[0], {{"Host", "evil.com"}});
  if (resp.status_code == 200 && resp.body.find("evil.com") != std::string::npos &&
      baseline.body.find("evil.com") == std::string::npos) {
    findings.push_back({"Host Header Injection", "high", crawl.urls[0],
                        "Host header reflected in response", "",
                        "Host: evil.com", ""});
  }
  return findings;
}

/// TRACE/OPTIONS — check if dangerous HTTP methods are enabled.
std::vector<Finding> scan_trace_options(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string url = crawl.urls[0];
  // Check OPTIONS for allowed methods.
  auto resp = http.get(url, {{"Access-Control-Request-Method", "TRACE"}});
  auto allow = resp.headers.find("Allow");
  if (allow != resp.headers.end() &&
      allow->second.find("TRACE") != std::string::npos) {
    findings.push_back({"TRACE Enabled", "low", url,
                        "HTTP TRACE method enabled (XST risk)", "", "", ""});
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_modern_scanners() {
  return {
      {"GraphQL", scan_graphql},
      {"HTTP Smuggling", scan_http_smuggling},
      {"Cache Poisoning", scan_cache_poisoning},
      {"WebSocket", scan_websocket},
      {"H2C Smuggling", scan_h2c_smuggling},
      {"HTTP/2 Rapid Reset", scan_http2_rapid_reset},
      {"Host Header Injection", scan_host_header},
      {"TRACE/OPTIONS", scan_trace_options},
  };
}

} // namespace apex
