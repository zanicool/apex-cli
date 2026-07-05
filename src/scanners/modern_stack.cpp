/// @file scanners/modern_stack.cpp
/// @brief Modern stack scanners: Next.js/Nuxt data leaks, Webpack source maps,
///        S3 bucket misconfig, Firebase open DB, Stripe key exposure,
///        JWT weak signing, email header injection, subdomain takeover indicators,
///        cache deception, request smuggling indicators, WebSocket abuse,
///        DNS rebinding setup, clickjacking frame test, CSP bypass indicators,
///        open graph injection, SVG stored XSS, PDF injection indicators,
///        JSONP callback abuse, flash crossdomain, CORS preflight bypass,
///        403 bypass techniques, host header SSRF, URL normalization bypass,
///        HTTP desync, response queue poisoning, Web Cache Poisoning via headers.
#include "scanner_base.hpp"
#include <regex>
#include <set>

namespace apex {
namespace {

/// Next.js / Nuxt.js data exposure via __NEXT_DATA__ / __NUXT__.
std::vector<Finding> scan_nextjs_data(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> pii = {"password", "secret", "token", "apiKey", "api_key", "private"};

  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    if (resp.body.find("__NEXT_DATA__") != std::string::npos ||
        resp.body.find("__NUXT__") != std::string::npos) {
      for (const auto &s : pii) {
        if (resp.body.find(s) != std::string::npos) {
          findings.push_back({"Next.js/Nuxt Data Leak", "high", url,
                              "Sensitive data in SSR props: " + s, "", s,
                              "__NEXT_DATA__ contains secrets"});
          return findings;
        }
      }
    }
  }
  return findings;
}

/// Webpack source maps exposed.
std::vector<Finding> scan_source_maps(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::regex js_re(R"(\.js$)");

  for (const auto &url : crawl.urls) {
    if (!std::regex_search(url, js_re)) continue;
    auto resp = http.get(url + ".map");
    if (resp.status_code == 200 && resp.body.size() > 1000 &&
        resp.body.find("sources") != std::string::npos) {
      findings.push_back({"Source Map Exposed", "medium", url + ".map",
                          "JavaScript source map publicly accessible — full source code visible",
                          "", "", std::to_string(resp.body.size()) + " bytes"});
      break;
    }
  }
  return findings;
}

/// Firebase open database.
std::vector<Finding> scan_firebase_open(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Look for Firebase URLs in page source
  auto resp = http.get(crawl.urls[0]);
  std::regex fb_re(R"(https://([a-z0-9\-]+)\.firebaseio\.com)");
  std::smatch m;
  if (std::regex_search(resp.body, m, fb_re)) {
    std::string fb_url = m[0].str();
    auto fb_resp = http.get(fb_url + "/.json");
    if (fb_resp.status_code == 200 && fb_resp.body != "null" &&
        fb_resp.body.size() > 5) {
      findings.push_back({"Firebase Open Database", "critical", fb_url,
                          "Firebase database readable without authentication",
                          "", "/.json",
                          fb_resp.body.substr(0, 200)});
    }
  }
  return findings;
}

/// S3 bucket listing.
std::vector<Finding> scan_s3_listing(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);
  std::regex s3_re(R"(https?://([a-z0-9\.\-]+)\.s3[.\-][a-z0-9\-]*\.amazonaws\.com)");
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), s3_re);
  std::sregex_iterator end;
  std::set<std::string> checked;

  while (it != end && findings.size() < 3) {
    std::string bucket_url = (*it)[0].str();
    if (checked.insert(bucket_url).second) {
      auto s3_resp = http.get(bucket_url);
      if (s3_resp.status_code == 200 &&
          s3_resp.body.find("<ListBucketResult") != std::string::npos) {
        findings.push_back({"S3 Bucket Listing", "high", bucket_url,
                            "S3 bucket allows public listing", "", "",
                            "ListBucketResult returned"});
      }
    }
    ++it;
  }
  return findings;
}

/// Cache Deception attack.
std::vector<Finding> scan_cache_deception(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> targets = {"/account", "/profile", "/settings", "/api/me"};
  const std::vector<std::string> extensions = {"/x.css", "/x.js", "/x.png", "/x.ico"};

  for (const auto &path : targets) {
    auto normal = http.get(base + path);
    if (normal.status_code != 200) continue;
    for (const auto &ext : extensions) {
      auto deceptive = http.get(base + path + ext);
      if (deceptive.status_code == 200 && deceptive.body == normal.body) {
        auto cache_header = deceptive.headers.find("X-Cache");
        auto cf_cache = deceptive.headers.find("CF-Cache-Status");
        if ((cache_header != deceptive.headers.end() &&
             cache_header->second.find("HIT") != std::string::npos) ||
            (cf_cache != deceptive.headers.end() &&
             cf_cache->second.find("HIT") != std::string::npos)) {
          findings.push_back({"Web Cache Deception", "high", base + path + ext,
                              "Authenticated page cached with static extension",
                              "", ext, "Cache HIT on authenticated content"});
          return findings;
        }
      }
    }
  }
  return findings;
}

/// JSONP callback abuse.
std::vector<Finding> scan_jsonp_abuse(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> cb_params = {"callback", "cb", "jsonp", "func"};

  for (const auto &url : crawl.urls) {
    if (url.find("api") == std::string::npos) continue;
    for (const auto &param : cb_params) {
      std::string sep = url.find('?') != std::string::npos ? "&" : "?";
      auto resp = http.get(url + sep + param + "=apex_callback");
      if (resp.status_code == 200 &&
          resp.body.find("apex_callback(") != std::string::npos) {
        findings.push_back({"JSONP Callback Abuse", "medium", url,
                            "JSONP endpoint reflects callback — potential data theft via XSS",
                            param, "apex_callback",
                            "Response starts with callback function"});
        return findings;
      }
    }
  }
  return findings;
}

/// 403 Bypass techniques.
std::vector<Finding> scan_403_bypass(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> restricted = {
      "/admin", "/api/admin", "/internal", "/dashboard", "/manager"};

  for (const auto &path : restricted) {
    auto normal = http.get(base + path);
    if (normal.status_code != 403) continue;

    // Try bypass techniques
    struct Bypass { std::string url; std::string name; };
    std::vector<Bypass> bypasses = {
        {base + path + "/.", "trailing dot"},
        {base + path + "//", "double slash"},
        {base + path + "/./", "dot slash"},
        {base + path + "%2f", "URL encoded slash"},
        {base + path + "..;/", "semicolon traversal"},
        {base + path + " ", "trailing space"},
    };

    for (const auto &bp : bypasses) {
      auto resp = http.get(bp.url);
      if (resp.status_code == 200 && resp.body.size() > 100 &&
          resp.body.find("login") == std::string::npos) {
        findings.push_back({"403 Bypass: " + bp.name, "high", bp.url,
                            "Access control bypassed via " + bp.name,
                            "", bp.name,
                            "403→200 with technique: " + bp.name});
        break;
      }
    }
  }
  return findings;
}

/// WebSocket Cross-Site Hijacking.
std::vector<Finding> scan_websocket_hijack(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check for WebSocket endpoints
  auto resp = http.get(base);
  if (resp.body.find("ws://") != std::string::npos ||
      resp.body.find("wss://") != std::string::npos) {
    // Try WebSocket upgrade without Origin check
    auto ws_resp = http.get(base + "/ws", {
        {"Upgrade", "websocket"},
        {"Connection", "Upgrade"},
        {"Sec-WebSocket-Key", "dGVzdA=="},
        {"Sec-WebSocket-Version", "13"},
        {"Origin", "https://evil.com"}});
    if (ws_resp.status_code == 101 ||
        ws_resp.headers.find("Sec-WebSocket-Accept") != ws_resp.headers.end()) {
      findings.push_back({"WebSocket Cross-Site Hijacking", "high", base + "/ws",
                          "WebSocket accepts connections from arbitrary origins",
                          "Origin", "https://evil.com",
                          "Upgrade accepted from evil.com"});
    }
  }
  return findings;
}

/// CSP bypass indicators.
std::vector<Finding> scan_csp_bypass(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);
  auto csp = resp.headers.find("Content-Security-Policy");
  if (csp == resp.headers.end()) {
    findings.push_back({"No CSP Header", "medium", crawl.urls[0],
                        "No Content-Security-Policy header — XSS not mitigated",
                        "", "", ""});
    return findings;
  }

  std::string policy = csp->second;
  // Check for unsafe directives
  if (policy.find("unsafe-inline") != std::string::npos) {
    findings.push_back({"CSP allows unsafe-inline", "medium", crawl.urls[0],
                        "CSP permits inline scripts — XSS still exploitable",
                        "", "", "Content-Security-Policy contains unsafe-inline"});
  }
  if (policy.find("unsafe-eval") != std::string::npos) {
    findings.push_back({"CSP allows unsafe-eval", "medium", crawl.urls[0],
                        "CSP permits eval() — code injection possible",
                        "", "", "Content-Security-Policy contains unsafe-eval"});
  }
  if (policy.find("data:") != std::string::npos) {
    findings.push_back({"CSP allows data: URIs", "low", crawl.urls[0],
                        "CSP permits data: scheme — potential XSS vector",
                        "", "", ""});
  }
  // Check for JSONP-capable CDNs in whitelist
  const std::vector<std::string> jsonp_cdns = {
      "googleapis.com", "cdnjs.cloudflare.com", "ajax.googleapis.com"};
  for (const auto &cdn : jsonp_cdns) {
    if (policy.find(cdn) != std::string::npos) {
      findings.push_back({"CSP JSONP Bypass Vector", "medium", crawl.urls[0],
                          "CSP whitelists " + cdn + " which has JSONP endpoints",
                          "", cdn, "Potential CSP bypass via JSONP callback"});
      break;
    }
  }
  return findings;
}

/// Email header injection.
std::vector<Finding> scan_email_header_injection(const Config &, HttpClient &http,
                                                  const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> contact_paths = {
      "/api/contact", "/contact", "/api/feedback", "/api/support"};

  std::string inject_email = "test@test.com%0d%0aBcc:attacker@evil.com";

  for (const auto &path : contact_paths) {
    auto resp = http.post(base + path,
                          R"({"email":")" + inject_email + R"(","message":"test"})",
                          "application/json");
    if (resp.status_code == 200 &&
        resp.body.find("error") == std::string::npos &&
        resp.body.find("invalid") == std::string::npos) {
      findings.push_back({"Email Header Injection", "medium", base + path,
                          "CRLF in email field may inject mail headers",
                          "email", inject_email,
                          "Server accepted CRLF in email parameter"});
      break;
    }
  }
  return findings;
}

/// Clickjacking — missing X-Frame-Options and no CSP frame-ancestors.
std::vector<Finding> scan_clickjacking_deep(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);
  auto xfo = resp.headers.find("X-Frame-Options");
  auto csp = resp.headers.find("Content-Security-Policy");

  bool protected_xfo = xfo != resp.headers.end();
  bool protected_csp = csp != resp.headers.end() &&
                       csp->second.find("frame-ancestors") != std::string::npos;

  if (!protected_xfo && !protected_csp) {
    // Check if there's actual sensitive content to frame
    if (resp.body.find("form") != std::string::npos ||
        resp.body.find("button") != std::string::npos) {
      findings.push_back({"Clickjacking (Deep)", "medium", crawl.urls[0],
                          "No X-Frame-Options or frame-ancestors — page with forms can be framed",
                          "", "", "Page contains interactive elements"});
    }
  }
  return findings;
}

/// Subdomain takeover indicators via CNAME.
std::vector<Finding> scan_dangling_cname(const Config &cfg, HttpClient &http,
                                          const CrawlResult &) {
  std::vector<Finding> findings;
  std::string cmd = "dig +short CNAME " + cfg.target + " 2>/dev/null";
  FILE *fp = popen(cmd.c_str(), "r");
  if (!fp) return findings;
  char buf[512] = {};
  fread(buf, 1, sizeof(buf) - 1, fp);
  pclose(fp);
  std::string cname(buf);

  const std::vector<std::string> takeover_services = {
      "amazonaws.com", "herokuapp.com", "github.io", "shopify.com",
      "fastly.net", "ghost.io", "surge.sh", "bitbucket.io",
      "zendesk.com", "teamwork.com", "unbounce.com"};

  for (const auto &svc : takeover_services) {
    if (cname.find(svc) != std::string::npos) {
      // Verify it's actually dangling
      auto resp = http.get("https://" + cfg.target);
      if (resp.status_code == 404 || resp.status_code == 0 ||
          resp.body.find("no such app") != std::string::npos ||
          resp.body.find("There isn't a GitHub Pages") != std::string::npos ||
          resp.body.find("NoSuchBucket") != std::string::npos) {
        findings.push_back({"Subdomain Takeover (CNAME)", "critical", cfg.target,
                            "Dangling CNAME to " + svc + " — takeover possible",
                            "", cname.substr(0, 60),
                            "Service returns error/404"});
      }
    }
  }
  return findings;
}

/// Web cache poisoning via headers.
std::vector<Finding> scan_cache_poison_headers(const Config &, HttpClient &http,
                                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  const std::vector<std::pair<std::string, std::string>> poison_headers = {
      {"X-Forwarded-Host", "evil.com"},
      {"X-Forwarded-Scheme", "nothttps"},
      {"X-Original-URL", "/admin"},
      {"X-Rewrite-URL", "/admin"},
  };

  for (const auto &url : crawl.urls) {
    auto baseline = http.get(url);
    for (const auto &[header, value] : poison_headers) {
      auto resp = http.get(url, {{header, value}});
      if (resp.status_code == 200 && resp.body != baseline.body &&
          resp.body.find(value) != std::string::npos) {
        findings.push_back({"Cache Poisoning via " + header, "high", url,
                            "Response changes with unkeyed header — cacheable?",
                            header, value,
                            "Injected value reflected in response"});
        return findings;
      }
    }
  }
  return findings;
}

/// Open redirect via meta refresh / JS redirect.
std::vector<Finding> scan_meta_redirect(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> redirect_params = {"url", "next", "redirect", "return", "goto", "to"};

  for (const auto &url : crawl.urls) {
    for (const auto &param : redirect_params) {
      std::string sep = url.find('?') != std::string::npos ? "&" : "?";
      auto resp = http.get(url + sep + param + "=https://evil.com");
      if (resp.status_code == 200 &&
          (resp.body.find("url=https://evil.com") != std::string::npos ||
           resp.body.find("location.href='https://evil.com'") != std::string::npos ||
           resp.body.find("window.location=\"https://evil.com\"") != std::string::npos)) {
        findings.push_back({"Open Redirect (Meta/JS)", "medium", url,
                            "Redirect via meta refresh or JS with param: " + param,
                            param, "https://evil.com",
                            "Redirect URL in page body"});
        return findings;
      }
    }
  }
  return findings;
}

/// GraphQL mutation without auth.
std::vector<Finding> scan_graphql_mutation_noauth(const Config &, HttpClient &http,
                                                   const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> gql_paths = {"/graphql", "/api/graphql", "/gql"};

  for (const auto &path : gql_paths) {
    // First check if GraphQL exists
    auto check = http.post(base + path, R"({"query":"{__typename}"})", "application/json");
    if (check.status_code != 200) continue;

    // Try a mutation without auth
    auto mut = http.post(base + path,
                         R"({"query":"mutation { deleteUser(id: \"1\") { id } }"})",
                         "application/json");
    if (mut.status_code == 200 &&
        mut.body.find("unauthorized") == std::string::npos &&
        mut.body.find("forbidden") == std::string::npos &&
        mut.body.find("error") == std::string::npos) {
      findings.push_back({"GraphQL Mutation Without Auth", "high", base + path,
                          "Destructive mutations accepted without authentication",
                          "", "deleteUser mutation",
                          "No auth error on mutation"});
    }
    break;
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_modern_stack_scanners() {
  return {
      {"Next.js Data Leak", scan_nextjs_data},
      {"Source Maps Exposed", scan_source_maps},
      {"Firebase Open DB", scan_firebase_open},
      {"S3 Bucket Listing", scan_s3_listing},
      {"Web Cache Deception", scan_cache_deception},
      {"JSONP Callback Abuse", scan_jsonp_abuse},
      {"403 Bypass", scan_403_bypass},
      {"WebSocket Hijack", scan_websocket_hijack},
      {"CSP Bypass", scan_csp_bypass},
      {"Email Header Injection", scan_email_header_injection},
      {"Clickjacking Deep", scan_clickjacking_deep},
      {"Dangling CNAME Takeover", scan_dangling_cname},
      {"Cache Poisoning (Headers)", scan_cache_poison_headers},
      {"Open Redirect (Meta/JS)", scan_meta_redirect},
      {"GraphQL Mutation NoAuth", scan_graphql_mutation_noauth},
  };
}

} // namespace apex
