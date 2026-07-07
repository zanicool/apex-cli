/// @file scanners/web.cpp
/// @brief Web vulnerabilities: CORS advanced, open redirect advanced, HPP,
///        JSONP, CSP bypass, SSI, DOM XSS patterns, postMessage.
#include <set>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Advanced CORS — test with specific origins.
std::vector<Finding> scan_cors_advanced(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> origins = {"https://evil.com", "https://null", "https://target.com.evil.com",
                                            "https://targetcom.evil.com"};

  for (const auto& url : crawl.urls) {
    for (const auto& origin : origins) {
      auto resp = http.get(url, {{"Origin", origin}});
      auto acao = resp.headers.find("Access-Control-Allow-Origin");
      if (acao != resp.headers.end() && acao->second == origin) {
        auto acac = resp.headers.find("Access-Control-Allow-Credentials");
        std::string sev = (acac != resp.headers.end() && acac->second == "true") ? "high" : "medium";
        findings.push_back({"CORS Advanced", sev, url, "Reflects origin: " + origin, "", origin, ""});
        break;
      }
    }
  }
  return findings;
}

/// HTTP Parameter Pollution.
std::vector<Finding> scan_hpp(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  for (const auto& url : crawl.urls) {
    for (const auto& p : crawl.params) {
      if (p.url != url) continue;
      // Send same param twice with different values.
      std::string test_url = p.url + "?" + p.name + "=first&" + p.name + "=second";
      auto resp = http.get(test_url);
      if (resp.body.find("second") != std::string::npos && resp.body.find("first") == std::string::npos) {
        findings.push_back({"HPP", "low", url, "Last param value used (HPP possible)", p.name, "first&" + p.name + "=second", ""});
      }
    }
  }
  return findings;
}

/// JSONP callback injection.
std::vector<Finding> scan_jsonp(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> cb_params = {"callback", "cb", "jsonp", "fn"};

  for (const auto& url : crawl.urls) {
    for (const auto& cb : cb_params) {
      auto resp = http.get(url + "?" + cb + "=evil");
      if (resp.body.find("evil(") != std::string::npos) {
        findings.push_back({"JSONP", "medium", url, "JSONP callback injection via " + cb, cb, "evil", ""});
        break;
      }
    }
  }
  return findings;
}

/// CSP bypass detection.
std::vector<Finding> scan_csp_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);
  auto csp = resp.headers.find("Content-Security-Policy");
  if (csp == resp.headers.end()) return findings;

  const std::string& policy = csp->second;
  const std::vector<std::pair<std::string, std::string>> weaknesses = {{"unsafe-inline", "Allows inline scripts"},
                                                                       {"unsafe-eval", "Allows eval()"},
                                                                       {"data:", "Allows data: URIs"},
                                                                       {"*", "Wildcard source"},
                                                                       {"http:", "Allows HTTP (mixed content)"},
                                                                       {"'nonce-'", "Nonce-based (check if predictable)"}};

  for (const auto& [pattern, desc] : weaknesses) {
    if (policy.find(pattern) != std::string::npos) {
      findings.push_back({"CSP Bypass", "medium", crawl.urls[0], "CSP weakness: " + desc, "", pattern, ""});
    }
  }

  // Check for known CDN bypasses.
  const std::vector<std::string> bypass_cdns = {"cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "ajax.googleapis.com",
                                                "*.google.com"};
  for (const auto& cdn : bypass_cdns) {
    if (policy.find(cdn) != std::string::npos) {
      findings.push_back({"CSP Bypass", "medium", crawl.urls[0], "CSP allows " + cdn + " (known bypass vector)", "", cdn, ""});
    }
  }
  return findings;
}

/// Server-Side Includes injection.
std::vector<Finding> scan_ssi(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::string payload = "<!--#exec cmd=\"echo SSI_CONFIRMED\"-->";

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "q");
    for (const auto& [base, param] : targets) {
      auto resp = http.get(base + payload);
      if (resp.body.find("SSI_CONFIRMED") != std::string::npos) {
        findings.push_back({"SSI Injection", "high", url, "Server-Side Include injection", param, payload, ""});
      }
    }
  }
  return findings;
}

/// Open redirect advanced — more bypass techniques.
std::vector<Finding> scan_open_redirect_advanced(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {"//evil.com",     "/\\evil.com",    "/%09/evil.com",
                                             "//%20/evil.com", "https:evil.com", "//evil%00.com",
                                             "///evil.com",    "////evil.com",   "https://evil.com%23.target.com"};
  const std::vector<std::string> params = {"next", "url", "redirect", "return", "goto", "continue"};

  for (const auto& url : crawl.urls) {
    for (const auto& param : params) {
      for (const auto& payload : payloads) {
        auto resp = http.get(url + "?" + param + "=" + payload);
        auto loc = resp.headers.find("Location");
        if (loc != resp.headers.end() && loc->second.find("evil") != std::string::npos) {
          findings.push_back({"Open Redirect (Advanced)", "medium", url, "Redirect bypass via " + param, param, payload, loc->second});
          goto next_url;
        }
      }
    }
  next_url:;
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_web_scanners() {
  return {
      {"CORS Advanced", scan_cors_advanced}, {"HPP", scan_hpp},           {"JSONP", scan_jsonp},
      {"CSP Bypass", scan_csp_bypass},       {"SSI Injection", scan_ssi}, {"Open Redirect (Advanced)", scan_open_redirect_advanced},
  };
}

}  // namespace apex
