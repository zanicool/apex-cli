/// @file scanners/smart.cpp
/// @brief Smart detection: boolean-blind SQLi, context-aware XSS, WAF
///        detection, wildcard filtering, deduplication support.
#include "scanner_base.hpp"
#include <functional>
#include <numeric>

namespace apex {
namespace {

/// Detect WAF presence by sending malicious payloads and checking responses.
bool detect_waf(HttpClient &http, const std::string &url) {
  auto resp = http.get(url + "?test=<script>alert(1)</script>' OR 1=1--");
  if (resp.status_code == 403 || resp.status_code == 406) return true;
  const std::vector<std::string> waf_sigs = {
      "cloudflare", "akamai", "incapsula", "sucuri", "wordfence",
      "mod_security", "blocked", "forbidden", "waf"};
  return contains_any(resp.body, waf_sigs);
}

/// Check if target returns wildcard responses (same for any input).
bool is_wildcard(HttpClient &http, const std::string &url,
                 const std::string &param) {
  auto r1 = http.get(url + "?" + param + "=randomvalue12345");
  auto r2 = http.get(url + "?" + param + "=differentvalue67890");
  if (r1.body.empty() || r2.body.empty()) return false;
  size_t diff = (r1.body.size() > r2.body.size())
                    ? r1.body.size() - r2.body.size()
                    : r2.body.size() - r1.body.size();
  return diff < 10 && r1.status_code == r2.status_code;
}

/// Boolean-blind SQL injection via response size differential.
std::vector<Finding> scan_sqli_blind_boolean(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::string true_payload = "' AND '1'='1";
  const std::string false_payload = "' AND '1'='2";

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      if (is_wildcard(http, url, param)) continue;
      auto true_resp = http.get(base + true_payload);
      auto false_resp = http.get(base + false_payload);
      size_t size_diff = (true_resp.body.size() > false_resp.body.size())
                             ? true_resp.body.size() - false_resp.body.size()
                             : false_resp.body.size() - true_resp.body.size();
      if (size_diff > 50 && true_resp.status_code == false_resp.status_code) {
        findings.push_back({"SQLi (Blind)", "high", url,
                            "Boolean-blind SQLi: size diff=" +
                                std::to_string(size_diff),
                            param, true_payload, ""});
      }
    }
  }
  return findings;
}

/// Detect XSS reflection context and use context-appropriate payloads.
std::vector<Finding> scan_xss_context_aware(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::string canary = "apex7x7z";

  struct CtxPayload {
    const char *ctx;
    const char *payload;
  };
  const CtxPayload ctx_payloads[] = {
      {"html", "<img src=x onerror=alert(1)>"},
      {"attr", "\" onmouseover=alert(1) x=\""},
      {"js", "';alert(1);//"},
      {"url", "javascript:alert(1)"},
  };

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "q");
    for (const auto &[base, param] : targets) {
      auto resp = http.get(base + canary);
      if (resp.body.find(canary) == std::string::npos) continue;

      // Detect context.
      std::string ctx = "html";
      size_t pos = resp.body.find(canary);
      if (pos > 0) {
        std::string before = resp.body.substr(
            pos > 30 ? pos - 30 : 0, pos > 30 ? 30 : pos);
        if (before.find("=\"") != std::string::npos ||
            before.find("='") != std::string::npos)
          ctx = "attr";
        else if (before.find("var ") != std::string::npos ||
                 before.find("'") != std::string::npos)
          ctx = "js";
        else if (before.find("href=") != std::string::npos)
          ctx = "url";
      }

      for (const auto &cp : ctx_payloads) {
        if (ctx != cp.ctx) continue;
        auto test = http.get(base + std::string(cp.payload));
        if (test.body.find(cp.payload) != std::string::npos) {
          findings.push_back({"XSS (Context)", "high", url,
                              "Context-aware XSS in " + ctx + " context",
                              param, cp.payload, ""});
          break;
        }
      }
    }
  }
  return findings;
}

/// WAF detection and reporting.
std::vector<Finding> scan_waf_detect(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct WafSig {
    const char *header;
    const char *value;
    const char *name;
  };
  const WafSig sigs[] = {
      {"Server", "cloudflare", "Cloudflare"},
      {"X-Sucuri-ID", "", "Sucuri"},
      {"X-CDN", "Incapsula", "Imperva/Incapsula"},
      {"Server", "AkamaiGHost", "Akamai"},
      {"X-Powered-By", "wordfence", "Wordfence"},
  };

  auto resp = http.get(base + "/?test=<script>alert(1)</script>");
  for (const auto &sig : sigs) {
    auto it = resp.headers.find(sig.header);
    if (it != resp.headers.end()) {
      std::string needle = sig.value;
      if (needle.empty() || it->second.find(needle) != std::string::npos) {
        findings.push_back({"WAF Detected", "info", base,
                            std::string("WAF: ") + sig.name, "", "", ""});
      }
    }
  }

  if (resp.status_code == 403 || resp.status_code == 406) {
    findings.push_back({"WAF Detected", "info", base,
                        "WAF blocking malicious input (HTTP " +
                            std::to_string(resp.status_code) + ")",
                        "", "", ""});
  }
  return findings;
}

/// Time-based blind SQL injection.
std::vector<Finding> scan_sqli_time_based(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {
      "' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--",
      "' AND pg_sleep(5)--", "1; SELECT SLEEP(5)"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      auto baseline = http.get(base + "test");
      for (const auto &payload : payloads) {
        auto resp = http.get(base + payload);
        if (resp.duration.count() >= 4500 &&
            baseline.duration.count() < 2000) {
          findings.push_back({"SQLi (Time)", "high", url,
                              "Time-based blind SQLi: " +
                                  std::to_string(resp.duration.count()) + "ms",
                              param, payload, ""});
          break;
        }
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_smart_scanners() {
  return {
      {"SQLi (Blind Boolean)", scan_sqli_blind_boolean},
      {"XSS (Context-Aware)", scan_xss_context_aware},
      {"WAF Detection", scan_waf_detect},
      {"SQLi (Time-Based)", scan_sqli_time_based},
  };
}

} // namespace apex
