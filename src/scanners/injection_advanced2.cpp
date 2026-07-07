/// @file scanners/injection_advanced.cpp
/// @brief Advanced injection: SSTI (Server-Side Template Injection),
///        deserialization attacks, LDAP injection, XPath injection,
///        expression language injection, and header injection.
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// SSTI detection via mathematical expression evaluation.
std::vector<Finding> scan_ssti(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // SSTI payloads that evaluate math — if reflected as result, SSTI confirmed
  struct SSTIPayload {
    std::string payload;
    std::string expected;
    std::string engine;
  };

  std::vector<SSTIPayload> payloads = {
      {"{{7*7}}", "49", "Jinja2/Twig"},
      {"${7*7}", "49", "Freemarker/Velocity"},
      {"<%= 7*7 %>", "49", "ERB/EJS"},
      {"#{7*7}", "49", "Pebble/Thymeleaf"},
      {"{{7*'7'}}", "7777777", "Jinja2 (string mult)"},
      {"${{7*7}}", "49", "Spring EL"},
      {"{7*7}", "49", "Smarty"},
      {"@(7*7)", "49", "Razor"},
  };

  // Find injectable params
  for (const auto& url : crawl.urls) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) continue;

    std::string query = url.substr(qpos + 1);
    std::regex param_re(R"x(([^&=]+)=([^&]*))x");
    std::sregex_iterator it(query.begin(), query.end(), param_re);
    std::sregex_iterator end;

    for (; it != end; ++it) {
      std::string param = (*it)[1].str();
      std::string base_url = url.substr(0, qpos + 1) + param + "=";

      for (const auto& p : payloads) {
        auto resp = http.get(base_url + p.payload);
        if (resp.status_code == 200 && resp.body.find(p.expected) != std::string::npos) {
          // Verify it's not just reflecting "49" from somewhere else
          auto check = http.get(base_url + "apex_safe_string_12345");
          if (check.body.find(p.expected) == std::string::npos) {
            findings.push_back(Finding{"SSTI — " + p.engine + " CONFIRMED", "critical", base_url + p.payload,
                                       "Server-Side Template Injection confirmed via " + p.engine +
                                           ". "
                                           "Payload '" +
                                           p.payload + "' evaluated to '" + p.expected +
                                           "'. "
                                           "Enables Remote Code Execution on the server.",
                                       param, p.payload, ""});
            return findings;  // Critical — stop
          }
        }
      }
      break;  // Test first param only for speed
    }
    if (!findings.empty()) break;
  }
  return findings;
}

/// CRLF injection in HTTP headers.
std::vector<Finding> scan_crlf_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // CRLF payloads in URL params
  std::vector<std::string> crlf_payloads = {
      "%0d%0aX-Injected:apex",
      "%0d%0a%0d%0a<script>alert(1)</script>",
      "\\r\\nX-Injected:apex",
      "%E5%98%8A%E5%98%8DX-Injected:apex",  // UTF-8 CRLF
  };

  for (const auto& url : crawl.urls) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) continue;

    for (const auto& payload : crlf_payloads) {
      auto resp = http.get(url + payload);
      // Check if injected header appears in response headers
      for (const auto& [key, val] : resp.headers) {
        if (key == "X-Injected" && val == "apex") {
          findings.push_back(Finding{"CRLF Injection — Header Injection", "high", url + payload,
                                     "CRLF characters in URL param inject into HTTP response headers. "
                                     "Enables: Set-Cookie injection (session fixation), "
                                     "XSS via response splitting, cache poisoning.",
                                     "", payload, ""});
          return findings;
        }
      }
      // Also check body for response splitting
      if (resp.body.find("X-Injected:apex") != std::string::npos) {
        findings.push_back(Finding{"CRLF Injection — Response Splitting", "high", url + payload,
                                   "CRLF injection causes HTTP response splitting. "
                                   "Full control over response body possible.",
                                   "", payload, ""});
        return findings;
      }
    }
    break;  // Test first URL with params
  }
  return findings;
}

/// Deserialization indicators — known vulnerable endpoints and patterns.
std::vector<Finding> scan_deserialization(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check for Java deserialization indicators
  auto resp = http.get(base);

  // Look for Java serialized objects in cookies/params
  for (const auto& [key, val] : resp.headers) {
    std::string lower = key;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "set-cookie") {
      // Java serialized: starts with rO0AB (base64 of 0xACED)
      if (val.find("rO0AB") != std::string::npos) {
        findings.push_back(Finding{"Java Deserialization — Serialized Cookie", "critical", base,
                                   "Cookie contains Java serialized object (rO0AB prefix). "
                                   "If deserialized without validation, enables Remote Code Execution "
                                   "via gadget chains (Commons Collections, etc.).",
                                   "", "", val.substr(0, 100)});
      }
      // .NET ViewState
      if (val.find("__VIEWSTATE") != std::string::npos) {
        findings.push_back(Finding{".NET ViewState — Potential Deserialization", "medium", base,
                                   "ASP.NET ViewState detected. If MAC validation is disabled, "
                                   "attacker can inject malicious serialized objects for RCE.",
                                   "", "", ""});
      }
    }
  }

  // Check for .NET ViewState in body
  if (resp.body.find("__VIEWSTATE") != std::string::npos) {
    std::regex vs_re(R"x(__VIEWSTATE[^>]+value="([^"]+)")x");
    std::smatch m;
    if (std::regex_search(resp.body, m, vs_re)) {
      std::string vs = m[1].str();
      // Unprotected ViewState doesn't start with /wE (encrypted indicator)
      if (vs.size() > 10 && vs.substr(0, 3) != "/wE") {
        findings.push_back(Finding{".NET ViewState — Not Encrypted", "high", base,
                                   "ViewState is not encrypted (missing /wE prefix). "
                                   "If MAC is also missing, RCE via deserialization is possible. "
                                   "Use ysoserial.net to generate payloads.",
                                   "__VIEWSTATE", vs.substr(0, 50) + "...", ""});
      }
    }
  }

  // PHP deserialization indicators
  std::vector<std::string> php_paths = {"/api/import", "/api/upload", "/api/data"};
  for (const auto& path : php_paths) {
    auto r = http.get(base + path);
    if (r.status_code == 200 || r.status_code == 400) {
      if (r.body.find("unserialize") != std::string::npos || r.body.find("O:") != std::string::npos) {
        findings.push_back(Finding{"PHP Deserialization Indicator", "medium", base + path,
                                   "Response contains PHP serialization patterns. "
                                   "If user input is unserialized, RCE via POP chains.",
                                   "", "", ""});
        break;
      }
    }
  }

  return findings;
}

/// Open redirect scanner — chain with OAuth for account takeover.
std::vector<Finding> scan_open_redirect(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find redirect params in crawled URLs
  std::regex redirect_param_re(
      R"x([?&](next|url|redirect|return|goto|continue|dest|destination|redir|returnUrl|return_to|forward|target|out|view|ref|r)=)x");

  for (const auto& url : crawl.urls) {
    std::smatch m;
    if (std::regex_search(url, m, redirect_param_re)) {
      std::string param = m[1].str();
      std::string inject_url = url.substr(0, url.find(param + "=") + param.size() + 1);

      // Test with external URL
      std::vector<std::string> payloads = {
          "https://evil.com", "//evil.com", "/\\evil.com", "https:evil.com", "////evil.com",
      };

      for (const auto& payload : payloads) {
        auto resp = http.get(inject_url + payload);
        // Check for redirect to evil
        if (resp.status_code == 301 || resp.status_code == 302 || resp.status_code == 303 || resp.status_code == 307) {
          auto loc = resp.headers.find("Location");
          if (loc != resp.headers.end() && loc->second.find("evil.com") != std::string::npos) {
            findings.push_back(Finding{"Open Redirect CONFIRMED", "medium", inject_url + payload,
                                       "Server redirects to attacker-controlled URL. "
                                       "Chain with OAuth redirect_uri for token theft, "
                                       "or use for phishing with legitimate-looking URL.",
                                       param, payload, "Location: " + loc->second});
            return findings;
          }
        }
        // Check meta/JS redirect in body
        if (resp.status_code == 200 && (resp.body.find("evil.com") != std::string::npos)) {
          findings.push_back(Finding{"Open Redirect — Client-Side", "low", inject_url + payload,
                                     "Server reflects redirect URL in response body (meta/JS redirect).", param, payload, ""});
          return findings;
        }
      }
      break;
    }
  }
  return findings;
}

/// Host header injection.
std::vector<Finding> scan_host_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Inject evil Host header
  auto resp = http.get(base, {{"Host", "evil.com"}});
  if (resp.status_code == 200 && resp.body.find("evil.com") != std::string::npos) {
    findings.push_back(Finding{"Host Header Injection", "high", base,
                               "Server reflects injected Host header in response. "
                               "Enables: password reset poisoning (reset link points to evil.com), "
                               "web cache poisoning, and SSRF via routing.",
                               "Host", "evil.com", ""});
  }

  // X-Forwarded-Host
  auto resp2 = http.get(base, {{"X-Forwarded-Host", "evil.com"}});
  if (resp2.status_code == 200 && resp2.body.find("evil.com") != std::string::npos) {
    findings.push_back(Finding{"Host Header Injection — X-Forwarded-Host", "high", base,
                               "X-Forwarded-Host reflected in response. "
                               "Enables password reset poisoning and cache poisoning.",
                               "X-Forwarded-Host", "evil.com", ""});
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_injection_advanced_scanners() {
  return {
      {"SSTI Detection", scan_ssti},         {"CRLF Injection", scan_crlf_injection},        {"Deserialization", scan_deserialization},
      {"Open Redirect", scan_open_redirect}, {"Host Header Injection", scan_host_injection},
  };
}

}  // namespace apex
