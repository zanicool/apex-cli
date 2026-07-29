/// @file scanners/extra.cpp
/// @brief Extra scanners: SAML, web cache deception, timing attacks, account
///        takeover, email injection, ReDoS, null byte, range amplification,
///        hop-by-hop, method override, XSLT, log injection.
#include <chrono>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Web cache deception — trick cache into storing private data.
std::vector<Finding> scan_web_cache_deception(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/account", "/profile", "/settings"};
  const std::vector<std::string> extensions = {"/x.css", "/x.js", "/x.png"};

  for (const auto& path : paths) {
    for (const auto& ext : extensions) {
      auto resp = http.get(base + path + ext);
      if (resp.status_code == 200 && resp.body.size() > 100) {
        auto cache = resp.headers.find("X-Cache");
        if (cache != resp.headers.end() && cache->second.find("HIT") != std::string::npos) {
          findings.push_back({"Web Cache Deception", "high", base + path + ext, "Private page cached with static extension", "", ext, ""});
        }
      }
    }
  }
  return findings;
}

/// Timing attacks — detect information leakage via response time.
std::vector<Finding> scan_timing(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "username");
    for (const auto& [base, param] : targets) {
      // Compare timing for existing vs non-existing values.
      long total_short = 0, total_long = 0;
      for (int i = 0; i < 3; ++i) {
        auto r1 = http.get(base + "admin");
        auto r2 = http.get(base + "nonexistent_user_xyz_" + std::to_string(i));
        total_short += r1.duration.count();
        total_long += r2.duration.count();
      }
      long diff = std::abs(total_short / 3 - total_long / 3);
      if (diff > 50) {
        findings.push_back({"Timing Attack", "low", url, "Response time difference: " + std::to_string(diff) + "ms avg", param, "", ""});
      }
    }
  }
  return findings;
}

/// Email header injection.
std::vector<Finding> scan_email_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::string payload = "test@test.com%0aBcc:evil@evil.com";

  for (const auto& url : crawl.urls) {
    for (const auto& p : crawl.params) {
      if (p.url != url) continue;
      if (p.name.find("email") == std::string::npos && p.name.find("mail") == std::string::npos) continue;
      auto resp = http.get(p.url + "?" + p.name + "=" + payload);
      if (resp.status_code == 200 && resp.body.find("error") == std::string::npos) {
        findings.push_back({"Email Injection", "medium", url, "Email header injection possible", p.name, payload, ""});
      }
    }
  }
  return findings;
}

/// ReDoS — Regular Expression Denial of Service.
std::vector<Finding> scan_redos(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Payloads that trigger catastrophic backtracking.
  const std::vector<std::string> payloads = {std::string(50, 'a') + "!", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", std::string(30, '0') + "x"};

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "q");
    for (const auto& [base, param] : targets) {
      auto baseline = http.get(base + "normal");
      for (const auto& payload : payloads) {
        auto resp = http.get(base + payload);
        if (resp.duration.count() > baseline.duration.count() + 3000) {
          findings.push_back({"ReDoS", "medium", url, "Regex DoS: " + std::to_string(resp.duration.count()) + "ms", param, payload, ""});
          break;
        }
      }
    }
  }
  return findings;
}

/// Null byte injection.
std::vector<Finding> scan_null_byte(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "file");
    for (const auto& [base, param] : targets) {
      auto resp = http.get(base + "../../etc/passwd%00.jpg");
      if (resp.body.find("root:") != std::string::npos) {
        findings.push_back({"Null Byte", "high", url, "Null byte truncation bypass", param, "../../etc/passwd%00.jpg", ""});
      }
    }
  }
  return findings;
}

/// Range header amplification.
std::vector<Finding> scan_range_amplification(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Send overlapping range request.
  std::string ranges = "bytes=0-0";
  for (int i = 1; i < 100; ++i) ranges += ",0-0";

  auto resp = http.get(crawl.urls[0], {{"Range", ranges}});
  if (resp.status_code == 206 && resp.body.size() > 1000) {
    findings.push_back(
        {"Range Amplification", "medium", crawl.urls[0], "Server processes overlapping ranges (DoS risk)", "", ranges.substr(0, 50), ""});
  }
  return findings;
}

/// Hop-by-hop header abuse.
std::vector<Finding> scan_hop_by_hop(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto normal = http.get(crawl.urls[0]);
  auto resp = http.get(crawl.urls[0], {{"Connection", "close, X-Forwarded-For"}});
  if (resp.status_code != normal.status_code || resp.body.size() != normal.body.size()) {
    findings.push_back({"Hop-by-Hop", "low", crawl.urls[0], "Hop-by-hop header stripping detected", "", "", ""});
  }
  return findings;
}

/// Method override — X-HTTP-Method-Override.
std::vector<Finding> scan_method_override(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/api/user/1", "/api/admin"};
  for (const auto& path : paths) {
    auto resp = http.post(base + path, "", "text/plain", {{"X-HTTP-Method-Override", "DELETE"}});
    if (resp.status_code == 200 || resp.status_code == 204) {
      findings.push_back(
          {"Method Override", "medium", base + path, "X-HTTP-Method-Override accepted (DELETE)", "", "X-HTTP-Method-Override: DELETE", ""});
    }
  }
  return findings;
}

/// XSLT injection.
std::vector<Finding> scan_xslt(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::string payload =
      R"xml(<?xml version="1.0"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:value-of select="system-property('xsl:version')"/></xsl:template></xsl:stylesheet>)xml";

  for (const auto& url : crawl.urls) {
    auto resp = http.post(url, payload, "application/xml");
    if (resp.body.find("1.0") != std::string::npos || resp.body.find("2.0") != std::string::npos) {
      findings.push_back({"XSLT Injection", "high", url, "XSLT processing detected", "", "", ""});
    }
  }
  return findings;
}

/// Log injection.
std::vector<Finding> scan_log_injection(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::string payload = "test%0d%0aINJECTED_LOG_ENTRY";

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "username");
    for (const auto& [base, param] : targets) {
      auto resp = http.get(base + payload);
      // Only report if the injected content is actually reflected in response
      if (resp.status_code == 200 && resp.body.find("INJECTED_LOG_ENTRY") != std::string::npos) {
        findings.push_back({"Log Injection", "low", url, "CRLF in parameter reflected in response (log/header injection)", param, payload, ""});
        break;
      }
    }
  }
  return findings;
}

/// SAML vulnerability scanner.
std::vector<Finding> scan_saml(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> saml_paths = {"/saml/metadata", "/auth/saml/metadata", "/sso/saml/metadata"};

  for (const auto& path : saml_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.find("EntityDescriptor") != std::string::npos) {
      findings.push_back({"SAML Metadata", "info", base + path, "SAML metadata exposed", "", "", ""});
      // Check for signature wrapping vulnerability.
      if (resp.body.find("WantAssertionsSigned") != std::string::npos && resp.body.find("false") != std::string::npos) {
        findings.push_back({"SAML Weakness", "high", base + path, "SAML assertions not required to be signed", "", "", ""});
      }
    }
  }
  return findings;
}

/// Billion Laughs — XML bomb DoS.
std::vector<Finding> scan_billion_laughs(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  // Small XML bomb that shouldn't crash but tests if XML parsing is unlimited.
  const std::string payload =
      "<?xml version=\"1.0\"?><!DOCTYPE lolz ["
      "<!ENTITY lol \"lol\">"
      "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;\">"
      "<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;\">"
      "]><root>&lol3;</root>";
  for (const auto& url : crawl.urls) {
    auto resp = http.post(url, payload, "application/xml");
    if (resp.duration.count() > 5000) {
      findings.push_back(
          {"Billion Laughs", "medium", url, "XML bomb caused " + std::to_string(resp.duration.count()) + "ms delay", "", "", ""});
    }
  }
  return findings;
}

/// Open Redirect → OAuth chain — steal tokens via redirect.
std::vector<Finding> scan_redirect_oauth_chain(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::string> oauth_paths = {"/oauth/authorize", "/auth/authorize", "/connect/authorize"};
  for (const auto& path : oauth_paths) {
    auto resp = http.get(base + path + "?redirect_uri=https://evil.com/callback&response_type=code&client_id=test");
    if (resp.status_code == 302 || resp.status_code == 301) {
      auto loc = resp.headers.find("Location");
      if (loc != resp.headers.end() && loc->second.find("evil.com") != std::string::npos) {
        findings.push_back({"OAuth Redirect Chain", "high", base + path, "OAuth allows arbitrary redirect_uri", "",
                            "redirect_uri=https://evil.com/callback", ""});
      }
    }
  }
  return findings;
}

/// Tech-Specific — targeted checks based on detected technology.
std::vector<Finding> scan_tech_specific(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  auto resp = http.get(base + "/");

  // ColdFusion specific.
  if (resp.body.find("cfid") != std::string::npos || resp.body.find(".cfm") != std::string::npos) {
    auto cf = http.get(base + "/CFIDE/administrator/enter.cfm");
    if (cf.status_code == 200)
      findings.push_back(
          {"Tech-Specific", "high", base + "/CFIDE/administrator/enter.cfm", "ColdFusion admin panel accessible", "", "", ""});
  }
  // Laravel specific.
  if (resp.body.find("laravel") != std::string::npos) {
    auto dbg = http.get(base + "/_ignition/health-check");
    if (dbg.status_code == 200)
      findings.push_back({"Tech-Specific", "medium", base + "/_ignition/health-check", "Laravel Ignition debug mode enabled", "", "", ""});
  }
  // Django specific.
  if (resp.body.find("csrfmiddlewaretoken") != std::string::npos) {
    auto dbg = http.get(base + "/__debug__/");
    if (dbg.status_code == 200)
      findings.push_back({"Tech-Specific", "high", base + "/__debug__/", "Django debug toolbar accessible", "", "", ""});
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_extra_scanners() {
  return {
      {"Web Cache Deception", scan_web_cache_deception},
      {"Timing Attack", scan_timing},
      {"Email Injection", scan_email_injection},
      {"ReDoS", scan_redos},
      {"Null Byte", scan_null_byte},
      {"Range Amplification", scan_range_amplification},
      {"Hop-by-Hop", scan_hop_by_hop},
      {"Method Override", scan_method_override},
      {"XSLT Injection", scan_xslt},
      {"Log Injection", scan_log_injection},
      {"SAML", scan_saml},
      {"Billion Laughs", scan_billion_laughs},
      {"OAuth Redirect Chain", scan_redirect_oauth_chain},
      {"Tech-Specific", scan_tech_specific},
  };
}

}  // namespace apex
