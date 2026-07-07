/// @file scanners/cache_poison.cpp
/// @brief Web Cache Poisoning + Web Cache Deception scanner.
///        Exploits differences between cache key and server behavior.
///        Also detects prototype pollution gadgets and DOM clobbering.
#include <random>
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Generate a random cache buster to avoid poisoning real cache.
std::string cache_buster() {
  static std::mt19937 rng(std::random_device{}());
  return "apex" + std::to_string(rng() % 999999);
}

/// Web Cache Poisoning: inject unkeyed headers reflected in response.
std::vector<Finding> scan_cache_poison_headers(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  std::string buster = cache_buster();

  // Unkeyed headers that might be reflected in response
  std::vector<std::pair<std::string, std::string>> poison_headers = {
      {"X-Forwarded-Host", buster + ".evil.com"},   {"X-Original-URL", "/" + buster},   {"X-Rewrite-URL", "/" + buster},
      {"X-Forwarded-Scheme", "nothttps"},           {"X-Forwarded-Proto", "nothttps"},  {"X-Host", buster + ".evil.com"},
      {"X-Forwarded-Server", buster + ".evil.com"}, {"X-HTTP-Method-Override", "POST"}, {"X-Original-Host", buster + ".evil.com"},
  };

  std::string test_url = base + "/?cb=" + buster;

  for (const auto& [header, value] : poison_headers) {
    auto resp = http.get(test_url, {{header, value}});
    if (resp.status_code == 200 && resp.body.find(value) != std::string::npos) {
      // Header value reflected — check if cacheable
      bool cacheable = false;
      for (const auto& [key, val] : resp.headers) {
        std::string lower = key;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower == "cache-control" && (val.find("public") != std::string::npos || val.find("max-age") != std::string::npos)) {
          cacheable = true;
        }
        if (lower == "x-cache" || lower == "cf-cache-status" || lower == "x-varnish" || lower == "age") {
          cacheable = true;
        }
      }

      std::string severity = cacheable ? "high" : "medium";
      findings.push_back({"Web Cache Poisoning — " + header, severity, test_url,
                          "Unkeyed header '" + header + "' is reflected in response" +
                              (cacheable ? " AND response is cacheable. Full cache poisoning possible — "
                                           "inject XSS/redirect for all users via cache."
                                         : ". If response becomes cached, XSS/redirect affects all users."),
                          header, value, "Reflected in " + std::to_string(resp.body.size()) + " byte response"});
      if (cacheable) break;  // Critical finding, stop
    }
  }
  return findings;
}

/// Web Cache Deception: trick cache into storing authenticated responses.
std::vector<Finding> scan_cache_deception(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Try path confusion: /account/profile/nonexistent.css
  // If server serves /account/profile (dynamic) but cache keys on .css extension (static)
  std::vector<std::string> auth_paths = {"/account", "/profile", "/settings", "/dashboard", "/api/me", "/api/user", "/my-account"};

  std::vector<std::string> static_suffixes = {"/apex-test.css", "/apex-test.js", "/apex-test.png", "/.css", "/..%2fapex.css", "%0d%0a.css"};

  for (const auto& path : auth_paths) {
    auto normal = http.get(base + path);
    if (normal.status_code != 200) continue;

    for (const auto& suffix : static_suffixes) {
      auto deception = http.get(base + path + suffix);
      if (deception.status_code == 200 && deception.body == normal.body) {
        // Same content served — check if this one gets cached
        bool cached = false;
        for (const auto& [key, val] : deception.headers) {
          std::string lower = key;
          std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
          if (lower == "x-cache" && val.find("HIT") != std::string::npos) cached = true;
          if (lower == "cf-cache-status" && val.find("HIT") != std::string::npos) cached = true;
          if (lower == "cache-control" && val.find("public") != std::string::npos) cached = true;
        }

        findings.push_back({"Web Cache Deception", cached ? "high" : "medium", base + path + suffix,
                            "Path confusion: " + path + suffix + " serves same content as " + path +
                                ". "
                                "If cached, attacker can trick victim into visiting this URL, "
                                "cache stores their authenticated response, attacker retrieves it.",
                            "", suffix, cached ? "CONFIRMED: Response was cached" : "Response identical, cache status unknown"});
        if (cached) return findings;
        break;
      }
    }
  }
  return findings;
}

/// Prototype Pollution: detect __proto__ and constructor.prototype in URL params/JSON.
std::vector<Finding> scan_prototype_pollution(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check if target uses JavaScript frameworks (likely if .js files present)
  auto resp = http.get(base);
  if (resp.body.find("<script") == std::string::npos) return findings;

  // URL-based prototype pollution
  std::vector<std::string> pp_payloads = {
      "?__proto__[apex]=polluted",
      "?constructor[prototype][apex]=polluted",
      "?__proto__.apex=polluted",
      "#__proto__[apex]=polluted",
  };

  for (const auto& payload : pp_payloads) {
    auto r = http.get(base + payload);
    if (r.status_code == 200) {
      // Check if response reflects or processes the pollution
      // Look for common gadgets that would execute if polluted
      if (r.body.find("polluted") != std::string::npos) {
        findings.push_back({"Prototype Pollution — Reflected", "high", base + payload,
                            "Prototype pollution payload reflected in response. "
                            "If client-side JS merges URL params into objects, this enables XSS "
                            "via gadgets (innerHTML, srcdoc, onclick, etc.).",
                            "__proto__", payload, ""});
        break;
      }
    }
  }

  // Check for known vulnerable JS libraries
  std::regex lib_re(R"x((lodash|jquery|backbone|underscore|merge|deepmerge|hoek|qs)[./\-](\d+\.\d+))x");
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), lib_re);
  std::sregex_iterator end;
  for (; it != end; ++it) {
    findings.push_back({"Prototype Pollution — Vulnerable Library", "medium", base,
                        "Library '" + (*it)[1].str() + " v" + (*it)[2].str() +
                            "' detected. "
                            "Many versions of this library are vulnerable to prototype pollution. "
                            "Check if object merge/extend functions process attacker input.",
                        "", (*it).str(), ""});
    break;
  }

  return findings;
}

/// DOM Clobbering: detect clobberable DOM elements.
std::vector<Finding> scan_dom_clobbering(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);
  if (resp.status_code != 200) return findings;

  // Look for patterns where HTML id/name attributes could clobber JS globals
  // Pattern: code references a global that could be overridden by DOM element
  std::regex global_ref_re(
      R"x((?:window\.|document\.)(config|settings|data|options|params|user|auth|token|key|secret|endpoint|api|url|callback))x");
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), global_ref_re);
  std::sregex_iterator end;

  std::vector<std::string> clobberable;
  for (; it != end; ++it) {
    std::string name = (*it)[1].str();
    // Check if there's no existing element with this id
    std::string id_check = "id=\"" + name + "\"";
    if (resp.body.find(id_check) == std::string::npos) {
      clobberable.push_back(name);
    }
  }

  if (!clobberable.empty()) {
    findings.push_back({"DOM Clobbering — Clobberable Globals", "medium", base,
                        "JavaScript references global variables that can be overridden via DOM: " + clobberable[0] +
                            (clobberable.size() > 1 ? " (+" + std::to_string(clobberable.size() - 1) + " more)" : "") +
                            ". If attacker can inject HTML (e.g., via stored content), they can "
                            "override these globals with <a id=\"" +
                            clobberable[0] + "\" href=\"evil\">.",
                        "", clobberable[0], ""});
  }

  return findings;
}

/// CORS misconfiguration: reflect origin, null origin, subdomain wildcard.
std::vector<Finding> scan_cors_misconfig(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Test origin reflection
  std::vector<std::pair<std::string, std::string>> origins = {
      {"https://evil.com", "arbitrary origin"},
      {"null", "null origin (sandboxed iframe)"},
      {"https://evil." + base.substr(base.find("://") + 3), "subdomain of target"},
  };

  for (const auto& [origin, desc] : origins) {
    auto resp = http.get(base + "/api/", {{"Origin", origin}});
    auto acao = resp.headers.find("Access-Control-Allow-Origin");
    auto acac = resp.headers.find("Access-Control-Allow-Credentials");

    if (acao != resp.headers.end() && acao->second == origin) {
      bool with_creds = (acac != resp.headers.end() && acac->second == "true");
      std::string severity = with_creds ? "critical" : "high";
      findings.push_back({"CORS Misconfiguration — " + desc, severity, base,
                          "Server reflects " + desc + " in Access-Control-Allow-Origin" +
                              (with_creds ? " WITH credentials allowed. "
                                            "Attacker can steal authenticated data cross-origin from any website."
                                          : ". May allow cross-origin data theft."),
                          "Origin", origin, "ACAO: " + acao->second + (with_creds ? ", ACAC: true" : "")});
      break;
    }
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_cache_poison_scanners() {
  return {
      {"Cache Poison Headers", scan_cache_poison_headers}, {"Cache Deception", scan_cache_deception},
      {"Prototype Pollution", scan_prototype_pollution},   {"DOM Clobbering", scan_dom_clobbering},
      {"CORS Misconfiguration", scan_cors_misconfig},
  };
}

}  // namespace apex
