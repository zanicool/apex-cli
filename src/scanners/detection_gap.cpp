/// @file scanners/detection_gap.cpp
/// @brief Scanners for gaps found in vulnerability battery testing:
///        SSTI (improved), NoSQL Injection, IDOR, CORS (improved),
///        Secrets/Credentials in responses.
#include "scanner_base.hpp"
#include "confirm.hpp"
#include <regex>
#include <set>

namespace apex {
namespace {

/// Improved SSTI: also probes common param names on all crawled URLs.
std::vector<Finding> scan_ssti_deep(const Config &, HttpClient &http,
                                    const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Arithmetic canaries only: the "detect" value (49) never appears in the
  // payload itself, so a match proves EVALUATION, not mere reflection.
  // Payloads like {{self.__class__}} were removed because their detect string
  // ("__class__") is a substring of the payload — reflecting it unescaped
  // (normal XSS-style behaviour) produced false SSTI criticals.
  const std::vector<std::pair<std::string, std::string>> payloads = {
      {"{{7*7}}", "49"},
      {"${7*7}", "49"},
      {"<%= 7*7 %>", "49"},
  };
  const std::vector<std::string> ssti_params = {"name", "template", "input",
                                                 "msg", "text", "content"};

  for (const auto &url : crawl.urls) {
    // Try discovered params first
    std::vector<std::pair<std::string, std::string>> targets;
    for (const auto &p : crawl.params) {
      if (p.url == url) targets.push_back({p.url + "?" + p.name + "=", p.name});
    }
    // Also try common SSTI param names
    for (const auto &pname : ssti_params) {
      targets.push_back({url + "?" + pname + "=", pname});
    }

    for (const auto &[base, param] : targets) {
      auto baseline = http.get(base + "test123xyz");
      for (const auto &[payload, detect] : payloads) {
        auto resp = http.get(base + payload);
        // Centralized invariant: proves EVALUATION (not reflection) only when
        // the detect string is absent from the payload, present in the body,
        // and absent from the baseline. See src/scanners/confirm.hpp.
        if (confirm::is_evaluation_match(payload, detect, resp.body,
                                         baseline.body)) {
          findings.push_back({"SSTI", "critical", url,
                              "Server-Side Template Injection", param, payload,
                              detect});
          goto next_url; // one finding per URL is enough
        }
      }
    }
    next_url:;
  }
  return findings;
}

/// NoSQL Injection: MongoDB operator injection.
std::vector<Finding> scan_nosql(const Config &, HttpClient &http,
                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {
      "[$ne]=x", "[$gt]=", "[$regex]=.*", "{\"$ne\":\"\"}", "{\"$gt\":\"\"}"};
  const std::vector<std::string> indicators = {
      "admin", "superuser", "root", "username", "email"};

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "username");
    for (const auto &[base, param] : targets) {
      auto baseline = http.get(base + "normalvalue123");
      for (const auto &payload : payloads) {
        auto resp = http.get(base + payload);
        if (resp.status_code == 200 && resp.body.size() > baseline.body.size() &&
            contains_any(resp.body, indicators) &&
            !contains_any(baseline.body, indicators)) {
          findings.push_back({"NoSQL Injection", "critical", url,
                              "MongoDB operator injection", param, payload,
                              resp.body.substr(0, 200)});
          goto next_nosql;
        }
      }
    }
    next_nosql:;
  }
  return findings;
}

/// IDOR: Insecure Direct Object Reference via sequential ID enumeration.
///
/// A different response for a different id is NOT, by itself, IDOR — a public
/// data API (like this target's /users) legitimately returns different data
/// per id. Genuine IDOR requires an AUTHORIZATION differential: the object is
/// access-controlled, yet reachable across that control. Since we crawl
/// unauthenticated, we confirm an authz boundary exists by checking that the
/// endpoint distinguishes authenticated from unauthenticated access. If the
/// endpoint is fully public (identical behaviour with and without any auth
/// context, and never challenges with 401/403), we do NOT report.
std::vector<Finding> scan_idor(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Look for URLs with numeric IDs
  std::regex id_re(R"([\?&](id|user_id|uid|account|profile)=(\d+))");

  // Determine whether a given id-endpoint enforces any authorization at all.
  // We compare a request bearing a (bogus) auth context against a bare one.
  // Only if the app treats them differently — or challenges unauthenticated
  // access with 401/403 — is there a boundary that IDOR could bypass.
  auto has_authz_boundary = [&](const std::string &full_url) -> bool {
    // A genuine authorization boundary reveals itself by CHALLENGING access:
    // the resource (or its unauthenticated variant) returns 401/403, or a
    // bogus credential is actively rejected while the bare request is not.
    // A fully public API answers 200 regardless — that is not IDOR, so we do
    // not rely on mere body differences (which vary with the id itself).
    auto bare = http.get(full_url);
    if (bare.status_code == 401 || bare.status_code == 403) return true;
    std::vector<std::pair<std::string, std::string>> hdrs = {
        {"Authorization", "Bearer apexinvalidtoken"},
        {"Cookie", "session=apexinvalidsession"}};
    auto authed = http.get(full_url, hdrs);
    // Rejecting a bogus credential with a challenge status proves an auth layer.
    if (authed.status_code == 401 || authed.status_code == 403) return true;
    // A status-code change between bare and bogus-auth also indicates the app
    // processes auth. (Body-only differences are intentionally NOT trusted.)
    if (authed.status_code != bare.status_code) return true;
    return false;
  };

  for (const auto &url : crawl.urls) {
    std::smatch m;
    if (!std::regex_search(url, m, id_re)) continue;

    std::string param = m[1].str();
    int id = std::stoi(m[2].str());
    std::string base_path = url.substr(0, url.find('?')) + "?" + param + "=";

    // Get response for current ID
    auto resp1 = http.get(base_path + std::to_string(id));
    if (resp1.status_code != 200) continue;

    // Gate: only pursue IDOR if this endpoint enforces some authorization.
    if (!has_authz_boundary(base_path + std::to_string(id))) continue;

    // Try adjacent IDs — if we get different data, IDOR likely
    for (int other : {id + 1, id - 1, id + 100}) {
      if (other <= 0) continue;
      auto resp2 = http.get(base_path + std::to_string(other));
      if (resp2.status_code == 200 && !resp2.body.empty() &&
          resp2.body != resp1.body &&
          resp2.body.size() > 10) {
        findings.push_back({"IDOR", "high", url,
                            "Cross-object access despite an authorization "
                            "boundary (sequential ID)",
                            param,
                            std::to_string(other),
                            "Authz boundary present, yet ID " +
                                std::to_string(other) +
                                " returned different data unauthenticated"});
        break;
      }
    }
  }

  // Also check /users/1, /users/2 style paths
  for (const auto &url : crawl.urls) {
    std::regex path_id_re(R"((/(?:users?|profiles?|accounts?|orders?)/)\d+)");
    std::smatch m;
    if (!std::regex_search(url, m, path_id_re)) continue;
    std::string prefix = url.substr(0, url.find(m[1].str()) + m[1].str().size());
    if (!has_authz_boundary(prefix + "1")) continue;
    auto r1 = http.get(prefix + "1");
    auto r2 = http.get(prefix + "2");
    if (r1.status_code == 200 && r2.status_code == 200 &&
        r1.body != r2.body && r1.body.size() > 10 && r2.body.size() > 10) {
      findings.push_back({"IDOR", "high", url,
                          "Enumerable protected resource path", "path_id",
                          "1,2",
                          "Authz boundary present, yet both IDs return "
                          "different valid data unauthenticated"});
    }
  }
  return findings;
}

/// Improved CORS: test origin reflection and null origin.
std::vector<Finding> scan_cors_deep(const Config &, HttpClient &http,
                                    const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Test a subset of URLs (max 20)
  size_t limit = std::min(crawl.urls.size(), size_t(20));
  for (size_t i = 0; i < limit; ++i) {
    const auto &url = crawl.urls[i];

    // Test 1: reflected origin
    auto resp = http.get(url, {{"Origin", "https://evil.com"}});
    auto acao = resp.headers.find("Access-Control-Allow-Origin");
    if (acao != resp.headers.end()) {
      if (acao->second == "https://evil.com") {
        auto acac = resp.headers.find("Access-Control-Allow-Credentials");
        std::string sev = (acac != resp.headers.end() && acac->second == "true")
                              ? "critical" : "high";
        findings.push_back({"CORS Misconfiguration", sev, url,
                            "Origin reflected: " + acao->second, "", "",
                            "Access-Control-Allow-Origin: " + acao->second});
        continue;
      }
      if (acao->second == "*") {
        findings.push_back({"CORS Misconfiguration", "medium", url,
                            "Wildcard CORS allows any origin", "", "",
                            "Access-Control-Allow-Origin: *"});
        continue;
      }
    }

    // Test 2: null origin
    resp = http.get(url, {{"Origin", "null"}});
    acao = resp.headers.find("Access-Control-Allow-Origin");
    if (acao != resp.headers.end() && acao->second == "null") {
      findings.push_back({"CORS Misconfiguration", "high", url,
                          "Null origin accepted", "", "null",
                          "Access-Control-Allow-Origin: null"});
    }
  }
  return findings;
}

/// Secrets/Credentials in responses: scan response bodies for leaked secrets.
std::vector<Finding> scan_response_secrets(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  struct SecretPattern {
    std::string name;
    std::regex re;
    std::string severity;
  };
  std::vector<SecretPattern> patterns = {
      {"AWS Access Key", std::regex(R"(AKIA[0-9A-Z]{16})"), "critical"},
      {"AWS Secret Key",
       std::regex(R"((?:aws_secret|secret_key|AWS_SECRET)[^=]*=\s*[A-Za-z0-9/+=]{40})"),
       "critical"},
      {"Generic API Key",
       std::regex(R"((?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,})"),
       "high"},
      {"Private Key", std::regex(R"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)"),
       "critical"},
      {"JWT Token",
       std::regex(R"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
       "high"},
      {"Stripe Key", std::regex(R"(sk_live_[0-9a-zA-Z]{24,})"), "critical"},
      {"Database URL",
       std::regex(R"((?:mysql|postgres|mongodb)://[^\s"'<]+:[^\s"'<]+@[^\s"'<]+)"),
       "critical"},
      {"Password in Config",
       std::regex(R"((?:password|passwd|pwd|secret)\s*[:=]\s*["'][^"']{4,}["'])"),
       "high"},
  };

  // Scan crawled URLs + common config endpoints
  std::vector<std::string> urls_to_check = crawl.urls;
  if (!crawl.urls.empty()) {
    std::string base = base_url_from(crawl.urls[0]);
    for (const auto &p : {"/api/config", "/env", "/debug", "/status",
                          "/actuator/env", "/.env"}) {
      urls_to_check.push_back(base + p);
    }
  }

  size_t limit = std::min(urls_to_check.size(), size_t(50));
  for (size_t i = 0; i < limit; ++i) {
    auto resp = http.get(urls_to_check[i]);
    if (resp.status_code != 200 || resp.body.empty()) continue;

    for (const auto &pat : patterns) {
      std::smatch m;
      if (std::regex_search(resp.body, m, pat.re)) {
        std::string evidence = m[0].str();
        // Mask the actual secret value
        if (evidence.size() > 20)
          evidence = evidence.substr(0, 10) + "..." + evidence.substr(evidence.size() - 5);
        findings.push_back({"Secrets Exposure", pat.severity, urls_to_check[i],
                            pat.name + " found in response", "", "",
                            evidence});
        break; // one finding per URL
      }
    }
  }
  return findings;
}

/// Auth-bypass SQL injection on POST login forms.
///
/// APEX's primary SQLi scanner is GET-only and error-string-based, so it misses
/// the classic login auth-bypass (e.g. uid=admin'-- ) where the app silently
/// logs the attacker in with NO SQL error in the body. We detect it by response
/// differential: submit a rejected baseline (junk credentials) and then SQLi
/// payloads to the same POST login form WITHOUT following redirects, and flag a
/// finding when the injected request crosses from "login rejected" to an
/// authenticated destination (see confirm::is_auth_bypass).
std::vector<Finding> scan_login_sqli(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> sqli_payloads = {"admin'--", "' OR '1'='1'--"};

  std::set<std::string> tested_actions;
  int forms_tested = 0;
  for (const auto &form : crawl.forms) {
    if (forms_tested >= 2) break; // bound work hard: at most 2 login forms
    // Only POST forms that look like a login (have a password field).
    bool is_post = form.method == "POST" || form.method == "post" ||
                   form.method.empty();
    if (!is_post) continue;
    std::string user_field, pass_field;
    for (const auto &f : form.fields) {
      std::string n = f.name;
      for (auto &c : n) c = static_cast<char>(::tolower(c));
      if (pass_field.empty() &&
          (n.find("pass") != std::string::npos || n == "pwd"))
        pass_field = f.name;
      else if (user_field.empty() &&
               (n.find("user") != std::string::npos || n == "uid" ||
                n.find("email") != std::string::npos || n == "login" ||
                n.find("name") != std::string::npos))
        user_field = f.name;
    }
    if (user_field.empty() || pass_field.empty()) continue;

    // Resolve action to an absolute URL.
    std::string action = form.action;
    if (action.rfind("http", 0) != 0) {
      std::string origin = base_url_from(crawl.urls.empty() ? "" : crawl.urls[0]);
      if (!action.empty() && action[0] == '/')
        action = origin + action;
      else
        action = origin + "/" + action;
    }
    // Dedup: the same login form appears on many crawled pages.
    if (!tested_actions.insert(action).second) continue;
    ++forms_tested;

    auto body_of = [&](const std::string &u, const std::string &p) {
      return user_field + "=" + url_encode(u) + "&" + pass_field + "=" +
             url_encode(p);
    };

    // Rejected baseline: obviously-invalid credentials.
    auto baseline = http.post_no_follow(
        action, body_of("apexnouser1234", "apexnopass1234"),
        "application/x-www-form-urlencoded");
    auto base_loc = baseline.headers.count("Location")
                        ? baseline.headers.at("Location")
                        : "";

    for (const auto &payload : sqli_payloads) {
      auto atk = http.post_no_follow(action, body_of(payload, "x"),
                                     "application/x-www-form-urlencoded");
      std::string atk_loc =
          atk.headers.count("Location") ? atk.headers.at("Location") : "";
      if (confirm::is_auth_bypass(baseline.status_code, base_loc,
                                  atk.status_code, atk_loc)) {
        findings.push_back(
            {"SQLi", "critical", action,
             "Authentication-bypass SQL injection on login form", user_field,
             payload,
             "rejected baseline -> " +
                 (base_loc.empty() ? std::to_string(baseline.status_code)
                                   : base_loc) +
                 "; injection -> " +
                 (atk_loc.empty() ? std::to_string(atk.status_code) : atk_loc)});
        break; // one confirmation per form is enough
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_detection_gap_scanners() {
  return {
      {"SSTI Deep", scan_ssti_deep},
      {"NoSQL Injection", scan_nosql},
      {"IDOR", scan_idor},
      {"CORS Deep", scan_cors_deep},
      {"Secrets Exposure", scan_response_secrets},
      {"Login SQLi (auth bypass)", scan_login_sqli},
  };
}

} // namespace apex
