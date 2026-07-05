/// @file scanners/recon_deep2.cpp
/// @brief Deep Recon Phase 2: JS file secret extraction, API schema auto-discovery,
///        subdomain brute from JS/HTML, hidden endpoint extraction from source maps,
///        and technology-specific path fuzzing.
#include "scanner_base.hpp"
#include <regex>
#include <set>

namespace apex {
namespace {

/// Extract secrets and API endpoints from all JavaScript files.
std::vector<Finding> scan_js_secrets(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Get main page and find JS files
  auto resp = http.get(base);
  std::regex js_re(R"x((?:src|href)=["']([^"']*\.js(?:\?[^"']*)?)["'])x");
  std::set<std::string> js_urls;
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), js_re);
  std::sregex_iterator end;
  for (; it != end && js_urls.size() < 15; ++it) {
    std::string url = (*it)[1].str();
    if (url[0] == '/') url = base + url;
    else if (url.find("http") != 0) url = base + "/" + url;
    js_urls.insert(url);
  }

  // Secret patterns
  struct SecretPattern {
    std::string name;
    std::string pattern;
    std::string severity;
  };

  std::vector<SecretPattern> patterns = {
      {"AWS Access Key", R"x(AKIA[A-Z0-9]{16})x", "critical"},
      {"AWS Secret Key", R"x((?:aws.?secret|secret.?key)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"])x", "critical"},
      {"Stripe Secret Key", R"x(sk_live_[A-Za-z0-9]{24,})x", "critical"},
      {"Stripe Publishable", R"x(pk_live_[A-Za-z0-9]{24,})x", "low"},
      {"GitHub Token", R"x(ghp_[A-Za-z0-9]{36})x", "critical"},
      {"GitLab Token", R"x(glpat-[A-Za-z0-9_-]{20,})x", "critical"},
      {"Slack Token", R"x(xox[baprs]-[A-Za-z0-9-]{10,})x", "high"},
      {"Google API Key", R"x(AIza[0-9A-Za-z_-]{35})x", "medium"},
      {"Firebase Config", R"x(apiKey:\s*['"]AIza[^'"]+['"])x", "medium"},
      {"Private Key", R"x(-----BEGIN (?:RSA )?PRIVATE KEY-----)x", "critical"},
      {"JWT Secret", R"x((?:jwt.?secret|token.?secret)\s*[:=]\s*['"]([^'"]{8,})['"])x", "high"},
      {"Database URL", R"x((?:postgres|mysql|mongodb)://[^'">\s]+)x", "critical"},
      {"SendGrid Key", R"x(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})x", "high"},
      {"Twilio", R"x(SK[0-9a-fA-F]{32})x", "high"},
      {"Mailgun Key", R"x(key-[0-9a-zA-Z]{32})x", "high"},
      {"Heroku API Key", R"x([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})x", "low"},
  };

  for (const auto &js_url : js_urls) {
    auto js_resp = http.get(js_url);
    if (js_resp.status_code != 200 || js_resp.body.size() < 100) continue;

    for (const auto &pat : patterns) {
      std::regex re(pat.pattern);
      std::sregex_iterator sit(js_resp.body.begin(), js_resp.body.end(), re);
      if (sit != end) {
        std::string match = (*sit).str();
        // Skip obviously fake/placeholder values
        if (match.find("EXAMPLE") != std::string::npos) continue;
        if (match.find("xxx") != std::string::npos) continue;
        if (match.find("test") != std::string::npos) continue;
        if (match.find("000000") != std::string::npos) continue;

        findings.push_back(Finding{pat.name + " in JavaScript", pat.severity, js_url,
                            pat.name + " found in JS bundle. Key: " + match.substr(0, 25) + "...",
                            "", match.substr(0, 30) + "...", ""});
        break;
      }
    }
    if (findings.size() >= 5) break;
  }

  return findings;
}

/// Extract API endpoints from JavaScript files.
std::vector<Finding> scan_js_api_endpoints(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);
  std::regex js_re(R"x((?:src|href)=["']([^"']*\.js(?:\?[^"']*)?)["'])x");
  std::set<std::string> js_urls;
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), js_re);
  std::sregex_iterator end;
  for (; it != end && js_urls.size() < 10; ++it) {
    std::string url = (*it)[1].str();
    if (url[0] == '/') url = base + url;
    else if (url.find("http") != 0) url = base + "/" + url;
    js_urls.insert(url);
  }

  std::set<std::string> api_endpoints;
  std::regex api_re(R"x(["'](/api/[^"'\s}{]+)["'])x");

  for (const auto &js_url : js_urls) {
    auto js_resp = http.get(js_url);
    if (js_resp.status_code != 200) continue;

    std::sregex_iterator ait(js_resp.body.begin(), js_resp.body.end(), api_re);
    for (; ait != end && api_endpoints.size() < 30; ++ait) {
      api_endpoints.insert((*ait)[1].str());
    }
  }

  if (api_endpoints.size() > 5) {
    std::string endpoints_list;
    int count = 0;
    for (const auto &ep : api_endpoints) {
      endpoints_list += ep + "\n";
      if (++count >= 20) break;
    }
    findings.push_back(Finding{"Hidden API Endpoints in JS", "info", base,
                        std::to_string(api_endpoints.size()) + " API endpoints extracted from JavaScript bundles",
                        "", "", endpoints_list});
  }

  // Test each discovered endpoint for auth bypass
  for (const auto &ep : api_endpoints) {
    if (ep.find("admin") != std::string::npos || ep.find("internal") != std::string::npos ||
        ep.find("debug") != std::string::npos || ep.find("private") != std::string::npos) {
      auto test = http.get(base + ep);
      if (test.status_code == 200 && test.body.size() > 100 &&
          (test.body.find("{") == 0 || test.body.find("[") == 0) &&
          test.body.find("error") == std::string::npos) {
        findings.push_back(Finding{"Hidden Admin API Accessible", "high", base + ep,
                            "Admin/internal API endpoint from JS is accessible without auth.",
                            "", ep, test.body.substr(0, 200)});
        break;
      }
    }
  }

  return findings;
}

/// Discover subdomains from JS/HTML content.
std::vector<Finding> scan_subdomain_from_source(const Config &, HttpClient &http,
                                                 const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Extract main domain
  std::string domain = base;
  auto proto = domain.find("://");
  if (proto != std::string::npos) domain = domain.substr(proto + 3);
  auto slash = domain.find("/");
  if (slash != std::string::npos) domain = domain.substr(0, slash);
  if (domain.substr(0, 4) == "www.") domain = domain.substr(4);

  auto resp = http.get(base);
  
  // Find subdomains in page source
  std::string pattern = R"x(([a-z0-9][-a-z0-9]*\.)x" + std::string(")") +
                        domain;
  // Simplified: just find anything.domain in the source
  std::set<std::string> subdomains;
  std::regex sub_re("[a-z0-9][-a-z0-9]*\\." + domain);
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), sub_re);
  std::sregex_iterator end;
  for (; it != end; ++it) {
    std::string sub = (*it).str();
    if (sub != "www." + domain && sub != domain) {
      subdomains.insert(sub);
    }
  }

  if (subdomains.size() > 3) {
    std::string sub_list;
    for (const auto &s : subdomains) sub_list += s + "\n";
    findings.push_back(Finding{"Subdomains Discovered in Source", "info", base,
                        std::to_string(subdomains.size()) + " subdomains found in page source",
                        "", "", sub_list.substr(0, 500)});
  }

  // Check interesting subdomains
  std::vector<std::string> interesting = {"staging", "dev", "test", "beta", "api-dev", "admin"};
  for (const auto &sub : subdomains) {
    for (const auto &keyword : interesting) {
      if (sub.find(keyword) != std::string::npos) {
        auto check = http.get("https://" + sub);
        if (check.status_code == 200 && check.body.size() > 500) {
          findings.push_back(Finding{"Development Subdomain Live: " + sub, "medium",
                              "https://" + sub,
                              "Development/staging subdomain found in source and is live. "
                              "May have weaker security controls.",
                              "", sub, ""});
          break;
        }
      }
    }
  }

  return findings;
}

/// Technology-specific path fuzzing based on detected stack.
std::vector<Finding> scan_tech_path_fuzz(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);

  // Detect technology and fuzz accordingly
  struct TechPaths {
    std::string indicator;
    std::string tech;
    std::vector<std::pair<std::string, std::string>> paths; // path, expected indicator
  };

  std::vector<TechPaths> tech_fuzz = {
      {"next", "Next.js", {
          {"/_next/data/", "\"pageProps\""},
          {"/api/__nextauth/session", "\"user\""},
          {"/_next/static/development/_buildManifest.js", "module.exports"},
      }},
      {"nuxt", "Nuxt.js", {
          {"/_nuxt/", "window.__NUXT__"},
          {"/__nuxt_error", "statusCode"},
      }},
      {"rails", "Ruby on Rails", {
          {"/rails/info", "Rails version"},
          {"/rails/mailers", "Action Mailer"},
          {"/sidekiq", "Sidekiq"},
      }},
      {"express", "Express.js", {
          {"/debug/info", "\"uptime\""},
          {"/__coverage__", "coverage"},
      }},
      {"flask", "Flask/Python", {
          {"/console", ">>> "},
          {"/debug", "Werkzeug"},
      }},
  };

  for (const auto &tech : tech_fuzz) {
    if (resp.body.find(tech.indicator) == std::string::npos) continue;

    for (const auto &[path, indicator] : tech.paths) {
      auto r = http.get(base + path);
      if (r.status_code == 200 && r.body.find(indicator) != std::string::npos &&
          r.body.find("Access Denied") == std::string::npos &&
          r.body.find("<!DOCTYPE html><html id=\"__next_error__\"") == std::string::npos) {
        std::string severity = (indicator.find("console") != std::string::npos ||
                                indicator.find("Werkzeug") != std::string::npos) ? "critical" : "medium";
        findings.push_back(Finding{tech.tech + " Internal Endpoint: " + path, severity,
                            base + path,
                            tech.tech + " internal endpoint accessible. Found: " + indicator,
                            "", path, ""});
      }
    }
  }
  return findings;
}

/// Authenticated endpoint discovery — find what's behind login.
std::vector<Finding> scan_post_auth_discovery(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find login endpoint and discover what API routes exist behind auth
  std::vector<std::string> dashboard_paths = {
      "/dashboard", "/app", "/portal", "/account", "/home",
      "/console", "/workspace", "/projects"};

  for (const auto &path : dashboard_paths) {
    auto resp = http.get(base + path);
    // If it redirects to login, the path exists but requires auth
    if (resp.status_code == 302 || resp.status_code == 301) {
      auto loc = resp.headers.find("Location");
      if (loc != resp.headers.end() &&
          (loc->second.find("login") != std::string::npos ||
           loc->second.find("signin") != std::string::npos ||
           loc->second.find("auth") != std::string::npos)) {
        findings.push_back(Finding{"Authenticated Route Discovered: " + path, "info",
                            base + path,
                            "Path exists but requires authentication (redirects to login). "
                            "Create an account to scan authenticated attack surface.",
                            "", path, "Redirects to: " + loc->second});
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_recon_deep2_scanners() {
  return {
      {"JS Secrets", scan_js_secrets},
      {"JS API Endpoints", scan_js_api_endpoints},
      {"Subdomain from Source", scan_subdomain_from_source},
      {"Tech Path Fuzz", scan_tech_path_fuzz},
      {"Post-Auth Discovery", scan_post_auth_discovery},
  };
}

} // namespace apex
