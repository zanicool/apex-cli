/// @file scanners/interactive_surface.cpp
/// @brief Interactive attack surface discovery: login forms, password resets,
///        file uploads, iframes, onclick/JS handlers, AJAX endpoints,
///        hidden forms, client portals, registration flows.
#include "scanner_base.hpp"
#include <set>

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

/// Discover login/auth forms and portals.
/// Scanner implementation.
/// @brief Scan for login_discovery vulnerabilities.
std::vector<Finding> scan_login_discovery(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
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

  // Common login/portal paths.
  const std::vector<std::string> login_paths = {
      "/login", "/signin", "/sign-in", "/auth/login", "/admin/login",
      "/user/login", "/account/login", "/portal", "/client", "/clients",
      "/dashboard", "/my-account", "/members", "/member/login",
      "/wp-login.php", "/wp-admin", "/administrator", "/admin",
      "/panel", "/cpanel", "/webmail", "/owa", "/remote",
      "/api/auth/login", "/api/login", "/oauth/authorize",
      "/sso/login", "/saml/login", "/cas/login",
  };

  // Iterate over targets.
  for (const auto &path : login_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 200) {
      // Verify it's actually a login form.
      bool has_password = resp.body.find("password") != std::string::npos ||
                          resp.body.find("passwd") != std::string::npos;
      bool has_input = resp.body.find("<input") != std::string::npos;
      bool has_form = resp.body.find("<form") != std::string::npos;

      if (has_password && has_input) {
        findings.push_back({"Login Form Found", "info", base + path,
                            "Authentication form at " + path, "", "", ""});
      } else if (has_form && has_input) {
        findings.push_back({"Interactive Form", "info", base + path,
                            "Form-based interface at " + path, "", "", ""});
      }
    } else if (resp.status_code == 302 || resp.status_code == 301) {
      auto loc = resp.headers.find("Location");
      if (loc != resp.headers.end()) {
        findings.push_back({"Auth Redirect", "info", base + path,
                            "Redirects to: " + loc->second, "", "", ""});
      }
    }
  }
  // Return collected findings.
  // Return collected findings.
  // Return collected findings.
  return findings;
}

/// Extract forms, iframes, and interactive elements from crawled pages.
/// Scanner implementation.
/// @brief Scan for interactive_elements vulnerabilities.
std::vector<Finding> scan_interactive_elements(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::set<std::string> found_forms;
  std::set<std::string> found_iframes;
  std::set<std::string> found_uploads;

  // Iterate over targets.
  // Process each crawled URL.
  // Process each crawled URL.
  // Process each crawled URL.
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;

    // Find forms with interesting actions.
    std::regex form_re(R"(<form[^>]*action\s*=\s*["']([^"']+)["'][^>]*>)", std::regex::icase);
    auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), form_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
      std::string action = (*it)[1].str();
      std::string form_tag = (*it)[0].str();
      if (found_forms.count(action)) continue;
      found_forms.insert(action);

      // Categorize the form.
      if (form_tag.find("file") != std::string::npos ||
          form_tag.find("multipart") != std::string::npos ||
          resp.body.find("type=\"file\"") != std::string::npos) {
        found_uploads.insert(action);
      }
    }

    // Find file upload inputs specifically.
    if (resp.body.find("type=\"file\"") != std::string::npos ||
        resp.body.find("type='file'") != std::string::npos) {
      found_uploads.insert(url);
    }

    // Find iframes (potential clickjacking targets, third-party content).
    std::regex iframe_re(R"(<iframe[^>]*src\s*=\s*["']([^"']+)["'])", std::regex::icase);
    auto ib = std::sregex_iterator(resp.body.begin(), resp.body.end(), iframe_re);
    for (auto it = ib; it != end; ++it) {
      std::string src = (*it)[1].str();
      if (found_iframes.count(src)) continue;
      found_iframes.insert(src);
    }
  }

  // Report findings.
  if (!found_forms.empty()) {
    std::string detail = std::to_string(found_forms.size()) + " unique form actions:";
    int c = 0;
    for (const auto &f : found_forms) {
      if (c++ < 15) detail += "\n  " + f;
    }
    findings.push_back({"Form Actions Discovered", "info", crawl.urls[0],
                        detail, "", "", ""});
  }

  if (!found_uploads.empty()) {
    for (const auto &u : found_uploads) {
      findings.push_back({"File Upload Found", "medium", u,
                          "File upload functionality — test for unrestricted upload",
                          "", "", ""});
    }
  }

  if (!found_iframes.empty()) {
    for (const auto &src : found_iframes) {
      // External iframes are more interesting.
      if (src.find("http") == 0 && src.find(base_url_from(crawl.urls[0])) == std::string::npos) {
        findings.push_back({"External Iframe", "low", src,
                            "Third-party iframe embedded — verify trust", "", "", ""});
      }
    }
  }
  return findings;
}

/// Discover JavaScript event handlers and AJAX endpoints.
/// Scanner implementation.
/// @brief Scan for js_handlers vulnerabilities.
std::vector<Finding> scan_js_handlers(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::set<std::string> ajax_endpoints;
  std::set<std::string> event_urls;

  // Iterate over targets.
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;

    // Find onclick/onsubmit handlers that reference URLs.
    std::regex handler_re(R"((?:onclick|onsubmit|onchange|onfocus)\s*=\s*["']([^"']+)["'])", std::regex::icase);
    auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), handler_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
      std::string handler = (*it)[1].str();
      // Extract URLs from handler.
      std::regex url_in_handler(R"((?:location|href|window\.open|fetch|ajax)\s*[\(=]\s*['"]([^'"]+))");
      std::smatch m;
      if (std::regex_search(handler, m, url_in_handler))
        event_urls.insert(m[1].str());
    }

    // Find fetch/XMLHttpRequest/axios calls.
    std::regex ajax_re(R"((?:fetch|axios\.\w+|\.ajax|\$\.(?:get|post))\s*\(\s*['"`]([^'"`\s]+))");
    auto ab = std::sregex_iterator(resp.body.begin(), resp.body.end(), ajax_re);
    for (auto it = ab; it != end; ++it) {
      ajax_endpoints.insert((*it)[1].str());
    }

    // Find data-* attributes with URLs (common in SPAs).
    std::regex data_re(R"(data-(?:url|action|endpoint|api|href)\s*=\s*["']([^"']+)["'])");
    auto db = std::sregex_iterator(resp.body.begin(), resp.body.end(), data_re);
    for (auto it = db; it != end; ++it) {
      ajax_endpoints.insert((*it)[1].str());
    }
  }

  if (!ajax_endpoints.empty()) {
    std::string detail = std::to_string(ajax_endpoints.size()) + " AJAX/API endpoints in JS:";
    int c = 0;
    for (const auto &ep : ajax_endpoints) {
      if (c++ < 15) detail += "\n  " + ep;
    }
    findings.push_back({"AJAX Endpoints in Handlers", "info", crawl.urls[0],
                        detail, "", "", ""});

    // Probe AJAX endpoints.
    std::string base = base_url_from(crawl.urls[0]);
    for (const auto &ep : ajax_endpoints) {
      std::string full = ep.find("http") == 0 ? ep : base + ep;
      auto resp = http.get(full);
      if (resp.status_code == 200 && resp.body.size() > 20 &&
          resp.body.find("unauthorized") == std::string::npos) {
        findings.push_back({"AJAX Endpoint Accessible", "medium", full,
                            "API endpoint from JS handler accessible without auth",
                            "", "", ""});
      }
      if (findings.size() > 20) break;
    }
  }
  return findings;
}

/// Discover password reset, registration, and account recovery flows.
/// Scanner implementation.
/// @brief Scan for account_flows vulnerabilities.
std::vector<Finding> scan_account_flows(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct Flow { const char *path; const char *name; };
  const Flow flows[] = {
      {"/forgot-password", "Password Reset"},
      {"/reset-password", "Password Reset"},
      {"/password/reset", "Password Reset"},
      {"/account/recover", "Account Recovery"},
      {"/register", "Registration"},
      {"/signup", "Registration"},
      {"/sign-up", "Registration"},
      {"/create-account", "Registration"},
      {"/invite", "Invite Flow"},
      {"/join", "Join Flow"},
      {"/subscribe", "Subscription"},
      {"/contact", "Contact Form"},
      {"/support", "Support Form"},
      {"/feedback", "Feedback Form"},
      {"/api/password/reset", "API Password Reset"},
      {"/api/register", "API Registration"},
      {"/api/contact", "API Contact"},
  };

  // Iterate over targets.
  for (const auto &flow : flows) {
    auto resp = http.get(base + flow.path);
    if (resp.status_code == 200 && resp.body.size() > 200 &&
        (resp.body.find("<form") != std::string::npos ||
         resp.body.find("<input") != std::string::npos ||
         resp.body.find("submit") != std::string::npos)) {
      findings.push_back({std::string(flow.name) + " Flow", "info", base + flow.path,
                          std::string(flow.name) + " form accessible", "", "", ""});
    }
  }
  return findings;
}

/// Discover hidden/commented forms and debug interfaces.
/// Scanner implementation.
/// @brief Scan for hidden_forms vulnerabilities.
std::vector<Finding> scan_hidden_forms(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;

  // Iterate over targets.
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;

    // Hidden forms (display:none, hidden class, type=hidden with action).
    std::regex hidden_re(R"(<form[^>]*(?:style\s*=\s*["'][^"']*display\s*:\s*none|class\s*=\s*["'][^"']*hidden)[^>]*>)", std::regex::icase);
    std::smatch m;
    if (std::regex_search(resp.body, m, hidden_re)) {
      findings.push_back({"Hidden Form", "medium", url,
                          "Hidden form found — may be debug/admin interface", "", "", ""});
    }

    // HTML comments containing forms or endpoints.
    std::regex comment_re(R"(<!--[\s\S]*?(?:action|endpoint|api|admin|debug|test)[\s\S]*?-->)");
    if (std::regex_search(resp.body, m, comment_re)) {
      std::string comment = m[0].str().substr(0, 200);
      if (comment.find("action") != std::string::npos ||
          comment.find("api") != std::string::npos) {
        findings.push_back({"Commented Code with Endpoints", "low", url,
                            "HTML comment contains endpoint references", "", "", ""});
      }
    }

    // Disabled form fields (may accept input if enabled client-side).
    if (resp.body.find("disabled") != std::string::npos &&
        resp.body.find("<input") != std::string::npos) {
      std::regex disabled_re(R"(<input[^>]*disabled[^>]*name\s*=\s*["']([^"']+)["'])");
      if (std::regex_search(resp.body, m, disabled_re)) {
        findings.push_back({"Disabled Input Field: " + m[1].str(), "low", url,
                            "Disabled field '" + m[1].str() + "' — may be bypassable",
                            m[1].str(), "", ""});
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_interactive_surface_scanners() {
  return {
      {"Login/Portal Discovery", scan_login_discovery},
      {"Interactive Elements", scan_interactive_elements},
      {"JS Event Handlers", scan_js_handlers},
      {"Account Flows", scan_account_flows},
      {"Hidden Forms", scan_hidden_forms},
  };
}

} // namespace apex
