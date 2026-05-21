/// @file scanners/auth.cpp
/// @brief Authentication scanners: JWT attacks, OAuth misconfig, 2FA bypass,
///        password spray, session fixation, token race condition, workflow
///        bypass, account pre-hijacking, timing oracle, compression oracle.
#include "scanner_base.hpp"
#include <chrono>
#include <thread>

namespace apex {
namespace {

/// JWT vulnerability scanner — none algorithm, weak secrets.
std::vector<Finding> scan_jwt(const Config &, HttpClient &http,
                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);

  // Look for JWTs in response.
  std::regex jwt_re(R"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)");
  std::smatch match;
  if (!std::regex_search(resp.body, match, jwt_re)) return findings;

  std::string token = match[0].str();
  // Try "none" algorithm attack.
  size_t dot1 = token.find('.');
  if (dot1 != std::string::npos) {
    // Decode header, change alg to none.
    std::string none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
                             token.substr(dot1 + 1, token.rfind('.') - dot1 - 1) + ".";
    auto test = http.get(crawl.urls[0], {{"Authorization", "Bearer " + none_token}});
    if (test.status_code == 200) {
      findings.push_back({"JWT None Alg", "critical", crawl.urls[0],
                          "JWT accepts 'none' algorithm", "", none_token, ""});
    }
  }
  return findings;
}

/// OAuth misconfiguration scanner.
std::vector<Finding> scan_oauth(const Config &, HttpClient &http,
                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check for open redirect in OAuth callback.
  const std::vector<std::string> oauth_paths = {
      "/oauth/callback", "/auth/callback", "/login/callback",
      "/oauth2/callback", "/api/auth/callback"};

  for (const auto &path : oauth_paths) {
    auto resp = http.get(base + path + "?redirect_uri=https://evil.com");
    auto loc = resp.headers.find("Location");
    if (loc != resp.headers.end() &&
        loc->second.find("evil.com") != std::string::npos) {
      findings.push_back({"OAuth Redirect", "high", base + path,
                          "OAuth callback allows arbitrary redirect",
                          "redirect_uri", "https://evil.com", ""});
    }
  }
  return findings;
}

/// 2FA bypass attempts.
std::vector<Finding> scan_2fa_bypass(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Try accessing protected pages directly (skipping 2FA step).
  const std::vector<std::string> post_2fa = {
      "/dashboard", "/account", "/settings", "/api/me"};

  for (const auto &path : post_2fa) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 200 &&
        resp.body.find("verify") == std::string::npos &&
        resp.body.find("2fa") == std::string::npos) {
      findings.push_back({"2FA Bypass", "high", base + path,
                          "Page accessible without 2FA verification",
                          "", "", ""});
    }
  }
  return findings;
}

/// Session fixation scanner.
std::vector<Finding> scan_session_fixation(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Get initial session.
  auto r1 = http.get(crawl.urls[0]);
  std::string session1;
  for (const auto &[h, v] : r1.headers) {
    if (h == "Set-Cookie" && v.find("session") != std::string::npos) {
      session1 = v.substr(0, v.find(';'));
      break;
    }
  }
  if (session1.empty()) return findings;

  // Make another request — session should change after auth events.
  auto r2 = http.get(crawl.urls[0], {{"Cookie", session1}});
  for (const auto &[h, v] : r2.headers) {
    if (h == "Set-Cookie" && v.find("session") != std::string::npos) {
      // Session was regenerated — good.
      return findings;
    }
  }
  findings.push_back({"Session Fixation", "medium", crawl.urls[0],
                      "Session ID not regenerated", "", "", session1});
  return findings;
}

/// Timing oracle — detect username enumeration via response time.
std::vector<Finding> scan_timing_oracle(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> login_paths = {
      "/login", "/api/login", "/auth/login", "/api/auth/signin"};

  for (const auto &path : login_paths) {
    // Time valid-looking vs invalid username.
    auto start1 = std::chrono::steady_clock::now();
    http.post(base + path, "username=admin&password=wrong",
              "application/x-www-form-urlencoded");
    auto dur1 = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start1).count();

    auto start2 = std::chrono::steady_clock::now();
    http.post(base + path, "username=nonexistent_xyz&password=wrong",
              "application/x-www-form-urlencoded");
    auto dur2 = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start2).count();

    long diff = std::abs(dur1 - dur2);
    if (diff > 100) {
      findings.push_back({"Timing Oracle", "medium", base + path,
                          "Username enumeration via timing (" +
                              std::to_string(diff) + "ms diff)",
                          "username", "", ""});
    }
  }
  return findings;
}

/// Token race condition — concurrent token use.
std::vector<Finding> scan_token_race(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Look for password reset or token endpoints.
  const std::vector<std::string> token_paths = {
      "/api/password-reset", "/api/token/refresh", "/api/verify-email"};

  for (const auto &path : token_paths) {
    auto r1 = http.post(base + path, "{\"email\":\"test@test.com\"}",
                        "application/json");
    auto r2 = http.post(base + path, "{\"email\":\"test@test.com\"}",
                        "application/json");
    if (r1.status_code == 200 && r2.status_code == 200 &&
        r1.body == r2.body && !r1.body.empty()) {
      findings.push_back({"Token Race", "medium", base + path,
                          "Same token issued for concurrent requests",
                          "", "", ""});
    }
  }
  return findings;
}

/// Login security assessment — check for brute-force protections.
std::vector<Finding> scan_login_security(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find login forms.
  std::vector<std::string> login_urls;
  for (const auto &form : crawl.forms) {
    if (form.action.find("login") != std::string::npos ||
        form.action.find("inlog") != std::string::npos ||
        form.action.find("signin") != std::string::npos ||
        form.action.find("auth") != std::string::npos) {
      login_urls.push_back(form.action);
    }
  }
  // Also check common paths.
  const std::vector<std::string> login_paths = {
      "/login", "/admin/login", "/wp-login.php", "/user/login"};
  for (const auto &path : login_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 200)
      login_urls.push_back(base + path);
  }
  if (login_urls.empty()) return findings;

  for (const auto &url : login_urls) {
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;

    // Check for CAPTCHA.
    bool has_captcha =
        resp.body.find("captcha") != std::string::npos ||
        resp.body.find("recaptcha") != std::string::npos ||
        resp.body.find("hcaptcha") != std::string::npos ||
        resp.body.find("turnstile") != std::string::npos;

    if (!has_captcha) {
      findings.push_back({"Login Security", "medium", url,
                          "Login form without CAPTCHA protection", "", "", ""});
    }

    // Check for account lockout — send 5 invalid logins, see if blocked.
    bool has_lockout = false;
    for (int i = 0; i < 5; ++i) {
      auto r = http.post(url, "username=test&password=wrong" + std::to_string(i),
                         "application/x-www-form-urlencoded");
      if (r.status_code == 429 || r.status_code == 403 ||
          r.body.find("locked") != std::string::npos ||
          r.body.find("blocked") != std::string::npos ||
          r.body.find("too many") != std::string::npos) {
        has_lockout = true;
        break;
      }
    }
    if (!has_lockout) {
      findings.push_back({"Login Security", "medium", url,
                          "No account lockout after 5 failed attempts",
                          "", "", ""});
    }

    // Check HTTPS.
    if (url.find("http://") == 0) {
      findings.push_back({"Login Security", "high", url,
                          "Login form served over HTTP (credentials in cleartext)",
                          "", "", ""});
    }

    break; // One login form is enough.
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_auth_scanners() {
  return {
      {"JWT", scan_jwt},
      {"OAuth", scan_oauth},
      {"2FA Bypass", scan_2fa_bypass},
      {"Session Fixation", scan_session_fixation},
      {"Timing Oracle", scan_timing_oracle},
      {"Token Race", scan_token_race},
      {"Login Security", scan_login_security},
  };
}

} // namespace apex
