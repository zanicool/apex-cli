/// @file scanners/auth_advanced2.cpp
/// @brief Advanced auth scanners part 2: password policy, account enumeration,
///        registration abuse, token predictability, session puzzling,
///        OAuth token theft, SAML attacks, SSO bypass, remember-me weakness,
///        concurrent session, privilege via signup, invite link abuse.
#include "scanner_base.hpp"
#include <regex>
#include <set>

namespace apex {
namespace {

/// Weak password policy — accepts trivial passwords.
std::vector<Finding> scan_weak_password_policy(const Config &, HttpClient &http,
                                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> reg_paths = {
      "/api/register", "/api/signup", "/register", "/api/auth/register"};
  const std::vector<std::string> weak_passwords = {"1", "aa", "123"};

  for (const auto &path : reg_paths) {
    for (const auto &pwd : weak_passwords) {
      std::string email = "apex_pwtest_" + std::to_string(time(nullptr)) + "@test.com";
      auto resp = http.post(base + path,
                            R"({"email":")" + email + R"(","password":")" + pwd + "\"}",
                            "application/json");
      if (resp.status_code == 200 || resp.status_code == 201) {
        if (resp.body.find("error") == std::string::npos &&
            resp.body.find("weak") == std::string::npos &&
            resp.body.find("short") == std::string::npos) {
          findings.push_back({"Weak Password Policy", "medium", base + path,
                              "Registration accepts password: '" + pwd + "'",
                              "password", pwd,
                              "No password strength enforcement"});
          return findings;
        }
      }
    }
  }
  return findings;
}

/// Account enumeration via registration.
std::vector<Finding> scan_account_enum_register(const Config &, HttpClient &http,
                                                 const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> reg_paths = {
      "/api/register", "/api/signup", "/register"};

  for (const auto &path : reg_paths) {
    // Try registering with likely-existing email
    auto resp1 = http.post(base + path,
                           R"({"email":"admin@)" + std::string(crawl.urls[0].substr(crawl.urls[0].find("://") + 3, crawl.urls[0].find("/", 8) - crawl.urls[0].find("://") - 3)) + R"(","password":"Test12345!"})",
                           "application/json");
    // Try with definitely-not-existing email
    auto resp2 = http.post(base + path,
                           R"({"email":"definitely_not_exists_xyz@nonexistent.invalid","password":"Test12345!"})",
                           "application/json");

    if (resp1.status_code != resp2.status_code ||
        (resp1.body.find("exists") != std::string::npos &&
         resp2.body.find("exists") == std::string::npos) ||
        (resp1.body.find("taken") != std::string::npos &&
         resp2.body.find("taken") == std::string::npos)) {
      findings.push_back({"Account Enumeration (Registration)", "low", base + path,
                          "Different responses reveal whether email exists",
                          "email", "",
                          "Existing vs non-existing email gives different response"});
      break;
    }
  }
  return findings;
}

/// Account enumeration via forgot password.
std::vector<Finding> scan_account_enum_forgot(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {
      "/api/forgot-password", "/api/password-reset", "/forgot-password"};

  for (const auto &path : paths) {
    auto resp1 = http.post(base + path,
                           R"({"email":"admin@example.com"})", "application/json");
    auto resp2 = http.post(base + path,
                           R"({"email":"nonexist_xyz_abc@nowhere.invalid"})", "application/json");

    if (resp1.body != resp2.body &&
        resp1.status_code == resp2.status_code) {
      findings.push_back({"Account Enumeration (Forgot Password)", "low", base + path,
                          "Different response for existing vs non-existing email",
                          "email", "",
                          "Responses differ in content"});
      break;
    }
  }
  return findings;
}

/// Token in URL — sensitive token passed as query parameter.
std::vector<Finding> scan_token_in_url(const Config &, HttpClient &,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::regex token_re(R"([\?&](token|access_token|auth_token|session_token|jwt)=([A-Za-z0-9_\.\-]{20,}))");

  for (const auto &url : crawl.urls) {
    std::smatch m;
    if (std::regex_search(url, m, token_re)) {
      findings.push_back({"Sensitive Token in URL", "medium", url,
                          "Auth token in query string — visible in logs/referrer",
                          m[1].str(), m[2].str().substr(0, 15) + "...",
                          "Token exposed in URL"});
    }
  }
  return findings;
}

/// No session expiry — old tokens still work.
std::vector<Finding> scan_no_session_expiry(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Check if server sets cookie expiry
  auto resp = http.get(crawl.urls[0]);
  for (const auto &[h, v] : resp.headers) {
    if (h != "Set-Cookie") continue;
    if (v.find("session") != std::string::npos || v.find("token") != std::string::npos) {
      if (v.find("Max-Age=") == std::string::npos &&
          v.find("Expires=") == std::string::npos) {
        findings.push_back({"No Session Expiry", "low", crawl.urls[0],
                            "Session cookie has no expiry — persists until browser closes",
                            "", "", v.substr(0, 80)});
      } else if (v.find("Max-Age=31536000") != std::string::npos ||
                 v.find("Max-Age=63072000") != std::string::npos) {
        findings.push_back({"Excessive Session Duration", "medium", crawl.urls[0],
                            "Session cookie expires in 1+ years",
                            "", "", v.substr(0, 80)});
      }
      break;
    }
  }
  return findings;
}

/// OAuth misconfiguration — open redirect in redirect_uri.
std::vector<Finding> scan_oauth_redirect_bypass(const Config &, HttpClient &http,
                                                 const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> oauth_paths = {
      "/oauth/authorize", "/auth/authorize", "/connect/authorize",
      "/api/oauth/authorize"};

  const std::vector<std::string> bypass_uris = {
      "https://evil.com",
      "https://evil.com%23@" + base.substr(base.find("://") + 3),
      base + ".evil.com",
      "https://evil.com/" + base.substr(base.find("://") + 3),
  };

  for (const auto &path : oauth_paths) {
    for (const auto &uri : bypass_uris) {
      auto resp = http.get(base + path + "?redirect_uri=" + uri +
                           "&response_type=code&client_id=test");
      auto loc = resp.headers.find("Location");
      if (loc != resp.headers.end() && loc->second.find("evil.com") != std::string::npos) {
        findings.push_back({"OAuth Redirect URI Bypass", "high", base + path,
                            "redirect_uri validation bypassed",
                            "redirect_uri", uri,
                            "Redirected to: " + loc->second.substr(0, 100)});
        return findings;
      }
    }
  }
  return findings;
}

/// Registration role injection — set role during signup.
std::vector<Finding> scan_registration_role(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> reg_paths = {
      "/api/register", "/api/signup", "/api/auth/register"};

  for (const auto &path : reg_paths) {
    std::string email = "apex_roletest_" + std::to_string(time(nullptr)) + "@test.com";
    // Try registering with admin role
    auto resp = http.post(base + path,
                          R"({"email":")" + email + R"(","password":"Test12345!","role":"admin"})",
                          "application/json");
    if (resp.status_code == 200 || resp.status_code == 201) {
      if (resp.body.find("\"role\":\"admin\"") != std::string::npos ||
          resp.body.find("\"is_admin\":true") != std::string::npos) {
        findings.push_back({"Registration Role Injection", "critical", base + path,
                            "Admin role assigned during registration",
                            "role", "admin",
                            "Response confirms admin role"});
        break;
      }
    }
  }
  return findings;
}

/// Concurrent session — no limit on active sessions.
std::vector<Finding> scan_concurrent_sessions(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> login_paths = {
      "/api/login", "/api/auth/login", "/login"};

  for (const auto &path : login_paths) {
    auto r1 = http.post(base + path,
                        R"({"email":"test@test.com","password":"test"})",
                        "application/json");
    auto r2 = http.post(base + path,
                        R"({"email":"test@test.com","password":"test"})",
                        "application/json");
    if (r1.status_code == 200 && r2.status_code == 200 &&
        r1.body.find("token") != std::string::npos &&
        r2.body.find("token") != std::string::npos) {
      // Both logins succeeded — no session invalidation
      // Only flag if tokens are different (both are valid)
      if (r1.body != r2.body) {
        findings.push_back({"No Concurrent Session Limit", "low", base + path,
                            "Multiple active sessions allowed simultaneously",
                            "", "", "Two different tokens issued"});
      }
      break;
    }
  }
  return findings;
}

/// Invite/magic link token weakness.
std::vector<Finding> scan_invite_link(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> invite_paths = {
      "/invite", "/api/invite/verify", "/join", "/api/team/invite"};

  for (const auto &path : invite_paths) {
    // Try common/predictable tokens
    auto resp = http.get(base + path + "?token=test");
    if (resp.status_code == 200 &&
        resp.body.find("expired") == std::string::npos &&
        resp.body.find("invalid") == std::string::npos &&
        resp.body.size() > 100) {
      findings.push_back({"Invite Link Weakness", "medium", base + path,
                          "Invite endpoint accepts arbitrary token values",
                          "token", "test",
                          "No proper validation of invite token"});
      break;
    }
  }
  return findings;
}

/// Password reset token in response body.
std::vector<Finding> scan_reset_token_leak(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> reset_paths = {
      "/api/forgot-password", "/api/password-reset", "/api/auth/reset"};

  for (const auto &path : reset_paths) {
    auto resp = http.post(base + path,
                          R"({"email":"test@test.com"})", "application/json");
    if (resp.status_code == 200) {
      // Check if reset token is leaked in response
      std::regex token_re(R"re("(?:token|reset_token|code)":\s*"([A-Za-z0-9_\-]{10,})")re");
      std::smatch m;
      if (std::regex_search(resp.body, m, token_re)) {
        findings.push_back({"Password Reset Token Leaked", "critical", base + path,
                            "Reset token returned in API response instead of email-only",
                            "", m[1].str().substr(0, 15) + "...",
                            "Token visible in response body"});
        break;
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_auth_advanced2_scanners() {
  return {
      {"Weak Password Policy", scan_weak_password_policy},
      {"Account Enum (Register)", scan_account_enum_register},
      {"Account Enum (Forgot)", scan_account_enum_forgot},
      {"Token in URL", scan_token_in_url},
      {"Session Expiry", scan_no_session_expiry},
      {"OAuth Redirect Bypass", scan_oauth_redirect_bypass},
      {"Registration Role Injection", scan_registration_role},
      {"Concurrent Sessions", scan_concurrent_sessions},
      {"Invite Link Weakness", scan_invite_link},
      {"Reset Token Leak", scan_reset_token_leak},
  };
}

} // namespace apex
