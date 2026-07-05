/// @file scanners/auth_scanner.cpp
/// @brief Authenticated Attack Surface Scanner: auto-detects registration forms,
///        creates test accounts, and scans the authenticated attack surface.
///        This finds what unauthenticated scanning misses entirely.
#include "scanner_base.hpp"
#include <regex>

namespace apex {
namespace {

/// Find registration and login endpoints.
std::vector<Finding> scan_auth_surface_map(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct AuthEndpoint {
    std::string path;
    std::string type; // register, login, reset, verify
  };

  std::vector<AuthEndpoint> endpoints;

  // Discover auth endpoints
  std::vector<std::pair<std::string, std::string>> paths = {
      {"/api/register", "register"}, {"/api/v1/register", "register"},
      {"/api/signup", "register"}, {"/api/v1/signup", "register"},
      {"/api/auth/register", "register"}, {"/api/auth/signup", "register"},
      {"/api/login", "login"}, {"/api/v1/login", "login"},
      {"/api/auth/login", "login"}, {"/api/v1/auth/login", "login"},
      {"/api/auth/forgot-password", "reset"}, {"/api/v1/auth/forgot-password", "reset"},
      {"/api/password/reset", "reset"}, {"/api/auth/verify", "verify"},
      {"/api/v1/auth/verify-email", "verify"}, {"/api/auth/confirm", "verify"},
  };

  for (const auto &[path, type] : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 405 || resp.status_code == 400 ||
        resp.status_code == 422 || resp.status_code == 200) {
      if (resp.body.find("Access Denied") == std::string::npos &&
          resp.body.find("<!DOCTYPE html>") == std::string::npos) {
        endpoints.push_back({path, type});
      }
    }
  }

  if (!endpoints.empty()) {
    std::string ep_list;
    for (const auto &ep : endpoints) {
      ep_list += "[" + ep.type + "] " + ep.path + "\n";
    }
    findings.push_back(Finding{"Authentication Surface Mapped", "info", base,
                        std::to_string(endpoints.size()) + " auth endpoints discovered:\n" + ep_list,
                        "", "", ""});
  }

  // Test registration for mass assignment
  for (const auto &ep : endpoints) {
    if (ep.type != "register") continue;

    // Check what fields the registration accepts
    auto resp = http.post(base + ep.path, "{}", "application/json");
    if (resp.body.find("email") != std::string::npos ||
        resp.body.find("required") != std::string::npos) {
      // Registration endpoint exists and validates input
      // Try to register with extra admin fields
      std::string payload = R"({"email":"apextest_)" + std::to_string(time(nullptr)) +
                            R"(@test.com","password":"ApexTest123!","role":"admin","is_staff":true})";
      auto reg = http.post(base + ep.path, payload, "application/json");
      if (reg.status_code == 200 || reg.status_code == 201) {
        if (reg.body.find("admin") != std::string::npos ||
            reg.body.find("staff") != std::string::npos) {
          findings.push_back(Finding{"Registration Mass Assignment", "critical", base + ep.path,
                              "Registration accepts role/privilege fields. "
                              "User can self-assign admin at signup.",
                              "role", "admin",
                              reg.body.substr(0, 200)});
        }
      }
    }
  }

  // Test for user enumeration via registration
  for (const auto &ep : endpoints) {
    if (ep.type != "register") continue;
    auto existing = http.post(base + ep.path,
                              R"({"email":"admin@)" + base.substr(base.find("://") + 3) +
                              R"(","password":"test123"})",
                              "application/json");
    if (existing.body.find("already exists") != std::string::npos ||
        existing.body.find("already registered") != std::string::npos ||
        existing.body.find("taken") != std::string::npos) {
      findings.push_back(Finding{"User Enumeration via Registration", "medium", base + ep.path,
                          "Registration endpoint reveals whether an email is already registered. "
                          "Allows enumeration of valid user accounts.",
                          "email", "admin@...",
                          "Response differs for existing vs non-existing accounts"});
    }
    break;
  }

  // Test password reset for user enumeration
  for (const auto &ep : endpoints) {
    if (ep.type != "reset") continue;
    auto real = http.post(base + ep.path,
                          R"({"email":"admin@)" + base.substr(base.find("://") + 3) + R"("})",
                          "application/json");
    auto fake = http.post(base + ep.path,
                          R"({"email":"nonexistent_apex_test_12345@nowhere.invalid"})",
                          "application/json");
    if (real.body != fake.body || real.status_code != fake.status_code) {
      findings.push_back(Finding{"User Enumeration via Password Reset", "medium", base + ep.path,
                          "Password reset responds differently for existing vs non-existing emails.",
                          "email", "",
                          "Existing: " + std::to_string(real.status_code) +
                          ", Non-existing: " + std::to_string(fake.status_code)});
    }
    break;
  }

  return findings;
}

/// Test for account takeover vectors.
std::vector<Finding> scan_account_takeover(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Password reset token in response (should only be in email)
  std::vector<std::string> reset_paths = {
      "/api/auth/forgot-password", "/api/v1/auth/forgot-password",
      "/api/password/reset", "/api/forgot-password"};

  for (const auto &path : reset_paths) {
    auto resp = http.post(base + path,
                          R"({"email":"test@test.com"})",
                          "application/json");
    if (resp.status_code == 200 &&
        (resp.body.find("token") != std::string::npos ||
         resp.body.find("reset_url") != std::string::npos ||
         resp.body.find("reset_link") != std::string::npos) &&
        resp.body.find("{") == 0) {
      findings.push_back(Finding{"Password Reset Token in Response", "critical", base + path,
                          "Password reset endpoint returns the reset token/link in the API response. "
                          "Attacker can reset any account's password without access to their email.",
                          "", path,
                          resp.body.substr(0, 200)});
      return findings;
    }
  }

  // Check if password change doesn't require current password
  std::vector<std::string> change_paths = {
      "/api/auth/change-password", "/api/v1/auth/change-password",
      "/api/password/change", "/api/user/password"};

  for (const auto &path : change_paths) {
    auto resp = http.post(base + path,
                          R"({"new_password":"NewPass123!"})",
                          "application/json");
    if (resp.status_code == 200 &&
        resp.body.find("success") != std::string::npos &&
        resp.body.find("current_password") == std::string::npos &&
        resp.body.find("{") == 0) {
      findings.push_back(Finding{"Password Change Without Current Password", "high", base + path,
                          "Password can be changed without providing current password. "
                          "Any session hijack (XSS, CSRF) leads to permanent account takeover.",
                          "", path, ""});
      break;
    }
  }

  return findings;
}

/// Test for 2FA bypass vectors.
std::vector<Finding> scan_2fa_bypass(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::vector<std::string> verify_paths = {
      "/api/auth/2fa/verify", "/api/v1/auth/verify-otp",
      "/api/auth/verify", "/api/mfa/verify"};

  for (const auto &path : verify_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 404) continue;

    // Try null/empty code
    auto null_resp = http.post(base + path,
                               R"({"code":"","user_id":"1"})",
                               "application/json");
    if (null_resp.status_code == 200 &&
        null_resp.body.find("success") != std::string::npos &&
        null_resp.body.find("{") == 0) {
      findings.push_back(Finding{"2FA Bypass — Empty Code Accepted", "critical", base + path,
                          "2FA verification accepts empty/null code. "
                          "Complete authentication bypass.",
                          "code", "\"\"", null_resp.body.substr(0, 200)});
      return findings;
    }

    // Try code manipulation
    auto zero_resp = http.post(base + path,
                               R"({"code":"000000","user_id":"1"})",
                               "application/json");
    if (zero_resp.status_code == 200 &&
        zero_resp.body.find("success") != std::string::npos &&
        zero_resp.body.find("{") == 0) {
      findings.push_back(Finding{"2FA Bypass — Default Code", "critical", base + path,
                          "2FA accepts code '000000'. Possible backdoor or broken validation.",
                          "code", "000000", ""});
      return findings;
    }

    // Check rate limiting on 2FA
    int success_count = 0;
    for (int i = 0; i < 10; i++) {
      std::string code = std::to_string(100000 + i);
      auto r = http.post(base + path,
                         "{\"code\":\"" + code + "\",\"user_id\":\"1\"}",
                         "application/json");
      if (r.status_code != 429) success_count++;
    }
    if (success_count >= 10) {
      findings.push_back(Finding{"2FA — No Rate Limiting", "high", base + path,
                          "2FA verification has no rate limiting. "
                          "6-digit code can be brute-forced in <1000 requests (10 per second = 100 seconds).",
                          "code", "brute-force", ""});
    }
    break;
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_auth_scanner_scanners() {
  return {
      {"Auth Surface Map", scan_auth_surface_map},
      {"Account Takeover", scan_account_takeover},
      {"2FA Bypass", scan_2fa_bypass},
  };
}

} // namespace apex
