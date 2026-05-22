/// @file auto_login.hpp
/// @brief Automatically log into web applications and extract session cookies.
/// Supports: form-based login, JSON API login, OAuth redirects.
#ifndef APEX_AUTO_LOGIN_HPP
#define APEX_AUTO_LOGIN_HPP

#include "http.hpp"
#include <string>
#include <vector>
#include <map>
#include <regex>

namespace apex {

struct SessionInfo {
  std::string cookie;       // Full cookie header value
  std::string auth_header;  // Bearer token if found
  bool authenticated = false;
};

// Forward declarations
inline SessionInfo extract_session(const Response &resp);
inline std::string url_encode(const std::string &s);

/// Auto-login: find login form, submit credentials, extract session.
inline SessionInfo auto_login(HttpClient &http, const std::string &base_url,
                              const std::string &username,
                              const std::string &password) {
  SessionInfo session;

  // Common login paths to try
  std::vector<std::string> login_paths = {
      "/login", "/signin", "/auth/login", "/api/login",
      "/api/v1/login", "/api/auth/login", "/account/login",
      "/user/login", "/members/login", "/session/new"};

  std::string login_url;
  std::string login_page_body;

  // Find the login page
  for (const auto &path : login_paths) {
    auto resp = http.get(base_url + path);
    if (resp.status_code == 200 && resp.body.size() > 200) {
      if (resp.body.find("password") != std::string::npos ||
          resp.body.find("Password") != std::string::npos) {
        login_url = base_url + path;
        login_page_body = resp.body;
        break;
      }
    }
  }

  if (login_url.empty()) return session;

  // Extract CSRF token if present
  std::string csrf;
  std::regex csrf_re(R"(name=["'](?:csrf|_token|authenticity_token|csrfmiddlewaretoken)["']\s+value=["']([^"']+)["'])");
  std::smatch m;
  if (std::regex_search(login_page_body, m, csrf_re)) {
    csrf = m[1].str();
  }

  // Try JSON login first
  {
    std::string json_body = "{\"email\":\"" + username + "\",\"password\":\"" + password + "\"}";
    auto resp = http.post(login_url, json_body, "application/json");
    if (resp.status_code == 200 || resp.status_code == 302) {
      session = extract_session(resp);
      if (session.authenticated) return session;
    }
    // Try with username field
    json_body = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
    resp = http.post(login_url, json_body, "application/json");
    if (resp.status_code == 200 || resp.status_code == 302) {
      session = extract_session(resp);
      if (session.authenticated) return session;
    }
  }

  // Try form-based login
  {
    std::string form_body = "email=" + url_encode(username) +
                            "&password=" + url_encode(password);
    if (!csrf.empty()) {
      form_body += "&_token=" + url_encode(csrf) +
                   "&csrf_token=" + url_encode(csrf) +
                   "&authenticity_token=" + url_encode(csrf);
    }
    // Also try username field
    form_body += "&username=" + url_encode(username);

    auto resp = http.post(login_url, form_body, "application/x-www-form-urlencoded");
    session = extract_session(resp);
    if (session.authenticated) return session;
  }

  return session;
}

/// Extract session cookies and tokens from a login response.
inline SessionInfo extract_session(const Response &resp) {
  SessionInfo session;

  // Extract Set-Cookie headers
  std::string cookies;
  for (const auto &[key, value] : resp.headers) {
    std::string k = key;
    // Case-insensitive header check
    for (auto &c : k) c = std::tolower(c);
    if (k == "set-cookie") {
      auto name_end = value.find('=');
      auto val_end = value.find(';');
      if (name_end != std::string::npos) {
        std::string cookie_pair = value.substr(0, val_end);
        if (!cookies.empty()) cookies += "; ";
        cookies += cookie_pair;
      }
    }
  }

  if (!cookies.empty()) {
    session.cookie = cookies;
    session.authenticated = true;
  }

  // Check for token in response body
  if (resp.body.find("\"token\"") != std::string::npos ||
      resp.body.find("\"access_token\"") != std::string::npos) {
    std::regex token_re(R"del("(?:token|access_token|jwt)"\s*:\s*"([^"]+)")del");
    std::smatch m;
    if (std::regex_search(resp.body, m, token_re)) {
      session.auth_header = "Bearer " + m[1].str();
      session.authenticated = true;
    }
  }

  // Check Location header for successful redirect (302 = login success usually)
  if (resp.status_code == 302 || resp.status_code == 301) {
    if (!cookies.empty()) {
      session.authenticated = true;
    }
  }

  return session;
}

/// URL-encode a string.
inline std::string url_encode(const std::string &s) {
  std::string result;
  for (char c : s) {
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      result += c;
    } else {
      char buf[4];
      snprintf(buf, sizeof(buf), "%%%02X", (unsigned char)c);
      result += buf;
    }
  }
  return result;
}

} // namespace apex

#endif // APEX_AUTO_LOGIN_HPP
