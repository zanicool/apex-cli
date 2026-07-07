/// @file scanners/race_condition.cpp
/// @brief Race condition scanner: detect endpoints vulnerable to TOCTOU,
///        double-spend, and concurrent request abuse.
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Detect endpoints likely vulnerable to race conditions.
/// We can't safely exploit these, but we identify them for manual testing.
std::vector<Finding> scan_race_candidates(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Patterns that indicate race-vulnerable operations
  struct RaceTarget {
    std::string path;
    std::string operation;
    std::string risk;
  };

  std::vector<RaceTarget> targets = {
      {"/api/redeem", "Coupon/code redemption", "Double redemption via concurrent requests"},
      {"/api/v1/redeem", "Coupon/code redemption", "Double redemption via concurrent requests"},
      {"/api/coupon/apply", "Coupon application", "Apply same coupon multiple times"},
      {"/api/promo/apply", "Promo code", "Stack promotions via race"},
      {"/api/transfer", "Money transfer", "Double-spend via concurrent transfers"},
      {"/api/v1/transfer", "Money transfer", "Double-spend via concurrent transfers"},
      {"/api/withdraw", "Withdrawal", "Withdraw more than balance"},
      {"/api/v1/withdraw", "Withdrawal", "Withdraw more than balance"},
      {"/api/vote", "Voting", "Multiple votes via race"},
      {"/api/like", "Like/upvote", "Infinite likes via concurrent requests"},
      {"/api/follow", "Follow action", "Duplicate follow for rewards"},
      {"/api/referral", "Referral", "Self-referral or double referral credit"},
      {"/api/v1/referral", "Referral", "Self-referral or double referral credit"},
      {"/api/claim", "Claim reward", "Claim same reward multiple times"},
      {"/api/checkout", "Checkout", "Double-purchase at discounted rate"},
      {"/api/v1/checkout", "Checkout", "Double-purchase at discounted rate"},
      {"/api/order", "Order placement", "Duplicate order exploit"},
      {"/api/register", "Registration", "Duplicate account creation"},
      {"/api/trial", "Free trial", "Multiple free trials"},
      {"/api/v1/trial/start", "Free trial", "Multiple free trials"},
      {"/api/invite/accept", "Invite acceptance", "Accept same invite multiple times"},
  };

  for (const auto& t : targets) {
    auto resp = http.get(base + t.path);
    // 405 = exists but wrong method (likely POST)
    // 401/403 = exists but requires auth
    // 400 = exists but needs body
    if (resp.status_code == 405 || resp.status_code == 401 || resp.status_code == 403 || resp.status_code == 400 ||
        resp.status_code == 422) {
      findings.push_back({"Race Condition Target — " + t.operation, "medium", base + t.path,
                          "Endpoint likely performs state-changing operation: " + t.operation +
                              ". "
                              "Risk: " +
                              t.risk +
                              ". "
                              "Test by sending 10-50 concurrent POST requests.",
                          "", "", "Status: " + std::to_string(resp.status_code)});
    }
  }
  return findings;
}

/// Check for missing idempotency keys on payment endpoints.
std::vector<Finding> scan_idempotency(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::vector<std::string> payment_paths = {"/api/payment",     "/api/v1/payment",   "/api/charge",          "/api/pay",
                                            "/api/v1/pay",      "/api/transactions", "/api/v1/transactions", "/api/checkout/complete",
                                            "/api/order/create"};

  for (const auto& path : payment_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 405 || resp.status_code == 401 || resp.status_code == 400 || resp.status_code == 422) {
      // Check if response mentions idempotency
      bool has_idempotency = false;
      for (const auto& [key, val] : resp.headers) {
        std::string lower = key;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("idempotency") != std::string::npos) {
          has_idempotency = true;
          break;
        }
      }
      if (!has_idempotency && resp.body.find("idempotency") == std::string::npos) {
        findings.push_back({"Payment Endpoint — No Idempotency Key", "medium", base + path,
                            "Payment endpoint found without idempotency mechanism. "
                            "Retried/concurrent requests may cause double charges.",
                            "", "", ""});
        break;
      }
    }
  }
  return findings;
}

/// Check for rate limiting on sensitive operations.
std::vector<Finding> scan_rate_limit_absence(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::vector<std::string> auth_paths = {"/api/auth/login",           "/api/v1/auth/login",           "/api/login",
                                         "/api/auth/forgot-password", "/api/v1/auth/forgot-password", "/api/auth/verify",
                                         "/api/v1/auth/verify-otp",   "/api/auth/reset-password"};

  for (const auto& path : auth_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 405 || resp.status_code == 400 || resp.status_code == 422) {
      // Check for rate limit headers
      bool has_rate_limit = false;
      for (const auto& [key, val] : resp.headers) {
        std::string lower = key;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("ratelimit") != std::string::npos || lower.find("rate-limit") != std::string::npos ||
            lower.find("x-rate") != std::string::npos || lower.find("retry-after") != std::string::npos) {
          has_rate_limit = true;
          break;
        }
      }
      if (!has_rate_limit) {
        findings.push_back({"Auth Endpoint — No Rate Limiting", "medium", base + path,
                            "Authentication endpoint has no rate limit headers. "
                            "Vulnerable to credential brute-forcing and OTP guessing.",
                            "", "", ""});
        break;
      }
    }
  }
  return findings;
}

/// Detect WebSocket endpoints (often lack auth/rate limiting).
std::vector<Finding> scan_websocket(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check for WebSocket upgrade endpoints
  std::vector<std::string> ws_paths = {"/ws", "/websocket", "/socket.io/", "/api/ws", "/realtime", "/cable", "/hub", "/signalr"};

  for (const auto& path : ws_paths) {
    auto resp = http.get(base + path, {{"Upgrade", "websocket"}, {"Connection", "Upgrade"}});
    if (resp.status_code == 101 || resp.status_code == 200 || resp.status_code == 400) {
      if (resp.body.find("websocket") != std::string::npos || resp.body.find("socket") != std::string::npos || resp.status_code == 101) {
        findings.push_back({"WebSocket Endpoint Found", "info", base + path,
                            "WebSocket endpoint discovered. Test for: "
                            "auth bypass, message injection, and lack of rate limiting.",
                            "", "", "Status: " + std::to_string(resp.status_code)});
        break;
      }
    }
  }

  // Check HTML for WebSocket URLs
  auto resp = http.get(base);
  std::regex ws_re(R"x(wss?://[^"'\s]+)x");
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), ws_re);
  std::sregex_iterator end;
  for (; it != end; ++it) {
    findings.push_back(
        {"WebSocket URL in Source", "info", base, "WebSocket URL found in page source: " + (*it).str(), "", (*it).str(), ""});
    break;
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_race_condition_scanners() {
  return {
      {"Race Condition Targets", scan_race_candidates},
      {"Missing Idempotency", scan_idempotency},
      {"Rate Limit Absence", scan_rate_limit_absence},
      {"WebSocket Discovery", scan_websocket},
  };
}

}  // namespace apex
