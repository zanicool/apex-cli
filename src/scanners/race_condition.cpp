/// @file scanners/race_condition.cpp
/// @brief Race condition scanner: detect endpoints vulnerable to TOCTOU,
///        double-spend, and concurrent request abuse.
#include <regex>

#include "scanner_base.hpp"
#include "../response_validator.hpp"

namespace apex {
namespace {

bool distinct_route(const Response& candidate, const Response& missing) {
  if (candidate.status_code == 0 || candidate.status_code == 404 || candidate.status_code == 410) return false;
  return candidate.status_code != missing.status_code || responses_differ(candidate, missing, 40);
}

bool has_header_fragment(const Response& response, const std::string& fragment) {
  for (const auto& [key, value] : response.headers) {
    std::string lower = key;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find(fragment) != std::string::npos) return true;
  }
  return false;
}

/// Identify real, distinct state-changing routes for manual race testing.
std::vector<Finding> scan_race_candidates(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  const std::string base = base_url_from(crawl.urls[0]);
  const auto missing = http.get(base + "/api/apex-route-probe-7f3c9d");

  struct RaceTarget { std::string path; std::string operation; std::string risk; };
  const std::vector<RaceTarget> targets = {
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

  for (const auto& target : targets) {
    const auto response = http.get(base + target.path);
    const bool method_or_auth_signal = response.status_code == 400 || response.status_code == 401 ||
                                       response.status_code == 403 || response.status_code == 405 ||
                                       response.status_code == 422;
    if (!method_or_auth_signal || !distinct_route(response, missing)) continue;
    findings.push_back({"Race Condition Target — " + target.operation, "info", base + target.path,
                        "Distinct state-changing endpoint identified for manual concurrency testing. Risk: " + target.risk,
                        "", "", "Route differs from soft-404 probe; HTTP " + std::to_string(response.status_code)});
  }
  return findings;
}

/// Identify payment routes where idempotency support is not advertised.
std::vector<Finding> scan_idempotency(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  const std::string base = base_url_from(crawl.urls[0]);
  const auto missing = http.get(base + "/api/apex-payment-probe-7f3c9d");
  const std::vector<std::string> paths = {"/api/payment", "/api/v1/payment", "/api/charge", "/api/pay",
                                          "/api/v1/pay", "/api/transactions", "/api/v1/transactions",
                                          "/api/checkout/complete", "/api/order/create"};

  for (const auto& path : paths) {
    const auto response = http.get(base + path);
    const bool endpoint_signal = response.status_code == 400 || response.status_code == 401 ||
                                 response.status_code == 405 || response.status_code == 422;
    if (!endpoint_signal || !distinct_route(response, missing)) continue;
    std::string body = response.body;
    std::transform(body.begin(), body.end(), body.begin(), ::tolower);
    if (!has_header_fragment(response, "idempotency") && body.find("idempotency") == std::string::npos) {
      findings.push_back({"Payment Endpoint — Idempotency Review", "info", base + path,
                          "Distinct payment endpoint does not advertise an idempotency contract; active duplicate charging was not attempted",
                          "", "", "Soft-404 differential confirmed endpoint; no idempotency header/body guidance"});
      break;
    }
  }
  return findings;
}

/// Identify real auth routes lacking visible throttling metadata. Active brute-force
/// confirmation is performed by the dedicated bounty scanner.
std::vector<Finding> scan_rate_limit_absence(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  const std::string base = base_url_from(crawl.urls[0]);
  const auto missing = http.get(base + "/api/apex-auth-probe-7f3c9d");
  const std::vector<std::string> paths = {"/api/auth/login", "/api/v1/auth/login", "/api/login",
                                          "/api/auth/forgot-password", "/api/v1/auth/forgot-password",
                                          "/api/auth/verify", "/api/v1/auth/verify-otp", "/api/auth/reset-password"};

  for (const auto& path : paths) {
    const auto response = http.get(base + path);
    const bool endpoint_signal = response.status_code == 400 || response.status_code == 401 ||
                                 response.status_code == 405 || response.status_code == 422;
    if (!endpoint_signal || !distinct_route(response, missing)) continue;
    std::string body = response.body;
    std::transform(body.begin(), body.end(), body.begin(), ::tolower);
    const bool auth_semantics = body.find("password") != std::string::npos || body.find("credential") != std::string::npos ||
                                body.find("login") != std::string::npos || body.find("email") != std::string::npos ||
                                body.find("otp") != std::string::npos || body.find("authentication") != std::string::npos;
    if (!auth_semantics) continue;
    const bool advertised = has_header_fragment(response, "ratelimit") || has_header_fragment(response, "rate-limit") ||
                            has_header_fragment(response, "x-rate") || has_header_fragment(response, "retry-after");
    if (!advertised) {
      findings.push_back({"Auth Endpoint — Throttling Review", "info", base + path,
                          "Distinct authentication endpoint exposes no throttling metadata; active confirmation required",
                          "", "", "Auth semantics and soft-404 differential confirmed; no rate-limit headers"});
      break;
    }
  }
  return findings;
}

std::vector<Finding> scan_websocket(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  const std::string base = base_url_from(crawl.urls[0]);
  const std::vector<std::pair<std::string, std::string>> upgrade_headers = {{"Upgrade", "websocket"}, {"Connection", "Upgrade"}};
  const auto missing = http.get(base + "/apex-websocket-probe-7f3c9d", upgrade_headers);
  const std::vector<std::string> paths = {"/ws", "/websocket", "/socket.io/", "/api/ws", "/realtime", "/cable", "/hub", "/signalr"};

  for (const auto& path : paths) {
    const auto response = http.get(base + path, upgrade_headers);
    bool upgrade_response = response.status_code == 101 || has_header_fragment(response, "upgrade");
    std::string body = response.body;
    std::transform(body.begin(), body.end(), body.begin(), ::tolower);
    if (distinct_route(response, missing) && (upgrade_response || body.find("websocket") != std::string::npos)) {
      findings.push_back({"WebSocket Endpoint Found", "info", base + path,
                          "WebSocket endpoint confirmed by upgrade semantics or explicit protocol response", "", "",
                          "HTTP " + std::to_string(response.status_code)});
      break;
    }
  }

  const auto page = http.get(base);
  std::regex ws_re(R"x(wss?://[^"'\s]+)x");
  std::smatch match;
  if (std::regex_search(page.body, match, ws_re)) {
    findings.push_back({"WebSocket URL in Source", "info", base,
                        "WebSocket URL found in page source: " + match.str(), "", match.str(), match.str()});
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_race_condition_scanners() {
  return {{"Race Condition Targets", scan_race_candidates},
          {"Missing Idempotency", scan_idempotency},
          {"Rate Limit Absence", scan_rate_limit_absence},
          {"WebSocket Discovery", scan_websocket}};
}

}  // namespace apex
