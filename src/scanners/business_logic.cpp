/// @file scanners/business_logic.cpp
/// @brief Business logic scanners: coupon abuse, referral fraud, cart manipulation,
///        negative quantity, free shipping bypass, trial abuse, feature flag leak,
///        export data without limit, bulk action abuse, time-based access control.
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Coupon/promo code abuse — reuse and stacking.
std::vector<Finding> scan_coupon_abuse(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> coupon_paths = {"/api/coupon/apply", "/api/promo", "/api/discount", "/api/cart/coupon",
                                                 "/api/checkout/coupon"};

  for (const auto& path : coupon_paths) {
    // Try applying same coupon twice
    auto r1 = http.post(base + path, R"({"code":"TEST10"})", "application/json");
    if (r1.status_code != 200) continue;
    auto r2 = http.post(base + path, R"({"code":"TEST10"})", "application/json");
    if (r2.status_code == 200 && r2.body.find("error") == std::string::npos && r2.body.find("already") == std::string::npos) {
      findings.push_back({"Coupon Reuse", "medium", base + path, "Same coupon code can be applied multiple times", "code", "TEST10",
                          "No duplicate check"});
    }
    // Try stacking different codes
    auto r3 = http.post(base + path, R"({"code":"SAVE20"})", "application/json");
    if (r3.status_code == 200 && r3.body.find("error") == std::string::npos) {
      findings.push_back({"Coupon Stacking", "medium", base + path, "Multiple coupon codes can be stacked", "code", "TEST10 + SAVE20",
                          "No stacking prevention"});
    }
    break;
  }
  return findings;
}

/// Negative quantity in cart/order.
std::vector<Finding> scan_negative_quantity(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> cart_paths = {"/api/cart/add", "/api/cart/update", "/api/order", "/api/basket/add", "/api/items/add"};

  for (const auto& path : cart_paths) {
    auto resp = http.post(base + path, R"({"product_id":1,"quantity":-5})", "application/json");
    if (resp.status_code == 200 && resp.body.find("error") == std::string::npos) {
      findings.push_back({"Negative Quantity Accepted", "high", base + path,
                          "Cart accepts negative quantity — potential credit/refund abuse", "quantity", "-5", "Server returned 200 OK"});
      break;
    }
  }
  return findings;
}

/// Free shipping bypass — set shipping to 0.
std::vector<Finding> scan_shipping_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> checkout_paths = {"/api/checkout", "/api/order/create", "/api/shipping"};

  for (const auto& path : checkout_paths) {
    auto resp = http.post(base + path, R"({"shipping_cost":0,"shipping_method":"free"})", "application/json");
    if (resp.status_code == 200 && resp.body.find("error") == std::string::npos) {
      findings.push_back({"Shipping Cost Manipulation", "medium", base + path, "Shipping cost accepted as 0 from client side",
                          "shipping_cost", "0", "No server-side validation"});
      break;
    }
  }
  return findings;
}

/// Unlimited data export — no pagination/limit on export endpoints.
std::vector<Finding> scan_unlimited_export(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> export_paths = {"/api/export",           "/api/users/export", "/api/data/export",
                                                 "/api/reports/download", "/api/csv",          "/api/download"};

  for (const auto& path : export_paths) {
    auto resp = http.get(base + path + "?limit=999999");
    if (resp.status_code == 200 && resp.body.size() > 1000) {
      findings.push_back({"Unlimited Data Export", "medium", base + path, "Export endpoint accepts unlimited limit — DoS/data theft risk",
                          "limit", "999999", "Response: " + std::to_string(resp.body.size()) + " bytes"});
      break;
    }
  }
  return findings;
}

/// Feature flag / debug mode leak.
std::vector<Finding> scan_feature_flags(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> flag_paths = {"/api/features",      "/api/flags",   "/api/config/features",
                                               "/api/feature-flags", "/api/toggles", "/api/experiments"};

  for (const auto& path : flag_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 50 &&
        (resp.body.find("enabled") != std::string::npos || resp.body.find("flag") != std::string::npos)) {
      findings.push_back(
          {"Feature Flags Exposed", "medium", base + path, "Internal feature flags publicly accessible", "", "", resp.body.substr(0, 200)});
      break;
    }
  }
  return findings;
}

/// Trial/subscription bypass.
std::vector<Finding> scan_trial_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> sub_paths = {"/api/subscription", "/api/plan", "/api/billing/plan"};

  for (const auto& path : sub_paths) {
    auto resp = http.post(base + path, R"({"plan":"enterprise","trial_end":"2099-12-31"})", "application/json");
    if (resp.status_code == 200 && resp.body.find("error") == std::string::npos &&
        // Must be a JSON response, not a WAF/redirect/HTML page
        resp.body.find("<!DOCTYPE") == std::string::npos && resp.body.find("<HTML>") == std::string::npos &&
        resp.body.find("Access Denied") == std::string::npos && resp.body.find("Just a moment") == std::string::npos &&
        (resp.body.find("{") == 0 || resp.body.find("[") == 0) &&
        // Must contain confirmation of the change
        (resp.body.find("enterprise") != std::string::npos || resp.body.find("success") != std::string::npos ||
         resp.body.find("updated") != std::string::npos)) {
      findings.push_back({"Subscription Plan Manipulation", "high", base + path, "Plan/trial dates modifiable from client side", "plan",
                          "enterprise", "Server accepted plan upgrade without payment"});
      break;
    }
  }
  return findings;
}

/// Referral fraud — self-referral or unlimited referrals.
std::vector<Finding> scan_referral_fraud(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> ref_paths = {"/api/referral", "/api/invite", "/api/refer"};

  for (const auto& path : ref_paths) {
    // Try self-referral
    auto resp = http.post(base + path, R"({"email":"self@self.com","referrer":"self@self.com"})", "application/json");
    if (resp.status_code == 200 && resp.body.find("error") == std::string::npos) {
      findings.push_back({"Self-Referral Accepted", "low", base + path, "User can refer themselves — reward abuse", "email/referrer",
                          "same email", "No self-referral check"});
      break;
    }
  }
  return findings;
}

/// Bulk action without rate limit.
std::vector<Finding> scan_bulk_abuse(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> bulk_paths = {"/api/bulk/delete", "/api/bulk/update", "/api/bulk/send", "/api/mass-email",
                                               "/api/notifications/send-all"};

  for (const auto& path : bulk_paths) {
    auto resp = http.post(base + path, R"({"ids":["1","2","3","4","5","6","7","8","9","10"]})", "application/json");
    if (resp.status_code == 200 && resp.body.find("error") == std::string::npos) {
      findings.push_back({"Bulk Action Without Limit", "medium", base + path, "Bulk operation endpoint has no size/rate restriction", "ids",
                          "10 items", "Accepted without throttling"});
      break;
    }
  }
  return findings;
}

/// Order ID enumeration — sequential predictable IDs.
std::vector<Finding> scan_order_enum(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> order_paths = {"/api/order/", "/api/orders/", "/api/invoice/"};
  const std::vector<std::string> pii = {"\"email\"", "\"phone\"", "\"address\"", "\"name\""};

  for (const auto& path : order_paths) {
    auto r1 = http.get(base + path + "1");
    auto r2 = http.get(base + path + "2");
    if (r1.status_code == 200 && r2.status_code == 200 && r1.body != r2.body && contains_any(r1.body, pii)) {
      findings.push_back({"Order ID Enumeration", "high", base + path, "Sequential order IDs expose customer data", "order_id", "1, 2",
                          "Both IDs return PII-containing order details"});
      break;
    }
  }
  return findings;
}

/// Timestamp-based access bypass.
std::vector<Finding> scan_time_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> time_paths = {"/api/sale", "/api/event", "/api/promo/active"};

  for (const auto& path : time_paths) {
    // Try manipulating timestamp to access expired/future content
    auto resp = http.get(base + path + "?timestamp=9999999999");
    if (resp.status_code == 200 && resp.body.size() > 50 && resp.body.find("error") == std::string::npos &&
        resp.body.find("expired") == std::string::npos) {
      findings.push_back({"Timestamp Access Bypass", "low", base + path, "Time-gated content accessible by manipulating timestamp",
                          "timestamp", "9999999999", "Future timestamp accepted"});
      break;
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_business_logic_scanners() {
  return {
      {"Coupon Abuse", scan_coupon_abuse},           {"Negative Quantity", scan_negative_quantity},
      {"Shipping Bypass", scan_shipping_bypass},     {"Unlimited Export", scan_unlimited_export},
      {"Feature Flags Exposed", scan_feature_flags}, {"Trial/Subscription Bypass", scan_trial_bypass},
      {"Referral Fraud", scan_referral_fraud},       {"Bulk Action Abuse", scan_bulk_abuse},
      {"Order Enumeration", scan_order_enum},        {"Timestamp Bypass", scan_time_bypass},
  };
}

}  // namespace apex
