/// @file targeting.cpp
/// @brief Intelligent Targeting Engine implementation.
#include "targeting.hpp"

#include <algorithm>
#include <regex>

namespace apex {

// ============================================================
// ENDPOINT SENSITIVITY CLASSIFICATION
// ============================================================

Sensitivity classify_endpoint(const std::string& url, const std::set<std::string>& params) {
  std::string lower = url;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

  // Critical: payment, admin, financial operations
  static const std::vector<std::string> critical_patterns = {"payment", "checkout", "billing",   "invoice",    "withdraw",    "transfer",
                                                             "admin",   "manage",   "superuser", "staff",      "internal",    "ops",
                                                             "api/key", "apikey",   "secret",    "credential", "token/create"};
  for (const auto& p : critical_patterns) {
    if (lower.find(p) != std::string::npos) return Sensitivity::CRITICAL;
  }

  // High: auth, user data, settings
  static const std::vector<std::string> high_patterns = {
      "auth", "login", "register", "signup", "password", "reset", "profile", "account", "settings", "session", "oauth",
      "sso",  "2fa",   "mfa",      "verify", "confirm",  "user/", "users/",  "email",   "phone",    "address", "delete"};
  for (const auto& p : high_patterns) {
    if (lower.find(p) != std::string::npos) return Sensitivity::HIGH;
  }

  // Check params for sensitive indicators
  for (const auto& param : params) {
    std::string p = param;
    std::transform(p.begin(), p.end(), p.begin(), ::tolower);
    if (p.find("token") != std::string::npos || p.find("key") != std::string::npos || p.find("secret") != std::string::npos ||
        p.find("pass") != std::string::npos || p.find("credit") != std::string::npos || p.find("amount") != std::string::npos) {
      return Sensitivity::HIGH;
    }
  }

  // Medium: API endpoints, user-facing features
  if (lower.find("api") != std::string::npos || lower.find("/v1/") != std::string::npos || lower.find("/v2/") != std::string::npos ||
      lower.find("graphql") != std::string::npos) {
    return Sensitivity::MEDIUM;
  }

  return Sensitivity::LOW;
}

// ============================================================
// ASSET PROFILE BUILDER
// ============================================================

AssetProfile build_profile(const CrawlResult& crawl, HttpClient& http) {
  AssetProfile profile;

  if (crawl.urls.empty()) return profile;

  // Extract domain
  std::string base = crawl.urls[0];
  auto proto_end = base.find("://");
  if (proto_end != std::string::npos) {
    auto slash = base.find("/", proto_end + 3);
    profile.domain = base.substr(proto_end + 3, slash - proto_end - 3);
  }

  // Copy technology detection from crawl
  profile.technologies = crawl.technologies;
  profile.has_graphql = crawl.has_graphql;
  profile.has_websocket = crawl.has_websocket;
  profile.is_spa = crawl.is_spa;
  profile.server = crawl.server_header;
  profile.endpoint_count = crawl.urls.size();
  profile.param_count = crawl.params.size();

  // Detect specific platforms
  profile.is_wordpress = crawl.technologies.count("wordpress") > 0;

  // Detect mobile app indicators (app store links, mobile API endpoints, deep links)
  for (const auto& url : crawl.urls) {
    if (url.find("itunes.apple.com") != std::string::npos ||
        url.find("play.google.com") != std::string::npos ||
        url.find("apps.apple.com") != std::string::npos ||
        url.find("/api/mobile") != std::string::npos ||
        url.find("/.well-known/apple-app-site-association") != std::string::npos ||
        url.find("/.well-known/assetlinks.json") != std::string::npos) {
      profile.has_mobile_indicators = true;
      break;
    }
  }

  // Detect container/K8s indicators
  if (profile.server.find("istio") != std::string::npos ||
      profile.server.find("envoy") != std::string::npos ||
      crawl.technologies.count("kubernetes") > 0 ||
      crawl.technologies.count("docker") > 0) {
    profile.is_containerized = true;
  }

  // Detect serverless
  if (profile.server.find("Vercel") != std::string::npos ||
      profile.server.find("Netlify") != std::string::npos ||
      crawl.technologies.count("vercel") > 0 ||
      crawl.technologies.count("netlify") > 0 ||
      crawl.technologies.count("lambda") > 0) {
    profile.is_serverless = true;
  }

  // Detect cloud provider from headers/DNS
  if (profile.server.find("cloudflare") != std::string::npos) {
    profile.cloud_provider = "cloudflare";
    profile.waf = "cloudflare";
  } else if (profile.server.find("AmazonS3") != std::string::npos || profile.server.find("CloudFront") != std::string::npos) {
    profile.cloud_provider = "aws";
  } else if (profile.server.find("Microsoft") != std::string::npos) {
    profile.cloud_provider = "azure";
  } else if (profile.server.find("Google") != std::string::npos) {
    profile.cloud_provider = "gcp";
  }

  // Detect JWT usage
  auto home = http.get(crawl.urls[0]);
  if (home.body.find("jwt") != std::string::npos || home.body.find("Bearer") != std::string::npos ||
      home.body.find("eyJ") != std::string::npos) {
    profile.has_jwt = true;
  }

  // Detect OAuth
  if (home.body.find("oauth") != std::string::npos || home.body.find("client_id") != std::string::npos ||
      home.body.find("redirect_uri") != std::string::npos) {
    profile.has_oauth = true;
  }

  // Build endpoint list with classification
  for (const auto& url : crawl.urls) {
    std::set<std::string> params;
    for (const auto& p : crawl.params) {
      if (url.find(p.url) != std::string::npos) params.insert(p.name);
    }

    Endpoint ep;
    ep.url = url;
    ep.method = "GET";
    ep.sensitivity = classify_endpoint(url, params);
    ep.params = params;
    ep.is_api = url.find("api") != std::string::npos || url.find("/v1") != std::string::npos;
    profile.endpoints.push_back(ep);
  }

  // Detect if primarily an API service
  int api_count = 0;
  for (const auto& ep : profile.endpoints) {
    if (ep.is_api) api_count++;
  }
  if (profile.endpoint_count > 0 && api_count > profile.endpoint_count / 2) {
    profile.is_api_service = true;
  }

  return profile;
}

// ============================================================
// MODULE RELEVANCE SCORING
// ============================================================

double AssetProfile::module_relevance(const std::string& module_name) const {
  std::string name = module_name;
  std::transform(name.begin(), name.end(), name.begin(), ::tolower);

  // Always relevant (universal checks)
  if (name.find("security header") != std::string::npos || name.find("info disclosure") != std::string::npos ||
      name.find("cors") != std::string::npos || name.find("waf") != std::string::npos) {
    return 1.0;
  }

  // WordPress-specific: only if WordPress detected
  if (name.find("wp ") != std::string::npos || name.find("wordpress") != std::string::npos) {
    return is_wordpress ? 1.0 : 0.0;
  }

  // GraphQL: only if GraphQL detected
  if (name.find("graphql") != std::string::npos) {
    return has_graphql ? 1.0 : 0.1;
  }

  // JWT: only if JWT/Bearer detected
  if (name.find("jwt") != std::string::npos) {
    return has_jwt ? 1.0 : 0.2;
  }

  // OAuth: only if OAuth detected
  if (name.find("oauth") != std::string::npos) {
    return has_oauth ? 1.0 : 0.2;
  }

  // WebSocket: only if WS detected
  if (name.find("websocket") != std::string::npos) {
    return has_websocket ? 1.0 : 0.0;
  }

  // SPA-specific checks
  if (name.find("dom") != std::string::npos || name.find("prototype") != std::string::npos || name.find("browser") != std::string::npos) {
    return is_spa ? 1.0 : 0.4;
  }

  // API checks
  if (name.find("api") != std::string::npos || name.find("rest") != std::string::npos) {
    return is_api_service ? 1.0 : 0.5;
  }

  // E-commerce checks
  if (name.find("payment") != std::string::npos || name.find("cart") != std::string::npos || name.find("ecommerce") != std::string::npos ||
      name.find("coupon") != std::string::npos) {
    // Only if we found payment/commerce endpoints
    for (const auto& ep : endpoints) {
      if (ep.sensitivity == Sensitivity::CRITICAL) return 0.8;
    }
    return 0.2;
  }

  // Cloud checks: match to detected provider
  if (name.find("aws") != std::string::npos || name.find("s3") != std::string::npos) {
    return cloud_provider == "aws" ? 1.0 : 0.3;
  }
  if (name.find("azure") != std::string::npos) {
    return cloud_provider == "azure" ? 1.0 : 0.2;
  }
  if (name.find("gcp") != std::string::npos || name.find("firebase") != std::string::npos) {
    return cloud_provider == "gcp" ? 1.0 : 0.3;
  }

  // Injection checks: always somewhat relevant
  if (name.find("sqli") != std::string::npos || name.find("xss") != std::string::npos || name.find("injection") != std::string::npos ||
      name.find("ssrf") != std::string::npos || name.find("ssti") != std::string::npos || name.find("lfi") != std::string::npos) {
    return param_count > 0 ? 0.9 : 0.3;
  }

  // Mobile app scanners: only relevant if target is a mobile app or has mobile indicators
  if (name.find("Mobile") != std::string::npos || name.find("mobile") != std::string::npos ||
      name.find("Android") != std::string::npos || name.find("iOS") != std::string::npos ||
      name.find("android") != std::string::npos || name.find("biometric") != std::string::npos ||
      name.find("keychain") != std::string::npos || name.find("keystore") != std::string::npos ||
      name.find("obfuscation") != std::string::npos || name.find("jailbreak") != std::string::npos) {
    return has_mobile_indicators ? 0.8 : 0.1;
  }

  // Container/K8s: only if indicators present
  if (name.find("Container") != std::string::npos || name.find("container") != std::string::npos ||
      name.find("Docker") != std::string::npos || name.find("Kubernetes") != std::string::npos ||
      name.find("Helm") != std::string::npos || name.find("etcd") != std::string::npos) {
    return is_containerized ? 0.8 : 0.2;
  }

  // Serverless: only if platform detected
  if (name.find("Lambda") != std::string::npos || name.find("serverless") != std::string::npos ||
      name.find("Vercel") != std::string::npos || name.find("Netlify") != std::string::npos ||
      name.find("Cloudflare Worker") != std::string::npos) {
    return is_serverless ? 0.9 : 0.2;
  }

  // Default: moderate relevance
  return 0.5;
}

// ============================================================
// PRIORITY TARGETS
// ============================================================

std::vector<Endpoint> AssetProfile::get_priority_targets() const {
  auto sorted = endpoints;
  std::sort(sorted.begin(), sorted.end(),
            [](const Endpoint& a, const Endpoint& b) { return static_cast<int>(a.sensitivity) > static_cast<int>(b.sensitivity); });
  return sorted;
}

// ============================================================
// SMART MODULE SELECTION
// ============================================================

std::vector<Scanner> select_modules(const std::vector<Scanner>& all_scanners, const AssetProfile& profile, double threshold) {
  std::vector<Scanner> selected;

  for (const auto& scanner : all_scanners) {
    double relevance = profile.module_relevance(scanner.name);
    if (relevance >= threshold) {
      selected.push_back(scanner);
    }
  }

  // Sort by relevance (most relevant first = run first)
  std::sort(selected.begin(), selected.end(),
            [&profile](const Scanner& a, const Scanner& b) { return profile.module_relevance(a.name) > profile.module_relevance(b.name); });

  return selected;
}

}  // namespace apex
