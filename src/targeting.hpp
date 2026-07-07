/// @file targeting.hpp
/// @brief Intelligent Targeting Engine — asset profiling and smart module selection.
///
/// Instead of running all 93 modules blindly, this engine:
/// 1. Builds an asset profile from crawl + recon data
/// 2. Selects relevant scanner modules based on detected technology
/// 3. Prioritizes endpoints by sensitivity (auth, payment, admin)
/// 4. Adapts crawl depth based on what it finds
///
/// This is what makes Apex think like a researcher, not a brute-forcer.
#ifndef APEX_TARGETING_HPP
#define APEX_TARGETING_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "scanner.hpp"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace apex {

/// Sensitivity level for an endpoint.
enum class Sensitivity {
  LOW,      // Static content, public pages
  MEDIUM,   // User-facing features
  HIGH,     // Auth, profile, settings
  CRITICAL  // Payment, admin, API keys
};

/// A profiled endpoint with context.
struct Endpoint {
  std::string url;
  std::string method;
  Sensitivity sensitivity;
  std::set<std::string> params;
  std::string technology;
  bool requires_auth = false;
  bool is_api = false;
};

/// Asset profile built from reconnaissance.
struct AssetProfile {
  std::string domain;
  std::set<std::string> technologies;
  std::set<std::string> subdomains;
  std::vector<Endpoint> endpoints;
  std::string cloud_provider;  // aws, gcp, azure, cloudflare
  std::string server;
  std::string waf;
  bool has_graphql = false;
  bool has_websocket = false;
  bool has_oauth = false;
  bool has_jwt = false;
  bool is_spa = false;
  bool is_api_service = false;
  bool is_wordpress = false;
  int endpoint_count = 0;
  int param_count = 0;

  /// Get a relevance score (0.0-1.0) for a scanner module.
  double module_relevance(const std::string &module_name) const;

  /// Get priority-ordered endpoints for deep testing.
  std::vector<Endpoint> get_priority_targets() const;
};

/// Build an asset profile from crawl results and initial recon.
AssetProfile build_profile(const CrawlResult &crawl, HttpClient &http);

/// Filter scanners by relevance to the asset profile.
/// Returns only scanners with relevance > threshold.
std::vector<Scanner> select_modules(const std::vector<Scanner> &all_scanners,
                                     const AssetProfile &profile,
                                     double threshold = 0.3);

/// Classify endpoint sensitivity based on path/params.
Sensitivity classify_endpoint(const std::string &url,
                               const std::set<std::string> &params);

} // namespace apex

#endif // APEX_TARGETING_HPP
