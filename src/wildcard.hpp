/// @file wildcard.hpp
/// @brief Detect wildcard/SPA responses that return 200 for any path.
#ifndef APEX_WILDCARD_HPP
#define APEX_WILDCARD_HPP

#include "http.hpp"
#include <string>

namespace apex {

/// Fingerprint of a baseline "not found" response.
struct BaselineFingerprint {
  int status_code = 0;
  size_t body_size = 0;
  std::string body_hash; // first 64 chars of body for comparison
  bool is_wildcard = false;
};

/// Get the baseline fingerprint for a host (request a random non-existent path).
inline BaselineFingerprint get_baseline(HttpClient &http, const std::string &base_url) {
  BaselineFingerprint fp;
  auto resp = http.get(base_url + "/apex_nonexistent_path_xz9q7w2m4k");
  fp.status_code = resp.status_code;
  fp.body_size = resp.body.size();
  fp.body_hash = resp.body.substr(0, 64);

  // If random path returns 200 with content, it's likely a wildcard/SPA
  if (resp.status_code == 200 && resp.body.size() > 100) {
    // Double check with another random path
    auto resp2 = http.get(base_url + "/apex_also_not_real_p3j8v6n1");
    if (resp2.status_code == 200 && resp2.body.size() == resp.body.size()) {
      fp.is_wildcard = true;
    }
  }
  return fp;
}

/// Check if a response is just the wildcard/default page (not real content).
inline bool is_wildcard_response(const Response &resp, const BaselineFingerprint &fp) {
  if (!fp.is_wildcard) {
    // Not a wildcard host — only filter if same status + same size as 404 baseline
    return resp.status_code == fp.status_code && resp.body.size() == fp.body_size;
  }
  // Wildcard host — response must differ significantly from baseline
  if (resp.body.size() == fp.body_size) return true;
  // Allow small variance (±50 bytes) for dynamic tokens/nonces
  if (std::abs((long)resp.body.size() - (long)fp.body_size) < 50) return true;
  return false;
}

/// Check if response is a WAF/CDN challenge page.
inline bool is_waf_challenge(const Response &resp) {
  if (resp.body.find("Just a moment...") != std::string::npos) return true;
  if (resp.body.find("Cloudflare Access") != std::string::npos) return true;
  if (resp.body.find("challenge-platform") != std::string::npos) return true;
  if (resp.body.find("Checking your browser") != std::string::npos) return true;
  if (resp.body.find("Please verify you are a human") != std::string::npos) return true;
  if (resp.status_code == 403 && resp.body.find("Request blocked") != std::string::npos) return true;
  return false;
}

} // namespace apex

#endif // APEX_WILDCARD_HPP
