#pragma once
#include <string>
#include <algorithm>
#include "http.hpp"

namespace apex {

/// Check if a response is from a real API endpoint vs a generic page/error/CDN
inline bool is_real_api_response(const Response &resp) {
    // 404/403/405/501 = endpoint doesn't exist
    if (resp.status_code == 404 || resp.status_code == 403 ||
        resp.status_code == 405 || resp.status_code == 501) return false;

    // Empty body with 200 is suspicious but might be valid
    if (resp.body.empty()) return false;

    // If it returns HTML for a JSON API call, it's a CDN/error page
    std::string body_lower = resp.body.substr(0, 500);
    std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(), ::tolower);

    if (body_lower.find("<!doctype") != std::string::npos ||
        body_lower.find("<html") != std::string::npos) {
        // HTML response to an API path = not a real API
        return false;
    }

    // Cloudflare challenge/block pages
    if (body_lower.find("cloudflare") != std::string::npos &&
        (body_lower.find("challenge") != std::string::npos ||
         body_lower.find("ray id") != std::string::npos ||
         body_lower.find("please wait") != std::string::npos)) {
        return false;
    }

    // Generic WAF blocks
    if (body_lower.find("access denied") != std::string::npos ||
        body_lower.find("forbidden") != std::string::npos ||
        body_lower.find("blocked") != std::string::npos) {
        return false;
    }

    return true;
}

/// Check if a response actually reflects our input (vs generic page)
inline bool reflects_input(const Response &resp, const std::string &marker) {
    if (marker.empty()) return false;
    return resp.body.find(marker) != std::string::npos;
}

/// Check if two responses are meaningfully different (not just timestamps/nonces)
inline bool responses_differ(const Response &a, const Response &b, int min_diff_bytes = 50) {
    if (a.status_code != b.status_code) return true;

    // Compare body length — ignore small differences (timestamps, nonces)
    int diff = std::abs((int)a.body.length() - (int)b.body.length());
    if (diff > min_diff_bytes) return true;

    // Same length but different content?
    if (a.body.length() == b.body.length() && a.body != b.body) {
        // Count actual differences
        int char_diffs = 0;
        for (size_t i = 0; i < std::min(a.body.length(), (size_t)2000); i++) {
            if (a.body[i] != b.body[i]) char_diffs++;
        }
        // If more than 10% differs, it's meaningful
        return char_diffs > (int)(a.body.length() * 0.1);
    }

    return false;
}

/// Check if endpoint exists by comparing against the site's 404 response
inline bool endpoint_exists(HttpClient &http, const std::string &url, const std::string &base_url) {
    auto resp = http.get(url);

    // Obviously doesn't exist
    if (resp.status_code == 404 || resp.status_code == 410) return false;

    // Compare against a known-bad path
    auto not_found = http.get(base_url + "/apex_nonexistent_path_" + std::to_string(rand()));
    if (not_found.status_code == resp.status_code && !responses_differ(resp, not_found, 100)) {
        // Same response as a path that definitely doesn't exist = soft 404
        return false;
    }

    return resp.status_code >= 200 && resp.status_code < 400;
}

/// Validate that a finding has real evidence, not just a status code
inline bool has_real_evidence(const std::string &response_body, const std::string &expected_pattern) {
    if (expected_pattern.empty()) return !response_body.empty();

    std::string body_lower = response_body;
    std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(), ::tolower);
    std::string pattern_lower = expected_pattern;
    std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(), ::tolower);

    return body_lower.find(pattern_lower) != std::string::npos;
}

} // namespace apex
