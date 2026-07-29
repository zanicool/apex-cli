#pragma once
/// @file idor_detector.hpp
/// @brief IDOR (Insecure Direct Object Reference) auto-detector.
#ifndef APEX_IDOR_DETECTOR_HPP
#define APEX_IDOR_DETECTOR_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Detects IDOR vulnerabilities by swapping numeric/UUID identifiers in URLs
/// and comparing responses for unauthorized data access.
class IDORDetector {
public:
  explicit IDORDetector(HttpClient &http, const Config &cfg);

  /// Detect IDOR vulnerabilities across all crawled URLs.
  std::vector<Finding> detect(const CrawlResult &crawl);

private:
  struct IDMatch {
    std::string url;
    std::string original_id;
    size_t start_pos;
    size_t length;
    bool is_uuid;
  };

  std::vector<IDMatch> extract_ids(const std::string &url);
  std::string replace_id(const std::string &url, const IDMatch &match,
                         const std::string &new_id);
  bool responses_differ_significantly(const Response &r1, const Response &r2);
  size_t hash_body(const std::string &body);

  HttpClient &http_;
  const Config &cfg_;
};

} // namespace apex

#endif // APEX_IDOR_DETECTOR_HPP
