/// @file confidence.hpp
/// @brief Confidence scoring for findings + watch mode diff.
#ifndef APEX_CONFIDENCE_HPP
#define APEX_CONFIDENCE_HPP

#include "scanner.hpp"
#include <algorithm>
#include <fstream>
#include <set>
#include <string>
#include <vector>

namespace apex {

/// Confidence levels.
enum class Confidence { Possible = 1, Probable = 2, Confirmed = 3 };

inline const char *confidence_str(Confidence c) {
  switch (c) {
  case Confidence::Confirmed:
    return "confirmed";
  case Confidence::Probable:
    return "probable";
  case Confidence::Possible:
    return "possible";
  }
  return "unknown";
}

/// Score a finding's confidence based on evidence quality.
inline Confidence score_confidence(const Finding &f) {
  // Confirmed: has concrete evidence that differs from baseline
  if (!f.evidence.empty() && !f.payload.empty()) {
    // SQL errors, reflected payloads, file contents = confirmed
    if (f.type == "SQLi" || f.type == "XSS" || f.type == "LFI" ||
        f.type == "XXE" || f.type == "SSTI" || f.type == "SSTI Deep" ||
        f.type == "NoSQL Injection" || f.type == "CMDi")
      return Confidence::Confirmed;
    if (f.type == "SSRF" && f.evidence.find("ami-id") != std::string::npos)
      return Confidence::Confirmed;
    if (f.type == "IDOR")
      return Confidence::Confirmed;
    if (f.type == "Secrets Exposure")
      return Confidence::Confirmed;
    if (f.type == "CORS Misconfiguration")
      return Confidence::Confirmed;
    return Confidence::Probable;
  }

  // Probable: has payload or evidence but not both
  if (!f.payload.empty() || !f.evidence.empty()) {
    if (f.type == "Blind CMDi" || f.type == "Blind SQLi OOB" ||
        f.type == "Timing Oracle")
      return Confidence::Probable;
    return Confidence::Probable;
  }

  // Possible: informational, no direct proof
  if (f.type == "Missing Header" || f.type == "Clickjacking" ||
      f.type == "Cookie Security" || f.type == "Info Disclosure" ||
      f.type == "Header Leak" || f.type == "Server Banner Disclosure")
    return Confidence::Possible;

  return Confidence::Possible;
}

/// Filter findings by minimum confidence level.
inline std::vector<Finding>
filter_by_confidence(const std::vector<Finding> &findings, int min_level) {
  if (min_level <= 0)
    return findings;
  std::vector<Finding> filtered;
  for (const auto &f : findings) {
    if (static_cast<int>(score_confidence(f)) >= min_level)
      filtered.push_back(f);
  }
  return filtered;
}

/// Summary of confidence distribution.
struct ConfidenceSummary {
  int confirmed = 0;
  int probable = 0;
  int possible = 0;
  int total = 0;
};

inline ConfidenceSummary
summarize_confidence(const std::vector<Finding> &findings) {
  ConfidenceSummary s;
  s.total = findings.size();
  for (const auto &f : findings) {
    switch (score_confidence(f)) {
    case Confidence::Confirmed:
      ++s.confirmed;
      break;
    case Confidence::Probable:
      ++s.probable;
      break;
    case Confidence::Possible:
      ++s.possible;
      break;
    }
  }
  return s;
}

// ─── Watch Mode: Diff ──────────────────────────────────────────────────────

/// A finding key for deduplication/diff.
inline std::string finding_key(const Finding &f) {
  return f.type + "|" + f.url + "|" + f.param;
}

/// Load previous findings from a report.json file.
inline std::set<std::string> load_baseline(const std::string &path) {
  std::set<std::string> keys;
  std::ifstream file(path);
  if (!file.is_open())
    return keys;

  std::string content((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

  // Simple JSON parsing for finding keys
  size_t pos = 0;
  while ((pos = content.find("\"type\"", pos)) != std::string::npos) {
    auto extract = [&](const std::string &field) -> std::string {
      size_t fp = content.find("\"" + field + "\"", pos);
      if (fp == std::string::npos || fp > pos + 500)
        return "";
      size_t vs = content.find("\"", fp + field.size() + 3);
      size_t ve = content.find("\"", vs + 1);
      if (vs == std::string::npos || ve == std::string::npos)
        return "";
      return content.substr(vs + 1, ve - vs - 1);
    };

    std::string type = extract("type");
    std::string url = extract("url");
    std::string param = extract("param");
    if (!type.empty())
      keys.insert(type + "|" + url + "|" + param);
    pos += 6;
  }
  return keys;
}

/// Compute diff: new findings not in baseline.
struct WatchDiff {
  std::vector<Finding> new_findings;
  std::vector<Finding> resolved; // in baseline but not in current
  int unchanged = 0;
};

inline WatchDiff compute_diff(const std::vector<Finding> &current,
                              const std::set<std::string> &baseline) {
  WatchDiff diff;
  std::set<std::string> current_keys;

  for (const auto &f : current) {
    std::string key = finding_key(f);
    current_keys.insert(key);
    if (baseline.find(key) == baseline.end())
      diff.new_findings.push_back(f);
    else
      ++diff.unchanged;
  }

  return diff;
}

} // namespace apex

#endif // APEX_CONFIDENCE_HPP
