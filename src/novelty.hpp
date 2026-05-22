/// @file novelty.hpp
/// @brief Novelty scoring + HackerOne duplicate risk assessment.
///
/// Helps avoid submitting findings that are likely duplicates on bug bounty
/// platforms by scoring how "novel" a finding is.
///
/// Factors:
///   - Vuln type commonality (XSS on search = very common = likely dupe)
///   - Endpoint predictability (/.env, /admin = everyone finds these)
///   - Evidence uniqueness (generic vs specific)
///   - Program disclosure history (hacktivity check)
#ifndef APEX_NOVELTY_HPP
#define APEX_NOVELTY_HPP

#include "http.hpp"
#include "scanner.hpp"
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace apex {

/// Novelty level for a finding.
enum class Novelty {
  High = 3,   // Likely unique — submit
  Medium = 2, // Possibly unique — check hacktivity first
  Low = 1,    // Likely duplicate — probably already reported
};

inline const char *novelty_str(Novelty n) {
  switch (n) {
  case Novelty::High: return "HIGH (likely unique)";
  case Novelty::Medium: return "MEDIUM (check hacktivity)";
  case Novelty::Low: return "LOW (likely duplicate)";
  }
  return "?";
}

inline const char *novelty_icon(Novelty n) {
  switch (n) {
  case Novelty::High: return "🟢";
  case Novelty::Medium: return "🟡";
  case Novelty::Low: return "🔴";
  }
  return "?";
}

/// Common endpoints that everyone scans — findings here are almost always dupes.
inline bool is_common_endpoint(const std::string &url) {
  static const std::vector<std::string> common = {
      "/.env", "/.git/config", "/admin", "/login", "/wp-admin",
      "/wp-login.php", "/phpinfo.php", "/.DS_Store", "/server-status",
      "/swagger.json", "/openapi.json", "/graphql", "/api/v1",
      "/robots.txt", "/.well-known", "/sitemap.xml", "/crossdomain.xml",
      "/elmah.axd", "/trace.axd", "/actuator", "/actuator/health",
      "/debug", "/console", "/.htaccess", "/backup", "/config",
      "/wp-json", "/xmlrpc.php", "/readme.html",
  };
  for (const auto &c : common) {
    if (url.find(c) != std::string::npos) return true;
  }
  return false;
}

/// Vuln types that are extremely commonly reported (high dupe risk).
inline int type_commonality(const std::string &type) {
  // Score 1-10: higher = more commonly reported = higher dupe risk
  static const std::map<std::string, int> scores = {
      {"Missing Header", 10},
      {"Clickjacking", 9},
      {"Cookie Security", 9},
      {"Server Banner Disclosure", 9},
      {"Info Disclosure", 8},
      {"CORS", 7},
      {"CORS Misconfiguration", 7},
      {"Open Redirect", 7},
      {"XSS", 6},          // common but depends on endpoint
      {"CSRF", 6},
      {"SQLi", 5},         // less common = more valuable
      {"SSRF", 4},
      {"SSTI", 3},
      {"CMDi", 3},
      {"IDOR", 4},
      {"NoSQL Injection", 3},
      {"XXE", 3},
      {"LFI", 4},
      {"JWT None Alg", 4},
      {"Secrets Exposure", 3},
      {"RCE", 2},
      {"Auth Bypass", 2},
      {"Prototype Pollution", 3},
  };
  auto it = scores.find(type);
  return it != scores.end() ? it->second : 5;
}

/// Score novelty of a single finding.
inline Novelty score_novelty(const Finding &f) {
  int dupe_risk = 0;

  // Factor 1: type commonality
  int commonality = type_commonality(f.type);
  dupe_risk += commonality;

  // Factor 2: endpoint predictability
  if (is_common_endpoint(f.url)) dupe_risk += 4;

  // Factor 3: severity (low sev = more likely already reported and ignored)
  if (f.severity == "low" || f.severity == "info") dupe_risk += 3;

  // Factor 4: generic vs specific evidence
  if (f.evidence.empty() && f.payload.empty()) dupe_risk += 2;

  // Factor 5: parameter specificity
  if (f.param.empty() || f.param == "id" || f.param == "q" ||
      f.param == "search" || f.param == "url")
    dupe_risk += 1;

  // Reduce risk for complex/chained findings
  if (f.type.find("Blind") != std::string::npos) dupe_risk -= 2;
  if (f.type.find("Second Order") != std::string::npos) dupe_risk -= 3;
  if (f.type.find("Race") != std::string::npos) dupe_risk -= 2;

  // Classify
  if (dupe_risk >= 12) return Novelty::Low;
  if (dupe_risk >= 7) return Novelty::Medium;
  return Novelty::High;
}

/// Check HackerOne hacktivity for similar disclosed reports.
struct HacktivityMatch {
  std::string title;
  std::string url;
  std::string severity;
  std::string disclosed_at;
};

inline std::vector<HacktivityMatch>
check_hacktivity(HttpClient &http, const std::string &program,
                 const std::string &vuln_type) {
  std::vector<HacktivityMatch> matches;

  // HackerOne hacktivity search via public GraphQL
  std::string query = R"({"query":"query { hacktivity_items(first:10, )"
                      R"(where:{report:{disclosed:true, severity:{rating:{}}, )"
                      R"(team:{handle:{_eq:\")" +
                      program +
                      R"(\"}}}}) { edges { node { ... on HacktivityItemInterface )"
                      R"({ id, votes { total_count }, report { title, url, )"
                      R"(severity_rating, disclosed_at }}}}}}"})";

  // Fallback: search via public hacktivity page scraping
  std::string search_url = "https://hackerone.com/hacktivity?queryString=" +
                           vuln_type + "+program:" + program +
                           "&sortField=latest_disclosable_activity_at&filter=type:public";

  auto resp = http.get(search_url);
  if (resp.status_code != 200) return matches;

  // Parse titles from response (simplified)
  size_t pos = 0;
  while ((pos = resp.body.find("\"title\":\"", pos)) != std::string::npos) {
    pos += 9;
    size_t end = resp.body.find("\"", pos);
    if (end == std::string::npos) break;
    std::string title = resp.body.substr(pos, end - pos);
    if (title.find(vuln_type) != std::string::npos ||
        title.find("XSS") != std::string::npos ||
        title.find("SQL") != std::string::npos) {
      matches.push_back({title, "", "", ""});
    }
    if (matches.size() >= 5) break;
  }

  return matches;
}

/// Full novelty report for all findings.
struct NoveltyReport {
  std::vector<std::pair<Finding, Novelty>> scored;
  int high_novelty = 0;
  int medium_novelty = 0;
  int low_novelty = 0;
};

inline NoveltyReport assess_novelty(const std::vector<Finding> &findings) {
  NoveltyReport report;
  for (const auto &f : findings) {
    auto n = score_novelty(f);
    report.scored.push_back({f, n});
    switch (n) {
    case Novelty::High: ++report.high_novelty; break;
    case Novelty::Medium: ++report.medium_novelty; break;
    case Novelty::Low: ++report.low_novelty; break;
    }
  }
  // Sort: high novelty first
  std::sort(report.scored.begin(), report.scored.end(),
            [](const auto &a, const auto &b) {
              return static_cast<int>(a.second) > static_cast<int>(b.second);
            });
  return report;
}

/// Filter findings to only those worth reporting (medium+ novelty).
inline std::vector<Finding>
filter_reportable(const std::vector<Finding> &findings, int min_novelty = 2) {
  std::vector<Finding> result;
  for (const auto &f : findings) {
    if (static_cast<int>(score_novelty(f)) >= min_novelty)
      result.push_back(f);
  }
  return result;
}

} // namespace apex

#endif // APEX_NOVELTY_HPP
