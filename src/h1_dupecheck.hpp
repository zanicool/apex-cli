/// @file h1_dupecheck.hpp
/// @brief Scrape HackerOne hacktivity to check if a finding is already
/// disclosed. Uses libcurl to fetch the hacktivity page and regex to extract
/// report titles.
#ifndef APEX_H1_DUPECHECK_HPP
#define APEX_H1_DUPECHECK_HPP

#include "http.hpp"
#include <algorithm>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

namespace apex {

struct DisclosedReport {
  std::string title;
  std::string url;
};

/// Fetch disclosed reports from H1 hacktivity for a program.
inline std::vector<DisclosedReport>
fetch_hacktivity(HttpClient &http, const std::string &program) {
  std::vector<DisclosedReport> reports;

  // Fetch the hacktivity overview page with disclosed filter
  std::string url = "https://hackerone.com/hacktivity/overview?queryString="
                    "disclosed%3Atrue%20program%3A" +
                    program;

  auto resp =
      http.get(url, {{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) "
                                    "AppleWebKit/537.36 Chrome/120.0.0.0"},
                     {"Accept", "text/html"}});

  if (resp.status_code != 200 || resp.body.empty())
    return reports;

  // Extract report titles from HTML
  // Pattern: visible text that looks like vulnerability titles
  std::vector<std::string> vuln_keywords = {
      "xss",         "sql",        "ssrf",      "idor",      "cors",
      "redirect",    "injection",  "bypass",    "takeover",  "leak",
      "expos",       "graphql",    "rce",       "csrf",      "ssti",
      "lfi",         "upload",     "race",      "privilege", "auth",
      "token",       "password",   "session",   "cookie",    "misconfigur",
      "information", "disclosure", "subdomain", "bucket",    "endpoint",
      "api",         "overflow",   "traversal", "smuggling", "deserialization"};

  // Extract text between > and < that starts with uppercase
  std::regex title_re(">([A-Z][^<]{10,150})<");
  auto begin =
      std::sregex_iterator(resp.body.begin(), resp.body.end(), title_re);
  auto end = std::sregex_iterator();

  std::set<std::string> seen;
  for (auto it = begin; it != end; ++it) {
    std::string title = (*it)[1].str();
    // Trim
    while (!title.empty() && (title.back() == ' ' || title.back() == '\n'))
      title.pop_back();

    if (title.size() < 12 || seen.count(title))
      continue;

    // Check if it contains a vuln keyword
    std::string lower = title;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    for (const auto &kw : vuln_keywords) {
      if (lower.find(kw) != std::string::npos) {
        seen.insert(title);
        reports.push_back({title, ""});
        break;
      }
    }
  }

  // Also extract from JSON embedded in page
  std::regex json_re("\"title\":\"([^\"]{10,150})\"");
  begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), json_re);
  for (auto it = begin; it != end; ++it) {
    std::string title = (*it)[1].str();
    if (seen.count(title))
      continue;
    std::string lower = title;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto &kw : vuln_keywords) {
      if (lower.find(kw) != std::string::npos) {
        seen.insert(title);
        reports.push_back({title, ""});
        break;
      }
    }
  }

  return reports;
}

/// Check if a finding matches any disclosed report.
/// Returns: pair<is_dupe, matching_titles>
inline std::pair<bool, std::vector<std::string>>
check_h1_dupe(HttpClient &http, const std::string &program,
              const std::string &finding_type, const std::string &target) {
  auto reports = fetch_hacktivity(http, program);
  std::vector<std::string> matches;

  if (reports.empty())
    return {false, matches};

  // Tokenize our finding
  std::string search = finding_type + " " + target;
  std::transform(search.begin(), search.end(), search.begin(), ::tolower);

  std::vector<std::string> words;
  std::string word;
  for (char c : search) {
    if (c == ' ' || c == '/' || c == '.' || c == '-') {
      if (word.size() > 3)
        words.push_back(word);
      word.clear();
    } else {
      word += c;
    }
  }
  if (word.size() > 3)
    words.push_back(word);

  // Match against disclosed reports
  for (const auto &report : reports) {
    std::string lower = report.title;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    int match_count = 0;
    for (const auto &w : words) {
      if (lower.find(w) != std::string::npos)
        match_count++;
    }
    if (match_count >= 2)
      matches.push_back(report.title);
  }

  return {!matches.empty(), matches};
}

/// Print dupe check results.
inline void print_dupe_check(const std::string &program,
                             const std::string &finding, HttpClient &http) {
  std::cout << "\n🔍 Checking H1 hacktivity for: " << program << "\n";
  std::cout << "   Finding: " << finding << "\n\n";

  auto reports = fetch_hacktivity(http, program);

  if (reports.empty()) {
    std::cout << "   ⚠️  No disclosed reports found for '" << program << "'\n";
    std::cout << "   Cannot verify — program may not disclose reports.\n\n";
    return;
  }

  std::cout << "   📋 " << reports.size() << " disclosed reports found.\n\n";

  auto [is_dupe, matches] = check_h1_dupe(http, program, finding, "");

  if (is_dupe) {
    std::cout << "   🔴 LIKELY DUPLICATE — " << matches.size()
              << " similar report(s):\n";
    for (const auto &m : matches)
      std::cout << "      → " << m.substr(0, 90) << "\n";
    std::cout << "\n   💡 Don't submit.\n";
  } else {
    std::cout << "   🟢 NO MATCH in disclosed reports.\n";
    std::cout << "   💡 Looks unique (but undisclosed dupes still possible).\n";
  }
  std::cout << "\n";
}

} // namespace apex

#endif // APEX_H1_DUPECHECK_HPP
