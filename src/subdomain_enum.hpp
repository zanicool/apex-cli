#pragma once
/// @file subdomain_enum.hpp
/// @brief Subdomain Enumeration Engine — DNS brute-force + CT logs.
#ifndef APEX_SUBDOMAIN_ENUM2_HPP
#define APEX_SUBDOMAIN_ENUM2_HPP

#include "http.hpp"
#include "scanner.hpp"
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace apex {

/// Query Certificate Transparency logs via crt.sh for subdomain enumeration
inline std::set<std::string> enumerate_subdomains_ct(HttpClient &http,
                                                     const std::string &domain) {
  std::set<std::string> subdomains;
  std::string url = "https://crt.sh/?q=%25." + domain + "&output=json";
  auto resp = http.get(url);
  if (resp.status_code != 200 || resp.body.empty())
    return subdomains;
  std::regex name_re(R"("name_value"\s*:\s*"([^"]+))");
  auto begin =
      std::sregex_iterator(resp.body.begin(), resp.body.end(), name_re);
  for (auto it = begin; it != std::sregex_iterator(); ++it) {
    std::string name = (*it)[1].str();
    std::istringstream ss(name);
    std::string line;
    while (std::getline(ss, line, '\n')) {
      if (line.empty() || line[0] == '*')
        continue;
      if (line.find(domain) != std::string::npos)
        subdomains.insert(line);
    }
  }
  return subdomains;
}

/// Query Wayback Machine for historical URLs
inline std::vector<std::string>
enumerate_wayback_urls(HttpClient &http, const std::string &domain) {
  std::vector<std::string> urls;
  std::string url = "https://web.archive.org/cdx/search/cdx?url=*." + domain +
                    "/*&output=text&fl=original&collapse=urlkey&limit=500";
  auto resp = http.get(url);
  if (resp.status_code != 200 || resp.body.empty())
    return urls;
  std::istringstream ss(resp.body);
  std::string line;
  while (std::getline(ss, line)) {
    if (!line.empty() && line.find("http") == 0)
      urls.push_back(line);
  }
  return urls;
}

/// Full subdomain enumeration engine with DNS brute-force, CT log lookup,
/// and subdomain takeover detection.
class SubdomainEnum {
public:
  /// Enumerate subdomains for the given domain.
  std::vector<Finding> enumerate(const std::string &domain, HttpClient &http);

private:
  static std::vector<std::string> get_prefixes();
  std::set<std::string> brute_force_dns(const std::string &domain,
                                        HttpClient &http);
  std::set<std::string> ct_log_lookup(const std::string &domain,
                                      HttpClient &http);
  std::vector<Finding> check_takeover(const std::string &subdomain,
                                      HttpClient &http);
  bool resolves(const std::string &hostname, HttpClient &http);
};

} // namespace apex

#endif // APEX_SUBDOMAIN_ENUM2_HPP
