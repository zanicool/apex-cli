/// @file recon.cpp
/// @brief Reconnaissance: crt.sh subdomain enum + HTTP probing.
#include "recon.hpp"

#include <iostream>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

ReconResult run_recon(const Config& cfg, HttpClient& http) {
  ReconResult result;
  std::set<std::string> subs;

  // Passive: crt.sh certificate transparency.
  std::string crt_url = "https://crt.sh/?q=%25." + cfg.target + "&output=json";
  auto resp = http.get(crt_url);

  if (resp.status_code == 200 && !resp.body.empty()) {
    // Extract common_name values from JSON.
    std::regex name_re(R"x("common_name"\s*:\s*"([^"]+)")x");
    auto it = std::sregex_iterator(resp.body.begin(), resp.body.end(), name_re);
    auto it_end = std::sregex_iterator();
    for (; it != it_end; ++it) {
      std::string sub = (*it)[1].str();
      // Remove wildcard prefix.
      if (sub.size() > 2 && sub.substr(0, 2) == "*.") {
        sub = sub.substr(2);
      }
      subs.insert(sub);
    }
  }

  // Always include the target itself.
  subs.insert(cfg.target);

  result.subdomains.assign(subs.begin(), subs.end());
  std::cout << "  -> " << result.subdomains.size() << " subdomains\n";

  // Probe: check which subdomains are live.
  for (const auto& sub : result.subdomains) {
    std::string url = "https://" + sub;
    auto probe = http.get(url);
    if (probe.status_code > 0 && probe.error.empty()) {
      result.live_targets.push_back(url);
    } else {
      // Try HTTP fallback.
      url = "http://" + sub;
      probe = http.get(url);
      if (probe.status_code > 0 && probe.error.empty()) {
        result.live_targets.push_back(url);
      }
    }
  }

  std::cout << "  -> " << result.live_targets.size() << " live targets\n";

  // Passive: Wayback Machine historical URLs
  std::string wb_url = "https://web.archive.org/cdx/search/cdx?url=*." + cfg.target +
                        "/*&output=text&fl=original&collapse=urlkey&limit=200";
  auto wb_resp = http.get(wb_url);
  if (wb_resp.status_code == 200 && !wb_resp.body.empty()) {
    std::istringstream wb_stream(wb_resp.body);
    std::string line;
    std::set<std::string> wb_urls;
    while (std::getline(wb_stream, line)) {
      if (line.find("http") == 0) wb_urls.insert(line);
    }
    result.wayback_urls.assign(wb_urls.begin(), wb_urls.end());
    if (!result.wayback_urls.empty()) {
      std::cout << "  -> " << result.wayback_urls.size() << " Wayback URLs\n";
    }
  }

  return result;
}

}  // namespace apex
