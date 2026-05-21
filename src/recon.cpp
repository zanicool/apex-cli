/// @file recon.cpp
/// @brief Reconnaissance: crt.sh subdomain enum + HTTP probing.
#include "recon.hpp"
#include <iostream>
#include <regex>
#include <set>

namespace apex {

ReconResult run_recon(const Config &cfg, HttpClient &http) {
  ReconResult result;
  std::set<std::string> subs;

  // Passive: crt.sh certificate transparency.
  std::string crt_url =
      "https://crt.sh/?q=%25." + cfg.target + "&output=json";
  auto resp = http.get(crt_url);

  if (resp.status_code == 200 && !resp.body.empty()) {
    // Extract common_name values from JSON.
    std::regex name_re(R"x("common_name"\s*:\s*"([^"]+)")x");
    auto it = std::sregex_iterator(resp.body.begin(), resp.body.end(),
                                   name_re);
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
  for (const auto &sub : result.subdomains) {
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
  return result;
}

} // namespace apex
