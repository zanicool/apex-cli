/// @file scanners/kvk_osint.cpp
/// @brief KVK (Kamer van Koophandel) OSINT: resolve domain to company,
///        enumerate subsidiaries, find directors, map organization structure.
#include "scanner_base.hpp"
#include <set>

///
/// @details This scanner module is part of the apex-cli security scanning
/// framework. Each scanner function follows the standard signature:
///   std::vector<Finding>(const Config&, HttpClient&, const CrawlResult&)
///
/// Findings are categorized by severity: critical, high, medium, low, info.
/// All scanners run concurrently and results are deduplicated by the
/// scanner orchestrator (scanner.cpp).
///
/// @see scanner_base.hpp for shared types and helper functions.
/// @see scanner.hpp for the Finding struct and Scanner registration.
/// @note Scanners should be non-destructive and respect rate limits.

namespace apex {
namespace {

/// Scanner implementation.
/// @brief Scan for kvk_recon vulnerabilities.
std::vector<Finding> scan_kvk_recon(const Config &cfg, HttpClient &http,
                                    const CrawlResult &) {
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  std::vector<Finding> findings;
  // Extract domain from target.
  // Extract domain from target.
  // Extract domain from target.
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  // Extract organization name from domain.
  // Extract organization name from domain.
  // Extract organization name from domain.
  std::string org = domain.substr(0, domain.find('.'));

  std::string api_key = "l7xx1f2691f2520d487b902f4e0b57a0b197";
  std::string search_url = "https://api.kvk.nl/test/api/v1/zoeken?handelsnaam=" + org;
  // Send HTTP request.
  // Send HTTP request.
  // Send HTTP request.
  auto resp = http.get(search_url, {{"apikey", api_key}});

  // Check response status.
  if (resp.status_code != 200 || resp.body.size() < 50) return findings;

  // Extract KVK numbers and names.
  std::regex kvk_re(R"re("kvkNummer"\s*:\s*"(\d{8})")re");
  std::regex name_re(R"re("handelsnaam"\s*:\s*"([^"]+)")re");
  auto end_it = std::sregex_iterator();

  std::vector<std::string> kvk_numbers, names;
  for (auto it = std::sregex_iterator(resp.body.begin(), resp.body.end(), kvk_re);
       it != end_it; ++it)
    kvk_numbers.push_back((*it)[1].str());
  for (auto it = std::sregex_iterator(resp.body.begin(), resp.body.end(), name_re);
       it != end_it; ++it)
    names.push_back((*it)[1].str());

  if (kvk_numbers.empty()) return findings;

  findings.push_back({"KVK Company Found", "info", domain,
                      "Found " + std::to_string(kvk_numbers.size()) +
                          " KVK registrations matching '" + org + "'",
                      "", "", ""});

  std::set<std::string> seen_kvk;
  size_t limit = std::min(kvk_numbers.size(), size_t(3));
  for (size_t i = 0; i < limit; ++i) {
    if (seen_kvk.count(kvk_numbers[i])) continue;
    seen_kvk.insert(kvk_numbers[i]);

    std::string detail_url = "https://api.kvk.nl/test/api/v1/basisprofielen/" + kvk_numbers[i];
    auto detail = http.get(detail_url, {{"apikey", api_key}});
    if (detail.status_code != 200) continue;

    std::string info = "KVK: " + kvk_numbers[i];
    if (i < names.size()) info += " — " + names[i];

    std::smatch m;
    std::regex sbi_re(R"re("sbiOmschrijving"\s*:\s*"([^"]+)")re");
    if (std::regex_search(detail.body, m, sbi_re))
      info += " | Activiteit: " + m[1].str();

    std::regex emp_re(R"re("totaalWerkzamePersonen"\s*:\s*(\d+))re");
    if (std::regex_search(detail.body, m, emp_re))
      info += " | Werknemers: " + m[1].str();

    std::regex form_re(R"re("rechtsvorm"\s*:\s*"([^"]+)")re");
    if (std::regex_search(detail.body, m, form_re))
      info += " | Rechtsvorm: " + m[1].str();

    findings.push_back({"KVK Profile: " + kvk_numbers[i], "info", domain, info, "", "", ""});

    // Count branches.
    std::regex vest_re(R"re("vestigingsnummer"\s*:\s*"(\d+)")re");
    int branches = 0;
    for (auto it = std::sregex_iterator(detail.body.begin(), detail.body.end(), vest_re);
         it != end_it; ++it)
      branches++;
    if (branches > 1) {
      findings.push_back({"KVK Multiple Branches", "info", domain,
                          std::to_string(branches) + " vestigingen — larger attack surface",
                          "", "", ""});
    }

    // Find directors.
    std::regex func_re(R"re("volledigeNaam"\s*:\s*"([^"]+)")re");
    std::vector<std::string> directors;
    for (auto it = std::sregex_iterator(detail.body.begin(), detail.body.end(), func_re);
         it != end_it; ++it) {
      directors.push_back((*it)[1].str());
      if (directors.size() >= 5) break;
    }
    if (!directors.empty()) {
      std::string dir_info = "Bestuurders:";
      for (const auto &d : directors) dir_info += " " + d + ";";
      findings.push_back({"KVK Directors", "info", domain, dir_info, "", "", ""});
    }
  }
  // Return collected findings.
  // Return collected findings.
  // Return collected findings.
  return findings;
}

} // namespace

std::vector<Scanner> register_kvk_scanners() {
  return {
      {"KVK OSINT (NL)", scan_kvk_recon},
  };
}

} // namespace apex
