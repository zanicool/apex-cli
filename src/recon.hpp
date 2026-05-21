/// @file recon.hpp
/// @brief Reconnaissance: subdomain enumeration and probing.
#ifndef APEX_RECON_HPP
#define APEX_RECON_HPP

#include "config.hpp"
#include "http.hpp"
#include <string>
#include <vector>

namespace apex {

/// Recon results.
struct ReconResult {
  std::vector<std::string> subdomains;
  std::vector<std::string> live_targets;
};

/// Run reconnaissance phase.
ReconResult run_recon(const Config &cfg, HttpClient &http);

} // namespace apex

#endif // APEX_RECON_HPP
