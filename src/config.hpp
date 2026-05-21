/// @file config.hpp
/// @brief Configuration types for Apex CLI.
#ifndef APEX_CONFIG_HPP
#define APEX_CONFIG_HPP

#include <string>
#include <vector>

namespace apex {

/// Scan configuration parsed from CLI flags.
struct Config {
  std::string target;
  bool deep = false;
  double rate = 0.0;
  int threads = 100;
  int timeout = 10;
  std::string proxy;
  std::string output_dir;
  std::string report = "json,terminal";
  std::string scope;
  std::vector<std::string> skip;
  bool dry_run = false;
  std::string oob_server = "http://jarvis.local:9877";
  bool no_oob = false;
  int crawl_depth = 3;
  int max_urls = 500;
  bool osint_mode = false;  // Enable OSINT reconnaissance
  std::string ssh_target;   // SSH target (user@host) for agent-based scanning
  std::string ssh_key;      // SSH private key path
};

} // namespace apex

#endif // APEX_CONFIG_HPP
