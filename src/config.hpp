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
  std::string install_dir = "."; // Path to apex-cli installation (for scripts/)
  std::string report = "json,terminal";
  std::string scope;
  std::vector<std::string> skip;
  bool dry_run = false;
  std::string oob_server = "http://jarvis.local:9877";
  bool no_oob = false;
  int rate_limit = 0;          // Max requests per second (0 = unlimited)
  std::string custom_ua;       // Custom User-Agent header
  int crawl_depth = 3;
  int max_urls = 500;
  bool osint_mode = false;    // Enable OSINT reconnaissance
  bool quick = false;         // Quick mode: only high-value scanners
  bool smart = false;         // Smart mode: crawl-first scanner selection
  bool watch = false;         // Watch mode: continuous monitoring
  int watch_interval = 3600;  // Watch interval in seconds (default 1h)
  std::string watch_baseline; // Path to previous scan for diff
  int confidence_min = 0;     // Min confidence to report (0=all, 1=possible,
                              // 2=probable, 3=confirmed)
  bool bounty = false;        // Bug bounty mode: novelty scoring + dupe risk
  bool pipeline =
      false; // Full pipeline: recon → smart → deep → novelty → report
  std::string h1_program; // HackerOne program handle for hacktivity check
  std::string wf_api_key; // Wordfence Intelligence API key
  std::string ssh_target; // SSH target (user@host) for agent-based scanning
  std::string ssh_key;    // SSH private key path
  bool chain = false; // Chain executor: escalate findings into full exploits

  // Authentication
  std::string auth_cookie; // Cookie header value for authenticated scanning
  std::string auth_header; // Custom auth header (e.g. "Bearer token123")
  std::string auth_basic;  // Basic auth (user:pass)
  std::string login_user;  // Username/email for auto-login
  std::string login_pass;  // Password for auto-login
};

} // namespace apex

#endif // APEX_CONFIG_HPP
