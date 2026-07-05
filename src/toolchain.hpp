/// @file toolchain.hpp
/// @brief External tool detection and orchestration.
#ifndef APEX_TOOLCHAIN_HPP
#define APEX_TOOLCHAIN_HPP

#include "config.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// An external tool with its path and availability.
struct Tool {
  std::string name;
  std::string path; // Empty if not installed.
  std::string version;
  bool available = false;
};

/// Detect all external tools and report availability.
std::vector<Tool> detect_tools();

/// Print tool status table.
void print_tool_status(const std::vector<Tool> &tools);

/// Run httpx for fast subdomain probing (replaces built-in probe).
std::vector<std::string> run_httpx(const std::vector<std::string> &hosts);

/// Run katana for JS-aware crawling (replaces built-in crawler).
std::vector<std::string> run_katana(const std::string &target, int depth);

/// Run sqlmap on a confirmed SQLi finding for deep exploitation proof.
std::string run_sqlmap(const Finding &finding);

/// Run dalfox on a confirmed XSS finding for verification.
std::string run_dalfox(const Finding &finding);

/// Run ffuf for content discovery.
std::vector<std::string> run_ffuf(const std::string &base_url,
                                  const std::string &wordlist);

/// Run nuclei with specific templates on target.
std::vector<Finding> run_nuclei(const std::string &target,
                                const std::string &tags);

} // namespace apex

#endif // APEX_TOOLCHAIN_HPP
