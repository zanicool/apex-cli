/// @file tools.hpp
/// @brief External Tool Orchestration — parallel execution of external security tools.
#ifndef APEX_TOOLS_HPP
#define APEX_TOOLS_HPP

#include <functional>
#include <string>
#include <vector>

namespace apex {

/// Result of running an external tool.
struct ToolResult {
  std::string name;
  std::string output;
  int exit_code = -1;
  double duration_ms = 0;
  bool timed_out = false;
  bool skipped = false;    // Tool not installed
  std::string error;
};

/// Configuration for a tool job.
struct ToolJob {
  std::string name;
  std::string command;
  int timeout_seconds = 60;
  bool required = false;   // If true, failure is an error
};

/// Run multiple tools in parallel with resource management.
/// max_parallel: maximum concurrent tools (0 = all at once)
/// Returns results in completion order.
std::vector<ToolResult> run_tools_parallel(
    const std::vector<ToolJob> &jobs,
    int max_parallel = 4);

/// Check which tools are installed and their versions.
struct ToolInfo {
  std::string name;
  std::string path;
  std::string version;
  bool available = false;
};

std::vector<ToolInfo> detect_external_tools();

} // namespace apex

#endif // APEX_TOOLS_HPP
