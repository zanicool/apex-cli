/// @file proc.hpp
/// @brief Safe subprocess execution without a shell.
///
/// All external-tool invocations (nuclei, sqlmap, chrome, zap) go through
/// these helpers. The command is run via fork() + execvp() with an explicit
/// argv array (no shell), so user-controlled data (e.g. the scan target) can
/// never be interpreted by a shell. This eliminates command-injection entirely
/// — a target like "example.com; rm -rf ~" is passed as a single literal
/// argv[] element.
#ifndef APEX_PROC_HPP
#define APEX_PROC_HPP

#include <string>
#include <vector>

namespace apex {

/// Result of running an external command.
struct ProcResult {
  int exit_code = -1;   ///< Process exit status (-1 if spawn failed).
  std::string stdout_data; ///< Captured standard output.
  bool spawned = false; ///< True if the process was launched at all.
};

/// Check whether a command exists on PATH (safe; no user data).
/// @param name Executable name, e.g. "nuclei".
bool command_exists(const std::string &name);

/// Run a command with an explicit argument vector (no shell).
/// @param argv Full argument list; argv[0] is the executable name/path.
/// @param timeout_secs Kill the process after this many seconds (0 = no limit).
/// @param capture_stdout If true, stdout is captured into the result.
/// @return ProcResult with exit code and (optionally) captured stdout.
ProcResult run_command(const std::vector<std::string> &argv,
                       int timeout_secs = 0, bool capture_stdout = false);

} // namespace apex

#endif // APEX_PROC_HPP
