/// @file tools.cpp
/// @brief External Tool Orchestration implementation.
#include "tools.hpp"

#include <array>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <future>
#include <iostream>
#include <mutex>
#include <thread>

namespace apex {
namespace {

/// Run a single tool with timeout.
ToolResult run_one(const ToolJob& job) {
  ToolResult result;
  result.name = job.name;

  auto start = std::chrono::steady_clock::now();

  // Build command with timeout wrapper
  std::string cmd = "timeout " + std::to_string(job.timeout_seconds) + "s " + job.command + " 2>/dev/null";

  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    result.error = "Failed to execute";
    result.exit_code = -1;
    return result;
  }

  // Read output (bounded to 256KB)
  std::string output;
  std::array<char, 4096> buffer;
  while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
    output += buffer.data();
    if (output.size() > 256 * 1024) break;  // Cap output
  }

  int status = pclose(pipe);
  result.exit_code = WEXITSTATUS(status);
  result.output = std::move(output);

  auto end = std::chrono::steady_clock::now();
  result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

  // Check if timed out (exit code 124 from timeout command)
  if (result.exit_code == 124) {
    result.timed_out = true;
    result.error = "Timed out after " + std::to_string(job.timeout_seconds) + "s";
  }

  return result;
}

}  // namespace

std::vector<ToolResult> run_tools_parallel(const std::vector<ToolJob>& jobs, int max_parallel) {
  if (max_parallel <= 0) max_parallel = jobs.size();

  std::vector<ToolResult> results;
  std::mutex results_mu;
  std::atomic<int> running{0};

  std::vector<std::future<void>> futures;

  for (const auto& job : jobs) {
    futures.push_back(std::async(std::launch::async, [&, job]() {
      // Simple concurrency limiter
      while (running.load() >= max_parallel) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
      }
      running++;
      auto result = run_one(job);
      running--;

      std::lock_guard<std::mutex> lock(results_mu);
      results.push_back(std::move(result));
    }));
  }

  // Wait for all to complete
  for (auto& f : futures) {
    f.get();
  }

  return results;
}

std::vector<ToolInfo> detect_external_tools() {
  struct ToolDef {
    std::string name;
    std::string binary;
    std::string version_flag;
  };

  std::vector<ToolDef> tools = {
      {"nuclei", "nuclei", "-version"},
      {"subfinder", "subfinder", "-version"},
      {"httpx", "httpx", "-version"},
      {"katana", "katana", "-version"},
      {"ffuf", "ffuf", "-V"},
      {"sqlmap", "sqlmap", "--version"},
      {"dalfox", "dalfox", "version"},
      {"nikto", "nikto", "-Version"},
      {"wapiti", "wapiti", "--version"},
      {"nmap", "nmap", "--version"},
      {"dig", "dig", "-v"},
      {"chromium", "chromium", "--version"},
  };

  std::vector<ToolInfo> results;

  for (const auto& t : tools) {
    ToolInfo info;
    info.name = t.name;

    // Check if binary exists
    std::string which_cmd = "which " + t.binary + " 2>/dev/null";
    FILE* pipe = popen(which_cmd.c_str(), "r");
    if (pipe) {
      char buf[256] = {};
      if (fgets(buf, sizeof(buf), pipe)) {
        std::string path(buf);
        if (!path.empty() && path[0] == '/') {
          path.erase(path.find_last_not_of("\n\r") + 1);
          info.path = path;
          info.available = true;
        }
      }
      pclose(pipe);
    }

    // Get version if available
    if (info.available && !t.version_flag.empty()) {
      std::string ver_cmd = t.binary + " " + t.version_flag + " 2>&1 | head -1";
      FILE* vpipe = popen(ver_cmd.c_str(), "r");
      if (vpipe) {
        char buf[256] = {};
        if (fgets(buf, sizeof(buf), vpipe)) {
          info.version = std::string(buf);
          info.version.erase(info.version.find_last_not_of("\n\r") + 1);
        }
        pclose(vpipe);
      }
    }

    results.push_back(info);
  }

  return results;
}

}  // namespace apex
