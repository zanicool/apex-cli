/// @file toolchain.cpp
/// @brief External tool detection and orchestration implementation.
#include "toolchain.hpp"
#include <array>
#include <cstdio>
#include <iostream>
#include <sstream>

namespace apex {

namespace {

/// Run a command and capture stdout.
std::string exec_cmd(const std::string &cmd, int timeout_sec = 30) {
  std::string full =
      "timeout " + std::to_string(timeout_sec) + " " + cmd + " 2>/dev/null";
  FILE *pipe = popen(full.c_str(), "r");
  if (!pipe)
    return "";
  std::string result;
  char buf[4096];
  while (fgets(buf, sizeof(buf), pipe))
    result += buf;
  pclose(pipe);
  return result;
}

/// Check if a tool exists and get its path.
Tool check_tool(const std::string &name) {
  Tool t;
  t.name = name;
  std::string path = exec_cmd("which " + name, 5);
  if (!path.empty() && path[0] == '/') {
    path.erase(path.find_last_not_of("\n\r") + 1);
    t.path = path;
    t.available = true;
    // Get version.
    std::string ver = exec_cmd(name + " --version 2>/dev/null | head -1", 5);
    if (!ver.empty()) {
      ver.erase(ver.find_last_not_of("\n\r") + 1);
      t.version = ver;
    }
  }
  return t;
}

} // namespace

std::vector<Tool> detect_tools() {
  const std::vector<std::string> names = {
      "nuclei", "httpx", "katana", "subfinder",    "ffuf",   "sqlmap",
      "dalfox", "nikto", "wapiti", "schemathesis", "zap.sh", "zap-cli"};
  std::vector<Tool> tools;
  for (const auto &name : names) {
    tools.push_back(check_tool(name));
  }
  return tools;
}

void print_tool_status(const std::vector<Tool> &tools) {
  std::cout << "\n  External tools:\n";
  for (const auto &t : tools) {
    if (t.available)
      std::cout << "    ✓ " << t.name << " (" << t.version << ")\n";
    else
      std::cout << "    ✗ " << t.name << " (not installed)\n";
  }
  std::cout << "    Run: scripts/install-tools.sh to install missing tools\n";
}

std::vector<std::string> run_httpx(const std::vector<std::string> &hosts) {
  if (hosts.empty())
    return {};
  // Write hosts to temp file.
  std::string tmp = "/tmp/apex_httpx_in.txt";
  FILE *f = fopen(tmp.c_str(), "w");
  if (!f)
    return {};
  for (const auto &h : hosts)
    fprintf(f, "%s\n", h.c_str());
  fclose(f);

  std::string out =
      exec_cmd("cat " + tmp + " | httpx -silent -status-code -no-color", 30);
  std::vector<std::string> live;
  std::istringstream stream(out);
  std::string line;
  while (std::getline(stream, line)) {
    // httpx outputs: url [status]
    size_t space = line.find(' ');
    std::string url =
        (space != std::string::npos) ? line.substr(0, space) : line;
    if (!url.empty())
      live.push_back(url);
  }
  return live;
}

std::vector<std::string> run_katana(const std::string &target, int depth) {
  std::string cmd = "katana -u https://" + target + " -d " +
                    std::to_string(depth) + " -silent -no-color -jc";
  std::string out = exec_cmd(cmd, 60);
  std::vector<std::string> urls;
  std::istringstream stream(out);
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty() && line.find("http") == 0)
      urls.push_back(line);
  }
  return urls;
}

std::string run_sqlmap(const Finding &finding) {
  if (finding.url.empty() || finding.param.empty())
    return "";
  std::string target_url = finding.url;
  if (!finding.param.empty())
    target_url += "?" + finding.param + "=1";
  std::string cmd = "sqlmap -u '" + target_url + "' -p '" + finding.param +
                    "' --batch --level=1 --risk=1 --threads=4 --timeout=10"
                    " --output-dir=/tmp/apex_sqlmap 2>/dev/null | tail -20";
  return exec_cmd(cmd, 60);
}

std::string run_dalfox(const Finding &finding) {
  if (finding.url.empty())
    return "";
  std::string target_url = finding.url;
  if (!finding.param.empty())
    target_url += "?" + finding.param + "=FUZZ";
  std::string cmd =
      "dalfox url '" + target_url + "' --silence 2>/dev/null | head -10";
  return exec_cmd(cmd, 30);
}

std::vector<std::string> run_ffuf(const std::string &base_url,
                                  const std::string &wordlist) {
  std::string cmd = "ffuf -u '" + base_url + "/FUZZ' -w " + wordlist +
                    " -mc 200,301,302,403 -s 2>/dev/null";
  std::string out = exec_cmd(cmd, 60);
  std::vector<std::string> paths;
  std::istringstream stream(out);
  std::string line;
  while (std::getline(stream, line)) {
    if (!line.empty())
      paths.push_back(line);
  }
  return paths;
}

std::vector<Finding> run_nuclei(const std::string &target,
                                const std::string &tags) {
  std::string cmd =
      "nuclei -u https://" + target + " -tags " + tags +
      " -severity critical,high,medium -jsonl -silent 2>/dev/null";
  std::string out = exec_cmd(cmd, 120);
  std::vector<Finding> findings;
  std::istringstream stream(out);
  std::string line;
  while (std::getline(stream, line)) {
    // Parse nuclei JSONL output.
    Finding f;
    f.type = "Nuclei";
    // Extract template-id and matched-at.
    size_t tid = line.find("\"template-id\":\"");
    if (tid != std::string::npos) {
      tid += 15;
      size_t end = line.find("\"", tid);
      f.detail = line.substr(tid, end - tid);
    }
    size_t mat = line.find("\"matched-at\":\"");
    if (mat != std::string::npos) {
      mat += 14;
      size_t end = line.find("\"", mat);
      f.url = line.substr(mat, end - mat);
    }
    size_t sev = line.find("\"severity\":\"");
    if (sev != std::string::npos) {
      sev += 12;
      size_t end = line.find("\"", sev);
      f.severity = line.substr(sev, end - sev);
    }
    if (!f.url.empty())
      findings.push_back(f);
  }
  return findings;
}

} // namespace apex
