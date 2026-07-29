/// @file nuclei_runner.cpp
/// @brief Nuclei template integration: runs nuclei and parses JSON output.
#include "nuclei_runner.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <regex>
#include <sstream>

namespace apex {

const std::vector<std::string> NucleiRunner::template_dirs_ = {
    "cves/", "exposures/", "misconfiguration/", "vulnerabilities/",
    "default-logins/", "takeovers/"};

NucleiRunner::NucleiRunner(const Config &cfg) : cfg_(cfg) {
  nuclei_path_ = find_nuclei_binary();
}

bool NucleiRunner::is_available() const { return !nuclei_path_.empty(); }

std::vector<Finding> NucleiRunner::run(const std::string &target) {
  std::vector<Finding> findings;

  if (!is_available()) return findings;

  // Run nuclei with focused template directories
  for (const auto &tmpl_dir : template_dirs_) {
    std::string output = execute_nuclei(target, tmpl_dir);
    if (output.empty()) continue;

    auto results = parse_json_output(output);
    for (const auto &result : results) {
      findings.push_back(to_finding(result));
    }
  }

  return findings;
}

std::string NucleiRunner::find_nuclei_binary() const {
  // Check common paths
  std::vector<std::string> paths = {
      "/usr/local/bin/nuclei", "/usr/bin/nuclei",
      std::string(std::getenv("HOME") ? std::getenv("HOME") : "") +
          "/go/bin/nuclei",
      std::string(std::getenv("HOME") ? std::getenv("HOME") : "") +
          "/.local/bin/nuclei"};

  for (const auto &path : paths) {
    if (!path.empty() && std::filesystem::exists(path)) {
      return path;
    }
  }

  // Try which command
  std::array<char, 256> buffer;
  std::string result;
  FILE *pipe = popen("which nuclei 2>/dev/null", "r");
  if (pipe) {
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
      result += buffer.data();
    }
    pclose(pipe);
    // Trim whitespace
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
      result.pop_back();
    if (!result.empty() && std::filesystem::exists(result)) {
      return result;
    }
  }

  return "";
}

std::string NucleiRunner::execute_nuclei(const std::string &target,
                                         const std::string &template_dir) {
  if (nuclei_path_.empty()) return "";

  // Build nuclei command with safety limits
  int rate_limit = cfg_.rate_limit > 0 ? cfg_.rate_limit : 100;
  int timeout_val = cfg_.timeout > 0 ? cfg_.timeout * 3 : 30;

  std::string cmd = nuclei_path_ + " -u " + target + " -t " + template_dir +
                    " -json" + " -silent" + " -rate-limit " +
                    std::to_string(rate_limit) + " -timeout " +
                    std::to_string(timeout_val) +
                    " -no-color" + " -no-interactsh" +
                    " 2>/dev/null";

  // Execute with overall timeout
  std::string full_cmd =
      "timeout " + std::to_string(timeout_val * 2) + " " + cmd;

  std::array<char, 4096> buffer;
  std::string output;
  FILE *pipe = popen(full_cmd.c_str(), "r");
  if (!pipe) return "";

  while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
    output += buffer.data();
    // Safety: limit output size
    if (output.size() > 1024 * 1024) break;
  }
  pclose(pipe);

  return output;
}

std::vector<NucleiRunner::NucleiResult>
NucleiRunner::parse_json_output(const std::string &output) {
  std::vector<NucleiResult> results;

  // Each line is a JSON object
  std::istringstream stream(output);
  std::string line;

  // Simple JSON field extraction regex patterns
  static const std::regex template_id_re(R"re("template-id"\s*:\s*"([^"]+)")re");
  static const std::regex name_re(R"re("name"\s*:\s*"([^"]+)")re");
  static const std::regex severity_re(R"re("severity"\s*:\s*"([^"]+)")re");
  static const std::regex matched_url_re(R"re("matched-at"\s*:\s*"([^"]+)")re");
  static const std::regex extracted_re(
      R"re("extracted-results"\s*:\s*\["([^"]*)")re");
  static const std::regex desc_re(R"re("description"\s*:\s*"([^"]*)")re");
  static const std::regex ref_re(R"re("reference"\s*:\s*\["([^"]*)")re");
  while (std::getline(stream, line)) {
    if (line.empty() || line[0] != '{') continue;

    NucleiResult result;
    std::smatch m;

    if (std::regex_search(line, m, template_id_re))
      result.template_id = m[1].str();
    if (std::regex_search(line, m, name_re)) result.name = m[1].str();
    if (std::regex_search(line, m, severity_re)) result.severity = m[1].str();
    if (std::regex_search(line, m, matched_url_re))
      result.matched_url = m[1].str();
    if (std::regex_search(line, m, extracted_re))
      result.extracted_results = m[1].str();
    if (std::regex_search(line, m, desc_re)) result.description = m[1].str();
    if (std::regex_search(line, m, ref_re)) result.reference = m[1].str();

    if (!result.template_id.empty()) {
      results.push_back(result);
    }
  }

  return results;
}

Finding NucleiRunner::to_finding(const NucleiResult &result) {
  Finding f;
  f.type = "Nuclei: " + result.name;

  // Map nuclei severity to our severity levels
  if (result.severity == "critical")
    f.severity = "critical";
  else if (result.severity == "high")
    f.severity = "high";
  else if (result.severity == "medium")
    f.severity = "medium";
  else if (result.severity == "low")
    f.severity = "low";
  else
    f.severity = "info";

  f.url = result.matched_url;
  f.detail = result.description.empty()
                 ? ("Nuclei template " + result.template_id + " matched")
                 : result.description;
  f.evidence = result.extracted_results;
  f.payload = result.template_id;

  // Set CVSS based on severity
  if (f.severity == "critical")
    f.cvss_score = 9.5;
  else if (f.severity == "high")
    f.cvss_score = 7.5;
  else if (f.severity == "medium")
    f.cvss_score = 5.0;
  else if (f.severity == "low")
    f.cvss_score = 3.0;
  else
    f.cvss_score = 0.0;

  f.confidence = 85; // Nuclei templates are generally reliable
  f.owasp_category = "A06:2021 Vulnerable and Outdated Components";

  return f;
}

} // namespace apex
