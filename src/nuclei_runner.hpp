#pragma once
/// @file nuclei_runner.hpp
/// @brief Nuclei template integration for automated vulnerability scanning.
#ifndef APEX_NUCLEI_RUNNER_HPP
#define APEX_NUCLEI_RUNNER_HPP

#include "config.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Integrates with the Nuclei vulnerability scanner binary,
/// running focused templates and parsing results into Findings.
class NucleiRunner {
public:
  explicit NucleiRunner(const Config &cfg);

  /// Run nuclei against the target and return parsed findings.
  std::vector<Finding> run(const std::string &target);

  /// Check if nuclei binary is available in PATH.
  bool is_available() const;

private:
  struct NucleiResult {
    std::string template_id;
    std::string name;
    std::string severity;
    std::string matched_url;
    std::string extracted_results;
    std::string description;
    std::string reference;
  };

  std::string find_nuclei_binary() const;
  std::string execute_nuclei(const std::string &target,
                             const std::string &template_dir);
  std::vector<NucleiResult> parse_json_output(const std::string &output);
  Finding to_finding(const NucleiResult &result);

  const Config &cfg_;
  std::string nuclei_path_;

  static const std::vector<std::string> template_dirs_;
};

} // namespace apex

#endif // APEX_NUCLEI_RUNNER_HPP
