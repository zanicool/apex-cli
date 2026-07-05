#pragma once
#include "cms_detector.hpp"
#include "osint.hpp"
#include "scanner.hpp"
#include <fstream>
#include <string>

namespace apex {

/// JSONL logger for complete recon history
class ReconLogger {
public:
  ReconLogger(const std::string &output_dir);

  // Log CMS findings
  void log_cms(const CMSVersion &cms, const std::string &url);

  // Log OSINT findings
  void log_leak(const OSINTLeak &leak);
  void log_employee(const EmployeeExposure &emp);
  void log_techstack(const TechStackIntel &tech);

  // Log vulnerability findings
  void log_finding(const Finding &finding);

  // Flush and close
  void close();

private:
  std::ofstream cms_log_;
  std::ofstream osint_log_;
  std::ofstream vuln_log_;

  std::string escape_json(const std::string &str);
  std::string timestamp();
};

} // namespace apex
