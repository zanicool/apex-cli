#include "recon_logger.hpp"
#include <chrono>
#include <iomanip>
#include <sstream>

namespace apex {

ReconLogger::ReconLogger(const std::string &output_dir) {
  cms_log_.open(output_dir + "/cms_recon.jsonl", std::ios::app);
  osint_log_.open(output_dir + "/osint_recon.jsonl", std::ios::app);
  vuln_log_.open(output_dir + "/vuln_recon.jsonl", std::ios::app);
}

std::string ReconLogger::timestamp() {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  std::stringstream ss;
  ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

std::string ReconLogger::escape_json(const std::string &str) {
  std::string escaped;
  for (char c : str) {
    if (c == '"')
      escaped += "\\\"";
    else if (c == '\\')
      escaped += "\\\\";
    else if (c == '\n')
      escaped += "\\n";
    else if (c == '\r')
      escaped += "\\r";
    else if (c == '\t')
      escaped += "\\t";
    else
      escaped += c;
  }
  return escaped;
}

void ReconLogger::log_cms(const CMSVersion &cms, const std::string &url) {
  cms_log_ << "{"
           << "\"timestamp\":\"" << timestamp() << "\","
           << "\"url\":\"" << escape_json(url) << "\","
           << "\"cms\":\"" << escape_json(cms.name) << "\","
           << "\"version\":\"" << escape_json(cms.version) << "\","
           << "\"latest\":\"" << escape_json(cms.latest_version) << "\","
           << "\"outdated\":" << (cms.outdated ? "true" : "false") << "}\n";
  cms_log_.flush();
}

void ReconLogger::log_leak(const OSINTLeak &leak) {
  osint_log_ << "{"
             << "\"timestamp\":\"" << timestamp() << "\","
             << "\"type\":\"leak\","
             << "\"source\":\"" << escape_json(leak.source) << "\","
             << "\"leak_type\":\"" << escape_json(leak.type) << "\","
             << "\"value\":\"" << escape_json(leak.value) << "\","
             << "\"breach\":\"" << escape_json(leak.breach_name) << "\","
             << "\"date\":\"" << escape_json(leak.date) << "\","
             << "\"severity\":\"" << escape_json(leak.severity) << "\""
             << "}\n";
  osint_log_.flush();
}

void ReconLogger::log_employee(const EmployeeExposure &emp) {
  osint_log_ << "{"
             << "\"timestamp\":\"" << timestamp() << "\","
             << "\"type\":\"employee\","
             << "\"name\":\"" << escape_json(emp.name) << "\","
             << "\"email\":\"" << escape_json(emp.email) << "\","
             << "\"role\":\"" << escape_json(emp.role) << "\","
             << "\"linkedin\":\"" << escape_json(emp.linkedin_url) << "\""
             << "}\n";
  osint_log_.flush();
}

void ReconLogger::log_techstack(const TechStackIntel &tech) {
  osint_log_ << "{"
             << "\"timestamp\":\"" << timestamp() << "\","
             << "\"type\":\"techstack\","
             << "\"source\":\"" << escape_json(tech.source) << "\","
             << "\"technology\":\"" << escape_json(tech.technology) << "\","
             << "\"version\":\"" << escape_json(tech.version) << "\","
             << "\"url\":\"" << escape_json(tech.url) << "\""
             << "}\n";
  osint_log_.flush();
}

void ReconLogger::log_finding(const Finding &finding) {
  vuln_log_ << "{"
            << "\"timestamp\":\"" << timestamp() << "\","
            << "\"type\":\"" << escape_json(finding.type) << "\","
            << "\"severity\":\"" << escape_json(finding.severity) << "\","
            << "\"url\":\"" << escape_json(finding.url) << "\","
            << "\"detail\":\"" << escape_json(finding.detail) << "\","
            << "\"param\":\"" << escape_json(finding.param) << "\","
            << "\"payload\":\"" << escape_json(finding.payload) << "\","
            << "\"evidence\":\"" << escape_json(finding.evidence) << "\""
            << "}\n";
  vuln_log_.flush();
}

void ReconLogger::close() {
  cms_log_.close();
  osint_log_.close();
  vuln_log_.close();
}

} // namespace apex
