/// @file reporter.cpp
/// @brief Report generation: JSON file and terminal summary.
#include "reporter.hpp"
#include <fstream>
#include <iostream>

namespace apex {

namespace {

/// Escape a string for JSON output.
std::string json_escape(const std::string &s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    switch (c) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      out += c;
    }
  }
  return out;
}

/// Count findings by severity.
struct Counts {
  int critical = 0;
  int high = 0;
  int medium = 0;
  int low = 0;
  int info = 0;
};

Counts count_severity(const std::vector<Finding> &findings) {
  Counts c;
  for (const auto &f : findings) {
    if (f.severity == "critical")
      ++c.critical;
    else if (f.severity == "high")
      ++c.high;
    else if (f.severity == "medium")
      ++c.medium;
    else if (f.severity == "low")
      ++c.low;
    else
      ++c.info;
  }
  return c;
}

} // namespace

void generate_report(const Config &cfg, const std::vector<Finding> &findings,
                     std::chrono::seconds elapsed) {
  // JSON report.
  if (cfg.report.find("json") != std::string::npos) {
    std::string path = cfg.output_dir + "/report.json";
    std::ofstream out(path);
    if (out.is_open()) {
      out << "{\n  \"target\": \"" << json_escape(cfg.target) << "\",\n";
      out << "  \"duration_seconds\": " << elapsed.count() << ",\n";
      out << "  \"findings\": [\n";
      for (size_t i = 0; i < findings.size(); ++i) {
        const auto &f = findings[i];
        out << "    {\"type\": \"" << json_escape(f.type) << "\", ";
        out << "\"severity\": \"" << json_escape(f.severity) << "\", ";
        out << "\"url\": \"" << json_escape(f.url) << "\", ";
        out << "\"detail\": \"" << json_escape(f.detail) << "\"";
        if (!f.param.empty())
          out << ", \"param\": \"" << json_escape(f.param) << "\"";
        if (!f.payload.empty())
          out << ", \"payload\": \"" << json_escape(f.payload) << "\"";
        if (!f.evidence.empty())
          out << ", \"evidence\": \"" << json_escape(f.evidence) << "\"";
        out << "}";
        if (i + 1 < findings.size())
          out << ",";
        out << "\n";
      }
      out << "  ]\n}\n";
      std::cout << "  -> JSON: " << path << "\n";
    }
  }

  // Terminal report.
  if (cfg.report.find("terminal") != std::string::npos) {
    auto c = count_severity(findings);
    std::cout << "\n";
    std::cout << "  Scan Results — " << cfg.target << "\n";
    std::cout << "  Duration: " << elapsed.count()
              << "s | Findings: " << findings.size() << "\n";
    std::cout << "  Critical: " << c.critical << "  High: " << c.high
              << "  Medium: " << c.medium << "  Low: " << c.low << "\n";

    for (const auto &f : findings) {
      std::cout << "  [" << f.severity << "] " << f.type << " — " << f.url
                << "\n";
      if (!f.detail.empty()) {
        std::cout << "    " << f.detail << "\n";
      }
    }
  }

  // PDF report (requires python3 + reportlab).
  if (cfg.report.find("pdf") != std::string::npos) {
    std::string json_path = cfg.output_dir + "/report.json";
    std::string pdf_path = cfg.output_dir + "/report.pdf";
    std::string script = cfg.install_dir + "/scripts/pdf-report.py";
    std::string cmd = "python3 " + script + " " + json_path + " " + pdf_path +
                      " 2>/dev/null";
    int ret = system(cmd.c_str());
    if (ret != 0) {
      std::cout << "  [!] PDF generation failed. Install: pip3 install "
                   "reportlab\n";
    }
  }
}

} // namespace apex
