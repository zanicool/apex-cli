/// @file cognitive/cpm_bridge.cpp
/// @brief CPM-Apex Integration Bridge implementation.
#include "cpm_bridge.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

namespace apex {
namespace bridge {

std::vector<InternalFinding> load_cpm_findings(const std::string& json_path) {
  std::vector<InternalFinding> findings;
  std::ifstream file(json_path);
  if (!file.is_open()) return findings;

  // Simple line-by-line JSON parsing (each line = one finding)
  std::string line;
  while (std::getline(file, line)) {
    InternalFinding f;
    // Parse type
    auto extract = [&](const std::string& key) -> std::string {
      auto pos = line.find("\"" + key + "\"");
      if (pos == std::string::npos) return "";
      pos = line.find(":", pos) + 1;
      while (pos < line.size() && (line[pos] == ' ' || line[pos] == '"')) pos++;
      auto end = line.find_first_of("\",}", pos);
      return line.substr(pos, end - pos);
    };

    f.type = extract("type");
    f.severity = extract("severity");
    f.detail = extract("detail");
    f.service = extract("service");
    f.host = extract("host");
    std::string port_s = extract("port");
    if (!port_s.empty()) f.port = std::stoi(port_s);
    f.has_auth = extract("has_auth") == "true";

    if (!f.type.empty()) findings.push_back(f);
  }

  return findings;
}

std::vector<FullStackChain> correlate(const std::vector<Finding>& external_findings,
                                      const std::vector<InternalFinding>& internal_findings) {
  std::vector<FullStackChain> chains;

  // Find SSRF externally + exposed service internally
  for (const auto& ext : external_findings) {
    if (ext.type.find("SSRF") == std::string::npos) continue;

    for (const auto& intern : internal_findings) {
      if (intern.type == "exposed_service" && !intern.has_auth) {
        FullStackChain chain;
        chain.name = "SSRF → " + intern.service + " (no auth) → ";

        // Determine impact based on service
        if (intern.service == "redis") {
          chain.name += "RCE via Redis commands";
          chain.impact = "critical";
          chain.confidence = 0.9;
        } else if (intern.service == "mongodb" || intern.service == "mysql" || intern.service == "postgresql") {
          chain.name += "Data breach via " + intern.service;
          chain.impact = "critical";
          chain.confidence = 0.85;
        } else if (intern.service == "elasticsearch") {
          chain.name += "Data exfiltration via Elasticsearch";
          chain.impact = "high";
          chain.confidence = 0.8;
        } else if (intern.service == "docker") {
          chain.name += "Container escape via Docker API";
          chain.impact = "critical";
          chain.confidence = 0.85;
        } else {
          chain.name += "Internal service access";
          chain.impact = "high";
          chain.confidence = 0.7;
        }

        chain.external_steps.push_back(ext);
        chain.internal_steps.push_back(intern);

        std::ostringstream nar;
        nar << "FULL-STACK ATTACK CHAIN:\n\n"
            << "Step 1 (External - Apex):\n"
            << "  " << ext.type << " at " << ext.url << "\n"
            << "  Allows server-side requests to internal network.\n\n"
            << "Step 2 (Internal - CPM):\n"
            << "  " << intern.service << " on " << intern.host << ":" << intern.port << "\n"
            << "  " << (intern.has_auth ? "Has auth" : "NO AUTHENTICATION") << "\n\n"
            << "Step 3 (Impact):\n"
            << "  Attacker uses SSRF to reach " << intern.service << " internally.\n"
            << "  No auth required → full access to " << intern.service << ".\n"
            << "  Result: " << chain.impact << " — " << chain.name << "\n\n"
            << "Neither tool finds this alone. CPM doesn't know about the SSRF.\n"
            << "Apex doesn't know " << intern.service << " has no auth.";
        chain.narrative = nar.str();

        chains.push_back(chain);
      }
    }
  }

  // Find JWT weakness externally + exposed admin panel internally
  for (const auto& ext : external_findings) {
    if (ext.type.find("JWT") == std::string::npos) continue;

    for (const auto& intern : internal_findings) {
      if (intern.type == "exposed_service" && intern.service == "admin_panel") {
        FullStackChain chain;
        chain.name = "JWT Forgery → Admin Panel → Full System Control";
        chain.impact = "critical";
        chain.confidence = 0.85;
        chain.external_steps.push_back(ext);
        chain.internal_steps.push_back(intern);
        chain.narrative =
            "JWT weakness allows forging admin tokens.\n"
            "Admin panel (found by CPM) accepts these tokens.\n"
            "Result: full system administration access.";
        chains.push_back(chain);
      }
    }
  }

  // Find info disclosure externally + weak permissions internally
  for (const auto& ext : external_findings) {
    if (ext.type.find("Disclosure") == std::string::npos && ext.type.find("Exposed") == std::string::npos) continue;

    for (const auto& intern : internal_findings) {
      if (intern.type == "weak_permission" || intern.type == "cve") {
        FullStackChain chain;
        chain.name = std::string("Info Leak → Internal Knowledge → ") + (intern.type == "cve" ? "CVE Exploitation" : "Permission Abuse");
        chain.impact = "high";
        chain.confidence = 0.6;
        chain.external_steps.push_back(ext);
        chain.internal_steps.push_back(intern);
        chain.narrative =
            "External information disclosure reveals internal architecture.\n"
            "Combined with " +
            intern.detail +
            " found by CPM.\n"
            "Attacker gains knowledge + exploit path.";
        chains.push_back(chain);
      }
    }
  }

  // Sort by confidence × impact
  std::sort(chains.begin(), chains.end(), [](const FullStackChain& a, const FullStackChain& b) {
    auto impact_score = [](const std::string& s) {
      if (s == "critical") return 10;
      if (s == "high") return 7;
      return 4;
    };
    return a.confidence * impact_score(a.impact) > b.confidence * impact_score(b.impact);
  });

  return chains;
}

std::string generate_combined_report(const std::vector<FullStackChain>& chains) {
  if (chains.empty()) return "No full-stack attack chains found.\n";

  std::ostringstream report;
  report << "# Full-Stack Security Assessment (CPM + Apex)\n\n";
  report << "## Attack Chains: " << chains.size() << " identified\n\n";

  for (size_t i = 0; i < chains.size(); i++) {
    const auto& chain = chains[i];
    report << "### Chain " << (i + 1) << ": " << chain.name << "\n";
    report << "- **Impact:** " << chain.impact << "\n";
    report << "- **Confidence:** " << (int)(chain.confidence * 100) << "%\n";
    report << "- **External findings:** " << chain.external_steps.size() << "\n";
    report << "- **Internal findings:** " << chain.internal_steps.size() << "\n\n";
    report << "```\n" << chain.narrative << "\n```\n\n";
  }

  return report.str();
}

}  // namespace bridge
}  // namespace apex
