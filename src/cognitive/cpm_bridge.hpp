/// @file cognitive/cpm_bridge.hpp
/// @brief CPM-Apex Integration Bridge
///
/// Connects CPM (internal system checks) with Apex (external web scanning)
/// to create full-stack attack chains that neither tool can find alone.
///
/// Example:
///   CPM finds: "Redis on port 6379, no auth"
///   Apex finds: "SSRF on /api/fetch"
///   Bridge concludes: "SSRF → Redis → RCE (critical chain, 94% confidence)"
#ifndef APEX_CPM_BRIDGE_HPP
#define APEX_CPM_BRIDGE_HPP

#include "../scanner.hpp"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace apex {
namespace bridge {

/// A finding from CPM (internal system check).
struct InternalFinding {
  std::string type;           // "exposed_service", "weak_config", "cve", "permission"
  std::string severity;       // critical, high, medium, low
  std::string detail;         // Human-readable description
  std::string service;        // "redis", "docker", "ssh", "mysql"
  std::string host;           // "localhost", "10.0.0.5"
  int port = 0;              // 6379, 3306, etc.
  bool requires_auth = false; // Does the service need credentials?
  bool has_auth = false;      // Does it actually have auth configured?
  std::string cve_id;         // If it's a known CVE
};

/// A combined attack chain spanning internal + external.
struct FullStackChain {
  std::string name;           // "SSRF → Redis → RCE"
  std::string impact;         // "critical"
  double confidence;          // 0.0-1.0
  std::vector<Finding> external_steps;      // Apex findings
  std::vector<InternalFinding> internal_steps; // CPM findings
  std::string narrative;      // Full explanation
};

/// Load CPM findings from a JSON export file.
std::vector<InternalFinding> load_cpm_findings(const std::string &json_path);

/// Correlate external (Apex) + internal (CPM) findings into full-stack chains.
std::vector<FullStackChain> correlate(
    const std::vector<Finding> &external_findings,
    const std::vector<InternalFinding> &internal_findings);

/// Generate a combined report showing full attack paths.
std::string generate_combined_report(const std::vector<FullStackChain> &chains);

} // namespace bridge
} // namespace apex

#endif // APEX_CPM_BRIDGE_HPP
