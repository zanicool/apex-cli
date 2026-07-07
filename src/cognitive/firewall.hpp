/// @file cognitive/firewall.hpp
/// @brief Critical Validation Firewall — prevents false criticals from being submitted.
///
/// One bad submission destroys reputation. This layer ensures Apex only
/// outputs findings it can actually defend.
#ifndef APEX_COGNITIVE_FIREWALL_HPP
#define APEX_COGNITIVE_FIREWALL_HPP

#include "calibration.hpp"
#include "narrative.hpp"
#include <string>
#include <vector>

namespace apex {
namespace cognitive {

/// Validation check result.
struct ValidationCheck {
  std::string name;        // "evidence_integrity", "impact_verification", etc.
  bool passed = false;
  std::string reason;      // Why it passed/failed
  double confidence_impact; // How much this affects overall confidence
};

/// Final validation verdict.
struct FirewallVerdict {
  bool approved = false;
  double final_confidence = 0.0;
  std::string gate;          // "submit", "needs_evidence", "research_only", "blocked"
  std::vector<ValidationCheck> checks;
  std::vector<std::string> blockers;  // What prevents submission
  std::vector<std::string> warnings;  // Non-blocking concerns
};

/// Run the full validation firewall on a report.
FirewallVerdict validate(const ExploitReport &report,
                          const CalibrationEngine &calibration);

/// Summary for output.
std::string render_verdict(const FirewallVerdict &verdict);

} // namespace cognitive
} // namespace apex

#endif // APEX_COGNITIVE_FIREWALL_HPP
