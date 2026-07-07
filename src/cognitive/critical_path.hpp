/// @file cognitive/critical_path.hpp
/// @brief Critical Path Engine — find, prove, and prioritize maximum-impact vulnerabilities.
///
/// Not more findings. Better findings. One proven critical beats 100 unverified mediums.
#ifndef APEX_COGNITIVE_CRITICAL_PATH_HPP
#define APEX_COGNITIVE_CRITICAL_PATH_HPP

#include "../http.hpp"
#include "../scanner.hpp"
#include "core.hpp"
#include "state_machine.hpp"
#include <string>
#include <vector>

namespace apex {
namespace cognitive {

/// Criticality score components.
struct CriticalityScore {
  double impact = 0.0;         // 0-1: how bad if exploited
  double exploitability = 0.0; // 0-1: how easy to exploit
  double exposure = 0.0;       // 0-1: how accessible
  double confidence = 0.0;     // 0-1: how sure are we

  double total() const { return impact * exploitability * exposure * confidence; }
};

/// A critical finding candidate with full evidence chain.
struct CriticalCandidate {
  Finding finding;
  CriticalityScore score;
  std::vector<std::string> signals;    // Independent indicators
  std::string impact_narrative;         // Why this matters (for report)
  std::string proof_method;             // How to reproduce
  bool verified = false;
  std::string chain_context;            // Part of larger chain?
};

/// Run the critical path analysis on findings + world model.
/// Returns only high-confidence critical candidates, fully prioritized.
std::vector<CriticalCandidate> find_criticals(
    const std::vector<Finding> &findings,
    const std::vector<Workflow> &workflows,
    const WorldModel &world,
    HttpClient &http);

/// Score a single finding for criticality.
CriticalityScore score_criticality(const Finding &f, const WorldModel &world);

/// Build impact chains from multiple findings.
std::vector<CriticalCandidate> build_impact_chains(
    const std::vector<Finding> &findings,
    const WorldModel &world);

} // namespace cognitive
} // namespace apex

#endif // APEX_COGNITIVE_CRITICAL_PATH_HPP
