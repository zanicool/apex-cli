/// @file verification.hpp
/// @brief Verification Pipeline + Scan Memory Engine.
///
/// Findings go through: UNVERIFIED → SUSPECTED → VERIFIED → CONFIRMED
/// Each transition requires evidence. Scan memory enables delta comparisons.
#ifndef APEX_VERIFICATION_HPP
#define APEX_VERIFICATION_HPP

#include "http.hpp"
#include "scanner.hpp"
#include <chrono>
#include <map>
#include <string>
#include <vector>

namespace apex {

/// Verification state of a finding.
enum class VerifyState {
  UNVERIFIED,  // Just detected, no re-test
  SUSPECTED,   // Behavioral indicator but not confirmed
  VERIFIED,    // Reproduced with differential evidence
  CONFIRMED,   // Multiple independent confirmations
  FALSE_POS    // Failed verification, demoted
};

/// Evidence record for a single verification attempt.
struct Evidence {
  std::string method;          // "differential", "timing", "reflection", "behavioral"
  std::string request;         // The request that triggered it
  std::string response_snippet;// Relevant response portion (max 500 chars)
  int response_code = 0;
  size_t response_size = 0;
  long response_time_ms = 0;
  std::string baseline_diff;   // What changed vs baseline
  std::string timestamp;       // ISO 8601
};

/// A verified finding with full evidence chain.
struct VerifiedFinding {
  Finding finding;
  VerifyState state = VerifyState::UNVERIFIED;
  std::vector<Evidence> evidence_chain;
  int verify_attempts = 0;
  std::string state_reason;    // Why it's in this state
};

/// Scan snapshot for memory/delta comparison.
struct ScanSnapshot {
  std::string target;
  std::string timestamp;       // ISO 8601
  std::vector<std::string> endpoints;
  std::vector<std::string> technologies;
  std::vector<std::string> parameters;
  std::vector<VerifiedFinding> findings;
  std::map<std::string, std::string> metadata; // arbitrary k/v
};

/// Delta between two scans.
struct ScanDelta {
  std::vector<std::string> new_endpoints;
  std::vector<std::string> removed_endpoints;
  std::vector<std::string> new_technologies;
  std::vector<VerifiedFinding> new_findings;
  std::vector<VerifiedFinding> resolved_findings;
  std::vector<VerifiedFinding> persistent_findings;
};

/// Run verification pipeline on a list of findings.
/// Re-tests each finding and assigns a VerifyState.
std::vector<VerifiedFinding> verify_findings(
    const std::vector<Finding> &findings,
    HttpClient &http,
    int max_verify = 10);

/// Save a scan snapshot to disk.
void save_snapshot(const ScanSnapshot &snapshot, const std::string &output_dir);

/// Load the most recent snapshot for a target.
ScanSnapshot load_previous_snapshot(const std::string &target,
                                     const std::string &output_dir);

/// Compare two snapshots and produce a delta.
ScanDelta compute_delta(const ScanSnapshot &previous,
                         const ScanSnapshot &current);

} // namespace apex

#endif // APEX_VERIFICATION_HPP
