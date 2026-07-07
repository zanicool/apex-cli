/// @file cognitive/narrative.hpp
/// @brief Exploit Narrative & Evidence Engine
///
/// Transforms a critical candidate into a submission-ready report.
/// From "maybe critical" to "provably critical with evidence."
#ifndef APEX_COGNITIVE_NARRATIVE_HPP
#define APEX_COGNITIVE_NARRATIVE_HPP

#include "../scanner.hpp"
#include "critical_path.hpp"
#include <string>
#include <vector>

namespace apex {
namespace cognitive {

/// A single piece of evidence in the chain.
struct EvidenceItem {
  std::string type;          // "request", "response", "comparison", "timing"
  std::string description;
  std::string request;       // Exact request made
  std::string response;      // Key response content (truncated)
  int response_code = 0;
  std::string state_before;  // What was true before
  std::string state_after;   // What changed
  double confidence = 0.0;
};

/// Reproduction steps for a report.
struct ReproductionSteps {
  std::string precondition;  // "Unauthenticated attacker with network access"
  std::vector<std::string> steps; // Ordered steps
  std::string expected_result;    // What you should see
  std::string actual_result;      // What Apex observed
  std::string impact;             // Security consequence
};

/// Report quality assessment.
struct ReportQuality {
  double evidence_quality = 0.0;    // 0-1
  double reproducibility = 0.0;     // 0-1
  double impact_clarity = 0.0;      // 0-1
  double root_cause_clarity = 0.0;  // 0-1
  double submission_readiness = 0.0;// 0-1 overall
  std::vector<std::string> missing; // What's needed to improve
  std::string verdict;              // "submit", "needs_work", "insufficient"
};

/// A complete submission-ready report.
struct ExploitReport {
  std::string title;
  std::string severity;
  std::string asset;
  std::string summary;                // 2-3 sentence overview
  ReproductionSteps reproduction;
  std::vector<EvidenceItem> evidence;
  std::string impact_analysis;
  std::string root_cause;
  std::string remediation;
  std::string cwe;
  std::string cvss;
  ReportQuality quality;
};

/// Build a complete exploit report from a critical candidate.
ExploitReport build_report(const CriticalCandidate &candidate, HttpClient &http);

/// Assess report quality (would a triager accept this?).
ReportQuality assess_quality(const ExploitReport &report);

/// Generate the full text report ready for submission.
std::string render_report(const ExploitReport &report);

} // namespace cognitive
} // namespace apex

#endif // APEX_COGNITIVE_NARRATIVE_HPP
