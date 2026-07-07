/// @file reasoning.hpp
/// @brief Autonomous Security Reasoning Engine.
///
/// This is not a scanner. This is a system that thinks.
///
/// It takes what Apex has found so far and asks:
///   "Given these observations, what should I investigate next?"
///   "Do these findings combine into something bigger?"
///   "What is the most likely attack path to critical impact?"
///
/// Architecture:
///   Observation → Hypothesis → Test → Conclusion → Next Hypothesis
///
/// Unlike the scanner modules (which test predefined patterns), the reasoning
/// engine generates NEW test ideas based on context it has never seen before.
#ifndef APEX_REASONING_HPP
#define APEX_REASONING_HPP

#include "scanner.hpp"
#include "targeting.hpp"
#include "verification.hpp"
#include <map>
#include <string>
#include <vector>

namespace apex {

/// A hypothesis the engine wants to test.
struct Hypothesis {
  std::string id;
  std::string description;      // "JWT + admin endpoint = privilege escalation"
  std::string test_plan;        // What to do to confirm/deny
  double confidence = 0.0;      // 0.0-1.0 how likely this is exploitable
  std::string status;           // "pending", "testing", "confirmed", "rejected"
  std::vector<std::string> depends_on; // Finding IDs that support this
  std::string result;           // What happened when tested
};

/// An attack path: ordered sequence of findings that chain together.
struct AttackPath {
  std::string id;
  std::string name;             // "Git Leak → API Key → Admin Takeover"
  std::string impact;           // "critical", "high", etc.
  double probability = 0.0;     // How likely this path is exploitable
  std::vector<Finding> steps;   // Ordered findings in the chain
  std::string narrative;        // Human-readable explanation
};

/// The reasoning engine's state after analysis.
struct ReasoningResult {
  std::vector<Hypothesis> hypotheses;
  std::vector<AttackPath> attack_paths;
  std::vector<Finding> escalated_findings; // Findings with upgraded severity
  std::string summary;          // Overall assessment
  int risk_score = 0;           // 0-100 overall target risk
};

/// Run the reasoning engine on current findings + profile.
/// This is the "brain" that connects dots.
ReasoningResult reason(const std::vector<Finding> &findings,
                        const AssetProfile &profile,
                        const CrawlResult &crawl,
                        HttpClient &http);

} // namespace apex

#endif // APEX_REASONING_HPP
