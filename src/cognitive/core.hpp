/// @file cognitive/core.hpp
/// @brief Apex Cognitive Security Core v1
///
/// The intelligence layer that sits above all existing systems.
/// It doesn't replace the scanner — it DIRECTS it.
///
/// Architecture:
///   World Model     — what Apex believes about the target
///   Hypothesis Engine — what Apex thinks might be true
///   Decision Engine  — what Apex decides to do next
///   Evidence Engine  — how Apex proves/disproves beliefs
///
/// Flow:
///   Observe → Model → Hypothesize → Decide → Act → Measure → Update
///
/// This is the difference between a scanner and a researcher.
#ifndef APEX_COGNITIVE_CORE_HPP
#define APEX_COGNITIVE_CORE_HPP

#include "../crawler.hpp"
#include "../http.hpp"
#include "../scanner.hpp"
#include "../knowledge/graph.hpp"
#include <map>
#include <string>
#include <vector>

namespace apex {
namespace cognitive {

// ============================================================
// WORLD MODEL — what Apex believes about the target
// ============================================================

/// A belief about the target with confidence.
struct Belief {
  std::string subject;      // What it's about ("endpoint:/api/payment")
  std::string predicate;    // What we believe ("handles_money")
  double confidence = 0.0;  // 0.0-1.0
  std::string evidence;     // Why we believe this
  std::string source;       // Where this came from ("url_pattern", "response_analysis")
};

/// The world model: everything Apex believes about the target.
struct WorldModel {
  std::string target;
  std::vector<Belief> beliefs;
  std::map<std::string, std::string> endpoint_purposes; // url → purpose
  std::map<std::string, double> endpoint_importance;    // url → score 0-1
  std::set<std::string> confirmed_technologies;
  std::set<std::string> suspected_vulnerabilities;
  double overall_risk = 0.0;

  /// Add a belief, updating confidence if it already exists.
  void add_belief(const Belief &belief);

  /// Get confidence for a specific belief.
  double confidence_of(const std::string &subject, const std::string &predicate) const;

  /// Get all beliefs about a subject.
  std::vector<Belief> beliefs_about(const std::string &subject) const;

  /// Get the most important endpoints (sorted by importance).
  std::vector<std::string> priority_targets(int max = 10) const;
};

// ============================================================
// HYPOTHESIS ENGINE — what Apex thinks might be true
// ============================================================

/// A testable hypothesis.
struct CognitiveHypothesis {
  std::string id;
  std::string statement;        // "This endpoint probably has an IDOR"
  double prior_probability;     // Before testing: 0.0-1.0
  double posterior_probability; // After evidence: 0.0-1.0
  std::string test_method;      // How to test it
  std::string status;           // "untested", "testing", "confirmed", "rejected"
  std::vector<std::string> supporting_beliefs; // What supports this hypothesis
  std::string result;           // What happened when tested
};

// ============================================================
// DECISION ENGINE — what Apex decides to do next
// ============================================================

/// An action Apex can take.
struct Action {
  std::string type;             // "scan_module", "custom_test", "crawl_deeper", "verify"
  std::string target;           // What to act on
  std::string rationale;        // Why this action
  double expected_value;        // How valuable this action is (priority)
  std::map<std::string, std::string> params; // Action parameters
};

// ============================================================
// EVIDENCE ENGINE — how Apex proves/disproves
// ============================================================

/// Evidence collected from an action.
struct CognitiveEvidence {
  std::string hypothesis_id;    // What this evidence is for
  std::string observation;      // What we observed
  double likelihood_if_true;    // P(evidence | hypothesis true)
  double likelihood_if_false;   // P(evidence | hypothesis false)
  bool supports_hypothesis;     // Does this evidence support or refute?
};

// ============================================================
// THE COGNITIVE CORE — orchestrates everything
// ============================================================

/// The main cognitive engine.
class CognitiveCore {
public:
  CognitiveCore();

  /// Phase 1: Build world model from existing scan data.
  void observe(const CrawlResult &crawl, const std::vector<Finding> &findings,
               const std::set<std::string> &technologies);

  /// Phase 2: Generate hypotheses based on world model.
  void hypothesize();

  /// Phase 3: Decide what to do next (prioritized action list).
  std::vector<Action> decide();

  /// Phase 4: Update beliefs based on new evidence.
  void update(const CognitiveEvidence &evidence);

  /// Execute one cognitive cycle (observe → hypothesize → decide).
  std::vector<Action> think(const CrawlResult &crawl,
                             const std::vector<Finding> &findings,
                             const std::set<std::string> &technologies);

  /// Get current state.
  const WorldModel &world() const { return world_model_; }
  const std::vector<CognitiveHypothesis> &hypotheses() const { return hypotheses_; }

  /// Summary for reporting.
  std::string summary() const;

private:
  WorldModel world_model_;
  std::vector<CognitiveHypothesis> hypotheses_;
  knowledge::Graph knowledge_;
  int cycle_count_ = 0;

  // Internal methods
  void infer_endpoint_purposes();
  void infer_auth_levels();
  void infer_data_sensitivity();
  void generate_vulnerability_hypotheses();
  void generate_chain_hypotheses();
  double calculate_action_value(const Action &action) const;
};

} // namespace cognitive
} // namespace apex

#endif // APEX_COGNITIVE_CORE_HPP
