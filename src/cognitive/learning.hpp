/// @file cognitive/learning.hpp
/// @brief Experimental Learning Framework — Apex learns which strategies work.
///
/// Not "more checks". Better decisions.
/// After 100 scans, Apex should make measurably better choices than on scan 1.
#ifndef APEX_COGNITIVE_LEARNING_HPP
#define APEX_COGNITIVE_LEARNING_HPP

#include <deque>
#include <map>
#include <string>
#include <vector>

namespace apex {
namespace cognitive {

// ============================================================
// EXPERIMENT REGISTRY
// ============================================================

/// A recorded experiment (action taken + outcome).
struct Experiment {
  std::string id;
  std::string hypothesis;
  std::string action;            // What Apex did
  std::string reason;            // Why it chose this
  std::string technology_context;// What tech was detected
  double expected_gain;          // Predicted value
  double actual_gain;            // What actually happened (0=useless, 1=critical find)
  double cost;                   // Time/requests spent
  bool produced_finding;         // Did it find something real?
  std::string finding_severity;  // If yes, what severity
  std::string timestamp;
};

// ============================================================
// STRATEGY PERFORMANCE
// ============================================================

/// Performance record for a strategy in a specific context.
struct StrategyRecord {
  std::string strategy;          // "jwt_testing", "race_condition", "sqli_blind"
  std::string context;           // "nextjs+jwt", "laravel+api", etc.
  int attempts = 0;
  int successes = 0;
  double avg_gain = 0.0;
  double success_rate = 0.0;

  void update(bool success, double gain) {
    attempts++;
    if (success) successes++;
    success_rate = (double)successes / attempts;
    avg_gain = ((avg_gain * (attempts - 1)) + gain) / attempts;
  }
};

// ============================================================
// LEARNING METRICS
// ============================================================

struct LearningMetrics {
  int total_experiments = 0;
  int useful_experiments = 0;     // Produced a real finding
  double avg_information_gain = 0.0;
  double wasted_action_rate = 0.0; // Actions that produced nothing
  double false_hypothesis_rate = 0.0;
  double avg_time_to_confirmation = 0.0; // Experiments before confirmation
  std::string best_strategy;
  std::string worst_strategy;
  double improvement_over_baseline = 0.0; // vs random selection
};

// ============================================================
// THE LEARNING ENGINE
// ============================================================

class LearningEngine {
public:
  /// Record an experiment outcome.
  void record(const Experiment &experiment);

  /// Get the best strategy for a given context.
  /// Returns strategy name + expected success rate.
  std::pair<std::string, double> best_strategy_for(const std::string &context) const;

  /// Get ranked strategies for a context (best first).
  std::vector<StrategyRecord> ranked_strategies(const std::string &context) const;

  /// Should this action be taken? Based on historical performance.
  /// Returns adjusted expected value (may lower if strategy historically weak).
  double adjusted_value(const std::string &strategy,
                         const std::string &context,
                         double raw_expected_value) const;

  /// Get learning metrics.
  LearningMetrics metrics() const;

  /// Summary for reporting.
  std::string summary() const;

  /// Save learning state to disk.
  void save(const std::string &path) const;

  /// Load learning state from disk.
  void load(const std::string &path);

  /// How many experiments recorded.
  int experiment_count() const { return experiments_.size(); }

private:
  std::deque<Experiment> experiments_;
  std::map<std::string, StrategyRecord> strategy_performance_;
  // Key: "strategy|context"

  static constexpr int MAX_EXPERIMENTS = 5000;

  std::string make_key(const std::string &strategy, const std::string &context) const {
    return strategy + "|" + context;
  }
};

} // namespace cognitive
} // namespace apex

#endif // APEX_COGNITIVE_LEARNING_HPP
