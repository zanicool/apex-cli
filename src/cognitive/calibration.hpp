/// @file cognitive/calibration.hpp
/// @brief Belief Calibration Engine + Self-Adversarial Reviewer
///
/// Two systems that make the cognitive core self-correcting:
///
/// 1. Calibration: tracks prediction accuracy over time.
///    "I said 80% confident → was I right 80% of the time?"
///
/// 2. Reviewer: challenges every important claim before acceptance.
///    "You say IDOR — did you actually test with two different users?"
#ifndef APEX_COGNITIVE_CALIBRATION_HPP
#define APEX_COGNITIVE_CALIBRATION_HPP

#include "core.hpp"
#include <deque>
#include <string>
#include <vector>

namespace apex {
namespace cognitive {

// ============================================================
// BELIEF CALIBRATION ENGINE
// ============================================================

/// A tracked prediction with outcome.
struct Prediction {
  std::string hypothesis_id;
  std::string statement;
  double predicted_confidence;  // What Apex said
  bool actual_outcome;          // What actually happened
  std::string timestamp;
};

/// Calibration metrics.
struct CalibrationMetrics {
  int total_predictions = 0;
  int correct_predictions = 0;
  double accuracy = 0.0;            // correct / total
  double overconfidence_rate = 0.0; // predicted high, was wrong
  double underconfidence_rate = 0.0;// predicted low, was right
  double brier_score = 0.0;         // Mean squared error of probabilities
  double calibration_error = 0.0;   // |predicted - actual| averaged

  /// Is the system well-calibrated? (brier < 0.25 is good)
  bool is_calibrated() const { return brier_score < 0.25; }
};

/// The calibration engine.
class CalibrationEngine {
public:
  /// Record a prediction (before verification).
  void record_prediction(const std::string &hypothesis_id,
                          const std::string &statement,
                          double confidence);

  /// Record the actual outcome (after verification).
  void record_outcome(const std::string &hypothesis_id, bool was_correct);

  /// Get current calibration metrics.
  CalibrationMetrics metrics() const;

  /// Get confidence adjustment factor.
  /// If system is overconfident, this returns < 1.0 (dampen).
  /// If underconfident, returns > 1.0 (boost).
  double adjustment_factor() const;

  /// Apply calibration to a raw confidence score.
  double calibrate(double raw_confidence) const;

  /// How many predictions tracked.
  int history_size() const { return predictions_.size(); }

  /// Summary string for reporting.
  std::string summary() const;

private:
  std::deque<Prediction> predictions_; // Rolling window (max 500)
  static constexpr int MAX_HISTORY = 500;
};

// ============================================================
// SELF-ADVERSARIAL REVIEWER
// ============================================================

/// An objection raised by the reviewer.
struct Objection {
  std::string claim;            // What's being challenged
  std::string objection;        // Why it might be wrong
  std::string required_test;    // What would resolve this
  double severity = 0.0;        // How serious this objection is (0-1)
};

/// Result of a review.
struct ReviewResult {
  std::string finding_type;
  std::string finding_url;
  std::vector<Objection> objections;
  double original_confidence;
  double adjusted_confidence;
  bool requires_additional_testing = false;
  std::string verdict;          // "accepted", "weakened", "rejected", "needs_more_evidence"
};

/// The adversarial reviewer.
class Reviewer {
public:
  /// Review a finding — challenge its evidence.
  ReviewResult review(const Finding &finding, const WorldModel &world) const;

  /// Review a hypothesis — is the reasoning sound?
  ReviewResult review_hypothesis(const CognitiveHypothesis &hypothesis,
                                  const WorldModel &world) const;

private:
  /// Check if evidence is sufficient for the claim.
  std::vector<Objection> challenge_evidence(const Finding &f) const;

  /// Check for alternative explanations.
  std::vector<Objection> find_alternatives(const Finding &f, const WorldModel &world) const;

  /// Check if the finding could be a false positive.
  std::vector<Objection> check_fp_indicators(const Finding &f) const;
};

} // namespace cognitive
} // namespace apex

#endif // APEX_COGNITIVE_CALIBRATION_HPP
