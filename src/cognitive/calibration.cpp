/// @file cognitive/calibration.cpp
/// @brief Belief Calibration Engine + Self-Adversarial Reviewer implementation.
#include "calibration.hpp"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>

namespace apex {
namespace cognitive {

// ============================================================
// BELIEF CALIBRATION ENGINE
// ============================================================

void CalibrationEngine::record_prediction(const std::string& hypothesis_id, const std::string& statement, double confidence) {
  Prediction p;
  p.hypothesis_id = hypothesis_id;
  p.statement = statement;
  p.predicted_confidence = confidence;
  p.actual_outcome = false;  // Unknown until recorded
  predictions_.push_back(p);

  if ((int)predictions_.size() > MAX_HISTORY) {
    predictions_.pop_front();
  }
}

void CalibrationEngine::record_outcome(const std::string& hypothesis_id, bool was_correct) {
  for (auto& p : predictions_) {
    if (p.hypothesis_id == hypothesis_id) {
      p.actual_outcome = was_correct;
      break;
    }
  }
}

CalibrationMetrics CalibrationEngine::metrics() const {
  CalibrationMetrics m;
  if (predictions_.empty()) return m;

  m.total_predictions = predictions_.size();
  double brier_sum = 0.0;
  double calibration_sum = 0.0;
  int overconfident = 0;
  int underconfident = 0;

  for (const auto& p : predictions_) {
    double actual = p.actual_outcome ? 1.0 : 0.0;
    double predicted = p.predicted_confidence;

    // Brier score: (predicted - actual)^2
    brier_sum += (predicted - actual) * (predicted - actual);

    // Calibration error: |predicted - actual|
    calibration_sum += std::abs(predicted - actual);

    // Accuracy
    bool predicted_positive = predicted >= 0.5;
    if (predicted_positive == p.actual_outcome) m.correct_predictions++;

    // Over/under confidence
    if (predicted >= 0.7 && !p.actual_outcome) overconfident++;
    if (predicted <= 0.3 && p.actual_outcome) underconfident++;
  }

  m.accuracy = (double)m.correct_predictions / m.total_predictions;
  m.brier_score = brier_sum / m.total_predictions;
  m.calibration_error = calibration_sum / m.total_predictions;
  m.overconfidence_rate = (double)overconfident / m.total_predictions;
  m.underconfidence_rate = (double)underconfident / m.total_predictions;

  return m;
}

double CalibrationEngine::adjustment_factor() const {
  auto m = metrics();
  if (m.total_predictions < 10) return 1.0;  // Not enough data

  // If overconfident: dampen (return < 1.0)
  if (m.overconfidence_rate > 0.3) return 0.7;
  if (m.overconfidence_rate > 0.2) return 0.85;

  // If underconfident: boost (return > 1.0)
  if (m.underconfidence_rate > 0.3) return 1.3;
  if (m.underconfidence_rate > 0.2) return 1.15;

  return 1.0;
}

double CalibrationEngine::calibrate(double raw_confidence) const {
  double adjusted = raw_confidence * adjustment_factor();
  return std::max(0.0, std::min(1.0, adjusted));
}

std::string CalibrationEngine::summary() const {
  auto m = metrics();
  std::ostringstream ss;
  ss << "Calibration Engine (" << m.total_predictions << " predictions):\n";
  ss << "  Accuracy: " << (int)(m.accuracy * 100) << "%\n";
  ss << "  Brier Score: " << m.brier_score << (m.is_calibrated() ? " (good)" : " (needs improvement)") << "\n";
  ss << "  Overconfidence: " << (int)(m.overconfidence_rate * 100) << "%\n";
  ss << "  Underconfidence: " << (int)(m.underconfidence_rate * 100) << "%\n";
  ss << "  Adjustment factor: " << adjustment_factor() << "\n";
  return ss.str();
}

// ============================================================
// SELF-ADVERSARIAL REVIEWER
// ============================================================

ReviewResult Reviewer::review(const Finding& finding, const WorldModel& world) const {
  ReviewResult result;
  result.finding_type = finding.type;
  result.finding_url = finding.url;
  result.original_confidence = finding.confidence / 100.0;

  // Run all challenge methods
  auto evidence_objections = challenge_evidence(finding);
  auto alternative_objections = find_alternatives(finding, world);
  auto fp_objections = check_fp_indicators(finding);

  result.objections.insert(result.objections.end(), evidence_objections.begin(), evidence_objections.end());
  result.objections.insert(result.objections.end(), alternative_objections.begin(), alternative_objections.end());
  result.objections.insert(result.objections.end(), fp_objections.begin(), fp_objections.end());

  // Calculate confidence adjustment
  double total_severity = 0.0;
  for (const auto& obj : result.objections) {
    total_severity += obj.severity;
  }

  // Each objection reduces confidence proportionally
  double confidence_reduction = std::min(0.6, total_severity * 0.15);
  result.adjusted_confidence = std::max(0.05, result.original_confidence - confidence_reduction);

  // Verdict
  if (result.objections.empty()) {
    result.verdict = "accepted";
  } else if (total_severity > 2.0) {
    result.verdict = "rejected";
    result.adjusted_confidence = 0.1;
  } else if (total_severity > 1.0) {
    result.verdict = "needs_more_evidence";
    result.requires_additional_testing = true;
  } else {
    result.verdict = "weakened";
  }

  return result;
}

ReviewResult Reviewer::review_hypothesis(const CognitiveHypothesis& hypothesis, const WorldModel& world) const {
  ReviewResult result;
  result.finding_type = "hypothesis:" + hypothesis.id;
  result.original_confidence = hypothesis.prior_probability;

  // Challenge: is the supporting evidence strong enough?
  if (hypothesis.supporting_beliefs.empty()) {
    result.objections.push_back(
        {hypothesis.statement, "No supporting beliefs — hypothesis is speculative", "Gather evidence before testing", 0.8});
  }

  // Challenge: is the prior too high without evidence?
  if (hypothesis.prior_probability > 0.6 && hypothesis.status == "untested") {
    result.objections.push_back(
        {hypothesis.statement, "High confidence without testing — possible overconfidence", "Reduce prior or test immediately", 0.5});
  }

  // Verdict
  double total_severity = 0.0;
  for (const auto& obj : result.objections) total_severity += obj.severity;

  result.adjusted_confidence = std::max(0.1, result.original_confidence - total_severity * 0.2);
  result.verdict = result.objections.empty() ? "accepted" : "weakened";

  return result;
}

std::vector<Objection> Reviewer::challenge_evidence(const Finding& f) const {
  std::vector<Objection> objections;

  // No evidence at all
  if (f.evidence.empty()) {
    objections.push_back(
        {f.type, "No evidence provided — detection only, not confirmation", "Reproduce the finding with differential testing", 0.7});
  }

  // High severity but no payload
  if ((f.severity == "critical" || f.severity == "high") && f.payload.empty()) {
    objections.push_back({f.type, "Critical/high finding without a specific payload — how was it triggered?",
                          "Provide exact request that demonstrates the vulnerability", 0.5});
  }

  // SQL Injection without actual DB error
  if (f.type.find("SQL") != std::string::npos && f.evidence.find("SQL") == std::string::npos &&
      f.evidence.find("mysql") == std::string::npos && f.evidence.find("syntax") == std::string::npos) {
    objections.push_back(
        {f.type, "SQL injection claimed but no database error in evidence", "Test with time-based blind or trigger specific error", 0.6});
  }

  // XSS without reflection proof
  if (f.type.find("XSS") != std::string::npos && f.evidence.find("alert") == std::string::npos &&
      f.evidence.find("onerror") == std::string::npos && f.evidence.find("<script") == std::string::npos) {
    objections.push_back({f.type, "XSS claimed but payload not confirmed in evidence",
                          "Verify exact reflection context (in attribute? in JS? in HTML?)", 0.5});
  }

  return objections;
}

std::vector<Objection> Reviewer::find_alternatives(const Finding& f, const WorldModel& world) const {
  std::vector<Objection> objections;

  // Could the response be a generic error page?
  if (f.evidence.find("<!DOCTYPE") != std::string::npos || f.evidence.find("<HTML>") != std::string::npos) {
    objections.push_back({f.type, "Evidence contains HTML — possibly a generic error/WAF page, not actual vulnerability indicator",
                          "Compare with baseline response for this endpoint", 0.8});
  }

  // Could the status code 200 be misleading?
  if (f.type.find("Bypass") != std::string::npos || f.type.find("Access") != std::string::npos) {
    objections.push_back({f.type, "Access control bypass: does status 200 mean actual data access, or just a different error page?",
                          "Verify response contains actual protected content, not just a 200 with generic body", 0.4});
  }

  return objections;
}

std::vector<Objection> Reviewer::check_fp_indicators(const Finding& f) const {
  std::vector<Objection> objections;

  // WAF/CDN false positive indicators
  if (f.url.find("cloudflare") != std::string::npos || f.evidence.find("Attention Required") != std::string::npos ||
      f.evidence.find("Access Denied") != std::string::npos) {
    objections.push_back({f.type, "WAF/CDN response detected — this is likely a false positive",
                          "Retry with WAF evasion or confirm this is actual application response", 0.9});
  }

  // Timing-based without control test
  if (f.type.find("Time") != std::string::npos && f.type.find("Blind") != std::string::npos) {
    objections.push_back({f.type, "Time-based detection: network jitter could explain timing difference",
                          "Repeat with multiple sleep values (2s, 4s, 6s) — timing should be proportional", 0.4});
  }

  return objections;
}

}  // namespace cognitive
}  // namespace apex
