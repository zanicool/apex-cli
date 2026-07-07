/// @file cognitive/learning.cpp
/// @brief Experimental Learning Framework implementation.
#include "learning.hpp"
#include <algorithm>
#include <fstream>
#include <numeric>
#include <sstream>

namespace apex {
namespace cognitive {

void LearningEngine::record(const Experiment &experiment) {
  experiments_.push_back(experiment);
  if ((int)experiments_.size() > MAX_EXPERIMENTS) {
    experiments_.pop_front();
  }

  // Update strategy performance
  std::string key = make_key(experiment.action, experiment.technology_context);
  strategy_performance_[key].strategy = experiment.action;
  strategy_performance_[key].context = experiment.technology_context;
  strategy_performance_[key].update(experiment.produced_finding, experiment.actual_gain);
}

std::pair<std::string, double> LearningEngine::best_strategy_for(
    const std::string &context) const {
  std::string best;
  double best_rate = 0.0;

  for (const auto &[key, record] : strategy_performance_) {
    if (key.find(context) != std::string::npos || record.context == context) {
      if (record.success_rate > best_rate && record.attempts >= 3) {
        best_rate = record.success_rate;
        best = record.strategy;
      }
    }
  }

  // If no context-specific data, look for strategy across all contexts
  if (best.empty()) {
    for (const auto &[key, record] : strategy_performance_) {
      if (record.success_rate > best_rate && record.attempts >= 5) {
        best_rate = record.success_rate;
        best = record.strategy;
      }
    }
  }

  return {best, best_rate};
}

std::vector<StrategyRecord> LearningEngine::ranked_strategies(
    const std::string &context) const {
  std::vector<StrategyRecord> relevant;

  for (const auto &[key, record] : strategy_performance_) {
    if (context.empty() || key.find(context) != std::string::npos ||
        record.context == context) {
      if (record.attempts >= 2) {
        relevant.push_back(record);
      }
    }
  }

  std::sort(relevant.begin(), relevant.end(),
            [](const StrategyRecord &a, const StrategyRecord &b) {
              return a.success_rate > b.success_rate;
            });

  return relevant;
}

double LearningEngine::adjusted_value(const std::string &strategy,
                                       const std::string &context,
                                       double raw_expected_value) const {
  std::string key = make_key(strategy, context);
  auto it = strategy_performance_.find(key);

  if (it == strategy_performance_.end() || it->second.attempts < 3) {
    return raw_expected_value; // Not enough data, trust the raw estimate
  }

  // Blend raw estimate with historical performance
  // More data = more weight on historical
  double data_weight = std::min(0.8, it->second.attempts / 20.0);
  double historical = it->second.avg_gain;
  double blended = raw_expected_value * (1.0 - data_weight) + historical * data_weight;

  return blended;
}

LearningMetrics LearningEngine::metrics() const {
  LearningMetrics m;
  if (experiments_.empty()) return m;

  m.total_experiments = experiments_.size();
  double total_gain = 0.0;
  int false_hypotheses = 0;
  int wasted = 0;

  for (const auto &exp : experiments_) {
    if (exp.produced_finding) m.useful_experiments++;
    else wasted++;
    if (exp.actual_gain < 0.1 && exp.expected_gain > 0.5) false_hypotheses++;
    total_gain += exp.actual_gain;
  }

  m.avg_information_gain = total_gain / m.total_experiments;
  m.wasted_action_rate = (double)wasted / m.total_experiments;
  m.false_hypothesis_rate = (double)false_hypotheses / m.total_experiments;

  // Find best and worst strategies
  double best_rate = 0.0, worst_rate = 1.0;
  for (const auto &[key, record] : strategy_performance_) {
    if (record.attempts < 3) continue;
    if (record.success_rate > best_rate) {
      best_rate = record.success_rate;
      m.best_strategy = record.strategy + " in " + record.context +
                         " (" + std::to_string((int)(best_rate * 100)) + "%)";
    }
    if (record.success_rate < worst_rate) {
      worst_rate = record.success_rate;
      m.worst_strategy = record.strategy + " in " + record.context +
                          " (" + std::to_string((int)(worst_rate * 100)) + "%)";
    }
  }

  // Improvement: compare recent performance vs early performance
  if (experiments_.size() >= 20) {
    double early_gain = 0, recent_gain = 0;
    int half = experiments_.size() / 2;
    for (int i = 0; i < half; i++) early_gain += experiments_[i].actual_gain;
    for (int i = half; i < (int)experiments_.size(); i++) recent_gain += experiments_[i].actual_gain;
    early_gain /= half;
    recent_gain /= (experiments_.size() - half);
    m.improvement_over_baseline = (recent_gain - early_gain) / std::max(0.01, early_gain);
  }

  return m;
}

std::string LearningEngine::summary() const {
  auto m = metrics();
  std::ostringstream ss;
  ss << "Learning Engine (" << m.total_experiments << " experiments):\n";
  ss << "  Useful actions: " << m.useful_experiments << "/" << m.total_experiments
     << " (" << (int)((1.0 - m.wasted_action_rate) * 100) << "% efficiency)\n";
  ss << "  Avg information gain: " << (int)(m.avg_information_gain * 100) << "%\n";
  ss << "  False hypothesis rate: " << (int)(m.false_hypothesis_rate * 100) << "%\n";
  ss << "  Wasted actions: " << (int)(m.wasted_action_rate * 100) << "%\n";
  if (!m.best_strategy.empty())
    ss << "  Best strategy: " << m.best_strategy << "\n";
  if (!m.worst_strategy.empty())
    ss << "  Worst strategy: " << m.worst_strategy << "\n";
  if (m.total_experiments >= 20)
    ss << "  Improvement: " << (m.improvement_over_baseline > 0 ? "+" : "")
       << (int)(m.improvement_over_baseline * 100) << "% vs baseline\n";
  return ss.str();
}

void LearningEngine::save(const std::string &path) const {
  std::ofstream out(path);
  if (!out.is_open()) return;

  out << "{\n  \"strategies\": [\n";
  bool first = true;
  for (const auto &[key, record] : strategy_performance_) {
    if (!first) out << ",\n";
    first = false;
    out << "    {\"strategy\":\"" << record.strategy << "\","
        << "\"context\":\"" << record.context << "\","
        << "\"attempts\":" << record.attempts << ","
        << "\"successes\":" << record.successes << ","
        << "\"avg_gain\":" << record.avg_gain << ","
        << "\"success_rate\":" << record.success_rate << "}";
  }
  out << "\n  ]\n}\n";
}

void LearningEngine::load(const std::string &path) {
  // Simple load — parse strategy records from JSON
  std::ifstream in(path);
  if (!in.is_open()) return;

  std::string content((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());

  // Basic parsing (production would use a JSON library)
  // For now, the save format is enough to prove the concept
  // TODO: implement proper JSON parsing for persistence
}

} // namespace cognitive
} // namespace apex
