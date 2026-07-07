/// @file cognitive/strategy.hpp
/// @brief Research Strategy Optimizer — spend time where criticals are most likely.
///
/// Not more tests. Smarter choices.
/// A researcher wins by seeing the weak spot faster, not by running more payloads.
#ifndef APEX_COGNITIVE_STRATEGY_HPP
#define APEX_COGNITIVE_STRATEGY_HPP

#include "core.hpp"
#include "learning.hpp"
#include <string>
#include <vector>

namespace apex {
namespace cognitive {

/// A research opportunity — where should Apex invest time?
struct Opportunity {
  std::string area;              // "authentication", "payment", "authorization"
  std::string target_url;        // Specific endpoint or pattern
  std::string technology;        // Relevant tech stack
  double probability_of_critical;// 0-1: how likely to find a critical
  double potential_impact;       // 0-1: how bad if exploited
  double novelty;                // 0-1: how unexplored (less tested = more novel)
  double cost;                   // 0-1: how expensive to test (time/requests)
  double research_value;         // Final score: (prob × impact × novelty) / cost
  std::string rationale;         // Why this is a good bet
};

/// Research budget allocation.
struct BudgetAllocation {
  std::string area;
  int allocated_actions;   // How many test actions to spend here
  double weight;           // 0-1: proportion of total budget
  std::string reason;
};

/// A complete research plan for a target.
struct ResearchPlan {
  std::string target;
  int total_budget;         // Total actions available
  std::vector<Opportunity> opportunities; // Ranked by value
  std::vector<BudgetAllocation> allocations; // How to spend the budget
  std::string summary;
};

/// Generate a research plan based on world model + historical learning.
ResearchPlan plan_research(const WorldModel &world,
                            const LearningEngine &learning,
                            int budget = 100);

/// Rank opportunities by research value.
std::vector<Opportunity> rank_opportunities(const WorldModel &world,
                                             const LearningEngine &learning);

} // namespace cognitive
} // namespace apex

#endif // APEX_COGNITIVE_STRATEGY_HPP
