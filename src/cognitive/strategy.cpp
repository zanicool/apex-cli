/// @file cognitive/strategy.cpp
/// @brief Research Strategy Optimizer implementation.
#include "strategy.hpp"
#include <algorithm>
#include <cmath>
#include <sstream>

namespace apex {
namespace cognitive {

std::vector<Opportunity> rank_opportunities(const WorldModel &world,
                                             const LearningEngine &learning) {
  std::vector<Opportunity> opportunities;

  // Generate opportunities from world model beliefs and endpoint purposes
  for (const auto &[url, purpose] : world.endpoint_purposes) {
    Opportunity opp;
    opp.target_url = url;
    opp.technology = "";
    for (const auto &t : world.confirmed_technologies) opp.technology += t + "+";
    if (!opp.technology.empty()) opp.technology.pop_back();

    // Determine area and base probability
    if (purpose == "financial") {
      opp.area = "payment_logic";
      opp.probability_of_critical = 0.35;
      opp.potential_impact = 1.0;
      opp.cost = 0.4;
      opp.rationale = "Financial endpoint — race conditions, amount manipulation, bypass";
    } else if (purpose == "authentication") {
      opp.area = "authentication";
      opp.probability_of_critical = 0.3;
      opp.potential_impact = 0.9;
      opp.cost = 0.3;
      opp.rationale = "Auth endpoint — bypass, enumeration, token weakness";
    } else if (purpose == "admin") {
      opp.area = "authorization";
      opp.probability_of_critical = 0.25;
      opp.potential_impact = 0.95;
      opp.cost = 0.3;
      opp.rationale = "Admin endpoint — privilege escalation, access control bypass";
    } else if (purpose == "user_data") {
      opp.area = "data_access";
      opp.probability_of_critical = 0.2;
      opp.potential_impact = 0.7;
      opp.cost = 0.3;
      opp.rationale = "User data endpoint — IDOR, mass assignment, PII exposure";
    } else if (purpose == "api") {
      opp.area = "api_security";
      opp.probability_of_critical = 0.15;
      opp.potential_impact = 0.6;
      opp.cost = 0.4;
      opp.rationale = "API endpoint — injection, schema abuse, auth issues";
    } else {
      continue; // Skip low-value endpoints
    }

    // Adjust probability based on historical learning
    auto [best_strat, success_rate] = learning.best_strategy_for(opp.technology);
    if (success_rate > 0 && best_strat.find(opp.area) != std::string::npos) {
      opp.probability_of_critical *= (1.0 + success_rate); // Boost if historically successful
    }

    // Novelty: higher if we haven't found much here yet
    double beliefs_about = world.beliefs_about(url).size();
    opp.novelty = std::max(0.2, 1.0 - (beliefs_about / 10.0));

    // Calculate research value
    opp.research_value = (opp.probability_of_critical * opp.potential_impact * opp.novelty) /
                          std::max(0.1, opp.cost);

    opportunities.push_back(opp);
  }

  // Add technology-based opportunities (not tied to specific endpoint)
  for (const auto &tech : world.confirmed_technologies) {
    if (tech == "jwt") {
      Opportunity opp;
      opp.area = "jwt_analysis";
      opp.technology = tech;
      opp.probability_of_critical = 0.25;
      opp.potential_impact = 0.9;
      opp.novelty = 0.8;
      opp.cost = 0.2;
      opp.research_value = (0.25 * 0.9 * 0.8) / 0.2;
      opp.rationale = "JWT detected — algorithm confusion, weak secret, token forgery";
      opportunities.push_back(opp);
    }
    if (tech == "graphql") {
      Opportunity opp;
      opp.area = "graphql_abuse";
      opp.technology = tech;
      opp.probability_of_critical = 0.2;
      opp.potential_impact = 0.7;
      opp.novelty = 0.7;
      opp.cost = 0.3;
      opp.research_value = (0.2 * 0.7 * 0.7) / 0.3;
      opp.rationale = "GraphQL — introspection, batch abuse, authorization bypass";
      opportunities.push_back(opp);
    }
  }

  // Sort by research value (highest first)
  std::sort(opportunities.begin(), opportunities.end(),
            [](const Opportunity &a, const Opportunity &b) {
              return a.research_value > b.research_value;
            });

  return opportunities;
}

ResearchPlan plan_research(const WorldModel &world,
                            const LearningEngine &learning,
                            int budget) {
  ResearchPlan plan;
  plan.target = world.target;
  plan.total_budget = budget;

  // Rank opportunities
  plan.opportunities = rank_opportunities(world, learning);

  // Allocate budget proportional to research value
  double total_value = 0;
  for (const auto &opp : plan.opportunities) total_value += opp.research_value;

  if (total_value == 0) {
    // No clear opportunities — spread evenly
    BudgetAllocation ba;
    ba.area = "general";
    ba.allocated_actions = budget;
    ba.weight = 1.0;
    ba.reason = "No clear high-value targets — general scan";
    plan.allocations.push_back(ba);
  } else {
    // Group by area and allocate
    std::map<std::string, double> area_values;
    std::map<std::string, std::string> area_reasons;
    for (const auto &opp : plan.opportunities) {
      area_values[opp.area] += opp.research_value;
      if (area_reasons[opp.area].empty()) area_reasons[opp.area] = opp.rationale;
    }

    for (const auto &[area, value] : area_values) {
      BudgetAllocation ba;
      ba.area = area;
      ba.weight = value / total_value;
      ba.allocated_actions = std::max(5, (int)(ba.weight * budget));
      ba.reason = area_reasons[area];
      plan.allocations.push_back(ba);
    }

    // Sort allocations by weight
    std::sort(plan.allocations.begin(), plan.allocations.end(),
              [](const BudgetAllocation &a, const BudgetAllocation &b) {
                return a.weight > b.weight;
              });
  }

  // Generate summary
  std::ostringstream ss;
  ss << "Research Plan for " << world.target << "\n";
  ss << "Budget: " << budget << " actions\n\n";
  ss << "Strategy:\n";
  for (size_t i = 0; i < plan.allocations.size() && i < 5; i++) {
    auto &a = plan.allocations[i];
    ss << "  " << (i + 1) << ". " << a.area << " (" << a.allocated_actions << " actions, "
       << (int)(a.weight * 100) << "%)\n";
    ss << "     Reason: " << a.reason << "\n";
  }
  ss << "\nHighest value targets:\n";
  for (size_t i = 0; i < plan.opportunities.size() && i < 3; i++) {
    auto &o = plan.opportunities[i];
    ss << "  → " << o.target_url << " [value: " << (int)(o.research_value * 100) << "]\n";
    ss << "    " << o.rationale << "\n";
  }
  plan.summary = ss.str();

  return plan;
}

} // namespace cognitive
} // namespace apex
