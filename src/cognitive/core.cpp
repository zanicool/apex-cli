/// @file cognitive/core.cpp
/// @brief Apex Cognitive Security Core v1 implementation.
#include "core.hpp"
#include <algorithm>
#include <cmath>
#include <sstream>

namespace apex {
namespace cognitive {

// ============================================================
// WORLD MODEL
// ============================================================

void WorldModel::add_belief(const Belief &belief) {
  // Update existing belief or add new one
  for (auto &b : beliefs) {
    if (b.subject == belief.subject && b.predicate == belief.predicate) {
      // Bayesian update: combine evidence
      b.confidence = 1.0 - (1.0 - b.confidence) * (1.0 - belief.confidence);
      if (!belief.evidence.empty()) b.evidence += "; " + belief.evidence;
      return;
    }
  }
  beliefs.push_back(belief);
}

double WorldModel::confidence_of(const std::string &subject,
                                  const std::string &predicate) const {
  for (const auto &b : beliefs) {
    if (b.subject == subject && b.predicate == predicate) return b.confidence;
  }
  return 0.0;
}

std::vector<Belief> WorldModel::beliefs_about(const std::string &subject) const {
  std::vector<Belief> result;
  for (const auto &b : beliefs) {
    if (b.subject == subject) result.push_back(b);
  }
  return result;
}

std::vector<std::string> WorldModel::priority_targets(int max) const {
  std::vector<std::pair<std::string, double>> scored;
  for (const auto &[url, score] : endpoint_importance) {
    scored.push_back({url, score});
  }
  std::sort(scored.begin(), scored.end(),
            [](const auto &a, const auto &b) { return a.second > b.second; });

  std::vector<std::string> result;
  for (int i = 0; i < max && i < (int)scored.size(); i++) {
    result.push_back(scored[i].first);
  }
  return result;
}

// ============================================================
// COGNITIVE CORE
// ============================================================

CognitiveCore::CognitiveCore() {
  knowledge_.load_default_knowledge();
}

void CognitiveCore::observe(const CrawlResult &crawl,
                             const std::vector<Finding> &findings,
                             const std::set<std::string> &technologies) {
  world_model_.target = crawl.urls.empty() ? "" : crawl.urls[0];
  world_model_.confirmed_technologies = technologies;

  // Observe endpoints and infer their nature
  for (const auto &url : crawl.urls) {
    world_model_.endpoint_importance[url] = 0.5; // Default
  }

  // Learn from findings
  for (const auto &f : findings) {
    world_model_.suspected_vulnerabilities.insert(f.type);
    // Increase importance of endpoints with findings
    if (world_model_.endpoint_importance.count(f.url)) {
      world_model_.endpoint_importance[f.url] =
          std::min(1.0, world_model_.endpoint_importance[f.url] + 0.2);
    }
  }

  // Run inference
  infer_endpoint_purposes();
  infer_auth_levels();
  infer_data_sensitivity();
}

void CognitiveCore::infer_endpoint_purposes() {
  for (auto &[url, importance] : world_model_.endpoint_importance) {
    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Financial
    if (lower.find("payment") != std::string::npos || lower.find("transfer") != std::string::npos ||
        lower.find("withdraw") != std::string::npos || lower.find("checkout") != std::string::npos ||
        lower.find("billing") != std::string::npos || lower.find("invoice") != std::string::npos) {
      world_model_.endpoint_purposes[url] = "financial";
      world_model_.add_belief({url, "handles_money", 0.9, "URL contains financial keyword", "url_pattern"});
      importance = std::max(importance, 0.95);
    }
    // Authentication
    else if (lower.find("login") != std::string::npos || lower.find("auth") != std::string::npos ||
             lower.find("register") != std::string::npos || lower.find("password") != std::string::npos ||
             lower.find("session") != std::string::npos || lower.find("token") != std::string::npos) {
      world_model_.endpoint_purposes[url] = "authentication";
      world_model_.add_belief({url, "handles_auth", 0.85, "URL contains auth keyword", "url_pattern"});
      importance = std::max(importance, 0.85);
    }
    // Admin
    else if (lower.find("admin") != std::string::npos || lower.find("manage") != std::string::npos ||
             lower.find("internal") != std::string::npos || lower.find("staff") != std::string::npos) {
      world_model_.endpoint_purposes[url] = "admin";
      world_model_.add_belief({url, "requires_admin", 0.8, "URL contains admin keyword", "url_pattern"});
      importance = std::max(importance, 0.9);
    }
    // User data
    else if (lower.find("user") != std::string::npos || lower.find("profile") != std::string::npos ||
             lower.find("account") != std::string::npos || lower.find("settings") != std::string::npos) {
      world_model_.endpoint_purposes[url] = "user_data";
      world_model_.add_belief({url, "handles_pii", 0.7, "URL contains user data keyword", "url_pattern"});
      importance = std::max(importance, 0.7);
    }
    // API
    else if (lower.find("/api/") != std::string::npos || lower.find("/v1/") != std::string::npos ||
             lower.find("/v2/") != std::string::npos) {
      world_model_.endpoint_purposes[url] = "api";
      importance = std::max(importance, 0.6);
    }
  }
}

void CognitiveCore::infer_auth_levels() {
  for (const auto &[url, purpose] : world_model_.endpoint_purposes) {
    if (purpose == "admin") {
      world_model_.add_belief({url, "auth_level", 0.8, "Admin endpoint likely requires auth", "inference"});
    } else if (purpose == "financial") {
      world_model_.add_belief({url, "auth_level", 0.9, "Financial endpoint requires auth", "inference"});
    }
  }
}

void CognitiveCore::infer_data_sensitivity() {
  for (const auto &tech : world_model_.confirmed_technologies) {
    auto risks = knowledge_.risks_for(tech);
    for (const auto &node : risks.nodes) {
      world_model_.add_belief({tech, "has_risk:" + node.label, 0.6,
                               "Knowledge graph indicates risk", "knowledge_graph"});
    }
  }
}

void CognitiveCore::hypothesize() {
  hypotheses_.clear();
  generate_vulnerability_hypotheses();
  generate_chain_hypotheses();
}

void CognitiveCore::generate_vulnerability_hypotheses() {
  int id = 0;

  // For each technology, query knowledge graph for likely vulns
  for (const auto &tech : world_model_.confirmed_technologies) {
    auto suggestions = knowledge_.suggest_next_tests(
        world_model_.confirmed_technologies,
        std::vector<std::string>(world_model_.suspected_vulnerabilities.begin(),
                                 world_model_.suspected_vulnerabilities.end()));

    for (const auto &suggestion : suggestions) {
      CognitiveHypothesis h;
      h.id = "CH" + std::to_string(++id);
      h.statement = "The application is likely vulnerable to " + suggestion +
                    " based on detected technology: " + tech;
      h.prior_probability = 0.4;
      h.posterior_probability = 0.4;
      h.test_method = "Run targeted " + suggestion + " checks on priority endpoints";
      h.status = "untested";
      h.supporting_beliefs.push_back(tech + " detected");
      hypotheses_.push_back(h);
    }
  }

  // For financial endpoints: race condition hypothesis
  for (const auto &[url, purpose] : world_model_.endpoint_purposes) {
    if (purpose == "financial") {
      CognitiveHypothesis h;
      h.id = "CH" + std::to_string(++id);
      h.statement = "Financial endpoint " + url + " may be vulnerable to race conditions (double-spend)";
      h.prior_probability = 0.3;
      h.posterior_probability = 0.3;
      h.test_method = "Send 20+ parallel requests to test atomicity";
      h.status = "untested";
      h.supporting_beliefs.push_back("endpoint handles money");
      hypotheses_.push_back(h);
    }
  }

  // For auth endpoints: bypass hypothesis
  for (const auto &[url, purpose] : world_model_.endpoint_purposes) {
    if (purpose == "authentication") {
      CognitiveHypothesis h;
      h.id = "CH" + std::to_string(++id);
      h.statement = "Auth endpoint " + url + " may have bypass vectors (rate limit, token leak, enumeration)";
      h.prior_probability = 0.35;
      h.posterior_probability = 0.35;
      h.test_method = "Test for rate limiting, user enumeration, and token predictability";
      h.status = "untested";
      h.supporting_beliefs.push_back("endpoint handles authentication");
      hypotheses_.push_back(h);
    }
  }
}

void CognitiveCore::generate_chain_hypotheses() {
  int id = hypotheses_.size();

  // If we have multiple vulnerability types, hypothesize chains
  if (world_model_.suspected_vulnerabilities.size() >= 2) {
    CognitiveHypothesis h;
    h.id = "CH" + std::to_string(++id);
    h.statement = "Multiple weaknesses (" +
                  std::to_string(world_model_.suspected_vulnerabilities.size()) +
                  ") may chain into a critical attack path";
    h.prior_probability = 0.5;
    h.posterior_probability = 0.5;
    h.test_method = "Analyze finding relationships via attack graph";
    h.status = "untested";
    hypotheses_.push_back(h);
  }
}

std::vector<Action> CognitiveCore::decide() {
  std::vector<Action> actions;

  // Generate actions from hypotheses
  for (const auto &h : hypotheses_) {
    if (h.status != "untested") continue;
    if (h.prior_probability < 0.25) continue; // Not worth testing

    Action action;
    action.type = "test_hypothesis";
    action.target = h.id;
    action.rationale = h.statement;
    action.expected_value = h.prior_probability;
    action.params["method"] = h.test_method;
    actions.push_back(action);
  }

  // Generate actions for high-importance unexplored endpoints
  auto priorities = world_model_.priority_targets(5);
  for (const auto &url : priorities) {
    Action action;
    action.type = "deep_scan";
    action.target = url;
    action.rationale = "High-importance endpoint (score: " +
                       std::to_string(world_model_.endpoint_importance[url]) + ")";
    action.expected_value = world_model_.endpoint_importance[url];
    actions.push_back(action);
  }

  // Sort by expected value
  std::sort(actions.begin(), actions.end(),
            [](const Action &a, const Action &b) {
              return a.expected_value > b.expected_value;
            });

  return actions;
}

void CognitiveCore::update(const CognitiveEvidence &evidence) {
  // Bayesian update on the hypothesis
  for (auto &h : hypotheses_) {
    if (h.id != evidence.hypothesis_id) continue;

    // Bayes' theorem: P(H|E) = P(E|H) * P(H) / P(E)
    double p_e = evidence.likelihood_if_true * h.prior_probability +
                 evidence.likelihood_if_false * (1.0 - h.prior_probability);

    if (p_e > 0) {
      h.posterior_probability =
          (evidence.likelihood_if_true * h.prior_probability) / p_e;
    }

    h.status = evidence.supports_hypothesis ? "confirmed" : "weakened";
    if (h.posterior_probability > 0.8) h.status = "confirmed";
    if (h.posterior_probability < 0.1) h.status = "rejected";

    break;
  }
}

std::vector<Action> CognitiveCore::think(const CrawlResult &crawl,
                                          const std::vector<Finding> &findings,
                                          const std::set<std::string> &technologies) {
  cycle_count_++;
  observe(crawl, findings, technologies);
  hypothesize();
  return decide();
}

std::string CognitiveCore::summary() const {
  std::ostringstream ss;
  ss << "=== Cognitive Core State (cycle " << cycle_count_ << ") ===\n\n";

  ss << "World Model:\n";
  ss << "  Beliefs: " << world_model_.beliefs.size() << "\n";
  ss << "  Endpoints profiled: " << world_model_.endpoint_importance.size() << "\n";
  ss << "  Technologies: " << world_model_.confirmed_technologies.size() << "\n";
  ss << "  Suspected vulns: " << world_model_.suspected_vulnerabilities.size() << "\n\n";

  ss << "Hypotheses: " << hypotheses_.size() << "\n";
  int untested = 0, confirmed = 0, rejected = 0;
  for (const auto &h : hypotheses_) {
    if (h.status == "untested") untested++;
    else if (h.status == "confirmed") confirmed++;
    else if (h.status == "rejected") rejected++;
  }
  ss << "  Untested: " << untested << "\n";
  ss << "  Confirmed: " << confirmed << "\n";
  ss << "  Rejected: " << rejected << "\n\n";

  ss << "Priority Targets:\n";
  auto targets = world_model_.priority_targets(5);
  for (const auto &t : targets) {
    ss << "  [" << (int)(world_model_.endpoint_importance.at(t) * 100) << "%] " << t << "\n";
  }

  return ss.str();
}

} // namespace cognitive
} // namespace apex
