/// @file brain.hpp
/// @brief LLM-powered attack planner: analyzes findings and generates next steps.
#ifndef APEX_BRAIN_HPP
#define APEX_BRAIN_HPP

#include "chain.hpp"
#include "config.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// A planned action from the LLM.
struct PlannedAction {
  std::string method;  // GET, POST
  std::string url;
  std::string body;
  std::string reason;
  std::map<std::string, std::string> headers;
};

/// Result of LLM-driven exploitation.
struct BrainResult {
  std::vector<PlannedAction> actions;
  std::vector<AttackChain> chains;
  std::string summary;
  int actions_executed = 0;
  int chains_completed = 0;
};

/// LLM-powered attack brain.
class Brain {
public:
  explicit Brain(const Config &cfg, HttpClient &http);

  /// Analyze findings and execute LLM-planned attack chains.
  BrainResult think_and_act(const std::vector<Finding> &findings,
                            const std::string &target);

private:
  /// Ask LLM for next actions based on findings.
  std::vector<PlannedAction> plan(const std::vector<Finding> &findings,
                                  const std::string &context);

  /// Execute a planned action and return the response.
  std::string execute_action(const PlannedAction &action);

  /// Build context string from what we know.
  std::string build_context(const std::vector<Finding> &findings,
                            const std::string &target);

  /// Call ollama and return response text.
  std::string call_llm(const std::string &prompt);

  const Config &cfg_;
  HttpClient &http_;
};

} // namespace apex

#endif // APEX_BRAIN_HPP
