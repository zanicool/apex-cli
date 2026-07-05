/// @file brain.cpp
/// @brief LLM-powered attack planner using ollama.
#include "brain.hpp"
#include <array>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>

namespace apex {

Brain::Brain(const Config &cfg, HttpClient &http) : cfg_(cfg), http_(http) {}

BrainResult Brain::think_and_act(const std::vector<Finding> &findings,
                                 const std::string &target) {
  BrainResult result;

  // Build context from findings
  std::string context = build_context(findings, target);

  // Ask LLM for attack plan
  auto actions = plan(findings, context);
  result.actions = actions;

  // Execute each action and track results
  std::vector<std::pair<PlannedAction, std::string>> executed;
  for (const auto &action : actions) {
    std::string resp = execute_action(action);
    executed.push_back({action, resp});
    ++result.actions_executed;

    // Check if we found something interesting
    if (resp.find("FLAG{") != std::string::npos ||
        resp.find("root:") != std::string::npos ||
        resp.find("admin") != std::string::npos) {
      AttackChain chain;
      chain.complete = true;
      chain.impact = "LLM-guided exploitation successful";
      chain.proof = resp.substr(0, 500);
      for (const auto &[a, r] : executed) {
        ChainStep step;
        step.action = a.method;
        step.url = a.url;
        step.reason = a.reason;
        step.result = r.substr(0, 200);
        step.success = true;
        chain.steps.push_back(step);
      }
      chain.depth = static_cast<int>(chain.steps.size());
      result.chains.push_back(chain);
      ++result.chains_completed;
    }
  }

  result.summary = "Executed " + std::to_string(result.actions_executed) +
                   " actions, " + std::to_string(result.chains_completed) +
                   " chains completed";
  return result;
}

std::vector<PlannedAction>
Brain::plan(const std::vector<Finding> & /*findings*/,
            const std::string &context) {
  std::vector<PlannedAction> actions;

  // Build prompt
  std::string prompt =
      "You are a penetration tester. Given these findings, generate exactly 5 "
      "HTTP requests to escalate access. Output ONLY a JSON array, no "
      "explanation.\n\n"
      "Context:\n" +
      context +
      "\n\nOutput format:\n"
      "[{\"method\":\"GET\",\"url\":\"http://...\",\"body\":\"\","
      "\"reason\":\"...\"}]\n\n"
      "Rules:\n"
      "- Stay within scope (same host)\n"
      "- Focus on proving maximum impact\n"
      "- Chain findings together\n"
      "- Try to reach admin/root access\n";

  std::string response = call_llm(prompt);

  // Parse JSON array from response
  auto start = response.find('[');
  auto end = response.rfind(']');
  if (start == std::string::npos || end == std::string::npos)
    return actions;

  std::string json = response.substr(start, end - start + 1);

  // Simple per-field regex parsing
  std::regex url_re("\"url\"\\s*:\\s*\"([^\"]*)\"");
  std::regex method_re("\"method\"\\s*:\\s*\"([^\"]*)\"");
  std::regex reason_re("\"reason\"\\s*:\\s*\"([^\"]*)\"");
  std::regex body_re("\"body\"\\s*:\\s*\"([^\"]*)\"");

  // Split by },{  to get individual objects
  std::string obj;
  std::istringstream stream(json);
  while (std::getline(stream, obj, '}')) {
    PlannedAction a;
    std::smatch m;
    if (std::regex_search(obj, m, url_re))
      a.url = m[1].str();
    if (std::regex_search(obj, m, method_re))
      a.method = m[1].str();
    if (std::regex_search(obj, m, reason_re))
      a.reason = m[1].str();
    if (std::regex_search(obj, m, body_re))
      a.body = m[1].str();
    if (!a.url.empty() && !a.method.empty())
      actions.push_back(a);
  }

  return actions;
}

std::string Brain::execute_action(const PlannedAction &action) {
  // Scope check
  if (!cfg_.scope.empty() && action.url.find(cfg_.scope) == std::string::npos &&
      action.url.find(cfg_.target) == std::string::npos) {
    return "[blocked: out of scope]";
  }

  Response resp;
  if (action.method == "POST") {
    std::string ct = "application/x-www-form-urlencoded";
    if (action.body.find('{') == 0)
      ct = "application/json";
    resp = http_.post(action.url, action.body, ct);
  } else {
    resp = http_.get(action.url);
  }

  return resp.body.substr(0, 2000);
}

std::string Brain::build_context(const std::vector<Finding> &findings,
                                 const std::string &target) {
  std::ostringstream ctx;
  ctx << "Target: " << target << "\n";
  ctx << "Findings (" << findings.size() << "):\n";

  int shown = 0;
  for (const auto &f : findings) {
    if (f.severity == "info" && shown > 5)
      continue;
    ctx << "- [" << f.severity << "] " << f.type << " at " << f.url;
    if (!f.param.empty())
      ctx << " (param: " << f.param << ")";
    if (!f.evidence.empty())
      ctx << " evidence: " << f.evidence.substr(0, 100);
    ctx << "\n";
    if (++shown >= 15)
      break;
  }

  return ctx.str();
}

std::string Brain::call_llm(const std::string &prompt) {
  // Write prompt to temp file
  std::string tmp = "/tmp/apex-brain-prompt.txt";
  {
    std::ofstream f(tmp);
    f << prompt;
  }

  // Call ollama
  std::string model = "qwen3:14b"; // Fast, good enough for planning
  std::string cmd = "ollama run " + model + " < " + tmp + " 2>/dev/null";

  std::array<char, 4096> buffer;
  std::string result;
  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe)
    return "";

  while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
    result += buffer.data();
    if (result.size() > 8000)
      break; // Cap output
  }
  pclose(pipe);

  // Cleanup
  std::remove(tmp.c_str());
  return result;
}

} // namespace apex
