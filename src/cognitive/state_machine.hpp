/// @file cognitive/state_machine.hpp
/// @brief Application State Machine Discovery
///
/// Automatically discovers multi-step workflows and tests for:
/// - Step skipping (bypass payment, skip verification)
/// - Wrong order (refund before purchase)
/// - Permission boundaries (user A's workflow affects user B)
/// - Race conditions on state transitions
///
/// Works from crawl data (redirects, forms, URL sequences).
/// Extensible to authenticated flows when session is available.
#ifndef APEX_COGNITIVE_STATE_MACHINE_HPP
#define APEX_COGNITIVE_STATE_MACHINE_HPP

#include "../crawler.hpp"
#include "../http.hpp"
#include "../scanner.hpp"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace apex {
namespace cognitive {

/// A state in the application workflow.
struct AppState {
  std::string id;
  std::string url;
  std::string method;        // GET/POST
  std::string purpose;       // "login", "verify", "payment", "confirm"
  int sequence_position = 0; // Order in the workflow
};

/// A transition between states.
struct Transition {
  std::string from_state;
  std::string to_state;
  std::string trigger;       // "form_submit", "redirect", "link"
  bool requires_previous = true; // Must previous state be completed?
};

/// A discovered workflow.
struct Workflow {
  std::string name;          // "checkout", "registration", "password_reset"
  std::vector<AppState> states;
  std::vector<Transition> transitions;
  int total_steps = 0;
};

/// A workflow vulnerability.
struct WorkflowVuln {
  std::string type;          // "step_skip", "order_bypass", "state_confusion"
  std::string workflow;      // Which workflow
  std::string description;
  std::string skipped_step;  // Which step was bypassed
  std::string accessed_step; // Which step was reached directly
  double confidence = 0.0;
  std::string evidence;
};

/// Discover workflows from crawl data.
std::vector<Workflow> discover_workflows(const CrawlResult &crawl, HttpClient &http);

/// Test discovered workflows for logic flaws.
std::vector<WorkflowVuln> test_workflows(const std::vector<Workflow> &workflows,
                                          HttpClient &http);

/// Convert workflow vulns to scanner findings.
std::vector<Finding> workflow_to_findings(const std::vector<WorkflowVuln> &vulns);

} // namespace cognitive
} // namespace apex

#endif // APEX_COGNITIVE_STATE_MACHINE_HPP
