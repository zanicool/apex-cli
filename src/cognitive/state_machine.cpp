/// @file cognitive/state_machine.cpp
/// @brief Application State Machine Discovery implementation.
#include "state_machine.hpp"
#include <algorithm>
#include <regex>
#include <sstream>

namespace apex {
namespace cognitive {

namespace {

/// Infer purpose from URL/form action.
std::string infer_purpose(const std::string &url) {
  std::string lower = url;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

  if (lower.find("login") != std::string::npos || lower.find("signin") != std::string::npos)
    return "login";
  if (lower.find("register") != std::string::npos || lower.find("signup") != std::string::npos)
    return "register";
  if (lower.find("verify") != std::string::npos || lower.find("confirm") != std::string::npos)
    return "verify";
  if (lower.find("payment") != std::string::npos || lower.find("pay") != std::string::npos ||
      lower.find("checkout") != std::string::npos)
    return "payment";
  if (lower.find("order") != std::string::npos || lower.find("purchase") != std::string::npos)
    return "order";
  if (lower.find("refund") != std::string::npos || lower.find("return") != std::string::npos)
    return "refund";
  if (lower.find("reset") != std::string::npos || lower.find("forgot") != std::string::npos)
    return "reset";
  if (lower.find("profile") != std::string::npos || lower.find("settings") != std::string::npos)
    return "settings";
  if (lower.find("admin") != std::string::npos || lower.find("manage") != std::string::npos)
    return "admin";
  if (lower.find("complete") != std::string::npos || lower.find("success") != std::string::npos ||
      lower.find("thank") != std::string::npos)
    return "complete";
  if (lower.find("cart") != std::string::npos || lower.find("basket") != std::string::npos)
    return "cart";
  if (lower.find("shipping") != std::string::npos || lower.find("address") != std::string::npos)
    return "shipping";
  return "unknown";
}

/// Known workflow templates to match against.
struct WorkflowTemplate {
  std::string name;
  std::vector<std::string> expected_steps; // purposes in order
};

const std::vector<WorkflowTemplate> TEMPLATES = {
    {"registration", {"register", "verify", "complete"}},
    {"checkout", {"cart", "shipping", "payment", "complete"}},
    {"password_reset", {"reset", "verify", "complete"}},
    {"purchase", {"order", "payment", "complete"}},
    {"refund", {"order", "refund", "complete"}},
    {"onboarding", {"register", "profile", "verify", "complete"}},
};

} // namespace

std::vector<Workflow> discover_workflows(const CrawlResult &crawl, HttpClient &http) {
  std::vector<Workflow> workflows;

  // Step 1: Classify all endpoints by purpose
  std::map<std::string, std::vector<std::string>> purpose_map; // purpose → urls
  for (const auto &url : crawl.urls) {
    std::string purpose = infer_purpose(url);
    if (purpose != "unknown") {
      purpose_map[purpose].push_back(url);
    }
  }

  // Also classify form actions
  for (const auto &form : crawl.forms) {
    std::string purpose = infer_purpose(form.action);
    if (purpose != "unknown") {
      purpose_map[purpose].push_back(form.action);
    }
  }

  // Step 2: Match against known workflow templates
  for (const auto &tmpl : TEMPLATES) {
    int matched_steps = 0;
    Workflow wf;
    wf.name = tmpl.name;

    for (size_t i = 0; i < tmpl.expected_steps.size(); i++) {
      const auto &step = tmpl.expected_steps[i];
      auto it = purpose_map.find(step);
      if (it != purpose_map.end() && !it->second.empty()) {
        matched_steps++;
        AppState state;
        state.id = step + "_" + std::to_string(i);
        state.url = it->second[0];
        state.method = "GET"; // Assume GET for discovery
        state.purpose = step;
        state.sequence_position = i;
        wf.states.push_back(state);
      }
    }

    // If we found at least 2 steps of a workflow, it's worth testing
    if (matched_steps >= 2) {
      wf.total_steps = tmpl.expected_steps.size();

      // Build transitions
      for (size_t i = 0; i + 1 < wf.states.size(); i++) {
        Transition t;
        t.from_state = wf.states[i].id;
        t.to_state = wf.states[i + 1].id;
        t.trigger = "sequential";
        t.requires_previous = true;
        wf.transitions.push_back(t);
      }

      workflows.push_back(wf);
    }
  }

  return workflows;
}

std::vector<WorkflowVuln> test_workflows(const std::vector<Workflow> &workflows,
                                           HttpClient &http) {
  std::vector<WorkflowVuln> vulns;

  for (const auto &wf : workflows) {
    if (wf.states.size() < 2) continue;

    // Test 1: Step skipping — can we reach the final step without intermediate steps?
    auto &first = wf.states.front();
    auto &last = wf.states.back();

    // Try accessing the final step directly (without completing previous steps)
    auto direct = http.get(last.url);

    if (direct.status_code == 200 && direct.body.size() > 200 &&
        direct.body.find("login") == std::string::npos &&
        direct.body.find("error") == std::string::npos &&
        direct.body.find("redirect") == std::string::npos &&
        direct.body.find("unauthorized") == std::string::npos &&
        direct.body.find("Access Denied") == std::string::npos &&
        direct.body.find("<!DOCTYPE html><html id=\"__next_error__\"") == std::string::npos) {
      WorkflowVuln vuln;
      vuln.type = "step_skip";
      vuln.workflow = wf.name;
      vuln.description = "Final step of '" + wf.name + "' workflow accessible without "
                          "completing intermediate steps.";
      vuln.skipped_step = wf.states.size() > 1 ? wf.states[1].purpose : "intermediate";
      vuln.accessed_step = last.purpose;
      vuln.confidence = 0.6;
      vuln.evidence = "Direct GET to " + last.url + " returns 200 with " +
                      std::to_string(direct.body.size()) + " bytes content";
      vulns.push_back(vuln);
    }

    // Test 2: For each intermediate step, try skipping to the next
    for (size_t i = 0; i + 2 < wf.states.size(); i++) {
      auto &skip_to = wf.states[i + 2];
      auto resp = http.get(skip_to.url);

      if (resp.status_code == 200 && resp.body.size() > 200 &&
          resp.body.find("error") == std::string::npos &&
          resp.body.find("login") == std::string::npos &&
          resp.body.find("Access Denied") == std::string::npos) {
        WorkflowVuln vuln;
        vuln.type = "step_skip";
        vuln.workflow = wf.name;
        vuln.description = "Step '" + wf.states[i + 1].purpose + "' in '" + wf.name +
                            "' can be skipped — jumped directly to '" + skip_to.purpose + "'";
        vuln.skipped_step = wf.states[i + 1].purpose;
        vuln.accessed_step = skip_to.purpose;
        vuln.confidence = 0.5;
        vuln.evidence = "Status 200 with content on step " + std::to_string(i + 2);
        vulns.push_back(vuln);
        break; // One skip per workflow is enough evidence
      }
    }

    // Test 3: Can the refund/complete step be accessed from step 0?
    // (order bypass — skipping payment)
    if (wf.name == "checkout" || wf.name == "purchase") {
      for (const auto &state : wf.states) {
        if (state.purpose == "complete") {
          auto bypass = http.get(state.url);
          if (bypass.status_code == 200 && bypass.body.size() > 300 &&
              (bypass.body.find("success") != std::string::npos ||
               bypass.body.find("complete") != std::string::npos ||
               bypass.body.find("thank") != std::string::npos)) {
            WorkflowVuln vuln;
            vuln.type = "payment_bypass";
            vuln.workflow = wf.name;
            vuln.description = "Order completion page accessible without payment step. "
                                "Possible payment bypass vulnerability.";
            vuln.skipped_step = "payment";
            vuln.accessed_step = "complete";
            vuln.confidence = 0.7;
            vuln.evidence = "Completion page shows success indicators without prior payment";
            vulns.push_back(vuln);
          }
          break;
        }
      }
    }
  }

  return vulns;
}

std::vector<Finding> workflow_to_findings(const std::vector<WorkflowVuln> &vulns) {
  std::vector<Finding> findings;

  for (const auto &v : vulns) {
    std::string severity = "medium";
    if (v.type == "payment_bypass") severity = "critical";
    else if (v.confidence > 0.7) severity = "high";

    Finding f;
    f.type = "Workflow: " + v.type + " (" + v.workflow + ")";
    f.severity = severity;
    f.url = "";
    f.detail = v.description;
    f.param = v.skipped_step;
    f.payload = v.accessed_step;
    f.evidence = v.evidence;
    f.confidence = (int)(v.confidence * 100);
    f.cwe_id = "CWE-841";
    f.owasp_category = "A04:2021 Insecure Design";
    findings.push_back(f);
  }

  return findings;
}

} // namespace cognitive
} // namespace apex
