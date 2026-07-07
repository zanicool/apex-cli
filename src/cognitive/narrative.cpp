/// @file cognitive/narrative.cpp
/// @brief Exploit Narrative & Evidence Engine implementation.
#include "narrative.hpp"
#include <algorithm>
#include <sstream>

namespace apex {
namespace cognitive {

ExploitReport build_report(const CriticalCandidate &candidate, HttpClient &http) {
  ExploitReport report;
  const auto &f = candidate.finding;

  // Title
  report.title = f.type;
  report.severity = f.severity;
  report.asset = f.url;
  report.cwe = f.cwe_id;

  // Summary
  std::ostringstream summary;
  summary << f.type << " was discovered at " << f.url << ". ";
  if (!candidate.impact_narrative.empty()) {
    summary << candidate.impact_narrative;
  } else {
    summary << "This vulnerability has " << f.severity << " impact.";
  }
  report.summary = summary.str();

  // Reproduction steps
  report.reproduction.precondition = "Unauthenticated attacker with network access to " + f.url;

  if (!f.payload.empty()) {
    report.reproduction.steps.push_back("Navigate to: " + f.url);
    if (!f.param.empty()) {
      report.reproduction.steps.push_back("Inject payload in parameter '" + f.param + "': " + f.payload);
    } else {
      report.reproduction.steps.push_back("Send request with payload: " + f.payload);
    }
    report.reproduction.steps.push_back("Observe the response for vulnerability indicators");
  } else {
    report.reproduction.steps.push_back("Send request to: " + f.url);
    report.reproduction.steps.push_back("Observe the response");
  }

  report.reproduction.expected_result = "The server should reject malicious input or restrict access.";
  report.reproduction.actual_result = f.detail;
  report.reproduction.impact = candidate.impact_narrative;

  // Evidence
  if (!f.evidence.empty()) {
    EvidenceItem ev;
    ev.type = "response";
    ev.description = "Server response contains vulnerability indicator";
    ev.request = f.url + (f.payload.empty() ? "" : " [payload: " + f.payload + "]");
    ev.response = f.evidence;
    ev.confidence = f.confidence / 100.0;
    report.evidence.push_back(ev);
  }

  // Try to get fresh evidence by replaying
  if (!f.url.empty() && f.url.find("http") == 0) {
    auto replay = http.get(f.url);
    if (replay.status_code > 0) {
      EvidenceItem ev;
      ev.type = "replay";
      ev.description = "Replayed request to confirm finding";
      ev.request = "GET " + f.url;
      ev.response_code = replay.status_code;
      ev.response = replay.body.substr(0, 300);
      ev.confidence = replay.status_code == 200 ? 0.7 : 0.3;
      report.evidence.push_back(ev);
    }
  }

  // Impact analysis
  std::ostringstream impact;
  impact << "Impact: " << f.severity << "\n\n";
  if (candidate.score.impact >= 0.9) {
    impact << "This vulnerability allows an attacker to ";
    std::string t = f.type;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);
    if (t.find("sql") != std::string::npos) impact << "extract or modify database contents";
    else if (t.find("rce") != std::string::npos || t.find("command") != std::string::npos) impact << "execute arbitrary commands on the server";
    else if (t.find("takeover") != std::string::npos || t.find("bypass") != std::string::npos) impact << "gain unauthorized access to user accounts";
    else if (t.find("ssrf") != std::string::npos) impact << "make server-side requests to internal infrastructure";
    else if (t.find("payment") != std::string::npos) impact << "bypass payment controls, causing financial loss";
    else impact << "compromise the security of the application";
    impact << ".\n\n";
    impact << "Affected users: All users of the application.\n";
    impact << "Business impact: " << (candidate.score.impact >= 0.9 ? "Critical" : "High") << "\n";
  }
  report.impact_analysis = impact.str();

  // Root cause
  if (!f.cwe_id.empty()) {
    report.root_cause = f.cwe_id + ": " + f.type + "\n"
                        "The application does not properly validate/authorize the affected operation.";
  } else {
    report.root_cause = "Missing input validation or access control on the affected endpoint.";
  }

  // Remediation
  std::string t = f.type;
  std::transform(t.begin(), t.end(), t.begin(), ::tolower);
  if (t.find("sql") != std::string::npos) {
    report.remediation = "Use parameterized queries/prepared statements. Never concatenate user input into SQL.";
  } else if (t.find("xss") != std::string::npos) {
    report.remediation = "Encode all user output contextually. Implement Content-Security-Policy.";
  } else if (t.find("ssrf") != std::string::npos) {
    report.remediation = "Validate and allowlist URLs. Block private IP ranges. Use DNS rebinding protection.";
  } else if (t.find("bypass") != std::string::npos || t.find("access") != std::string::npos) {
    report.remediation = "Implement server-side authorization checks. Never trust client-side role data.";
  } else if (t.find("payment") != std::string::npos) {
    report.remediation = "Enforce workflow state server-side. Verify payment completion before order fulfillment.";
  } else {
    report.remediation = "Implement proper input validation and access controls on the affected endpoint.";
  }

  // Assess quality
  report.quality = assess_quality(report);

  return report;
}

ReportQuality assess_quality(const ExploitReport &report) {
  ReportQuality q;

  // Evidence quality
  if (report.evidence.empty()) {
    q.evidence_quality = 0.1;
    q.missing.push_back("No evidence collected — need proof of exploitation");
  } else {
    q.evidence_quality = std::min(1.0, report.evidence.size() * 0.4);
    for (const auto &ev : report.evidence) {
      if (ev.confidence > 0.7) q.evidence_quality = std::min(1.0, q.evidence_quality + 0.2);
    }
  }

  // Reproducibility
  if (report.reproduction.steps.empty()) {
    q.reproducibility = 0.1;
    q.missing.push_back("No reproduction steps");
  } else if (report.reproduction.steps.size() >= 3) {
    q.reproducibility = 0.9;
  } else {
    q.reproducibility = 0.5;
    q.missing.push_back("More detailed reproduction steps needed");
  }

  // Impact clarity
  if (report.impact_analysis.size() > 100) {
    q.impact_clarity = 0.8;
  } else if (report.impact_analysis.size() > 30) {
    q.impact_clarity = 0.5;
  } else {
    q.impact_clarity = 0.2;
    q.missing.push_back("Impact analysis needs more detail");
  }

  // Root cause
  if (!report.root_cause.empty() && !report.cwe.empty()) {
    q.root_cause_clarity = 0.9;
  } else if (!report.root_cause.empty()) {
    q.root_cause_clarity = 0.6;
  } else {
    q.root_cause_clarity = 0.2;
    q.missing.push_back("Root cause analysis missing");
  }

  // Overall submission readiness
  q.submission_readiness = (q.evidence_quality + q.reproducibility +
                            q.impact_clarity + q.root_cause_clarity) / 4.0;

  // Verdict
  if (q.submission_readiness >= 0.75) {
    q.verdict = "submit";
  } else if (q.submission_readiness >= 0.5) {
    q.verdict = "needs_work";
  } else {
    q.verdict = "insufficient";
  }

  return q;
}

std::string render_report(const ExploitReport &report) {
  std::ostringstream out;

  out << "**Title:** " << report.title << "\n\n";
  out << "**Severity:** " << report.severity << "\n\n";
  out << "**Asset:** " << report.asset << "\n\n";

  out << "**Summary:**\n\n" << report.summary << "\n\n";

  out << "**Steps to Reproduce:**\n\n";
  out << "Precondition: " << report.reproduction.precondition << "\n\n";
  for (size_t i = 0; i < report.reproduction.steps.size(); i++) {
    out << (i + 1) << ". " << report.reproduction.steps[i] << "\n";
  }
  out << "\n**Expected Result:** " << report.reproduction.expected_result << "\n\n";
  out << "**Actual Result:** " << report.reproduction.actual_result << "\n\n";

  if (!report.evidence.empty()) {
    out << "**Evidence:**\n\n";
    for (const auto &ev : report.evidence) {
      out << "- " << ev.description;
      if (ev.response_code > 0) out << " (HTTP " << ev.response_code << ")";
      out << "\n";
      if (!ev.response.empty()) {
        out << "  ```\n  " << ev.response.substr(0, 200) << "\n  ```\n";
      }
    }
    out << "\n";
  }

  out << "**Impact:**\n\n" << report.impact_analysis << "\n\n";
  out << "**Root Cause:** " << report.root_cause << "\n\n";
  out << "**Remediation:** " << report.remediation << "\n\n";

  if (!report.cwe.empty()) out << "**References:** " << report.cwe << "\n\n";

  // Quality assessment footer
  out << "---\n";
  out << "Submission Readiness: " << (int)(report.quality.submission_readiness * 100) << "%\n";
  out << "Verdict: " << report.quality.verdict << "\n";
  if (!report.quality.missing.empty()) {
    out << "Missing:\n";
    for (const auto &m : report.quality.missing) out << "  - " << m << "\n";
  }

  return out.str();
}

} // namespace cognitive
} // namespace apex
