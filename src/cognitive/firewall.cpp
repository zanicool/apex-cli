/// @file cognitive/firewall.cpp
/// @brief Critical Validation Firewall implementation.
#include <algorithm>
#include "firewall.hpp"
#include <sstream>

namespace apex {
namespace cognitive {

namespace {

/// Check 1: Evidence integrity — is proof real and direct?
ValidationCheck check_evidence(const ExploitReport &report) {
  ValidationCheck c;
  c.name = "evidence_integrity";

  if (report.evidence.empty()) {
    c.passed = false;
    c.reason = "No evidence collected — cannot submit without proof";
    c.confidence_impact = -0.4;
    return c;
  }

  // Check for substance in evidence
  bool has_real_proof = false;
  for (const auto &ev : report.evidence) {
    if (ev.confidence > 0.6 && !ev.response.empty() && ev.response.size() > 10) {
      has_real_proof = true;
    }
    // Reject if evidence is just HTML error page
    if (ev.response.find("Access Denied") != std::string::npos ||
        ev.response.find("<!DOCTYPE html>") != std::string::npos ||
        ev.response.find("Page Not Found") != std::string::npos) {
      c.passed = false;
      c.reason = "Evidence contains generic error/WAF page — not actual vulnerability proof";
      c.confidence_impact = -0.5;
      return c;
    }
  }

  if (has_real_proof) {
    c.passed = true;
    c.reason = "Evidence contains substantive proof with confidence > 60%";
    c.confidence_impact = 0.1;
  } else {
    c.passed = false;
    c.reason = "Evidence exists but lacks substance (low confidence or empty responses)";
    c.confidence_impact = -0.2;
  }
  return c;
}

/// Check 2: Impact verification — is the claimed impact real?
ValidationCheck check_impact(const ExploitReport &report) {
  ValidationCheck c;
  c.name = "impact_verification";

  // Critical/high claims need strong justification
  if (report.severity == "critical" || report.severity == "high") {
    if (report.impact_analysis.size() < 50) {
      c.passed = false;
      c.reason = "High severity claimed but impact analysis is insufficient";
      c.confidence_impact = -0.3;
      return c;
    }

    // Check for inflated claims without proof
    bool claims_rce = report.impact_analysis.find("execute") != std::string::npos ||
                      report.impact_analysis.find("RCE") != std::string::npos;
    bool claims_full_access = report.impact_analysis.find("full access") != std::string::npos ||
                              report.impact_analysis.find("full compromise") != std::string::npos;

    if (claims_rce || claims_full_access) {
      // Need strong evidence for extreme claims
      bool has_strong_evidence = false;
      for (const auto &ev : report.evidence) {
        if (ev.confidence > 0.8) has_strong_evidence = true;
      }
      if (!has_strong_evidence) {
        c.passed = false;
        c.reason = "Extreme impact claim (RCE/full compromise) without high-confidence evidence";
        c.confidence_impact = -0.3;
        return c;
      }
    }
  }

  c.passed = true;
  c.reason = "Impact claim is proportional to evidence";
  c.confidence_impact = 0.05;
  return c;
}

/// Check 3: Alternative explanations — could this be something else?
ValidationCheck check_alternatives(const ExploitReport &report) {
  ValidationCheck c;
  c.name = "alternative_explanation";

  // Common false positive patterns
  std::string all_evidence;
  for (const auto &ev : report.evidence) all_evidence += ev.response + " ";

  // Pattern: generic 200 response (CDN/SPA serves everything as 200)
  if (all_evidence.find("<div id=\"root\">") != std::string::npos ||
      all_evidence.find("__next") != std::string::npos ||
      all_evidence.find("__nuxt") != std::string::npos) {
    if (report.title.find("Bypass") != std::string::npos ||
        report.title.find("Access") != std::string::npos) {
      c.passed = false;
      c.reason = "SPA/framework detected — 200 response may be client-side routing, not access granted";
      c.confidence_impact = -0.3;
      return c;
    }
  }

  // Pattern: response size too similar to baseline (no real difference)
  // (can't check this without baseline, but flag if evidence is very short)
  if (all_evidence.size() < 30 && report.severity == "critical") {
    c.passed = false;
    c.reason = "Evidence too minimal for critical claim — could be coincidental";
    c.confidence_impact = -0.2;
    return c;
  }

  c.passed = true;
  c.reason = "No obvious alternative explanations found";
  c.confidence_impact = 0.05;
  return c;
}

/// Check 4: Reproduction quality — can someone else reproduce this?
ValidationCheck check_reproduction(const ExploitReport &report) {
  ValidationCheck c;
  c.name = "reproduction_quality";

  if (report.reproduction.steps.empty()) {
    c.passed = false;
    c.reason = "No reproduction steps — triager cannot verify";
    c.confidence_impact = -0.3;
    return c;
  }

  if (report.reproduction.steps.size() < 2) {
    c.passed = false;
    c.reason = "Reproduction steps too brief — need at least 2 clear steps";
    c.confidence_impact = -0.15;
    return c;
  }

  // Check that steps include a request
  bool has_request = false;
  for (const auto &step : report.reproduction.steps) {
    if (step.find("http") != std::string::npos || step.find("curl") != std::string::npos ||
        step.find("Navigate") != std::string::npos || step.find("Send") != std::string::npos) {
      has_request = true;
    }
  }

  if (!has_request) {
    c.passed = false;
    c.reason = "Steps don't include a concrete request — how does triager test?";
    c.confidence_impact = -0.1;
    return c;
  }

  c.passed = true;
  c.reason = "Steps are clear and actionable";
  c.confidence_impact = 0.1;
  return c;
}

/// Check 5: Scope check — is this in-scope for the program?
ValidationCheck check_scope(const ExploitReport &report) {
  ValidationCheck c;
  c.name = "scope_check";

  // Check for common out-of-scope patterns
  std::string title_lower = report.title;
  std::transform(title_lower.begin(), title_lower.end(), title_lower.begin(), ::tolower);

  if (title_lower.find("missing header") != std::string::npos ||
      title_lower.find("missing hsts") != std::string::npos ||
      title_lower.find("missing csp") != std::string::npos) {
    if (report.severity == "critical" || report.severity == "high") {
      c.passed = false;
      c.reason = "Missing header findings are typically informational, not critical";
      c.confidence_impact = -0.4;
      return c;
    }
  }

  if (title_lower.find("version") != std::string::npos &&
      title_lower.find("disclosure") != std::string::npos) {
    c.passed = false;
    c.reason = "Version disclosure is commonly excluded from scope";
    c.confidence_impact = -0.3;
    return c;
  }

  c.passed = true;
  c.reason = "Finding appears to be in-scope";
  c.confidence_impact = 0.0;
  return c;
}

} // namespace

FirewallVerdict validate(const ExploitReport &report,
                          const CalibrationEngine &calibration) {
  FirewallVerdict verdict;

  // Run all checks
  verdict.checks.push_back(check_evidence(report));
  verdict.checks.push_back(check_impact(report));
  verdict.checks.push_back(check_alternatives(report));
  verdict.checks.push_back(check_reproduction(report));
  verdict.checks.push_back(check_scope(report));

  // Calculate final confidence
  double base_confidence = report.quality.submission_readiness;

  for (const auto &check : verdict.checks) {
    base_confidence += check.confidence_impact;
    if (!check.passed) {
      verdict.blockers.push_back(check.name + ": " + check.reason);
    }
  }

  // Apply calibration adjustment (historical accuracy correction)
  verdict.final_confidence = calibration.calibrate(base_confidence);
  verdict.final_confidence = std::max(0.0, std::min(1.0, verdict.final_confidence));

  // Gate decision
  if (verdict.final_confidence >= 0.75 && verdict.blockers.empty()) {
    verdict.approved = true;
    verdict.gate = "submit";
  } else if (verdict.final_confidence >= 0.5 && verdict.blockers.size() <= 1) {
    verdict.approved = false;
    verdict.gate = "needs_evidence";
  } else if (verdict.final_confidence >= 0.3) {
    verdict.approved = false;
    verdict.gate = "research_only";
  } else {
    verdict.approved = false;
    verdict.gate = "blocked";
  }

  // Add warnings for borderline cases
  if (verdict.final_confidence > 0.6 && verdict.final_confidence < 0.75) {
    verdict.warnings.push_back("Close to submission threshold — small improvement would unlock");
  }

  return verdict;
}

std::string render_verdict(const FirewallVerdict &verdict) {
  std::ostringstream out;

  out << "CRITICAL VALIDATION FIREWALL\n";
  out << "============================\n\n";

  out << "Final Confidence: " << (int)(verdict.final_confidence * 100) << "%\n";
  out << "Gate: " << verdict.gate << "\n";
  out << "Approved: " << (verdict.approved ? "YES ✓" : "NO ✗") << "\n\n";

  out << "Checks:\n";
  for (const auto &check : verdict.checks) {
    out << "  " << (check.passed ? "✓" : "✗") << " " << check.name << ": " << check.reason << "\n";
  }

  if (!verdict.blockers.empty()) {
    out << "\nBlockers:\n";
    for (const auto &b : verdict.blockers) out << "  ✗ " << b << "\n";
  }

  if (!verdict.warnings.empty()) {
    out << "\nWarnings:\n";
    for (const auto &w : verdict.warnings) out << "  ⚠ " << w << "\n";
  }

  return out.str();
}

} // namespace cognitive
} // namespace apex
