/// @file cognitive/critical_path.cpp
/// @brief Critical Path Engine implementation.
///
/// Philosophy: 1 proven critical > 100 unverified mediums.
#include "critical_path.hpp"
#include <algorithm>
#include <sstream>

namespace apex {
namespace cognitive {

// ============================================================
// CRITICALITY SCORING
// ============================================================

CriticalityScore score_criticality(const Finding &f, const WorldModel &world) {
  CriticalityScore score;

  // Impact: what's the worst case?
  std::string type_lower = f.type;
  std::transform(type_lower.begin(), type_lower.end(), type_lower.begin(), ::tolower);

  if (type_lower.find("rce") != std::string::npos ||
      type_lower.find("command") != std::string::npos ||
      type_lower.find("deserialization") != std::string::npos) {
    score.impact = 1.0;
  } else if (type_lower.find("sql") != std::string::npos ||
             type_lower.find("takeover") != std::string::npos ||
             type_lower.find("bypass") != std::string::npos ||
             type_lower.find("payment") != std::string::npos) {
    score.impact = 0.9;
  } else if (type_lower.find("ssrf") != std::string::npos ||
             type_lower.find("idor") != std::string::npos ||
             type_lower.find("jwt") != std::string::npos ||
             type_lower.find("admin") != std::string::npos) {
    score.impact = 0.8;
  } else if (type_lower.find("xss") != std::string::npos ||
             type_lower.find("prototype") != std::string::npos) {
    score.impact = 0.6;
  } else if (type_lower.find("disclosure") != std::string::npos ||
             type_lower.find("header") != std::string::npos) {
    score.impact = 0.3;
  } else {
    score.impact = 0.5;
  }

  // Exploitability: how easy?
  if (!f.payload.empty() && !f.evidence.empty()) {
    score.exploitability = 0.9; // Have payload + evidence = easy to exploit
  } else if (!f.evidence.empty()) {
    score.exploitability = 0.7;
  } else if (!f.payload.empty()) {
    score.exploitability = 0.5;
  } else {
    score.exploitability = 0.3;
  }

  // Exposure: is this endpoint accessible?
  double endpoint_importance = 0.5;
  auto it = world.endpoint_importance.find(f.url);
  if (it != world.endpoint_importance.end()) {
    endpoint_importance = it->second;
  }
  score.exposure = endpoint_importance;

  // If it's a financial or auth endpoint, boost exposure
  if (type_lower.find("payment") != std::string::npos ||
      type_lower.find("transfer") != std::string::npos) {
    score.exposure = std::max(score.exposure, 0.95);
  }

  // Confidence from finding
  score.confidence = f.confidence / 100.0;
  if (score.confidence == 0.0) score.confidence = 0.5; // Default

  return score;
}

// ============================================================
// IMPACT CHAIN BUILDER
// ============================================================

std::vector<CriticalCandidate> build_impact_chains(
    const std::vector<Finding> &findings,
    const WorldModel &world) {

  std::vector<CriticalCandidate> chains;

  // Find findings that combine into critical chains
  bool has_info_leak = false, has_auth_issue = false, has_injection = false;
  bool has_ssrf = false, has_cloud = false, has_access_control = false;
  Finding info_finding, auth_finding, injection_finding, ssrf_finding, access_finding;

  for (const auto &f : findings) {
    std::string t = f.type;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);

    if (t.find("disclosure") != std::string::npos || t.find("exposed") != std::string::npos ||
        t.find("leak") != std::string::npos) {
      has_info_leak = true; info_finding = f;
    }
    if (t.find("auth") != std::string::npos || t.find("jwt") != std::string::npos ||
        t.find("session") != std::string::npos || t.find("bypass") != std::string::npos) {
      has_auth_issue = true; auth_finding = f;
    }
    if (t.find("sql") != std::string::npos || t.find("ssti") != std::string::npos ||
        t.find("injection") != std::string::npos || t.find("xss") != std::string::npos) {
      has_injection = true; injection_finding = f;
    }
    if (t.find("ssrf") != std::string::npos) {
      has_ssrf = true; ssrf_finding = f;
    }
    if (t.find("idor") != std::string::npos || t.find("access") != std::string::npos ||
        t.find("privilege") != std::string::npos) {
      has_access_control = true; access_finding = f;
    }
  }

  // Check if target is on cloud
  for (const auto &[url, purpose] : world.endpoint_purposes) {
    (void)url;
    (void)purpose;
  }
  has_cloud = !world.confirmed_technologies.empty() &&
              (world.confirmed_technologies.count("aws") || world.confirmed_technologies.count("gcp") ||
               world.confirmed_technologies.count("azure"));

  // Chain: Info Leak + Auth Issue = Account Takeover
  if (has_info_leak && has_auth_issue) {
    CriticalCandidate cc;
    cc.finding = auth_finding;
    cc.finding.type = "CHAIN: " + info_finding.type + " + " + auth_finding.type + " → Account Takeover";
    cc.finding.severity = "critical";
    cc.score.impact = 0.95;
    cc.score.exploitability = 0.7;
    cc.score.exposure = 0.9;
    cc.score.confidence = std::min(info_finding.confidence, auth_finding.confidence) / 100.0;
    cc.signals = {"information disclosure found", "authentication weakness found", "combination enables ATO"};
    cc.impact_narrative = "The information disclosure at " + info_finding.url +
                          " reveals enough context to exploit the authentication weakness at " +
                          auth_finding.url + ". Together, this enables account takeover.";
    cc.chain_context = "2-step chain";
    chains.push_back(cc);
  }

  // Chain: SSRF + Cloud = Infrastructure Compromise
  if (has_ssrf && has_cloud) {
    CriticalCandidate cc;
    cc.finding = ssrf_finding;
    cc.finding.type = "CHAIN: SSRF + Cloud Environment → Infrastructure Compromise";
    cc.finding.severity = "critical";
    cc.score.impact = 1.0;
    cc.score.exploitability = 0.8;
    cc.score.exposure = 0.9;
    cc.score.confidence = ssrf_finding.confidence / 100.0;
    cc.signals = {"SSRF confirmed", "cloud environment detected", "metadata endpoint likely reachable"};
    cc.impact_narrative = "SSRF at " + ssrf_finding.url + " in a cloud environment allows "
                          "accessing the metadata endpoint (169.254.169.254) to steal IAM credentials. "
                          "This gives full access to the cloud infrastructure.";
    cc.chain_context = "SSRF → cloud metadata → full compromise";
    chains.push_back(cc);
  }

  // Chain: Injection + Access Control = Data Breach
  if (has_injection && has_access_control) {
    CriticalCandidate cc;
    cc.finding = injection_finding;
    cc.finding.type = "CHAIN: " + injection_finding.type + " + " + access_finding.type + " → Data Breach";
    cc.finding.severity = "critical";
    cc.score.impact = 0.9;
    cc.score.exploitability = 0.75;
    cc.score.exposure = 0.85;
    cc.score.confidence = 0.6;
    cc.signals = {"injection point found", "access control weakness found", "data exfiltration path exists"};
    cc.impact_narrative = "Injection vulnerability combined with access control flaw "
                          "enables extraction of data beyond the attacker's authorization level.";
    cc.chain_context = "injection + access control bypass";
    chains.push_back(cc);
  }

  return chains;
}

// ============================================================
// MAIN CRITICAL PATH ANALYSIS
// ============================================================

std::vector<CriticalCandidate> find_criticals(
    const std::vector<Finding> &findings,
    const std::vector<Workflow> &workflows,
    const WorldModel &world,
    HttpClient &http) {

  std::vector<CriticalCandidate> candidates;

  // Step 1: Score all findings
  for (const auto &f : findings) {
    CriticalityScore score = score_criticality(f, world);

    // Only keep findings above criticality threshold
    if (score.total() < 0.15) continue;

    CriticalCandidate cc;
    cc.finding = f;
    cc.score = score;
    cc.signals.push_back("severity: " + f.severity);
    if (!f.evidence.empty()) cc.signals.push_back("has evidence");
    if (!f.payload.empty()) cc.signals.push_back("has payload");
    if (f.confidence > 70) cc.signals.push_back("high confidence");

    // Build impact narrative
    std::ostringstream narrative;
    narrative << f.type << " at " << f.url << ". ";
    if (score.impact >= 0.9) narrative << "Critical impact: could lead to full compromise. ";
    if (score.exploitability >= 0.8) narrative << "Easily exploitable with provided payload. ";
    cc.impact_narrative = narrative.str();

    candidates.push_back(cc);
  }

  // Step 2: Add workflow-based critical candidates
  for (const auto &wf : workflows) {
    // Convert workflow findings to critical candidates
    auto wf_vulns = test_workflows({wf}, http);
    for (const auto &v : wf_vulns) {
      if (v.type == "payment_bypass" || v.confidence > 0.6) {
        CriticalCandidate cc;
        cc.finding.type = "Business Logic: " + v.type;
        cc.finding.severity = v.type == "payment_bypass" ? "critical" : "high";
        cc.finding.detail = v.description;
        cc.finding.evidence = v.evidence;
        cc.score.impact = v.type == "payment_bypass" ? 1.0 : 0.7;
        cc.score.exploitability = 0.9; // Business logic = easy to exploit
        cc.score.exposure = 0.8;
        cc.score.confidence = v.confidence;
        cc.signals.push_back("workflow analysis");
        cc.signals.push_back(v.type);
        cc.impact_narrative = v.description;
        candidates.push_back(cc);
      }
    }
  }

  // Step 3: Build impact chains (combinations)
  auto chains = build_impact_chains(findings, world);
  candidates.insert(candidates.end(), chains.begin(), chains.end());

  // Step 4: Sort by criticality score (highest first)
  std::sort(candidates.begin(), candidates.end(),
            [](const CriticalCandidate &a, const CriticalCandidate &b) {
              return a.score.total() > b.score.total();
            });

  // Step 5: Keep only top candidates (focus, not flood)
  if (candidates.size() > 10) candidates.resize(10);

  return candidates;
}

} // namespace cognitive
} // namespace apex
