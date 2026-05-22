/// @file impact.cpp
/// @brief Impact prover and HackerOne report generator.
#include "impact.hpp"
#include <sstream>

namespace apex {

namespace {

struct ImpactTemplate {
  const char *type;
  const char *severity;
  const char *description;
  const char *fix;
  const char *owasp;
};

const ImpactTemplate kTemplates[] = {
    {"IDOR", "high",
     "Unauthorized access to other users' data via insecure direct object reference",
     "Implement proper authorization checks on all object references. Use indirect references or verify ownership.",
     "A01:2021 Broken Access Control"},
    {"SSRF", "critical",
     "Server-side request forgery allowing access to internal services and cloud metadata",
     "Validate and whitelist allowed URLs. Block internal IP ranges. Use network segmentation.",
     "A10:2021 SSRF"},
    {"SQLi", "critical",
     "SQL injection allowing database extraction and potential remote code execution",
     "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
     "A03:2021 Injection"},
    {"JWT", "high",
     "JWT authentication bypass via weak secret or algorithm confusion",
     "Use strong secrets (256+ bits). Explicitly specify allowed algorithms. Validate all claims.",
     "A07:2021 Identification and Authentication Failures"},
    {"LFI", "high",
     "Local file inclusion allowing arbitrary file read from the server",
     "Validate file paths against a whitelist. Use chroot or containerization. Never pass user input to file operations.",
     "A01:2021 Broken Access Control"},
    {"SSTI", "critical",
     "Server-side template injection leading to remote code execution",
     "Never pass user input directly to template engines. Use sandboxed rendering. Escape all output.",
     "A03:2021 Injection"},
};

} // namespace

std::vector<ImpactProof> prove_impact(const std::vector<AttackChain> &chains) {
  std::vector<ImpactProof> proofs;

  for (const auto &chain : chains) {
    if (!chain.complete) continue;

    ImpactProof proof;
    proof.chain_type = chain.initial_finding.type;
    proof.evidence = chain.proof;

    // Match template
    for (const auto &t : kTemplates) {
      if (chain.initial_finding.type.find(t.type) != std::string::npos) {
        proof.severity = t.severity;
        proof.description = t.description;
        proof.fix = t.fix;
        proof.owasp = t.owasp;
        break;
      }
    }
    if (proof.severity.empty()) {
      proof.severity = "medium";
      proof.description = chain.impact;
      proof.fix = "Review and fix the identified vulnerability.";
      proof.owasp = "A00:2021 Unknown";
    }

    // Build repro steps from chain
    std::ostringstream steps;
    steps << "## Steps to Reproduce\n\n";
    int i = 1;
    for (const auto &s : chain.steps) {
      steps << i++ << ". " << s.reason << "\n";
      steps << "   ```\n   " << s.action << " " << s.url << "\n   ```\n";
      if (s.success && !s.result.empty())
        steps << "   Response: " << s.result.substr(0, 100) << "\n";
      steps << "\n";
    }
    proof.repro_steps = steps.str();

    proofs.push_back(proof);
  }

  return proofs;
}

std::string generate_h1_report(const std::vector<ImpactProof> &proofs,
                               const std::string &target,
                               const std::string &program) {
  if (proofs.empty()) return "";

  std::ostringstream report;

  for (const auto &proof : proofs) {
    report << "# " << proof.chain_type << " — " << proof.description << "\n\n";
    report << "**Severity**: " << proof.severity << "\n";
    report << "**Target**: " << target << "\n";
    if (!program.empty())
      report << "**Program**: " << program << "\n";
    report << "**OWASP**: " << proof.owasp << "\n\n";

    report << "## Summary\n\n";
    report << proof.description << "\n\n";

    report << proof.repro_steps << "\n";

    report << "## Impact\n\n";
    report << proof.description << " This could allow an attacker to ";
    if (proof.severity == "critical")
      report << "gain full control of the application or access all user data.\n\n";
    else if (proof.severity == "high")
      report << "access unauthorized data or escalate privileges.\n\n";
    else
      report << "obtain sensitive information.\n\n";

    if (!proof.evidence.empty()) {
      report << "## Evidence\n\n```\n" << proof.evidence.substr(0, 1000)
             << "\n```\n\n";
    }

    report << "## Remediation\n\n" << proof.fix << "\n\n";
    report << "---\n\n";
  }

  return report.str();
}

} // namespace apex
