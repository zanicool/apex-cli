/// @file impact.hpp
/// @brief Impact prover: collects evidence of successful exploitation.
#ifndef APEX_IMPACT_HPP
#define APEX_IMPACT_HPP

#include "chain.hpp"
#include "config.hpp"
#include <string>
#include <vector>

namespace apex {

/// Evidence of exploitation impact.
struct ImpactProof {
  std::string chain_type;     // IDOR, SSRF, SQLi, etc.
  std::string severity;       // critical, high, medium
  std::string description;    // Human-readable impact
  std::string evidence;       // Raw proof (response data)
  std::string repro_steps;    // Step-by-step reproduction
  std::string fix;            // Suggested remediation
  std::string owasp;          // OWASP Top 10 mapping
};

/// Generate impact proofs from completed attack chains.
std::vector<ImpactProof> prove_impact(const std::vector<AttackChain> &chains);

/// Generate a HackerOne-format report from impact proofs.
std::string generate_h1_report(const std::vector<ImpactProof> &proofs,
                               const std::string &target,
                               const std::string &program);

} // namespace apex

#endif // APEX_IMPACT_HPP
