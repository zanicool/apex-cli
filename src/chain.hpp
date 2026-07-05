/// @file chain.hpp
/// @brief Attack chain executor: escalates findings into full exploit chains.
#ifndef APEX_CHAIN_HPP
#define APEX_CHAIN_HPP

#include "config.hpp"
#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// A single step in an attack chain.
struct ChainStep {
  std::string action; // http_get, http_post, extract, verify
  std::string url;
  std::string method;
  std::string body;
  std::string reason;
  std::string result;
  bool success = false;
};

/// A complete attack chain from initial finding to impact proof.
struct AttackChain {
  Finding initial_finding;
  std::vector<ChainStep> steps;
  std::string impact; // "Read all user data", "RCE as root"
  std::string proof;  // Evidence of exploitation
  int depth = 0;
  bool complete = false;
};

/// Chain executor: given findings, attempt to escalate each one.
class ChainExecutor {
public:
  explicit ChainExecutor(const Config &cfg, HttpClient &http);

  /// Attempt to chain all findings into full exploits.
  std::vector<AttackChain> execute(const std::vector<Finding> &findings);

private:
  /// Chain patterns per vulnerability type.
  AttackChain chain_idor(const Finding &f);
  AttackChain chain_ssrf(const Finding &f);
  AttackChain chain_sqli(const Finding &f);
  AttackChain chain_jwt(const Finding &f);
  AttackChain chain_lfi(const Finding &f);
  AttackChain chain_ssti(const Finding &f);

  /// Check if URL is within authorized scope.
  bool in_scope(const std::string &url) const;

  const Config &cfg_;
  HttpClient &http_;
};

} // namespace apex

#endif // APEX_CHAIN_HPP
