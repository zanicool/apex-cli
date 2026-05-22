/// @file owasp_intel.hpp
/// @brief OWASP mapping, attack chains, and impact descriptions for findings.
#ifndef APEX_OWASP_INTEL_HPP
#define APEX_OWASP_INTEL_HPP

#include "scanner.hpp"
#include <iostream>
#include <string>
#include <vector>

namespace apex {

struct FindingIntel {
  std::string owasp;       // OWASP category
  std::string impact;      // Business impact
  std::string chain;       // Attack chain suggestion
  std::string ref;         // Reference (book/lab)
};

inline FindingIntel get_intel(const Finding &f) {
  FindingIntel i;
  const auto &t = f.type;

  if (t == "SQLi" || t.find("SQL") != std::string::npos) {
    i.owasp = "A03:2021 Injection";
    i.impact = "Database dump, auth bypass, data exfiltration";
    i.chain = "SQLi → UNION extract → admin creds → account takeover";
    i.ref = "PortSwigger SQLi Labs, WAHH Ch.9";
  } else if (t == "XSS" || t.find("XSS") != std::string::npos) {
    i.owasp = "A03:2021 Injection (XSS)";
    i.impact = "Session hijack, phishing, keylogging";
    i.chain = "Stored XSS → steal admin cookie → ATO";
    i.ref = "PortSwigger XSS Labs, The Tangled Web Ch.6";
  } else if (t == "SSRF" || t.find("Cloud Metadata") != std::string::npos) {
    i.owasp = "A10:2021 SSRF";
    i.impact = "Internal network access, cloud credential theft";
    i.chain = "SSRF → AWS metadata → IAM creds → full account takeover";
    i.ref = "PortSwigger SSRF Labs, WAHH Ch.10";
  } else if (t == "SSTI" || t == "SSTI Deep") {
    i.owasp = "A03:2021 Injection (SSTI)";
    i.impact = "Remote code execution on server";
    i.chain = "SSTI → {{config}} → secret key → RCE via pickle/eval";
    i.ref = "PortSwigger SSTI Labs, HackTricks SSTI";
  } else if (t == "IDOR") {
    i.owasp = "API1:2023 Broken Object Level Auth";
    i.impact = "Access other users' data, PII exposure";
    i.chain = "IDOR → enumerate all users → mass data leak";
    i.ref = "OWASP API Top 10, Real-World Bug Hunting Ch.4";
  } else if (t == "LFI") {
    i.owasp = "A01:2021 Broken Access Control";
    i.impact = "Source code leak, credential files, /etc/passwd";
    i.chain = "LFI → /proc/self/environ → secrets → RCE";
    i.ref = "PortSwigger Path Traversal Labs";
  } else if (t == "CMDi" || t.find("CMDi") != std::string::npos) {
    i.owasp = "A03:2021 Injection (OS Command)";
    i.impact = "Full server compromise, reverse shell";
    i.chain = "CMDi → reverse shell → pivot → lateral movement";
    i.ref = "PortSwigger OS Command Injection Labs";
  } else if (t == "NoSQL Injection") {
    i.owasp = "A03:2021 Injection (NoSQL)";
    i.impact = "Auth bypass, data extraction";
    i.chain = "NoSQL → $ne bypass → admin access → full DB dump";
    i.ref = "HackTricks NoSQL, OWASP Testing Guide";
  } else if (t == "XXE") {
    i.owasp = "A05:2021 Security Misconfiguration";
    i.impact = "File read, SSRF, denial of service";
    i.chain = "XXE → file:///etc/passwd → internal SSRF → cloud metadata";
    i.ref = "PortSwigger XXE Labs, WAHH Ch.10";
  } else if (t.find("JWT") != std::string::npos) {
    i.owasp = "API2:2023 Broken Authentication";
    i.impact = "Forge tokens, impersonate any user";
    i.chain = "JWT none alg → forge admin token → full access";
    i.ref = "PortSwigger JWT Labs, Auth0 JWT Handbook";
  } else if (t == "CORS Misconfiguration" || t == "CORS Deep") {
    i.owasp = "A01:2021 Broken Access Control";
    i.impact = "Cross-origin data theft from authenticated users";
    i.chain = "CORS reflect → victim visits attacker page → steal API data";
    i.ref = "PortSwigger CORS Labs, The Tangled Web Ch.9";
  } else if (t == "Open Redirect") {
    i.owasp = "A01:2021 Broken Access Control";
    i.impact = "Phishing, OAuth token theft";
    i.chain = "Open Redirect → OAuth redirect_uri → steal auth code";
    i.ref = "PortSwigger Labs, Real-World Bug Hunting Ch.7";
  } else if (t == "Secrets Exposure") {
    i.owasp = "A02:2021 Cryptographic Failures";
    i.impact = "API key abuse, account takeover, lateral movement";
    i.chain = "Leaked key → API access → privilege escalation";
    i.ref = "OWASP Secrets Management, TruffleHog";
  } else if (t == "CSRF") {
    i.owasp = "A01:2021 Broken Access Control";
    i.impact = "Unauthorized actions on behalf of victim";
    i.chain = "CSRF → change email → password reset → ATO";
    i.ref = "PortSwigger CSRF Labs, WAHH Ch.13";
  } else if (t.find("GraphQL") != std::string::npos) {
    i.owasp = "API8:2023 Security Misconfiguration";
    i.impact = "Schema leak, data enumeration, DoS";
    i.chain = "Introspection → find hidden mutations → auth bypass";
    i.ref = "DVGA, HackTricks GraphQL";
  } else if (t.find("CMS") != std::string::npos) {
    i.owasp = "A06:2021 Vulnerable Components";
    i.impact = "Known CVE exploitation, RCE";
    i.chain = "Outdated CMS → public exploit → webshell → pivot";
    i.ref = "WPScan, Nuclei CMS templates";
  } else {
    i.owasp = "A05:2021 Security Misconfiguration";
    i.impact = "Information disclosure";
    i.chain = "";
    i.ref = "OWASP Testing Guide";
  }
  return i;
}

/// Print enriched finding with OWASP + chain + impact.
inline void print_enriched_finding(const Finding &f) {
  auto intel = get_intel(f);
  std::cout << "    [" << f.severity << "] " << f.type << "\n";
  std::cout << "      URL: " << f.url << "\n";
  if (!f.param.empty()) std::cout << "      Param: " << f.param << "\n";
  if (!f.payload.empty())
    std::cout << "      Payload: " << f.payload.substr(0, 50) << "\n";
  if (!f.evidence.empty())
    std::cout << "      Evidence: " << f.evidence.substr(0, 60) << "\n";
  std::cout << "      OWASP: " << intel.owasp << "\n";
  std::cout << "      Impact: " << intel.impact << "\n";
  if (!intel.chain.empty())
    std::cout << "      Chain: " << intel.chain << "\n";
  std::cout << "      Ref: " << intel.ref << "\n";
  std::cout << "\n";
}

} // namespace apex
#endif
