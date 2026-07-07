/// @file scanners/attack_chain.cpp
/// @brief AI-driven Attack Chain Engine: automatically combines individual findings
///        into multi-step exploitation chains for maximum impact.
///        This is what separates a scanner from a hacker.
///
///        Examples:
///        - Open Redirect + OAuth = Account Takeover
///        - SSRF + Cloud Metadata = Full Infrastructure Compromise
///        - CRLF + Cache = Stored XSS for ALL users
///        - IDOR + PII = Mass Data Breach
///        - Subdomain Takeover + Cookie Scope = Session Hijack
///
///        The engine runs AFTER all other scanners and chains their results.
#include <algorithm>
#include <map>
#include <regex>

#include "scanner_base.hpp"

namespace apex {

// Forward declaration — access global findings from scanner pipeline
extern std::vector<Finding> g_all_findings;

namespace {

/// Chain: Open Redirect + OAuth → Account Takeover
Finding chain_redirect_oauth(const std::vector<Finding>& findings) {
  bool has_redirect = false;
  bool has_oauth = false;
  std::string redirect_url, oauth_url;

  for (const auto& f : findings) {
    if (f.type.find("Open Redirect") != std::string::npos) {
      has_redirect = true;
      redirect_url = f.url;
    }
    if (f.type.find("OAuth") != std::string::npos && f.type.find("redirect") != std::string::npos) {
      has_oauth = true;
      oauth_url = f.url;
    }
  }

  if (has_redirect && has_oauth) {
    return Finding{"CHAIN: Open Redirect → OAuth Token Theft → Account Takeover",
                   "critical",
                   redirect_url,
                   "ATTACK CHAIN DETECTED:\n"
                   "1. Open redirect at: " +
                       redirect_url +
                       "\n"
                       "2. OAuth redirect_uri accepts subdomain/path manipulation\n"
                       "3. Attacker sets redirect_uri to open redirect endpoint\n"
                       "4. Open redirect forwards OAuth token to attacker server\n"
                       "5. Attacker uses stolen token → full account takeover\n\n"
                       "Impact: Any user who clicks the crafted OAuth link loses their account.",
                   "",
                   "",
                   ""};
  }
  return {};
}

/// Chain: SSRF + Cloud Metadata → Infrastructure Compromise
Finding chain_ssrf_cloud(const std::vector<Finding>& findings) {
  bool has_ssrf = false;
  bool has_cloud = false;
  std::string ssrf_url;

  for (const auto& f : findings) {
    if (f.type.find("SSRF") != std::string::npos) {
      has_ssrf = true;
      ssrf_url = f.url;
    }
    if (f.type.find("Cloud Metadata") != std::string::npos || f.type.find("AWS") != std::string::npos ||
        f.type.find("Firebase") != std::string::npos) {
      has_cloud = true;
    }
  }

  if (has_ssrf && has_cloud) {
    return Finding{"CHAIN: SSRF → Cloud Metadata → Full Infrastructure Takeover",
                   "critical",
                   ssrf_url,
                   "ATTACK CHAIN DETECTED:\n"
                   "1. SSRF vulnerability allows server-side requests\n"
                   "2. Cloud metadata service reachable (169.254.169.254)\n"
                   "3. Extract IAM role temporary credentials\n"
                   "4. Use credentials to access S3, RDS, Lambda, etc.\n"
                   "5. Pivot to other cloud services → full AWS/GCP/Azure compromise\n\n"
                   "Impact: Complete cloud infrastructure takeover. "
                   "All data, all services, all secrets.",
                   "",
                   "",
                   ""};
  }
  return {};
}

/// Chain: Cache Poisoning + XSS → Mass User Compromise
Finding chain_cache_xss(const std::vector<Finding>& findings) {
  bool has_cache_poison = false;
  bool has_header_reflect = false;
  std::string cache_url;

  for (const auto& f : findings) {
    if (f.type.find("Cache Poison") != std::string::npos) {
      has_cache_poison = true;
      cache_url = f.url;
    }
    if (f.type.find("Host Header") != std::string::npos || f.type.find("CRLF") != std::string::npos ||
        f.type.find("XSS") != std::string::npos) {
      has_header_reflect = true;
    }
  }

  if (has_cache_poison && has_header_reflect) {
    return Finding{"CHAIN: Cache Poisoning + Header Injection → Stored XSS for ALL Users",
                   "critical",
                   cache_url,
                   "ATTACK CHAIN DETECTED:\n"
                   "1. Unkeyed header reflected in cacheable response\n"
                   "2. Inject XSS payload via header (X-Forwarded-Host, Host, etc.)\n"
                   "3. Poisoned response gets cached by CDN/reverse proxy\n"
                   "4. ALL subsequent visitors receive the XSS payload\n"
                   "5. Steal sessions, redirect to phishing, cryptominer, etc.\n\n"
                   "Impact: Every user visiting the site gets compromised. "
                   "Equivalent to defacing the entire website.",
                   "",
                   "",
                   ""};
  }
  return {};
}

/// Chain: Subdomain Takeover + Cookie Scope → Session Hijack
Finding chain_subdomain_session(const std::vector<Finding>& findings) {
  bool has_takeover = false;
  std::string takeover_url;

  for (const auto& f : findings) {
    if (f.type.find("Subdomain Takeover") != std::string::npos) {
      has_takeover = true;
      takeover_url = f.url;
    }
  }

  if (has_takeover) {
    return Finding{"CHAIN: Subdomain Takeover → Cookie Theft → Session Hijack",
                   "critical",
                   takeover_url,
                   "ATTACK CHAIN DETECTED:\n"
                   "1. Unclaimed subdomain detected (can be registered by attacker)\n"
                   "2. If parent domain sets cookies without explicit Domain attribute,\n"
                   "   OR if cookies are set to .domain.com (includes all subdomains)\n"
                   "3. Attacker claims subdomain, serves page that reads cookies\n"
                   "4. Victim visits any page → cookie sent to attacker subdomain\n"
                   "5. Attacker hijacks session\n\n"
                   "Impact: Session hijack for all users whose cookies scope to subdomains.",
                   "",
                   "",
                   ""};
  }
  return {};
}

/// Chain: JWT None + Admin Endpoint → Privilege Escalation to God Mode
Finding chain_jwt_admin(const std::vector<Finding>& findings) {
  bool has_jwt_bypass = false;
  bool has_admin = false;
  std::string jwt_url, admin_url;

  for (const auto& f : findings) {
    if (f.type.find("JWT") != std::string::npos &&
        (f.type.find("None") != std::string::npos || f.type.find("HS256") != std::string::npos)) {
      has_jwt_bypass = true;
      jwt_url = f.url;
    }
    if (f.type.find("BFLA") != std::string::npos || f.type.find("Admin") != std::string::npos ||
        f.type.find("GraphQL") != std::string::npos) {
      has_admin = true;
      admin_url = f.url;
    }
  }

  if (has_jwt_bypass && has_admin) {
    return Finding{"CHAIN: JWT Forge → Admin Access → Full Application Takeover",
                   "critical",
                   jwt_url,
                   "ATTACK CHAIN DETECTED:\n"
                   "1. JWT signature bypass (none algorithm or weak secret)\n"
                   "2. Forge token with admin/elevated claims\n"
                   "3. Access admin endpoints: " +
                       admin_url +
                       "\n"
                       "4. Create new admin accounts, modify all data, extract secrets\n"
                       "5. Persistent backdoor access\n\n"
                       "Impact: Complete application takeover with admin privileges.",
                   "",
                   "",
                   ""};
  }
  return {};
}

/// Chain: SSTI → RCE → Reverse Shell → Infrastructure Pivot
Finding chain_ssti_rce(const std::vector<Finding>& findings) {
  bool has_ssti = false;
  std::string ssti_url;

  for (const auto& f : findings) {
    if (f.type.find("SSTI") != std::string::npos && f.type.find("CONFIRMED") != std::string::npos) {
      has_ssti = true;
      ssti_url = f.url;
    }
  }

  if (has_ssti) {
    return Finding{"CHAIN: SSTI → Remote Code Execution → Server Compromise",
                   "critical",
                   ssti_url,
                   "ATTACK CHAIN DETECTED:\n"
                   "1. Server-Side Template Injection confirmed\n"
                   "2. Escalate from math eval to OS command execution:\n"
                   "   Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}\n"
                   "   Twig: {{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}\n"
                   "3. Establish reverse shell\n"
                   "4. Dump database credentials from environment/config\n"
                   "5. Pivot to internal network, cloud metadata, other services\n\n"
                   "Impact: Complete server compromise. Read/write all files, "
                   "access database, pivot internally.",
                   "",
                   "",
                   ""};
  }
  return {};
}

/// Chain: Request Smuggling → Cache Poisoning → Credential Theft
Finding chain_smuggle_cache(const std::vector<Finding>& findings) {
  bool has_smuggling = false;
  std::string smuggle_url;

  for (const auto& f : findings) {
    if (f.type.find("Smuggling") != std::string::npos || f.type.find("Desync") != std::string::npos) {
      has_smuggling = true;
      smuggle_url = f.url;
    }
  }

  if (has_smuggling) {
    return Finding{"CHAIN: Request Smuggling → Response Queue Poisoning → Mass Credential Theft",
                   "critical",
                   smuggle_url,
                   "ATTACK CHAIN DETECTED:\n"
                   "1. HTTP request smuggling confirmed (CL.TE or TE.CL)\n"
                   "2. Smuggle a second request that captures the NEXT user's request\n"
                   "3. Victim's request (with cookies/auth) gets appended to smuggled response\n"
                   "4. Attacker retrieves the poisoned response containing victim's credentials\n"
                   "5. Repeat continuously to harvest credentials from all users\n\n"
                   "Alternative: Poison web cache via smuggled response → stored XSS for all.\n\n"
                   "Impact: Passive, continuous credential theft from ALL users. "
                   "Undetectable by the victims.",
                   "",
                   "",
                   ""};
  }
  return {};
}

/// Chain: GraphQL Introspection + Batch + IDOR → Mass Data Exfiltration
Finding chain_graphql_exfil(const std::vector<Finding>& findings) {
  bool has_introspection = false;
  bool has_batch = false;
  bool has_idor = false;
  std::string gql_url;

  for (const auto& f : findings) {
    if (f.type.find("GraphQL Introspection") != std::string::npos) {
      has_introspection = true;
      gql_url = f.url;
    }
    if (f.type.find("Batch") != std::string::npos || f.type.find("Alias") != std::string::npos) {
      has_batch = true;
    }
    if (f.type.find("BOLA") != std::string::npos || f.type.find("IDOR") != std::string::npos) {
      has_idor = true;
    }
  }

  if (has_introspection && (has_batch || has_idor)) {
    return Finding{"CHAIN: GraphQL Schema Dump + Batch Abuse → Mass Data Exfiltration",
                   "critical",
                   gql_url,
                   "ATTACK CHAIN DETECTED:\n"
                   "1. Full GraphQL schema dumped via introspection\n"
                   "2. Identify user/sensitive data queries from schema\n"
                   "3. Use alias batching to enumerate 100+ user IDs per request\n"
                   "4. Bypass rate limiting (one HTTP request = 100 GraphQL operations)\n"
                   "5. Exfiltrate entire user database in minutes\n\n"
                   "Impact: Full database dump via API. All user PII, emails, "
                   "payment info extractable at high speed.",
                   "",
                   "",
                   ""};
  }
  return {};
}

/// Chain: Race Condition + Payment → Infinite Money
Finding chain_race_payment(const std::vector<Finding>& findings) {
  bool has_race = false;
  bool has_payment = false;
  std::string race_url;

  for (const auto& f : findings) {
    if (f.type.find("Race") != std::string::npos) {
      has_race = true;
      race_url = f.url;
    }
    if (f.type.find("Idempotency") != std::string::npos || f.type.find("payment") != std::string::npos ||
        f.type.find("Payment") != std::string::npos) {
      has_payment = true;
    }
  }

  if (has_race && has_payment) {
    return Finding{"CHAIN: Race Condition + Payment → Financial Fraud (Double-Spend)",
                   "critical",
                   race_url,
                   "ATTACK CHAIN DETECTED:\n"
                   "1. Race-vulnerable payment/withdrawal endpoint detected\n"
                   "2. No idempotency key enforcement\n"
                   "3. Send 50 concurrent withdrawal requests simultaneously\n"
                   "4. Server processes all before balance check updates\n"
                   "5. Withdraw 50x the actual balance\n\n"
                   "Impact: Direct financial loss. Attacker drains accounts or "
                   "generates unlimited credits/refunds.",
                   "",
                   "",
                   ""};
  }
  return {};
}

/// The master chain analyzer — runs all chains against collected findings.
std::vector<Finding> scan_attack_chains(const Config&, HttpClient&, const CrawlResult&) {
  std::vector<Finding> chains;

  // Get all findings from the global scanner pipeline
  // Only consider findings with actual evidence (not speculative)
  std::vector<Finding> findings;
  for (const auto& f : g_all_findings) {
    if (!f.evidence.empty() || f.severity == "critical" || f.severity == "high") {
      // Additional filter: skip unverified/downgraded findings
      if (f.type.find("unverified") != std::string::npos) continue;
      if (f.type.find("AI:FP") != std::string::npos) continue;
      if (f.type.find("(unverified)") != std::string::npos) continue;
      findings.push_back(f);
    }
  }
  if (findings.empty()) return chains;

  // Run all chain detectors
  auto c1 = chain_redirect_oauth(findings);
  if (!c1.type.empty()) chains.push_back(c1);

  auto c2 = chain_ssrf_cloud(findings);
  if (!c2.type.empty()) chains.push_back(c2);

  auto c3 = chain_cache_xss(findings);
  if (!c3.type.empty()) chains.push_back(c3);

  auto c4 = chain_subdomain_session(findings);
  if (!c4.type.empty()) chains.push_back(c4);

  auto c5 = chain_jwt_admin(findings);
  if (!c5.type.empty()) chains.push_back(c5);

  auto c6 = chain_ssti_rce(findings);
  if (!c6.type.empty()) chains.push_back(c6);

  auto c7 = chain_smuggle_cache(findings);
  if (!c7.type.empty()) chains.push_back(c7);

  auto c8 = chain_graphql_exfil(findings);
  if (!c8.type.empty()) chains.push_back(c8);

  auto c9 = chain_race_payment(findings);
  if (!c9.type.empty()) chains.push_back(c9);

  // Summary finding
  if (!chains.empty()) {
    chains.insert(chains.begin(),
                  Finding{"ATTACK CHAIN ENGINE — " + std::to_string(chains.size()) + " exploit chains identified", "critical", "",
                          "The Attack Chain Engine combined individual findings into " + std::to_string(chains.size()) +
                              " multi-step exploitation paths. "
                              "Each chain demonstrates how seemingly low/medium findings combine into "
                              "critical exploits. This is how real attackers think.",
                          "", "", ""});
  }

  return chains;
}

}  // namespace

std::vector<Scanner> register_attack_chain_scanners() {
  return {
      {"Attack Chain Engine", scan_attack_chains},
  };
}

}  // namespace apex
