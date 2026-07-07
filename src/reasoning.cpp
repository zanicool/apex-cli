/// @file reasoning.cpp
/// @brief Autonomous Security Reasoning Engine implementation.
///
/// The engine works in three phases:
/// 1. OBSERVE: categorize all findings by attack surface area
/// 2. HYPOTHESIZE: generate testable theories about what chains are possible
/// 3. REASON: score attack paths by probability and impact
///
/// This is not pattern matching. It's inference.
#include "reasoning.hpp"

#include <algorithm>
#include <cmath>
#include <set>
#include <sstream>

namespace apex {
namespace {

// ============================================================
// OBSERVATION PHASE: categorize findings into attack surfaces
// ============================================================

struct Surface {
  std::vector<Finding> auth_findings;
  std::vector<Finding> injection_findings;
  std::vector<Finding> info_disclosure;
  std::vector<Finding> misconfig;
  std::vector<Finding> access_control;
  std::vector<Finding> crypto;
  std::vector<Finding> ssrf_findings;
  std::vector<Finding> client_side;
};

Surface categorize(const std::vector<Finding>& findings) {
  Surface s;
  for (const auto& f : findings) {
    std::string t = f.type;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);

    if (t.find("auth") != std::string::npos || t.find("jwt") != std::string::npos || t.find("oauth") != std::string::npos ||
        t.find("session") != std::string::npos || t.find("password") != std::string::npos || t.find("2fa") != std::string::npos) {
      s.auth_findings.push_back(f);
    } else if (t.find("sql") != std::string::npos || t.find("xss") != std::string::npos || t.find("ssti") != std::string::npos ||
               t.find("injection") != std::string::npos || t.find("lfi") != std::string::npos || t.find("rfi") != std::string::npos) {
      s.injection_findings.push_back(f);
    } else if (t.find("disclosure") != std::string::npos || t.find("exposed") != std::string::npos || t.find("leak") != std::string::npos ||
               t.find("internal") != std::string::npos) {
      s.info_disclosure.push_back(f);
    } else if (t.find("misconfig") != std::string::npos || t.find("missing") != std::string::npos ||
               t.find("header") != std::string::npos || t.find("cors") != std::string::npos) {
      s.misconfig.push_back(f);
    } else if (t.find("idor") != std::string::npos || t.find("access") != std::string::npos || t.find("admin") != std::string::npos ||
               t.find("privilege") != std::string::npos || t.find("bypass") != std::string::npos) {
      s.access_control.push_back(f);
    } else if (t.find("ssrf") != std::string::npos) {
      s.ssrf_findings.push_back(f);
    } else if (t.find("prototype") != std::string::npos || t.find("dom") != std::string::npos || t.find("client") != std::string::npos ||
               t.find("cache") != std::string::npos) {
      s.client_side.push_back(f);
    } else {
      s.misconfig.push_back(f);
    }
  }
  return s;
}

// ============================================================
// HYPOTHESIS GENERATION: what attack paths are plausible?
// ============================================================

std::vector<Hypothesis> generate_hypotheses(const Surface& surface, const AssetProfile& profile) {
  std::vector<Hypothesis> hypotheses;
  int id = 0;

  // Hypothesis: info disclosure + auth weakness = account takeover
  if (!surface.info_disclosure.empty() && !surface.auth_findings.empty()) {
    Hypothesis h;
    h.id = "H" + std::to_string(++id);
    h.description =
        "Information disclosure combined with authentication weakness "
        "may enable account takeover";
    h.test_plan =
        "1. Use disclosed information to identify user accounts\n"
        "2. Exploit auth weakness to access those accounts\n"
        "3. Verify cross-account data access";
    h.confidence = 0.6;
    h.status = "pending";
    hypotheses.push_back(h);
  }

  // Hypothesis: SSRF + cloud = infrastructure compromise
  if (!surface.ssrf_findings.empty() && !profile.cloud_provider.empty()) {
    Hypothesis h;
    h.id = "H" + std::to_string(++id);
    h.description = "SSRF in " + profile.cloud_provider +
                    " environment — "
                    "cloud metadata and internal services likely reachable";
    h.test_plan =
        "1. Attempt metadata endpoint via SSRF\n"
        "2. Extract IAM credentials\n"
        "3. Enumerate accessible cloud services";
    h.confidence = 0.8;
    h.status = "pending";
    hypotheses.push_back(h);
  }

  // Hypothesis: injection + admin endpoint = RCE
  if (!surface.injection_findings.empty() && !surface.access_control.empty()) {
    Hypothesis h;
    h.id = "H" + std::to_string(++id);
    h.description =
        "Injection vulnerability near admin/privileged endpoint "
        "likely leads to remote code execution or full data access";
    h.test_plan =
        "1. Confirm injection point\n"
        "2. Determine database/template engine\n"
        "3. Escalate from data extraction to code execution";
    h.confidence = 0.7;
    h.status = "pending";
    hypotheses.push_back(h);
  }

  // Hypothesis: client-side + OAuth = mass account takeover
  if (!surface.client_side.empty() && profile.has_oauth) {
    Hypothesis h;
    h.id = "H" + std::to_string(++id);
    h.description =
        "Client-side vulnerability (XSS/PP) combined with OAuth "
        "can steal tokens and take over accounts at scale";
    h.test_plan =
        "1. Confirm XSS/PP exploitation\n"
        "2. Craft payload that extracts OAuth tokens\n"
        "3. Demonstrate cross-origin token theft";
    h.confidence = 0.65;
    h.status = "pending";
    hypotheses.push_back(h);
  }

  // Hypothesis: multiple info disclosures = credential theft
  if (surface.info_disclosure.size() >= 3) {
    Hypothesis h;
    h.id = "H" + std::to_string(++id);
    h.description =
        "Multiple information disclosures likely expose enough context "
        "for credential theft or social engineering";
    h.test_plan =
        "1. Combine disclosed info (internal URLs, usernames, tech stack)\n"
        "2. Identify credential exposure vectors\n"
        "3. Test default/leaked credentials";
    h.confidence = 0.5;
    h.status = "pending";
    hypotheses.push_back(h);
  }

  // Hypothesis: weak crypto + JWT = token forgery
  if (profile.has_jwt) {
    bool has_jwt_finding = false;
    for (const auto& f : surface.auth_findings) {
      if (f.type.find("JWT") != std::string::npos) has_jwt_finding = true;
    }
    if (has_jwt_finding) {
      Hypothesis h;
      h.id = "H" + std::to_string(++id);
      h.description =
          "JWT vulnerability enables token forgery — "
          "attacker can create admin tokens";
      h.test_plan =
          "1. Determine JWT algorithm\n"
          "2. Attempt none/HS256 confusion\n"
          "3. Forge token with admin claims\n"
          "4. Access admin endpoints";
      h.confidence = 0.75;
      h.status = "pending";
      hypotheses.push_back(h);
    }
  }

  // Hypothesis: SPA + prototype pollution = persistent XSS
  if (profile.is_spa) {
    for (const auto& f : surface.client_side) {
      if (f.type.find("Prototype") != std::string::npos) {
        Hypothesis h;
        h.id = "H" + std::to_string(++id);
        h.description =
            "Prototype pollution in SPA application — "
            "can likely escalate to persistent XSS via gadget chain";
        h.test_plan =
            "1. Identify PP injection vector\n"
            "2. Find gadget in framework (innerHTML, src, etc)\n"
            "3. Demonstrate XSS execution via polluted property";
        h.confidence = 0.7;
        h.status = "pending";
        hypotheses.push_back(h);
      }
    }
  }

  return hypotheses;
}

// ============================================================
// ATTACK PATH CONSTRUCTION: build ordered exploitation chains
// ============================================================

std::vector<AttackPath> build_attack_paths(const Surface& surface, const AssetProfile& profile, const std::vector<Hypothesis>& /*hypotheses*/) {
  std::vector<AttackPath> paths;
  int id = 0;

  // Path: Info Leak → Auth Bypass → Account Takeover
  if (!surface.info_disclosure.empty() && !surface.auth_findings.empty()) {
    AttackPath path;
    path.id = "AP" + std::to_string(++id);
    path.name = "Information Disclosure → Auth Bypass → Account Takeover";
    path.impact = "critical";
    path.probability = 0.0;

    // Add steps
    for (const auto& f : surface.info_disclosure) {
      path.steps.push_back(f);
      if (path.steps.size() >= 2) break;
    }
    for (const auto& f : surface.auth_findings) {
      path.steps.push_back(f);
      if (path.steps.size() >= 4) break;
    }

    // Calculate probability based on finding confidence
    double avg_conf = 0;
    for (const auto& s : path.steps) avg_conf += s.confidence;
    avg_conf /= path.steps.size();
    path.probability = avg_conf / 100.0;

    // Generate narrative
    std::ostringstream nar;
    nar << "Attack narrative:\n";
    for (size_t i = 0; i < path.steps.size(); i++) {
      nar << "  Step " << (i + 1) << ": " << path.steps[i].type << " at " << path.steps[i].url << "\n";
    }
    nar << "\nThis chain demonstrates how seemingly low-severity information "
           "disclosures enable critical account takeover when combined with "
           "authentication weaknesses.";
    path.narrative = nar.str();

    paths.push_back(path);
  }

  // Path: SSRF → Cloud Metadata → Full Compromise
  if (!surface.ssrf_findings.empty() && !profile.cloud_provider.empty()) {
    AttackPath path;
    path.id = "AP" + std::to_string(++id);
    path.name = "SSRF → " + profile.cloud_provider + " Metadata → Infrastructure Compromise";
    path.impact = "critical";

    for (const auto& f : surface.ssrf_findings) {
      path.steps.push_back(f);
      break;
    }

    double avg_conf = 0;
    for (const auto& s : path.steps) avg_conf += s.confidence;
    path.probability = (avg_conf / path.steps.size()) / 100.0 * 0.8;

    path.narrative = "SSRF vulnerability in " + profile.cloud_provider +
                     " environment. Cloud metadata endpoint (169.254.169.254) is "
                     "likely reachable, exposing IAM credentials for full cloud compromise.";
    paths.push_back(path);
  }

  // Path: XSS/PP → Token Theft → Mass Account Takeover
  if (!surface.client_side.empty() && (profile.has_jwt || profile.has_oauth)) {
    AttackPath path;
    path.id = "AP" + std::to_string(++id);
    path.name = "Client-Side Vuln → Token Theft → Mass Account Takeover";
    path.impact = "critical";

    for (const auto& f : surface.client_side) {
      path.steps.push_back(f);
      break;
    }

    path.probability = 0.5;
    path.narrative =
        "Client-side vulnerability enables JavaScript execution in victim's browser. "
        "With " +
        std::string(profile.has_jwt ? "JWT" : "OAuth") +
        " tokens accessible via JavaScript, attacker can steal authentication "
        "tokens and take over any user's account who visits a crafted page.";
    paths.push_back(path);
  }

  // Sort by probability * impact
  std::sort(paths.begin(), paths.end(), [](const AttackPath& a, const AttackPath& b) {
    double score_a = a.probability * (a.impact == "critical" ? 10 : a.impact == "high" ? 7 : 4);
    double score_b = b.probability * (b.impact == "critical" ? 10 : b.impact == "high" ? 7 : 4);
    return score_a > score_b;
  });

  return paths;
}

// ============================================================
// RISK SCORING: overall target assessment
// ============================================================

int compute_risk_score(const Surface& surface, const AssetProfile& profile, const std::vector<AttackPath>& paths) {
  int score = 0;

  // Base score from finding counts
  score += surface.auth_findings.size() * 8;
  score += surface.injection_findings.size() * 10;
  score += surface.ssrf_findings.size() * 9;
  score += surface.access_control.size() * 7;
  score += surface.info_disclosure.size() * 3;
  score += surface.client_side.size() * 5;
  score += surface.misconfig.size() * 2;

  // Multiply by attack path viability
  for (const auto& path : paths) {
    if (path.impact == "critical" && path.probability > 0.5)
      score += 20;
    else if (path.impact == "high" && path.probability > 0.5)
      score += 10;
  }

  // Context modifiers
  if (profile.cloud_provider == "aws" || profile.cloud_provider == "gcp") score += 5;
  if (profile.has_jwt) score += 3;
  if (profile.has_oauth) score += 3;
  if (profile.waf.empty()) score += 5;  // No WAF = easier to exploit

  return std::min(100, score);
}

}  // namespace

// ============================================================
// PUBLIC API
// ============================================================

ReasoningResult reason(const std::vector<Finding>& findings, const AssetProfile& profile, const CrawlResult& /*crawl*/, HttpClient& /*http*/) {
  ReasoningResult result;

  if (findings.empty()) {
    result.summary = "No findings to reason about.";
    result.risk_score = 0;
    return result;
  }

  // Phase 1: Observe — categorize findings
  auto surface = categorize(findings);

  // Phase 2: Hypothesize — what attack paths are plausible?
  result.hypotheses = generate_hypotheses(surface, profile);

  // Phase 3: Build attack paths — ordered exploitation chains
  result.attack_paths = build_attack_paths(surface, profile, result.hypotheses);

  // Phase 4: Risk score — overall assessment
  result.risk_score = compute_risk_score(surface, profile, result.attack_paths);

  // Phase 5: Escalate — upgrade findings that participate in attack paths
  for (auto& path : result.attack_paths) {
    if (path.impact == "critical" && path.probability > 0.4) {
      for (auto& step : path.steps) {
        if (step.severity == "medium" || step.severity == "low") {
          step.severity = "high";
          step.detail += " [ESCALATED: part of critical attack chain '" + path.name + "']";
          result.escalated_findings.push_back(step);
        }
      }
    }
  }

  // Generate summary
  std::ostringstream summary;
  summary << "Risk Assessment: " << result.risk_score << "/100\n\n";
  summary << "Attack Surface:\n";
  summary << "  Auth weaknesses: " << surface.auth_findings.size() << "\n";
  summary << "  Injection points: " << surface.injection_findings.size() << "\n";
  summary << "  SSRF vectors: " << surface.ssrf_findings.size() << "\n";
  summary << "  Access control: " << surface.access_control.size() << "\n";
  summary << "  Info disclosure: " << surface.info_disclosure.size() << "\n\n";
  summary << "Hypotheses generated: " << result.hypotheses.size() << "\n";
  summary << "Attack paths identified: " << result.attack_paths.size() << "\n\n";

  if (!result.attack_paths.empty()) {
    summary << "Most likely attack path:\n";
    summary << "  " << result.attack_paths[0].name << "\n";
    summary << "  Probability: " << (int)(result.attack_paths[0].probability * 100) << "%\n";
    summary << "  Impact: " << result.attack_paths[0].impact << "\n";
  }

  result.summary = summary.str();
  return result;
}

}  // namespace apex
