/// @file verification.cpp
/// @brief Verification Pipeline + Scan Memory implementation.
#include "verification.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>

namespace apex {

namespace {

/// Get current ISO 8601 timestamp.
std::string now_iso8601() {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  std::ostringstream ss;
  ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
  return ss.str();
}

/// Verify a single finding by re-testing it.
VerifiedFinding verify_one(const Finding& f, HttpClient& http) {
  VerifiedFinding vf;
  vf.finding = f;
  vf.verify_attempts = 1;

  // Skip info/low findings (not worth re-testing)
  if (f.severity == "info" || f.severity == "low") {
    vf.state = VerifyState::SUSPECTED;
    vf.state_reason = "Low severity — accepted without deep verification";
    return vf;
  }

  // Skip findings without a testable URL
  if (f.url.empty() || f.url.find("http") != 0) {
    vf.state = VerifyState::UNVERIFIED;
    vf.state_reason = "No testable URL";
    return vf;
  }

  Evidence ev;
  ev.timestamp = now_iso8601();

  // Strategy 1: Differential verification
  // Get baseline (clean request), then replay the finding
  std::string clean_url = f.url;
  // Strip payload from URL if it's embedded there
  auto qpos = clean_url.find('?');
  std::string baseline_url = (qpos != std::string::npos) ? clean_url.substr(0, qpos) : clean_url;

  auto baseline = http.get(baseline_url);
  auto replay = http.get(f.url);

  ev.method = "differential";
  ev.request = f.url;
  ev.response_code = replay.status_code;
  ev.response_size = replay.body.size();
  ev.response_time_ms = replay.duration.count();

  // Check if replay produces different result than baseline
  if (replay.status_code != baseline.status_code || replay.body.size() != baseline.body.size()) {
    ev.baseline_diff = "status: " + std::to_string(baseline.status_code) + "→" + std::to_string(replay.status_code) +
                       ", size: " + std::to_string(baseline.body.size()) + "→" + std::to_string(replay.body.size());
  }

  // Verification logic based on finding type
  bool verified = false;
  std::string reason;

  // SQL Injection: look for DB errors in replay
  if (f.type.find("SQL") != std::string::npos || f.type.find("SQLi") != std::string::npos) {
    if (replay.body.find("SQL") != std::string::npos || replay.body.find("mysql") != std::string::npos ||
        replay.body.find("syntax") != std::string::npos || replay.body.find("SQLSTATE") != std::string::npos) {
      verified = true;
      reason = "Database error reproduced in replay";
      ev.response_snippet = replay.body.substr(replay.body.find("SQL") != std::string::npos ? replay.body.find("SQL") : 0, 200);
    }
  }

  // XSS: check if payload reflects
  if (f.type.find("XSS") != std::string::npos) {
    if (!f.payload.empty() && replay.body.find(f.payload) != std::string::npos) {
      verified = true;
      reason = "XSS payload reflected in response";
      ev.response_snippet = f.payload;
    }
  }

  // SSRF: check if internal content appears
  if (f.type.find("SSRF") != std::string::npos) {
    if (replay.body.find("root:") != std::string::npos || replay.body.find("ami-") != std::string::npos ||
        replay.body.find("instance") != std::string::npos) {
      verified = true;
      reason = "Internal data in response confirms SSRF";
      ev.response_snippet = replay.body.substr(0, 200);
    }
  }

  // Path Traversal: check for system file content
  if (f.type.find("LFI") != std::string::npos || f.type.find("Path Traversal") != std::string::npos) {
    if (replay.body.find("root:") != std::string::npos || replay.body.find("[fonts]") != std::string::npos) {
      verified = true;
      reason = "System file content returned";
      ev.response_snippet = replay.body.substr(0, 200);
    }
  }

  // SSTI: check if math evaluation appeared
  if (f.type.find("SSTI") != std::string::npos || f.type.find("Template") != std::string::npos) {
    if (replay.body.find("49") != std::string::npos && baseline.body.find("49") == std::string::npos) {
      verified = true;
      reason = "Template expression evaluated (49 appeared only with payload)";
    }
  }

  // Prototype Pollution: behavioral change
  if (f.type.find("Prototype") != std::string::npos) {
    if (replay.body.size() != baseline.body.size() && std::abs((int)replay.body.size() - (int)baseline.body.size()) > 100) {
      verified = true;
      reason = "Response changed significantly after prototype injection";
    }
  }

  // Generic: significant response difference = suspected
  if (!verified && !ev.baseline_diff.empty()) {
    vf.state = VerifyState::SUSPECTED;
    reason = "Response differs from baseline: " + ev.baseline_diff;
  }

  // Time-based findings: re-test with timing
  if (!verified && f.type.find("Time") != std::string::npos && f.type.find("Blind") != std::string::npos) {
    if (ev.response_time_ms > 3000) {
      verified = true;
      reason = "Response delayed " + std::to_string(ev.response_time_ms) + "ms (>3s threshold)";
    }
  }

  // Set final state
  if (verified) {
    vf.state = VerifyState::VERIFIED;
    vf.state_reason = reason;
    // Boost confidence
    vf.finding.confidence = std::min(100, vf.finding.confidence + 25);
  } else if (vf.state != VerifyState::SUSPECTED) {
    // Could not reproduce — might be FP or timing-dependent
    vf.state = VerifyState::UNVERIFIED;
    vf.state_reason = "Could not reproduce on re-test";
    vf.finding.confidence = std::max(10, vf.finding.confidence - 20);
  }

  vf.evidence_chain.push_back(ev);
  return vf;
}

}  // namespace

// ============================================================
// PUBLIC API
// ============================================================

std::vector<VerifiedFinding> verify_findings(const std::vector<Finding>& findings, HttpClient& http, int max_verify) {
  std::vector<VerifiedFinding> results;
  int verified_count = 0;

  for (const auto& f : findings) {
    if (verified_count >= max_verify) {
      // Accept remaining without deep verification
      VerifiedFinding vf;
      vf.finding = f;
      vf.state = VerifyState::UNVERIFIED;
      vf.state_reason = "Skipped — verification budget exceeded";
      results.push_back(vf);
      continue;
    }

    // Only verify high/critical findings (worth the extra requests)
    if (f.severity == "critical" || f.severity == "high") {
      results.push_back(verify_one(f, http));
      verified_count++;
    } else {
      VerifiedFinding vf;
      vf.finding = f;
      vf.state = VerifyState::SUSPECTED;
      vf.state_reason = "Accepted at face value (medium/low)";
      results.push_back(vf);
    }
  }

  return results;
}

void save_snapshot(const ScanSnapshot& snapshot, const std::string& output_dir) {
  std::string filename = output_dir + "/scan_memory_" + snapshot.target + "_" + snapshot.timestamp + ".json";
  // Sanitize filename
  for (auto& c : filename) {
    if (c == ':' || c == '/' || c == '\\' || c == ' ') c = '_';
  }

  std::ofstream out(filename);
  if (!out.is_open()) return;

  out << "{\n";
  out << "  \"target\": \"" << snapshot.target << "\",\n";
  out << "  \"timestamp\": \"" << snapshot.timestamp << "\",\n";
  out << "  \"endpoints\": [\n";
  for (size_t i = 0; i < snapshot.endpoints.size(); i++) {
    out << "    \"" << snapshot.endpoints[i] << "\"";
    if (i < snapshot.endpoints.size() - 1) out << ",";
    out << "\n";
  }
  out << "  ],\n";
  out << "  \"technologies\": [\n";
  for (size_t i = 0; i < snapshot.technologies.size(); i++) {
    out << "    \"" << snapshot.technologies[i] << "\"";
    if (i < snapshot.technologies.size() - 1) out << ",";
    out << "\n";
  }
  out << "  ],\n";
  out << "  \"finding_count\": " << snapshot.findings.size() << ",\n";
  out << "  \"findings\": [\n";
  for (size_t i = 0; i < snapshot.findings.size(); i++) {
    auto& vf = snapshot.findings[i];
    out << "    {\"type\": \"" << vf.finding.type << "\", "
        << "\"severity\": \"" << vf.finding.severity << "\", "
        << "\"url\": \"" << vf.finding.url << "\", "
        << "\"state\": " << static_cast<int>(vf.state) << ", "
        << "\"confidence\": " << vf.finding.confidence << ", "
        << "\"reason\": \"" << vf.state_reason << "\"}";
    if (i < snapshot.findings.size() - 1) out << ",";
    out << "\n";
  }
  out << "  ]\n";
  out << "}\n";
  out.close();

  std::cerr << "  [memory] Snapshot saved: " << filename << "\n";
}

ScanSnapshot load_previous_snapshot(const std::string& target, const std::string& output_dir) {
  ScanSnapshot empty;
  empty.target = target;
  // TODO: implement JSON parsing of previous snapshot
  // For now, return empty (first scan = no comparison)
  return empty;
}

ScanDelta compute_delta(const ScanSnapshot& previous, const ScanSnapshot& current) {
  ScanDelta delta;

  // Find new endpoints
  std::set<std::string> prev_eps(previous.endpoints.begin(), previous.endpoints.end());
  for (const auto& ep : current.endpoints) {
    if (prev_eps.find(ep) == prev_eps.end()) {
      delta.new_endpoints.push_back(ep);
    }
  }

  // Find removed endpoints
  std::set<std::string> curr_eps(current.endpoints.begin(), current.endpoints.end());
  for (const auto& ep : previous.endpoints) {
    if (curr_eps.find(ep) == curr_eps.end()) {
      delta.removed_endpoints.push_back(ep);
    }
  }

  // Find new technologies
  std::set<std::string> prev_tech(previous.technologies.begin(), previous.technologies.end());
  for (const auto& t : current.technologies) {
    if (prev_tech.find(t) == prev_tech.end()) {
      delta.new_technologies.push_back(t);
    }
  }

  // Find new vs persistent findings
  std::set<std::string> prev_finding_keys;
  for (const auto& f : previous.findings) {
    prev_finding_keys.insert(f.finding.type + "|" + f.finding.url);
  }

  for (const auto& f : current.findings) {
    std::string key = f.finding.type + "|" + f.finding.url;
    if (prev_finding_keys.find(key) == prev_finding_keys.end()) {
      delta.new_findings.push_back(f);
    } else {
      delta.persistent_findings.push_back(f);
    }
  }

  // Find resolved findings (in previous but not current)
  std::set<std::string> curr_finding_keys;
  for (const auto& f : current.findings) {
    curr_finding_keys.insert(f.finding.type + "|" + f.finding.url);
  }
  for (const auto& f : previous.findings) {
    std::string key = f.finding.type + "|" + f.finding.url;
    if (curr_finding_keys.find(key) == curr_finding_keys.end()) {
      delta.resolved_findings.push_back(f);
    }
  }

  return delta;
}

}  // namespace apex
